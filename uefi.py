#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
uefi - read UEFI / PC BIOS flash images.

A BIOS is the one firmware class where scanning for strings finds almost
nothing. A release build of EDK2 contains no library banners at all: no
"OpenSSL 3.0.x", no "EDK II", nothing a regex could catch. Measured on a
published OVMF build, the entire 4 MB image yields zero matches for every
signature in our database.

What it does contain is an inventory, written down by the build itself:

  * **Every module carries its own name.** A USER_INTERFACE section holds the
    module's name as the build system knew it ("DxeCore", "PciBusDxe",
    "SecureBootConfigDxe"), and a firmware file's GUID identifies it exactly
    even when that section is absent. The same OVMF image yields 108 named
    modules.

  * **The structure is the segmentation.** An Intel flash image is a
    descriptor naming regions (BIOS, Management Engine, GbE, platform data);
    the BIOS region holds firmware volumes; volumes hold files; files hold
    sections; and one of those sections is usually an LZMA stream containing
    another volume with everything interesting inside it. Measured on OVMF:
    1.4 MB compressed expands to 16 MB, and 105 of the 108 modules are in
    there. A tool that does not decompress sees three modules and calls it a
    BIOS.

Two honest limits are built in rather than papered over. The version a module
declares is its own VERSION section, which in EDK2 practice is almost always
"1.0" - it is reported when present and never treated as a library version.
And EFI/Tiano compression (the pre-LZMA scheme, still used by some vendors) is
recognised but not decompressed: those sections are reported as unreadable,
which is a finding, rather than skipped, which would silently shrink the
inventory.

The flash-descriptor reader follows the public specification but has not been
run against a real vendor dump - we have no BIOS sample from a customer yet.
The firmware volume, file, section and LZMA readers were developed against
published EDK2 OVMF builds.
"""

import lzma
import struct

# --- Intel flash descriptor ------------------------------------------------ #
IFD_SIGNATURE = b"\x5a\xa5\xf0\x0f"     # 0x0FF0A55A, little-endian
IFD_SIGNATURE_OFFSET = 0x10
IFD_REGIONS = ["descriptor", "bios", "management-engine", "gigabit-ethernet",
               "platform-data"]

# --- firmware volume ------------------------------------------------------- #
FV_SIGNATURE = b"_FVH"
FV_SIGNATURE_OFFSET = 40
FV_HEADER_MIN = 56
FV_HEADER_MAX = 1024

# Known filesystem GUIDs, so a volume can say what it is rather than show 16
# bytes of hex. Anything not listed is still walked - vendors define their own.
FS_GUIDS = {
    "7a c0 73 54 cb 3d ca 4d bd 6f 1e 96 89 e7 34 9a": "FFS3",
    "78 e5 8c 8c 3d 8a 1c 4f 99 35 89 61 85 c3 2d d3": "FFS2",
    "d9 54 93 7a 68 04 4a 44 81 ce 0b f6 17 d8 90 df": "FFS1",
    "8d 2b f1 ff 96 76 8b 4c a9 85 27 47 07 5b 4f 50": "NVRAM store",
}

# --- firmware file --------------------------------------------------------- #
FFS_HEADER_SIZE = 24
FFS_TYPES = {
    0x01: "raw", 0x02: "freeform", 0x03: "security-core", 0x04: "pei-core",
    0x05: "dxe-core", 0x06: "peim", 0x07: "driver",
    0x08: "combined-peim-driver", 0x09: "application", 0x0A: "smm",
    0x0B: "firmware-volume-image", 0x0C: "combined-smm-dxe", 0x0D: "smm-core",
    0x0E: "mm-standalone", 0x0F: "mm-core-standalone", 0xF0: "pad",
}

# --- section --------------------------------------------------------------- #
SECTION_COMPRESSION = 0x01
SECTION_GUID_DEFINED = 0x02
SECTION_PE32 = 0x10
SECTION_TE = 0x12
SECTION_VERSION = 0x14
SECTION_USER_INTERFACE = 0x15
SECTION_FIRMWARE_VOLUME_IMAGE = 0x17
SECTION_RAW = 0x19

# EE4E5898-3914-4259-9D6E-DC7BD79403CF, as it is laid out on disk.
LZMA_DECOMPRESS_GUID = bytes.fromhex("98584eee143959429d6edc7bd79403cf")
BROTLI_DECOMPRESS_GUID = bytes.fromhex("861a0e3b7f1a4e4687a5b6238ee7b4a3")

COMPRESSION_NONE, COMPRESSION_TIANO, COMPRESSION_LZMA = 0, 1, 2

# Hostile-input caps. A firmware volume nests inside a section inside a file
# inside a volume; a crafted image can nest that forever, and an LZMA stream
# can claim any expanded size at all.
MAX_DEPTH = 8
MAX_FILES = 4096
MAX_VOLUMES = 64
MAX_EXPANDED_BYTES = 256 * 1024 * 1024
MAX_EXPANSIONS = 16


def _guid_key(blob):
    return " ".join(f"{b:02x}" for b in blob)


def format_guid(blob):
    """The mixed-endian GUID text everyone in the UEFI world quotes."""
    if len(blob) != 16:
        return blob.hex()
    a, b, c = struct.unpack_from("<IHH", blob, 0)
    return (f"{a:08X}-{b:04X}-{c:04X}-{blob[8]:02X}{blob[9]:02X}-"
            + "".join(f"{x:02X}" for x in blob[10:16]))


def _utf16(blob):
    text = blob.decode("utf-16-le", "replace").split("\x00")[0].strip()
    return text or None


# --------------------------------------------------------------------------- #
# Flash descriptor
# --------------------------------------------------------------------------- #

def parse_flash_descriptor(data):
    """Intel flash descriptor regions, or None.

    A customer's BIOS dump is usually the whole SPI flash, not just the BIOS:
    the Management Engine sits in there too, and it is signed Intel code we
    cannot read. Naming the regions is what lets the report say "this 5 MB is
    the ME and it was not analysed" instead of quietly averaging it into a
    verdict about the firmware.

    Written from the public specification; not yet run against a real vendor
    dump, which is why every caller reports it as spec-derived.
    """
    if len(data) < 0x1000:
        return None
    if data[IFD_SIGNATURE_OFFSET:IFD_SIGNATURE_OFFSET + 4] != IFD_SIGNATURE:
        return None

    flmap0, = struct.unpack_from("<I", data, 0x14)
    region_base = ((flmap0 >> 16) & 0xFF) << 4
    region_count = min(((flmap0 >> 24) & 0x07) + 1, len(IFD_REGIONS))
    if not 0 < region_base < len(data) - 4:
        return None

    regions = []
    for index in range(region_count):
        at = region_base + index * 4
        if at + 4 > len(data):
            break
        value, = struct.unpack_from("<I", data, at)
        base = (value & 0x1FFF) << 12
        limit = (((value >> 16) & 0x1FFF) << 12) + 0xFFF
        if base > limit:                      # the documented "unused" marker
            continue
        regions.append({
            "name": IFD_REGIONS[index],
            "offset": base,
            "length": min(limit, len(data) - 1) - base + 1,
            "truncated": limit >= len(data),
        })
    if not regions:
        return None
    return {"regions": regions, "region_base": region_base}


# --------------------------------------------------------------------------- #
# Firmware volumes
# --------------------------------------------------------------------------- #

def parse_volume_header(data, offset):
    """An EFI_FIRMWARE_VOLUME_HEADER at `offset`, or None.

    "_FVH" occurs by chance inside compiled code - four times in a 4 MB OVMF
    image - so the signature alone identifies nothing. The header checksum is
    what settles it: every UINT16 of the header sums to zero, which random
    code does not do.
    """
    if offset < 0 or offset + FV_HEADER_MIN > len(data):
        return None
    if data[offset + FV_SIGNATURE_OFFSET:offset + FV_SIGNATURE_OFFSET + 4] != FV_SIGNATURE:
        return None

    length, _sig, attributes, header_length, checksum, ext_offset = \
        struct.unpack_from("<Q4sIHHH", data, offset + 32)
    revision = data[offset + 55]

    if revision not in (1, 2):
        return None
    if not FV_HEADER_MIN <= header_length <= FV_HEADER_MAX:
        return None
    if header_length % 2 or offset + header_length > len(data):
        return None
    if not header_length <= length <= len(data) - offset:
        return None
    words = struct.unpack_from(f"<{header_length // 2}H", data, offset)
    if sum(words) & 0xFFFF:
        return None

    guid = data[offset + 16:offset + 32]
    name = None
    first_file = offset + header_length
    if ext_offset:
        ext = offset + ext_offset
        if ext + 20 <= len(data):
            name = data[ext:ext + 16]
            ext_size, = struct.unpack_from("<I", data, ext + 16)
            if 20 <= ext_size <= length:
                first_file = (ext + ext_size + 7) & ~7

    return {
        "offset": offset,
        "length": length,
        "header_length": header_length,
        "attributes": attributes,
        "checksum": checksum,
        "revision": revision,
        "filesystem_guid": format_guid(guid),
        "filesystem": FS_GUIDS.get(_guid_key(guid)),
        "name_guid": format_guid(name) if name else None,
        "first_file": first_file,
    }


def find_volumes(data, limit=MAX_VOLUMES):
    """Every firmware volume in `data`, outermost first."""
    volumes, at = [], 0
    while len(volumes) < limit:
        found = data.find(FV_SIGNATURE, at)
        if found < 0:
            break
        at = found + 4
        header = parse_volume_header(data, found - FV_SIGNATURE_OFFSET)
        if header:
            volumes.append(header)
    return volumes


# --------------------------------------------------------------------------- #
# Files and sections
# --------------------------------------------------------------------------- #

class _Walk:
    """State shared by one traversal: the caps, and what was found."""

    def __init__(self):
        self.modules = []
        self.data_volumes = []
        self.expansions = []
        self.unreadable = []
        self.expanded_bytes = 0
        self.files = 0
        self.volumes = 0

    def remaining(self):
        return max(0, MAX_EXPANDED_BYTES - self.expanded_bytes)

    def budget(self, size):
        """Charge `size` against the expansion limit, or refuse it."""
        if self.expanded_bytes + size > MAX_EXPANDED_BYTES:
            return False
        self.expanded_bytes += size
        return True


def _decompress_guided(blob, at, size, walk):
    """The payload of a GUID_DEFINED section, decompressed if we can.

    Returns (bytes, None) or (None, reason). A reason is a finding: the
    modules behind an unreadable section exist, and saying so is the whole
    point of the tool.
    """
    if at + 24 > len(blob):
        return None, "GUID-defined section header is truncated"
    guid = blob[at + 4:at + 20]
    data_offset, attributes = struct.unpack_from("<HH", blob, at + 20)
    if not 24 <= data_offset <= size:
        return None, "GUID-defined section declares an impossible data offset"
    payload = blob[at + data_offset:at + size]

    if guid == LZMA_DECOMPRESS_GUID:
        return _lzma(payload, walk)
    if guid == BROTLI_DECOMPRESS_GUID:
        return None, ("a Brotli-compressed section was found; fw2sbom cannot "
                      "expand it, so the modules inside are not listed")
    if attributes & 0x01:       # PROCESSING_REQUIRED, and we do not know how
        return None, (f"section {format_guid(guid)} needs processing we do not "
                      "implement; the modules inside are not listed")
    return payload, None        # signed or CRC'd only: the data is plain


def _lzma(payload, walk):
    if len(payload) < 13:
        return None, "LZMA section is too short to carry a header"
    # The header may declare the expanded size or mark it unknown (every byte
    # 0xFF), and a stream that declines to say how big it is must not thereby
    # escape the limit - so the size is checked when declared and the output is
    # charged against the budget either way.
    declared = int.from_bytes(payload[5:13], "little")
    if declared != 0xFFFFFFFFFFFFFFFF and declared > walk.remaining():
        return None, (f"an LZMA section declares {declared} bytes, over the "
                      "expansion limit; it was not decompressed")
    try:
        out = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(
            payload, walk.remaining())
    except Exception as e:
        return None, f"an LZMA section did not decompress: {e}"
    if not out:
        return None, "an LZMA section decompressed to nothing"
    if not walk.budget(len(out)):
        return None, ("an LZMA section expanded past the limit; it was not "
                      "read")
    return out, None


def _decompress_standard(blob, at, size, walk):
    """EFI_COMPRESSION_SECTION: the older scheme, still shipped by vendors."""
    if at + 9 > len(blob):
        return None, "compression section header is truncated"
    declared, kind = struct.unpack_from("<IB", blob, at + 4)
    payload = blob[at + 9:at + size]
    if kind == COMPRESSION_NONE:
        return payload, None
    if kind == COMPRESSION_LZMA:
        return _lzma(payload, walk)
    if kind == COMPRESSION_TIANO:
        return None, ("an EFI/Tiano-compressed section was found; fw2sbom "
                      "cannot expand it, so the modules inside are not listed")
    return None, f"a section uses compression type {kind}, which we do not know"


def _walk_sections(blob, at, end, walk, depth, origin):
    """Sections of one firmware file. Fills `walk`, returns the module record."""
    module = {"name": None, "version": None, "has_code": False,
              "unreadable": []}
    while at + 4 <= end and depth <= MAX_DEPTH:
        size = int.from_bytes(blob[at:at + 3], "little")
        kind = blob[at + 3]
        body = at + 4
        if size == 0xFFFFFF:                 # EFI_COMMON_SECTION_HEADER2
            if at + 8 > end:
                break
            size, = struct.unpack_from("<I", blob, at + 4)
            body = at + 8
        if size < 4 or at + size > end:
            break

        if kind == SECTION_USER_INTERFACE:
            module["name"] = module["name"] or _utf16(blob[body:at + size])
        elif kind == SECTION_VERSION:
            # UINT16 BuildNumber, then the version string.
            module["version"] = module["version"] or _utf16(blob[body + 2:at + size])
        elif kind in (SECTION_PE32, SECTION_TE):
            module["has_code"] = True
        elif kind == SECTION_FIRMWARE_VOLUME_IMAGE:
            _walk_volume(blob, body, walk, depth + 1, f"{origin}>0x{body:x}")
        elif kind in (SECTION_COMPRESSION, SECTION_GUID_DEFINED):
            if kind == SECTION_COMPRESSION:
                inner, reason = _decompress_standard(blob, at, size, walk)
            else:
                inner, reason = _decompress_guided(blob, at, size, walk)
            if reason:
                module["unreadable"].append(reason)
                walk.unreadable.append(reason)
            elif inner and depth < MAX_DEPTH:
                # A compressed section holds more sections, and those are
                # where a BIOS keeps almost everything. The expanded bytes are
                # kept as well: module names come from the structure, but any
                # library banner a vendor compiled in is in here and nowhere
                # else, and the signature scan never sees it otherwise.
                if len(walk.expansions) < MAX_EXPANSIONS:
                    walk.expansions.append({"origin": origin, "data": inner})
                _walk_sections(inner, 0, len(inner), walk, depth + 1, origin)
        at += (size + 3) & ~3
    return module


def _walk_volume(blob, offset, walk, depth, origin):
    """Files of one firmware volume, and the sections of each.

    Only a volume whose filesystem GUID says FFS is walked for files. The
    other kind a flash image contains is the variable store, which shares the
    volume header and holds UEFI variables rather than modules - reading it as
    FFS invents a module out of whatever the NVRAM happened to contain, which
    is how one turned up in the first run against a real image.
    """
    header = parse_volume_header(blob, offset)
    if not header or depth > MAX_DEPTH or walk.volumes >= MAX_VOLUMES:
        return
    walk.volumes += 1
    if header["filesystem"] not in ("FFS1", "FFS2", "FFS3"):
        walk.data_volumes.append({
            "offset": offset,
            "length": header["length"],
            "filesystem": header["filesystem"] or header["filesystem_guid"],
        })
        return

    at = header["first_file"]
    end = min(offset + header["length"], len(blob))

    while at + FFS_HEADER_SIZE <= end and walk.files < MAX_FILES:
        # The volume ends at erased flash - which means the whole header is
        # erased, not just the GUID. A pad file carries an all-0xFF GUID with
        # a perfectly valid size, so testing the GUID alone ends the walk at
        # the first pad: on a published OVMF image that hid every PEI module
        # in the firmware behind the second file of the volume.
        if blob[at:at + FFS_HEADER_SIZE] == b"\xff" * FFS_HEADER_SIZE:
            break
        guid = blob[at:at + 16]
        kind = blob[at + 18]
        size = int.from_bytes(blob[at + 20:at + 23], "little")
        if size == 0xFFFFFF:                # FFS3 extended size
            if at + 32 > end:
                break
            size, = struct.unpack_from("<Q", blob, at + 24)
            body = at + 32
        else:
            body = at + FFS_HEADER_SIZE
        if size < FFS_HEADER_SIZE or at + size > end:
            break

        walk.files += 1
        if kind != 0xF0:                    # padding is not a module
            module = _walk_sections(blob, body, at + size, walk, depth + 1,
                                    origin)
            module["volume_kind"] = header["filesystem"]
            module.update({
                "guid": format_guid(guid),
                "type": FFS_TYPES.get(kind, f"0x{kind:02x}"),
                "type_id": kind,
                "size": size,
                "volume": origin,
            })
            walk.modules.append(module)
        at += (size + 7) & ~7


def read_modules(data, volumes=None):
    """Every UEFI module in `data`, with what could not be read.

    Returns {modules, unreadable, expanded_bytes, volumes}. Modules keep the
    order they appear in the flash, which is the order the firmware itself
    lays them out.
    """
    walk = _Walk()
    for header in volumes if volumes is not None else find_volumes(data):
        _walk_volume(data, header["offset"], walk, 0,
                     f"0x{header['offset']:x}")
    return {
        "modules": walk.modules,
        "data_volumes": walk.data_volumes,
        "expansions": walk.expansions,
        "unreadable": walk.unreadable,
        "expanded_bytes": walk.expanded_bytes,
        "volumes": walk.volumes,
    }


# --------------------------------------------------------------------------- #
# Instruction set
# --------------------------------------------------------------------------- #
# IMAGE_FILE_MACHINE_*, the field every PE/COFF image carries. A BIOS module is
# a PE32+ or a Terse Executable, so the architecture is written down rather
# than guessed from opcode statistics - which on a 4 MB image of mixed code,
# compressed data and erased flash would be guesswork anyway.
MACHINES = {
    0x014C: ("ia32", "x86 (IA-32)"),
    0x8664: ("x86-64", "x86-64"),
    0x01C2: ("arm-thumb", "ARM (Thumb-2)"),
    0xAA64: ("aarch64", "AArch64"),
    0x5064: ("riscv64", "RISC-V (64-bit)"),
    0x0200: ("ia64", "Itanium"),
    0x0EBC: ("ebc", "EFI Byte Code"),
}


def _machine_of_image(blob, at, end):
    """The machine field of a PE32/PE32+ or TE image at `at`, or None."""
    if at + 4 > end:
        return None
    if blob[at:at + 2] == b"VZ":                     # Terse Executable
        machine, = struct.unpack_from("<H", blob, at + 2)
        return machine
    if blob[at:at + 2] != b"MZ":
        return None
    if at + 0x40 > end:
        return None
    lfanew, = struct.unpack_from("<I", blob, at + 0x3C)
    head = at + lfanew
    if head + 6 > end or blob[head:head + 4] != b"PE\x00\x00":
        return None
    machine, = struct.unpack_from("<H", blob, head + 4)
    return machine


def detect_machine(data, volumes):
    """The instruction set of the modules, read from their PE headers.

    Deliberately shallow: only sections that are already plaintext are looked
    at, so this costs a few microseconds and runs before anything is
    decompressed. Every module in an image is built for the same machine, so
    the first one found answers the question.
    """
    for header in volumes or []:
        if header["filesystem"] not in ("FFS1", "FFS2", "FFS3"):
            continue
        at = header["first_file"]
        end = min(header["offset"] + header["length"], len(data))
        files = 0
        while at + FFS_HEADER_SIZE <= end and files < 64:
            if data[at:at + FFS_HEADER_SIZE] == b"\xff" * FFS_HEADER_SIZE:
                break
            size = int.from_bytes(data[at + 20:at + 23], "little")
            if size < FFS_HEADER_SIZE or at + size > end:
                break
            files += 1
            section, section_end = at + FFS_HEADER_SIZE, at + size
            while section + 4 <= section_end:
                ssize = int.from_bytes(data[section:section + 3], "little")
                stype = data[section + 3]
                if ssize < 4 or section + ssize > section_end:
                    break
                if stype in (SECTION_PE32, SECTION_TE):
                    machine = _machine_of_image(data, section + 4, section_end)
                    if machine in MACHINES:
                        return {"machine": machine,
                                "architecture": MACHINES[machine][0],
                                "label": MACHINES[machine][1]}
                section += (ssize + 3) & ~3
            at += (size + 7) & ~7
    return None


# --------------------------------------------------------------------------- #

def detect(data):
    """Identify a UEFI / PC BIOS image, or return None.

    Two shapes arrive: a whole SPI flash beginning with an Intel descriptor,
    and a bare BIOS region or firmware volume. Both have to be recognised,
    because which one a customer sends depends on how they dumped it.
    """
    descriptor = parse_flash_descriptor(data)
    volumes = find_volumes(data)
    if not volumes and not descriptor:
        return None

    return {
        "kind": "flash-descriptor" if descriptor else "firmware-volumes",
        # The descriptor names the BIOS region; volumes found outside it are
        # still reported, because a wrong descriptor is a thing that happens.
        "descriptor": descriptor,
        "volumes": volumes,
        "machine": detect_machine(data, volumes),
    }
