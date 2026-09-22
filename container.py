#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
container - walk a firmware image's containers and read what is inside them.

A microcontroller image is one flat blob, and scanning it for strings finds
everything there is to find. A Linux device image is not: it is a boot header,
then a compressed kernel, then a compressed root filesystem, and every
component worth naming sits inside one of those compressed regions. Scanning
the raw bytes finds nothing, which is exactly what fw2sbom did to a real router
image before this module existed - the correct verdict ("compressed"), and a
completely empty SBOM.

Three things happen here:

  1. **Segment the image.** uImage headers, compressed regions and filesystem
     superblocks are located and turned into a list of segments, each with its
     own offset, kind and (where we can produce it) decompressed content.

  2. **Read the root filesystem.** SquashFS is walked and its files made
     available by path.

  3. **Read the package database.** /usr/lib/opkg/status and its dpkg and apk
     equivalents list every installed package with an exact version. This is
     the single most valuable thing in a Linux firmware image: not a heuristic
     guess from a version banner, but the build system's own record. A 14 MB
     router image yields several hundred components this way.

Standard library only. gzip, xz, lzma and bzip2 are all available; lzo, lz4 and
zstd are not, and a region using one is reported as un-expanded with the
algorithm named rather than skipped in silence. "We could not open this" and
"there was nothing here" must never look the same.
"""

import bz2
import collections
import lzma
import re
import struct
import zlib

import elf
import esp32
import ext
import fit
import cpio
import cramfs
import jffs2
import microcode
import squashfs
import ubi
import ubifs
import uefi
import vendor_container
import yaffs

# A decompressed region is capped so a crafted image cannot exhaust memory.
MAX_EXPANDED = 256 * 1024 * 1024
MAX_SEGMENTS = 64

# Every on-image filesystem reader raises its own error type, and the code that
# reads packages, binaries and files out of one should not care which reader it
# was handed. Catching the specific type is how a second filesystem turns into
# a traceback instead of a warning.
FILESYSTEM_ERRORS = (squashfs.SquashFSError, cramfs.CramFSError,
                     jffs2.JFFS2Error, ubifs.UBIFSError, cpio.CPIOError,
                     ext.ExtError, yaffs.YAFFSError)

UIMAGE_MAGIC = 0x27051956
UIMAGE_HEADER_SIZE = 64
UIMAGE_COMPRESSION = {0: None, 1: "gzip", 2: "bzip2", 3: "lzma", 4: "lzo",
                      5: "lz4", 6: "zstd"}
UIMAGE_OS = {5: "Linux", 0: "invalid"}
UIMAGE_ARCH = {2: "arm", 3: "x86", 5: "mips", 6: "mips64", 22: "arm64",
               23: "riscv"}

# Magics we look for anywhere in the image, not only at offset 0. The whole
# point is that in a Linux image the interesting regions never start at 0.
SCAN_MAGICS = [
    (b"\x1f\x8b\x08", "gzip"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"BZh9", "bzip2"),
    (b"\x5d\x00\x00\x80", "lzma"),
    (b"\x5d\x00\x00\x10", "lzma"),
    (b"\x5d\x00\x00\x00", "lzma"),
]

# Package databases, in the order we look for them. All three are the same
# shape: blocks of "Field: value" lines separated by blank lines.
PACKAGE_DATABASES = [
    ("/usr/lib/opkg/status", "opkg", "pkg:opkg"),
    ("/var/lib/opkg/status", "opkg", "pkg:opkg"),
    ("/var/lib/dpkg/status", "dpkg", "pkg:deb"),
    ("/lib/apk/db/installed", "apk", "pkg:apk"),
]

OS_RELEASE_FILES = ["/etc/openwrt_release", "/etc/os-release",
                    "/usr/lib/os-release"]


def _expand(algorithm, blob, limit=MAX_EXPANDED):
    """Decompress one region, or raise ValueError naming what went wrong."""
    try:
        if algorithm == "gzip":
            return zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(blob, limit)
        if algorithm == "xz":
            return lzma.LZMADecompressor(lzma.FORMAT_XZ).decompress(blob, limit)
        if algorithm == "lzma":
            return lzma.LZMADecompressor(lzma.FORMAT_ALONE).decompress(blob, limit)
        if algorithm == "bzip2":
            return bz2.BZ2Decompressor().decompress(blob, limit)
    except Exception as e:                      # malformed region, not a crash
        raise ValueError(f"{algorithm} region did not decompress: {e}")
    raise ValueError(f"no standard-library decompressor for {algorithm}")


def parse_uimage(data, offset=0):
    """Parse a U-Boot legacy uImage header, or return None.

    The header's 32-byte name field is worth reading on its own: OpenWrt
    writes the kernel version into it, so "MIPS OpenWrt Linux-5.10.176" is
    available before anything has been decompressed.
    """
    if len(data) < offset + UIMAGE_HEADER_SIZE:
        return None
    magic, _hcrc, _time, size, load, entry, _dcrc, os_id, arch_id, _type, comp = \
        struct.unpack_from(">IIIIIIIBBBB", data, offset)
    if magic != UIMAGE_MAGIC:
        return None
    name = data[offset + 32:offset + 64].split(b"\x00")[0].decode(
        "utf-8", "replace")
    return {
        "offset": offset,
        "payload_offset": offset + UIMAGE_HEADER_SIZE,
        "payload_size": size,
        "load_address": load,
        "entry_point": entry,
        "os": UIMAGE_OS.get(os_id, f"os-{os_id}"),
        "architecture": UIMAGE_ARCH.get(arch_id, f"arch-{arch_id}"),
        "compression": UIMAGE_COMPRESSION.get(comp, f"comp-{comp}"),
        "name": name,
    }


# Carrying a segment's bytes and having *expanded* them are different claims.
# `expanded` tells the opacity judgement "whatever this scored, we read it", so
# a region that is merely a slice of the input must not set it: an encrypted
# ESP32 partition or an Intel ME region would otherwise be handed back as
# plaintext on the strength of having been copied out of the file.
def _segment(kind, offset, length, label, content=None, **extra):
    seg = {"kind": kind, "offset": offset, "length": length, "label": label,
           "content": content, "expanded": content is not None,
           "warnings": []}
    seg.update(extra)
    return seg


def _espressif_segments(data, detected, say):
    """Turn an Espressif image or flash layout into segments.

    An application image is header plus segments, each with its own load
    address. A full flash image is a partition table naming several of those
    alongside data areas; the partitions are the segmentation, because that is
    what the device itself uses.
    """
    segments = []
    image = detected["image"]
    core = f" ({detected['core']})" if detected["core"] else ""
    say(f"container: Espressif {detected['kind']} image, {detected['chip']}"
        f"{core}, entry 0x{image['entry_point']:08x}")

    application = image.get("app")
    if application and application.get("idf_version"):
        say(f"container:   ESP-IDF {application['idf_version']}"
            + (f", project {application['project_name']}"
               if application.get("project_name") else ""))

    if detected["kind"] == "application":
        segments.append(_segment(
            "boot-header", 0, esp32.IMAGE_HEADER_SIZE,
            f"Espressif image header ({detected['chip']})",
            content=data[:esp32.IMAGE_HEADER_SIZE], expanded=False,
            espressif=image))
        for entry in image["segments"]:
            segments.append(_segment(
                "esp-segment", entry["offset"], entry["length"],
                f"ESP segment {entry['index']} @ 0x{entry['load_address']:08x}",
                content=data[entry["offset"]:entry["offset"] + entry["length"]],
                expanded=False, load_address=entry["load_address"]))
        return segments

    # A full flash image: the partition table is the map.
    say(f"container: partition table with {len(detected['partitions'])} entries")
    for partition in detected["partitions"]:
        start = partition["address"]
        end = min(len(data), start + partition["size"])
        if start >= len(data):
            continue
        blob = data[start:end]
        label = (f"partition {partition['name']} "
                 f"({partition['type']}/{partition['subtype']})")
        say(f"container:   {label} at 0x{start:06x}, "
            f"{partition['size'] // 1024} KiB")
        # An app partition holds a complete image; carry the parsed header so
        # the framework version and chip reach the SBOM from here too.
        parsed = next((i for i in detected.get("images") or []
                       if i.get("partition") == partition["name"]), None)
        segments.append(_segment(
            "partition", start, end - start, label, content=blob,
            expanded=False, partition=partition,
            **({"espressif": parsed} if parsed else {})))

    if detected.get("bootloader"):
        boot = detected["bootloader"]
        segments.append(_segment(
            "bootloader", boot["offset"], boot["end"] - boot["offset"],
            f"second-stage bootloader ({detected['chip']})",
            content=data[boot["offset"]:boot["end"]], expanded=False,
            espressif=boot))
    return segments


def _uefi_segments(data, detected, say):
    """Segment a PC BIOS image the way the platform itself divides it.

    A customer's BIOS dump is usually a whole SPI flash: the firmware is one
    region of it, and the Management Engine - signed Intel code nobody outside
    Intel can read - is another. Measuring the file as a whole averages those
    together and produces a verdict about neither.
    """
    segments = []
    descriptor = detected["descriptor"]

    if descriptor:
        say(f"container: Intel flash descriptor, "
            f"{len(descriptor['regions'])} regions")
        for region in descriptor["regions"]:
            start = region["offset"]
            end = min(len(data), start + region["length"])
            if start >= len(data) or end <= start:
                continue
            say(f"container:   region {region['name']} at 0x{start:06x}, "
                f"{(end - start) // 1024} KiB")
            segments.append(_segment(
                "flash-region", start, end - start,
                f"flash region: {region['name']}",
                content=data[start:end], expanded=False, region=region))

    inventory = uefi.read_modules(data, detected["volumes"])
    named = sum(1 for m in inventory["modules"] if m["name"])
    say(f"container: {len(detected['volumes'])} firmware volume(s), "
        f"{len(inventory['modules'])} module(s), {named} named")

    for index, volume in enumerate(detected["volumes"]):
        start = volume["offset"]
        end = min(len(data), start + volume["length"])
        kind = volume["filesystem"] or volume["filesystem_guid"]
        label = f"UEFI firmware volume ({kind})"
        segments.append(_segment(
            "firmware-volume", start, end - start, label,
            content=data[start:end], expanded=False, volume=volume,
            **({"uefi": inventory} if index == 0 else {})))

    # The expanded volumes are where a vendor's own libraries live, if the
    # image has any. Without them the signature scan reads only the 3% of a
    # BIOS that is not compressed.
    for index, expansion in enumerate(inventory["expansions"], 1):
        segments.append(_segment(
            "uefi-expanded", 0, len(expansion["data"]),
            f"decompressed UEFI volume {index} (from {expansion['origin']})",
            content=expansion["data"]))

    for note in inventory["unreadable"]:
        say(f"container:   {note}")
    return segments


def _ubi_segments(data, image, verbose, log, say, warnings):
    """Segments for every volume of a UBI image.

    A volume's bytes are reassembled from erase blocks scattered across the
    flash, so they have no single position in the file. Each segment is placed
    at the volume's first erase block and says so in its label; offsets inside
    it are offsets into the reassembled volume.
    """
    segments = []
    say(f"container: UBI image at 0x{image['start']:x}, "
        f"{image['peb_size'] // 1024} KiB erase blocks, "
        f"{len(image['volumes'])} volume(s)")
    for note in image["warnings"]:
        warnings.append(f"UBI: {note}")
        say(f"container:   {note}")

    for volume in image["volumes"]:
        label = f"UBI volume '{volume['name']}'"
        blob = volume["data"]
        say(f"container:   {label} ({volume['type']}), {volume['lebs']} "
            f"logical blocks, {len(blob)} bytes")

        if blob[:4] == ubifs.MAGIC_BYTES:
            try:
                fs = ubifs.UBIFS(blob)
            except ubifs.UBIFSError as e:
                # A filesystem whose files cannot be listed is recorded as
                # exactly that. Its bytes are not handed to the walk as a
                # region: a UBIFS volume is mostly unused space, and judged
                # byte by byte it reads as erased flash - "empty", which is
                # the opposite of what was found.
                reason = f"UBIFS could not be read: {e}"
                warnings.append(f"{label}: {reason}")
                say(f"container:   {label}: {reason}")
                segment = _segment(
                    "unread-filesystem", volume["first_peb"], len(blob),
                    f"{label}: UBIFS, files not listed", content=None,
                    ubi_volume=volume["name"], unread_reason=reason)
                segment["warnings"].append(reason)
                segments.append(segment)
            else:
                segments.append(_segment(
                    "filesystem", volume["first_peb"], len(blob),
                    f"{label}: UBIFS", content=None, filesystem=fs,
                    ubi_volume=volume["name"]))
            continue

        # Anything else - a SquashFS rootfs, a kernel, raw data - is read the
        # way the same bytes would be read outside UBI. One level only: a UBI
        # image inside a UBI volume is not a thing.
        inner, inner_warnings = walk(blob, verbose, log, _inside_ubi=True)
        warnings.extend(f"{label}: {w}" for w in inner_warnings)
        if not inner and blob.strip(b"\xff"):
            # Too small for the walk to call it a region; still content.
            inner = [_segment("unclaimed", 0, len(blob), "volume contents",
                              content=blob, expanded=False)]
        for segment in inner:
            if segment["content"] is None and segment["kind"] != "filesystem":
                # Its bytes are in the volume, not at any offset in the file:
                # judged from the file, it would be judged on the wrong bytes.
                segment["content"] = blob[segment["offset"]:
                                          segment["offset"] + segment["length"]]
                segment["expanded"] = False
            segment["volume_offset"] = segment["offset"]
            segment["label"] = (f"{label}: {segment['label']} "
                                f"(at 0x{segment['offset']:x} in the volume)")
            segment["offset"] = volume["first_peb"]
            segment["ubi_volume"] = volume["name"]
            segments.append(segment)
    return segments


# Compression a ramdisk or kernel may use, recognised from its first bytes -
# a FIT ramdisk often declares "none" because U-Boot passes it on untouched
# and the kernel does the decompressing.
LEADING_MAGICS = [
    (b"\x1f\x8b\x08", "gzip"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"BZh", "bzip2"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"\x02\x21\x4c\x18", "lz4"),
    (b"\x89LZO", "lzo"),
]
FIT_COMPRESSION = {"none": None, "gzip": "gzip", "lzma": "lzma", "xz": "xz",
                   "bzip2": "bzip2", "lzo": "lzo", "lz4": "lz4", "zstd": "zstd"}
MAX_INITRAMFS_PROBES = 48


def _sniff_compression(blob):
    for magic, algorithm in LEADING_MAGICS:
        if blob.startswith(magic):
            return algorithm
    return None


def _cpio_segment(archive, offset, length, label, **extra):
    return _segment("filesystem", offset, length, label, content=None,
                    filesystem=archive, **extra)


def _find_initramfs(blob):
    """A cpio archive inside an expanded kernel, or None.

    Linux can carry its initramfs built into the kernel image: raw, or
    compressed a second time inside the already-decompressed kernel. That is
    how a lot of camera firmware ships its entire userland, and without
    looking for it the root filesystem is never found at all.
    """
    at = cpio.find_offset(blob)
    if at is not None:
        archive = cpio.CPIO(blob, at)
        # The kernel's own default initramfs - /dev, /dev/console, /root - is
        # a real archive with no files in it, and not a root filesystem.
        if archive.files():
            return archive, f"at 0x{at:x}"
    probes = 0
    for magic, algorithm in SCAN_MAGICS:
        at = blob.find(magic)
        while at != -1 and probes < MAX_INITRAMFS_PROBES:
            probes += 1
            try:
                inner = _expand(algorithm, blob[at:])
            except ValueError:
                inner = None
            if inner and cpio.looks_like_cpio(inner):
                try:
                    archive = cpio.CPIO(inner)
                except cpio.CPIOError:
                    archive = None
                if archive is not None and archive.files():
                    return archive, f"{algorithm} at 0x{at:x}"
            at = blob.find(magic, at + 1)
    return None


def _device_tree_model(blob):
    """A .dtb's own "model" and first "compatible", when it has them."""
    try:
        tree = fit.parse_fdt(blob)
    except fit.FITError:
        return None
    root = tree["root"]
    model = fit._string(blob, root, "model")
    compatible = fit._string(blob, root, "compatible")
    return model or compatible


def _fit_segments(data, image, say, warnings, claim):
    """Segments for a FIT image, each image read as it declares itself."""
    segments = []
    start = image["offset"]
    say(f"container: FIT image at 0x{start:x}, {len(image['images'])} image(s): "
        f"{image['description'] or 'no description'}")
    for note in image["warnings"]:
        warnings.append(f"FIT: {note}")
        say(f"container:   {note}")

    # The tree itself. With external data it is a few KiB in front of the
    # images; with embedded data it wraps them, and only the part before the
    # first image is header. Filesystem images are left unclaimed so the
    # filesystem scan below finds them exactly as it would anywhere else.
    embedded = sorted(i["offset"] for i in image["images"]
                      if i["placement"] == "embedded" and i["present"])
    header_end = embedded[0] if embedded else image["header_end"]
    segments.append(_segment(
        "boot-header", start, header_end - start,
        f"FIT header ({image['description'] or 'no description'})",
        content=data[start:header_end], expanded=False, fit=image))
    keep_open = [(i["offset"], i["offset"] + i["size"]) for i in image["images"]
                 if i["type"] == "filesystem" and i["present"]]
    pieces, position = [], start
    for low, high in sorted(keep_open):
        if low > position:
            pieces.append((position, min(low, image["header_end"])))
        position = max(position, high)
    if position < image["header_end"]:
        pieces.append((position, image["header_end"]))
    for low, high in pieces:
        if high > low:
            claim(low, high)

    for entry in image["images"]:
        verified = [c["algo"] for c in entry["checks"] if c["ok"]]
        failed = [c["algo"] for c in entry["checks"] if c["ok"] is False]
        state = (f"{', '.join(verified)} verified" if verified else "no hash checked")
        if failed:
            state += f"; {', '.join(failed)} MISMATCH"
        say(f"container:   {entry['name']}: {entry['type']}, {entry['arch']}, "
            f"{entry['compression'] or 'no compression declared'}, "
            f"{entry['size']} bytes ({entry['placement']}; {state})")
        if not entry["present"] or entry["type"] == "filesystem":
            continue
        low, high = entry["offset"], entry["offset"] + entry["size"]
        blob = data[low:high]
        name = f"FIT image '{entry['name']}'"
        extra = {"fit_image": entry}

        if entry["type"] == "flat_dt":
            model = _device_tree_model(blob)
            if model:
                say(f"container:   {entry['name']}: device tree for {model!r}")
            segments.append(_segment(
                "device-tree", low, high - low,
                f"{name}: device tree" + (f" ({model})" if model else ""),
                content=blob, expanded=False, device_tree_model=model, **extra))
            claim(low, high)
            continue

        algorithm = FIT_COMPRESSION.get(entry["compression"] or "none",
                                        entry["compression"])
        if algorithm is None:
            algorithm = _sniff_compression(blob)
        content, note, expanded = blob, None, False
        if algorithm:
            try:
                content, expanded = _expand(algorithm, blob), True
                say(f"container:   {entry['name']}: expanded {len(blob)} -> "
                    f"{len(content)} bytes ({algorithm})")
            except ValueError as e:
                content, note = None, str(e)
                warnings.append(f"{name}: {e}")
                say(f"container:   {entry['name']}: NOT expanded: {e}")

        if content is not None and cpio.looks_like_cpio(content):
            try:
                archive = cpio.CPIO(content)
            except cpio.CPIOError as e:
                say(f"container:   {entry['name']}: cpio did not read: {e}")
            else:
                say(f"container:   {entry['name']}: initramfs, "
                    f"{len(archive.entries)} entries")
                segments.append(_cpio_segment(
                    archive, low, high - low,
                    f"{name}: initramfs (cpio{', ' + algorithm if algorithm else ''})",
                    **extra))
                claim(low, high)
                continue

        kind = "kernel" if entry["type"] == "kernel" else "fit-image"
        seg = _segment(kind, low, high - low,
                       f"{name}: {entry['description'] or entry['type']} "
                       f"({algorithm or 'raw'})",
                       content=content, expanded=expanded, **extra)
        if note:
            seg["warnings"].append(note)
        for algo in failed:
            seg["warnings"].append(f"{algo} does not match the image's data")
        segments.append(seg)
        claim(low, high)
    return segments


STRUCTURAL_KINDS = ("filesystem", "unread-filesystem", "boot-header",
                    "vendor-header", "kernel", "fit-image", "device-tree",
                    "image-metadata", "firmware-volume", "partition-table")


def _nested_segments(expanded, offset, label, verbose, log, warnings,
                     inside_ubi, depth):
    """The segments inside an expanded region, or None if it holds none.

    A disk image shipped gzipped - OpenWrt's x86 images, many appliance
    updates - expands to a partition table and filesystems. Scanned as one
    blob of strings it yields noise; walked, it yields its root filesystem.
    Only one level down, and only used when the walk finds structure there.
    """
    inner, inner_warnings = walk(expanded, verbose, log, _inside_ubi=inside_ubi,
                                 _depth=depth + 1)
    if not any(s["kind"] in STRUCTURAL_KINDS for s in inner):
        return None
    warnings.extend(f"{label}: {w}" for w in inner_warnings)
    for segment in inner:
        if segment["content"] is None and segment["kind"] not in (
                "filesystem", "unread-filesystem"):
            segment["content"] = expanded[segment["offset"]:
                                          segment["offset"] + segment["length"]]
            segment["expanded"] = False
        segment["expanded_offset"] = segment["offset"]
        segment["label"] = (f"{segment['label']} (in the {label}, at "
                            f"0x{segment['offset']:x} once expanded)")
        segment["offset"] = offset
    return inner


SECTOR = 512
MBR_TYPES = {0x83: "Linux", 0x82: "Linux swap", 0x0B: "FAT32", 0x0C: "FAT32 (LBA)",
             0x06: "FAT16", 0x0E: "FAT16 (LBA)", 0x07: "NTFS/exFAT", 0xEF: "EFI system",
             0xEE: "GPT protective", 0x05: "extended", 0x0F: "extended (LBA)"}


def parse_partition_table(data):
    """An MBR (and a GPT behind it, if protective) at the start of `data`.

    Checked strictly, because 0x55AA at byte 510 is also how a FAT boot
    sector ends: every entry must be empty or well-formed, and every
    partition must start after sector 0, not overlap another, and lie inside
    the image. Returns {kind, partitions, length} or None.
    """
    if len(data) < SECTOR * 2 or data[510:512] != b"\x55\xaa":
        return None
    partitions, spans = [], []
    for index in range(4):
        entry = data[446 + index * 16:462 + index * 16]
        if entry == b"\0" * 16:
            continue
        boot, kind = entry[0], entry[4]
        start, count = struct.unpack_from("<II", entry, 8)
        if boot not in (0, 0x80) or kind == 0 or start == 0 or count == 0:
            return None
        if (start + count) * SECTOR > len(data) + SECTOR:
            return None
        spans.append((start, start + count))
        partitions.append({"index": index + 1, "type": kind,
                           "name": MBR_TYPES.get(kind, f"type 0x{kind:02x}"),
                           "offset": start * SECTOR, "length": count * SECTOR})
    if not partitions:
        return None
    spans.sort()
    if any(a[1] > b[0] for a, b in zip(spans, spans[1:])):
        return None
    table = {"kind": "MBR", "partitions": partitions, "length": SECTOR}
    if any(p["type"] == 0xEE for p in partitions) and data[512:520] == b"EFI PART":
        entries_lba, count, size = struct.unpack_from("<QII", data, 512 + 72)
        gpt = []
        if 128 <= size <= 1024 and count <= 256:
            for index in range(count):
                at = entries_lba * SECTOR + index * size
                entry = data[at:at + size]
                if len(entry) < 128 or entry[:16] == b"\0" * 16:
                    continue
                first, last = struct.unpack_from("<QQ", entry, 32)
                name = entry[56:128].decode("utf-16-le", "replace").split("\0")[0]
                gpt.append({"index": index + 1, "type": entry[:16].hex(),
                            "name": name or "unnamed", "offset": first * SECTOR,
                            "length": (last - first + 1) * SECTOR})
            table = {"kind": "GPT", "partitions": gpt,
                     "length": (entries_lba * SECTOR + count * size)}
    return table


def _microcode_segments(data, say, covered=(), parent=None):
    """A segment for every Intel microcode update in `data`.

    Microcode is encrypted, so judged by its bytes it reads as an opaque
    region - in a real BIOS, a false "could not be analysed". Recognised by
    its header, it is a component with a CPUID and a revision, which is what
    CPU advisories are written against.
    """
    segments = []
    for update in microcode.scan(data):
        start, end = update["offset"], update["offset"] + update["size"]
        if any(s <= start < e for s, e in covered):
            continue
        label = (f"Intel microcode {update['fms']} revision "
                 f"0x{update['revision']:x} ({update['date']})")
        say(f"container: {label}, CPUID 0x{update['cpuid']:x}, "
            f"platforms 0x{update['platforms']:x}"
            + (f", plus {len(update['extended'])} more CPUID(s)"
               if update["extended"] else ""))
        if parent is None:
            segments.append(_segment("microcode", start, end - start, label,
                                     content=data[start:end], expanded=False,
                                     microcode=update))
        else:
            segments.append(_segment(
                "microcode", parent["offset"], end - start,
                f"{label} (inside {parent['label']})",
                content=data[start:end], expanded=False, microcode=update))
    return segments


def walk(data, verbose=False, log=None, _inside_ubi=False, _depth=0):
    """Segment a firmware image. Returns (segments, warnings).

    Segments are returned in image order. Each carries `content` - the bytes
    to analyse for that region, decompressed where we could - or None with a
    warning saying why not.
    """
    say = log or (lambda *_a, **_k: None)
    segments, warnings = [], []
    covered = []                                # (start, end) already claimed

    def claim(start, end):
        covered.append((start, end))

    # --- 0. A PC BIOS, which is a structure rather than a blob -------------
    firmware = uefi.detect(data)
    if firmware:
        segments = _uefi_segments(data, firmware, say)
        segments.extend(_microcode_segments(data, say))
        for expanded in [s for s in segments if s["kind"] == "uefi-expanded"]:
            segments.extend(_microcode_segments(expanded["content"], say,
                                                parent=expanded))
        segments.sort(key=lambda seg: seg["offset"])
        return segments, warnings

    # --- 0. Espressif, which is neither a flat image nor a Linux one -------
    espressif = esp32.detect(data)
    if espressif:
        segments = _espressif_segments(data, espressif, say)
        segments.sort(key=lambda seg: seg["offset"])
        return segments, warnings

    # --- 0.5 A vendor's own wrapper round the front -------------------------
    # Only the header is claimed. Everything behind it is firmware this walk
    # already knows how to read, so the kernel scan and the filesystem scan do
    # the rest exactly as they would for a bare image - which is the whole
    # reason these wrappers are cheap to support.
    chain = vendor_container.detect_chain(data)
    for index, found in enumerate(chain):
        detail = found.get("board") or found["vendors"]
        say(f"container: {found['label']} header ({detail})")
        for part in found["parts"]:
            say(f"container:   {part['name']} at 0x{part['offset']:x}, "
                f"{part['length']} bytes")
        for note in found["notes"]:
            say(f"container:   {note}")
        start, end = found["offset"], found["offset"] + found["header_length"]
        segments.append(_segment(
            "vendor-header", start, end - start,
            f"{found['label']} header",
            content=data[start:end], expanded=False,
            **({"vendor_container": chain} if index == 0 else {})))
        claim(start, end)

    # --- 0.6 OpenWrt's metadata, appended to the end of a sysupgrade image --
    trailer = None if _inside_ubi else vendor_container.read_openwrt_metadata(data)
    if trailer:
        version = (trailer["metadata"] or {}).get("version") or {}
        described = " ".join(str(version[k]) for k in ("dist", "version", "revision")
                             if version.get(k)) or "metadata not parsed"
        board = version.get("board")
        say(f"container: OpenWrt image metadata: {described}"
            + (f", board {board}" if board else "")
            + (", signature block present" if trailer["signature_block"] else ""))
        start = trailer["start"]
        segments.append(_segment(
            "image-metadata", start, len(data) - start,
            f"OpenWrt image metadata ({described}"
            + (f", board {board})" if board else ")"),
            content=data[start:], expanded=False,
            openwrt_metadata=trailer["metadata"]))
        claim(start, len(data))

    # --- 0.65 A partition table: an eMMC dump or a disk image --------------
    table = parse_partition_table(data)
    if table:
        described = ", ".join(f"{p['name']} at 0x{p['offset']:x}"
                              for p in table["partitions"])
        say(f"container: {table['kind']} partition table, "
            f"{len(table['partitions'])} partition(s): {described}")
        segments.append(_segment(
            "partition-table", 0, table["length"],
            f"{table['kind']} partition table ({len(table['partitions'])} "
            "partition(s))", content=data[:table["length"]], expanded=False,
            partition_table=table))
        claim(0, table["length"])

    # --- 0.7 FIT images: a boot container that documents itself ------------
    for offset in fit.find_offsets(data):
        if any(s <= offset < e for s, e in covered):
            continue
        try:
            image = fit.read_fit(data, offset)
        except fit.FITError:
            continue
        segments.extend(_fit_segments(data, image, say, warnings, claim))

    # --- 1. A boot header at offset 0 ---------------------------------------
    header = parse_uimage(data)
    if header:
        say(f"container: u-boot uImage, {header['os']}/{header['architecture']}, "
            f"{header['compression'] or 'uncompressed'} payload of "
            f"{header['payload_size']} bytes")
        say(f"container:   header name: {header['name']!r}")
        segments.append(_segment(
            "boot-header", 0, UIMAGE_HEADER_SIZE,
            f"U-Boot uImage header ({header['os']}/{header['architecture']})",
            content=data[:UIMAGE_HEADER_SIZE], expanded=False, uimage=header))
        claim(0, UIMAGE_HEADER_SIZE)

        start = header["payload_offset"]
        end = min(len(data), start + header["payload_size"])
        blob = data[start:end]
        kernel, note = blob, None
        if header["compression"]:
            try:
                kernel = _expand(header["compression"], blob)
                say(f"container: kernel expanded {len(blob)} -> {len(kernel)} bytes "
                    f"({header['compression']})")
            except ValueError as e:
                kernel, note = None, str(e)
                warnings.append(f"kernel: {e}")
                say(f"container: kernel NOT expanded: {e}")
        seg = _segment("kernel", start, end - start,
                       f"{header['os']} kernel ({header['compression'] or 'raw'})",
                       content=kernel,
                       # Expanded only if it really was: a kernel whose
                       # decompression failed has no content to have expanded.
                       expanded=bool(header["compression"]) and kernel is not None,
                       uimage=header)
        if note:
            seg["warnings"].append(note)
        segments.append(seg)
        claim(start, end)

    # --- 1.5 UBI, before anything looks for a filesystem ---------------------
    # A SquashFS inside a UBI volume has erase-block headers every 128 KiB of
    # the raw image. Found there by the filesystem scan below, its superblock
    # would open and every read past the first block would return headers
    # instead of data - so UBI claims its region first.
    if not _inside_ubi:
        for offset in ubi.find_offsets(data):
            if any(s <= offset < e for s, e in covered):
                continue
            try:
                image = ubi.read_image(data, offset)
            except ubi.UBIError:
                continue
            segments.extend(_ubi_segments(data, image, verbose, log, say,
                                          warnings))
            claim(offset, image["end"])

    # --- 2. Filesystems anywhere in the image -------------------------------
    for offset in squashfs.find_offsets(data):
        if any(s <= offset < e for s, e in covered):
            continue
        try:
            image = squashfs.SquashFS(data, offset)
        except FILESYSTEM_ERRORS as e:
            # A 4-byte magic hits by chance in 14 MB of compressed data; a
            # superblock that will not open is almost always one of those.
            continue
        end = min(len(data), offset + image.bytes_used)
        say(f"container: SquashFS {image.version_major}.{image.version_minor} at "
            f"0x{offset:x}, {image.compressor}, {image.inode_count} inodes, "
            f"{image.bytes_used} bytes")
        segments.append(_segment(
            "filesystem", offset, end - offset,
            f"SquashFS {image.version_major}.{image.version_minor} "
            f"({image.compressor})",
            content=None, filesystem=image))
        claim(offset, end)
        if len(segments) >= MAX_SEGMENTS:
            break

    for offset in cramfs.find_offsets(data):
        if any(s <= offset < e for s, e in covered):
            continue
        try:
            image = cramfs.CramFS(data, offset)
        except cramfs.CramFSError:
            continue
        end = min(len(data), offset + image.size)
        say(f"container: CramFS at 0x{offset:x}, {image.byte_order}, "
            f"{image.file_count} files, {image.size} bytes")
        segments.append(_segment(
            "filesystem", offset, end - offset,
            f"CramFS ({image.byte_order})",
            content=None, filesystem=image))
        claim(offset, end)
        if len(segments) >= MAX_SEGMENTS:
            break

    for offset in ubifs.find_offsets(data):
        if any(s <= offset < e for s, e in covered):
            continue
        try:
            image = ubifs.UBIFS(data, offset)
        except ubifs.UBIFSError:
            continue
        end = min(len(data), offset + image.leb_count * image.leb_size)
        say(f"container: UBIFS at 0x{offset:x}, {image.leb_count} logical "
            f"blocks of {image.leb_size} bytes, {image.default_compressor}")
        for note in image.warnings:
            say(f"container:   {note}")
        segments.append(_segment(
            "filesystem", offset, end - offset, "UBIFS",
            content=None, filesystem=image))
        claim(offset, end)
        if len(segments) >= MAX_SEGMENTS:
            break

    # ext2/3/4 - the rootfs wherever firmware lives on a block device.
    for offset in ext.find_offsets(data):
        if any(s <= offset < e for s, e in covered):
            continue
        try:
            image = ext.Ext(data, offset)
        except ext.ExtError:
            continue
        end = min(len(data), offset + image.size)
        say(f"container: {image.version} at 0x{offset:x}, "
            f"{image.block_size}-byte blocks, {image.size} bytes"
            + (f", volume {image.volume_name!r}" if image.volume_name else ""))
        for note in image.warnings:
            say(f"container:   {note}")
        segments.append(_segment(
            "filesystem", offset, end - offset,
            f"{image.version}" + (f" '{image.volume_name}'" if image.volume_name
                                  else ""),
            content=None, filesystem=image))
        claim(offset, end)
        if len(segments) >= MAX_SEGMENTS:
            break

    # YAFFS: raw NAND pages with their spare areas, geometry found by trial.
    for offset in yaffs.find_offsets(data):
        if any(s <= offset < e for s, e in covered):
            continue
        try:
            image = yaffs.YAFFS(data, offset)
        except yaffs.YAFFSError:
            continue
        say(f"container: {image.geometry.label()} at 0x{offset:x}, "
            f"{len(image.objects)} objects, {image.end - offset} bytes")
        segments.append(_segment(
            "filesystem", offset, image.end - offset,
            f"YAFFS{image.geometry.version} ({image.byte_order})",
            content=None, filesystem=image))
        claim(offset, image.end)
        if len(segments) >= MAX_SEGMENTS:
            break

    # JFFS2 has no superblock: a stream is wherever nodes with valid header
    # CRCs begin, and it ends where the last of them does. On a device dump it
    # is usually the writable overlay sitting after a read-only rootfs.
    for offset in jffs2.find_offsets(data):
        if any(s <= offset < e for s, e in covered):
            continue
        try:
            image = jffs2.JFFS2(data, offset)
        except jffs2.JFFS2Error:
            continue
        end = image.last_node_end
        say(f"container: JFFS2 at 0x{offset:x}, {image.byte_order}, "
            f"{image.node_count} nodes, {end - offset} bytes")
        segments.append(_segment(
            "filesystem", offset, end - offset,
            f"JFFS2 ({image.byte_order})",
            content=None, filesystem=image))
        claim(offset, end)
        if len(segments) >= MAX_SEGMENTS:
            break

    # --- 3. Compressed regions that are not part of anything above ----------
    for magic, algorithm in SCAN_MAGICS:
        at = data.find(magic)
        while at != -1 and len(segments) < MAX_SEGMENTS:
            if not any(s <= at < e for s, e in covered):
                try:
                    expanded = _expand(algorithm, data[at:])
                except ValueError:
                    expanded = None
                # A stray magic inside compressed data expands to nothing
                # useful; require a result big enough to be a real region.
                if expanded and len(expanded) >= 1024:
                    say(f"container: {algorithm} region at 0x{at:x} expanded to "
                        f"{len(expanded)} bytes")
                    archive = None
                    if cpio.looks_like_cpio(expanded):
                        try:
                            archive = cpio.CPIO(expanded)
                        except cpio.CPIOError:
                            archive = None
                    nested = None
                    if archive is None and _depth == 0:
                        nested = _nested_segments(
                            expanded, at, f"{algorithm} region at 0x{at:x}",
                            verbose, log, warnings, _inside_ubi, _depth)
                    if archive is not None:
                        say(f"container:   an initramfs, {len(archive.entries)} "
                            "entries")
                        segments.append(_cpio_segment(
                            archive, at, len(data) - at,
                            f"initramfs (cpio, {algorithm})",
                            algorithm=algorithm))
                    elif nested:
                        say(f"container:   the expanded data is itself an image: "
                            f"{len(nested)} segment(s) inside")
                        segments.extend(nested)
                    else:
                        segments.append(_segment(
                            "compressed", at, len(data) - at,
                            f"{algorithm} region", content=expanded,
                            algorithm=algorithm))
                    claim(at, len(data))
                    break
            at = data.find(magic, at + 1)

    # --- 3.5 An initramfs built into an expanded kernel ---------------------
    for segment in list(segments):
        if segment["kind"] not in ("kernel", "compressed", "fit-image") \
                or not segment.get("expanded") or not segment["content"]:
            continue
        found = _find_initramfs(segment["content"])
        if found is None:
            continue
        archive, where = found
        say(f"container: initramfs inside {segment['label']} ({where}), "
            f"{len(archive.entries)} entries")
        segments.append(_cpio_segment(
            archive, segment["offset"], segment["length"],
            f"initramfs (cpio) inside {segment['label']}"))

    # --- 3.7 CPU microcode, anywhere not already read as a filesystem -------
    microcode_found = _microcode_segments(data, say, covered)
    for segment in microcode_found:
        claim(segment["offset"], segment["offset"] + segment["length"])
    for segment in [s for s in segments if s.get("expanded") and s["content"]]:
        microcode_found.extend(_microcode_segments(segment["content"], say,
                                                   parent=segment))
    segments.extend(microcode_found)

    # --- 4. Whatever is left ------------------------------------------------
    segments.sort(key=lambda s: s["offset"])
    covered.sort()
    position, gaps = 0, []
    for start, end in covered:
        if start > position:
            gaps.append((position, start))
        position = max(position, end)
    if position < len(data):
        gaps.append((position, len(data)))
    for start, end in gaps:
        if end - start < 512:
            continue
        # expanded=False because this is a slice of the input, not something
        # we expanded. Marking it expanded tells the opacity judgement "we read
        # this whatever it scored", which turned every encrypted region that
        # was not inside a recognised container into "plaintext" - the exact
        # failure this tool exists to prevent, on the commonest path of all.
        segments.append(_segment("unclaimed", start, end - start,
                                 "unidentified region", expanded=False,
                                 content=data[start:end]))

    segments.sort(key=lambda s: s["offset"])
    return segments, warnings


# --------------------------------------------------------------------------- #
# Root filesystem contents
# --------------------------------------------------------------------------- #

def _read_text(image, files, path, limit=4 * 1024 * 1024):
    node = files.get(path)
    if not node or node.get("size", 0) > limit:
        return None
    try:
        return image.read_file(node).decode("utf-8", "replace")
    except FILESYSTEM_ERRORS:
        return None


def _parse_control_blocks(text):
    """Blocks of 'Field: value' lines, as opkg and dpkg both write them."""
    blocks = []
    for chunk in re.split(r"\n\s*\n", text):
        fields = {}
        key = None
        for line in chunk.splitlines():
            match = re.match(r"^([A-Za-z][A-Za-z0-9-]*):[ \t]*(.*)$", line)
            if match:
                key = match.group(1)
                fields[key] = match.group(2).strip()
            elif key and line.startswith((" ", "\t")):
                fields[key] += " " + line.strip()
        if fields:
            blocks.append(fields)
    return blocks


def _parse_apk_installed(text):
    """apk's database uses single-letter keys: P: name, V: version."""
    packages = []
    for chunk in re.split(r"\n\s*\n", text):
        fields = dict(re.findall(r"^([A-Za-z]):(.*)$", chunk, re.M))
        if fields.get("P"):
            packages.append({"Package": fields["P"].strip(),
                             "Version": fields.get("V", "").strip(),
                             "Architecture": fields.get("A", "").strip()})
    return packages


# The status file is a summary; the per-package control records carry more.
# On OpenWrt they add the declared licence, the upstream source package, the
# declared dependencies, and - for the packages that matter to a CVE feed -
# a CPE the build system assigned itself. Reading a declared identifier is not
# the same as inventing one: this is the vendor stating what the package is.
CONTROL_DIRS = {
    "opkg": "/usr/lib/opkg/info/",
    "dpkg": "/var/lib/dpkg/info/",
}


def read_package_controls(image, files, manager):
    """{package: {License, CPE-ID, Depends, Source, ...}} from control files."""
    directory = CONTROL_DIRS.get(manager)
    controls = {}
    if not directory:
        return controls
    for path, _node in files.items():
        if not (path.startswith(directory) and path.endswith(".control")):
            continue
        text = _read_text(image, files, path, limit=256 * 1024)
        if not text:
            continue
        blocks = _parse_control_blocks(text)
        if not blocks:
            continue
        fields = blocks[0]
        name = fields.get("Package") or path[len(directory):-len(".control")]
        controls[name] = fields
    return controls


def _split_depends(value):
    """Dependency names from a Depends field, dropping version constraints."""
    names = []
    for item in (value or "").split(","):
        item = item.strip()
        if not item:
            continue
        names.append(item.split("(")[0].split()[0].strip())
    return [n for n in names if n]


def read_package_database(image, files):
    """Installed packages with exact versions, from the on-image database.

    This is the difference between a Linux firmware SBOM that is worth
    something and one that is not. A version banner in a binary is a heuristic;
    this file is the package manager's own record of what was installed.
    """
    for path, manager, purl_type in PACKAGE_DATABASES:
        text = _read_text(image, files, path)
        if not text:
            continue
        blocks = (_parse_apk_installed(text) if manager == "apk"
                  else _parse_control_blocks(text))
        packages = []
        for fields in blocks:
            name = fields.get("Package")
            version = fields.get("Version")
            if not name:
                continue
            # dpkg keeps removed-but-not-purged packages in the same file.
            status = fields.get("Status", "")
            if status and "installed" not in status:
                continue
            packages.append({
                "name": name,
                "version": version or None,
                "architecture": fields.get("Architecture") or None,
                "description": (fields.get("Description")
                                or f"{manager} package {name}"),
                "purl_type": purl_type,
                "manager": manager,
                "source_path": path,
            })
        if not packages:
            continue
        controls = read_package_controls(image, files, manager)
        for package in packages:
            fields = controls.get(package["name"])
            if not fields:
                continue
            package["license"] = fields.get("License") or None
            package["cpe"] = _normalise_cpe(fields.get("CPE-ID"),
                                            package["version"])
            package["source"] = fields.get("SourceName") or fields.get("Source")
            package["depends"] = _split_depends(fields.get("Depends"))
            if fields.get("Description") and not package["description"]:
                package["description"] = fields["Description"]
        return {"manager": manager, "path": path, "packages": packages,
                "controls": len(controls)}
    return None


def _normalise_cpe(declared, version):
    """Turn a declared CPE 2.2 URI into a 2.3 name, keeping the version.

    OpenWrt writes CPE 2.2 ("cpe:/a:openssl:openssl"). Consumers generally
    want 2.3. The vendor, product and part come from the declaration; only the
    version is filled in from the installed package, and only when the
    declaration does not already carry one.
    """
    if not declared or not declared.startswith("cpe:/"):
        return None
    parts = declared[len("cpe:/"):].split(":")
    part = parts[0] if parts else "a"
    vendor = parts[1] if len(parts) > 1 and parts[1] else "*"
    product = parts[2] if len(parts) > 2 and parts[2] else "*"
    declared_version = parts[3] if len(parts) > 3 and parts[3] else None
    # The package version carries a downstream revision ("1.1.1t-2"); the
    # upstream part before the last dash is what a CVE feed matches on.
    use = declared_version or (version or "").rsplit("-", 1)[0] or "*"
    return f"cpe:2.3:{part}:{vendor}:{product}:{use}:*:*:*:*:*:*:*"


def read_os_release(image, files):
    """Distribution identity from an os-release style file."""
    for path in OS_RELEASE_FILES:
        text = _read_text(image, files, path, limit=64 * 1024)
        if not text:
            continue
        fields = {}
        for match in re.finditer(r"^([A-Z_]+)=['\"]?([^'\"\n]*)['\"]?$",
                                 text, re.M):
            fields[match.group(1)] = match.group(2)
        name = fields.get("DISTRIB_ID") or fields.get("NAME")
        version = (fields.get("DISTRIB_RELEASE") or fields.get("VERSION_ID")
                   or fields.get("VERSION"))
        if name:
            return {"path": path, "name": name, "version": version or None,
                    "revision": fields.get("DISTRIB_REVISION"),
                    "target": fields.get("DISTRIB_TARGET"),
                    "architecture": fields.get("DISTRIB_ARCH"),
                    "description": (fields.get("DISTRIB_DESCRIPTION")
                                    or fields.get("PRETTY_NAME") or name),
                    "fields": fields}
    return None


# --------------------------------------------------------------------------- #
# Binaries inside the root filesystem
# --------------------------------------------------------------------------- #

# A rootfs has a few hundred ELFs; the caps stop a crafted image turning this
# into an unbounded amount of work.
MAX_BINARIES = 4000
MAX_SCANNED_BYTES = 192 * 1024 * 1024


def read_package_file_lists(image, files, manager):
    """{file path: package name}, from the package manager's own file lists.

    opkg and dpkg both record which files each package installed. That mapping
    is what lifts a DT_NEEDED edge between two files into a dependency between
    two packages - which is the form an SBOM actually wants.
    """
    owners = {}
    if manager == "opkg":
        prefix, suffix = "/usr/lib/opkg/info/", ".list"
    elif manager == "dpkg":
        prefix, suffix = "/var/lib/dpkg/info/", ".list"
    else:
        return owners
    for path, node in files.items():
        if not (path.startswith(prefix) and path.endswith(suffix)):
            continue
        package = path[len(prefix):-len(suffix)].split(":")[0]
        text = _read_text(image, files, path, limit=2 * 1024 * 1024)
        if not text:
            continue
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("/"):
                owners.setdefault(line, package)
    return owners


def analyze_binaries(image, files, package_info=None, verbose=False, log=None,
                     progress=None):
    """Parse every ELF in the filesystem and relate them to each other.

    Returns the instruction set (a Linux image has no vector table to
    recognise, so this is the only place it is stated), the toolchains that
    built the binaries, kernel-module metadata, and the dependency edges.
    """
    say = log or (lambda *_a, **_k: None)
    machines = collections.Counter()
    toolchains = collections.Counter()
    providers = {}            # soname or filename -> path that provides it
    binaries = []
    modules = []
    warnings = []
    scanned = 0
    report = progress or (lambda *_a, **_k: None)
    listing = sorted(files.items())

    for position, (path, node) in enumerate(listing, 1):
        report(position / len(listing),
               {"kind": "binaries", "index": position, "count": len(listing)})
        if len(binaries) >= MAX_BINARIES or scanned > MAX_SCANNED_BYTES:
            warnings.append("stopped reading binaries at the configured cap")
            break
        size = node.get("size", 0)
        if size < 64:
            continue
        try:
            blob = image.read_file(node)
        except FILESYSTEM_ERRORS as e:
            warnings.append(f"{path}: {e}")
            continue
        scanned += len(blob)
        if not elf.looks_like_elf(blob[:20]):
            continue
        info = elf.parse(blob)
        if not info:
            continue

        machines[(info["machine"], info["class"], info["endian"])] += 1
        if info["comment"]:
            toolchains[info["comment"]] += 1

        name = path.rsplit("/", 1)[-1]
        providers.setdefault(name, path)
        if info["soname"]:
            providers.setdefault(info["soname"], path)
        key = elf.soname_key(info["soname"] or name)
        if key:
            providers.setdefault(key, path)

        binaries.append({"path": path, "needed": info["needed"],
                         "soname": info["soname"], "type": info["type"]})
        if info["modinfo"]:
            modules.append({
                "path": path,
                "name": info["modinfo"].get("name") or name,
                "version": info["modinfo"].get("version"),
                "license": info["modinfo"].get("license"),
                "description": info["modinfo"].get("description"),
            })

    architecture = None
    if machines:
        (machine, width, endian), count = machines.most_common(1)[0]
        architecture = f"{machine} ({width}-bit {endian}-endian)"
        say(f"rootfs: {len(binaries)} ELF binaries, {architecture} "
            f"({count}/{len(binaries)})")

    # --- DT_NEEDED, lifted from files to packages where we can ------------
    owners = {}
    if package_info:
        owners = read_package_file_lists(image, files, package_info["manager"])
        if owners:
            say(f"rootfs: {len(owners)} files attributed to packages")

    file_edges = 0
    package_edges = collections.defaultdict(set)
    unresolved = collections.Counter()
    for binary in binaries:
        source_package = owners.get(binary["path"])
        for needed in binary["needed"]:
            target = (providers.get(needed)
                      or providers.get(elf.soname_key(needed)))
            if target is None:
                unresolved[needed] += 1
                continue
            file_edges += 1
            target_package = owners.get(target)
            if (source_package and target_package
                    and source_package != target_package):
                package_edges[source_package].add(target_package)

    if file_edges:
        say(f"rootfs: {file_edges} library dependencies resolved"
            + (f", {sum(len(v) for v in package_edges.values())} package edges"
               if package_edges else ""))
    if unresolved:
        # Usually the C library's own internal names, or a library the vendor
        # left out of the image. Worth recording, not worth a warning each.
        warnings.append(
            f"{len(unresolved)} library name(s) referenced but not present in "
            f"the image, e.g. {', '.join(list(unresolved)[:4])}")

    return {
        "architecture": architecture,
        "machines": dict(machines),
        "binary_count": len(binaries),
        "toolchains": dict(toolchains),
        "modules": modules,
        "file_owners": owners,
        "file_dependency_count": file_edges,
        "package_dependencies": {k: sorted(v) for k, v in package_edges.items()},
        "unresolved": dict(unresolved),
        "warnings": warnings,
    }


# Directories holding the package manager's own bookkeeping. When a package
# database exists these files describe packages we have already enumerated
# authoritatively, and scanning them is actively harmful: a .control file's
# "Description: The OpenSSL Project is ..." matches the openssl signature and
# produces a version-less component sourced from a text file.
PACKAGE_METADATA_DIRS = ("/usr/lib/opkg/", "/var/lib/opkg/", "/var/lib/dpkg/",
                         "/lib/apk/db/")

# Scanning caps. A rootfs has a few thousand files; these stop a crafted image
# turning a scan into unbounded work.
MAX_SCAN_FILES = 6000
MAX_SCAN_BYTES = 192 * 1024 * 1024
MAX_SCAN_FILE_BYTES = 32 * 1024 * 1024


def unclaimed_files(rootfs, log=None, progress=None):
    """Yield (path, contents) for files no package in the image accounts for.

    The package manager's record is authoritative for the files it covers, so
    those are left alone - piling regex heuristics on top of an exact version
    from the build system can only add noise. What it does not cover is a
    different matter: vendor binaries dropped into the image, statically
    linked blobs, and every file on a device that ships no package database at
    all. That last case is the common one outside OpenWrt, and until now it
    produced no components from the root filesystem whatsoever.
    """
    say = log or (lambda *_a, **_k: None)
    image = rootfs.get("image")
    files = rootfs.get("files") or {}
    owners = (rootfs.get("binaries") or {}).get("file_owners") or {}
    if image is None:
        return

    report = progress or (lambda *_a, **_k: None)
    listing = sorted(files.items())
    scanned = count = skipped = 0
    for position, (path, node) in enumerate(listing, 1):
        report(position / len(listing),
               {"kind": "files", "index": position, "count": len(listing)})
        if count >= MAX_SCAN_FILES or scanned >= MAX_SCAN_BYTES:
            say(f"rootfs: stopped scanning after {count} files")
            return
        if path in owners:
            continue
        if any(path.startswith(d) for d in PACKAGE_METADATA_DIRS):
            continue
        size = node.get("size", 0)
        if size < 16 or size > MAX_SCAN_FILE_BYTES:
            skipped += 1
            continue
        try:
            blob = image.read_file(node)
        except FILESYSTEM_ERRORS as e:
            # Kept, with the reason, so the SBOM can say which files went
            # unread: a file that could not be decompressed is not a file
            # with nothing in it.
            skipped += 1
            rootfs.setdefault("unread_files", {})[path] = {
                "reason": str(e), "size": size}
            say(f"rootfs: {path} could not be read: {e}")
            continue
        scanned += len(blob)
        count += 1
        yield path, blob


def inspect_filesystem(segment, verbose=False, log=None, progress=None):
    """Read what an on-image filesystem can tell us about its contents."""
    say = log or (lambda *_a, **_k: None)
    image = segment.get("filesystem")
    if image is None:
        return None
    try:
        files = segment.get("files") or image.files()
    except FILESYSTEM_ERRORS as e:
        segment["warnings"].append(f"filesystem could not be walked: {e}")
        return None
    segment["warnings"].extend(image.warnings)

    packages = read_package_database(image, files)
    os_release = read_os_release(image, files)
    if os_release:
        say(f"rootfs: {os_release['description']}")
    if packages:
        say(f"rootfs: {len(packages['packages'])} packages from "
            f"{packages['path']} ({packages['manager']})")
    else:
        say("rootfs: no package database found")

    binaries = analyze_binaries(image, files, packages, verbose, say,
                                progress=progress)
    segment["warnings"].extend(binaries["warnings"])

    return {"image": image, "files": files, "packages": packages,
            "os_release": os_release, "file_count": len(files),
            "binaries": binaries, "segment": segment}
