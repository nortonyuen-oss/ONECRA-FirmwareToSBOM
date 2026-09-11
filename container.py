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
import lzma
import re
import struct
import zlib

import squashfs

# A decompressed region is capped so a crafted image cannot exhaust memory.
MAX_EXPANDED = 256 * 1024 * 1024
MAX_SEGMENTS = 64

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


def _segment(kind, offset, length, label, content=None, **extra):
    seg = {"kind": kind, "offset": offset, "length": length, "label": label,
           "content": content, "expanded": content is not None,
           "warnings": []}
    seg.update(extra)
    return seg


def walk(data, verbose=False, log=None):
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
            content=data[:UIMAGE_HEADER_SIZE], uimage=header))
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
                       content=kernel, uimage=header)
        if note:
            seg["warnings"].append(note)
        segments.append(seg)
        claim(start, end)

    # --- 2. Filesystems anywhere in the image -------------------------------
    for offset in squashfs.find_offsets(data):
        if any(s <= offset < e for s, e in covered):
            continue
        try:
            image = squashfs.SquashFS(data, offset)
        except squashfs.SquashFSError as e:
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
                    segments.append(_segment(
                        "compressed", at, len(data) - at,
                        f"{algorithm} region", content=expanded,
                        algorithm=algorithm))
                    claim(at, len(data))
                    break
            at = data.find(magic, at + 1)

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
        segments.append(_segment("unclaimed", start, end - start,
                                 "unidentified region",
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
    except squashfs.SquashFSError:
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
        if packages:
            return {"manager": manager, "path": path, "packages": packages}
    return None


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


def inspect_filesystem(segment, verbose=False, log=None):
    """Read what an on-image filesystem can tell us about its contents."""
    say = log or (lambda *_a, **_k: None)
    image = segment.get("filesystem")
    if image is None:
        return None
    try:
        files = image.files()
    except squashfs.SquashFSError as e:
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

    return {"image": image, "files": files, "packages": packages,
            "os_release": os_release, "file_count": len(files)}
