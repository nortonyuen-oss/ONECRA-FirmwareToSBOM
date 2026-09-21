#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fit - read U-Boot FIT images (Flattened Image Tree, ".itb").

FIT replaced the legacy uImage on most ARM and on newer MIPS boards: an
OpenWrt image for a MediaTek Filogic router, a Qualcomm IPQ gateway, a great
many cameras. It is a device tree - the same binary format as a .dtb - whose
nodes describe the images the bootloader loads: a kernel, one or more device
trees, a ramdisk, a root filesystem. Each says what it is, for which
architecture, compressed how, and carries its own hashes.

So a FIT is a container that documents itself, and this module only reads
that documentation:

  * **Where each image's bytes are.** Either inside the tree (a `data`
    property) or after it: `data-position` from the start of the FIT, or
    `data-offset` from the end of the tree. OpenWrt's sysupgrade images put
    the data outside, its initramfs images inside; both are read.
  * **What each one is**, declared rather than guessed: `type`, `arch`, `os`,
    `compression`, `description`. The kernel's compression matters in
    practice - a FIT kernel compressed with LZMA may start with properties
    other than the 0x5d a magic scan looks for, and goes unexpanded without
    it.
  * **Whether each image is intact.** The hashes FIT carries (crc32, sha1,
    sha256 and friends) are recomputed. A mismatch is reported: the image was
    damaged or altered after it was built. Signatures are noted but not
    verified - that needs the vendor's public key.

Everything is bounded - depth, node count, property count, every offset -
because the tree is whatever a customer uploaded.

Verified against OpenWrt 23.05.5 release images for the Xiaomi AX3000T, one
with external data and a SquashFS rootfs, one with embedded data and an
initramfs, whose SHA-256 sums match those OpenWrt publishes.
"""

import hashlib
import struct
import zlib

FDT_MAGIC = 0xD00DFEED
FDT_MAGIC_BYTES = struct.pack(">I", FDT_MAGIC)
FDT_BEGIN_NODE, FDT_END_NODE, FDT_PROP, FDT_NOP, FDT_END = 1, 2, 3, 4, 9
HEADER_SIZE = 40

# Hostile-input caps.
MAX_DEPTH = 32
MAX_NODES = 10000
MAX_PROPS = 100000
MAX_IMAGES = 64

# FIT architecture names -> (architecture, label), in the tool's vocabulary.
ARCHITECTURES = {
    "arm": ("arm", "ARM (32-bit)"),
    "arm64": ("arm64", "AArch64 (64-bit)"),
    "mips": ("mips", "MIPS (32-bit)"),
    "mips64": ("mips64", "MIPS64"),
    "x86": ("x86", "x86 (32-bit)"),
    "x86_64": ("x86_64", "x86-64"),
    "riscv": ("riscv", "RISC-V"),
    "powerpc": ("powerpc", "PowerPC"),
}

HASHES = {"crc32": None, "md5": "md5", "sha1": "sha1", "sha256": "sha256",
          "sha384": "sha384", "sha512": "sha512"}


class FITError(Exception):
    pass


def parse_fdt(data, at=0):
    """A flattened device tree at `at`, as nested dicts.

    Each node is {"props": {name: (offset, length)}, "children": {...}}; a
    property is kept as a position rather than a copy, because a FIT's
    `data` property can be many megabytes.
    """
    if at + HEADER_SIZE > len(data):
        raise FITError("too short for a device tree header")
    (magic, total, off_struct, off_strings, _rsv, version, last_comp, _cpu,
     size_strings, size_struct) = struct.unpack_from(">10I", data, at)
    if magic != FDT_MAGIC:
        raise FITError("no device tree magic")
    if version < 16 or last_comp > 17:
        raise FITError(f"device tree version {version} is not supported")
    if not HEADER_SIZE <= total <= len(data) - at:
        raise FITError(f"device tree claims {total} bytes; the data holds "
                       f"{len(data) - at}")
    if (off_struct + size_struct > total or off_strings + size_strings > total
            or off_struct < HEADER_SIZE):
        raise FITError("device tree blocks lie outside it")

    strings = at + off_strings
    p, end = at + off_struct, at + off_struct + size_struct
    root = None
    stack = []
    nodes = props = 0
    while p + 4 <= end:
        token, = struct.unpack_from(">I", data, p)
        p += 4
        if token == FDT_BEGIN_NODE:
            name_end = data.find(b"\0", p, end)
            if name_end == -1:
                raise FITError("unterminated node name")
            name = data[p:name_end].decode("utf-8", "replace")
            p = at + ((name_end + 1 - at + 3) & ~3)
            node = {"props": {}, "children": {}}
            nodes += 1
            if nodes > MAX_NODES or len(stack) >= MAX_DEPTH:
                raise FITError("device tree too large or too deep")
            if stack:
                stack[-1]["children"][name] = node
            elif root is None:
                root = node
            else:
                raise FITError("more than one root node")
            stack.append(node)
        elif token == FDT_END_NODE:
            if not stack:
                raise FITError("unbalanced node end")
            stack.pop()
        elif token == FDT_PROP:
            if p + 8 > end or not stack:
                raise FITError("property outside a node")
            length, nameoff = struct.unpack_from(">II", data, p)
            p += 8
            if p + length > end or nameoff >= size_strings:
                raise FITError("property runs past the tree")
            name_end = data.find(b"\0", strings + nameoff, strings + size_strings)
            if name_end == -1:
                raise FITError("unterminated property name")
            name = data[strings + nameoff:name_end].decode("utf-8", "replace")
            stack[-1]["props"][name] = (p, length)
            props += 1
            if props > MAX_PROPS:
                raise FITError("too many properties")
            p = at + ((p + length - at + 3) & ~3)
        elif token == FDT_NOP:
            continue
        elif token == FDT_END:
            break
        else:
            raise FITError(f"unknown device tree token {token} at 0x{p - 4:x}")
    if root is None or stack:
        raise FITError("device tree structure is incomplete")
    return {"root": root, "total": total}


def _string(data, node, name):
    spot = node["props"].get(name)
    if not spot:
        return None
    raw = data[spot[0]:spot[0] + spot[1]]
    return raw.split(b"\0")[0].decode("utf-8", "replace") or None


def _u32(data, node, name):
    spot = node["props"].get(name)
    if not spot or spot[1] != 4:
        return None
    return struct.unpack_from(">I", data, spot[0])[0]


def _verify(data, node, blob):
    """Recompute every hash the image node declares."""
    results = []
    for child_name, child in node["children"].items():
        if child_name.startswith("signature"):
            results.append({"algo": _string(data, child, "algo") or "signature",
                            "kind": "signature", "ok": None})
            continue
        if not child_name.startswith("hash"):
            continue
        algo = (_string(data, child, "algo") or "").lower()
        spot = child["props"].get("value")
        if not spot or algo not in HASHES:
            results.append({"algo": algo or "unknown", "kind": "hash", "ok": None})
            continue
        expected = data[spot[0]:spot[0] + spot[1]]
        if blob is None:
            actual = None
        elif algo == "crc32":
            actual = struct.pack(">I", zlib.crc32(blob) & 0xFFFFFFFF)
        else:
            actual = hashlib.new(HASHES[algo], blob, usedforsecurity=False).digest()
        results.append({"algo": algo, "kind": "hash", "expected": expected.hex(),
                        "ok": None if actual is None else actual == expected})
    return results


def read_fit(data, at=0):
    """Every image a FIT at `at` describes. Raises FITError if it is not one.

    A plain device tree (a .dtb) has no /images node, and is not a FIT.
    """
    tree = parse_fdt(data, at)
    root = tree["root"]
    images_node = root["children"].get("images")
    if images_node is None:
        raise FITError("a device tree, but not a FIT: no /images node")

    warnings = []
    external_base = at + ((tree["total"] + 3) & ~3)
    images = []
    for name, node in list(images_node["children"].items())[:MAX_IMAGES]:
        spot = node["props"].get("data")
        position, size = None, None
        if spot:
            position, size, placement = spot[0], spot[1], "embedded"
        else:
            size = _u32(data, node, "data-size")
            if _u32(data, node, "data-position") is not None:
                position = at + _u32(data, node, "data-position")
            elif _u32(data, node, "data-offset") is not None:
                position = external_base + _u32(data, node, "data-offset")
            placement = "external"
        blob = None
        if position is None or size is None:
            warnings.append(f"image '{name}' says nowhere where its data is")
        elif position + size > len(data):
            warnings.append(f"image '{name}' claims {size} bytes at 0x{position:x}, "
                            "past the end of the file - the image looks truncated")
        else:
            blob = data[position:position + size]
        checks = _verify(data, node, blob)
        for check in checks:
            if check["ok"] is False:
                warnings.append(f"image '{name}': its {check['algo']} does not "
                                "match its data - damaged or altered after it "
                                "was built")
        images.append({
            "name": name,
            "type": _string(data, node, "type"),
            "arch": _string(data, node, "arch"),
            "os": _string(data, node, "os"),
            "compression": _string(data, node, "compression"),
            "description": _string(data, node, "description"),
            "offset": position, "size": size, "placement": placement,
            "present": blob is not None,
            "checks": checks,
        })
    if not images:
        raise FITError("a FIT with no images")

    configurations = root["children"].get("configurations") or {"props": {},
                                                                "children": {}}
    default = _string(data, configurations, "default")
    header_end = at + tree["total"]
    return {
        "offset": at,
        "header_size": tree["total"],
        "header_end": header_end,
        "description": _string(data, root, "description"),
        "timestamp": _u32(data, root, "timestamp"),
        "images": images,
        "default_configuration": default,
        "end": max([header_end] + [i["offset"] + i["size"] for i in images
                                   if i["present"]]),
        "warnings": warnings,
    }


def declared_architecture(images):
    """The architecture the kernel image declares, as (architecture, label)."""
    for image in images:
        if image["type"] == "kernel" and image["arch"] in ARCHITECTURES:
            return ARCHITECTURES[image["arch"]]
    for image in images:
        if image["arch"] in ARCHITECTURES:
            return ARCHITECTURES[image["arch"]]
    return None


def find_offsets(data, alignment=4, limit=8):
    """Where FIT images begin: a device tree with an /images node.

    A .dtb carried inside a FIT has the same magic and is skipped, both
    because it is not a FIT and because it lies inside one already found.
    """
    found, at = [], 0
    while len(found) < limit:
        at = data.find(FDT_MAGIC_BYTES, at)
        if at == -1:
            return found
        if at % alignment == 0:
            try:
                fit = read_fit(data, at)
            except FITError:
                pass
            else:
                found.append(at)
                at = max(at + 4, fit["end"])
                continue
        at += 4
    return found


def detect(data):
    """A FIT at the start of the image, or None."""
    if data[:4] != FDT_MAGIC_BYTES:
        return None
    try:
        return read_fit(data, 0)
    except FITError:
        return None
