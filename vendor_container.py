#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vendor_container - recognise the wrappers router and camera vendors ship.

A consumer router's firmware download is rarely a bare image. It is an image
with a vendor's own header bolted on the front: a magic, a length, a checksum,
a board identifier, sometimes a signature. The header is small and the payload
behind it is the firmware we already know how to read - so the only thing
standing between a `.trx` file and a full SBOM is knowing to skip 32 bytes.

That is why this module is deliberately thin. It does not extract anything: it
names the container, records what the header states, and marks the header's
bytes as accounted for. Everything after that is the existing walk - the
compressed-region scan finds the kernel, the filesystem scan finds the rootfs.
Re-implementing either here would be duplicating work that is already correct.

Two things it will not do:

  * **Guess a payload offset.** A header whose layout we cannot read from the
    sample is reported as recognised-but-unparsed rather than sliced at a
    plausible-looking boundary. A wrong offset does not fail loudly; it shifts
    every subsequent finding by a few bytes and quietly produces nonsense.

  * **Pretend an encrypted payload is readable.** D-Link's SHRS images are
    encrypted on real devices. Naming the container does not change that, and
    the payload still reaches the opacity judgement, which reports it as
    unreadable - which is the true answer.

Developed against the format samples published by the unblob project (MIT),
which cover both TRX revisions, Netgear's CHK, D-Link's SHRS, Instar's BNEG
and Moxa's FRM.
"""

import struct

# --- Broadcom TRX ---------------------------------------------------------- #
# The format behind a large share of consumer routers - Netgear, Linksys, Asus,
# Buffalo and the OpenWrt builds for them. Revision 1 names three parts,
# revision 2 four; part 0 is the kernel and part 1 the root filesystem.
TRX_MAGIC = b"HDR0"
TRX_MAX_PARTS = 4

# --- Netgear CHK ----------------------------------------------------------- #
# A board-identifying wrapper that, on a real device, contains a TRX.
CHK_MAGIC = 0x2A23245E          # "*#$^", big-endian
CHK_MAX_HEADER = 512

# --- D-Link SHRS ----------------------------------------------------------- #
# Fixed 1,756-byte header carrying two big-endian payload sizes, an IV and
# digests. The payload is AES-encrypted on shipping devices.
SHRS_MAGIC = b"SHRS"
SHRS_HEADER_SIZE = 1756

# --- Instar BNEG ----------------------------------------------------------- #
# An IP-camera vendor's container: magic, two counters, then length-prefixed
# parts. Cameras are a firmware class we are otherwise short of.
BNEG_MAGIC = b"BNEG"
BNEG_HEADER_SIZE = 20

# --- Moxa FRM -------------------------------------------------------------- #
# Industrial gateways. The word at offset 8 is the total file length, which is
# what makes the magic safe to trust.
FRM_MAGIC = b"*FRM"

MAX_IMAGE = 512 * 1024 * 1024


def _plausible(value, limit):
    return isinstance(value, int) and 0 < value <= limit


def parse_trx(data):
    """A Broadcom TRX header, or None."""
    if len(data) < 28 or data[:4] != TRX_MAGIC:
        return None
    length, crc32, flag_version = struct.unpack_from("<III", data, 4)
    flags, version = flag_version & 0xFFFF, flag_version >> 16
    if version not in (1, 2):
        return None
    count = 4 if version == 2 else 3
    header_size = 16 + count * 4
    if len(data) < header_size:
        return None
    # The declared length covers the header and everything after it. A stray
    # "HDR0" inside compressed data almost never satisfies that.
    if not _plausible(length, min(len(data), MAX_IMAGE)) or length < header_size:
        return None

    offsets = struct.unpack_from(f"<{count}I", data, 16)
    parts, names = [], ("kernel", "root filesystem", "part 2", "part 3")
    for index, offset in enumerate(offsets):
        if not offset:                       # an unused slot, not an error
            continue
        if not header_size <= offset < length:
            return None
        following = [o for o in offsets[index + 1:] if o > offset]
        end = min(following) if following else length
        parts.append({"index": index, "name": names[index],
                      "offset": offset, "length": end - offset})
    if not parts:
        return None
    return {
        "format": "trx",
        "label": f"Broadcom TRX v{version}",
        "vendors": "Netgear, Linksys, Asus, Buffalo and OpenWrt builds for them",
        "header_length": header_size,
        "declared_length": length,
        "crc32": crc32,
        "flags": flags,
        "version": version,
        "parts": parts,
        "notes": [],
    }


def parse_chk(data):
    """A Netgear CHK header, or None. On a device it wraps a TRX."""
    if len(data) < 40:
        return None
    magic, header_length = struct.unpack_from(">II", data, 0)
    if magic != CHK_MAGIC:
        return None
    if not 40 <= header_length <= min(CHK_MAX_HEADER, len(data)):
        return None
    board_length, = struct.unpack_from(">I", data, 8)
    board = None
    if 0 < board_length <= 64 and 40 + board_length <= len(data):
        board = data[40:40 + board_length].split(b"\x00")[0].decode(
            "ascii", "replace").strip() or None
    kernel_length, rootfs_length = struct.unpack_from(">II", data, 12)
    return {
        "format": "chk",
        "label": "Netgear CHK",
        "vendors": "Netgear",
        "header_length": header_length,
        "board": board,
        "declared_kernel_length": kernel_length,
        "declared_rootfs_length": rootfs_length,
        "parts": [{"index": 0, "name": "payload", "offset": header_length,
                   "length": len(data) - header_length}],
        "notes": [],
    }


def parse_shrs(data):
    """A D-Link SHRS header, or None.

    The two big-endian sizes at offsets 4 and 8 have to agree with the file for
    this to be believed - the magic alone is four bytes of ASCII.
    """
    if len(data) < SHRS_HEADER_SIZE + 16 or data[:4] != SHRS_MAGIC:
        return None
    payload_size, decrypted_size = struct.unpack_from(">II", data, 4)
    if not _plausible(payload_size, MAX_IMAGE):
        return None
    if SHRS_HEADER_SIZE + payload_size > len(data):
        return None
    return {
        "format": "shrs",
        "label": "D-Link SHRS",
        "vendors": "D-Link",
        "header_length": SHRS_HEADER_SIZE,
        "declared_length": payload_size,
        "decrypted_length": decrypted_size,
        "parts": [{"index": 0, "name": "payload", "offset": SHRS_HEADER_SIZE,
                   "length": payload_size}],
        "notes": ["SHRS payloads are AES-encrypted on shipping devices; "
                  "naming the container does not make the payload readable, "
                  "and it is judged on its own bytes like any other region"],
    }


def parse_bneg(data):
    """An Instar BNEG container, or None."""
    if len(data) < BNEG_HEADER_SIZE or data[:4] != BNEG_MAGIC:
        return None
    _a, _b, first, second = struct.unpack_from("<IIII", data, 4)
    if not _plausible(first, len(data)):
        return None
    if BNEG_HEADER_SIZE + first > len(data):
        return None
    parts = [{"index": 0, "name": "part 0",
              "offset": BNEG_HEADER_SIZE, "length": first}]
    at = BNEG_HEADER_SIZE + first
    if second and at + second <= len(data):
        parts.append({"index": 1, "name": "part 1",
                      "offset": at, "length": second})
    return {
        "format": "bneg",
        "label": "Instar BNEG",
        "vendors": "Instar IP cameras",
        "header_length": BNEG_HEADER_SIZE,
        "parts": parts,
        "notes": [],
    }


def parse_frm(data):
    """A Moxa FRM header, or None. Offset 8 states the whole file's length."""
    if len(data) < 16 or data[:4] != FRM_MAGIC:
        return None
    version, = struct.unpack_from(">I", data, 4)
    declared, = struct.unpack_from("<I", data, 8)
    if declared != len(data):
        return None
    return {
        "format": "frm",
        "label": "Moxa FRM",
        "vendors": "Moxa industrial gateways",
        "header_length": 16,
        "declared_length": declared,
        "version": version,
        "parts": [{"index": 0, "name": "payload", "offset": 16,
                   "length": len(data) - 16}],
        "notes": [],
    }


PARSERS = (parse_trx, parse_chk, parse_shrs, parse_bneg, parse_frm)


def detect(data, offset=0):
    """The vendor container at `offset`, or None.

    Only offset 0 is examined by callers today: these headers sit at the front
    of a download. Taking the argument keeps the one nested case - a TRX inside
    a Netgear CHK - readable.
    """
    view = data[offset:] if offset else data
    for parser in PARSERS:
        found = parser(view)
        if found:
            found["offset"] = offset
            for part in found["parts"]:
                part["offset"] += offset
            return found
    return None


def detect_chain(data):
    """Containers all the way down, outermost first.

    Netgear ships a TRX inside a CHK, so stopping at the first header would
    leave the real structure unread.
    """
    chain, at, seen = [], 0, set()
    while len(chain) < 4:
        found = detect(data, at)
        if not found or at in seen:
            break
        seen.add(at)
        chain.append(found)
        inner = [p for p in found["parts"] if p["name"] in ("payload",)]
        if not inner:
            break
        at = inner[0]["offset"]
    return chain


# --- OpenWrt image metadata (fwtool) ---------------------------------------- #
# OpenWrt appends blocks to the *end* of a sysupgrade image, each followed by a
# 16-byte trailer: "FWx0", a CRC, a type (1 metadata, 0 signature) and the
# block's size including the trailer. The metadata is JSON the build system
# wrote - distribution, version, revision, target, board - so it names the
# firmware even when the rootfs cannot be read. The CRC is not checked here:
# fwtool's CRC is not a plain CRC-32 of the block, and a check we have not
# confirmed against a sample would be a claim we cannot back.
FWTOOL_MAGIC = b"FWx0"
FWTOOL_TRAILER = 16
FWTOOL_MAX_BLOCK = 64 * 1024


def read_openwrt_metadata(data):
    """The fwtool blocks at the end of `data`, or None if there are none.

    Returns {start, metadata, signature_block}: `start` is where the blocks
    begin, so
    the walk can account for those bytes; `metadata` is the parsed JSON, or
    None if it would not parse.
    """
    import json

    end, blocks = len(data), []
    while end >= FWTOOL_TRAILER and data[end - FWTOOL_TRAILER:end - 12] == FWTOOL_MAGIC:
        _magic, _crc, kind, size = struct.unpack_from(">4sIB3xI", data,
                                                      end - FWTOOL_TRAILER)
        if not FWTOOL_TRAILER <= size <= min(end, FWTOOL_MAX_BLOCK):
            break
        blocks.append((kind, data[end - size:end - FWTOOL_TRAILER]))
        end -= size
        if len(blocks) > 8:
            break
    if not blocks:
        return None
    metadata = None
    for kind, block in blocks:
        if kind == 1:
            try:
                metadata = json.loads(block.strip(b"\x00").decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                metadata = None
    return {"start": end, "metadata": metadata if isinstance(metadata, dict) else None,
            # A signature block is present; whether it holds a real
            # signature (an unsigned build writes a placeholder) is not judged.
            "signature_block": any(kind == 0 for kind, _ in blocks)}
