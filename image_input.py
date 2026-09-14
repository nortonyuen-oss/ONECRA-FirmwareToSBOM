#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
image_input - turn whatever the customer was given into a flat firmware image.

A microcontroller toolchain hands its user an `.elf`, and a flashing tool hands
them an `.hex` or an `.s19`. A raw `.bin` is a thing you have to know to ask
for. Until now fw2sbom accepted only the raw form and told everyone else to run
`objcopy` first - which is a step that needs the right cross-toolchain
installed, and which the person holding the firmware often cannot do.

So the four common delivery formats are read directly:

    Intel HEX          text records, 16/20/32-bit addressing
    Motorola S-record  text records, 16/24/32-bit addressing
    UF2               512-byte blocks, used by RP2040 and some Nordic boards
    ELF               the linker's own output; PT_LOAD segments are laid out

All four are *sparse*: they describe regions at addresses, not a contiguous
file. Reassembling them means choosing what goes in the gaps, and the answer is
0xFF, because that is what erased flash reads as - the same thing the device
itself would see. The reconstruction is recorded in the SBOM: offsets in the
evidence then refer to the rebuilt image, and saying which file it was rebuilt
from is the difference between a reproducible finding and a confusing one.

Every parser here reads a file from outside. Malformed input produces an error
that names the line, never a traceback; a record claiming an absurd address is
refused rather than allocating gigabytes.
"""

import re
import struct

import elf

BLANK = 0xFF                       # erased NOR flash
MAX_IMAGE_BYTES = 512 * 1024 * 1024
MAX_TEXT_BYTES = 256 * 1024 * 1024
MAX_GAP_BYTES = 64 * 1024 * 1024   # a gap wider than this means a bad address

UF2_MAGIC_START = 0x0A324655
UF2_MAGIC_SECOND = 0x9E5D5157
UF2_MAGIC_END = 0x0AB16F30
UF2_BLOCK = 512
UF2_NOT_MAIN_FLASH = 0x00000001


class InputFormatError(Exception):
    """The file is in a format we recognise but cannot read."""


# --------------------------------------------------------------------------- #
# Assembling sparse regions
# --------------------------------------------------------------------------- #

class _Sparse:
    """Regions at absolute addresses, flattened on demand."""

    def __init__(self):
        self.chunks = []           # (address, bytes)
        self.total = 0

    def add(self, address, blob):
        if not blob:
            return
        self.total += len(blob)
        if self.total > MAX_IMAGE_BYTES:
            raise InputFormatError(
                f"records describe more than {MAX_IMAGE_BYTES} bytes of data")
        self.chunks.append((address, blob))

    def flatten(self, warnings):
        """One contiguous image, plus the base address it starts at."""
        if not self.chunks:
            raise InputFormatError("no data records found")
        self.chunks.sort(key=lambda pair: pair[0])
        base = self.chunks[0][0]
        end = max(address + len(blob) for address, blob in self.chunks)
        span = end - base
        if span > MAX_IMAGE_BYTES:
            raise InputFormatError(
                f"records span {span} bytes from 0x{base:x} to 0x{end:x}; "
                "refusing to build an image that large")

        image = bytearray([BLANK]) * span
        written = bytearray(span)          # 1 where a record actually wrote
        overlaps = 0
        for address, blob in self.chunks:
            start = address - base
            if any(written[start:start + len(blob)]):
                overlaps += 1
            image[start:start + len(blob)] = blob
            written[start:start + len(blob)] = b"\x01" * len(blob)

        gaps = span - sum(written)
        if overlaps:
            warnings.append(f"{overlaps} record(s) overwrote an address another "
                            "record had already written")
        if gaps:
            biggest = _largest_gap(written)
            if biggest > MAX_GAP_BYTES:
                raise InputFormatError(
                    f"a {biggest}-byte gap between records suggests a bad "
                    "address; refusing to pad it")
            warnings.append(
                f"{gaps} byte(s) between records filled with 0x{BLANK:02X}, "
                "as erased flash reads")
        return bytes(image), base, gaps


def _largest_gap(written):
    biggest = run = 0
    for flag in written:
        run = 0 if flag else run + 1
        biggest = max(biggest, run)
    return biggest


# --------------------------------------------------------------------------- #
# Intel HEX
# --------------------------------------------------------------------------- #

_HEX_LINE = re.compile(rb"^:([0-9A-Fa-f]{2})([0-9A-Fa-f]{4})([0-9A-Fa-f]{2})"
                       rb"([0-9A-Fa-f]*)([0-9A-Fa-f]{2})$")


def looks_like_intel_hex(data):
    head = data[:512].lstrip()
    return head.startswith(b":") and _HEX_LINE.match(head.splitlines()[0] or b"")


def read_intel_hex(data):
    """Intel HEX. Record types 00/01/02/03/04/05."""
    sparse, warnings = _Sparse(), []
    upper = 0                       # from type 04 (linear) or 02 (segment)
    entry = None
    saw_eof = False

    for number, raw in enumerate(data.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        match = _HEX_LINE.match(line)
        if not match:
            raise InputFormatError(f"line {number} is not an Intel HEX record")
        count = int(match.group(1), 16)
        address = int(match.group(2), 16)
        kind = int(match.group(3), 16)
        payload = bytes.fromhex(match.group(4).decode("ascii"))
        checksum = int(match.group(5), 16)

        if len(payload) != count:
            raise InputFormatError(
                f"line {number}: record says {count} bytes, carries {len(payload)}")
        total = count + (address >> 8) + (address & 0xFF) + kind + sum(payload)
        if (-total) & 0xFF != checksum:
            raise InputFormatError(
                f"line {number}: checksum is 0x{checksum:02x}, computed "
                f"0x{(-total) & 0xFF:02x} - the file is corrupt")

        if kind == 0x00:
            sparse.add(upper + address, payload)
        elif kind == 0x01:
            saw_eof = True
            break
        elif kind == 0x02:
            upper = int.from_bytes(payload, "big") << 4
        elif kind == 0x04:
            upper = int.from_bytes(payload, "big") << 16
        elif kind in (0x03, 0x05):
            entry = int.from_bytes(payload, "big")
        else:
            warnings.append(f"line {number}: ignoring unknown record type "
                            f"0x{kind:02x}")

    if not saw_eof:
        warnings.append("no end-of-file record; the file may be truncated")
    image, base, gaps = sparse.flatten(warnings)
    return {"data": image, "format": "Intel HEX", "base_address": base,
            "entry_point": entry, "gaps_filled": gaps, "warnings": warnings}


# --------------------------------------------------------------------------- #
# Motorola S-record
# --------------------------------------------------------------------------- #

_SREC_LINE = re.compile(rb"^S([0-9])([0-9A-Fa-f]{2})([0-9A-Fa-f]+)$")
_SREC_ADDRESS_BYTES = {0: 2, 1: 2, 2: 3, 3: 4, 5: 2, 6: 3, 7: 4, 8: 3, 9: 2}


def looks_like_srec(data):
    head = data[:512].lstrip()
    return head.startswith(b"S") and bool(_SREC_LINE.match(
        (head.splitlines() or [b""])[0]))


def read_srec(data):
    """Motorola S-record. S0 header, S1/S2/S3 data, S7/S8/S9 start address."""
    sparse, warnings = _Sparse(), []
    entry = None
    header = None

    for number, raw in enumerate(data.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        match = _SREC_LINE.match(line)
        if not match:
            raise InputFormatError(f"line {number} is not an S-record")
        kind = int(match.group(1))
        count = int(match.group(2), 16)
        body = bytes.fromhex(match.group(3).decode("ascii"))

        if len(body) != count:
            raise InputFormatError(
                f"line {number}: record says {count} bytes, carries {len(body)}")
        payload, checksum = body[:-1], body[-1]
        if (~(count + sum(payload)) & 0xFF) != checksum:
            raise InputFormatError(
                f"line {number}: checksum is 0x{checksum:02x}, computed "
                f"0x{~(count + sum(payload)) & 0xFF:02x} - the file is corrupt")

        width = _SREC_ADDRESS_BYTES.get(kind)
        if width is None or len(payload) < width:
            warnings.append(f"line {number}: ignoring S{kind} record")
            continue
        address = int.from_bytes(payload[:width], "big")
        rest = payload[width:]

        if kind == 0:
            header = rest.rstrip(b"\x00").decode("ascii", "replace") or None
        elif kind in (1, 2, 3):
            sparse.add(address, rest)
        elif kind in (7, 8, 9):
            entry = address

    image, base, gaps = sparse.flatten(warnings)
    if header:
        warnings.append(f"S0 header record: {header!r}")
    return {"data": image, "format": "Motorola S-record", "base_address": base,
            "entry_point": entry, "gaps_filled": gaps, "warnings": warnings}


# --------------------------------------------------------------------------- #
# UF2
# --------------------------------------------------------------------------- #

def looks_like_uf2(data):
    return (len(data) >= UF2_BLOCK
            and struct.unpack_from("<II", data, 0) == (UF2_MAGIC_START,
                                                       UF2_MAGIC_SECOND))


def read_uf2(data):
    """UF2: 512-byte blocks, each carrying an address and up to 476 bytes."""
    sparse, warnings = _Sparse(), []
    families = set()
    blocks = skipped = 0

    if len(data) % UF2_BLOCK:
        warnings.append(f"file is not a whole number of {UF2_BLOCK}-byte "
                        "blocks; the tail is ignored")
    for index in range(len(data) // UF2_BLOCK):
        block = data[index * UF2_BLOCK:(index + 1) * UF2_BLOCK]
        start, second, flags, address, length, _seq, _total, family = \
            struct.unpack_from("<8I", block, 0)
        if start != UF2_MAGIC_START or second != UF2_MAGIC_SECOND:
            raise InputFormatError(f"block {index} has the wrong magic")
        if struct.unpack_from("<I", block, UF2_BLOCK - 4)[0] != UF2_MAGIC_END:
            raise InputFormatError(f"block {index} has no end magic")
        if flags & UF2_NOT_MAIN_FLASH:
            skipped += 1
            continue
        if length > 476:
            raise InputFormatError(
                f"block {index} claims {length} payload bytes; the maximum "
                "is 476")
        families.add(family)
        sparse.add(address, block[32:32 + length])
        blocks += 1

    if skipped:
        warnings.append(f"{skipped} block(s) marked not-main-flash were skipped")
    if len(families) > 1:
        warnings.append(f"blocks target {len(families)} different family IDs; "
                        "this file may hold more than one image")
    image, base, gaps = sparse.flatten(warnings)
    family_id = families.pop() if len(families) == 1 else None
    return {"data": image, "format": "UF2", "base_address": base,
            "entry_point": None, "gaps_filled": gaps, "warnings": warnings,
            "family_id": f"0x{family_id:08x}" if family_id else None,
            "blocks": blocks}


# --------------------------------------------------------------------------- #
# ELF
# --------------------------------------------------------------------------- #

def read_elf(data):
    """Lay out an ELF's PT_LOAD segments the way a flasher would.

    p_paddr is preferred over p_vaddr: on a microcontroller the load address is
    where the bytes are actually written, and that is the address every other
    part of the analysis reasons about.
    """
    info = elf.parse(data)
    if not info:
        raise InputFormatError("not a readable ELF file")

    reader = elf._Reader(data, info["class"] == 64, info["endian"] == "little")
    header_size = 64 if reader.is64 else 52
    if reader.is64:
        phoff, phentsize, phnum = reader.addr(32), reader.u16(54), reader.u16(56)
    else:
        phoff, phentsize, phnum = reader.addr(28), reader.u16(42), reader.u16(44)
    if not phnum:
        raise InputFormatError(
            "this ELF has no program headers, so it says nothing about where "
            "its contents are loaded; it is probably an object file rather "
            "than a linked image")

    sparse, warnings = _Sparse(), []
    for index in range(min(phnum, 4096)):
        at = phoff + index * phentsize
        if not reader.fits(at, phentsize):
            warnings.append("program header table is truncated")
            break
        p_type = reader.u32(at)
        if p_type != elf.PT_LOAD:
            continue
        if reader.is64:
            offset, vaddr, paddr = (reader.addr(at + 8), reader.addr(at + 16),
                                    reader.addr(at + 24))
            filesz = reader.addr(at + 32)
        else:
            offset, vaddr, paddr = (reader.addr(at + 4), reader.addr(at + 8),
                                    reader.addr(at + 12))
            filesz = reader.addr(at + 16)
        if not filesz:
            continue
        if not reader.fits(offset, filesz):
            warnings.append(f"segment {index} points past the end of the file")
            continue
        address = paddr or vaddr
        sparse.add(address, data[offset:offset + filesz])

    if not sparse.chunks:
        raise InputFormatError("this ELF has no loadable segments with contents")

    image, base, gaps = sparse.flatten(warnings)
    return {"data": image, "format": f"ELF ({info['machine']}, "
                                     f"{info['class']}-bit {info['endian']}-endian)",
            "base_address": base, "entry_point": None, "gaps_filled": gaps,
            "warnings": warnings, "elf": info}


# --------------------------------------------------------------------------- #

def detect_and_load(data, verbose=False, log=None):
    """Return the flat image for `data`, converting it if we need to.

    Raw input is passed through untouched, so an ordinary .bin analysis is
    byte-for-byte what it always was.
    """
    say = log or (lambda *_a, **_k: None)

    if elf.looks_like_elf(data[:20]):
        reader = read_elf(data)
    elif looks_like_uf2(data):
        reader = read_uf2(data)
    elif len(data) <= MAX_TEXT_BYTES and looks_like_intel_hex(data):
        reader = read_intel_hex(data)
    elif len(data) <= MAX_TEXT_BYTES and looks_like_srec(data):
        reader = read_srec(data)
    else:
        return {"data": data, "format": "raw binary", "base_address": None,
                "entry_point": None, "gaps_filled": 0, "warnings": [],
                "converted": False}

    reader["converted"] = True
    say(f"input: {reader['format']}, reassembled {len(reader['data'])} bytes"
        + (f" from base 0x{reader['base_address']:x}"
           if reader["base_address"] is not None else "")
        + (f", {reader['gaps_filled']} byte(s) of padding"
           if reader["gaps_filled"] else ""))
    for warning in reader["warnings"]:
        say(f"input:   {warning}")
    return reader
