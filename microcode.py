#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
microcode - find Intel CPU microcode updates in a firmware image.

A PC BIOS carries microcode for every processor the board supports, and the
microcode revision is what Intel's security advisories are written against:
"CPUID 806EC, fixed in microcode 0xF4". An SBOM that lists the BIOS modules
but not the microcode leaves out the one component a CPU vulnerability is
matched on.

Each update starts with a 48-byte header that Intel documents publicly (SDM
volume 3, "Microcode Update Facilities"): header version, update revision,
date, processor signature (CPUID), checksum, loader revision, processor
flags, data size and total size - optionally followed by an extended
signature table naming further CPUIDs the same update applies to. Only that
header is read. The update body is encrypted and is not, and could not be,
looked inside.

The header is recognised strictly, because four bytes of 01 00 00 00 are
everywhere: both version fields must be 1, the date must be a real BCD date,
the sizes must be whole kilobytes and consistent, and the whole update must
sum to zero as 32-bit words - the checksum the processor itself checks.

Verified against updates from Intel's public microcode repository (release
microcode-20260812), including ones with extended signature tables.
AMD microcode has a different format and is not read yet.
"""

import re
import struct

HEADER_SIZE = 48
DEFAULT_DATA = 2000
DEFAULT_TOTAL = 2048
MAX_TOTAL = 4 * 1024 * 1024
MAX_EXTENDED = 32
MAX_UPDATES = 512

# Header version 1 at +0 and loader revision 1 at +20, on a 16-byte boundary.
_CANDIDATE = re.compile(rb"\x01\x00\x00\x00(?=.{16}\x01\x00\x00\x00)", re.DOTALL)


def _bcd_date(value):
    """mmddyyyy in BCD, as Intel writes it, to ISO - or None if not a date."""
    text = f"{value:08x}"
    if not text.isdigit():
        return None
    month, day, year = int(text[0:2]), int(text[2:4]), int(text[4:8])
    if not (1 <= month <= 12 and 1 <= day <= 31 and 1990 <= year <= 2099):
        return None
    return f"{year:04d}-{month:02d}-{day:02d}"


def decode_cpuid(signature):
    """(family, model, stepping) as the OS reports them, and Intel's own
    file name for the update, e.g. 06-8e-0c."""
    stepping = signature & 0xF
    model = (signature >> 4) & 0xF
    family = (signature >> 8) & 0xF
    ext_model = (signature >> 16) & 0xF
    ext_family = (signature >> 20) & 0xFF
    display_family = family + ext_family if family == 0xF else family
    display_model = model + (ext_model << 4) if family in (0x6, 0xF) else model
    return (display_family, display_model, stepping,
            f"{display_family:02x}-{display_model:02x}-{stepping:02x}")


def parse_update(data, at):
    """The microcode update whose header is at `at`, or None."""
    if at + HEADER_SIZE > len(data):
        return None
    (version, revision, date, signature, _checksum, loader, flags,
     data_size, total_size) = struct.unpack_from("<9I", data, at)
    if version != 1 or loader != 1:
        return None
    iso_date = _bcd_date(date)
    if iso_date is None or signature == 0:
        return None
    data_size = data_size or DEFAULT_DATA
    total_size = total_size or DEFAULT_TOTAL
    if (total_size % 1024 or not DEFAULT_TOTAL <= total_size <= MAX_TOTAL
            or data_size % 4 or data_size + HEADER_SIZE > total_size
            or at + total_size > len(data)):
        return None
    words = struct.unpack_from(f"<{total_size // 4}I", data, at)
    if sum(words) & 0xFFFFFFFF:
        return None

    extended = []
    if total_size > data_size + HEADER_SIZE:
        table = at + HEADER_SIZE + data_size
        if table + 20 <= at + total_size:
            count, = struct.unpack_from("<I", data, table)
            for index in range(min(count, MAX_EXTENDED)):
                entry = table + 20 + index * 12
                if entry + 12 > at + total_size:
                    break
                ext_signature, ext_flags, _ext_checksum = struct.unpack_from(
                    "<III", data, entry)
                extended.append({"cpuid": ext_signature, "platforms": ext_flags})

    family, model, stepping, name = decode_cpuid(signature)
    return {
        "offset": at, "size": total_size, "revision": revision,
        "date": iso_date, "cpuid": signature, "platforms": flags,
        "family": family, "model": model, "stepping": stepping,
        "fms": name, "extended": extended,
    }


def scan(data, alignment=16):
    """Every microcode update in `data`, in image order."""
    found = []
    position = 0
    for match in _CANDIDATE.finditer(data):
        at = match.start()
        if at < position or at % alignment:
            continue
        update = parse_update(data, at)
        if update is None:
            continue
        found.append(update)
        position = at + update["size"]
        if len(found) >= MAX_UPDATES:
            break
    return found
