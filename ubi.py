#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ubi - read UBI, the volume layer over raw NAND flash.

A NAND firmware image is rarely a filesystem. It is UBI: a run of physical
erase blocks, each carrying two small headers - an erase-counter header, and a
volume-identifier header saying which logical block of which volume this
physical block holds. The volumes are the real content: on an OpenWrt NAND
device a kernel, a SquashFS rootfs and a UBIFS overlay; on a camera, a
configuration volume and an application volume.

So UBI is a container, and this module only reassembles it. The physical
blocks of a volume are scattered across the flash in whatever order wear
levelling left them, and more than one can claim the same logical block - the
newest sequence number wins, as it does on the device. What comes out is each
volume's bytes in logical order, handed back to the walk to be read like any
other region: a UBIFS reader for UBIFS, the SquashFS reader for SquashFS.

Three things are checked rather than assumed:

  * **Every header's CRC.** "UBI#" is four bytes of ASCII.
  * **The volume table's own CRCs**, record by record. A table holds up to 128
    slots; most are empty, and an empty slot reads as garbage if taken at face
    value - which is exactly what the first hand-decode of a real image did.
  * **Missing and truncated blocks.** A dump cut off mid-block, or a volume
    whose logical blocks are not all present, is reported, and the gap filled
    with erased flash rather than silently closed up - closing it would shift
    every later byte of the volume and corrupt whatever reads it.

Verified against the UBI samples published by the unblob project (MIT): a
minimal image with a static and a dynamic volume, and a 3.4 MB image with
128 KiB erase blocks, two UBIFS volumes, and a truncation in the middle of a
block.
"""

import struct
import zlib

EC_MAGIC = b"UBI#"
VID_MAGIC = b"UBI!"
EC_HEADER_SIZE = 64
VID_HEADER_SIZE = 64
VTBL_RECORD_SIZE = 172
LAYOUT_VOLUME_ID = 0x7FFFEFFF
MAX_VOLUMES = 128
VOLUME_TYPES = {1: "dynamic", 2: "static"}

# Hostile-input caps.
MIN_PEB = 512
MAX_PEB = 4 * 1024 * 1024
MAX_PEBS = 1 << 20
MAX_VOLUME_BYTES = 512 * 1024 * 1024


class UBIError(Exception):
    pass


def ubi_crc32(data):
    """UBI's CRC: seeded with 0xFFFFFFFF and not inverted at the end.

    That is one complement away from zlib's crc32, and it is the same CRC
    UBIFS uses. Checked against every header of the published samples.
    """
    return (~zlib.crc32(data, 0)) & 0xFFFFFFFF


def parse_ec_header(data, at):
    """An erase-counter header at `at`, or None."""
    if at + EC_HEADER_SIZE > len(data) or data[at:at + 4] != EC_MAGIC:
        return None
    header = data[at:at + EC_HEADER_SIZE]
    stored, = struct.unpack_from(">I", header, 60)
    if ubi_crc32(header[:60]) != stored:
        return None
    version, erase_count, vid_offset, data_offset, image_seq = struct.unpack_from(
        ">B3xQIII", header, 4)
    return {"version": version, "erase_count": erase_count,
            "vid_header_offset": vid_offset, "data_offset": data_offset,
            "image_seq": image_seq}


def parse_vid_header(data, at):
    """A volume-identifier header at `at`, or None if absent or damaged."""
    if at + VID_HEADER_SIZE > len(data) or data[at:at + 4] != VID_MAGIC:
        return None
    header = data[at:at + VID_HEADER_SIZE]
    stored, = struct.unpack_from(">I", header, 60)
    if ubi_crc32(header[:60]) != stored:
        return None
    (_version, vol_type, copy_flag, _compat, vol_id, lnum, data_size,
     used_ebs, data_pad, data_crc, sqnum) = struct.unpack_from(
        ">BBBBII4xIIII4xQ", header, 4)
    return {"vol_type": vol_type, "copy_flag": copy_flag, "vol_id": vol_id,
            "lnum": lnum, "data_size": data_size, "used_ebs": used_ebs,
            "data_pad": data_pad, "data_crc": data_crc, "sqnum": sqnum}


def _peb_size(data, start):
    """The erase-block size: the distance to the next valid EC header."""
    at = start + 4
    while True:
        at = data.find(EC_MAGIC, at)
        if at == -1:
            return len(data) - start                   # a single block
        distance = at - start
        if distance >= MIN_PEB and parse_ec_header(data, at):
            return distance
        at += 4


def _volume_table(blob):
    """The layout volume's records, each checked against its own CRC."""
    volumes = {}
    for index in range(min(MAX_VOLUMES, len(blob) // VTBL_RECORD_SIZE)):
        record = blob[index * VTBL_RECORD_SIZE:(index + 1) * VTBL_RECORD_SIZE]
        stored, = struct.unpack_from(">I", record, VTBL_RECORD_SIZE - 4)
        if ubi_crc32(record[:VTBL_RECORD_SIZE - 4]) != stored:
            continue
        reserved, alignment, data_pad, vol_type, _upd, name_len = struct.unpack_from(
            ">IIIBBH", record, 0)
        if not reserved or not 0 < name_len <= 127:
            continue                                     # an empty slot
        volumes[index] = {
            "name": record[16:16 + name_len].decode("utf-8", "replace"),
            "reserved_pebs": reserved,
            "type": VOLUME_TYPES.get(vol_type, f"type {vol_type}"),
        }
    return volumes


def read_image(data, start=0):
    """Reassemble every volume of the UBI image starting at `start`.

    Returns {peb_size, leb_size, end, volumes: [...], warnings: [...]}, or
    raises UBIError if there is no valid UBI image there.
    """
    first = parse_ec_header(data, start)
    if first is None:
        raise UBIError("no valid UBI erase-counter header")
    peb_size = _peb_size(data, start)
    if not MIN_PEB <= peb_size <= MAX_PEB:
        raise UBIError(f"implausible erase-block size {peb_size}")
    vid_offset, data_offset = first["vid_header_offset"], first["data_offset"]
    if not EC_HEADER_SIZE <= vid_offset < data_offset < peb_size:
        raise UBIError("header offsets do not fit inside an erase block")
    leb_size = peb_size - data_offset

    warnings = []
    blocks = {}                         # (vol_id, lnum) -> (sqnum, peb offset, vid)
    at, count, end = start, 0, start
    while at + EC_HEADER_SIZE <= len(data) and count < MAX_PEBS:
        ec = parse_ec_header(data, at)
        if ec is None:
            # An erased block reads as 0xFF throughout and belongs to the
            # image; anything else means the UBI region has ended.
            if data[at:at + EC_HEADER_SIZE] != b"\xff" * EC_HEADER_SIZE:
                break
        else:
            vid = parse_vid_header(data, at + vid_offset)
            if vid is not None:
                key = (vid["vol_id"], vid["lnum"])
                if key not in blocks or vid["sqnum"] > blocks[key][0]:
                    blocks[key] = (vid["sqnum"], at, vid)
        end = min(len(data), at + peb_size)
        at += peb_size
        count += 1

    if end - start < count * peb_size:
        warnings.append(f"the image ends {count * peb_size - (end - start)} bytes "
                        "into its last erase block; that block is read as far "
                        "as it goes")

    table = {}
    for lnum in (0, 1):                               # two copies of the table
        entry = blocks.get((LAYOUT_VOLUME_ID, lnum))
        if entry:
            _sq, peb, _vid = entry
            table = _volume_table(data[peb + data_offset:peb + peb_size])
            if table:
                break
    if not table:
        warnings.append("no readable volume table; volumes are numbered, not named")

    volumes = []
    for vol_id in sorted({v for v, _l in blocks if v != LAYOUT_VOLUME_ID}):
        lebs = sorted((lnum, entry) for (v, lnum), entry in blocks.items()
                      if v == vol_id)
        top = lebs[-1][0]
        if (top + 1) * leb_size > MAX_VOLUME_BYTES:
            warnings.append(f"volume {vol_id} claims more than the size limit")
            continue
        present = {lnum: entry for lnum, entry in lebs}
        out = bytearray()
        missing = []
        static = False
        for lnum in range(top + 1):
            entry = present.get(lnum)
            if entry is None:
                missing.append(lnum)
                out += b"\xff" * leb_size
                continue
            _sq, peb, vid = entry
            static = vid["vol_type"] == 2
            size = vid["data_size"] if static and vid["data_size"] else leb_size
            chunk = data[peb + data_offset:peb + data_offset + size]
            if len(chunk) < size and not static:
                chunk += b"\xff" * (size - len(chunk))   # truncated: stays aligned
            out += chunk
        info = table.get(vol_id, {})
        name = info.get("name") or f"volume {vol_id}"
        if missing:
            warnings.append(f"volume '{name}': logical blocks {missing[:8]}"
                            f"{'...' if len(missing) > 8 else ''} are missing and "
                            "were filled with erased flash")
        volumes.append({
            "id": vol_id,
            "name": name,
            "type": info.get("type") or ("static" if static else "dynamic"),
            "data": bytes(out),
            "lebs": len(present),
            "missing_lebs": missing,
            "first_peb": min(entry[1] for entry in present.values()),
        })

    return {"peb_size": peb_size, "leb_size": leb_size, "start": start,
            "end": end, "image_seq": first["image_seq"], "volumes": volumes,
            "warnings": warnings}


def find_offsets(data, start=0, alignment=512):
    """Where UBI images begin: a valid EC header on an aligned boundary."""
    found, at = [], start
    while True:
        at = data.find(EC_MAGIC, at)
        if at == -1:
            return found
        if at % alignment == 0 and parse_ec_header(data, at):
            found.append(at)
            try:
                image = read_image(data, at)
                at = max(at + 4, image["end"])
                continue
            except UBIError:
                pass
        at += 4
