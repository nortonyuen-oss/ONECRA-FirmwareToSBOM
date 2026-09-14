#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
esp32 - read Espressif firmware images and flash layouts.

ESP32 parts are in an enormous number of IoT devices, and their firmware is
neither a flat microcontroller image nor a Linux one. An application image is a
24-byte header followed by segments, each with its own load address; a
full-flash image is a partition table at 0x8000 naming several of those plus
data areas. Scanning either as one blob works about as badly as it does on a
router.

Two things here are worth more than the segmentation:

  * **The chip is stated, not inferred.** The header carries a chip ID, so the
    instruction set comes from the image rather than from an opcode histogram -
    and it distinguishes the Xtensa parts from the RISC-V ones, which no
    entropy or opcode heuristic reliably does.

  * **ESP-IDF writes its own version into the image.** `esp_app_desc_t` sits at
    the start of the first segment and carries the application version, the
    project name, the build date and the IDF version. That is a structural
    field, not a string that happened to match a regex, so it is as good as a
    package database entry.

Verified against published Tasmota images for ESP32 and ESP32-C3, both the
application images and a full factory flash image. Real builds do leave parts
of the app descriptor empty - Tasmota fills in only `idf_ver` - so every field
is reported when present and omitted when not, rather than assumed.
"""

import struct

IMAGE_MAGIC = 0xE9
IMAGE_HEADER_SIZE = 24
SEGMENT_HEADER_SIZE = 8
MAX_SEGMENTS = 16                  # ESP_IMAGE_MAX_SEGMENTS

APP_DESC_MAGIC = 0xABCD5432
APP_DESC_SIZE = 256

PARTITION_TABLE_OFFSET = 0x8000
PARTITION_MAGIC = b"\xaa\x50"
PARTITION_ENTRY_SIZE = 32
MAX_PARTITIONS = 95                # the table is one 3 KiB sector

# esp_chip_id_t, with the core each part actually uses. The Xtensa/RISC-V
# split is the reason to read this field rather than guess from the bytes.
CHIPS = {
    0x0000: ("ESP32", "Xtensa LX6"),
    0x0002: ("ESP32-S2", "Xtensa LX7"),
    0x0005: ("ESP32-C3", "RISC-V"),
    0x0009: ("ESP32-S3", "Xtensa LX7"),
    0x000C: ("ESP32-C2", "RISC-V"),
    0x000D: ("ESP32-C6", "RISC-V"),
    0x0010: ("ESP32-H2", "RISC-V"),
    0x0012: ("ESP32-P4", "RISC-V"),
    0x0017: ("ESP32-C5", "RISC-V"),
}

PARTITION_TYPES = {0: "app", 1: "data"}
APP_SUBTYPES = {0x00: "factory", 0x20: "test"}
DATA_SUBTYPES = {
    0x00: "ota", 0x01: "phy", 0x02: "nvs", 0x03: "coredump",
    0x04: "nvs_keys", 0x05: "efuse", 0x06: "undefined",
    0x80: "esphttpd", 0x81: "fat", 0x82: "spiffs", 0x83: "littlefs",
}

# Load addresses fall inside the parts' address space; a stray 0xE9 in
# compressed data almost never produces a plausible entry point.
ENTRY_RANGE = (0x3C000000, 0x50200000)


def _subtype_name(kind, subtype):
    if kind == 0:
        if 0x10 <= subtype <= 0x1F:
            return f"ota_{subtype - 0x10}"
        return APP_SUBTYPES.get(subtype, f"0x{subtype:02x}")
    if kind == 1:
        return DATA_SUBTYPES.get(subtype, f"0x{subtype:02x}")
    return f"0x{subtype:02x}"


def parse_app_descriptor(data, offset):
    """esp_app_desc_t, written by ESP-IDF at the start of the first segment.

    Real images leave fields blank - Tasmota fills in only idf_ver - so an
    empty string is reported as absent rather than as an empty version.
    """
    if offset + APP_DESC_SIZE > len(data):
        return None
    magic, secure_version = struct.unpack_from("<II", data, offset)
    if magic != APP_DESC_MAGIC:
        return None

    def text(start, length):
        raw = data[offset + start:offset + start + length]
        value = raw.split(b"\x00")[0].decode("utf-8", "replace").strip()
        return value or None

    return {
        "secure_version": secure_version,
        "app_version": text(16, 32),
        "project_name": text(48, 32),
        "build_time": text(80, 16),
        "build_date": text(96, 16),
        "idf_version": text(112, 32),
        "elf_sha256": data[offset + 144:offset + 176].hex(),
    }


def parse_image(data, offset=0):
    """An Espressif application or bootloader image, or None.

    Returns the header fields, the segment table and the app descriptor if one
    is present. Nothing here raises: a stray 0xE9 in compressed data must fail
    the plausibility checks and be dropped, not abort an analysis.
    """
    if offset + IMAGE_HEADER_SIZE > len(data) or data[offset] != IMAGE_MAGIC:
        return None
    segment_count = data[offset + 1]
    if not 1 <= segment_count <= MAX_SEGMENTS:
        return None
    entry_point, = struct.unpack_from("<I", data, offset + 4)
    if not ENTRY_RANGE[0] <= entry_point <= ENTRY_RANGE[1]:
        return None

    chip_id, = struct.unpack_from("<H", data, offset + 12)
    chip, core = CHIPS.get(chip_id, (f"unknown chip 0x{chip_id:04x}", None))
    hash_appended = bool(data[offset + 23] & 1)

    segments, at = [], offset + IMAGE_HEADER_SIZE
    for index in range(segment_count):
        if at + SEGMENT_HEADER_SIZE > len(data):
            return None
        load_address, length = struct.unpack_from("<II", data, at)
        at += SEGMENT_HEADER_SIZE
        if length > len(data) or at + length > len(data):
            return None
        segments.append({"index": index, "load_address": load_address,
                         "offset": at, "length": length})
        at += length

    if not segments:
        return None

    return {
        "offset": offset,
        "chip": chip,
        "chip_id": chip_id,
        "core": core,
        "entry_point": entry_point,
        "hash_appended": hash_appended,
        "segments": segments,
        "end": at,
        "app": parse_app_descriptor(data, segments[0]["offset"]),
    }


def parse_partition_table(data, offset=PARTITION_TABLE_OFFSET):
    """The partition table of a full-flash image, or None.

    A device's flash holds several images plus data areas, and the table is
    the only thing that says which is which. Tasmota's layout is a good
    reminder not to assume the textbook one: it ships a `safeboot` app where
    the examples show `factory`.
    """
    if offset + PARTITION_ENTRY_SIZE > len(data):
        return None
    if data[offset:offset + 2] != PARTITION_MAGIC:
        return None

    partitions, at = [], offset
    while len(partitions) < MAX_PARTITIONS:
        if at + PARTITION_ENTRY_SIZE > len(data):
            break
        if data[at:at + 2] != PARTITION_MAGIC:
            break
        kind, subtype = data[at + 2], data[at + 3]
        address, size = struct.unpack_from("<II", data, at + 4)
        name = data[at + 12:at + 28].split(b"\x00")[0].decode("ascii", "replace")
        partitions.append({
            "name": name or f"partition-{len(partitions)}",
            "type": PARTITION_TYPES.get(kind, f"0x{kind:02x}"),
            "type_id": kind,
            "subtype": _subtype_name(kind, subtype),
            "subtype_id": subtype,
            "address": address,
            "size": size,
        })
        at += PARTITION_ENTRY_SIZE

    return partitions or None


def detect(data):
    """Identify an Espressif image, flat or full-flash. Returns None if not.

    An application image starts with the magic. A full-flash image starts with
    erased flash - the bootloader lives at 0x1000 and the partition table at
    0x8000 - so both shapes have to be recognised.
    """
    image = parse_image(data, 0)
    if image:
        return {"kind": "application", "image": image, "partitions": None,
                "chip": image["chip"], "core": image["core"]}

    partitions = parse_partition_table(data)
    bootloader = parse_image(data, 0x1000)
    if not partitions and not bootloader:
        return None

    images = []
    for partition in partitions or []:
        if partition["type_id"] != 0:
            continue
        found = parse_image(data, partition["address"])
        if found:
            found["partition"] = partition["name"]
            images.append(found)

    if bootloader:
        bootloader["partition"] = "bootloader"
    if not images and not bootloader:
        return None

    primary = next((i for i in images if i.get("app")), None) or \
        (images[0] if images else bootloader)
    return {"kind": "flash", "image": primary, "images": images,
            "bootloader": bootloader, "partitions": partitions,
            "chip": primary["chip"], "core": primary["core"]}
