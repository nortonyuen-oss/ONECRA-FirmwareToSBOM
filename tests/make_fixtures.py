#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_fixtures - deterministic synthetic firmware images for the fw2sbom tests.

Every image here is generated from a fixed seed, so a fixture is reproducible
on any machine and the test suite can assert exact offsets, record counts and
payload sizes. The generated .bin files are build output and stay out of git;
this generator is the thing under version control.

Nothing here comes from a customer, a product or a real device. The open-source
banner strings ("mbed TLS 3.4.0", "BusyBox v1.36.1", ...) are test vectors for
the signature regexes - a signature test has to contain the strings it matches
or it tests nothing - and the version numbers were chosen to be ordinary
released versions with no connection to any image we have been given.

Usage:
    python tests/make_fixtures.py [OUT_DIR]     # default: tests/fixtures/
"""

import gzip
import hashlib
import json
import lzma
import zlib
import os
import random
import struct
import sys

# One seed for the whole module: fixtures must be byte-identical between runs,
# between machines and between Python versions, so nothing may use the global
# `random` module state or os.urandom.
SEED = 0x66773262  # "fw2b"

# Cortex-M vector-table constants the detector looks for (see analyze_cortex_m).
CORTEX_SRAM_TOP = 0x20008000    # initial SP: 4-byte aligned, inside typical SRAM
CORTEX_RESET = 0x00000201       # reset vector: Thumb bit set, below 0x20000000

# MCS-51 opcodes the detector counts: LJMP, LCALL, MOV DPTR, MOVX A,@DPTR,
# MOVX @DPTR,A, RET. They must make up >= 8% of the image (see analyze_mcs51).
MCS51_OPCODES = (0x02, 0x12, 0x90, 0xE0, 0xF0, 0x22)

EDID_MAGIC = b"\x00\xff\xff\xff\xff\xff\xff\x00"

FIXTURES = {}   # name -> builder function, filled by @fixture


def fixture(filename):
    """Register a builder so `main` can generate every fixture by name."""
    def register(fn):
        FIXTURES[filename] = fn
        return fn
    return register


def rng(salt):
    """A generator seeded per fixture, so adding one cannot shift the others."""
    return random.Random(SEED ^ (int(hashlib.sha256(salt.encode()).hexdigest()[:8], 16)))


def filler(r, n):
    """`n` bytes of code-like noise: high entropy, no printable runs."""
    return bytes(r.randrange(0x00, 0x100) for _ in range(n))


def strings_blob(items):
    """NUL-terminated strings, as a compiler would lay out .rodata."""
    return b"".join(s.encode("ascii") + b"\x00" for s in items)


def cortex_vector_table(r, n_plausible=14):
    """A Cortex-M vector table: SP, reset, then 14 exception vectors.

    `n_plausible` controls how many of slots 2-15 are valid handler addresses;
    the detector requires at least 10, so a lower number produces an image that
    deliberately fails identification.
    """
    table = struct.pack("<II", CORTEX_SRAM_TOP, CORTEX_RESET)
    for i in range(14):
        if i < n_plausible:
            # Thumb handler address below the SRAM base, or an unused slot.
            vec = 0 if i % 5 == 4 else (r.randrange(0x200, 0x30000) * 2) | 1
        else:
            vec = 0x80000000 | r.randrange(0x1000)     # implausible on purpose
        table += struct.pack("<I", vec)
    return table


def edid_block(pnp, product_code, serial, week, year, version, name):
    """A 128-byte VESA E-EDID block that passes structural validation.

    The detector checks the magic, that the whole block sums to 0 mod 256, and
    that the packed PnP id decodes to three uppercase letters.
    """
    block = bytearray(128)
    block[0:8] = EDID_MAGIC
    packed = 0
    for i, ch in enumerate(pnp):
        packed |= (ord(ch) - 64) << (10 - 5 * i)
    block[8] = (packed >> 8) & 0xFF
    block[9] = packed & 0xFF
    block[10] = product_code & 0xFF
    block[11] = (product_code >> 8) & 0xFF
    block[12:16] = serial.to_bytes(4, "little")
    block[16] = week
    block[17] = year - 1990
    block[18], block[19] = (int(p) for p in version.split("."))
    block[20] = 0x80                      # digital input
    block[21], block[22] = 34, 19         # 16:9, ~55cm diagonal
    block[126] = 0                        # no extension blocks

    # Monitor name descriptor at the third 18-byte descriptor slot.
    desc = 54 + 36
    block[desc:desc + 3] = b"\x00\x00\x00"
    block[desc + 3] = 0xFC
    block[desc + 4] = 0x00
    label = name.encode("ascii")[:13]
    block[desc + 5:desc + 5 + len(label)] = label
    if len(label) < 13:
        block[desc + 5 + len(label)] = 0x0A          # terminator
        for i in range(desc + 6 + len(label), desc + 18):
            block[i] = 0x20                          # space padding

    block[127] = (-sum(block[:127])) & 0xFF
    assert (sum(block) & 0xFF) == 0, "EDID checksum must make the block sum to 0"
    return bytes(block)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

@fixture("cortexm_rtos.bin")
def build_cortexm_rtos():
    """ARM Cortex-M RTOS image with version banners for several components.

    The happy path: a plaintext image whose architecture is positively
    identified and whose components carry exact versions.
    """
    r = rng("cortexm_rtos")
    banners = strings_blob([
        "Booting Zephyr OS build v3.5.99-ncs1",
        "*** Booting nRF Connect SDK v2.6.0 ***",
        "mbed TLS 3.4.0",
        "MBEDTLS_SSL_HANDSHAKE_FAILURE",
        "lwIP 2.1.3",
        "tcp_output: pcb->snd_queuelen",
        "littlefs v2.8.0",
        "lfs_dir_commit",
        "FreeRTOS V10.5.1",
        "vTaskStartScheduler",
        "GCC: (GNU Arm Embedded Toolchain 12.2.rel1) 12.2.0",
        "CMSIS-RTOS2",
        "SystemCoreClock",
    ])
    body = filler(r, 0x1000) + banners + filler(r, 0x2000)
    return cortex_vector_table(r) + body


@fixture("cortexm_utf16.bin")
def build_cortexm_utf16():
    """Cortex-M image whose only version banners are UTF-16LE.

    An ASCII-only string scanner finds nothing here: the interleaved NULs cut
    every run down to one character.
    """
    r = rng("cortexm_utf16")
    text = strings_blob(["fw2sbom fixture: UTF-16LE version banners follow"])
    wide = "".join(s + "\x00" for s in
                   ["OpenSSL 1.1.1w  11 Sep 2023",
                    "SQLite version 3.42.0",
                    "libcurl/8.1.2"]).encode("utf-16-le")
    body = filler(r, 0x800) + text + wide + filler(r, 0x800)
    return cortex_vector_table(r) + body


@fixture("mcs51_display.bin")
def build_mcs51_display():
    """8051 display-controller image: vector table, dense opcodes, EDID, MCCS.

    Also the entropy case that motivated architecture-first opacity: dense 8051
    code sits around 7 bits/byte and a threshold alone would call it packed.
    """
    r = rng("mcs51_display")
    size = 0x18000
    image = bytearray(r.randrange(0x100) for _ in range(size))

    # Interrupt vector table: LJMP at 0x0000 and at 0x0003 + 8k.
    for slot in [0x0000] + [3 + 8 * k for k in range(9)]:
        target = r.randrange(0x1000, 0x8000)
        image[slot] = 0x02
        image[slot + 1] = (target >> 8) & 0xFF
        image[slot + 2] = target & 0xFF

    # Raise the core-opcode share to ~18%, matching a real Keil C51 build.
    for _ in range(int(size * 0.16)):
        image[r.randrange(0x100, size)] = r.choice(MCS51_OPCODES)

    # Two EDID blocks and an MCCS capability string, at 4 KiB-aligned offsets
    # the way a scaler keeps its data tables.
    blocks = [
        edid_block("ABC", 0x1234, 0x01020304, 12, 2023, "1.4", "FIXTURE-24"),
        edid_block("XYZ", 0x5678, 0x0A0B0C0D, 33, 2024, "1.4", "FIXTURE-27"),
    ]
    for i, block in enumerate(blocks):
        at = 0x4000 + i * 0x2000
        image[at:at + len(block)] = block

    caps = (b"(prot(monitor)type(LCD)model(FIXTURE)cmds(01 02 03 07 0C E3 F3)"
            b"vcp(02 04 05 08 10 12 14(05 08 0B) 16 18 1A)mccs_ver(2.2))\x00")
    image[0x9000:0x9000 + len(caps)] = caps
    return bytes(image)


@fixture("packet_front.bin")
def build_packet_front():
    """Vendor ISP dump: a file header, then [framing][payload] records.

    Framing is sum8 checksum, length byte, page index and a per-record
    sequence counter - the layout the de-framer is built to recognise.
    """
    return _packetized(framing_first=True)


@fixture("packet_back.bin")
def build_packet_back():
    """The same dump with [payload][framing] records.

    De-framing this loses the first payload chunk: nothing distinguishes the
    bytes before the first framing group from the file header. The test pins
    that documented limitation so a future change cannot quietly alter it.
    """
    return _packetized(framing_first=False)


def _packetized(framing_first):
    r = rng("packetized")
    payload = build_cortexm_rtos()
    chunk = 32
    payload += b"\xff" * (-len(payload) % chunk)
    header = b"ISPDUMP\x00" + bytes(r.randrange(0x100) for _ in range(56))

    records = []
    for i in range(len(payload) // chunk):
        part = payload[i * chunk:(i + 1) * chunk]
        framing = bytes([
            0,                       # checksum, filled in below
            chunk,                   # length byte == payload width
            (i // 256) & 0xFF,       # page index: steps up slowly
            i & 0xFF,                # sequence: +1 per record
        ])
        framing = bytes([sum(framing[1:] + part) & 0xFF]) + framing[1:]
        records.append(framing + part if framing_first else part + framing)
    return header + b"".join(records)


@fixture("opaque_encrypted.bin")
def build_opaque_encrypted():
    """An encrypted payload: no blank flash, no structure, ciphertext entropy.

    fw2sbom must report this as opaque with a single firmware component, not as
    "no components found" - the distinction the whole tool is built around.
    """
    r = rng("opaque_encrypted")
    return bytes(r.randrange(0x100) for _ in range(96 * 1024))


@fixture("random_flat.bin")
def build_random_flat():
    """200 KiB of random bytes: the container detector's false-positive guard.

    Random data must not produce a constant column and a +1 counter column at
    the same stride. If this ever de-frames, the detector has become too loose.
    """
    r = rng("random_flat")
    return bytes(r.randrange(0x100) for _ in range(200 * 1024))


@fixture("router_uimage.bin")
def build_router_uimage():
    """Linux router image: uImage header, gzip kernel, damaged squashfs.

    Two things are under test. The kernel exercises the container walk and
    decompression: its version banner is only reachable through the gzip
    region, so finding it proves the walker works end to end.

    The SquashFS superblock is deliberately well-formed enough to be
    recognised but its tables are not real. A firmware analyser is fed images
    from customers and vendors, and a damaged or truncated filesystem must
    produce a warning and a partial result, never a traceback. Reading a real
    SquashFS is covered by the corpus tests, which need an actual vendor image.
    """
    r = rng("router_uimage")
    kernel = strings_blob([
        "Linux version 5.10.110 (build@fixture) (gcc version 10.3.0) #1 SMP",
        "Kernel command line: console=ttyS0,115200 root=/dev/mtdblock2",
        "VFS: Mounted root (squashfs filesystem) readonly",
    ]) * 8 + filler(r, 4096)
    rootfs = strings_blob([
        "BusyBox v1.36.1 (2024-01-01 00:00:00 UTC) multi-call binary.",
        "OpenSSL 1.1.1w  11 Sep 2023",
        "dropbear_2022.83",
        "inflate 1.2.13 Copyright 1995-2022 Mark Adler",
    ]) * 8 + filler(r, 8192)

    compressed_kernel = gzip.compress(kernel, 9)
    # Trailing byte of the last word is the compression field: 1 = gzip. The
    # header has to agree with the bytes, or the walker is being told to read
    # a gzip region as if it were raw.
    uimage_header = struct.pack(">IIIIIIII", 0x27051956, 0, 0,
                                len(compressed_kernel),
                                0x80000000, 0x80000000, 0, 0x05050201)
    uimage_header += b"MIPS fixture Linux-5.10.110".ljust(32, b"\x00")

    # A SquashFS 4.0 superblock claiming xz. inode/directory/fragment table
    # offsets point past the end, so the reader must degrade rather than crash.
    squashfs_super = b"hsqs" + struct.pack(
        "<IIIIHHHHHHQQQQQQQQ",
        16,                     # inode_count
        0,                      # mtime
        131072,                 # block_size
        1,                      # fragment_count
        4,                      # compressor: xz
        17,                     # block_log
        0,                      # flags
        1,                      # id_count
        4, 0,                   # version 4.0
        0,                      # root inode reference
        4096,                   # bytes_used
        0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF, 0xFFFFFF)

    return (uimage_header
            + compressed_kernel
            + b"\xff" * 1024                      # blank flash between volumes
            + squashfs_super + gzip.compress(rootfs, 9)
            + b"\xff" * 4096)


@fixture("encrypted_kernel.bin")
def build_encrypted_kernel():
    """A flash dump whose kernel is encrypted, followed by erased flash.

    Modelled on a real device: a uImage header that claims gzip, a payload
    that is not gzip and not anything else readable, and tens of megabytes of
    0xFF after it. Measured as one lump the image reads as low-entropy
    "plaintext" - the padding outvotes the ciphertext - and the SBOM says the
    firmware is plaintext with no components, when the truth is that its one
    real region could not be read at all.

    The repeated 16-byte blocks are deliberate: identical plaintext blocks
    encrypting to identical ciphertext is the signature of ECB mode, and
    saying so is worth more to a reader than "high entropy".
    """
    r = rng("encrypted_kernel")
    block_pool = [bytes(r.randrange(0x100) for _ in range(16))
                  for _ in range(64)]
    body = bytearray()
    while len(body) < 512 * 1024:
        # Mostly unique blocks, with a few repeats as ECB would produce.
        body += (r.choice(block_pool) if r.random() < 0.04
                 else bytes(r.randrange(0x100) for _ in range(16)))
    payload = bytes(body)

    header = struct.pack(">IIIIIIII", 0x27051956, 0, 0, len(payload),
                         0, 0, 0, 0x05020201)      # Linux/ARM, gzip, but not
    header += b"\x00" * 32                          # no name, as the real one had
    return header + payload + b"\xff" * (2 * 1024 * 1024)


@fixture("bare_unknown.bin")
def build_bare_unknown():
    """Plaintext image of no recognised architecture and no known component.

    The legitimately empty result: fw2sbom should say so plainly rather than
    reach for a low-confidence match.
    """
    r = rng("bare_unknown")
    text = strings_blob([
        "fixture build 2026-01-01",
        "internal diagnostic table",
        "sensor calibration data follows",
    ])
    return filler(r, 0x2000) + text + b"\x00" * 0x1000 + filler(r, 0x2000)


# --- Espressif ------------------------------------------------------------- #
#
# Real ESP32 images were used to confirm the layout (published Tasmota builds
# for ESP32 and ESP32-C3), but nothing from them is copied here: the fixture is
# generated, and it deliberately fills in every app-descriptor field, which the
# real builds do not. That is the point of having both - the fixture proves the
# fields are read correctly, and the real images prove we cope when they are
# blank.

ESP_APP_DESC_MAGIC = 0xABCD5432
ESP_ENTRY = 0x400D0018          # inside the ESP32 IROM range
ESP_CHIP_ID = 0x0000            # ESP32, Xtensa LX6


def esp_app_descriptor():
    """esp_app_desc_t, 256 bytes, every documented field populated."""
    def text(value, width):
        raw = value.encode("ascii")
        return raw + b"\x00" * (width - len(raw))

    desc = struct.pack("<II", ESP_APP_DESC_MAGIC, 1)    # magic, secure_version
    desc += b"\x00" * 8                                  # reserv1[2]
    desc += text("1.2.3", 32)                            # version
    desc += text("fixture-app", 32)                      # project_name
    desc += text("00:00:00", 16)                         # time
    desc += text("Jan  1 2026", 16)                      # date
    desc += text("v5.1.2", 32)                           # idf_ver
    desc += bytes(range(32))                             # app_elf_sha256
    desc += b"\x00" * (256 - len(desc))                  # reserv2[20]
    return desc


def esp_image(r, chip_id=ESP_CHIP_ID, entry=ESP_ENTRY, with_descriptor=True):
    """A complete Espressif application image: header, segments, checksum."""
    first = (esp_app_descriptor() if with_descriptor else b"") + filler(r, 0x400)
    bodies = [(0x3F400020, first),
              (0x3FFB0000, strings_blob(["littlefs", "fixture-app"])),
              (0x400D0018, filler(r, 0x800))]

    header = bytes([0xE9, len(bodies), 0x02, 0x20])
    header += struct.pack("<I", entry)
    header += bytes([0x00, 0xEE, 0x00, 0x00])            # wp_pin, spi_pin_drv
    header += struct.pack("<H", chip_id)
    header += bytes([0x00, 0x00, 0x00, 0x00, 0x00])      # chip revisions
    header += b"\x00" * 4                                # reserved
    header += b"\x00"                                    # hash_appended: no

    out = bytearray(header)
    for load_address, body in bodies:
        out += struct.pack("<II", load_address, len(body)) + body

    out += b"\x00" * (15 - (len(out) % 16))              # pad, then checksum
    checksum = 0xEF
    for _, body in bodies:
        for byte in body:
            checksum ^= byte
    out.append(checksum)
    return bytes(out)


def esp_partition_table(entries):
    """The 0xAA50 table the second-stage bootloader reads at 0x8000."""
    table = bytearray()
    for name, kind, subtype, address, size in entries:
        table += b"\xaa\x50" + bytes([kind, subtype])
        table += struct.pack("<II", address, size)
        table += name.encode("ascii").ljust(16, b"\x00")
        table += struct.pack("<I", 0)                    # flags
    return bytes(table)


@fixture("esp32_app.bin")
def build_esp32_app():
    """A bare ESP32 application image, as an OTA update would arrive.

    The whole point of reading the header is that the chip - and therefore the
    instruction set - is declared rather than guessed, and that ESP-IDF records
    its own version in a struct instead of a banner string.
    """
    return esp_image(rng("esp32_app"))


@fixture("esp32_flash.bin")
def build_esp32_flash():
    """A full 512 KiB flash image: bootloader, partition table, app, data.

    Reading a flash dump as one blob is meaningless - the partition table is
    the only thing that says which region is an application and which is
    filesystem data, so it is the segmentation.
    """
    r = rng("esp32_flash")
    partitions = [
        ("nvs",     1, 0x02, 0x009000, 0x5000),
        ("otadata", 1, 0x00, 0x00E000, 0x2000),
        ("factory", 0, 0x00, 0x010000, 0x60000),
        ("storage", 1, 0x83, 0x070000, 0x10000),
    ]

    flash = bytearray(b"\xff" * 0x80000)

    bootloader = esp_image(rng("esp32_boot"), with_descriptor=False)
    flash[0x1000:0x1000 + len(bootloader)] = bootloader

    table = esp_partition_table(partitions)
    flash[0x8000:0x8000 + len(table)] = table

    app = esp_image(r)
    flash[0x10000:0x10000 + len(app)] = app

    data = strings_blob(["littlefs v2.8.1", "fixture data partition"])
    flash[0x70000:0x70000 + len(data)] = data
    return bytes(flash)


# --- UEFI / PC BIOS -------------------------------------------------------- #
#
# Built from the specifications, then checked against published EDK2 OVMF
# images. Two things here exist because the real images disagreed with a naive
# reading of the spec: a pad file whose GUID is all 0xFF (which is not the end
# of the volume, though it looks exactly like erased flash), and a variable
# store sharing the volume header with the module volumes (which must not be
# walked as if it held modules).

FFS2_GUID = bytes.fromhex("78e58c8c3d8a1c4f9935896185c32dd3")
NVRAM_GUID = bytes.fromhex("8d2bf1ff96768b4ca9852747075b4f50")
LZMA_SECTION_GUID = bytes.fromhex("98584eee143959429d6edc7bd79403cf")
CRC32_SECTION_GUID = bytes.fromhex("2e5a9b0b1b6f0e4c8c2ff2d0a1b3c4d5")

PE32_MACHINE_X64 = 0x8664


def uefi_pe32(r, machine=PE32_MACHINE_X64, size=0x200):
    """A PE32 *section* holding just enough PE/COFF for the machine field.

    It has to be a section: a firmware file is a sequence of sections, and a
    bare image dropped in among them is read as a section header made of
    whatever its first four bytes happen to be.
    """
    head = bytearray(b"\x00" * 0x40)
    head[0:2] = b"MZ"
    struct.pack_into("<I", head, 0x3C, 0x40)
    coff = b"PE\x00\x00" + struct.pack("<HH", machine, 1) + b"\x00" * 16
    body = bytes(head) + coff
    return uefi_section(0x10, body + filler(r, max(0, size - len(body))))


def uefi_section(kind, body):
    """EFI_COMMON_SECTION_HEADER plus payload, padded to 4 bytes."""
    size = len(body) + 4
    raw = size.to_bytes(3, "little") + bytes([kind]) + body
    return raw + b"\x00" * (-len(raw) % 4)


def uefi_ui_section(name):
    return uefi_section(0x15, name.encode("utf-16-le") + b"\x00\x00")


def uefi_version_section(version):
    return uefi_section(0x14, struct.pack("<H", 1)
                        + version.encode("utf-16-le") + b"\x00\x00")


def uefi_guided_section(guid, payload, attributes=0x0001):
    """EFI_GUID_DEFINED_SECTION: header, GUID, data offset, attributes."""
    body = guid + struct.pack("<HH", 24, attributes) + payload
    size = len(body) + 4
    raw = size.to_bytes(3, "little") + bytes([0x02]) + body
    return raw + b"\x00" * (-len(raw) % 4)


def uefi_compression_section(kind, payload):
    """EFI_COMPRESSION_SECTION. Type 1 is EFI/Tiano, which we cannot expand."""
    body = struct.pack("<IB", len(payload), kind) + payload
    size = len(body) + 4
    raw = size.to_bytes(3, "little") + bytes([0x01]) + body
    return raw + b"\x00" * (-len(raw) % 4)


def uefi_file(guid, kind, sections):
    """EFI_FFS_FILE_HEADER plus its sections, padded to 8 bytes."""
    body = b"".join(sections)
    size = len(body) + 24
    header = (guid + struct.pack("<BB", 0xAA, 0x55) + bytes([kind, 0x00])
              + size.to_bytes(3, "little") + bytes([0xF8]))
    raw = header + body
    return raw + b"\x00" * (-len(raw) % 8)


def uefi_pad_file(size=64):
    """A pad file. Its GUID is all 0xFF, which is exactly what erased flash
    looks like - reading the GUID alone to find the end of a volume stops here
    and loses every module that follows."""
    header = (b"\xff" * 16 + struct.pack("<BB", 0xAA, 0x55)
              + bytes([0xF0, 0x00]) + size.to_bytes(3, "little") + bytes([0xF8]))
    return header + b"\xff" * (size - 24)


def uefi_volume(guid, files, total=None, block_size=0x1000):
    """EFI_FIRMWARE_VOLUME_HEADER with a valid checksum, plus its files."""
    body = b"".join(files)
    header_length = 72
    total = total or (((header_length + len(body)) // block_size) + 1) * block_size
    blocks = total // block_size

    header = bytearray(header_length)
    header[16:32] = guid
    struct.pack_into("<Q", header, 32, total)
    header[40:44] = b"_FVH"
    struct.pack_into("<I", header, 44, 0x0004FEFF)     # attributes, as EDK2 sets
    struct.pack_into("<H", header, 48, header_length)
    struct.pack_into("<H", header, 52, 0)              # no extended header
    header[55] = 2                                     # revision
    struct.pack_into("<II", header, 56, blocks, block_size)
    struct.pack_into("<II", header, 64, 0, 0)          # block map terminator

    # Every UINT16 of the header sums to zero. That is what separates a volume
    # from the "_FVH" that turns up by chance inside compiled code.
    total_sum = sum(struct.unpack(f"<{header_length // 2}H", bytes(header)))
    struct.pack_into("<H", header, 50, (-total_sum) & 0xFFFF)

    out = bytes(header) + body
    return out + b"\xff" * (total - len(out))


def uefi_modules(r):
    """The files a small DXE volume would hold."""
    return [
        uefi_file(bytes.fromhex("7fcba2d6186a2f4eb43b9920a733700a"), 0x05, [
            uefi_pe32(r), uefi_ui_section("DxeCore"),
            uefi_version_section("1.0")]),
        uefi_pad_file(),
        uefi_file(bytes.fromhex("0400b8933bfa9f4b9b8e2ce2b0d4c8f1"), 0x07, [
            uefi_pe32(r), uefi_ui_section("PciBusDxe"),
            uefi_version_section("1.0")]),
        uefi_file(bytes.fromhex("11223344556677889900aabbccddeeff"), 0x07, [
            uefi_pe32(r)]),                    # no UI section: GUID is the name
    ]


@fixture("uefi_volume.bin")
def build_uefi_volume():
    """A bare UEFI firmware volume, as a BIOS region dump arrives.

    Holds a compressed inner volume as well, because that is where a real BIOS
    keeps nearly everything: a reader that stops at the outer volume sees three
    modules and calls it a firmware image.
    """
    r = rng("uefi_volume")
    inner = uefi_volume(FFS2_GUID, [
        uefi_file(bytes.fromhex("145bcd0a156a428aaf6249864da0e6e6"), 0x06, [
            uefi_pe32(r), uefi_ui_section("PlatformPei"),
            uefi_version_section("1.0")]),
        uefi_pad_file(),
        uefi_file(bytes.fromhex("52c05b140b98496cbc3b04b50211d680"), 0x04, [
            uefi_pe32(r), uefi_ui_section("PeiCore")]),
    ])
    packed = lzma.compress(
        uefi_section(0x17, inner),
        format=lzma.FORMAT_ALONE,
        filters=[{"id": lzma.FILTER_LZMA1, "preset": 6}])

    files = uefi_modules(r) + [
        uefi_file(bytes.fromhex("93fd219e729c154c8c4be77f1db2d792"), 0x0B, [
            uefi_guided_section(LZMA_SECTION_GUID, packed)]),
        # EFI/Tiano compression: recognised, not expanded, and said so.
        uefi_file(bytes.fromhex("aabbccdd00112233445566778899aabb"), 0x07, [
            uefi_compression_section(1, filler(r, 0x200))]),
    ]
    return uefi_volume(FFS2_GUID, files)


@fixture("uefi_flash.bin")
def build_uefi_flash():
    """A whole SPI flash: descriptor, a variable store, the BIOS region.

    What a customer actually dumps off a PC. The Management Engine region is
    included and is opaque by construction - reporting it as "not analysed"
    rather than averaging it into a verdict about the firmware is the point of
    reading the descriptor at all.
    """
    r = rng("uefi_flash")
    size = 0x400000
    flash = bytearray(b"\xff" * size)

    # Intel flash descriptor: signature at 0x10, then FLMAP0 naming the region
    # table, then one UINT32 per region holding base and limit in 4 KiB units.
    struct.pack_into("<I", flash, 0x10, 0x0FF0A55A)
    region_base = 0x40
    struct.pack_into("<I", flash, 0x14,
                     ((region_base >> 4) << 16) | (4 << 24))   # 5 regions
    regions = [(0x000000, 0x000FFF),      # descriptor
               (0x200000, 0x3FFFFF),      # BIOS
               (0x001000, 0x1FFFFF),      # management engine
               (0, 0), (0, 0)]            # no GbE, no platform data
    for index, (base, limit) in enumerate(regions):
        value = 0x00007FFF if (base, limit) == (0, 0) else \
            ((base >> 12) & 0x1FFF) | (((limit >> 12) & 0x1FFF) << 16)
        struct.pack_into("<I", flash, region_base + index * 4, value)

    # The ME region: signed Intel code we cannot read, so high-entropy filler.
    me = filler(r, 0x1FF000)
    flash[0x1000:0x1000 + len(me)] = me

    store = uefi_volume(NVRAM_GUID, [], total=0x10000)
    flash[0x200000:0x200000 + len(store)] = store

    bios = uefi_volume(FFS2_GUID, uefi_modules(r), total=0x100000)
    flash[0x210000:0x210000 + len(bios)] = bios
    return bytes(flash)


# --- CPU microcode ----------------------------------------------------------- #
#
# The header is Intel's published format; the body is filler, not Intel's
# code, since the body is encrypted and never read anyway. One update has an
# extended signature table, and one has a checksum that is off by one - which
# must be rejected, because that sum is the only thing separating a header
# from twelve words that happen to look like one.

MICROCODE_FFS_GUID = bytes.fromhex("36b27d1956f8244990f8cdf12fb875f3")


def microcode_update(r, revision, date, cpuid, platforms, kilobytes,
                     extended=(), corrupt=False):
    ext = b""
    if extended:
        entries = b"".join(struct.pack("<III", sig, flags, 0) for sig, flags in extended)
        ext_header = struct.pack("<II", len(extended), 0) + b"\x00" * 12
        ext = ext_header + entries
        ext_sum = sum(struct.unpack(f"<{len(ext) // 4}I", ext))
        ext = ext[:4] + struct.pack("<I", (-ext_sum) & 0xFFFFFFFF) + ext[8:]
    total = kilobytes * 1024
    data_size = total - 48 - len(ext)
    body = filler(r, data_size)
    header = struct.pack("<9I", 1, revision, date, cpuid, 0, 1, platforms,
                         data_size, total) + b"\x00" * 12
    blob = bytearray(header + body + ext)
    checksum = (-sum(struct.unpack(f"<{total // 4}I", bytes(blob)))) & 0xFFFFFFFF
    struct.pack_into("<I", blob, 16, (checksum + (1 if corrupt else 0)) & 0xFFFFFFFF)
    return bytes(blob)


def microcode_blobs(r):
    return [
        microcode_update(r, 0xF4, 0x02232023, 0x806EC, 0x94, 4),
        microcode_update(r, 0x2B, 0x05142024, 0x90672, 0x07, 6,
                         extended=[(0x90672, 0x07), (0x90675, 0x07), (0xB06F2, 0x07)]),
        microcode_update(r, 0x99, 0x01012024, 0x50654, 0xB7, 3, corrupt=True),
    ]


@fixture("bios_microcode.bin")
def build_bios_microcode():
    """The SPI flash of uefi_flash.bin, with a microcode volume added to the
    BIOS region the way board firmware carries it: a raw FFS file holding
    one update after another."""
    flash = bytearray(build_uefi_flash())
    volume = uefi_volume(FFS2_GUID, [
        uefi_file(MICROCODE_FFS_GUID, 0x01, microcode_blobs(rng("microcode")))],
        total=0x10000)
    flash[0x310000:0x310000 + len(volume)] = volume
    return bytes(flash)


# --- CramFS ---------------------------------------------------------------- #
#
# Built here rather than downloaded because the published CramFS samples hold
# two text files called apple.txt and cherry.txt: they prove the reader walks
# the format, and prove nothing at all about whether a component comes out the
# other end. This one carries a package database and a banner, so the whole
# path is exercised - filesystem, package database, signature scan.

CRAMFS_MAGIC_LE = 0x28CD3D45
CRAMFS_SIGNATURE = b"Compressed ROMFS"
CRAMFS_BLOCK = 4096
S_IFREG_755 = 0x81ED
S_IFDIR_755 = 0x41ED


def cramfs_inode(mode, size, namelen_units, offset_units):
    """The 12-byte inode, little-endian, with its three packed words."""
    return struct.pack("<III",
                       (mode & 0xFFFF),
                       (size & 0xFFFFFF),
                       (namelen_units & 0x3F) | ((offset_units & 0x03FFFFFF) << 6))


def cramfs_entry(name, mode, size, offset_units):
    """An inode followed by its name, padded to a 4-byte boundary."""
    raw = name.encode("ascii")
    padded = raw + b"\x00" * (-len(raw) % 4)
    return cramfs_inode(mode, size, len(padded) // 4, offset_units) + padded


def cramfs_file_data(payload):
    """A block table of block *end* offsets, then the zlib-compressed blocks.

    The table is written by the caller once the absolute start is known, so
    this returns the compressed blocks and their lengths.
    """
    blocks = [payload[i:i + CRAMFS_BLOCK]
              for i in range(0, max(len(payload), 1), CRAMFS_BLOCK)]
    return [zlib.compress(b, 9) for b in blocks if b] or [zlib.compress(b"", 9)]


@fixture("cramfs_rootfs.bin")
def build_cramfs_rootfs():
    """A small CramFS root filesystem with a package database and a banner.

    Laid out by hand: superblock, then the root directory's entries, then one
    subdirectory's entries, then each file's block table and data. Every offset
    an inode carries is in 4-byte units, which is the detail a reader written
    from a half-remembered spec gets wrong.
    """
    status = (
        "Package: busybox\n"
        "Version: 1.36.1-r2\n"
        "Architecture: arm_cortex-a7\n"
        "License: GPL-2.0-only\n"
        "Installed-Time: 1700000000\n"
        "\n"
        "Package: openssl-util\n"
        "Version: 3.0.12-r1\n"
        "Architecture: arm_cortex-a7\n"
        "License: Apache-2.0\n"
        "Installed-Time: 1700000000\n"
    ).encode("ascii")
    banner = (b"\x7fELF\x01\x01\x01" + b"\x00" * 9
              + struct.pack("<HH", 2, 40)          # ET_EXEC, EM_ARM
              + strings_blob(["BusyBox v1.36.1 (2023-11-14 20:19:46 UTC)",
                              "mbed TLS 3.4.0", "usage: busybox [function]"]))
    release = (b'NAME="OpenWrt"\n'
               b'VERSION="22.03.4"\n'
               b'ID=openwrt\n'
               b'PRETTY_NAME="OpenWrt 22.03.4"\n')

    # Two directories, three files. The subdirectory is what exercises walk().
    files = [("status", status), ("busybox", banner), ("os-release", release)]
    compressed = {name: cramfs_file_data(body) for name, body in files}

    # --- lay the image out ------------------------------------------------- #
    root_entries_at = 76
    root_names = [("etc", S_IFDIR_755), ("busybox", S_IFREG_755)]
    root_size = sum(12 + (-(-len(n.encode()) // 4)) * 4 for n, _ in root_names)

    etc_entries_at = root_entries_at + root_size
    etc_names = [("opkg-status", S_IFREG_755), ("os-release", S_IFREG_755)]
    etc_size = sum(12 + (-(-len(n.encode()) // 4)) * 4 for n, _ in etc_names)

    at = etc_entries_at + etc_size
    placed = {}
    for name, body in files:
        blocks = compressed[name]
        table_at = at
        ends, cursor = [], table_at + len(blocks) * 4
        for block in blocks:
            cursor += len(block)
            ends.append(cursor)
        placed[name] = {"table_at": table_at, "ends": ends, "blocks": blocks,
                        "size": len(body)}
        at = cursor + (-cursor % 4)

    total = at
    image = bytearray(total)

    root_inode = cramfs_inode(S_IFDIR_755, root_size, 0, root_entries_at // 4)
    header = struct.pack("<III", CRAMFS_MAGIC_LE, total, 0)
    header += struct.pack("<I", 0)
    header += CRAMFS_SIGNATURE
    header += struct.pack("<IIII", 0, 0, total // CRAMFS_BLOCK + 1, len(files))
    header += b"fw2sbom-fixture\x00"
    image[0:64] = header
    image[64:76] = root_inode

    root_blob = (cramfs_entry("etc", S_IFDIR_755, etc_size, etc_entries_at // 4)
                 + cramfs_entry("busybox", S_IFREG_755, placed["busybox"]["size"],
                                placed["busybox"]["table_at"] // 4))
    image[root_entries_at:root_entries_at + len(root_blob)] = root_blob

    etc_blob = (cramfs_entry("opkg-status", S_IFREG_755, placed["status"]["size"],
                             placed["status"]["table_at"] // 4)
                + cramfs_entry("os-release", S_IFREG_755,
                               placed["os-release"]["size"],
                               placed["os-release"]["table_at"] // 4))
    image[etc_entries_at:etc_entries_at + len(etc_blob)] = etc_blob

    for name in placed:
        spot = placed[name]
        table = b"".join(struct.pack("<I", e) for e in spot["ends"])
        image[spot["table_at"]:spot["table_at"] + len(table)] = table
        cursor = spot["table_at"] + len(table)
        for block in spot["blocks"]:
            image[cursor:cursor + len(block)] = block
            cursor += len(block)
    return bytes(image)


# --- JFFS2 ----------------------------------------------------------------- #
#
# The published JFFS2 samples prove the reader decodes every compressor in both
# byte orders. They do not test the three things that make JFFS2 a log rather
# than a filesystem image, so these fixtures do:
#
#   * a deleted file - a later directory entry pointing at inode 0. The
#     deleted binary carries a dropbear banner, and dropbear must not appear
#     in the SBOM: listing software that is not on the device is wrong in a way
#     nobody downstream can detect;
#   * a file rewritten across versions, where the newer node must win;
#   * a device dump with a read-only rootfs and a JFFS2 overlay after it, where
#     the overlay's contents must not vanish just because it is not first.

JFFS2_MAGIC = 0x1985
DT_DIR, DT_REG = 4, 8
S_IFDIR_755, S_IFREG_755 = 0o040755, 0o100755


def kernel_crc32(data):
    """crc32_le with no inversion, as JFFS2 writes it. Written out here so the
    fixtures do not borrow the reader's idea of the checksum they check."""
    return (~zlib.crc32(data, 0xFFFFFFFF)) & 0xFFFFFFFF


def jffs2_node(order, nodetype, body):
    head = struct.pack(order + "HHI", JFFS2_MAGIC, nodetype, 12 + len(body))
    node = head + struct.pack(order + "I", kernel_crc32(head)) + body
    return node + b"\xff" * (-len(node) % 4)


def jffs2_dirent(order, pino, version, ino, name, dtype):
    raw = name.encode("ascii")
    body = struct.pack(order + "IIIIBBH", pino, version, ino, 0, len(raw),
                       dtype, 0) + struct.pack(order + "II", 0, 0) + raw
    return jffs2_node(order, 0xE001, body)


def jffs2_inode(order, ino, version, mode, isize, offset, payload, dsize,
                compr):
    body = struct.pack(order + "IIIHHIIIIIIIBBHII", ino, version, mode, 0, 0,
                       isize, 0, 0, 0, offset, len(payload), dsize, compr, 0,
                       0, 0, 0) + payload
    return jffs2_node(order, 0xE002, body)


def rtime_pack(data):
    """The simplest valid rtime stream: every byte, then 'no repeat'."""
    return b"".join(bytes([value, 0]) for value in data)


def lzo_reference(name):
    """A reference LZO stream from tests/lzo_vectors.json, made by an
    independent implementation. The fixtures cannot compress LZO themselves -
    the standard library has no LZO - and should not borrow lzo.py to do it."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "lzo_vectors.json")
    with open(path, encoding="utf-8") as f:
        vector = next(v for v in json.load(f)["vectors"] if v["name"] == name)
    return bytes.fromhex(vector["lzo"]), vector["length"]


LZO_TEXT = b"The quick brown fox jumps over the lazy dog. " * 60


def build_jffs2(order=">"):
    """A small JFFS2 rootfs, big-endian as on a MIPS router."""
    busybox = (b"\x7fELF\x01\x02\x01" + b"\x00" * 9
               + struct.pack(">HH", 2, 8)              # ET_EXEC, EM_MIPS
               + strings_blob(["BusyBox v1.36.1 (2023-11-14 20:19:46 UTC)",
                               "usage: busybox [function]"]))
    dropbear = (b"\x7fELF\x01\x02\x01" + b"\x00" * 9
                + struct.pack(">HH", 2, 8)
                + strings_blob(["SSH-2.0-dropbear_2022.82",
                                "dropbear: removed in a later upgrade"]))
    old_release = b'NAME="VendorOS"\nVERSION="0.9"\n'
    release = (b'NAME="OpenWrt"\nVERSION="22.03.4"\nID=openwrt\n'
               b'PRETTY_NAME="OpenWrt 22.03.4"\n')
    motd, motd_size = lzo_reference("text")

    nodes = [
        # directories
        jffs2_dirent(order, 1, 1, 2, "bin", DT_DIR),
        jffs2_inode(order, 2, 1, S_IFDIR_755, 0, 0, b"", 0, 0),
        jffs2_dirent(order, 1, 2, 3, "etc", DT_DIR),
        jffs2_inode(order, 3, 1, S_IFDIR_755, 0, 0, b"", 0, 0),
        # /bin/busybox - zlib, as mkfs.jffs2 writes by default
        jffs2_dirent(order, 2, 3, 4, "busybox", DT_REG),
        jffs2_inode(order, 4, 1, S_IFREG_755, len(busybox), 0,
                    zlib.compress(busybox), len(busybox), 0x06),
        # /bin/dropbear - written, then deleted by a later unlink
        jffs2_dirent(order, 2, 4, 5, "dropbear", DT_REG),
        jffs2_inode(order, 5, 1, S_IFREG_755, len(dropbear), 0, dropbear,
                    len(dropbear), 0x00),
        # /etc/os-release - an old version, then the current one over it
        jffs2_dirent(order, 3, 5, 6, "os-release", DT_REG),
        jffs2_inode(order, 6, 1, 0o100644, len(old_release), 0,
                    rtime_pack(old_release), len(old_release), 0x02),
        jffs2_inode(order, 6, 2, 0o100644, len(release), 0, release,
                    len(release), 0x00),
        # /etc/motd - LZO, as on devices built for decompression speed
        jffs2_dirent(order, 3, 6, 7, "motd", DT_REG),
        jffs2_inode(order, 7, 1, 0o100644, motd_size, 0, motd, motd_size,
                    0x07),
        # the unlink: a newer entry for the same name, pointing at inode 0
        jffs2_dirent(order, 2, 7, 0, "dropbear", DT_REG),
    ]
    body = b"".join(nodes)
    return body + b"\xff" * (-len(body) % 0x10000)     # to an erase block


@fixture("jffs2_rootfs.bin")
def build_jffs2_rootfs():
    """A JFFS2 root filesystem on its own, as an overlay partition dump."""
    return build_jffs2(">")


@fixture("cramfs_jffs2_flash.bin")
def build_cramfs_jffs2_flash():
    """A device dump: a CramFS rootfs, then a JFFS2 overlay after it.

    The overlay is where packages installed after the factory image land, and
    it carries a library the rootfs does not. Only the first filesystem is read
    as the rootfs; the second must still have its files scanned.
    """
    rootfs = build_cramfs_rootfs()
    head = rootfs + b"\xff" * (-len(rootfs) % 0x10000)
    order = "<"
    library = (b"\x7fELF\x01\x01\x01" + b"\x00" * 9
               + struct.pack("<HH", 3, 40)           # ET_DYN, EM_ARM
               + strings_blob(["libcurl/8.4.0 OpenSSL/3.0.12",
                               "installed to the overlay after first boot"]))
    overlay = b"".join([
        jffs2_dirent(order, 1, 1, 2, "usr", DT_DIR),
        jffs2_inode(order, 2, 1, S_IFDIR_755, 0, 0, b"", 0, 0),
        jffs2_dirent(order, 2, 2, 3, "libcurl.so.4", DT_REG),
        jffs2_inode(order, 3, 1, S_IFREG_755, len(library), 0,
                    zlib.compress(library), len(library), 0x06),
    ])
    overlay += b"\xff" * (-len(overlay) % 0x10000)
    return head + overlay


# --- UBI and UBIFS ----------------------------------------------------------- #
#
# The published samples prove the readers decode real toolchain output, and one
# of them holds 706 LZO-compressed data nodes. What they do not hold is any
# software: two text files about fruit. And none of them has zlib- or
# zstd-compressed data, a deleted file, or a UBI image whose volumes come in an
# order where the first filesystem is not the root. These fixtures do:
#
#   * a UBIFS rootfs with data nodes stored raw, zlib, LZO and zstd - the LZO
#     and zstd streams made by independent implementations, not by the code
#     under test;
#   * a deleted binary whose nodes are still on the flash but no longer in the
#     index, carrying a dropbear banner that must not reach the SBOM;
#   * a two-level index, so the walk is a walk and not a single list;
#   * a UBI image whose first volume is a UBIFS data partition and whose second
#     is a CramFS rootfs, with its erase blocks out of order and one logical
#     block present twice - the older copy holding a banner that must lose.

UBIFS_MAGIC = 0x06101831
UBIFS_LEB = 15360                 # 16 KiB erase blocks, 1 KiB of UBI headers
UBIFS_INO, UBIFS_DATA, UBIFS_DENT, UBIFS_SB, UBIFS_MST, UBIFS_IDX = 0, 1, 2, 6, 7, 9
UBIFS_KEY_INO, UBIFS_KEY_DATA, UBIFS_KEY_DENT = 0, 1, 2


def ubi_crc(data):
    """UBI's and UBIFS's CRC, written out rather than borrowed from the readers."""
    return (~zlib.crc32(data, 0)) & 0xFFFFFFFF


def zstd_reference():
    """The zstd frame from tests/zstd_vectors.json, made by CPython 3.14's
    compression.zstd - so the fixture builds on any Python, including one
    that cannot read what it builds."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "zstd_vectors.json")
    with open(path, encoding="utf-8") as f:
        vector = json.load(f)["vectors"][0]
    return bytes.fromhex(vector["zstd"]), vector["length"]


class UBIFSBuilder:
    """Lays UBIFS nodes into logical blocks and remembers where each one went."""

    def __init__(self):
        self.lebs = {}                 # lnum -> bytearray
        self.sqnum = 0
        self.lnum, self.offs = 3, 0    # 0 superblock, 1-2 master

    def node(self, node_type, body, lnum=None, size=None):
        self.sqnum += 1
        length = 24 + len(body)
        if size:
            body += b"\x00" * (size - length)
            length = size
        tail = struct.pack("<QIBB2x", self.sqnum, length, node_type, 0) + body
        raw = struct.pack("<II", UBIFS_MAGIC, ubi_crc(tail)) + tail
        if lnum is None:
            if self.offs + len(raw) > UBIFS_LEB:
                self.lnum, self.offs = self.lnum + 1, 0
            lnum, offs = self.lnum, self.offs
            self.offs += len(raw) + (-len(raw) % 8)
        else:
            offs = len(self.lebs.get(lnum, b""))
        leb = self.lebs.setdefault(lnum, bytearray())
        leb[offs:offs + len(raw)] = raw
        leb.extend(b"\x00" * (-len(leb) % 8))
        return (lnum, offs, len(raw))

    def inode(self, inum, mode, size, nlink=1):
        body = struct.pack("<II", inum, UBIFS_KEY_INO << 29) + b"\x00" * 8
        body += struct.pack("<QQ", self.sqnum + 1, size)     # creat_sqnum, size
        body += b"\x00" * 36                                  # times
        body += struct.pack("<IIII", nlink, 0, 0, mode)
        return self.node(UBIFS_INO, body + b"\x00" * (160 - 24 - len(body)))

    def dentry(self, parent, name, inum, itype):
        raw = name.encode("ascii")
        body = struct.pack("<II", parent, (UBIFS_KEY_DENT << 29) | (zlib.crc32(raw) & 0x1FFFFFFF))
        body += b"\x00" * 8
        body += struct.pack("<QBBH4x", inum, 0, itype, len(raw)) + raw + b"\x00"
        return self.node(UBIFS_DENT, body)

    def data(self, inum, block, plain_size, compr, payload):
        body = struct.pack("<II", inum, (UBIFS_KEY_DATA << 29) | block) + b"\x00" * 8
        body += struct.pack("<IHH", plain_size, compr, 0) + payload
        return self.node(UBIFS_DATA, body)

    def index(self, level, children):
        body = struct.pack("<HH", len(children), level)
        for lnum, offs, length in children:
            body += struct.pack("<III", lnum, offs, length) + b"\x00" * 8
        return self.node(UBIFS_IDX, body)

    def image(self, root, default_compr):
        leb_count = self.lnum + 1
        sb = struct.pack("<2xBBIIII", 0, 0, 0, 512, UBIFS_LEB, leb_count)
        sb += struct.pack("<IQIIIIII", leb_count, 0, 1, 1, 1, 1, 8, 0)
        sb += struct.pack("<IH", 4, default_compr)
        self.node(UBIFS_SB, sb, lnum=0, size=4096)
        # A stale master first, then the current one: the newest must win.
        master = lambda root_ref: (struct.pack("<QQII", 16, 1, 0, 3)
                                   + struct.pack("<III", *root_ref)
                                   + b"\x00" * (512 - 24 - 36))
        for lnum in (1, 2):
            self.node(UBIFS_MST, master((0, 0, 0)), lnum=lnum)
            self.node(UBIFS_MST, master(root), lnum=lnum)
        out = bytearray()
        for lnum in range(leb_count):
            leb = bytes(self.lebs.get(lnum, b""))
            out += leb + b"\xff" * (UBIFS_LEB - len(leb))
        return bytes(out)


def build_ubifs(files, deleted=(), default_compr=2):
    """A UBIFS image holding `files` - [(path, mode, compr, payload, size)] -
    plus `deleted` files whose nodes are written but left out of the index.

    compr is 0 none, 1 LZO, 2 zlib, 3 zstd; for LZO and zstd the payload is
    the compressed stream and size the plain length.
    """
    b = UBIFSBuilder()
    leaves = [b.inode(1, 0o040755, 0, nlink=2)]
    dirs = {"": 1}
    next_inum = 2

    def directory(path):
        nonlocal next_inum
        if path in dirs:
            return dirs[path]
        parent, _, name = path.rpartition("/")
        pinum = directory(parent)
        inum = dirs[path] = next_inum
        next_inum += 1
        leaves.append(b.dentry(pinum, name, inum, 1))
        leaves.append(b.inode(inum, 0o040755, 0, nlink=2))
        return inum

    def regular(path, mode, compr, payload, size):
        nonlocal next_inum
        parent, _, name = path.rpartition("/")
        pinum = directory(parent)
        inum = next_inum
        next_inum += 1
        refs = [b.dentry(pinum, name, inum, 0), b.inode(inum, mode, size)]
        if compr == 2:
            for block in range(0, size, 4096):
                chunk = payload[block:block + 4096]
                squeeze = zlib.compressobj(9, zlib.DEFLATED, -15)
                refs.append(b.data(inum, block // 4096, len(chunk), 2,
                                   squeeze.compress(chunk) + squeeze.flush()))
        else:
            assert size <= 4096 or compr == 0, "one block per stream"
            for block in range(0, max(size, 1), 4096):
                chunk = payload[block:block + 4096] if compr == 0 else payload
                refs.append(b.data(inum, block // 4096,
                                   min(4096, size - block), compr, chunk))
        return refs

    for spec in files:
        leaves.extend(regular(*spec))
    for spec in deleted:
        regular(*spec)                  # on the flash, not in the index

    # Two levels: the leaves split between two index nodes under the root.
    half = len(leaves) // 2
    root = b.index(1, [b.index(0, leaves[:half]), b.index(0, leaves[half:])])
    return b.image(root, default_compr)


def ubifs_rootfs_files():
    busybox = (b"\x7fELF\x01\x01\x01" + b"\x00" * 9
               + struct.pack("<HH", 2, 40)            # ET_EXEC, EM_ARM
               + strings_blob(["BusyBox v1.36.1 (2023-11-14 20:19:46 UTC)",
                               "usage: busybox [function]"])
               + bytes(range(256)) * 20)              # past one 4 KiB block
    release = (b'NAME="OpenWrt"\nVERSION="23.05.2"\nID=openwrt\n'
               b'PRETTY_NAME="OpenWrt 23.05.2"\n')
    status = (b"Package: dnsmasq\nVersion: 2.89-r1\n"
              b"Architecture: arm_cortex-a7\nLicense: GPL-2.0-only\n\n")
    motd, motd_size = lzo_reference("text")
    notes, notes_size = zstd_reference()
    return [
        ("/bin/busybox", 0o100755, 2, busybox, len(busybox)),
        ("/etc/os-release", 0o100644, 0, release, len(release)),
        ("/usr/lib/opkg/status", 0o100644, 2, status, len(status)),
        ("/etc/motd", 0o100644, 1, motd, motd_size),
        ("/etc/notes", 0o100644, 3, notes, notes_size),
    ]


def ubifs_deleted_files():
    dropbear = (b"\x7fELF\x01\x01\x01" + b"\x00" * 9
                + struct.pack("<HH", 2, 40)
                + strings_blob(["SSH-2.0-dropbear_2022.82",
                                "dropbear: removed before the last commit"]))
    return [("/usr/sbin/dropbear", 0o100755, 0, dropbear, len(dropbear))]


@fixture("ubifs_rootfs.bin")
def build_ubifs_rootfs():
    """A raw UBIFS rootfs, as mkfs.ubifs writes it before ubinize."""
    return build_ubifs(ubifs_rootfs_files(), ubifs_deleted_files())


UBI_PEB = 16384
UBI_VID_OFFSET, UBI_DATA_OFFSET = 512, 1024
UBI_LAYOUT_VOLUME = 0x7FFFEFFF


def ubi_ec_header():
    head = struct.pack(">4sB3xQIII32x", b"UBI#", 1, 0, UBI_VID_OFFSET,
                       UBI_DATA_OFFSET, 0x5EED)
    return head + struct.pack(">I", ubi_crc(head))


def ubi_vid_header(vol_id, lnum, sqnum, vol_type=1, compat=0):
    head = struct.pack(">4sBBBBII4xIIII4xQ12x", b"UBI!", 1, vol_type, 0, compat,
                       vol_id, lnum, 0, 0, 0, 0, sqnum)
    return head + struct.pack(">I", ubi_crc(head))


def ubi_peb(vol_id, lnum, sqnum, payload, compat=0):
    assert len(payload) <= UBI_PEB - UBI_DATA_OFFSET, "payload overflows the block"
    peb = bytearray(b"\xff" * UBI_PEB)
    peb[0:64] = ubi_ec_header()
    peb[UBI_VID_OFFSET:UBI_VID_OFFSET + 64] = ubi_vid_header(vol_id, lnum, sqnum,
                                                             compat=compat)
    peb[UBI_DATA_OFFSET:UBI_DATA_OFFSET + len(payload)] = payload
    return bytes(peb)


def ubi_volume_table(volumes):
    records = b""
    # As many records as fit in a logical block, up to 128: 89 here.
    for index in range(min(128, UBIFS_LEB // 172)):
        if index < len(volumes):
            name = volumes[index][0].encode("ascii")
            record = struct.pack(">IIIBBH", volumes[index][1], 1, 0, 1, 0, len(name))
            record += name + b"\x00" * (128 - len(name)) + b"\x00" * 24
        else:
            record = b"\x00" * 168
        records += record + struct.pack(">I", ubi_crc(record))
    return records


@fixture("ubi_flash.bin")
def build_ubi_flash():
    """A NAND UBI image: volume 0 a UBIFS data partition, volume 1 a CramFS
    rootfs. The rootfs is not first, so taking the first filesystem as the
    root would read the wrong one."""
    library = (b"\x7fELF\x01\x01\x01" + b"\x00" * 9
               + struct.pack("<HH", 3, 40)
               + strings_blob(["libcurl/8.4.0 OpenSSL/3.0.12",
                               "installed to the data volume"]))
    data_volume = build_ubifs([("/lib/libcurl.so.4", 0o100755, 2, library,
                                len(library))])
    rootfs = build_cramfs_rootfs()
    rootfs += b"\xff" * (-len(rootfs) % UBIFS_LEB)

    def lebs(blob):
        return [blob[i:i + UBIFS_LEB] for i in range(0, len(blob), UBIFS_LEB)]

    sqnum = 0
    pebs = []
    table = ubi_volume_table([("data", len(lebs(data_volume))),
                              ("rootfs", len(lebs(rootfs)))])
    for lnum in (0, 1):
        sqnum += 1
        pebs.append(ubi_peb(UBI_LAYOUT_VOLUME, lnum, sqnum, table, compat=5))
    # A stale copy of rootfs LEB 0 - an interrupted wear-levelling move -
    # whose banner must lose to the newer copy written after it.
    stale = bytearray(lebs(rootfs)[0])
    stale[-64:] = b"SSH-2.0-dropbear_2019.78 stale copy".ljust(64, b"\x00")
    sqnum += 1
    pebs.append(ubi_peb(1, 0, sqnum, bytes(stale)))
    for vol_id, blob in ((0, data_volume), (1, rootfs)):
        for lnum, leb in enumerate(lebs(blob)):
            sqnum += 1
            pebs.append(ubi_peb(vol_id, lnum, sqnum, leb))
    pebs.append(b"\xff" * UBI_PEB)                     # an erased block
    # Wear levelling leaves blocks in no particular order; keep the layout
    # volume first so the image still starts where a scanner expects.
    head, rest = pebs[:2], pebs[2:]
    rng("ubi_flash.bin").shuffle(rest)
    return b"".join(head + rest)


# --- FIT, cpio and OpenWrt's image metadata ----------------------------------- #
#
# The OpenWrt release images these readers were verified against prove they
# read real toolchain output. What those two images do not hold: the
# `data-offset` placement, a kernel stored uncompressed, a hash that fails, an
# initramfs built into a kernel, or the cpio details the kernel honours -
# concatenated archives, hard links whose data sits on the last entry, a
# later entry replacing an earlier one. These fixtures do.

def fdt_blob(tree):
    """A flattened device tree from nested dicts: a bytes value is a
    property, a dict a child node. Written out here rather than borrowed
    from fit.py, so the fixture does not share the reader's understanding."""
    strings, offsets = b"", {}
    struct_ = bytearray()

    def name_offset(name):
        nonlocal strings
        if name not in offsets:
            offsets[name] = len(strings)
            strings += name.encode("ascii") + b"\x00"
        return offsets[name]

    def pad():
        struct_.extend(b"\x00" * (-len(struct_) % 4))

    def node(name, body):
        struct_.extend(struct.pack(">I", 1) + name.encode("ascii") + b"\x00")
        pad()
        for key, value in body.items():
            if isinstance(value, dict):
                continue
            struct_.extend(struct.pack(">III", 3, len(value), name_offset(key)))
            struct_.extend(value)
            pad()
        for key, value in body.items():
            if isinstance(value, dict):
                node(key, value)
        struct_.extend(struct.pack(">I", 2))

    node("", tree)
    struct_.extend(struct.pack(">I", 9))
    off_rsvmap = 40
    off_struct = off_rsvmap + 16                     # one empty reservation
    off_strings = off_struct + len(struct_)
    total = off_strings + len(strings)
    header = struct.pack(">10I", 0xD00DFEED, total, off_struct, off_strings,
                         off_rsvmap, 17, 16, 0, len(strings), len(struct_))
    return header + b"\x00" * 16 + bytes(struct_) + strings


def fdt_str(text):
    return text.encode("ascii") + b"\x00"


def fdt_u32(value):
    return struct.pack(">I", value)


def fit_hashes(blob, algos=("crc32", "sha1")):
    nodes = {}
    for index, algo in enumerate(algos, 1):
        value = (struct.pack(">I", zlib.crc32(blob) & 0xFFFFFFFF) if algo == "crc32"
                 else hashlib.new(algo, blob).digest())
        nodes[f"hash-{index}"] = {"value": value, "algo": fdt_str(algo)}
    return nodes


def cpio_newc(entries):
    """A newc cpio archive from (name, mode, data, ino, nlink) entries."""
    out = bytearray()
    for name, mode, data, ino, nlink in entries + [("TRAILER!!!", 0, b"", 0, 1)]:
        raw = name.encode("ascii") + b"\x00"
        fields = [ino, mode, 0, 0, nlink, 0, len(data), 0, 0, 0, 0, len(raw), 0]
        out += b"070701" + "".join(f"{f:08X}" for f in fields).encode("ascii")
        out += raw
        out.extend(b"\x00" * (-len(out) % 4))
        out += data
        out.extend(b"\x00" * (-len(out) % 4))
    return bytes(out)


def aarch64_elf(strings):
    return (b"\x7fELF\x02\x01\x01" + b"\x00" * 9
            + struct.pack("<HH", 2, 183)                # ET_EXEC, EM_AARCH64
            + strings_blob(strings) + bytes(128))       # past the 64-byte floor


def initramfs_archives():
    """An early archive, NUL padding, then the real one - as a kernel with
    CPU microcode prepended receives it."""
    early = cpio_newc([
        ("kernel", 0o040755, b"", 1, 2),
        ("kernel/x86/microcode/GenuineIntel.bin", 0o100644, b"\x01" * 64, 2, 1),
        ("etc/os-release", 0o100644, b'NAME="Replaced"\nVERSION="0.1"\n', 3, 1),
    ])
    busybox = aarch64_elf(["BusyBox v1.36.1 (2024-09-01 00:00:00 UTC)",
                           "usage: busybox [function]"])
    release = (b'NAME="OpenWrt"\nVERSION="23.05.5"\nID=openwrt\n'
               b'PRETTY_NAME="OpenWrt 23.05.5"\n')
    status = (b"Package: dnsmasq\nVersion: 2.90-r3\n"
              b"Architecture: aarch64_cortex-a53\n\n"
              b"Package: uhttpd\nVersion: 2023.06.25~34a8a74d-r4\n"
              b"Architecture: aarch64_cortex-a53\n\n")
    main = cpio_newc([
        (".", 0o040755, b"", 10, 2),
        ("./bin", 0o040755, b"", 11, 2),
        # A hard-link pair: the data is on the last entry only.
        ("./bin/sh", 0o100755, b"", 12, 2),
        ("./bin/busybox", 0o100755, busybox, 12, 2),
        ("./sbin", 0o040755, b"", 13, 2),
        ("./sbin/init", 0o120777, b"/bin/busybox", 14, 1),
        ("./etc", 0o040755, b"", 15, 2),
        ("./etc/os-release", 0o100644, release, 16, 1),
        ("./usr", 0o040755, b"", 17, 2),
        ("./usr/lib", 0o040755, b"", 18, 2),
        ("./usr/lib/opkg", 0o040755, b"", 19, 2),
        ("./usr/lib/opkg/status", 0o100644, status, 20, 1),
        ("./.profile", 0o100644, b"export PATH=/bin:/sbin\n", 21, 1),
        ("./dev", 0o040755, b"", 22, 2),
        ("./dev/console", 0o020600, b"", 23, 1),
    ])
    return early + b"\x00" * 512 + main


def fixture_kernel(version):
    r = rng("fit-kernel-" + version)
    return strings_blob([
        f"Linux version {version} (builder@fixture) (aarch64-openwrt-linux-musl-gcc) #0 SMP",
        "Kernel command line: console=ttyS0,115200n1",
    ]) * 4 + filler(r, 8192)


def fixture_dtb(model):
    return fdt_blob({"model": fdt_str(model),
                     "compatible": fdt_str("fw2sbom,test-board"),
                     "#address-cells": fdt_u32(1)})


@fixture("fit_initramfs.bin")
def build_fit_initramfs():
    """A FIT with its images inside the tree, as OpenWrt's initramfs images
    are built: an LZMA kernel, an xz ramdisk, a device tree.

    The kernel is compressed with lc=1, lp=2, pb=2, so its first byte is 0x6d
    rather than the 0x5d a magic scan looks for; only the FIT's declared
    compression says what it is.
    """
    kernel = lzma.compress(fixture_kernel("5.15.167"), format=lzma.FORMAT_ALONE,
                           filters=[{"id": lzma.FILTER_LZMA1, "lc": 1, "lp": 2,
                                     "pb": 2, "dict_size": 1 << 20}])
    assert kernel[0] == 0x6D
    ramdisk = lzma.compress(initramfs_archives(), format=lzma.FORMAT_XZ)
    dtb = fixture_dtb("fw2sbom Test Board (initramfs)")
    tree = {
        "timestamp": fdt_u32(1726000000),
        "description": fdt_str("ARM64 OpenWrt FIT (Flattened Image Tree)"),
        "#address-cells": fdt_u32(1),
        "images": {
            "kernel-1": dict({"description": fdt_str("ARM64 OpenWrt Linux-5.15.167"),
                              "data": kernel, "type": fdt_str("kernel"),
                              "arch": fdt_str("arm64"), "os": fdt_str("linux"),
                              "compression": fdt_str("lzma")},
                             **fit_hashes(kernel, ("crc32", "sha1"))),
            # No compression property: U-Boot hands the ramdisk on untouched
            # and the kernel decompresses it.
            "initrd-1": dict({"description": fdt_str("ARM64 OpenWrt initrd"),
                              "data": ramdisk, "type": fdt_str("ramdisk"),
                              "arch": fdt_str("arm64"), "os": fdt_str("linux")},
                             **fit_hashes(ramdisk, ("crc32", "sha256"))),
            "fdt-1": dict({"description": fdt_str("ARM64 OpenWrt device tree blob"),
                           "data": dtb, "type": fdt_str("flat_dt"),
                           "arch": fdt_str("arm64"), "compression": fdt_str("none")},
                          **fit_hashes(dtb)),
        },
        "configurations": {
            "default": fdt_str("config-1"),
            "config-1": {"description": fdt_str("OpenWrt fw2sbom test board"),
                         "kernel": fdt_str("kernel-1"), "fdt": fdt_str("fdt-1"),
                         "ramdisk": fdt_str("initrd-1")},
        },
    }
    image = fdt_blob(tree)
    return image + b"\xff" * (-len(image) % 0x10000)


def fwtool_trailer(metadata):
    """OpenWrt's metadata and signature blocks, each with its 16-byte trailer."""
    block = json.dumps(metadata, indent=1).encode("ascii") + b"\n"
    out = block + struct.pack(">4sIB3xI", b"FWx0", 0, 1, len(block) + 16)
    signature = b"# fake certificate"
    out += signature + struct.pack(">4sIB3xI", b"FWx0", 0, 0, len(signature) + 16)
    return out


@fixture("fit_sysupgrade.bin")
def build_fit_sysupgrade():
    """A FIT with its images after the tree, as OpenWrt's sysupgrade images
    are built: a gzip kernel and a device tree placed by `data-position`, a
    CramFS rootfs by `data-offset`, and OpenWrt's metadata at the end."""
    kernel = gzip.compress(fixture_kernel("6.6.52"), 9)
    dtb = fixture_dtb("fw2sbom Test Board (sysupgrade)")
    rootfs = build_cramfs_rootfs()
    header_size = 0x1000

    def aligned(n):
        return n + (-n % 0x1000)

    kernel_at = header_size
    dtb_at = aligned(kernel_at + len(kernel))
    rootfs_at = aligned(dtb_at + len(dtb))

    def tree(rootfs_offset):
        return {
            "timestamp": fdt_u32(1726000000),
            "description": fdt_str("ARM64 OpenWrt FIT (Flattened Image Tree)"),
            "images": {
                "kernel-1": dict({"data-size": fdt_u32(len(kernel)),
                                  "data-position": fdt_u32(kernel_at),
                                  "description": fdt_str("ARM64 OpenWrt Linux-6.6.52"),
                                  "type": fdt_str("kernel"), "arch": fdt_str("arm64"),
                                  "os": fdt_str("linux"), "compression": fdt_str("gzip")},
                                 **fit_hashes(kernel)),
                "fdt-1": dict({"data-size": fdt_u32(len(dtb)),
                               "data-position": fdt_u32(dtb_at),
                               "description": fdt_str("device tree blob"),
                               "type": fdt_str("flat_dt"), "arch": fdt_str("arm64"),
                               "compression": fdt_str("none")},
                              **fit_hashes(dtb)),
                # data-offset counts from the end of the tree, 4-aligned.
                "rootfs-1": dict({"data-size": fdt_u32(len(rootfs)),
                                  "data-offset": fdt_u32(rootfs_offset),
                                  "description": fdt_str("ARM64 OpenWrt rootfs"),
                                  "type": fdt_str("filesystem"), "arch": fdt_str("arm64"),
                                  "compression": fdt_str("none")},
                                 **fit_hashes(rootfs)),
            },
            "configurations": {"default": fdt_str("config-1"),
                               "config-1": {"kernel": fdt_str("kernel-1"),
                                            "fdt": fdt_str("fdt-1"),
                                            "loadables": fdt_str("rootfs-1")}},
        }

    probe = fdt_blob(tree(0))                      # fixed-size fields: same size
    rootfs_offset = rootfs_at - ((len(probe) + 3) & ~3)
    header = fdt_blob(tree(rootfs_offset))
    assert len(header) == len(probe) and len(header) <= header_size
    image = bytearray(b"\xff" * aligned(rootfs_at + len(rootfs)))
    image[0:len(header)] = header
    image[kernel_at:kernel_at + len(kernel)] = kernel
    image[dtb_at:dtb_at + len(dtb)] = dtb
    image[rootfs_at:rootfs_at + len(rootfs)] = rootfs
    return bytes(image) + fwtool_trailer({
        "metadata_version": "1.1", "compat_version": "1.0",
        "supported_devices": ["fw2sbom,test-board"],
        "version": {"dist": "OpenWrt", "version": "23.05.5",
                    "revision": "r24106-10cc5fcd00", "target": "mediatek/filogic",
                    "board": "fw2sbom_test-board"}})


# --- ext2 / ext3 / ext4 --------------------------------------------------------
#
# The OpenWrt x86-64 release image this reader was checked against has 1,069
# files, every one identical to the same release's SquashFS - but they are
# all extent-mapped at depth 0, and none is inline, encrypted, sparse or
# indirect-mapped. The unblob samples hold three six-byte files. These do.

EXT_BLOCK = 1024


class ExtBuilder:
    """A single-group ext filesystem laid out by hand, 1 KiB blocks."""

    def __init__(self, inode_size=128, inodes=64, name="fw2sbom"):
        self.inode_size = inode_size
        self.inodes_count = inodes
        self.name = name
        self.blocks = {}                       # number -> bytes
        table_blocks = inodes * inode_size // EXT_BLOCK
        self.inode_table = 5                    # 1 sb, 2 gdt, 3-4 bitmaps
        self.next_block = self.inode_table + table_blocks
        self.inodes = {}                        # number -> bytearray
        self.next_inode = 11
        self.children = {2: []}                 # dir inode -> [(name, ino, type)]
        self.paths = {"": 2}

    def alloc(self, count=1):
        first = self.next_block
        self.next_block += count
        return first

    def put(self, number, data):
        assert len(data) <= EXT_BLOCK
        self.blocks[number] = data.ljust(EXT_BLOCK, b"\0")

    def new_inode(self, mode, size, flags=0, links=1):
        number = self.next_inode
        self.next_inode += 1
        raw = bytearray(self.inode_size)
        struct.pack_into("<HHI", raw, 0, mode, 0, size & 0xFFFFFFFF)
        struct.pack_into("<HI I", raw, 26, links, 0, flags)
        struct.pack_into("<I", raw, 108, size >> 32)
        if self.inode_size > 128:
            struct.pack_into("<H", raw, 128, 32)          # i_extra_isize
        self.inodes[number] = raw
        return number

    def link(self, path, number, kind):
        parent, _, name = path.rpartition("/")
        self.children[self.paths[parent]].append((name, number, kind))

    def mkdir(self, path, indexed=False):
        number = self.new_inode(0o040755, 0, flags=0x1000 if indexed else 0, links=2)
        self.link(path, number, 2)
        self.paths[path] = number
        self.children[number] = []
        if indexed:
            self.indexed = getattr(self, "indexed", set()) | {number}
        return number

    def blockmap_file(self, path, data, holes=()):
        """ext2/3 block pointers: direct, single, double indirect."""
        count = -(-len(data) // EXT_BLOCK)
        pointers = []
        for logical in range(count):
            if logical in holes:
                pointers.append(0)
                continue
            block = self.alloc()
            self.put(block, data[logical * EXT_BLOCK:(logical + 1) * EXT_BLOCK])
            pointers.append(block)
        per = EXT_BLOCK // 4
        i_block = pointers[:12] + [0] * (12 - len(pointers[:12]))
        rest = pointers[12:]
        single, rest = rest[:per], rest[per:]
        i_block.append(self._pointer_block(single) if single else 0)
        if rest:
            children = [self._pointer_block(rest[i:i + per])
                        for i in range(0, len(rest), per)]
            i_block.append(self._pointer_block(children))
        else:
            i_block.append(0)
        i_block.append(0)
        number = self.new_inode(0o100755, len(data))
        self.inodes[number][40:100] = struct.pack("<15I", *i_block)
        self.link(path, number, 1)
        return number

    def _pointer_block(self, pointers):
        block = self.alloc()
        self.put(block, struct.pack(f"<{len(pointers)}I", *pointers))
        return block

    def extent_file(self, path, data, uninitialised=(), tree=False, flags=0):
        """ext4 extents, one per block run; `tree` puts them in a leaf block
        under a depth-1 index, as a fragmented file's extents are."""
        count = -(-len(data) // EXT_BLOCK)
        extents = []
        for logical in range(count):
            block = self.alloc()
            self.put(block, data[logical * EXT_BLOCK:(logical + 1) * EXT_BLOCK])
            length = 1 | (0x8000 if logical in uninitialised else 0)
            extents.append(struct.pack("<IHHI", logical, length, 0, block))
        header = lambda n, depth: struct.pack("<HHHHI", 0xF30A, n, 4 if depth else 84, depth, 0)
        if tree:
            leaf = self.alloc()
            self.put(leaf, header(len(extents), 0) + b"".join(extents))
            i_block = header(1, 1) + struct.pack("<IIHH", 0, leaf, 0, 0)
        else:
            assert len(extents) <= 4
            i_block = header(len(extents), 0) + b"".join(extents)
        number = self.new_inode(0o100755, len(data), flags=0x80000 | flags)
        self.inodes[number][40:40 + len(i_block)] = i_block
        self.link(path, number, 1)
        return number

    def inline_file(self, path, data):
        """ext4 inline data: 60 bytes in i_block, the rest in system.data."""
        assert self.inode_size >= 256 and len(data) <= 60 + 28
        number = self.new_inode(0o100644, len(data), flags=0x10000000)
        raw = self.inodes[number]
        raw[40:40 + min(60, len(data))] = data[:60]
        rest = data[60:]
        struct.pack_into("<I", raw, 160, 0xEA020000)
        struct.pack_into("<BBHII I", raw, 164, 4, 7, 64, 0, len(rest), 0)
        raw[180:184] = b"data"
        raw[164 + 64:164 + 64 + len(rest)] = rest
        self.link(path, number, 1)
        return number

    def symlink(self, path, target):
        raw = target.encode("ascii")
        if len(raw) < 60:
            number = self.new_inode(0o120777, len(raw))
            self.inodes[number][40:40 + len(raw)] = raw
        else:
            block = self.alloc()
            self.put(block, raw)
            number = self.new_inode(0o120777, len(raw))
            struct.pack_into("<I", self.inodes[number], 40, block)
        self.link(path, number, 7)
        return number

    def deleted_entry(self, directory, name):
        """A directory entry whose inode is 0: what a removal leaves."""
        self.children[self.paths[directory]].append((name, 0, 1))

    def _directory_blocks(self, number):
        def entry(name, ino, kind, rec_len=None):
            raw = name.encode("ascii")
            length = rec_len or (8 + len(raw) + 3) & ~3
            return struct.pack("<IHBB", ino, length, len(raw), kind) + raw.ljust(length - 8, b"\0")

        parent = next((p for p, kids in self.children.items()
                       if any(k[1] == number for k in kids)), 2)
        dots = [(".", number, 2), ("..", parent, 2)]
        entries = sorted(self.children[number])
        blocks = []
        if number in getattr(self, "indexed", set()):
            # An htree root: ".", then ".." spanning the block with the index
            # hidden inside it, as the kernel writes one.
            root = entry(".", number, 2, 12) + entry("..", parent, 2, EXT_BLOCK - 12)
            blocks.append(root)
            dots = []
        current = b""
        for name, ino, kind in dots + entries:
            e = entry(name, ino, kind)
            if len(current) + len(e) > EXT_BLOCK:
                blocks.append(current)
                current = b""
            current += e
        blocks.append(current)
        out = []
        for block in blocks:
            if len(block) < EXT_BLOCK:
                # The last entry's rec_len runs to the end of the block.
                at, last = 0, 0
                while at < len(block):
                    last = at
                    at += struct.unpack_from("<H", block, at + 4)[0]
                block = bytearray(block.ljust(EXT_BLOCK, b"\0"))
                struct.pack_into("<H", block, last + 4, EXT_BLOCK - last)
            out.append(bytes(block))
        return out

    def image(self, incompat=0x2, compat=0x0, ro_compat=0x1):
        # Directories last, so every entry is known.
        for number in list(self.children):
            blocks = self._directory_blocks(number)
            first = self.alloc(len(blocks))
            for i, block in enumerate(blocks):
                self.put(first + i, block)
            raw = self.inodes.setdefault(number, bytearray(self.inode_size))
            if number == 2:
                struct.pack_into("<H", raw, 0, 0o040755)
                struct.pack_into("<H", raw, 26, 2)
                if self.inode_size > 128:
                    struct.pack_into("<H", raw, 128, 32)
            struct.pack_into("<I", raw, 4, len(blocks) * EXT_BLOCK)
            pointers = list(range(first, first + len(blocks)))
            raw[40:40 + 4 * len(pointers)] = struct.pack(f"<{len(pointers)}I", *pointers)
        total = self.next_block + 1
        sb = bytearray(1024)
        struct.pack_into("<IIIIIII", sb, 0, self.inodes_count, total, 0, 0, 0, 1, 0)
        struct.pack_into("<I", sb, 32, 8192)
        struct.pack_into("<I", sb, 40, self.inodes_count)
        struct.pack_into("<HH", sb, 56, 0xEF53, 1)
        struct.pack_into("<I", sb, 76, 1)
        struct.pack_into("<IH", sb, 84, 11, self.inode_size)
        struct.pack_into("<III", sb, 92, compat, incompat, ro_compat)
        sb[120:136] = self.name.encode("ascii").ljust(16, b"\0")
        out = bytearray(total * EXT_BLOCK)
        out[1024:2048] = sb
        struct.pack_into("<III", out, 2 * EXT_BLOCK, 3, 4, self.inode_table)
        for number, raw in self.inodes.items():
            at = self.inode_table * EXT_BLOCK + (number - 1) * self.inode_size
            out[at:at + self.inode_size] = raw
        for number, block in self.blocks.items():
            out[number * EXT_BLOCK:(number + 1) * EXT_BLOCK] = block
        return bytes(out)


def x86_64_elf(strings, pad=0):
    return (b"\x7fELF\x02\x01\x01" + b"\x00" * 9
            + struct.pack("<HH", 2, 62)                 # ET_EXEC, EM_X86_64
            + strings_blob(strings) + bytes(128 + pad))


@fixture("ext2_rootfs.bin")
def build_ext2_rootfs():
    """ext2 with block maps: a 300 KiB binary reaches single and double
    indirect blocks, a sparse file has a hole, symlinks are fast and slow,
    and a removed file leaves an entry with inode 0 behind."""
    b = ExtBuilder()
    for d in ("/bin", "/sbin", "/etc", "/usr", "/usr/lib", "/usr/lib/opkg", "/var"):
        b.mkdir(d)
    busybox = x86_64_elf(["BusyBox v1.36.1 (2024-09-01 00:00:00 UTC)"],
                         pad=300 * 1024)
    busybox = busybox[:-64] + b"banner at the very end: BusyBox v1.36.1\0".ljust(64, b"\0")
    b.blockmap_file("/bin/busybox", busybox)
    sparse = b"head of a sparse file\n".ljust(EXT_BLOCK, b"\0") * 3
    b.blockmap_file("/var/sparse.db", sparse, holes={1})
    b.blockmap_file("/etc/os-release",
                    b'NAME="Debian GNU/Linux"\nVERSION_ID="12"\nID=debian\n'
                    b'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n')
    b.blockmap_file("/usr/lib/opkg/status",
                    b"Package: openssh-server\nVersion: 9.2p1-2\n"
                    b"Architecture: x86_64\n\n")
    b.symlink("/sbin/init", "/bin/busybox")
    b.symlink("/etc/long-link",
              "/usr/share/a/deliberately/long/target/path/beyond/sixty/bytes/x")
    b.deleted_entry("/bin", "dropbear")
    return b.image(incompat=0x2)


def build_ext4_rootfs():
    b = ExtBuilder(inode_size=256, name="rootfs")
    for d in ("/bin", "/etc", "/usr", "/usr/lib", "/usr/lib/opkg", "/opt"):
        b.mkdir(d)
    b.mkdir("/usr/share", indexed=True)
    library = x86_64_elf(["libcurl/8.4.0 OpenSSL/3.0.12"], pad=4000)
    b.extent_file("/usr/lib/libcurl.so.4", library, tree=True)
    b.extent_file("/opt/preallocated.bin", b"written part\n".ljust(EXT_BLOCK, b"\0") * 2,
                  uninitialised={1})
    b.inline_file("/etc/os-release",
                  b'NAME="OpenWrt"\nVERSION="23.05.5"\nID=openwrt\n'
                  b'PRETTY_NAME="OpenWrt 23.05.5"\n')
    b.extent_file("/usr/lib/opkg/status",
                  b"Package: dnsmasq\nVersion: 2.90-r3\nArchitecture: x86_64\n\n")
    b.extent_file("/bin/busybox", x86_64_elf(["BusyBox v1.36.1 (2024-09-01)"]))
    for i in range(40):                          # enough to fill the htree block
        b.extent_file(f"/usr/share/data-file-{i:02d}.txt", b"x" * 20)
    b.extent_file("/etc/secret.conf", b"\x9c" * 700, flags=0x800)   # fscrypt
    # FILETYPE | RECOVER | EXTENTS | INLINE_DATA; has_journal.
    return b.image(incompat=0x2 | 0x4 | 0x40 | 0x8000, compat=0x4, ro_compat=0x1)


def build_ext4_boot():
    b = ExtBuilder(name="kernel")
    b.mkdir("/boot")
    b.blockmap_file("/boot/vmlinuz", b"Linux version 6.6.52 (fixture) #1 SMP\0" * 20)
    return b.image()


@fixture("ext4_disk.img.gz")
def build_ext4_disk():
    """A disk image shipped gzipped, as OpenWrt's x86 images are: an MBR,
    a boot partition, then the ext4 rootfs holding every ext4 feature the
    release sample does not."""
    boot, rootfs = build_ext4_boot(), build_ext4_rootfs()
    boot_at = 64 * 512
    root_at = boot_at + len(boot) + (-len(boot) % 4096)
    size = root_at + len(rootfs) + (-len(rootfs) % 4096)
    disk = bytearray(size)
    disk[0:3] = b"\xeb\x63\x90"
    for index, (start, length) in enumerate(((boot_at, len(boot)), (root_at, len(rootfs)))):
        entry = struct.pack("<B3sB3sII", 0x80 if index == 0 else 0, b"\0" * 3, 0x83,
                            b"\0" * 3, start // 512, -(-length // 512))
        disk[446 + 16 * index:462 + 16 * index] = entry
    disk[510:512] = b"\x55\xaa"
    disk[boot_at:boot_at + len(boot)] = boot
    disk[root_at:root_at + len(rootfs)] = rootfs
    return gzip.compress(bytes(disk), 9, mtime=0)


# --- YAFFS2 ----------------------------------------------------------------------
#
# The unblob samples cover every geometry and both byte orders, and hold fruit.
# This one holds software, a deleted binary still on the flash, and a chunk
# written twice where the newer copy must win.

YAFFS_PAGE, YAFFS_SPARE = 2048, 64


def yaffs2_chunk(order, data, seq, obj_id, chunk_id, n_bytes):
    page = data.ljust(YAFFS_PAGE, b"\xff")
    tags = struct.pack(order + "IIII", seq, obj_id, chunk_id, n_bytes)
    spare = (b"\xff\xff" + tags).ljust(YAFFS_SPARE, b"\xff")     # tags at 2
    return page + spare


def yaffs2_header(order, kind, parent, name, mode, size=0xFFFFFFFF, alias=b""):
    head = struct.pack(order + "II", kind, parent) + b"\xff\xff"
    head += name.encode("ascii").ljust(256, b"\0")
    head += b"\xff\xff"                                        # to 268
    head += struct.pack(order + "IIIIIIIi", mode, 0, 0, 0, 0, 0, size, -1)
    head += alias.ljust(160, b"\0")
    return head.ljust(512, b"\xff")


@fixture("yaffs2_rootfs.bin")
def build_yaffs2_rootfs():
    """A big-endian YAFFS2 rootfs, 2 KiB pages and 64-byte spare, tags after
    the bad-block marker - the layout of a MIPS camera's NAND."""
    o = ">"
    busybox = (b"\x7fELF\x01\x02\x01" + b"\x00" * 9 + struct.pack(">HH", 2, 8)
               + strings_blob(["BusyBox v1.31.1 (2020-05-01 00:00:00 UTC)"])
               + bytes(3000))                                   # two chunks
    dropbear = (b"\x7fELF\x01\x02\x01" + b"\x00" * 9 + struct.pack(">HH", 2, 8)
                + strings_blob(["SSH-2.0-dropbear_2019.78"]) + bytes(200))
    old_release = b'NAME="VendorOS"\nVERSION="0.1"\n'
    release = b'NAME="HiLinux"\nVERSION="2.0.4"\nID=hilinux\nPRETTY_NAME="HiLinux 2.0.4"\n'
    status = b"Package: lighttpd\nVersion: 1.4.59-1\nArchitecture: mips_24kc\n\n"
    chunks = []
    add = lambda *a: chunks.append(yaffs2_chunk(o, *a))
    seq = 0x1000
    add(yaffs2_header(o, 3, 1, "bin", 0o40755), seq, 0x101, 0, 0xFFFF)
    add(yaffs2_header(o, 3, 1, "etc", 0o40755), seq, 0x102, 0, 0xFFFF)
    add(yaffs2_header(o, 3, 1, "usr", 0o40755), seq, 0x103, 0, 0xFFFF)
    add(yaffs2_header(o, 3, 0x103, "lib", 0o40755), seq, 0x104, 0, 0xFFFF)
    add(yaffs2_header(o, 3, 0x104, "opkg", 0o40755), seq, 0x105, 0, 0xFFFF)
    add(yaffs2_header(o, 1, 0x101, "busybox", 0o100755, len(busybox)), seq, 0x110, 0, 0xFFFF)
    add(busybox[:YAFFS_PAGE], seq, 0x110, 1, YAFFS_PAGE)
    add(busybox[YAFFS_PAGE:], seq, 0x110, 2, len(busybox) - YAFFS_PAGE)
    add(yaffs2_header(o, 1, 0x102, "os-release", 0o100644, len(release)), seq, 0x111, 0, 0xFFFF)
    add(old_release, seq, 0x111, 1, len(old_release))          # superseded below
    add(yaffs2_header(o, 1, 0x105, "status", 0o100644, len(status)), seq, 0x112, 0, 0xFFFF)
    add(status, seq, 0x112, 1, len(status))
    add(yaffs2_header(o, 2, 0x101, "sh", 0o120777, alias=b"busybox"), seq, 0x113, 0, 0xFFFF)
    add(yaffs2_header(o, 1, 0x101, "dropbear", 0o100755, len(dropbear)), seq, 0x114, 0, 0xFFFF)
    add(dropbear, seq, 0x114, 1, len(dropbear))
    # A later block: os-release rewritten, dropbear deleted (moved under the
    # "deleted" directory, object 4), as YAFFS does on the device.
    seq = 0x1001
    add(release, seq, 0x111, 1, len(release))
    add(yaffs2_header(o, 1, 4, "dropbear", 0o100755, len(dropbear)), seq, 0x114, 0, 0xFFFF)
    image = b"".join(chunks)
    erased = (b"\xff" * (YAFFS_PAGE + YAFFS_SPARE)) * 4
    return image + erased


@fixture("kernel_initramfs.bin")
def build_kernel_initramfs():
    """A uImage whose kernel carries its whole userland as a built-in,
    gzip-compressed initramfs - the way a lot of camera firmware ships, with
    no separate root filesystem anywhere in the image."""
    archive = cpio_newc([
        ("bin", 0o040755, b"", 1, 2),
        ("bin/busybox", 0o100755,
         aarch64_elf(["BusyBox v1.35.0 (2023-02-01 00:00:00 UTC)"]), 2, 1),
        ("etc", 0o040755, b"", 3, 2),
        ("etc/os-release", 0o100644,
         b'NAME="CameraOS"\nVERSION="4.2"\nID=cameraos\n', 4, 1),
        ("usr/bin/ipcam", 0o100755,
         aarch64_elf(["SSH-2.0-dropbear_2020.81", "ipcam main loop"]), 5, 1),
    ])
    kernel = (fixture_kernel("4.9.37") + b"\x00" * 64
              + gzip.compress(archive, 9) + b"\x00" * 64 + filler(rng("ki"), 2048))
    compressed = lzma.compress(kernel, format=lzma.FORMAT_ALONE)
    header = struct.pack(">IIIIIIII", 0x27051956, 0, 0, len(compressed),
                         0x80008000, 0x80008000, 0, 0x05160203)   # arm64, lzma
    header += b"ARM64 camera Linux-4.9.37".ljust(32, b"\x00")
    return header + compressed + b"\xff" * 2048


# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #

def main(argv):
    out_dir = argv[1] if len(argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "fixtures")
    os.makedirs(out_dir, exist_ok=True)

    for name in sorted(FIXTURES):
        data = FIXTURES[name]()
        path = os.path.join(out_dir, name)
        with open(path, "wb") as f:
            f.write(data)
        digest = hashlib.sha256(data).hexdigest()
        print(f"{name:<24} {len(data):>8} bytes  sha256:{digest[:16]}")
    print(f"\n{len(FIXTURES)} fixture(s) -> {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
