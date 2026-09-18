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
