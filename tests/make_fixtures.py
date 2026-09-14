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
