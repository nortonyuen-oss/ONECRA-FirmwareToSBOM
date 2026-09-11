#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fw2sbom - Evidence-based CycloneDX 1.6 SBOM generator for embedded firmware
images (.bin): ARM Cortex-M / Zephyr-style images and MCS-51 (8051) images such as
display-controller / monitor-scaler firmware.

Pipeline:
  0. Container handling: detect packetized/record-framed images (vendor ISP dumps
     of the form [checksum|length|page|sequence][payload chunk] repeated) and
     strip the framing before any content analysis.
  1. Binary fingerprint: `file` output (if available), SHA-256/SHA-1/MD5 hashes,
     and instruction-set identification (ARM Cortex-M vector table, MCS-51 vector
     table + opcode profile).
  2. String extraction (printable ASCII runs).
  3. Signature matching against a curated database of common embedded components
     (Zephyr, FreeRTOS, mbed TLS, lwIP, newlib, MCUboot, littlefs, GCC, ...).
  4. Opacity assessment: entropy / blank-flash-run / byte-distribution tests that
     distinguish an analyzable plaintext image from an encrypted or compressed
     one, so an empty result is reported as "opaque", not as "no components".
  5. Embedded standard data: structural detection (parse + validate, not string
     matching) of standardised data blocks such as VESA E-EDID and DDC/CI MCCS
     capability strings.
  6. Emit a CycloneDX 1.6 JSON SBOM where every component carries evidence
     (matched strings + file offsets) and a confidence score.

The resulting SBOM is *binary-derived*: heuristic, possibly incomplete, and clearly
marked as such in metadata. Runs on any Linux with Python 3.8+ (stdlib only).
"""

import argparse
import collections
import hashlib
import json
import math
import os
import re
import shutil
import struct
import subprocess
import sys
import uuid
from datetime import datetime, timezone

import evidence_report

TOOL_NAME = "fw2sbom"
TOOL_VERSION = "1.4.1"

MAX_FILE_SIZE = 512 * 1024 * 1024  # refuse anything over 512 MiB
MAX_EVIDENCE_PER_COMPONENT = 8     # cap evidence entries kept per component

# --------------------------------------------------------------------------- #
# Signature database
# --------------------------------------------------------------------------- #
# Each signature:
#   name / supplier / type / purl (versionless base) / description
#   patterns: list of {regex, weight, vgroup (optional: capture group w/ version)}
# Confidence = max(weight of matched patterns) + 0.05 per extra distinct pattern,
# capped at 0.97 (never 1.0 - this is heuristic binary analysis).
SIGNATURES = [
    {
        "name": "zephyr",
        "supplier": "Zephyr Project",
        "type": "operating-system",
        "purl": "pkg:github/zephyrproject-rtos/zephyr",
        "description": "Zephyr RTOS",
        "patterns": [
            {"regex": r"Booting Zephyr OS build (?:zephyr-)?v?([0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.]+)?)", "weight": 0.95, "vgroup": 1},
            {"regex": r"Zephyr version ([0-9]+\.[0-9]+\.[0-9]+)", "weight": 0.9, "vgroup": 1},
            {"regex": r"Booting nRF Connect SDK v([0-9]+\.[0-9]+\.[0-9]+(?:-ncs[0-9]+)?)", "weight": 0.9, "vgroup": 1},
            {"regex": r"WEST_TOPDIR/zephyr/", "weight": 0.65},
            {"regex": r"zephyr-v?([0-9]+\.[0-9]+\.[0-9]+)", "weight": 0.7, "vgroup": 1},
            {"regex": r"Zephyr OS build v?([0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9]+)*)", "weight": 0.85, "vgroup": 1},
            {"regex": r"Zephyr OS", "weight": 0.6},
            {"regex": r"ZEPHYR_BASE|zephyr,\w+|zephyr/", "weight": 0.4},
            {"regex": r"west build", "weight": 0.2},
        ],
    },
    {
        "name": "freertos",
        "supplier": "Amazon Web Services",
        "type": "operating-system",
        "purl": "pkg:github/FreeRTOS/FreeRTOS-Kernel",
        "description": "FreeRTOS kernel",
        "patterns": [
            {"regex": r"FreeRTOS[ vV]+([0-9]+\.[0-9]+\.[0-9]+)", "weight": 0.9, "vgroup": 1},
            {"regex": r"FreeRTOS", "weight": 0.6},
            {"regex": r"vTaskStartScheduler|xTaskCreate|prvIdleTask", "weight": 0.5},
        ],
    },
    {
        "name": "mbedtls",
        "supplier": "Arm / Trusted Firmware",
        "type": "library",
        "purl": "pkg:github/Mbed-TLS/mbedtls",
        "description": "Mbed TLS cryptographic library",
        "patterns": [
            {"regex": r"[Mm]bed ?TLS[ /]v?([0-9]+\.[0-9]+\.[0-9]+)", "weight": 0.9, "vgroup": 1},
            {"regex": r"MBEDTLS_[A-Z0-9_]+", "weight": 0.5},
            {"regex": r"mbedtls_[a-z0-9_]+", "weight": 0.5},
        ],
    },
    {
        "name": "wolfssl",
        "supplier": "wolfSSL Inc.",
        "type": "library",
        "purl": "pkg:github/wolfSSL/wolfssl",
        "description": "wolfSSL embedded TLS library",
        "patterns": [
            {"regex": r"wolfSSL[ v]+([0-9]+\.[0-9]+\.[0-9]+)", "weight": 0.9, "vgroup": 1},
            {"regex": r"wolfSSL|wolfcrypt", "weight": 0.5},
        ],
    },
    {
        "name": "lwip",
        "supplier": "lwIP project",
        "type": "library",
        "purl": "pkg:github/lwip-tcpip/lwip",
        "description": "lwIP TCP/IP stack",
        "patterns": [
            {"regex": r"lwIP[ v/]+([0-9]+\.[0-9]+\.[0-9]+)", "weight": 0.9, "vgroup": 1},
            {"regex": r"lwIP", "weight": 0.6},
            {"regex": r"lwip_[a-z_]+|LWIP_[A-Z_]+", "weight": 0.4},
        ],
    },
    {
        "name": "newlib",
        "supplier": "Red Hat / newlib project",
        "type": "library",
        "purl": "pkg:generic/newlib",
        "description": "newlib C standard library",
        "patterns": [
            {"regex": r"newlib[- ]?v?([0-9]+\.[0-9]+\.[0-9]+)", "weight": 0.85, "vgroup": 1},
            {"regex": r"newlib[-/]([0-9]+\.[0-9]+\.[0-9]+)", "weight": 0.8, "vgroup": 1},
            {"regex": r"newlib-nano|newlib/libc/", "weight": 0.7},
            {"regex": r"newlib", "weight": 0.5},
            {"regex": r"_impure_ptr|__sinit|_reent", "weight": 0.3},
        ],
    },
    {
        "name": "picolibc",
        "supplier": "picolibc project",
        "type": "library",
        "purl": "pkg:github/picolibc/picolibc",
        "description": "picolibc C standard library",
        "patterns": [
            {"regex": r"picolibc[- ]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "weight": 0.85, "vgroup": 1},
            {"regex": r"picolibc", "weight": 0.6},
        ],
    },
    {
        "name": "gcc-arm-none-eabi",
        "supplier": "GNU Project",
        "type": "application",
        "purl": "pkg:generic/gcc",
        "description": "GCC toolchain (compiler identification strings)",
        "patterns": [
            {"regex": r"GCC:? \([^)]*\) ([0-9]+\.[0-9]+\.[0-9]+)", "weight": 0.9, "vgroup": 1},
            {"regex": r"arm-none-eabi-gcc", "weight": 0.6},
            {"regex": r"arm-zephyr-eabi", "weight": 0.5},
        ],
    },
    {
        "name": "mcuboot",
        "supplier": "MCUboot project",
        "type": "application",
        "purl": "pkg:github/mcu-tools/mcuboot",
        "description": "MCUboot secure bootloader",
        "patterns": [
            {"regex": r"MCUboot[ v]+([0-9]+\.[0-9]+\.[0-9]+)", "weight": 0.9, "vgroup": 1},
            {"regex": r"MCUBOOT|mcuboot", "weight": 0.55},
            {"regex": r"boot_go|img_mgmt", "weight": 0.3},
        ],
    },
    {
        "name": "littlefs",
        "supplier": "littlefs project",
        "type": "library",
        "purl": "pkg:github/littlefs-project/littlefs",
        "description": "littlefs embedded filesystem",
        "patterns": [
            {"regex": r"littlefs[ v/]+([0-9]+\.[0-9]+\.[0-9]+)", "weight": 0.9, "vgroup": 1},
            {"regex": r"littlefs", "weight": 0.6},
            {"regex": r"lfs_(?:mount|format|file_open)", "weight": 0.45},
        ],
    },
    {
        "name": "fatfs",
        "supplier": "ChaN",
        "type": "library",
        "purl": "pkg:generic/fatfs",
        "description": "FatFs FAT filesystem module",
        "patterns": [
            {"regex": r"FatFs.{0,20}R([0-9]+\.[0-9]+[a-z]?)", "weight": 0.85, "vgroup": 1},
            {"regex": r"FatFs", "weight": 0.6},
            {"regex": r"f_mount|f_open|ff\.c", "weight": 0.3},
        ],
    },
    {
        "name": "cmsis",
        "supplier": "Arm",
        "type": "library",
        "purl": "pkg:github/ARM-software/CMSIS_5",
        "description": "Arm CMSIS (Cortex Microcontroller Software Interface Standard)",
        "patterns": [
            {"regex": r"CMSIS[- ]?v?([0-9]+\.[0-9]+\.[0-9]+)", "weight": 0.85, "vgroup": 1},
            {"regex": r"CMSIS", "weight": 0.5},
            {"regex": r"SysTick_Handler|NVIC_[A-Za-z]+|__NVIC", "weight": 0.35},
        ],
    },
    {
        "name": "tinycrypt",
        "supplier": "Intel",
        "type": "library",
        "purl": "pkg:github/intel/tinycrypt",
        "description": "TinyCrypt cryptographic library",
        "patterns": [
            {"regex": r"tinycrypt", "weight": 0.6},
            {"regex": r"tc_(?:aes|sha256|hmac|ecc)_", "weight": 0.5},
        ],
    },
    {
        "name": "openthread",
        "supplier": "Google / Thread Group",
        "type": "library",
        "purl": "pkg:github/openthread/openthread",
        "description": "OpenThread mesh networking stack",
        "patterns": [
            {"regex": r"OPENTHREAD[/ ]+([0-9]+\.[0-9]+\.[0-9]+)", "weight": 0.9, "vgroup": 1},
            {"regex": r"openthread|OpenThread", "weight": 0.6},
        ],
    },
    {
        "name": "nimble",
        "supplier": "Apache Software Foundation",
        "type": "library",
        "purl": "pkg:github/apache/mynewt-nimble",
        "description": "Apache NimBLE Bluetooth LE stack",
        "patterns": [
            {"regex": r"NimBLE", "weight": 0.7},
            {"regex": r"ble_hs_|ble_gap_|ble_gatt", "weight": 0.45},
        ],
    },
    {
        "name": "trusted-firmware-m",
        "supplier": "Trusted Firmware",
        "type": "firmware",
        "purl": "pkg:generic/trusted-firmware-m",
        "description": "Trusted Firmware-M (TF-M)",
        "patterns": [
            {"regex": r"TF-M[ v]+([0-9]+\.[0-9]+\.[0-9]+)", "weight": 0.9, "vgroup": 1},
            {"regex": r"TF-M|tfm_|psa_call", "weight": 0.45},
        ],
    },
    {
        "name": "stm32-hal",
        "supplier": "STMicroelectronics",
        "type": "library",
        "purl": "pkg:generic/stm32-hal",
        "description": "STM32 HAL/LL drivers",
        "patterns": [
            {"regex": r"STM32[A-Z][0-9]xx? HAL", "weight": 0.8},
            {"regex": r"HAL_(?:Init|GPIO|UART|RCC)_?[A-Za-z]*", "weight": 0.5},
            {"regex": r"stm32[a-z][0-9]+xx", "weight": 0.4},
        ],
    },
    {
        "name": "nrfx",
        "supplier": "Nordic Semiconductor",
        "type": "library",
        "purl": "pkg:github/NordicSemiconductor/nrfx",
        "description": "Nordic nrfx peripheral drivers",
        "patterns": [
            {"regex": r"nrfx_[a-z0-9_]+", "weight": 0.6},
            {"regex": r"NRF_[A-Z0-9]+_NS|nRF[0-9]{4,5}", "weight": 0.45},
        ],
    },
    {
        "name": "nrf-connect-sdk",
        "supplier": "Nordic Semiconductor",
        "type": "framework",
        "purl": "pkg:github/nrfconnect/sdk-nrf",
        "description": "nRF Connect SDK (NCS) - Nordic's Zephyr-based SDK; "
                       "banner version is the Zephyr fork tag, not the NCS release",
        "patterns": [
            {"regex": r"Booting nRF Connect SDK", "weight": 0.9},
            {"regex": r"v[0-9]+\.[0-9]+\.[0-9]+-ncs[0-9]+", "weight": 0.6},
        ],
    },
    {
        "name": "nordic-softdevice-controller",
        "supplier": "Nordic Semiconductor",
        "type": "library",
        "purl": "pkg:generic/nordic-softdevice-controller",
        "description": "Nordic SoftDevice Controller (BLE link layer, closed source)",
        "patterns": [
            {"regex": r"SoftDevice Controller", "weight": 0.85},
            {"regex": r"dragoon/", "weight": 0.5},
        ],
    },
    {
        "name": "nordic-mpsl",
        "supplier": "Nordic Semiconductor",
        "type": "library",
        "purl": "pkg:generic/nordic-mpsl",
        "description": "Nordic Multiprotocol Service Layer (MPSL)",
        "patterns": [
            {"regex": r"MPSL ASSERT|MPSL Work|mpsl_[a-z_]+", "weight": 0.75},
        ],
    },
    {
        "name": "micropython",
        "supplier": "MicroPython project",
        "type": "application",
        "purl": "pkg:github/micropython/micropython",
        "description": "MicroPython interpreter",
        "patterns": [
            {"regex": r"MicroPython v([0-9]+\.[0-9]+\.[0-9]+)", "weight": 0.95, "vgroup": 1},
            {"regex": r"MicroPython", "weight": 0.6},
        ],
    },
    {
        "name": "busybox",
        "supplier": "BusyBox",
        "type": "application",
        "purl": "pkg:generic/busybox",
        "description": "BusyBox multi-call userspace utilities",
        "patterns": [
            {"regex": r"BusyBox v([0-9]+\.[0-9]+\.[0-9]+)", "weight": 0.95, "vgroup": 1},
            {"regex": r"BusyBox is a multi-call binary", "weight": 0.8},
            {"regex": r"busybox", "weight": 0.45},
        ],
    },
    {
        "name": "openssl",
        "supplier": "OpenSSL Project",
        "type": "library",
        "purl": "pkg:generic/openssl",
        "description": "OpenSSL TLS/crypto library",
        "patterns": [
            {"regex": r"OpenSSL ([0-9]+\.[0-9]+\.[0-9]+[a-z]?)", "weight": 0.95, "vgroup": 1},
            {"regex": r"SSLv3 part of OpenSSL", "weight": 0.8},
            {"regex": r"OPENSSL_", "weight": 0.5},
        ],
    },
    {
        "name": "zlib",
        "supplier": "zlib",
        "type": "library",
        "purl": "pkg:generic/zlib",
        "description": "zlib compression library",
        "patterns": [
            {"regex": r"inflate ([0-9]+\.[0-9]+\.[0-9]+) Copyright", "weight": 0.95, "vgroup": 1},
            {"regex": r"deflate ([0-9]+\.[0-9]+\.[0-9]+) Copyright", "weight": 0.95, "vgroup": 1},
            {"regex": r"invalid distance too far back", "weight": 0.7},
        ],
    },
    {
        "name": "u-boot",
        "supplier": "Das U-Boot",
        "type": "application",
        "purl": "pkg:generic/u-boot",
        "description": "Das U-Boot bootloader",
        "patterns": [
            {"regex": r"U-Boot (20[0-9]{2}\.[0-9]{2}(?:-[A-Za-z0-9.]+)?)", "weight": 0.95, "vgroup": 1},
            {"regex": r"Hit any key to stop autoboot", "weight": 0.8},
            {"regex": r"bootcmd", "weight": 0.4},
        ],
    },
    {
        "name": "linux-kernel",
        "supplier": "Linux",
        "type": "operating-system",
        "purl": "pkg:generic/linux",
        "description": "Linux kernel",
        "patterns": [
            {"regex": r"Linux version ([0-9]+\.[0-9]+(?:\.[0-9]+)?[^ ]*)", "weight": 0.95, "vgroup": 1},
            {"regex": r"Kernel command line", "weight": 0.7},
            {"regex": r"VFS: Mounted root", "weight": 0.7},
        ],
    },
    {
        "name": "dropbear",
        "supplier": "Dropbear",
        "type": "application",
        "purl": "pkg:generic/dropbear",
        "description": "Dropbear SSH server/client",
        "patterns": [
            {"regex": r"dropbear_([0-9]+\.[0-9]+)", "weight": 0.95, "vgroup": 1},
            {"regex": r"Dropbear SSH", "weight": 0.8},
        ],
    },
    {
        "name": "openssh",
        "supplier": "OpenBSD",
        "type": "application",
        "purl": "pkg:generic/openssh",
        "description": "OpenSSH",
        "patterns": [
            {"regex": r"OpenSSH_([0-9]+\.[0-9]+(?:p[0-9]+)?)", "weight": 0.95, "vgroup": 1},
        ],
    },
    {
        "name": "sqlite",
        "supplier": "SQLite",
        "type": "library",
        "purl": "pkg:generic/sqlite",
        "description": "SQLite embedded database",
        "patterns": [
            {"regex": r"SQLite version ([0-9]+\.[0-9]+\.[0-9]+)", "weight": 0.95, "vgroup": 1},
            {"regex": r"SQLite format 3", "weight": 0.75},
        ],
    },
    {
        "name": "libcurl",
        "supplier": "curl",
        "type": "library",
        "purl": "pkg:generic/curl",
        "description": "libcurl transfer library",
        "patterns": [
            {"regex": r"libcurl/([0-9]+\.[0-9]+\.[0-9]+)", "weight": 0.95, "vgroup": 1},
            {"regex": r"curl_easy_", "weight": 0.6},
        ],
    },
    {
        "name": "musl",
        "supplier": "musl",
        "type": "library",
        "purl": "pkg:generic/musl",
        "description": "musl C library",
        "patterns": [
            {"regex": r"musl libc \(([^)]+)\)", "weight": 0.85},
            {"regex": r"/lib/ld-musl-", "weight": 0.8},
        ],
    },
    {
        "name": "glibc",
        "supplier": "GNU",
        "type": "library",
        "purl": "pkg:generic/glibc",
        "description": "GNU C Library",
        "patterns": [
            {"regex": r"GNU C Library.*version ([0-9]+\.[0-9]+)", "weight": 0.95, "vgroup": 1},
            {"regex": r"GLIBC_2\.[0-9]+", "weight": 0.7},
        ],
    },
    {
        "name": "nrf5-sdk-ble-dfu",
        "supplier": "Nordic Semiconductor",
        "type": "library",
        "purl": "pkg:generic/nrf5-sdk-ble-dfu-bootloader",
        "description": "Nordic nRF5 SDK (legacy, non-Zephyr) BLE DFU bootloader/transport service",
        "patterns": [
            {"regex": r"ble_dfu_buttonless_bootloader_[a-z_]+", "weight": 0.75},
            {"regex": r"ble_dfu_[a-z_]+", "weight": 0.5},
            {"regex": r"nrf_dfu_[a-z_]+", "weight": 0.45},
        ],
    },
]

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def log(msg, verbose=True):
    if verbose:
        print(f"[fw2sbom] {msg}", file=sys.stderr)


def die(msg, code=1):
    print(f"[fw2sbom] ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def read_binary(path):
    if not os.path.exists(path):
        die(f"input file not found: {path}")
    if os.path.isdir(path):
        die(f"input is a directory, expected a firmware .bin file: {path}")
    size = os.path.getsize(path)
    if size == 0:
        die(f"input file is empty: {path}")
    if size > MAX_FILE_SIZE:
        die(f"input file too large ({size} bytes > {MAX_FILE_SIZE}); refusing to process")
    try:
        with open(path, "rb") as f:
            return f.read()
    except PermissionError:
        die(f"permission denied reading: {path}")
    except OSError as e:
        die(f"cannot read {path}: {e}")


def file_hashes(data):
    return {
        "SHA-512": hashlib.sha512(data).hexdigest(),
        "SHA-256": hashlib.sha256(data).hexdigest(),
        "SHA-1": hashlib.sha1(data).hexdigest(),
        "MD5": hashlib.md5(data).hexdigest(),
    }


def run_file_command(path, verbose=False):
    """Run `file` on the input if available (present on Kali by default)."""
    exe = shutil.which("file")
    if not exe:
        log("`file` command not found; skipping libmagic fingerprint", verbose)
        return None
    try:
        out = subprocess.run(
            [exe, "-b", path], capture_output=True, text=True, timeout=30, check=False
        )
        if out.returncode == 0:
            return out.stdout.strip()
        log(f"`file` returned {out.returncode}: {out.stderr.strip()}", verbose)
    except (subprocess.TimeoutExpired, OSError) as e:
        log(f"`file` invocation failed: {e}", verbose)
    return None


def extract_strings(data, min_len=6):
    """Extract printable ASCII strings with their byte offsets."""
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    return [(m.start(), m.group().decode("ascii")) for m in pattern.finditer(data)]


def analyze_cortex_m(data):
    """Heuristic Cortex-M vector table check on a raw .bin image."""
    result = {"looks_like_cortex_m": False, "details": []}
    if len(data) < 64:
        result["details"].append("file too small for a vector table")
        return result
    initial_sp, reset = struct.unpack_from("<II", data, 0)
    sp_ok = (
        initial_sp % 4 == 0
        and (0x20000000 <= initial_sp <= 0x20400000   # typical SRAM
             or 0x10000000 <= initial_sp <= 0x10080000  # CCM/SRAM alt
             or 0x24000000 <= initial_sp <= 0x24100000)  # AXI SRAM (H7)
    )
    reset_ok = (reset & 1) == 1 and 0x0 < (reset & ~1) < 0x20000000
    if sp_ok:
        result["details"].append(f"initial SP 0x{initial_sp:08x} points into typical SRAM")
    if reset_ok:
        result["details"].append(f"reset vector 0x{reset:08x} has Thumb bit set")
    plausible = 0
    for i in range(2, 16):
        (vec,) = struct.unpack_from("<I", data, i * 4)
        if vec == 0 or ((vec & 1) == 1 and (vec & ~1) < 0x20000000):
            plausible += 1
    result["details"].append(f"{plausible}/14 plausible exception vectors in slots 2-15")
    result["looks_like_cortex_m"] = sp_ok and reset_ok and plausible >= 10
    return result


def analyze_mcs51(data):
    """Heuristic MCS-51 (8051) detection on a raw code image.

    Two independent signals, both required:
      1. the 8051 interrupt vector table - an LJMP (0x02) at reset (0x0000) and
         at 0x0003 + 8*k, where each ISR slot is 8 bytes apart;
      2. an opcode profile dominated by the handful of instructions that make up
         most of any compiled 8051 image (LCALL/LJMP/MOV DPTR/MOVX/RET).
    """
    result = {"looks_like_mcs51": False, "details": [], "vectors": []}
    if len(data) < 0x40:
        result["details"].append("file too small for an 8051 vector table")
        return result

    vector_names = ["RESET", "INT0", "TIMER0", "INT1", "TIMER1",
                    "SERIAL", "TIMER2", "INT4", "INT5", "INT6"]
    slots = [0x0000] + [3 + 8 * k for k in range(len(vector_names) - 1)]
    for name, off in zip(vector_names, slots):
        if off + 3 <= len(data) and data[off] == 0x02:  # LJMP addr16
            target = (data[off + 1] << 8) | data[off + 2]
            result["vectors"].append({"name": name, "offset": off, "target": target})
    if result["vectors"]:
        listed = ", ".join(f"{v['name']}@0x{v['offset']:04x}->0x{v['target']:04x}"
                           for v in result["vectors"][:6])
        result["details"].append(
            f"{len(result['vectors'])} LJMP interrupt vectors: {listed}")

    counts = collections.Counter(data)
    ratio = sum(counts[op] for op in MCS51_CORE_OPCODES) / len(data)
    result["opcode_ratio"] = round(ratio, 4)
    result["details"].append(
        f"core 8051 opcodes (LCALL/LJMP/MOV DPTR/MOVX/RET) are {ratio:.1%} of all "
        f"bytes (uniform random would be {len(MCS51_CORE_OPCODES) / 256:.1%})")

    result["looks_like_mcs51"] = (len(result["vectors"]) >= MCS51_MIN_VECTORS
                                  and ratio >= MCS51_MIN_OPCODE_RATIO)
    return result


def analyze_architecture(data):
    """Identify the instruction set of a raw firmware image, if we can.

    Cortex-M is tested first: its vector table is a much stronger constraint, and
    a Thumb image would otherwise be at some risk of matching the 8051 profile.
    """
    cortex = analyze_cortex_m(data)
    mcs51 = {"looks_like_mcs51": False, "details": [], "vectors": []}
    if not cortex["looks_like_cortex_m"]:
        mcs51 = analyze_mcs51(data)

    if cortex["looks_like_cortex_m"]:
        architecture, label = "arm-cortex-m", "ARM Cortex-M (Thumb)"
    elif mcs51["looks_like_mcs51"]:
        architecture, label = "mcs-51", "MCS-51 / 8051"
    else:
        architecture, label = None, None

    return {
        "architecture": architecture,
        "label": label,
        # kept flat for backwards compatibility with existing callers
        "looks_like_cortex_m": cortex["looks_like_cortex_m"],
        # tag each line with the detector that produced it: the two ISAs are
        # tested independently and their evidence must not read as one finding
        "details": [f"cortex-m: {d}" for d in cortex["details"]]
                   + [f"mcs-51: {d}" for d in mcs51["details"]],
        "cortex_m": cortex,
        "mcs51": mcs51,
    }


# --------------------------------------------------------------------------- #
# Embedded standard data structures
# --------------------------------------------------------------------------- #
# Not every identifiable thing in a firmware image is a linked software library.
# Display controllers in particular embed standardised *data*: VESA E-EDID blocks
# and DDC/CI capability strings. These are found by parsing and validating the
# structures themselves rather than by matching strings, so they are reported
# separately from the signature hits, with an explicit evidence class.

EDID_MAGIC = b"\x00\xff\xff\xff\xff\xff\xff\x00"
EDID_BLOCK_SIZE = 128


def _edid_descriptor_name(block):
    """The 0xFC 'monitor name' descriptor of an EDID block, if present."""
    for i in range(54, 126, 18):
        if block[i:i + 3] == b"\x00\x00\x00" and block[i + 3] == 0xFC:
            raw = block[i + 5:i + 18].split(b"\n")[0]
            try:
                return raw.decode("ascii").strip()
            except UnicodeDecodeError:
                return None
    return None


def detect_edid_blocks(data):
    """Locate and validate VESA E-EDID blocks (128 bytes, magic + checksum)."""
    blocks = []
    for m in re.finditer(re.escape(EDID_MAGIC), data):
        offset = m.start()
        block = data[offset:offset + EDID_BLOCK_SIZE]
        if len(block) < EDID_BLOCK_SIZE or (sum(block) & 0xFF) != 0:
            continue  # a bad checksum means this is not really an EDID block
        packed = (block[8] << 8) | block[9]
        pnp = "".join(chr(((packed >> shift) & 0x1F) + 64) for shift in (10, 5, 0))
        if not pnp.isalpha() or not pnp.isupper():
            continue
        blocks.append({
            "offset": offset,
            "pnp_id": pnp,
            "product_code": (block[11] << 8) | block[10],
            "serial": int.from_bytes(block[12:16], "little"),
            "week": block[16],
            "version": f"{block[18]}.{block[19]}",
            "manufacture_year": 1990 + block[17] if block[17] else None,
            "extensions": block[126],
            "name": _edid_descriptor_name(block),
            "sha256": hashlib.sha256(block).hexdigest(),
        })
    return blocks


MCCS_VERSION_RX = re.compile(rb"mccs_ver\((\d+\.\d+)\)")
MCCS_CAPABILITY_RX = re.compile(rb"prot\((?:monitor|display)\)type\(([A-Za-z]+)\)")


def detect_mccs(data):
    """Locate VESA MCCS / DDC-CI capability strings and their declared version."""
    found = []
    for m in MCCS_CAPABILITY_RX.finditer(data):
        window = data[m.start():m.start() + 1024]
        version_match = MCCS_VERSION_RX.search(window)
        text = window.split(b"\x00")[0][:220]
        found.append({
            "offset": m.start(),
            "display_type": m.group(1).decode("ascii", "replace"),
            "version": version_match.group(1).decode() if version_match else None,
            "text": text.decode("ascii", "replace"),
        })
    return found


def detect_embedded_standards(data, verbose=False):
    """Structural detection of embedded standard data. Returns component dicts."""
    components = []

    edids = detect_edid_blocks(data)
    if edids:
        versions = sorted({b["version"] for b in edids})
        vendors = sorted({b["pnp_id"] for b in edids})
        names = [b["name"] for b in edids if b["name"]]
        evidence = [
            f"{len(edids)} EDID block(s) with valid 128-byte checksums, "
            f"first at offset 0x{edids[0]['offset']:x}",
            f"EDID structure version(s): {', '.join(versions)}",
            f"PnP manufacturer ID(s): {', '.join(vendors)}",
        ]
        if names:
            evidence.append("monitor name descriptor(s): "
                            + ", ".join(sorted(set(names))[:8]))
        components.append({
            "name": "vesa-e-edid",
            "supplier": "VESA",
            "type": "data",
            "purl": "pkg:generic/vesa-e-edid",
            "description": "VESA Enhanced Extended Display Identification Data "
                           "(E-EDID) blocks embedded in the image",
            "version": max(versions),
            "confidence": 0.95,
            "evidence": evidence,
            "occurrences": [b["offset"] for b in edids],
            "properties": [
                ("fw2sbom:edid_block_count", str(len(edids))),
                ("fw2sbom:edid_versions", ", ".join(versions)),
                ("fw2sbom:edid_pnp_ids", ", ".join(vendors)),
            ],
        })
        if verbose:
            log(f"embedded standard: VESA E-EDID x{len(edids)} "
                f"(v{max(versions)}, vendors {', '.join(vendors)})")

    mccs = detect_mccs(data)
    if mccs:
        version = next((c["version"] for c in mccs if c["version"]), None)
        evidence = [
            f"{len(mccs)} DDC/CI capability string(s), first at "
            f"offset 0x{mccs[0]['offset']:x}",
            f"capability string: {mccs[0]['text'][:160]}",
        ]
        if version:
            evidence.append(f"declared MCCS version from mccs_ver({version})")
        components.append({
            "name": "vesa-mccs",
            "supplier": "VESA",
            "type": "data",
            "purl": "pkg:generic/vesa-mccs",
            "description": "VESA Monitor Control Command Set (MCCS) capability "
                           "string served over DDC/CI",
            "version": version,
            "confidence": 0.95 if version else 0.8,
            "evidence": evidence,
            "occurrences": [c["offset"] for c in mccs],
            "properties": [
                ("fw2sbom:mccs_capability_strings", str(len(mccs))),
                ("fw2sbom:mccs_display_type", mccs[0]["display_type"]),
            ],
        })
        if verbose:
            log(f"embedded standard: VESA MCCS {version or '(version undeclared)'} "
                f"capability string x{len(mccs)}")

    return components


# --------------------------------------------------------------------------- #
# Packetized container detection / de-framing
# --------------------------------------------------------------------------- #
# Some vendors ship "firmware files" that are really a dump of the flash
# programming protocol rather than a flat image: a short file header, then
# fixed-size records of
#     [framing: checksum / length / page / sequence][payload chunk]
# Running a string scanner over such a file is meaningless - the payload bytes
# are chopped up by framing bytes every few dozen bytes.  The detector below is
# generic (no vendor magic): it looks for a record stride that has BOTH a column
# which is constant across every record AND a column that counts up by one per
# record.  Random data and ordinary flat firmware images do not produce that
# combination.

CONTAINER_MIN_STRIDE = 8
CONTAINER_MAX_STRIDE = 256
CONTAINER_MIN_RECORDS = 32        # fewer records than this and "framing" is noise
CONTAINER_PROBE_RECORDS = 256     # records sampled while searching for a stride
CONTAINER_MAX_FRAMING = 8         # widest per-record framing we are willing to strip
CONTAINER_MIN_PAYLOAD = 8         # narrower payload chunks are not worth de-framing
CONTAINER_MIN_COVERAGE = 0.5      # framing must span most of the file
CONTAINER_CONST_RATIO = 0.99      # tolerances for the full-file verification pass
CONTAINER_COUNTER_RATIO = 0.80

# MCS-51 (8051) detection. The listed opcodes - LJMP, LCALL, MOV DPTR,#d16,
# MOVX A,@DPTR, MOVX @DPTR,A, RET - dominate any compiled 8051 image; in a
# uniform random stream the six of them would account for 2.3% of all bytes.
MCS51_CORE_OPCODES = (0x02, 0x12, 0x90, 0xE0, 0xF0, 0x22)
MCS51_MIN_OPCODE_RATIO = 0.08
MCS51_MIN_VECTORS = 3

# Entropy thresholds for the opacity verdict (bits per byte).
OPACITY_HIGH = 7.5                # above this: no usable plaintext expected
OPACITY_STRONG = 7.9              # above this: indistinguishable from ciphertext
OPACITY_MAX_RUN = 8               # a plaintext image always has long 0x00/0xFF runs

COMPRESSION_MAGICS = [
    (b"\x1f\x8b\x08", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"\x5d\x00\x00", "lzma"),
    (b"\x04\x22\x4d\x18", "lz4"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"PK\x03\x04", "zip"),
    (b"hsqs", "squashfs"),
    (b"\x27\x05\x19\x56", "u-boot uImage"),
]


def shannon_entropy(data):
    """Shannon entropy in bits per byte (8.0 == indistinguishable from random)."""
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in collections.Counter(data).values())


def chi_square_uniform(data):
    """Chi-square statistic against a uniform byte distribution (df=255).

    A true random stream scores ~255 +/- 23; a biased one scores much higher, so
    this separates "looks like AES output" from "looks like a homebrew cipher".
    """
    if not data:
        return 0.0
    counts = collections.Counter(data)
    expected = len(data) / 256
    return sum((counts.get(b, 0) - expected) ** 2 / expected for b in range(256))


def longest_identical_run(data):
    """Length of the longest run of one repeated byte value."""
    if not data:
        return 0
    return max(len(m.group()) for m in re.finditer(rb"(.)\1*", data, re.DOTALL))


def _crc8(data, poly, init=0):
    crc = init
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


def _xor8(data):
    acc = 0
    for b in data:
        acc ^= b
    return acc


# Candidate per-record checksum algorithms, used to positively identify a
# checksum column - which proves that column is framing, not payload.
CHECKSUM_ALGORITHMS = [
    ("sum8", lambda p: sum(p) & 0xFF),
    ("neg-sum8", lambda p: (-sum(p)) & 0xFF),
    ("xor8", _xor8),
    ("crc8-0x07", lambda p: _crc8(p, 0x07)),
    ("crc8-0x31", lambda p: _crc8(p, 0x31)),
    ("crc8-0x1d", lambda p: _crc8(p, 0x1D)),
]


def _column(data, start, stride, count):
    """The `count` bytes at `start`, `start+stride`, `start+2*stride`, ..."""
    return data[start:start + count * stride:stride]


def _classify_columns(data, base, stride, nrec):
    """Classify each column of a candidate record grid.

    Returns (const, counter, slow): `const` maps column -> constant value,
    `counter` lists columns incrementing by 1 per record (a sequence number),
    `slow` lists columns that mostly repeat but only step upwards (a page/block
    index).  Payload columns fall into none of the three.
    """
    const, counter, slow = {}, [], []
    for j in range(stride):
        col = _column(data, base + j, stride, nrec)
        if len(set(col)) == 1:
            const[j] = col[0]
            continue
        steps = [(col[i + 1] - col[i]) & 0xFF for i in range(len(col) - 1)]
        if not steps:
            continue
        ones, zeros = steps.count(1), steps.count(0)
        if ones >= CONTAINER_COUNTER_RATIO * len(steps):
            counter.append(j)
        elif ones >= 2 and (ones + zeros) >= 0.95 * len(steps):
            slow.append(j)
    return const, counter, slow


def _cyclic_window(columns, stride):
    """Smallest cyclic window [start, start+width) covering all `columns`."""
    cols = sorted(columns)
    if len(cols) == 1:
        return cols[0], 1
    gaps = [(cols[(i + 1) % len(cols)] - cols[i]) % stride for i in range(len(cols))]
    k = gaps.index(max(gaps))
    start = cols[(k + 1) % len(cols)]
    return start, ((cols[k] - start) % stride) + 1


def _checksum_algorithm(data, rec_start, stride, nrec, col, pay_off, pay_width):
    """Name of the checksum algorithm that column `col` satisfies, or None.

    `col` and `pay_off` are offsets relative to the start of a record.
    """
    last = rec_start + (nrec - 1) * stride + max(col, pay_off + pay_width)
    if last >= len(data):
        nrec = max(1, nrec - 1)
    for name, fn in CHECKSUM_ALGORITHMS:
        ok = 0
        for k in range(nrec):
            rec = rec_start + k * stride
            if fn(data[rec + pay_off:rec + pay_off + pay_width]) == data[rec + col]:
                ok += 1
        if ok >= 0.9 * nrec:
            return name
    return None


def _resolve_framing(data, stride, nrec, meta_start, meta_width, target_width):
    """Widen the framing window from `meta_width` to `target_width`.

    Constant and counter columns are provably framing, but a checksum column is
    statistically indistinguishable from payload, so the provable window can be
    too narrow.  `meta_start` is an absolute file offset; the return value is the
    absolute offset of the resolved record start.  Candidates are ranked by:
      1. a verified checksum relation over the resulting payload (decisive),
      2. byte distribution - payload columns share one distribution, a framing
         column usually does not (only discriminates for plaintext payloads),
      3. otherwise assume framing precedes payload, the usual ISP convention,
         and flag the result as ambiguous.
    """
    extra = target_width - meta_width
    if extra <= 0:
        return meta_start, "exact (framing fully identified)"

    payload_width = stride - target_width
    sample = min(nrec, 128)
    # Prefer more framing on the left; candidates[0] is also the tie-break winner.
    candidates = []
    for left in range(extra, -1, -1):
        start = meta_start - left
        added = [start + i for i in range(left)] + \
                [meta_start + meta_width + i for i in range(extra - left)]
        if start >= 0:
            candidates.append((start, added))
    if not candidates:
        return meta_start, "assumed framing-before-payload (ambiguous)"

    for start, added in candidates:
        for col in added:
            alg = _checksum_algorithm(data, start, stride, sample,
                                      col - start, target_width, payload_width)
            if alg:
                return start, f"checksum column verified ({alg})"

    # Columns that are payload under every candidate framing - the reference
    # distribution that a framing column should deviate from.  Every chi-square
    # below is computed over the same number of samples: the statistic scales
    # with the sample count, so a pooled reference would not be comparable to a
    # single column.
    certain = list(range(meta_start + meta_width + extra,
                         meta_start + stride - extra))[:8]
    if len(certain) >= 3:
        reference = sorted(chi_square_uniform(_column(data, c, stride, nrec))
                           for c in certain)
        median = reference[len(reference) // 2]
        spread = sorted(abs(c - median) for c in reference)[len(reference) // 2]
        # The test only discriminates when the payload itself is non-uniform. In
        # an encrypted payload every column is uniform, so the comparison is pure
        # noise and would pick a framing boundary at random.
        if median > 1000:
            scored = sorted(
                (min(abs(chi_square_uniform(_column(data, col, stride, nrec)) - median)
                     for col in added), start)
                for start, added in candidates if added
            )
            if scored and scored[-1][0] > 3 * max(spread, 1.0) and                     (len(scored) == 1 or scored[-1][0] > 3 * max(scored[-2][0], 1.0)):
                return scored[-1][1], "byte-distribution outlier"

    return candidates[0][0], "assumed framing-before-payload (ambiguous)"


def _verify_framing(data, rec_start, stride, const_col, const_val, counter_col):
    """Full-file verification pass. Returns (first_record_offset, record_count)."""
    first = rec_start
    while first - stride >= 0 and data[first - stride + const_col] == const_val:
        first -= stride
    records = (len(data) - first) // stride
    if records < CONTAINER_MIN_RECORDS:
        return None
    col = _column(data, first + const_col, stride, records)
    if col.count(const_val) < CONTAINER_CONST_RATIO * records:
        return None
    if counter_col is not None:
        seq = _column(data, first + counter_col, stride, records)
        steps = [(seq[i + 1] - seq[i]) & 0xFF for i in range(len(seq) - 1)]
        if steps and steps.count(1) < CONTAINER_COUNTER_RATIO * len(steps):
            return None
    return first, records


def detect_packet_container(data, verbose=False):
    """Detect fixed-stride record framing. Returns a layout dict, or None."""
    if len(data) < CONTAINER_MIN_STRIDE * CONTAINER_MIN_RECORDS:
        return None

    best = None
    for probe in sorted({min(4096, len(data) // 8), len(data) // 2}):
        for stride in range(CONTAINER_MIN_STRIDE, CONTAINER_MAX_STRIDE + 1):
            available = (len(data) - probe) // stride
            if available < CONTAINER_MIN_RECORDS:
                continue
            nrec = min(available, CONTAINER_PROBE_RECORDS)
            const, counter, slow = _classify_columns(data, probe, stride, nrec)
            if not const or not counter:
                continue
            width = len(const) + len(counter) + len(slow)
            if width > CONTAINER_MAX_FRAMING or stride - width < CONTAINER_MIN_PAYLOAD:
                continue
            # Density, so that a multiple of the true stride cannot outscore it;
            # ties then go to the smallest stride.
            density = (2 * len(counter) + len(const) + len(slow)) / stride
            key = (round(density, 6), -stride)
            if best is None or key > best[0]:
                best = (key, stride, probe, const, counter, slow)
    if best is None:
        return None
    _key, stride, probe, const, counter, slow = best

    nrec = min((len(data) - probe) // stride, CONTAINER_PROBE_RECORDS)
    meta_col, meta_width = _cyclic_window(set(const) | set(counter) | set(slow), stride)

    # A constant column whose value equals a plausible payload width is almost
    # certainly a length byte - the strongest framing confirmation available.
    target_width, length_byte = meta_width, None
    for col in sorted(const):
        val = const[col]
        if CONTAINER_MIN_PAYLOAD <= val < stride and \
                CONTAINER_MAX_FRAMING >= stride - val >= meta_width:
            target_width, length_byte = stride - val, (col, val)
            break
    else:
        limit = min(CONTAINER_MAX_FRAMING, stride - CONTAINER_MIN_PAYLOAD)
        for width in range(meta_width, limit + 1):
            payload = stride - width
            if payload & (payload - 1) == 0:  # power of two: the usual chunk size
                target_width = width
                break

    rec_start, resolution = _resolve_framing(
        data, stride, nrec, probe + meta_col, meta_width, target_width)
    payload_width = stride - target_width
    if payload_width < CONTAINER_MIN_PAYLOAD:
        return None

    def relative(column):
        return (probe + column - rec_start) % stride

    const_col = min(const)
    verified = _verify_framing(data, rec_start, stride,
                               relative(const_col), const[const_col],
                               relative(counter[0]) if counter else None)
    if not verified:
        return None
    first, records = verified
    coverage = (records * stride) / len(data)
    if coverage < CONTAINER_MIN_COVERAGE:
        return None

    roles = {}
    for j in range(stride):
        r = relative(j)
        if r >= target_width:
            continue
        if j in const:
            roles[r] = f"const 0x{const[j]:02x}"
        elif j in counter:
            roles[r] = "seq +1/record"
        elif j in slow:
            roles[r] = "page index"
        else:
            roles[r] = "checksum/address?"
    layout = "".join(f"[{roles.get(i, '?')}]" for i in range(target_width))
    layout += f"[payload x{payload_width}]"

    container = {
        "stride": stride,
        "header_bytes": first,
        "records": records,
        "framing_width": target_width,
        "payload_offset": target_width,
        "payload_width": payload_width,
        "payload_bytes": records * payload_width,
        "trailing_bytes": len(data) - (first + records * stride),
        "coverage": round(coverage, 4),
        "length_byte": (f"column {relative(length_byte[0])} = 0x{length_byte[1]:02x}"
                        f" == payload width" if length_byte else None),
        "framing_resolution": resolution,
        "layout": layout,
    }
    if verbose:
        log(f"container: {stride}-byte records, {first}-byte file header, "
            f"{records} records, {target_width}B framing + {payload_width}B payload")
        log(f"container layout: {layout}")
        if container["length_byte"]:
            log(f"container length byte: {container['length_byte']}")
        log(f"container framing resolved by: {resolution}")
    return container


def deframe(data, container):
    """Concatenate the payload chunk of every record, dropping the framing."""
    stride = container["stride"]
    offset, width = container["payload_offset"], container["payload_width"]
    start = container["header_bytes"]
    out = bytearray()
    for k in range(container["records"]):
        record = start + k * stride
        out += data[record + offset:record + offset + width]
    return bytes(out)


def analyze_opacity(payload, architecture=None):
    """Decide whether a payload is analyzable plaintext or opaque bytes.

    `architecture` is the instruction set identified by analyze_architecture(); a
    positive identification settles the question, because dense 8-bit MCU code
    legitimately reaches ~7.0 bits/byte and would otherwise be misreported as
    packed or partially compressed.
    """
    entropy = shannon_entropy(payload)
    run = longest_identical_run(payload)
    chi2 = chi_square_uniform(payload)
    printable = sum(1 for b in payload if 0x20 <= b < 0x7F) / max(1, len(payload))

    duplicates = 0
    if len(payload) >= 32:
        blocks = collections.Counter(payload[i:i + 16]
                                     for i in range(0, len(payload) - 15, 16))
        duplicates = sum(c - 1 for c in blocks.values() if c > 1)

    compression = next((name for magic, name in COMPRESSION_MAGICS
                        if payload[:16].startswith(magic)), None)

    reasons = [f"Shannon entropy {entropy:.3f} bits/byte",
               f"longest identical-byte run {run}",
               f"chi-square vs uniform {chi2:.0f} (true random ~255)",
               f"printable-ASCII ratio {printable:.3f}"]

    if architecture:
        verdict, opaque = "plaintext", False
        reasons.append(f"{architecture} machine code identified: the image is "
                       "plaintext regardless of its entropy (dense 8-bit MCU code "
                       "routinely reaches ~7.0 bits/byte)")
    elif entropy < 6.5:
        verdict, opaque = "plaintext", False
        reasons.append("entropy consistent with ordinary code and data")
    elif entropy < OPACITY_HIGH:
        verdict, opaque = "mixed", False
        reasons.append("elevated entropy: packed or partially compressed regions")
    elif compression:
        verdict, opaque = f"compressed ({compression})", True
        reasons.append(f"{compression} container magic at payload start")
    else:
        verdict, opaque = "opaque", True
        if entropy >= OPACITY_STRONG:
            reasons.append("entropy is indistinguishable from ciphertext")
        if run <= OPACITY_MAX_RUN:
            reasons.append(f"no blank-flash runs (longest run {run}); an unencrypted "
                           "image always contains long 0x00/0xff stretches")
        if chi2 > 1000:
            reasons.append("byte distribution measurably biased: more consistent with "
                           "a vendor block/stream cipher than with AES-CBC/GCM")
        if duplicates:
            reasons.append(f"{duplicates} repeated 16-byte aligned block(s): possible "
                           "ECB-mode or repeating-keystream encryption")
        reasons.append("no compression container magic at payload start")

    return {
        "verdict": verdict,
        "opaque": opaque,
        "entropy": round(entropy, 4),
        "longest_run": run,
        "chi_square": round(chi2, 1),
        "printable_ratio": round(printable, 4),
        "duplicate_16b_blocks": duplicates,
        "compression": compression,
        "reasons": reasons,
    }


# --------------------------------------------------------------------------- #
# Signature matching
# --------------------------------------------------------------------------- #

def match_signatures(strings, verbose=False):
    """Match the signature DB against extracted strings. Returns list of hits."""
    hits = []
    for sig in SIGNATURES:
        matched_patterns = []  # (pattern_dict, offset, matched_text, version_or_None)
        for pat in sig["patterns"]:
            rx = re.compile(pat["regex"])
            best = None  # (offset, matched_text, version) - prefer hits w/ version
            for offset, s in strings:
                m = rx.search(s)
                if not m:
                    continue
                version = m.group(pat["vgroup"]) if pat.get("vgroup") else None
                if best is None or version:
                    best = (offset, m.group(0), version)
                if version:
                    break
            if best:
                matched_patterns.append((pat, best[0], best[1], best[2]))
        if not matched_patterns:
            continue
        weights = [p[0]["weight"] for p in matched_patterns]
        confidence = min(0.97, max(weights) + 0.05 * (len(matched_patterns) - 1))
        version = next((v for (_, _, _, v) in matched_patterns if v), None)
        hits.append({
            "sig": sig,
            "confidence": round(confidence, 2),
            "version": version,
            "evidence": matched_patterns[:MAX_EVIDENCE_PER_COMPONENT],
        })
        log(f"match: {sig['name']} confidence={confidence:.2f} version={version}", verbose)
    return sorted(hits, key=lambda h: -h["confidence"])


# Zephyr fork tag (printed by the NCS boot banner) -> nRF Connect SDK release family
ZEPHYR_FORK_TO_NCS = {
    "3.2.99-ncs1": "2.2.x/2.3.x",
    "3.3.99-ncs1": "2.4.x",
    "3.4.99-ncs1": "2.5.x",
    "3.5.99-ncs1": "2.6.x",
    "3.6.99-ncs1": "2.7.x",
    "3.6.99-ncs2": "2.7.x",
    "3.7.99-ncs1": "2.8.x",
    "3.7.99-ncs2": "2.9.x",
}

VERSION_TOKEN_RX = re.compile(r"\bv?([0-9]+\.[0-9]+(?:\.[0-9]+)+(?:-[A-Za-z0-9]+)?)\b")


def infer_versions(hits, verbose=False):
    """Second pass: fill in versions that are not captured by a vgroup pattern.

    1. nRF Connect SDK release family inferred from the Zephyr fork tag.
    2. Fallback: a version-like token inside the very string that matched the
       component (e.g. 'littlefs v2.8' when no dedicated pattern captured it).
    Inferred versions are flagged and emitted with reduced confidence.
    """
    by_name = {h["sig"]["name"]: h for h in hits}
    z, n = by_name.get("zephyr"), by_name.get("nrf-connect-sdk")
    if z and n and not n["version"] and z["version"] in ZEPHYR_FORK_TO_NCS:
        n["version"] = ZEPHYR_FORK_TO_NCS[z["version"]]
        n["version_inferred"] = (
            f"inferred from Zephyr fork tag v{z['version']} "
            f"(NCS release mapping table); confirm exact release with the vendor")
        log(f"inferred: nrf-connect-sdk {n['version']} (from zephyr fork tag)", verbose)
    for h in hits:
        if h["version"]:
            continue
        for _pat, _off, text, _v in h["evidence"]:
            m = VERSION_TOKEN_RX.search(text)
            if m:
                h["version"] = m.group(1)
                h["version_inferred"] = (
                    f"version-like token found in matched string '{text}' "
                    f"(not a dedicated version pattern)")
                log(f"inferred: {h['sig']['name']} {h['version']} (same-string token)",
                    verbose)
                break


def confidence_level(c):
    return "high" if c >= 0.8 else "medium" if c >= 0.5 else "low"


# --------------------------------------------------------------------------- #
# CycloneDX 1.6 output
# --------------------------------------------------------------------------- #

def build_sbom(input_path, data, file_magic, arm_info, hits, min_str_len, n_strings,
               container=None, opacity=None, payload=None, standards=None,
               firmware_version=None):
    fname = os.path.basename(input_path)
    hashes = file_hashes(data)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    offset_space = "payload (container framing stripped)" if container else "file"

    fw_props = [
        {"name": "fw2sbom:file_size_bytes", "value": str(len(data))},
        {"name": "fw2sbom:architecture",
         "value": arm_info.get("label") or "unidentified"},
        {"name": "fw2sbom:cortex_m_vector_table",
         "value": "detected" if arm_info["looks_like_cortex_m"] else "not-detected"},
    ]
    if arm_info.get("mcs51"):
        fw_props.append({
            "name": "fw2sbom:mcs51_vector_table",
            "value": "detected" if arm_info["mcs51"]["looks_like_mcs51"]
                     else "not-detected"})
    for d in arm_info["details"]:
        fw_props.append({"name": "fw2sbom:vector_table_detail", "value": d})
    if file_magic:
        fw_props.append({"name": "fw2sbom:file_magic", "value": file_magic})
    if container:
        fw_props += [
            {"name": "fw2sbom:container", "value": "packetized-record-framing"},
            {"name": "fw2sbom:container_record_stride",
             "value": str(container["stride"])},
            {"name": "fw2sbom:container_file_header_bytes",
             "value": str(container["header_bytes"])},
            {"name": "fw2sbom:container_records", "value": str(container["records"])},
            {"name": "fw2sbom:container_layout", "value": container["layout"]},
            {"name": "fw2sbom:container_payload_bytes",
             "value": str(container["payload_bytes"])},
            {"name": "fw2sbom:container_trailing_bytes",
             "value": str(container["trailing_bytes"])},
            {"name": "fw2sbom:container_coverage", "value": str(container["coverage"])},
            {"name": "fw2sbom:container_framing_resolution",
             "value": container["framing_resolution"]},
        ]
        if container["length_byte"]:
            fw_props.append({"name": "fw2sbom:container_length_byte",
                             "value": container["length_byte"]})
    if opacity:
        fw_props += [
            {"name": "fw2sbom:payload_verdict", "value": opacity["verdict"]},
            {"name": "fw2sbom:payload_entropy_bits_per_byte",
             "value": str(opacity["entropy"])},
            {"name": "fw2sbom:payload_longest_identical_run",
             "value": str(opacity["longest_run"])},
            {"name": "fw2sbom:payload_chi_square", "value": str(opacity["chi_square"])},
            {"name": "fw2sbom:payload_printable_ratio",
             "value": str(opacity["printable_ratio"])},
            {"name": "fw2sbom:payload_duplicate_16b_blocks",
             "value": str(opacity["duplicate_16b_blocks"])},
        ]

    components = []
    dep_refs = []
    for i, hit in enumerate(hits, 1):
        sig, conf = hit["sig"], hit["confidence"]
        ref = f"component-{i}-{sig['name']}"
        exact_version = hit["version"] and not hit.get("version_inferred")
        purl = sig["purl"] + (f"@{hit['version']}" if exact_version else "")
        methods = []
        for pat, offset, text, _v in hit["evidence"]:
            methods.append({
                "technique": "binary-analysis",
                "confidence": pat["weight"],
                "value": f"regex '{pat['regex']}' matched '{text}' "
                         f"at offset 0x{offset:x} of the {offset_space}",
            })
        comp = {
            "type": sig["type"],
            "bom-ref": ref,
            "name": sig["name"],
            "description": sig["description"],
            "purl": purl,
            "evidence": {
                "identity": [{
                    "field": "name",
                    "confidence": conf,
                    "methods": methods,
                }],
                "occurrences": [{
                    "location": fname,
                    "additionalContext":
                        f"first match at offset 0x{hit['evidence'][0][1]:x} "
                        f"of the {offset_space}",
                }],
            },
            "properties": [
                {"name": "fw2sbom:confidence", "value": str(conf)},
                {"name": "fw2sbom:confidence_level", "value": confidence_level(conf)},
                {"name": "fw2sbom:matched_patterns", "value": str(len(hit["evidence"]))},
            ],
        }
        if sig.get("supplier"):
            comp["supplier"] = {"name": sig["supplier"]}
        if hit["version"]:
            comp["version"] = hit["version"]
            inferred = hit.get("version_inferred")
            vconf = 0.4 if inferred else conf
            vmethods = ([{"technique": "other", "confidence": vconf,
                          "value": inferred}] if inferred else methods[:1])
            comp["evidence"]["identity"].append({
                "field": "version",
                "confidence": vconf,
                "methods": vmethods,
            })
            comp["properties"].append(
                {"name": "fw2sbom:version_source",
                 "value": "inferred" if inferred else "exact-version-string"})
        else:
            comp["properties"].append(
                {"name": "fw2sbom:version", "value": "unknown (no version string found)"})
        components.append(comp)
        dep_refs.append(ref)

    for i, std in enumerate(standards or [], 1):
        ref = f"standard-{i}-{std['name']}"
        purl = std["purl"] + (f"@{std['version']}" if std["version"] else "")
        methods = [{"technique": "binary-analysis",
                    "confidence": std["confidence"],
                    "value": e} for e in std["evidence"][:MAX_EVIDENCE_PER_COMPONENT]]
        comp = {
            "type": std["type"],
            "bom-ref": ref,
            "name": std["name"],
            "supplier": {"name": std["supplier"]},
            "description": std["description"],
            "purl": purl,
            "evidence": {
                "identity": [{
                    "field": "name",
                    "confidence": std["confidence"],
                    "methods": methods,
                }],
                "occurrences": [
                    {"location": fname,
                     "additionalContext": f"offset 0x{o:x} of the {offset_space}"}
                    for o in std["occurrences"][:MAX_EVIDENCE_PER_COMPONENT]
                ],
            },
            "properties": [
                {"name": "fw2sbom:confidence", "value": str(std["confidence"])},
                {"name": "fw2sbom:confidence_level",
                 "value": confidence_level(std["confidence"])},
                {"name": "fw2sbom:evidence_class", "value": "embedded-standard-data"},
            ] + [{"name": k, "value": v} for k, v in std["properties"]],
        }
        if std["version"]:
            comp["version"] = std["version"]
            comp["evidence"]["identity"].append({
                "field": "version",
                "confidence": std["confidence"],
                "methods": methods[:1],
            })
            comp["properties"].append({"name": "fw2sbom:version_source",
                                       "value": "parsed-from-structure"})
        components.append(comp)
        dep_refs.append(ref)

    if opacity and opacity["opaque"] and payload is not None:
        ref = "firmware-payload-opaque"
        encrypted = not opacity["compression"]
        components.append({
            "type": "firmware",
            "bom-ref": ref,
            "name": f"{fname}:payload",
            "description":
                "Unidentified firmware payload. The image content is "
                + ("encrypted or obfuscated" if encrypted else opacity["verdict"])
                + " and cannot be enumerated by static analysis. Its components are "
                  "unknown - request a plaintext image or the vendor's own SBOM from "
                  "the firmware supplier.",
            "hashes": [{"alg": a, "content": h}
                       for a, h in file_hashes(payload).items()],
            "evidence": {
                "identity": [{
                    "field": "name",
                    "confidence": 0.0,
                    "methods": [{
                        "technique": "binary-analysis",
                        "confidence": 0.0,
                        "value": reason,
                    } for reason in opacity["reasons"][:MAX_EVIDENCE_PER_COMPONENT]],
                }],
                "occurrences": [{
                    "location": fname,
                    "additionalContext":
                        f"{len(payload)} payload bytes"
                        + (f" de-framed from {container['records']} records"
                           if container else ""),
                }],
            },
            "properties": [
                {"name": "fw2sbom:opaque", "value": "true"},
                {"name": "fw2sbom:opacity_verdict", "value": opacity["verdict"]},
                {"name": "fw2sbom:analysis_result",
                 "value": "content not enumerable; vendor SBOM required"},
                {"name": "fw2sbom:payload_size_bytes", "value": str(len(payload))},
            ],
        })
        dep_refs.append(ref)

    bom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "lifecycles": [{"phase": "post-build"}],
            "tools": {
                "components": [{
                    "type": "application",
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "description": "Binary fingerprint + string signature SBOM extractor",
                }]
            },
            "component": {
                "type": "firmware",
                "bom-ref": f"firmware:{hashes['SHA-256'][:24]}",
                "name": fname,
                "version": firmware_version or "UNKNOWN",
                "hashes": [{"alg": a, "content": h} for a, h in hashes.items()],
                "properties": fw_props,
            },
            "properties": [
                {"name": "fw2sbom:sbom_type", "value": "binary-derived"},
                {"name": "fw2sbom:analysis_methods",
                 "value": "file(1) magic, packetized-container de-framing, "
                          "printable-string extraction, signature/regex matching, "
                          "instruction-set identification (Cortex-M / MCS-51), "
                          "embedded standard-data parsing (VESA E-EDID, DDC/CI "
                          "MCCS), entropy/opacity analysis"},
                {"name": "fw2sbom:offset_reference", "value": offset_space},
                {"name": "fw2sbom:strings_extracted", "value": str(n_strings)},
                {"name": "fw2sbom:min_string_length", "value": str(min_str_len)},
                {"name": "fw2sbom:disclaimer",
                 "value": "This SBOM was derived from static analysis of a stripped "
                          "firmware binary. Component identification and versions are "
                          "heuristic (evidence-based) and may be incomplete or "
                          "inaccurate. Absence of a component is not evidence of "
                          "absence."},
                {"name": "fw2sbom:opacity_disclaimer",
                 "value": "An 'opaque' verdict means the payload is encrypted, "
                          "obfuscated or compressed with an unrecognised scheme. No "
                          "static tool can enumerate components in that state; the "
                          "SBOM is therefore metadata-only by necessity and must be "
                          "completed from a vendor-supplied SBOM or plaintext image."},
            ],
        },
        "components": components,
        "dependencies": [{"ref": f"firmware:{hashes['SHA-256'][:24]}",
                          "dependsOn": dep_refs}]
                        + [{"ref": r, "dependsOn": []} for r in dep_refs],
    }
    return bom


def build_evidence_context(filename, data, payload, arm_info, container,
                           opacity, hits, standards, sbom_filename):
    """Collect everything the evidence workbook needs into one dict.

    Shared by the CLI and the drag-and-drop service so both deliverable pairs are
    produced by exactly the same analysis.
    """
    matched = {h["sig"]["name"] for h in hits}
    magics = evidence_report.scan_magics(payload)
    banks = evidence_report.analyze_banks(payload)
    return {
        "filename": filename,
        "data": data,
        "hashes": file_hashes(data),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
        "tool_name": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "architecture": arm_info["label"],
        "arch_details": arm_info["details"],
        "container": container,
        "opacity": opacity,
        "hits": hits,
        "standards": standards,
        "all_signatures": SIGNATURES,
        "not_found": [s for s in SIGNATURES if s["name"] not in matched],
        "magics": magics,
        "banks": banks,
        "bank_size": banks[0]["size"] if banks else evidence_report.BANK_SIZE,
        "edid_blocks": detect_edid_blocks(payload),
        "structural_checks": [
            ("VESA E-EDID block",
             any(s["name"] == "vesa-e-edid" for s in standards)),
            ("VESA MCCS / DDC-CI capability string",
             any(s["name"] == "vesa-mccs" for s in standards)),
            ("ARM Cortex-M vector table", arm_info["looks_like_cortex_m"]),
            ("MCS-51 vector table + opcode profile",
             arm_info.get("mcs51", {}).get("looks_like_mcs51", False)),
            ("Packetized record framing", container is not None),
        ],
        "vendor_hint": None,
        "firmware_version": None,
        "n_confirmed": len(hits),
        "n_standards": len(standards),
        "n_not_found": len(SIGNATURES) - len(matched),
        "n_magic_validated": sum(1 for m in magics if m["validated_hits"]),
        "n_magic_rejected": sum(1 for m in magics
                                if m["raw_hits"] and not m["validated_hits"]),
        "sbom_filename": sbom_filename,
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Generate an evidence-based CycloneDX 1.6 SBOM from an ARM "
                    "Cortex-M / Zephyr-style firmware .bin via binary fingerprinting.",
        epilog="Example: %(prog)s zephyr.bin -o zephyr.sbom.json --pretty -v",
    )
    ap.add_argument("input", help="firmware image (.bin) to analyze")
    ap.add_argument("-o", "--output", default=None,
                    help="output SBOM path (default: <input>.cdx.json)")
    ap.add_argument("-d", "--out-dir", metavar="DIR",
                    help="write both deliverables into DIR as <stem>_SBOM.cdx.json "
                         "and <stem>_Evidence.xlsx")
    ap.add_argument("--evidence", metavar="FILE",
                    help="write the Excel evidence/confidence workbook to FILE")
    ap.add_argument("--min-str-len", type=int, default=6, metavar="N",
                    help="minimum length for extracted strings (default: 6)")
    ap.add_argument("--dump-strings", metavar="FILE",
                    help="also write all extracted strings (offset<TAB>string) to FILE")
    ap.add_argument("--no-deframe", action="store_true",
                    help="do not detect/strip packetized container framing")
    ap.add_argument("--dump-payload", metavar="FILE",
                    help="write the de-framed payload (framing stripped) to FILE")
    ap.add_argument("--pretty", action="store_true", help="indent JSON output")
    ap.add_argument("--fail-if-empty", action="store_true",
                    help="exit with code 2 if no components are identified")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="verbose progress on stderr")
    ap.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    args = ap.parse_args(argv)

    if args.min_str_len < 3:
        die("--min-str-len must be >= 3 (shorter values produce mostly noise)")

    data = read_binary(args.input)
    log(f"read {len(data)} bytes from {args.input}", args.verbose)

    file_magic = run_file_command(args.input, args.verbose)
    if file_magic:
        log(f"file(1): {file_magic}", args.verbose)
        if any(k in file_magic for k in ("ELF", "PE32", "Mach-O")):
            log("WARNING: input looks like a linked executable, not a raw .bin; "
                "results may be off (strip to raw binary with objcopy -O binary)", True)

    container = None if args.no_deframe else detect_packet_container(data, args.verbose)
    payload = deframe(data, container) if container else data
    if container:
        log(f"de-framed {len(payload)} payload bytes "
            f"({len(data) - len(payload)} bytes of framing/header removed)",
            args.verbose)
    if args.dump_payload:
        try:
            with open(args.dump_payload, "wb") as f:
                f.write(payload)
        except OSError as e:
            die(f"cannot write payload dump: {e}")

    arm_info = analyze_architecture(payload)
    log(f"architecture: {arm_info['label'] or 'not identified'}", args.verbose)
    for detail in arm_info["details"]:
        log(f"  {detail}", args.verbose)

    opacity = analyze_opacity(payload, arm_info["label"])
    log(f"payload verdict: {opacity['verdict']} "
        f"(entropy {opacity['entropy']:.3f} bits/byte)", args.verbose)

    standards = detect_embedded_standards(payload, args.verbose)

    strings = extract_strings(payload, args.min_str_len)
    log(f"extracted {len(strings)} strings (min length {args.min_str_len})", args.verbose)

    if args.dump_strings:
        try:
            with open(args.dump_strings, "w", encoding="utf-8") as f:
                for off, s in strings:
                    f.write(f"0x{off:08x}\t{s}\n")
        except OSError as e:
            die(f"cannot write strings dump: {e}")

    hits = match_signatures(strings, args.verbose)
    infer_versions(hits, args.verbose)
    bom = build_sbom(args.input, data, file_magic, arm_info, hits,
                     args.min_str_len, len(strings),
                     container=container, opacity=opacity, payload=payload,
                     standards=standards)

    stem = os.path.splitext(os.path.basename(args.input))[0]
    if args.out_dir:
        try:
            os.makedirs(args.out_dir, exist_ok=True)
        except OSError as e:
            die(f"cannot create output directory {args.out_dir}: {e}")
        out_path = args.output or os.path.join(args.out_dir, stem + "_SBOM.cdx.json")
        evidence_path = args.evidence or os.path.join(args.out_dir,
                                                      stem + "_Evidence.xlsx")
    else:
        out_path = args.output or (args.input + ".cdx.json")
        evidence_path = args.evidence
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(bom, f, indent=2 if args.pretty else None)
            f.write("\n")
    except OSError as e:
        die(f"cannot write SBOM to {out_path}: {e}")

    if container:
        print(f"[fw2sbom] packetized container: {container['stride']}-byte records, "
              f"{container['records']} records, {container['framing_width']}B framing "
              f"+ {container['payload_width']}B payload "
              f"({container['payload_bytes']} payload bytes)", file=sys.stderr)
        print(f"[fw2sbom]   layout {container['layout']}", file=sys.stderr)

    if arm_info["label"]:
        print(f"[fw2sbom] architecture: {arm_info['label']}", file=sys.stderr)

    total = len(hits) + len(standards)
    if evidence_path:
        context = build_evidence_context(
            os.path.basename(args.input), data, payload, arm_info, container,
            opacity, hits, standards, os.path.basename(out_path))
        try:
            evidence_report.write_evidence_workbook(evidence_path, context, bom)
        except OSError as e:
            die(f"cannot write evidence workbook to {evidence_path}: {e}")
        print(f"[fw2sbom] evidence workbook -> {evidence_path}", file=sys.stderr)

    print(f"[fw2sbom] {total} component(s) identified -> {out_path}", file=sys.stderr)
    for h in hits:
        v = h["version"] or "?"
        print(f"[fw2sbom]   {h['sig']['name']:<22} version={v:<12} "
              f"confidence={h['confidence']} ({confidence_level(h['confidence'])})",
              file=sys.stderr)
    for std in standards:
        v = std["version"] or "?"
        print(f"[fw2sbom]   {std['name']:<22} version={v:<12} "
              f"confidence={std['confidence']} "
              f"({confidence_level(std['confidence'])}) [embedded standard data]",
              file=sys.stderr)
    if opacity["opaque"]:
        print(f"[fw2sbom] payload is OPAQUE ({opacity['verdict']}) - static component "
              "identification is not possible:", file=sys.stderr)
        for reason in opacity["reasons"]:
            print(f"[fw2sbom]   - {reason}", file=sys.stderr)
        print("[fw2sbom] recorded as a single opaque component; obtain a plaintext "
              "image or the vendor's SBOM to complete it", file=sys.stderr)
    elif not total:
        print("[fw2sbom] no known components matched; SBOM contains metadata only",
              file=sys.stderr)
    if not total and args.fail_if_empty:
        sys.exit(2)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        die("interrupted", 130)
