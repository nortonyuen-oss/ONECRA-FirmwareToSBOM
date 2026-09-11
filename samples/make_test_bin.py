#!/usr/bin/env python3
"""Generate a synthetic Zephyr-style Cortex-M firmware image (samples/zephyr.bin)
for testing fw2sbom. Layout: fake vector table + Thumb code padding + typical
embedded strings (Zephyr, mbed TLS, lwIP, newlib, littlefs, GCC, CMSIS)."""
import os
import struct
import sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zephyr.bin")

def main():
    blob = bytearray()
    # --- Cortex-M vector table (flash mapped at 0x08000000-style addresses) ---
    blob += struct.pack("<I", 0x20010000)        # initial SP -> SRAM
    blob += struct.pack("<I", 0x000004C1)        # reset handler (Thumb bit set)
    for i in range(14):                          # slots 2..15: plausible handlers
        blob += struct.pack("<I", 0x00000501 + i * 0x20)
    # --- fake Thumb code (nop = 0xbf00, push {r7,lr} = 0xb580 ...) ---
    for _ in range(2048):
        blob += struct.pack("<H", 0xBF00)
        blob += struct.pack("<H", 0xB580)
    # --- typical strings found in real Zephyr images ---
    strings = [
        b"*** Booting Zephyr OS build zephyr-v3.5.0 ***",
        b"Zephyr version 3.5.0",
        b"ZEPHYR_BASE=/workdir/zephyr",
        b"zephyr,console",
        b"mbed TLS 3.4.0",
        b"mbedtls_ssl_handshake",
        b"MBEDTLS_ERR_SSL_ALLOC_FAILED",
        b"lwIP 2.1.3",
        b"lwip_socket",
        b"newlib 4.3.0",
        b"_impure_ptr",
        b"littlefs v2.8.0",
        b"lfs_mount",
        b"GCC: (Zephyr SDK 0.16.3) 12.2.0",
        b"arm-zephyr-eabi",
        b"CMSIS-5.9.0",
        b"SysTick_Handler",
        b"Hello World! nucleo_f429zi",
        b"uart:~$ ",
        b"west build -b nucleo_f429zi samples/hello_world",
    ]
    for s in strings:
        blob += s + b"\x00"
        blob += os.urandom(3)  # a little binary noise between strings
    # --- pad to 32 KiB like a real image ---
    blob += b"\xff" * (32 * 1024 - len(blob) % (32 * 1024))
    with open(OUT, "wb") as f:
        f.write(blob)
    print(f"wrote {OUT} ({len(blob)} bytes)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
