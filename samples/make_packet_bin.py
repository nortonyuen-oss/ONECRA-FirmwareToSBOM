#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate packetized (ISP-dump style) test images for the container handler.

Wraps samples/zephyr.bin in the record framing that some vendors ship instead of
a flat image, so the de-framing detector can be regression-tested:

    [file header][checksum][length][page][sequence][payload chunk] x N

Also emits an encrypted-looking variant (random payload) to exercise the opacity
verdict, and a pure-random control that must NOT be detected as a container.

    python3 samples/make_packet_bin.py

Expected result: every packetized zephyr variant de-frames back to the same 7
components as the flat zephyr.bin; the encrypted variant reports "opaque"; the
control reports no container.
"""

import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
FILE_HEADER = b"VENDORFW\x01\x00" + bytes(110)   # 120-byte vendor file header


def packetize(image, chunk, mode):
    """Frame `image` into fixed-size records. `mode` picks the framing style."""
    body = bytearray()
    for i in range(0, len(image), chunk):
        payload = image[i:i + chunk].ljust(chunk, b"\xff")
        page = (i // (chunk * 128)) & 0xFF
        seq = ((i // chunk) % 128) + 1
        checksum = sum(payload) & 0xFF
        if mode == "checksum":            # [chk][len][page][seq][payload]
            body += bytes([checksum, chunk, page, seq]) + payload
        elif mode == "opaque-checksum":   # checksum we cannot recompute
            body += bytes([random.randrange(256), chunk, page, seq]) + payload
        elif mode == "no-checksum":       # [len][page][seq][payload]
            body += bytes([chunk, page, seq]) + payload
        elif mode == "trailer":           # [payload][chk][len][page][seq]
            body += payload + bytes([checksum, chunk, page, seq])
        else:
            raise ValueError(f"unknown mode: {mode}")
    return FILE_HEADER + bytes(body)


def main():
    random.seed(20260908)
    flat = open(os.path.join(HERE, "zephyr.bin"), "rb").read()

    cases = [
        ("packet_zephyr_checksum.bin", flat, 32, "checksum"),
        ("packet_zephyr_no_checksum.bin", flat, 32, "no-checksum"),
        ("packet_zephyr_trailer.bin", flat, 32, "trailer"),
        ("packet_zephyr_chunk64.bin", flat, 64, "opaque-checksum"),
        # Encrypted payload of the same shape: container detected, payload opaque.
        ("packet_encrypted.bin", bytes(random.randrange(256) for _ in range(len(flat))),
         32, "opaque-checksum"),
    ]
    for name, image, chunk, mode in cases:
        path = os.path.join(HERE, name)
        with open(path, "wb") as f:
            f.write(packetize(image, chunk, mode))
        print(f"wrote {name}: {os.path.getsize(path)} bytes "
              f"(chunk={chunk}, mode={mode})")

    # Control: high-entropy data with no framing at all.
    path = os.path.join(HERE, "random_control.bin")
    with open(path, "wb") as f:
        f.write(bytes(random.randrange(256) for _ in range(200000)))
    print(f"wrote random_control.bin: {os.path.getsize(path)} bytes (no container)")


if __name__ == "__main__":
    main()
