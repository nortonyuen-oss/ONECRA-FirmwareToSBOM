#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_zstd_vectors - reference zstd frames for the UBIFS fixtures.

UBIFS can compress data nodes with zstd, and fw2sbom reads them when the Python
running it has compression.zstd (3.14 and later). None of the published UBIFS
samples actually holds zstd-compressed data - the "zstd" sample's files are
small enough to be stored uncompressed - so the fixture needs a real frame to
put in a data node. The fixtures run on older Pythons too, where zstd cannot
be produced, so the frame is generated here once and committed.

Regenerate with Python 3.14 or later:

    python tests/make_zstd_vectors.py
"""

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUTPUT = os.path.join(HERE, "zstd_vectors.json")

PLAIN = b"zstd-compressed data node, as a UBIFS image may carry it. " * 40


def main():
    try:
        from compression import zstd
    except ImportError:
        sys.exit("regenerating needs Python 3.14 or later (compression.zstd)")
    frame = zstd.compress(PLAIN)
    with open(OUTPUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump({"generator": "compression.zstd (CPython 3.14 standard library)",
                   "vectors": [{"name": "ubifs-data-node", "length": len(PLAIN),
                                "sha256": hashlib.sha256(PLAIN).hexdigest(),
                                "zstd": frame.hex()}]}, f, indent=1)
        f.write("\n")
    print(f"{len(PLAIN)} bytes -> {len(frame)}-byte frame -> {OUTPUT}")


if __name__ == "__main__":
    main()
