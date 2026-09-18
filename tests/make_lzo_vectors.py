#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_lzo_vectors - reference LZO1X streams for testing lzo.py.

A decompressor can only be tested against a compressor that is not itself: a
decompressor checked against a compressor written from the same understanding
of the format passes whatever that understanding gets wrong. So these streams
come from lzallright, a binding to lzokay - an independent C++ implementation
of LZO1X - and the suite checks that lzo.py turns each back into the input.

The inputs are chosen, not sampled, so that together they drive every kind of
instruction the format has: the four sizes of back-reference, the length
extension, the overlapping copy, the initial literal run, the trailing
literals and the end-of-stream marker. The suite checks that coverage too, so
editing this list cannot quietly drop a case. Two instructions needed
construction rather than luck:

  * the two-byte near match (M1) turns up in low-alphabet data, and
  * the three-byte match straight after a literal run only when the match is
    exactly three bytes long at a distance of 2049-3072, which random data
    essentially never produces by chance.

lzallright is needed only to regenerate this file; the tests read the JSON and
need nothing outside the standard library.

    pip install lzallright
    python tests/make_lzo_vectors.py
"""

import hashlib
import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUTPUT = os.path.join(HERE, "lzo_vectors.json")


def inputs():
    r = random.Random(0x1985)

    def rand(n):
        return bytes(r.randrange(256) for _ in range(n))

    def periodic(n):
        # Compresses well, and never matches a random block, so the only long
        # match is the one each case deliberately places far back.
        return bytes((i * 7) % 251 for i in range(n))

    def after_literals():
        rr = random.Random(0)
        out = bytearray(bytes(rr.randrange(256) for _ in range(3200)))
        for _ in range(40):
            out += bytes(rr.randrange(256) for _ in range(rr.randrange(4, 12)))
            distance = rr.randrange(2049, 3073)
            start = len(out) - distance
            out += out[start:start + 3]
            follower = out[start + 3] if start + 3 < len(out) else 0
            out.append((follower + 1) % 256)
        return bytes(out)

    near = random.Random(0)
    return {
        "single-byte": b"x",
        "short-literal-run": b"firmware",
        "literal-run-300": rand(300),
        "overlapping-run": b"A" * 5000,
        "near-repeats": b"abcabcabdabcabxabc" * 40,
        "text": b"The quick brown fox jumps over the lazy dog. " * 60,
        "repeat-10k-back": (lambda b: b + periodic(10000) + b)(rand(200)),
        "repeat-20k-back": (lambda b: b + periodic(20000) + b)(rand(200)),
        "repeat-40k-back": (lambda b: b + periodic(40000) + b)(rand(120)),
        "long-match-3000": b"\x00" * 5 + b"XYZ" * 1000,
        "m1-near": bytes(near.randrange(15) + 0x41 for _ in range(3000)),
        "m1-after-literals": after_literals(),
    }


def main():
    try:
        import lzallright
    except ImportError:
        sys.exit("lzallright is needed to regenerate the vectors: "
                 "pip install lzallright")
    compressor = lzallright.LZOCompressor()
    vectors = []
    for name, plain in inputs().items():
        packed = compressor.compress(plain)
        vectors.append({"name": name, "length": len(plain),
                        "sha256": hashlib.sha256(plain).hexdigest(),
                        "lzo": packed.hex()})
    with open(OUTPUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump({"generator": "lzallright (lzokay), an independent LZO1X "
                                "implementation; see tests/make_lzo_vectors.py",
                   "vectors": vectors}, f, indent=1)
        f.write("\n")
    print(f"{len(vectors)} vectors -> {OUTPUT}")


if __name__ == "__main__":
    main()
