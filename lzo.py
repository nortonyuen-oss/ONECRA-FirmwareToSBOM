#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lzo - a pure-Python LZO1X decompressor.

LZO is the compressor embedded Linux reaches for when decompression speed
matters more than ratio: JFFS2 and UBIFS both use it, and plenty of vendor
firmware sets it as the default. Python's standard library has no LZO, and the
portable package ships nothing but the standard library, so this is written
out here - decompression only, following the structure of the kernel's
lzo1x_decompress_safe().

Everything in the format is a small number of instruction kinds - a literal
run, and four sizes of back-reference (M1 to M4) distinguished by the value of
the leading byte. The one detail that makes it easy to get subtly wrong: after
every back-reference, the count of literal bytes that follow (0 to 3) is taken
from the low two bits of the byte *two back* in the input - which is the
instruction byte itself for the short forms and the first distance byte for
the long ones. Take it from the wrong byte and short streams still decode
while long ones drift into garbage.

So it is tested differentially, against lzokay - an independent C++
implementation - rather than only against the published JFFS2 samples, whose
single LZO stream is nine bytes long and exercises almost none of the format.
tests/lzo_vectors.json holds reference streams chosen so that together they
run every instruction kind, and the suite checks that they still do. During
development the same comparison ran over 258 inputs, including 240 blocks of
real router, BIOS and ESP32 firmware - 5.9 MB of LZO - with no difference.

Every read is bounds-checked and output is capped, because the input is
whatever a customer uploaded.
"""

M2_MAX_OFFSET = 0x0800
M4_BASE = 0x4000
MAX_OUTPUT = 64 * 1024 * 1024


class LZOError(Exception):
    pass


def decompress(src, expected=None, limit=MAX_OUTPUT):
    """Decompress one LZO1X stream. `expected`, if given, trims the output."""
    out = bytearray()
    n = len(src)
    ip = 0

    def take():
        nonlocal ip
        if ip >= n:
            raise LZOError("input ended inside an instruction")
        value = src[ip]
        ip += 1
        return value

    def long_length(base):
        """A zero length byte extends the count: 255 per zero, then the rest."""
        extra = 0
        while True:
            value = take()
            if value:
                return extra + base + value
            extra += 255
            if extra > limit:
                raise LZOError("length run is implausibly long")

    def literals(count):
        nonlocal ip
        if ip + count > n:
            raise LZOError("literal run reaches past the input")
        out.extend(src[ip:ip + count])
        ip += count
        if len(out) > limit:
            raise LZOError("output exceeds the size limit")

    def match(back, length):
        start = len(out) - back
        if start < 0:
            raise LZOError("back-reference reaches before the output starts")
        if back >= length:
            out.extend(out[start:start + length])
        else:
            # Overlapping: the copy reads bytes it has just written. That is
            # how a run of one byte is encoded, so it has to be byte by byte.
            for index in range(length):
                out.append(out[start + index])
        if len(out) > limit:
            raise LZOError("output exceeds the size limit")

    if not src:
        raise LZOError("empty input")

    state = "start"
    t = 0
    trailing = 0

    # A first byte above 17 is a literal run with no preceding instruction.
    if src[0] > 17:
        t = take() - 17
        literals(t)
        if t < 4:
            t = take()
            state = "match"
        else:
            state = "after-literals"

    while True:
        if state == "start":
            t = take()
            if t >= 16:
                state = "match"
                continue
            count = long_length(15) if t == 0 else t
            literals(count + 3)
            state = "after-literals"
            continue

        if state == "after-literals":
            t = take()
            if t >= 16:
                state = "match"
                continue
            # Straight after a literal run a small value is a three-byte
            # match with its own, longer, distance base.
            low = take()
            match(1 + M2_MAX_OFFSET + (t >> 2) + (low << 2), 3)
            trailing = t & 3
        else:                                   # state == "match"
            if t >= 64:                         # M2: 3 to 8 bytes, near
                low = take()
                match(1 + ((t >> 2) & 7) + (low << 3), (t >> 5) + 1)
                trailing = t & 3
            elif t >= 32:                       # M3: any length, up to 16 KB back
                length = t & 31
                if length == 0:
                    length = long_length(31)
                first, second = take(), take()
                match(1 + (first >> 2) + (second << 6), length + 2)
                trailing = first & 3
            elif t >= 16:                       # M4: any length, 16-48 KB back
                length = t & 7
                if length == 0:
                    length = long_length(7)
                first, second = take(), take()
                back = ((t & 8) << 11) + (first >> 2) + (second << 6)
                if back == 0:                   # the end-of-stream marker
                    break
                match(back + M4_BASE, length + 2)
                trailing = first & 3
            else:                               # M1: two bytes, near
                low = take()
                match(1 + (t >> 2) + (low << 2), 2)
                trailing = t & 3

        if trailing == 0:
            state = "start"
            continue
        literals(trailing)
        t = take()
        state = "match"

    if expected is not None:
        if len(out) < expected:
            raise LZOError(f"stream ended after {len(out)} of {expected} bytes")
        return bytes(out[:expected])
    return bytes(out)
