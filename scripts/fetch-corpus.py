#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fetch-corpus - download the real vendor firmware the corpus tests run against.

Synthetic fixtures prove the parsers follow the format specifications. They
cannot prove the parsers survive what vendors actually ship, and that gap is
where firmware analysis usually breaks: real images have quirks no
specification mentions. So a handful of real, publicly downloadable images are
used as well.

They are not in git - they are third-party binaries with their own licences and
tens of megabytes each. The corpus tests skip when an image is missing, so the
suite still runs without them; it just proves less.

    python scripts/fetch-corpus.py

Each image is recorded with the SHA-256 of the copy this project was developed
against. A mismatch is reported but not fatal: vendors do re-cut releases under
the same filename, and knowing that happened is more useful than refusing to
run.
"""

import hashlib
import os
import sys
import urllib.request

CORPUS = [
    {
        "path": "router/openwrt-mt300n-v2-4.3.25.bin",
        "url": "https://fw.gl-inet.com/firmware/mt300n-v2/release4/"
               "openwrt-mt300n-v2-4.3.25-0318-1742298825.bin",
        "sha256": "05a823f7714848bf039a27afa9f2eca28089ab978aac9dcb9c3f3613f78a9023",
        "note": "GL.iNet GL-MT300N-V2 'Mango', OpenWrt 22.03.4, MIPS. "
                "uImage + LZMA kernel + xz SquashFS with a 359-entry opkg "
                "database.",
    },
]

TIMEOUT = 300


def main(argv):
    root = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "corpus")
    for entry in CORPUS:
        target = os.path.join(root, entry["path"])
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if os.path.exists(target):
            print(f"have  {entry['path']}")
        else:
            print(f"fetch {entry['url']}")
            with urllib.request.urlopen(entry["url"], timeout=TIMEOUT) as r:
                blob = r.read()
            with open(target, "wb") as f:
                f.write(blob)
        digest = hashlib.sha256(open(target, "rb").read()).hexdigest()
        state = "ok" if digest == entry["sha256"] else "DIFFERENT FROM RECORDED"
        print(f"      {os.path.getsize(target):>10} bytes  sha256 {state}")
        if state != "ok":
            print(f"      recorded {entry['sha256']}")
            print(f"      actual   {digest}")
        print(f"      {entry['note']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
