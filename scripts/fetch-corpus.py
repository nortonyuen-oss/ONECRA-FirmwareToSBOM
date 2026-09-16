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
    {
        "path": "esp32/tasmota32.bin",
        "url": "https://github.com/arendst/Tasmota/releases/download/v15.6.0/"
               "tasmota32.bin",
        "sha256": "5249c9b49e40c9fb96869f3fc573c3a00c9d99ea55997fd9117aaafbf7c0e7f3",
        "note": "Tasmota 15.6.0 for ESP32, Xtensa LX6. An application image "
                "whose app descriptor fills in only idf_ver - the blank-field "
                "case every synthetic fixture gets wrong.",
    },
    {
        "path": "esp32/tasmota32c3.bin",
        "url": "https://github.com/arendst/Tasmota/releases/download/v15.6.0/"
               "tasmota32c3.bin",
        "sha256": "5991d11ad8f8b100b165974e81544594394df1d12d165012a42c002e1985cb1c",
        "note": "Tasmota 15.6.0 for ESP32-C3, RISC-V. The core that no entropy "
                "or opcode heuristic can tell apart from the Xtensa parts.",
    },
    {
        "path": "esp32/tasmota32.factory.bin",
        "url": "https://github.com/arendst/Tasmota/releases/download/v15.6.0/"
               "tasmota32.factory.bin",
        "sha256": "35b8c70c843767919f6ec6e25c0d79f87e3519fae0c5c2b2f7d1631b27431a41",
        "note": "The same firmware as a full flash image: bootloader, "
                "partition table, and a layout that names its app partition "
                "'safeboot' rather than the textbook 'factory'.",
    },
    {
        "path": "uefi/edk2-ovmf-x64.fd",
        "url": "https://retrage.github.io/edk2-nightly/bin/RELEASEX64_OVMF.fd",
        "sha256": "f8c95686ef99f028fb3863e21fc98423f95a08bac1018c774bf6687921c85d83",
        "note": "An EDK2 release build. A PC BIOS with no library banners at "
                "all - the inventory is 123 modules behind an LZMA section "
                "that expands 1.4 MB into 16 MB.",
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
