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
import json
import os
import sys
import urllib.request

UNBLOB = ("https://raw.githubusercontent.com/onekey-sec/unblob/"
          "main/tests/integration/")

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
    # --- Format samples from the unblob project (MIT) ---------------------- #
    #
    # These are format-variant vectors rather than whole firmware: every byte
    # order, every compressor, padded and unpadded. That makes them the right
    # thing to write a reader against and the wrong thing to trust as proof it
    # survives a real vendor image - which is why the router, ESP32 and BIOS
    # entries above are still here. Both kinds earn their place.
    #
    # They are stored with Git LFS, so the raw URL serves a pointer file and
    # the fetcher resolves it.
    {
        "path": "formats/cramfs_le.bin",
        "url": UNBLOB + "filesystem/cramfs/little_endian/__input__/fruits.cramfs_le",
        "sha256": "8e594657cd8a394eb7abb2a10041681a925edb95e829d37a7a4ac5168f026b9e",
        "note": "CramFS, little-endian. The filesystem many small Linux "
                "devices use where a router uses SquashFS.",
    },
    {
        "path": "formats/cramfs_be.bin",
        "url": UNBLOB + "filesystem/cramfs/big_endian/__input__/fruits.cramfs_be",
        "sha256": "de1d6be79d816470ff54836760a0a1574fba6c2efa9ed13108f0669eb329d749",
        "note": "The same contents big-endian. The inode bitfields flip with "
                "the byte order, so the two decoders check each other.",
    },
    {
        "path": "formats/netgear_trx_v1.bin",
        "url": UNBLOB + "archive/netgear/trx/trx_v1/__input__/sample.trx",
        "sha256": "94c27fcc2ceeabeefde74134c84cfbdec79b237db720b01d914a69a47d2a292e",
        "note": "Broadcom TRX revision 1 - three parts.",
    },
    {
        "path": "formats/netgear_trx_v2.bin",
        "url": UNBLOB + "archive/netgear/trx/trx_v2/__input__/sample.trx",
        "sha256": "fa7ccf8baa38f293e5d26c397e59a673d8de2a1434fa6e5654a0b75309f56849",
        "note": "Broadcom TRX revision 2 - four parts. The wrapper on a large "
                "share of consumer routers.",
    },
    {
        "path": "formats/netgear_chk.bin",
        "url": UNBLOB + "archive/netgear/chk/__input__/sample.chk",
        "sha256": "18e9a759fc06d2c99e531188b39f4482d06a7b772393e225fd06550fe16321ee",
        "note": "Netgear CHK, the board-identifying wrapper that contains a "
                "TRX on a real device.",
    },
    {
        "path": "formats/dlink_shrs.bin",
        "url": UNBLOB + "archive/dlink/shrs/__input__/sample.bin",
        "sha256": "df841ac5e923fa5bd69d7f71aa131fbfa941bd10dd6d406698612540e078aaf0",
        "note": "D-Link SHRS: a 1,756-byte header over a payload that is "
                "AES-encrypted on shipping devices - the honest-opacity case.",
    },
    {
        "path": "formats/instar_bneg.bin",
        "url": UNBLOB + "archive/instar/bneg/__input__/output.bin",
        "sha256": "9b422c5cd65b3c72a2c113fd6d80a5d8241a4989b8b51b35c3a3c695979119f7",
        "note": "Instar BNEG. IP cameras are a firmware class we are short of.",
    },
    {
        "path": "formats/moxa_frm.bin",
        "url": UNBLOB + "archive/moxa/frm/moxa_frm/__input__/test.frm",
        "sha256": "91d68c12cb810a8b22c957ad7d9e57b0844eec701638acd0a6b450072d5f4e03",
        "note": "Moxa FRM, industrial gateways.",
    },
]

TIMEOUT = 300

LFS_POINTER = b"version https://git-lfs.github.com/spec/v1"
LFS_BATCH = "https://github.com/onekey-sec/unblob.git/info/lfs/objects/batch"


def resolve_lfs(blob):
    """Turn a Git LFS pointer into the bytes it points at.

    raw.githubusercontent.com serves the pointer, not the file, for anything
    stored with LFS - a 128-byte text file where a firmware image was expected.
    Silently writing that to disk would make every reader fail on a file that
    downloaded without an error.
    """
    if not blob.startswith(LFS_POINTER):
        return blob
    fields = dict(line.split(" ", 1)
                  for line in blob.decode("ascii").strip().split("\n"))
    oid = fields["oid"].split(":", 1)[1]
    request = urllib.request.Request(
        LFS_BATCH,
        data=json.dumps({"operation": "download", "transfers": ["basic"],
                         "objects": [{"oid": oid,
                                      "size": int(fields["size"])}]}).encode(),
        headers={"Accept": "application/vnd.git-lfs+json",
                 "Content-Type": "application/vnd.git-lfs+json"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as r:
        answer = json.loads(r.read())
    href = answer["objects"][0]["actions"]["download"]["href"]
    with urllib.request.urlopen(href, timeout=TIMEOUT) as r:
        return r.read()


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
                blob = resolve_lfs(r.read())
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
