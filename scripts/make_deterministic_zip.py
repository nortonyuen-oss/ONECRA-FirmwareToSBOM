#!/usr/bin/env python3
"""Zip a directory reproducibly.

A release record is only worth something if the hash it names can be
re-derived. Compress-Archive (and zip(1)) stamp each entry with its mtime and
walk the tree in filesystem order, so two builds of byte-identical content
still produce different archives -- and therefore a different SHA-256. This
writer sorts the entries, fixes every timestamp, and pins the compression
level, so identical inputs always produce an identical archive.

Usage: make_deterministic_zip.py <source-dir> <output.zip>

Entries are stored under the source directory's own name, so extracting gives
the customer one folder rather than 40 loose files in their Downloads.

stdlib only, like the rest of fw2sbom -- and deliberately runnable by the
embeddable interpreter that was just staged, so the build needs no second
Python on the machine.
"""

import os
import sys
import zipfile

# 1980-01-01 is the earliest timestamp the zip format can represent. The value
# itself is arbitrary; only its constancy matters.
FIXED_DATE_TIME = (1980, 1, 1, 0, 0, 0)

# Regular file, rw-r--r--. Windows ignores the unix bits, but pinning them
# keeps the archive identical no matter what the staged files' modes are.
FIXED_EXTERNAL_ATTR = (0o100644) << 16


def collect(src):
    """Every file under src as (archive-relative path, full path), sorted."""
    found = []
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames.sort()
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, src).replace(os.sep, "/")
            found.append((rel, full))
    found.sort(key=lambda pair: pair[0])
    return found


def main(argv):
    if len(argv) != 3:
        print(__doc__.strip(), file=sys.stderr)
        return 1

    src = os.path.abspath(argv[1])
    out = os.path.abspath(argv[2])

    if not os.path.isdir(src):
        print(f"error: not a directory: {src}", file=sys.stderr)
        return 1

    root = os.path.basename(src.rstrip(r"\/"))
    files = collect(src)
    if not files:
        print(f"error: no files under {src}", file=sys.stderr)
        return 1

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for rel, full in files:
            info = zipfile.ZipInfo(f"{root}/{rel}", date_time=FIXED_DATE_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = FIXED_EXTERNAL_ATTR
            info.create_system = 0  # claim MS-DOS regardless of build host
            with open(full, "rb") as f:
                z.writestr(info, f.read())

    print(f"{len(files)} file(s) -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
