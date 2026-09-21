#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cpio - read the "newc" cpio archives Linux uses for an initramfs.

An initramfs is how a great deal of embedded Linux carries its root
filesystem: an OpenWrt recovery or initramfs image, a camera whose whole
userland is built into the kernel, a FIT image's ramdisk. It is a cpio
archive - the "newc" variant, 110 bytes of ASCII hex per header - almost
always compressed, and once decompressed it is a filesystem like any other:
the package database, the release file and the binaries are all in it.

Three details the kernel honours and a naive reader does not:

  * **Several archives, one after another.** An initramfs may be a small
    early archive (CPU microcode) followed by the real one, with NUL padding
    between. Reading only the first finds a few firmware blobs and none of
    the userland.
  * **Hard links store their data once**, on the last entry of the set; the
    earlier ones have a size of zero. Taking each entry at face value lists
    empty files where binaries should be.
  * **A later entry for the same path replaces the earlier one**, as it does
    when the kernel unpacks the archives in order.

The old binary and "odc" formats are not read: nothing in current kernels
writes them. Every header field is checked to be hex and every size to lie
inside the archive, because the input is whatever a customer uploaded.
"""

MAGIC_NEWC = b"070701"
MAGIC_CRC = b"070702"
MAGICS = (MAGIC_NEWC, MAGIC_CRC)
HEADER_SIZE = 110
TRAILER = "TRAILER!!!"

S_IFMT, S_IFDIR, S_IFREG, S_IFLNK = 0o170000, 0o040000, 0o100000, 0o120000

# Hostile-input caps.
MAX_ENTRIES = 50000
MAX_NAME = 4096
MAX_ARCHIVES = 16


class CPIOError(Exception):
    pass


def _align4(n):
    return (n + 3) & ~3


def _header(data, at):
    """The 13 fields of a newc header at `at`, or None if there is none."""
    if at + HEADER_SIZE > len(data) or data[at:at + 6] not in MAGICS:
        return None
    raw = data[at + 6:at + HEADER_SIZE]
    try:
        fields = [int(raw[i:i + 8], 16) for i in range(0, 104, 8)]
    except ValueError:
        return None
    if not all(c in b"0123456789abcdefABCDEF" for c in raw):
        return None
    (ino, mode, _uid, _gid, nlink, _mtime, size, devmajor, devminor,
     _rmaj, _rmin, namesize, _check) = fields
    return {"ino": ino, "mode": mode, "nlink": nlink, "size": size,
            "dev": (devmajor, devminor), "namesize": namesize}


class CPIO:
    """A newc cpio archive, or several back to back. Same surface as the
    other filesystem readers."""

    byte_order = "ASCII headers"

    def __init__(self, data, offset=0):
        self.data = data
        self.offset = offset
        self.warnings = []
        self.entries = {}                 # path -> node
        self.archives = 0
        self._read()
        if not self.entries:
            raise CPIOError("no entries")

    def _read(self):
        data = self.data
        at = self.offset
        count = 0
        links = {}                        # (dev, ino) -> [nodes], for hard links
        while self.archives < MAX_ARCHIVES:
            header = _header(data, at)
            if header is None:
                break
            self.archives += 1
            while True:
                header = _header(data, at)
                if header is None:
                    self.warnings.append(
                        f"archive {self.archives} ends without a trailer at "
                        f"offset 0x{at:x}; entries before it are kept")
                    self.end = at
                    return
                namesize = header["namesize"]
                if not 0 < namesize <= MAX_NAME:
                    raise CPIOError(f"implausible name length at 0x{at:x}")
                name_end = at + HEADER_SIZE + namesize
                data_start = self.offset + _align4(name_end - self.offset)
                data_end = data_start + header["size"]
                if data_end > len(data):
                    self.warnings.append(
                        f"entry at 0x{at:x} runs past the end of the data; "
                        "the archive looks truncated")
                    self.end = len(data)
                    return
                name = data[at + HEADER_SIZE:name_end - 1].decode("utf-8", "replace")
                at = self.offset + _align4(data_end - self.offset)
                if name == TRAILER:
                    break
                count += 1
                if count > MAX_ENTRIES:
                    self.warnings.append(f"stopped after {MAX_ENTRIES} entries")
                    self.end = at
                    return
                while name.startswith(("./", "/")):
                    name = name[2:] if name.startswith("./") else name[1:]
                path = "/" + name
                if name in ("", ".") or "/../" in path + "/":
                    continue
                kind = {S_IFDIR: "directory", S_IFREG: "file",
                        S_IFLNK: "symlink"}.get(header["mode"] & S_IFMT, "other")
                node = {"type": kind, "path": path, "size": header["size"],
                        "at": data_start, "mode": header["mode"]}
                if kind == "symlink":
                    node["target"] = data[data_start:data_end].decode("utf-8", "replace")
                if kind == "file" and header["nlink"] > 1:
                    links.setdefault((header["dev"], header["ino"]), []).append(node)
                self.entries[path] = node        # a later entry replaces it
            # NUL padding between concatenated archives.
            while at < len(data) and data[at] == 0:
                at += 1
        self.end = at
        # Hard links: the data sits on whichever entry of the set carries it.
        for nodes in links.values():
            carrier = next((n for n in nodes if n["size"]), None)
            if carrier:
                for node in nodes:
                    node["size"], node["at"] = carrier["size"], carrier["at"]

    def walk(self):
        """Yield (path, node) for every non-directory entry."""
        for path in sorted(self.entries):
            node = self.entries[path]
            if node["type"] != "directory":
                yield path, node

    def files(self):
        """{path: node} for every regular file."""
        return {path: node for path, node in self.walk() if node["type"] == "file"}

    def read_file(self, node):
        return self.data[node["at"]:node["at"] + node["size"]]


def looks_like_cpio(data, at=0):
    return _header(data, at) is not None


def find_offset(data, limit=64 * 1024 * 1024):
    """Where the first newc archive begins in `data`, or None.

    Checked by parsing, not by the magic alone: "070701" is six printable
    characters and turns up in text.
    """
    at = data.find(MAGIC_NEWC, 0, limit)
    while at != -1:
        if looks_like_cpio(data, at):
            try:
                if len(CPIO(data, at).entries) >= 2:
                    return at
            except CPIOError:
                pass
        at = data.find(MAGIC_NEWC, at + 1, limit)
    return None
