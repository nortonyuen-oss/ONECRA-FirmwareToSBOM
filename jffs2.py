#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jffs2 - read-only JFFS2 reader.

JFFS2 is the writable filesystem on raw NOR and NAND flash: the overlay on an
OpenWrt router, the configuration and application partition on a great many
cameras and industrial devices. Where SquashFS and CramFS are built once and
written whole, JFFS2 is a log - a stream of nodes appended as files change, the
newest version of each piece winning. So a file is not stored anywhere in one
place: it is reassembled from every node that ever wrote part of it.

That shapes this reader more than anything in the format specification:

  * **A file is rebuilt from nodes, by version.** Each data node carries an
    offset, a length and a version number; a later version overwrites an
    earlier one where they overlap. A 26-byte file in the published samples is
    split across two nodes at offsets 0 and 22 - a reader that takes the first
    node it finds returns 22 bytes of a 26-byte file.

  * **Deleting a file writes a node too.** A directory entry pointing at inode
    zero is an unlink. Ignoring that resurrects every file the device deleted,
    and an SBOM listing binaries that are not on the device is wrong in a way
    nobody downstream can detect.

  * **There is no superblock.** The only way to know a region is JFFS2 is that
    it parses as JFFS2, so every node header's CRC is checked: 0x1985 is two
    bytes, and it turns up inside compressed data often enough to matter.

Compression is per node. None, zero, zlib, rtime and LZMA are read here; LZO
comes from `lzo.py`, a pure-Python decompressor, because the standard library
has none. rubin and dynrubin - historic, and never enabled by default - are
reported as unreadable rather than guessed at.

Verified against the JFFS2 samples published by the unblob project (MIT): both
byte orders, the old 0x1984 and current 0x1985 magics, padded and unpadded,
and every compressor above except LZMA, for which no sample exists - its
parameters are the kernel's (lc=0, lp=0, pb=0) and it is stated as such.
"""

import lzma
import struct
import zlib

try:                                       # pure Python, shipped alongside
    import lzo
except ImportError:                        # pragma: no cover - always shipped
    lzo = None

MAGIC = 0x1985
MAGIC_OLD = 0x1984                        # JFFS2_OLD_MAGIC_BITMASK
MAGIC_BYTES = {b"\x85\x19": "<", b"\x19\x85": ">",
               b"\x84\x19": "<", b"\x19\x84": ">"}

NODE_HEADER = 12
DIRENT_HEADER = 40
INODE_HEADER = 68

NODETYPE_DIRENT = 0xE001
NODETYPE_INODE = 0xE002
NODETYPE_CLEANMARKER = 0x2003
NODETYPE_PADDING = 0x2004
NODETYPE_SUMMARY = 0x2006

COMPR_NONE, COMPR_ZERO, COMPR_RTIME = 0x00, 0x01, 0x02
COMPR_RUBINMIPS, COMPR_COPY, COMPR_DYNRUBIN = 0x03, 0x04, 0x05
COMPR_ZLIB, COMPR_LZO, COMPR_LZMA = 0x06, 0x07, 0x08
COMPRESSORS = {0x00: "none", 0x01: "zero", 0x02: "rtime", 0x03: "rubinmips",
               0x04: "copy", 0x05: "dynrubin", 0x06: "zlib", 0x07: "lzo",
               0x08: "lzma"}

S_IFMT, S_IFDIR, S_IFREG, S_IFLNK = 0o170000, 0o040000, 0o100000, 0o120000
ROOT_INO = 1

# Hostile-input caps, matching the other filesystem readers.
MAX_NODES = 200000
MAX_ENTRIES = 20000
MAX_DEPTH = 32
MAX_FILE_BYTES = 64 * 1024 * 1024


class JFFS2Error(Exception):
    pass


def kernel_crc32(data, seed=0):
    """The kernel's crc32_le, which JFFS2 uses: no inversion before or after.

    zlib's crc32 inverts at both ends, so the two differ by a complement - an
    easy thing to get wrong, and checked against every node of the published
    samples.
    """
    return (~zlib.crc32(data, ~seed & 0xFFFFFFFF)) & 0xFFFFFFFF


def rtime_decompress(data, size):
    """The 'rtime' compressor: literal byte, then a repeat of an earlier run.

    Straight from fs/jffs2/compr_rtime.c. Copies are byte by byte because the
    source may overlap the destination - that overlap is how a run of one
    character compresses to four bytes.
    """
    out = bytearray()
    positions = [0] * 256
    at = 0
    while len(out) < size:
        if at + 2 > len(data):
            raise JFFS2Error("rtime stream ends early")
        value, repeat = data[at], data[at + 1]
        at += 2
        out.append(value)
        back = positions[value]
        positions[value] = len(out)
        for _ in range(repeat):
            if back >= len(out):
                raise JFFS2Error("rtime back-reference past the output")
            out.append(out[back])
            back += 1
    return bytes(out[:size])


def _decompress(compr, payload, size):
    if compr in (COMPR_NONE, COMPR_COPY):
        return payload[:size]
    if compr == COMPR_ZERO:
        return b"\x00" * size
    if compr == COMPR_ZLIB:
        return zlib.decompress(payload)[:size]
    if compr == COMPR_RTIME:
        return rtime_decompress(payload, size)
    if compr == COMPR_LZMA:
        # fs/jffs2/compr_lzma.c: a raw LZMA1 stream, lc=0 lp=0 pb=0.
        decoder = lzma.LZMADecompressor(
            format=lzma.FORMAT_RAW,
            filters=[{"id": lzma.FILTER_LZMA1, "lc": 0, "lp": 0, "pb": 0,
                      "dict_size": 1 << 20}])
        return decoder.decompress(payload, size)
    if compr == COMPR_LZO:
        if lzo is None:
            raise JFFS2Error("LZO support is missing from this installation")
        return lzo.decompress(payload, size)
    raise JFFS2Error(
        f"{COMPRESSORS.get(compr, hex(compr))} compression is not read")


class JFFS2:
    """A JFFS2 image. Same surface as squashfs.SquashFS and cramfs.CramFS."""

    def __init__(self, data, offset=0, end=None):
        self.data = data
        self.offset = offset
        self.end = len(data) if end is None else end
        self.warnings = []
        self.byte_order = None
        self.node_count = 0
        self.last_node_end = offset

        self._dirents = {}          # (pino, name) -> (version, ino, type)
        self._inodes = {}           # ino -> [node dicts]
        self._scan()
        if not self.node_count:
            raise JFFS2Error("no JFFS2 nodes with a valid header CRC")
        self._tree = self._build_tree()

    # --- scanning ---------------------------------------------------------- #

    def _scan(self):
        data, at, end = self.data, self.offset, self.end
        while at + NODE_HEADER <= end and self.node_count < MAX_NODES:
            order = MAGIC_BYTES.get(data[at:at + 2])
            if order is None:
                at = self._next_candidate(at + 4)
                continue
            magic, nodetype, totlen, hdr_crc = struct.unpack_from(
                order + "HHII", data, at)
            if (totlen < NODE_HEADER or at + totlen > end
                    or kernel_crc32(data[at:at + 8]) != hdr_crc):
                at = self._next_candidate(at + 4)
                continue
            if self.byte_order is None:
                self.byte_order = "little-endian" if order == "<" else "big-endian"
            self.node_count += 1
            if nodetype == NODETYPE_DIRENT:
                self._read_dirent(order, at, totlen)
            elif nodetype == NODETYPE_INODE:
                self._read_inode(order, at, totlen)
            self.last_node_end = at + totlen
            at += (totlen + 3) & ~3

    def _next_candidate(self, at):
        """The next 4-byte-aligned position that could hold a node header.

        Erased flash is most of a JFFS2 partition, and stepping through it four
        bytes at a time in Python is what makes a 64 MB dump slow. find() is C.
        """
        best = self.end
        for magic in MAGIC_BYTES:
            found = self.data.find(magic, at, self.end)
            while found != -1 and (found - self.offset) % 4:
                found = self.data.find(magic, found + 1, self.end)
            if found != -1 and found < best:
                best = found
        return best

    def _read_dirent(self, order, at, totlen):
        if totlen < DIRENT_HEADER:
            return
        pino, version, ino, _mctime, nsize, dtype = struct.unpack_from(
            order + "IIIIBB", self.data, at + NODE_HEADER)
        name = self.data[at + DIRENT_HEADER:at + DIRENT_HEADER + nsize]
        name = name.decode("utf-8", "replace")
        if not name or "/" in name or name in (".", ".."):
            return
        key = (pino, name)
        previous = self._dirents.get(key)
        # The highest version wins, and ino 0 at the highest version is an
        # unlink: the file was deleted and must not be listed.
        if previous is None or version >= previous[0]:
            self._dirents[key] = (version, ino, dtype)

    def _read_inode(self, order, at, totlen):
        if totlen < INODE_HEADER:
            return
        ino, version, mode = struct.unpack_from(order + "III", self.data,
                                                at + NODE_HEADER)
        isize, _atime, _mtime, _ctime, offset, csize, dsize = struct.unpack_from(
            order + "IIIIIII", self.data, at + 28)
        compr = self.data[at + 56]
        if csize > totlen - INODE_HEADER:
            self.warnings.append(f"inode {ino} v{version}: data runs past its node")
            return
        self._inodes.setdefault(ino, []).append({
            "version": version, "mode": mode, "isize": isize,
            "offset": offset, "csize": csize, "dsize": dsize, "compr": compr,
            "data_at": at + INODE_HEADER,
        })

    # --- the tree ---------------------------------------------------------- #

    def _build_tree(self):
        children = {}
        for (pino, name), (_version, ino, dtype) in self._dirents.items():
            if ino == 0:                   # an unlink, not a file
                continue
            children.setdefault(pino, []).append((name, ino, dtype))
        return children

    def _latest(self, ino):
        nodes = self._inodes.get(ino) or []
        return max(nodes, key=lambda n: n["version"]) if nodes else None

    def _kind(self, ino, dtype):
        latest = self._latest(ino)
        mode = latest["mode"] if latest else 0
        if (mode & S_IFMT) == S_IFDIR or dtype == 4:
            return "directory"
        if (mode & S_IFMT) == S_IFLNK or dtype == 10:
            return "symlink"
        if (mode & S_IFMT) == S_IFREG or dtype == 8:
            return "file"
        return "other"

    def walk(self):
        """Yield (path, node) for every non-directory entry."""
        stack = [(ROOT_INO, "", 0)]
        seen = {ROOT_INO}
        yielded = 0
        while stack:
            ino, path, depth = stack.pop()
            for name, child, dtype in sorted(self._tree.get(ino, [])):
                child_path = f"{path}/{name}"
                kind = self._kind(child, dtype)
                if kind == "directory":
                    if child in seen:
                        self.warnings.append(f"{child_path}: directory loop, not followed")
                        continue
                    if depth + 1 > MAX_DEPTH:
                        self.warnings.append(f"{child_path}: deeper than {MAX_DEPTH}")
                        continue
                    seen.add(child)
                    stack.append((child, child_path, depth + 1))
                    continue
                if yielded >= MAX_ENTRIES:
                    self.warnings.append(f"stopped after {MAX_ENTRIES} entries")
                    return
                latest = self._latest(child)
                yielded += 1
                yield child_path, {"ino": child, "type": kind,
                                   "size": latest["isize"] if latest else 0}

    def files(self):
        """{path: node} for every regular file."""
        return {path: node for path, node in self.walk()
                if node["type"] == "file"}

    def read_file(self, node):
        """A file's contents, rebuilt from every node that wrote part of it.

        Oldest version first, so where two nodes cover the same bytes the newer
        one is what remains - the same order the filesystem itself applies.
        """
        size = node["size"]
        if size > MAX_FILE_BYTES:
            raise JFFS2Error(f"file claims {size} bytes; refusing")
        out = bytearray(size)
        for piece in sorted(self._inodes.get(node["ino"], []),
                            key=lambda n: n["version"]):
            if not piece["dsize"]:
                continue
            payload = self.data[piece["data_at"]:piece["data_at"] + piece["csize"]]
            try:
                chunk = _decompress(piece["compr"], payload, piece["dsize"])
            except (JFFS2Error, zlib.error, lzma.LZMAError, ValueError) as e:
                raise JFFS2Error(f"inode {node['ino']} v{piece['version']}: {e}")
            start = piece["offset"]
            if start >= size:
                continue
            chunk = chunk[:size - start]
            out[start:start + len(chunk)] = chunk
        return bytes(out)


def find_offsets(data, start=0):
    """Where JFFS2 node streams begin: the first valid node after a gap.

    There is no superblock, so a stream is recognised by a node whose header
    CRC checks - and only the first of a contiguous run is returned, since the
    reader walks the rest itself.
    """
    found, at = [], start
    while True:
        best = -1
        for magic in MAGIC_BYTES:
            hit = data.find(magic, at)
            while hit != -1 and hit % 4:
                hit = data.find(magic, hit + 1)
            if hit != -1 and (best == -1 or hit < best):
                best = hit
        if best == -1:
            return found
        order = MAGIC_BYTES[data[best:best + 2]]
        if best + NODE_HEADER <= len(data):
            _m, _t, totlen, hdr_crc = struct.unpack_from(order + "HHII", data, best)
            if totlen >= NODE_HEADER and kernel_crc32(data[best:best + 8]) == hdr_crc:
                found.append(best)
                try:
                    image = JFFS2(data, best)
                    at = max(best + 4, image.last_node_end)
                    continue
                except JFFS2Error:
                    pass
        at = best + 4
