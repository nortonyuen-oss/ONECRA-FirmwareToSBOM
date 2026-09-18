#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ubifs - read-only UBIFS reader.

UBIFS is the filesystem that lives inside a UBI volume on NAND flash: the
writable overlay on an OpenWrt NAND router, the application and configuration
volumes on a great many cameras. Like JFFS2 it is written as a stream of
nodes, but unlike JFFS2 it keeps an index - a B+ tree rooted in the master
node - and the index is what says which nodes are the filesystem.

That decides how this reader works: it walks the index rather than scanning
every node. A scan sees every version of every node ever written, including
files that have since been deleted; the index sees only what the filesystem
held at its last commit. Resurrecting deleted binaries into an SBOM is wrong
in a way nobody downstream can detect, and walking the index makes it
impossible rather than something to be guarded against.

The price is stated rather than hidden: changes written after the last commit
live in the journal and are not replayed here. An image made by mkfs.ubifs -
which is what a firmware release contains - has no journal to replay; a dump
taken from a running device may, and anything written since its last commit
will not be seen.

Compression is per data node:

  * none, LZO (through lzo.py) and zlib are read;
  * zstd is read when the Python running this provides it (3.14 and later do)
    and otherwise reported as unreadable - never skipped silently. No sample
    holds zstd-compressed data (the "zstd" sample stores its tiny files
    uncompressed), so that path is exercised by a fixture, not a real image.

Every node's CRC is checked, and the index walk is bounded in depth and node
count, because the input is whatever a customer uploaded.

Verified against the UBIFS samples published by the unblob project (MIT) -
three raw UBIFS images and the UBIFS volumes inside two UBI images - including
706 LZO-compressed data nodes from a real toolchain, each of which decodes to
exactly its declared size.
"""

import struct
import zlib

try:                                       # pure Python, shipped alongside
    import lzo
except ImportError:                        # pragma: no cover - always shipped
    lzo = None

try:                                       # Python 3.14 and later
    from compression import zstd as _zstd
except ImportError:
    _zstd = None

# What a decoder raises on bad input - and nothing else, so a genuine bug is
# not reported to a customer as "this block could not be decompressed".
DECODE_ERRORS = ((zlib.error, ValueError)
                 + ((lzo.LZOError,) if lzo is not None else ())
                 + ((_zstd.ZstdError,) if _zstd is not None else ()))

MAGIC = 0x06101831
MAGIC_BYTES = struct.pack("<I", MAGIC)
COMMON_HEADER = 24
BLOCK_SIZE = 4096

INO_NODE, DATA_NODE, DENT_NODE, XENT_NODE = 0, 1, 2, 3
SB_NODE, MST_NODE, IDX_NODE = 6, 7, 9
NODE_NAMES = {0: "inode", 1: "data", 2: "dentry", 3: "xattr entry",
              4: "truncation", 5: "padding", 6: "superblock", 7: "master",
              8: "reference", 9: "index", 10: "commit start", 11: "orphan"}

COMPR_NONE, COMPR_LZO, COMPR_ZLIB, COMPR_ZSTD = 0, 1, 2, 3
COMPRESSORS = {0: "none", 1: "LZO", 2: "zlib", 3: "zstd"}

ITYPE_REG, ITYPE_DIR, ITYPE_LNK = 0, 1, 2
S_IFMT, S_IFDIR, S_IFREG, S_IFLNK = 0o170000, 0o040000, 0o100000, 0o120000
ROOT_INO = 1
SIMPLE_KEY_FORMAT = 0
KEY_LEN = 8
BRANCH_SIZE = 12 + KEY_LEN

# Hostile-input caps.
MAX_INDEX_NODES = 200000
MAX_INDEX_DEPTH = 64
MAX_ENTRIES = 20000
MAX_DEPTH = 32
MAX_FILE_BYTES = 64 * 1024 * 1024


class UBIFSError(Exception):
    pass


def ubifs_crc32(data):
    """The same CRC UBI uses: seeded with 0xFFFFFFFF, no final inversion."""
    return (~zlib.crc32(data, 0)) & 0xFFFFFFFF


def _decompress(compr, payload, size):
    if compr == COMPR_NONE:
        return payload[:size]
    if compr == COMPR_ZLIB:
        return zlib.decompress(payload, -15)[:size]     # raw deflate
    if compr == COMPR_LZO:
        if lzo is None:
            raise UBIFSError("LZO support is missing from this installation")
        return lzo.decompress(payload, size)
    if compr == COMPR_ZSTD:
        if _zstd is None:
            raise UBIFSError("zstd-compressed data cannot be read by this "
                             "Python; it needs 3.14 or later")
        return _zstd.decompress(payload)[:size]
    raise UBIFSError(f"unknown compression type {compr}")


class UBIFS:
    """A UBIFS image - one UBI volume's bytes. Same surface as the others."""

    byte_order = "little-endian"

    def __init__(self, data, offset=0):
        self.data = data
        self.offset = offset
        self.warnings = []
        self.unreadable = {}              # path -> reason, for the report

        header = self._node(0, 0, expect=SB_NODE)
        body = self.offset + COMMON_HEADER
        key_hash, key_format, _flags, min_io, leb_size, leb_count = \
            struct.unpack_from("<BBIIII", data, body + 2)
        fmt_version, default_compr = struct.unpack_from("<IH", data, body + 56)
        if key_format != SIMPLE_KEY_FORMAT:
            raise UBIFSError(f"key format {key_format} is not the simple format")
        if not 4096 <= leb_size <= 4 * 1024 * 1024:
            raise UBIFSError(f"implausible LEB size {leb_size}")
        self.leb_size = leb_size
        self.leb_count = leb_count
        self.min_io_size = min_io
        self.format_version = fmt_version
        self.default_compressor = COMPRESSORS.get(default_compr,
                                                  f"type {default_compr}")
        self.sqnum = header["sqnum"]

        present = (len(data) - offset) // leb_size
        if present < leb_count:
            self.warnings.append(
                f"the filesystem spans {leb_count} logical blocks and this image "
                f"holds {present}; whatever the rest held is not read")

        master = self._master()
        root_lnum, root_offs, _root_len = struct.unpack_from(
            "<III", data, master + 48)
        self.inodes = {}                  # inum -> inode record
        self.dentries = {}                # parent inum -> [(name, inum, type)]
        self.blocks = {}                  # inum -> {block: (compr, size, at, len)}
        self._walk_index(root_lnum, root_offs)
        if ROOT_INO not in self.inodes:
            # Without the index there is no telling which nodes are the
            # filesystem and which are old versions or deleted files, so no
            # attempt is made to rebuild one from a scan. Say precisely why.
            if root_lnum >= present:
                raise UBIFSError(
                    f"the index root is in logical block {root_lnum}, and this "
                    f"image holds only blocks 0-{present - 1} of {leb_count} - "
                    "it looks truncated, and without the index the files "
                    "cannot be listed")
            raise UBIFSError("the index has no root directory"
                             + (f" ({self.warnings[-1]})" if self.warnings else ""))

    # --- nodes ------------------------------------------------------------- #

    def _node(self, lnum, offs, expect=None):
        """The common header of the node at (lnum, offs), CRC checked."""
        at = self.offset + lnum * getattr(self, "leb_size", 0) + offs
        if at + COMMON_HEADER > len(self.data):
            raise UBIFSError(f"node at LEB {lnum} offset {offs} lies past the image")
        magic, crc, sqnum, length, node_type = struct.unpack_from(
            "<IIQIB", self.data, at)
        if magic != MAGIC:
            raise UBIFSError(f"no node at LEB {lnum} offset {offs}")
        if length < COMMON_HEADER or at + length > len(self.data):
            raise UBIFSError(f"node at LEB {lnum} offset {offs} runs past the image")
        if ubifs_crc32(self.data[at + 8:at + length]) != crc:
            raise UBIFSError(f"node at LEB {lnum} offset {offs} fails its CRC")
        if expect is not None and node_type != expect:
            raise UBIFSError(f"expected a {NODE_NAMES.get(expect)} node at LEB "
                             f"{lnum} offset {offs}, found "
                             f"{NODE_NAMES.get(node_type, node_type)}")
        return {"at": at, "length": length, "type": node_type, "sqnum": sqnum}

    def _master(self):
        """The newest valid master node. There are two copies, in LEBs 1 and
        2, and each LEB holds a run of them; the highest sequence number is
        the current one."""
        best = None
        for lnum in (1, 2):
            start = self.offset + lnum * self.leb_size
            end = min(len(self.data), start + self.leb_size)
            at = start
            while at + COMMON_HEADER <= end:
                found = self.data.find(MAGIC_BYTES, at, end)
                if found == -1:
                    break
                try:
                    node = self._node(lnum, found - start)
                except UBIFSError:
                    at = found + 8
                    continue
                if node["type"] == MST_NODE and (best is None
                                                 or node["sqnum"] > best["sqnum"]):
                    best = node
                at = found + max(8, (node["length"] + 7) & ~7)
        if best is None:
            raise UBIFSError("no valid master node")
        return best["at"]

    def _walk_index(self, lnum, offs):
        """Every leaf the index points at. Iterative, bounded, loop-safe."""
        stack = [(lnum, offs, 0)]
        seen = set()
        visited = 0
        while stack:
            lnum, offs, depth = stack.pop()
            if (lnum, offs) in seen or depth > MAX_INDEX_DEPTH:
                continue
            seen.add((lnum, offs))
            visited += 1
            if visited > MAX_INDEX_NODES:
                self.warnings.append("stopped walking the index at the node limit")
                return
            try:
                node = self._node(lnum, offs)
            except UBIFSError as e:
                # A truncated dump loses whatever the missing blocks held; the
                # rest of the tree is still worth reading.
                self.warnings.append(str(e))
                continue
            at = node["at"]
            if node["type"] == IDX_NODE:
                child_count, _level = struct.unpack_from("<HH", self.data,
                                                         at + COMMON_HEADER)
                for index in range(child_count):
                    branch = at + COMMON_HEADER + 4 + index * BRANCH_SIZE
                    if branch + 12 > at + node["length"]:
                        break
                    child_lnum, child_offs, _len = struct.unpack_from(
                        "<III", self.data, branch)
                    stack.append((child_lnum, child_offs, depth + 1))
            elif node["type"] == INO_NODE:
                self._read_inode(at)
            elif node["type"] == DENT_NODE:
                self._read_dentry(at, node["length"])
            elif node["type"] == DATA_NODE:
                self._read_data(at, node["length"])

    def _read_inode(self, at):
        inum, = struct.unpack_from("<I", self.data, at + 24)
        size, = struct.unpack_from("<Q", self.data, at + 48)
        nlink, _uid, _gid, mode = struct.unpack_from("<IIII", self.data, at + 92)
        self.inodes[inum] = {"size": size, "nlink": nlink, "mode": mode}

    def _read_dentry(self, at, length):
        parent, = struct.unpack_from("<I", self.data, at + 24)
        inum, = struct.unpack_from("<Q", self.data, at + 40)
        itype = self.data[at + 49]
        name_len, = struct.unpack_from("<H", self.data, at + 50)
        if 56 + name_len > length:
            return
        name = self.data[at + 56:at + 56 + name_len].decode("utf-8", "replace")
        if not name or "/" in name or name in (".", ".."):
            return
        self.dentries.setdefault(parent, []).append((name, inum, itype))

    def _read_data(self, at, length):
        inum, block = struct.unpack_from("<II", self.data, at + 24)
        size, compr, _compr_size = struct.unpack_from("<IHH", self.data, at + 40)
        self.blocks.setdefault(inum, {})[block & 0x1FFFFFFF] = (
            compr, size, at + 48, length - 48)

    # --- the tree ---------------------------------------------------------- #

    def _kind(self, inum, itype):
        mode = (self.inodes.get(inum) or {}).get("mode", 0) & S_IFMT
        if mode == S_IFDIR or itype == ITYPE_DIR:
            return "directory"
        if mode == S_IFLNK or itype == ITYPE_LNK:
            return "symlink"
        if mode == S_IFREG or itype == ITYPE_REG:
            return "file"
        return "other"

    def walk(self):
        """Yield (path, node) for every non-directory entry."""
        stack = [(ROOT_INO, "", 0)]
        seen = {ROOT_INO}
        yielded = 0
        while stack:
            inum, path, depth = stack.pop()
            for name, child, itype in sorted(self.dentries.get(inum, [])):
                child_path = f"{path}/{name}"
                kind = self._kind(child, itype)
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
                yielded += 1
                yield child_path, {"inum": child, "type": kind, "path": child_path,
                                   "size": (self.inodes.get(child) or {}).get("size", 0)}

    def files(self):
        """{path: node} for every regular file."""
        return {path: node for path, node in self.walk()
                if node["type"] == "file"}

    def read_file(self, node):
        """A file's contents from its 4 KiB data blocks. A block the index has
        no node for is a hole, and reads as zeros - as it does on the device."""
        size = node["size"]
        if size > MAX_FILE_BYTES:
            raise UBIFSError(f"file claims {size} bytes; refusing")
        out = bytearray(size)
        for block, (compr, plain, at, length) in sorted(
                self.blocks.get(node["inum"], {}).items()):
            start = block * BLOCK_SIZE
            if start >= size:
                continue
            payload = self.data[at:at + length]
            try:
                chunk = _decompress(compr, payload, plain)
            except UBIFSError as e:
                reason = str(e)
            except DECODE_ERRORS as e:
                reason = f"block {block} did not decompress ({COMPRESSORS.get(compr, compr)}): {e}"
            else:
                reason = None
            if reason:
                # Recorded by path, so the report can say which files went
                # unread and why - never a smaller list presented as complete.
                self.unreadable[node.get("path", f"inode {node['inum']}")] = reason
                raise UBIFSError(reason)
            chunk = chunk[:size - start]
            out[start:start + len(chunk)] = chunk
        return bytes(out)


def find_offsets(data, start=0):
    """Where a raw UBIFS image begins: a valid superblock node at LEB 0."""
    found, at = [], start
    while True:
        at = data.find(MAGIC_BYTES, at)
        if at == -1:
            return found
        if at + COMMON_HEADER + 40 <= len(data) and data[at + 20] == SB_NODE:
            try:
                UBIFS(data, at)
                found.append(at)
            except UBIFSError:
                pass
        at += 8
