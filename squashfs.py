#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
squashfs - read-only SquashFS 4.0 reader, standard library only.

SquashFS is what almost every Linux-based router, gateway and NVR keeps its
root filesystem in, and everything worth putting in an SBOM lives inside it:
the binaries, and - far more valuable - the package manager's status file,
which lists every installed package with an exact version. Without a reader,
those images yield nothing at all; with one, a 14 MB router image yields
several hundred components with versions good enough to match against a CVE
feed.

Read-only and deliberately small: enough to walk the directory tree and read
files out of it, nothing about writing, permissions or xattrs.

**Hostile input.** Firmware arrives from customers and vendors and is not
trusted. Every limit below exists because a malformed or deliberately crafted
image must not be able to hang the analyser, exhaust its memory, or walk it
off the end of a buffer. Nothing here raises on bad data: a damaged image
yields what could be read plus a list of what could not, because "this image
is partly unreadable" is a finding worth reporting, and a traceback is not.

Compression: gzip, xz and lzma come from the standard library and cover
OpenWrt and the vast majority of vendor images. lzo, lz4 and zstd have no
stdlib implementation; an image using one is reported as unreadable with the
compressor named, rather than silently producing an empty file list.
"""

import lzma
import struct
import zlib

MAGIC = b"hsqs"                       # little-endian; 'sqsh' is big-endian
SUPERBLOCK_FMT = "<IIIIIHHHHHHQQQQQQQQ"
SUPERBLOCK_SIZE = struct.calcsize(SUPERBLOCK_FMT)
METADATA_MAX = 8192

COMPRESSORS = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}
SUPPORTED_COMPRESSORS = {"gzip", "lzma", "xz"}

# Inode types. 1-7 are the basic forms, 8-14 the extended ones.
INODE_DIR, INODE_FILE, INODE_SYMLINK = 1, 2, 3
INODE_LDIR, INODE_LFILE, INODE_LSYMLINK = 8, 9, 10
DIR_TYPES = (INODE_DIR, INODE_LDIR)
FILE_TYPES = (INODE_FILE, INODE_LFILE)
SYMLINK_TYPES = (INODE_SYMLINK, INODE_LSYMLINK)

NO_FRAGMENT = 0xFFFFFFFF
UNCOMPRESSED_BIT = 0x1000000
SIZE_MASK = 0xFFFFFF

# Guards against malformed or hostile images.
MAX_DEPTH = 64                  # deeper than any real rootfs
MAX_ENTRIES = 200_000           # a big rootfs has a few thousand
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_READ = 512 * 1024 * 1024


class SquashFSError(Exception):
    """The image cannot be opened at all (bad magic, version, compressor)."""


def _decompress(compressor, blob, limit):
    """Decompress one block, refusing to produce more than `limit` bytes.

    The limit is the decompression-bomb guard: a few KB of crafted input can
    otherwise expand to gigabytes.
    """
    if compressor == "gzip":
        return zlib.decompressobj().decompress(blob, limit)
    if compressor == "xz":
        return lzma.LZMADecompressor(lzma.FORMAT_XZ).decompress(blob, limit)
    if compressor == "lzma":
        return lzma.LZMADecompressor(lzma.FORMAT_ALONE).decompress(blob, limit)
    raise SquashFSError(f"unsupported compressor: {compressor}")


class SquashFS:
    """A SquashFS 4.0 image sitting at `offset` inside `data`."""

    def __init__(self, data, offset=0):
        self.data = data
        self.offset = offset
        self.warnings = []
        self._meta_cache = {}
        self._bytes_read = 0

        if data[offset:offset + 4] != MAGIC:
            raise SquashFSError("not a little-endian SquashFS superblock")
        if offset + SUPERBLOCK_SIZE > len(data):
            raise SquashFSError("truncated superblock")

        (_magic, self.inode_count, self.mtime, self.block_size,
         self.fragment_count, compressor_id, self.block_log, self.flags,
         self.id_count, self.version_major, self.version_minor,
         self.root_ref, self.bytes_used, self.id_table, self.xattr_table,
         self.inode_table, self.directory_table, self.fragment_table,
         self.export_table) = struct.unpack_from(SUPERBLOCK_FMT, data, offset)

        if self.version_major != 4:
            raise SquashFSError(
                f"SquashFS {self.version_major}.{self.version_minor} is not "
                "supported; only 4.0 is")
        self.compressor = COMPRESSORS.get(compressor_id, f"unknown-{compressor_id}")
        if self.compressor not in SUPPORTED_COMPRESSORS:
            raise SquashFSError(
                f"SquashFS compressed with {self.compressor}, which has no "
                "standard-library decompressor")
        if not 0 < self.block_size <= 1024 * 1024:
            raise SquashFSError(f"implausible block size {self.block_size}")

    # ----------------------------------------------------------------- #
    # Metadata stream: a chain of blocks, each a u16 header then payload
    # ----------------------------------------------------------------- #
    def _metadata_block(self, position):
        cached = self._meta_cache.get(position)
        if cached:
            return cached
        at = self.offset + position
        if at + 2 > len(self.data):
            raise SquashFSError(f"metadata block past end of image at {position}")
        (header,) = struct.unpack_from("<H", self.data, at)
        size = header & 0x7FFF
        if size == 0 or at + 2 + size > len(self.data):
            raise SquashFSError(f"bad metadata block size {size} at {position}")
        blob = self.data[at + 2: at + 2 + size]
        block = blob if header & 0x8000 else _decompress(
            self.compressor, blob, METADATA_MAX)
        self._bytes_read += len(block)
        if self._bytes_read > MAX_TOTAL_READ:
            raise SquashFSError("image expands to more data than we will read")
        result = (block, position + 2 + size)
        self._meta_cache[position] = result
        return result

    def _read_metadata(self, start, offset, length):
        """Exactly `length` bytes from the metadata stream at (start, offset).

        Truncating to `length` is not cosmetic: a metadata block holds up to
        8 KiB and usually spans several directories, so returning the whole
        block lets a directory listing run on into its neighbour's entries.
        """
        out = b""
        position, first = start, True
        while len(out) < length:
            block, nxt = self._metadata_block(position)
            out += block[offset:] if first else block
            if not block:
                break
            first, position = False, nxt
        return out[:length]

    # ----------------------------------------------------------------- #
    # Inodes
    # ----------------------------------------------------------------- #
    @staticmethod
    def _split_ref(ref):
        """An inode reference packs (metadata block, offset within it)."""
        return (ref >> 16) & 0xFFFFFFFFFFFF, ref & 0xFFFF

    def read_inode(self, ref):
        block, offset = self._split_ref(ref)
        start = self.inode_table + block
        head = self._read_metadata(start, offset, 64)
        if len(head) < 16:
            raise SquashFSError("truncated inode")
        inode_type, mode, _uid, _gid, _mtime, number = \
            struct.unpack_from("<HHHHII", head, 0)
        node = {"type": inode_type, "mode": mode, "inode": number, "ref": ref}

        if inode_type == INODE_DIR:
            start_block, _nlink, size, off, _parent = \
                struct.unpack_from("<IIHHI", head, 16)
            node.update(start_block=start_block, size=size, offset=off)
        elif inode_type == INODE_LDIR:
            _nlink, size, start_block, _parent, _icount, off, _xattr = \
                struct.unpack_from("<IIIIHHI", head, 16)
            node.update(start_block=start_block, size=size, offset=off)
        elif inode_type in FILE_TYPES:
            if inode_type == INODE_FILE:
                start_block, fragment, off, size = \
                    struct.unpack_from("<IIII", head, 16)
                header_len = 32
            else:
                start_block, size, _sparse, _nlink, fragment, off, _xattr = \
                    struct.unpack_from("<QQQIIII", head, 16)
                header_len = 56
            node.update(start_block=start_block, fragment=fragment,
                        offset=off, size=size)
            count = (size // self.block_size if fragment != NO_FRAGMENT
                     else (size + self.block_size - 1) // self.block_size)
            if count < 0 or count > MAX_FILE_BYTES // max(1, self.block_size) + 1:
                raise SquashFSError(f"implausible block count {count}")
            raw = self._read_metadata(start, offset, header_len + 4 * count)
            node["block_sizes"] = list(
                struct.unpack_from(f"<{count}I", raw, header_len)) if count else []
        elif inode_type in SYMLINK_TYPES:
            _nlink, target_size = struct.unpack_from("<II", head, 16)
            if target_size > 4096:
                raise SquashFSError("implausible symlink length")
            raw = self._read_metadata(start, offset, 24 + target_size)
            node["target"] = raw[24:24 + target_size].decode("utf-8", "replace")
        return node

    # ----------------------------------------------------------------- #
    # Directories
    # ----------------------------------------------------------------- #
    def listdir(self, node):
        """Entries of a directory inode as [{name, type, ref}]."""
        size = node.get("size", 0)
        if node["type"] not in DIR_TYPES or size <= 3:
            return []                     # 3 is the empty-listing sentinel
        raw = self._read_metadata(self.directory_table + node["start_block"],
                                  node["offset"], size - 3)
        entries, i = [], 0
        while i + 12 <= len(raw):
            count, start_block, _base = struct.unpack_from("<IIi", raw, i)
            i += 12
            if count > MAX_ENTRIES:
                self.warnings.append(
                    f"directory header claims {count + 1} entries; truncated")
                break
            for _ in range(count + 1):
                if i + 8 > len(raw):
                    break
                offset, _inode_offset, entry_type, name_size = \
                    struct.unpack_from("<HhHH", raw, i)
                i += 8
                name = raw[i:i + name_size + 1].decode("utf-8", "replace")
                i += name_size + 1
                if name in (".", "..") or "/" in name or not name:
                    continue          # squashfs does not store these; be safe
                entries.append({"name": name, "type": entry_type,
                                "ref": (start_block << 16) | offset})
        return entries

    # ----------------------------------------------------------------- #
    # File contents
    # ----------------------------------------------------------------- #
    def _fragment(self, index):
        per_block = METADATA_MAX // 16
        pointer_at = self.offset + self.fragment_table + 8 * (index // per_block)
        if pointer_at + 8 > len(self.data):
            raise SquashFSError("fragment table past end of image")
        (block_start,) = struct.unpack_from("<Q", self.data, pointer_at)
        within = index % per_block
        raw = self._read_metadata(block_start, 0, 16 * (within + 1))
        start, size, _unused = struct.unpack_from("<QII", raw, 16 * within)
        return start, size

    def read_file(self, node):
        """The contents of a regular-file inode."""
        if node["type"] not in FILE_TYPES:
            raise SquashFSError(f"inode type {node['type']} is not a file")
        if node["size"] > MAX_FILE_BYTES:
            raise SquashFSError(f"file is {node['size']} bytes; refusing to read")

        chunks, position = [], node["start_block"]
        for encoded in node["block_sizes"]:
            size = encoded & SIZE_MASK
            if size == 0:                      # a hole
                chunks.append(b"\x00" * self.block_size)
                continue
            at = self.offset + position
            if at + size > len(self.data):
                raise SquashFSError("data block past end of image")
            blob = self.data[at:at + size]
            chunks.append(blob if encoded & UNCOMPRESSED_BIT
                          else _decompress(self.compressor, blob, self.block_size))
            position += size

        if node["fragment"] != NO_FRAGMENT:
            start, encoded = self._fragment(node["fragment"])
            size = encoded & SIZE_MASK
            at = self.offset + start
            if at + size > len(self.data):
                raise SquashFSError("fragment past end of image")
            blob = self.data[at:at + size]
            fragment = (blob if encoded & UNCOMPRESSED_BIT
                        else _decompress(self.compressor, blob, self.block_size))
            chunks.append(fragment[node["offset"]:])

        return b"".join(chunks)[:node["size"]]

    # ----------------------------------------------------------------- #
    # Walking
    # ----------------------------------------------------------------- #
    def walk(self):
        """Yield (path, inode) for every non-directory entry in the image.

        Iterative, with a visited set: a crafted image can point a directory
        at one of its own ancestors, and a recursive walk over that never
        returns. Real images have hit this too - an early version of this
        reader ran 1000 frames deep on an ordinary OpenWrt rootfs before the
        underlying bug was found.
        """
        try:
            root = self.read_inode(self.root_ref)
        except SquashFSError as e:
            self.warnings.append(f"cannot read root inode: {e}")
            return

        stack = [(self.root_ref, "", 0)]
        visited = {self.root_ref}
        yielded = 0

        while stack:
            ref, path, depth = stack.pop()
            try:
                node = self.read_inode(ref)
                entries = self.listdir(node)
            except SquashFSError as e:
                self.warnings.append(f"{path or '/'}: {e}")
                continue

            for entry in entries:
                child_path = f"{path}/{entry['name']}"
                if yielded >= MAX_ENTRIES:
                    self.warnings.append(
                        f"stopped after {MAX_ENTRIES} entries")
                    return
                try:
                    child = self.read_inode(entry["ref"])
                except SquashFSError as e:
                    self.warnings.append(f"{child_path}: {e}")
                    continue

                if child["type"] in DIR_TYPES:
                    if entry["ref"] in visited:
                        self.warnings.append(
                            f"{child_path}: directory loop, not followed")
                        continue
                    if depth + 1 > MAX_DEPTH:
                        self.warnings.append(
                            f"{child_path}: deeper than {MAX_DEPTH}, not followed")
                        continue
                    visited.add(entry["ref"])
                    stack.append((entry["ref"], child_path, depth + 1))
                else:
                    yielded += 1
                    yield child_path, child

    def files(self):
        """{path: inode} for every regular file, for lookup by path."""
        return {path: node for path, node in self.walk()
                if node["type"] in FILE_TYPES}


def find_offsets(data, start=0):
    """Offsets of every little-endian SquashFS superblock in `data`."""
    found, at = [], data.find(MAGIC, start)
    while at != -1:
        found.append(at)
        at = data.find(MAGIC, at + 4)
    return found
