#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ext - read-only ext2 / ext3 / ext4 reader.

ext4 is the root filesystem wherever firmware lives on a block device rather
than raw flash: eMMC-based NVRs and gateways, x86 appliances, OpenWrt's x86
images, most Linux systems on SD cards. ext2 and ext3 turn up in older and
simpler devices. They share one on-disk layout, and one reader covers all
three:

  * **Block maps and extents.** ext2/3 locate a file's data with direct and
    indirect block pointers; ext4 with extent trees. A file carries one or
    the other, marked in its inode, and both are read. Holes and
    uninitialised extents read as zeros, as they do on the device.
  * **Directories** are walked entry by entry. An htree-indexed directory
    keeps its ordinary entries in the same blocks, with the index hidden in
    entries a linear walk skips - so a linear walk lists it completely.
  * **Symlinks** stored inside the inode ("fast" symlinks) and in a block.
  * **Inline data** - a small file kept in the inode itself - is read.

What is not read, and said so rather than guessed at:

  * **Encrypted files** (fscrypt). Their names and contents are ciphertext;
    each is reported as unreadable, which the SBOM records as such.
  * **The journal is not replayed.** A filesystem marked as needing recovery
    was not cleanly unmounted - a dump taken from a running device - and
    whatever was in flight is not seen. The reader says so.

Every block number is checked against the image, and walks are bounded,
because the input is whatever a customer uploaded.

Verified against the ext2/3/4 samples published by the unblob project (MIT),
in 1, 2 and 4 KiB block sizes, and an OpenWrt 23.05.5 x86-64 release rootfs.
"""

import struct

SUPERBLOCK_OFFSET = 1024
MAGIC = 0xEF53

INCOMPAT_FILETYPE = 0x2
INCOMPAT_RECOVER = 0x4
INCOMPAT_META_BG = 0x10
INCOMPAT_EXTENTS = 0x40
INCOMPAT_64BIT = 0x80
INCOMPAT_INLINE_DATA = 0x8000
INCOMPAT_ENCRYPT = 0x10000
# Features whose absence of support would make us read the wrong bytes.
INCOMPAT_UNDERSTOOD = (0x2 | 0x4 | 0x8 | 0x10 | 0x40 | 0x80 | 0x200 | 0x400
                       | 0x1000 | 0x2000 | 0x4000 | 0x8000 | 0x10000 | 0x20000)
INCOMPAT_NAMES = {0x1: "compression", 0x1000: "dirdata"}

INODE_FLAG_ENCRYPT = 0x800
INODE_FLAG_EXTENTS = 0x80000
INODE_FLAG_INLINE_DATA = 0x10000000

S_IFMT, S_IFDIR, S_IFREG, S_IFLNK = 0o170000, 0o040000, 0o100000, 0o120000
ROOT_INODE = 2
EXTENT_MAGIC = 0xF30A
XATTR_MAGIC = 0xEA020000

# Hostile-input caps.
MAX_ENTRIES = 50000
MAX_DEPTH = 32
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_DIR_BYTES = 16 * 1024 * 1024
MAX_EXTENT_DEPTH = 5


class ExtError(Exception):
    pass


class Ext:
    """An ext2/3/4 filesystem at `offset`. Same surface as the others."""

    byte_order = "little-endian"

    def __init__(self, data, offset=0):
        self.data = data
        self.offset = offset
        self.warnings = []
        sb_at = offset + SUPERBLOCK_OFFSET
        if sb_at + 1024 > len(data):
            raise ExtError("too short for an ext superblock")
        sb = data[sb_at:sb_at + 1024]
        if struct.unpack_from("<H", sb, 56)[0] != MAGIC:
            raise ExtError("no ext superblock magic")

        (self.inodes_count, blocks_lo, _r, _free_b, _free_i, self.first_data_block,
         log_block) = struct.unpack_from("<IIIIIII", sb, 0)
        if log_block > 6:
            raise ExtError(f"implausible block size 1024 << {log_block}")
        self.block_size = 1024 << log_block
        self.blocks_per_group, = struct.unpack_from("<I", sb, 32)
        self.inodes_per_group, = struct.unpack_from("<I", sb, 40)
        self.state, = struct.unpack_from("<H", sb, 58)
        rev, = struct.unpack_from("<I", sb, 76)
        self.inode_size = struct.unpack_from("<H", sb, 88)[0] if rev >= 1 else 128
        compat, self.incompat, self.ro_compat = struct.unpack_from("<III", sb, 92)
        self.volume_name = sb[120:136].split(b"\0")[0].decode("utf-8", "replace")
        blocks_hi = 0
        self.desc_size = 32
        if self.incompat & INCOMPAT_64BIT:
            self.desc_size = struct.unpack_from("<H", sb, 254)[0] or 64
            blocks_hi, = struct.unpack_from("<I", sb, 0x150)
        self.blocks_count = blocks_lo | (blocks_hi << 32)

        if not (self.inodes_per_group and self.blocks_per_group
                and 128 <= self.inode_size <= self.block_size
                and 32 <= self.desc_size <= 1024
                and self.inodes_count):
            raise ExtError("superblock geometry is not plausible")
        unknown = self.incompat & ~INCOMPAT_UNDERSTOOD
        if unknown:
            names = [INCOMPAT_NAMES.get(1 << bit, hex(1 << bit))
                     for bit in range(32) if unknown & (1 << bit)]
            raise ExtError(f"uses features this reader does not understand: "
                           f"{', '.join(names)}")

        self.version = ("ext4" if self.incompat & (INCOMPAT_EXTENTS | INCOMPAT_64BIT
                                                    | INCOMPAT_INLINE_DATA)
                        else "ext3" if compat & 0x4 else "ext2")   # has_journal
        self.size = self.blocks_count * self.block_size
        if offset + self.size > len(data):
            self.warnings.append(
                f"the filesystem is {self.size} bytes and the image holds "
                f"{len(data) - offset} after it; blocks past the end read as missing")
        if self.incompat & INCOMPAT_RECOVER:
            self.warnings.append(
                "the journal needs recovery - this was not cleanly unmounted - "
                "and it is not replayed, so recent changes may not be seen")
        if self.incompat & INCOMPAT_META_BG:
            self.warnings.append("meta_bg group descriptors are read as a flat "
                                 "table; a very large filesystem may misread")
        self.group_count = -(-self.inodes_count // self.inodes_per_group)
        self._inode_tables = {}
        root = self.inode(ROOT_INODE)
        if root["mode"] & S_IFMT != S_IFDIR:
            raise ExtError("inode 2 is not a directory; not a readable ext root")
        self._files = None

    # --- blocks and inodes ------------------------------------------------- #

    def _block(self, number, count=1):
        if number == 0 or number + count > self.blocks_count:
            raise ExtError(f"block {number} lies outside the filesystem")
        at = self.offset + number * self.block_size
        end = at + count * self.block_size
        if end > len(self.data):
            raise ExtError(f"block {number} lies past the end of the image")
        return self.data[at:end]

    def _inode_table(self, group):
        if group not in self._inode_tables:
            if group >= self.group_count:
                raise ExtError(f"group {group} does not exist")
            table_block = self.first_data_block + 1
            at = (self.offset + table_block * self.block_size
                  + group * self.desc_size)
            if at + self.desc_size > len(self.data):
                raise ExtError(f"group descriptor {group} lies past the image")
            lo, = struct.unpack_from("<I", self.data, at + 8)
            hi = (struct.unpack_from("<I", self.data, at + 0x28)[0]
                  if self.desc_size >= 64 else 0)
            self._inode_tables[group] = lo | (hi << 32)
        return self._inode_tables[group]

    def inode(self, number):
        if not 1 <= number <= self.inodes_count:
            raise ExtError(f"inode {number} does not exist")
        group, index = divmod(number - 1, self.inodes_per_group)
        at = (self.offset + self._inode_table(group) * self.block_size
              + index * self.inode_size)
        if at + 128 > len(self.data):
            raise ExtError(f"inode {number} lies past the end of the image")
        raw = self.data[at:at + self.inode_size]
        mode, = struct.unpack_from("<H", raw, 0)
        size_lo, = struct.unpack_from("<I", raw, 4)
        links, = struct.unpack_from("<H", raw, 26)
        blocks_lo, flags = struct.unpack_from("<II", raw, 28)
        size_hi, = struct.unpack_from("<I", raw, 108)
        return {"number": number, "mode": mode, "size": size_lo | (size_hi << 32),
                "links": links, "blocks": blocks_lo, "flags": flags,
                "block": raw[40:100], "raw": raw}

    def _extent_blocks(self, node, depth=0):
        """(logical, physical, length, initialised) runs of an extent tree."""
        magic, entries, _max, tree_depth = struct.unpack_from("<HHHH", node, 0)
        if magic != EXTENT_MAGIC:
            raise ExtError("extent tree is damaged")
        if depth > MAX_EXTENT_DEPTH or entries > (len(node) - 12) // 12:
            raise ExtError("extent tree is implausibly deep or wide")
        for i in range(entries):
            at = 12 + i * 12
            if tree_depth == 0:
                logical, length, start_hi, start_lo = struct.unpack_from(
                    "<IHHI", node, at)
                initialised = length <= 32768
                if not initialised:
                    length -= 32768
                yield logical, start_lo | (start_hi << 32), length, initialised
            else:
                _logical, leaf_lo, leaf_hi = struct.unpack_from("<IIH", node, at)
                child = self._block(leaf_lo | (leaf_hi << 32))
                yield from self._extent_blocks(child, depth + 1)

    def _mapped_blocks(self, inode, count):
        """Block-map (ext2/3) pointers for the first `count` logical blocks."""
        per = self.block_size // 4
        pointers = list(struct.unpack_from("<15I", inode["block"], 0))
        out = pointers[:12]

        def expand(block, level):
            if len(out) >= count:
                return
            if block == 0:
                out.extend([0] * min(count - len(out), per ** level))
                return
            entries = struct.unpack_from(f"<{per}I", self._block(block), 0)
            for entry in entries:
                if len(out) >= count:
                    return
                if level == 1:
                    out.append(entry)
                else:
                    expand(entry, level - 1)

        for level, block in ((1, pointers[12]), (2, pointers[13]), (3, pointers[14])):
            expand(block, level)
        return out[:count]

    def _inline(self, inode):
        """Inline data: i_block, then the rest in the system.data xattr."""
        body = inode["block"]
        raw = inode["raw"]
        if len(raw) > 132:
            extra, = struct.unpack_from("<H", raw, 128)
            at = 128 + extra
            if at + 4 <= len(raw) and struct.unpack_from("<I", raw, at)[0] == XATTR_MAGIC:
                first = at + 4
                entry = first
                while entry + 16 <= len(raw) and raw[entry:entry + 4] != b"\0\0\0\0":
                    name_len, index, value_offs = struct.unpack_from("<BBH", raw, entry)
                    value_size, = struct.unpack_from("<I", raw, entry + 8)
                    name = raw[entry + 16:entry + 16 + name_len]
                    if index == 7 and name == b"data":
                        body += raw[first + value_offs:first + value_offs + value_size]
                    entry += (16 + name_len + 3) & ~3
        return body[:inode["size"]]

    def _content(self, inode, limit):
        size = inode["size"]
        if size > limit:
            raise ExtError(f"file claims {size} bytes; refusing")
        if inode["flags"] & INODE_FLAG_ENCRYPT:
            raise ExtError("the file is encrypted (fscrypt); its contents cannot "
                           "be read without the device's key")
        if inode["flags"] & INODE_FLAG_INLINE_DATA:
            return self._inline(inode)
        bs = self.block_size
        count = -(-size // bs)
        out = bytearray(size)
        if inode["flags"] & INODE_FLAG_EXTENTS:
            for logical, physical, length, initialised in self._extent_blocks(
                    inode["block"]):
                if not initialised or logical >= count:
                    continue
                length = min(length, count - logical)
                chunk = self._block(physical, length)
                start = logical * bs
                out[start:start + len(chunk)] = chunk[:size - start]
        else:
            for logical, block in enumerate(self._mapped_blocks(inode, count)):
                if block:
                    start = logical * bs
                    out[start:start + bs] = self._block(block)[:size - start]
        return bytes(out)

    def _symlink_target(self, inode):
        # A fast symlink keeps its target in i_block; it has no data blocks
        # and is not extent-mapped. (An xattr block can make i_blocks nonzero,
        # so size decides, not i_blocks alone.)
        if (inode["size"] < 60 and not inode["flags"] & INODE_FLAG_EXTENTS
                and not inode["flags"] & INODE_FLAG_INLINE_DATA):
            raw = inode["block"][:inode["size"]]
        else:
            # A target is at most a block long; a damaged size field that
            # claims gigabytes still has only its first block read.
            first = dict(inode, size=min(inode["size"], self.block_size))
            raw = self._content(first, self.block_size)
        return raw.split(b"\0")[0].decode("utf-8", "replace")

    # --- directories ------------------------------------------------------- #

    def _entries(self, inode):
        blob = self._content(inode, MAX_DIR_BYTES)
        filetype = self.incompat & INCOMPAT_FILETYPE
        if inode["flags"] & INODE_FLAG_INLINE_DATA:
            # Inline directory: the parent's inode number, then entries.
            blob = blob[4:]
        at = 0
        while at + 8 <= len(blob):
            number, rec_len = struct.unpack_from("<IH", blob, at)
            if filetype:
                name_len, kind = blob[at + 6], blob[at + 7]
            else:
                name_len, kind = struct.unpack_from("<H", blob, at + 6)[0], 0
            if rec_len < 8 or at + rec_len > len(blob):
                self.warnings.append(f"directory inode {inode['number']}: damaged "
                                     "entry; the rest of that block is skipped")
                at = (at // self.block_size + 1) * self.block_size
                continue
            if number and name_len:
                name = blob[at + 8:at + 8 + name_len].decode("utf-8", "replace")
                if name not in (".", "..") and "/" not in name:
                    yield name, number
            at += rec_len

    def walk(self):
        """Yield (path, node) for every non-directory entry."""
        if inode_flags_encrypted(self.inode(ROOT_INODE)):
            self.warnings.append("the root directory is encrypted; names cannot be read")
            return
        stack = [(ROOT_INODE, "", 0)]
        seen = {ROOT_INODE}
        yielded = 0
        while stack:
            number, path, depth = stack.pop()
            try:
                directory = self.inode(number)
                entries = sorted(self._entries(directory))
            except ExtError as e:
                self.warnings.append(f"{path or '/'}: {e}")
                continue
            for name, child in entries:
                child_path = f"{path}/{name}"
                try:
                    node = self.inode(child)
                except ExtError as e:
                    self.warnings.append(f"{child_path}: {e}")
                    continue
                kind = node["mode"] & S_IFMT
                if kind == S_IFDIR:
                    if child in seen:
                        continue
                    if depth + 1 > MAX_DEPTH:
                        self.warnings.append(f"{child_path}: deeper than {MAX_DEPTH}")
                        continue
                    if inode_flags_encrypted(node):
                        self.warnings.append(f"{child_path}: encrypted directory, "
                                             "not listed")
                        continue
                    seen.add(child)
                    stack.append((child, child_path, depth + 1))
                    continue
                if yielded >= MAX_ENTRIES:
                    self.warnings.append(f"stopped after {MAX_ENTRIES} entries")
                    return
                yielded += 1
                entry = {"inode": child, "path": child_path, "size": node["size"],
                         "type": ("file" if kind == S_IFREG
                                  else "symlink" if kind == S_IFLNK else "other")}
                if kind == S_IFLNK:
                    try:
                        entry["target"] = self._symlink_target(node)
                    except ExtError as e:
                        self.warnings.append(f"{child_path}: {e}")
                yield child_path, entry

    def files(self):
        """{path: node} for every regular file."""
        if self._files is None:
            self._files = {path: node for path, node in self.walk()
                           if node["type"] == "file"}
        return self._files

    def read_file(self, node):
        return self._content(self.inode(node["inode"]), MAX_FILE_BYTES)


def inode_flags_encrypted(inode):
    return bool(inode["flags"] & INODE_FLAG_ENCRYPT)


def find_offsets(data, alignment=512, limit=16):
    """Where ext filesystems begin: a superblock that opens, on a sector
    boundary. Two bytes of magic turn up by chance, so each is checked by
    opening it."""
    magic = struct.pack("<H", MAGIC)
    found, at = [], data.find(magic, SUPERBLOCK_OFFSET + 56)
    while at != -1 and len(found) < limit:
        start = at - 56 - SUPERBLOCK_OFFSET
        if start >= 0 and start % alignment == 0:
            try:
                image = Ext(data, start)
            except ExtError:
                pass
            else:
                found.append(start)
                at = data.find(magic, max(at + 2, start + min(image.size, len(data))))
                continue
        at = data.find(magic, at + 2)
    return found
