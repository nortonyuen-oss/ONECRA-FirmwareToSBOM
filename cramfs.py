#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cramfs - read-only CramFS reader.

CramFS is what a great many small Linux devices still use where a router would
use SquashFS: cameras, set-top boxes, older gateways, anything whose root
filesystem was fixed at build time and is small enough not to need SquashFS's
sophistication. The format is simple enough that this reader is a few hundred
lines, and the payoff is out of proportion to that: it presents the same
interface as `squashfs.SquashFS`, so everything downstream - package database
reading, ELF dependency analysis, per-file signature scanning - works on a
CramFS rootfs without another line of code.

Two details are worth stating because they are where a naive reader breaks:

  * **Both byte orders exist and the bitfields flip with them.** An inode packs
    mode/uid, size/gid and namelen/offset into three 32-bit words. Reading the
    words big-endian is not enough - the fields inside them sit at the other
    end too. A reader that byte-swaps the words but not the fields produces
    file sizes in the megabytes and name lengths of zero, which looks like a
    corrupt image rather than a bug.

  * **Lengths are in units, not bytes.** `namelen` counts 4-byte units and
    `offset` counts 4-byte units. Treating either as a byte count walks off
    into the middle of the image.

Verified against the CramFS samples published by the unblob project (MIT),
which carry the same content in both byte orders - so the two decoders are
checked against each other, not only against the specification.
"""

import struct
import zlib

MAGIC_LE = b"\x45\x3d\xcd\x28"          # 0x28cd3d45 stored little-endian
MAGIC_BE = b"\x28\xcd\x3d\x45"
SIGNATURE = b"Compressed ROMFS"
SUPERBLOCK_SIZE = 76
ROOT_INODE_OFFSET = 64
INODE_SIZE = 12
BLOCK_SIZE = 4096

S_IFMT = 0xF000
S_IFDIR = 0x4000
S_IFREG = 0x8000
S_IFLNK = 0xA000

# Hostile-input caps, matching the SquashFS reader's.
MAX_ENTRIES = 20000
MAX_DEPTH = 32
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_NAME = 255


class CramFSError(Exception):
    pass


class CramFS:
    """A CramFS image. Same surface as squashfs.SquashFS."""

    def __init__(self, data, offset=0):
        self.data = data
        self.offset = offset
        self.warnings = []

        head = data[offset:offset + SUPERBLOCK_SIZE]
        if len(head) < SUPERBLOCK_SIZE:
            raise CramFSError("truncated before the end of the superblock")
        if head[:4] == MAGIC_LE:
            self.endian = "<"
        elif head[:4] == MAGIC_BE:
            self.endian = ">"
        else:
            raise CramFSError("not a CramFS superblock")

        size, flags, _future = struct.unpack_from(self.endian + "III", head, 4)
        if head[16:32] != SIGNATURE + b"\x00" * (16 - len(SIGNATURE)) and \
                not head[16:32].startswith(SIGNATURE):
            raise CramFSError("superblock signature is not 'Compressed ROMFS'")

        crc, edition, blocks, files = struct.unpack_from(
            self.endian + "IIII", head, 32)
        if not 0 < size <= len(data) - offset:
            raise CramFSError(
                f"superblock claims {size} bytes, the image has "
                f"{len(data) - offset}")

        self.size = size
        self.flags = flags
        self.crc = crc
        self.edition = edition
        self.block_count = blocks
        self.file_count = files
        self.name = head[48:64].split(b"\x00")[0].decode("ascii", "replace")
        self.byte_order = "little-endian" if self.endian == "<" else "big-endian"
        self.root = self._inode(offset + ROOT_INODE_OFFSET)

    # --- structure --------------------------------------------------------- #

    def _inode(self, at):
        """One inode, with the bitfields unpacked for this byte order."""
        if at + INODE_SIZE > len(self.data):
            raise CramFSError(f"inode at 0x{at:x} runs past the image")
        first, second, third = struct.unpack_from(
            self.endian + "III", self.data, at)

        if self.endian == "<":
            mode, uid = first & 0xFFFF, first >> 16
            size, gid = second & 0xFFFFFF, second >> 24
            namelen, data_offset = third & 0x3F, third >> 6
        else:
            # The words are big-endian and so is the packing inside them.
            mode, uid = first >> 16, first & 0xFFFF
            size, gid = second >> 8, second & 0xFF
            namelen, data_offset = third >> 26, third & 0x03FFFFFF

        return {
            "at": at,
            "mode": mode,
            "uid": uid,
            "gid": gid,
            "size": size,
            # Both are counts of 4-byte units, not of bytes.
            "namelen": namelen * 4,
            "offset": data_offset * 4,
            "type": self._kind(mode),
        }

    @staticmethod
    def _kind(mode):
        kind = mode & S_IFMT
        if kind == S_IFDIR:
            return "directory"
        if kind == S_IFREG:
            return "file"
        if kind == S_IFLNK:
            return "symlink"
        return "other"

    def _name_of(self, node):
        at = node["at"] + INODE_SIZE
        raw = self.data[at:at + min(node["namelen"], MAX_NAME)]
        return raw.split(b"\x00")[0].decode("utf-8", "replace")

    def listdir(self, node):
        """Child inodes of a directory.

        A directory's `size` is the byte length of its entries, each of which
        is an inode immediately followed by its padded name.
        """
        if node["type"] != "directory":
            return []
        start = self.offset + node["offset"] if node["offset"] else node["offset"]
        start = node["offset"] + self.offset
        end = start + node["size"]
        if node["size"] == 0:
            return []
        if end > len(self.data):
            raise CramFSError(
                f"directory at 0x{start:x} claims {node['size']} bytes, "
                "which runs past the image")

        entries, at = [], start
        while at + INODE_SIZE <= end and len(entries) < MAX_ENTRIES:
            child = self._inode(at)
            if child["namelen"] == 0:
                raise CramFSError(f"zero-length name at 0x{at:x}")
            name = self._name_of(child)
            step = INODE_SIZE + child["namelen"]
            if name not in ("", ".", ".."):
                entries.append((name, child))
            at += step
        return entries

    # --- contents ---------------------------------------------------------- #

    def read_file(self, node):
        """The bytes of a regular file.

        Data is stored as 4 KiB blocks, each zlib-compressed. The block table
        holds the *end* offset of every block, so a block starts where the
        previous one ended and the first starts after the table.
        """
        if node["type"] != "file":
            return b""
        if node["size"] == 0:
            return b""
        if node["size"] > MAX_FILE_BYTES:
            raise CramFSError(f"file claims {node['size']} bytes; refusing")

        count = (node["size"] + BLOCK_SIZE - 1) // BLOCK_SIZE
        table_at = self.offset + node["offset"]
        if table_at + count * 4 > len(self.data):
            raise CramFSError("block table runs past the image")
        ends = struct.unpack_from(self.endian + f"{count}I", self.data, table_at)

        out = bytearray()
        start = table_at + count * 4
        for index, end in enumerate(ends):
            end = self.offset + end
            if not start <= end <= len(self.data):
                raise CramFSError(
                    f"block {index} ends at 0x{end:x}, outside the image")
            chunk = self.data[start:end]
            if chunk:
                try:
                    out += zlib.decompress(chunk)
                except zlib.error as e:
                    raise CramFSError(f"block {index} did not decompress: {e}")
            start = end
            if len(out) > MAX_FILE_BYTES:
                raise CramFSError("file expanded past the size limit")
        return bytes(out[:node["size"]])

    # --- traversal --------------------------------------------------------- #

    def walk(self):
        """Yield (path, inode) for every non-directory entry."""
        stack = [(self.root, "", 0)]
        seen = {self.root["at"]}
        yielded = 0

        while stack:
            node, path, depth = stack.pop()
            try:
                entries = self.listdir(node)
            except CramFSError as e:
                self.warnings.append(f"{path or '/'}: {e}")
                continue

            for name, child in entries:
                child_path = f"{path}/{name}"
                if yielded >= MAX_ENTRIES:
                    self.warnings.append(f"stopped after {MAX_ENTRIES} entries")
                    return
                if child["type"] == "directory":
                    # A crafted image can point a directory at an ancestor.
                    if child["at"] in seen:
                        self.warnings.append(
                            f"{child_path}: directory loop, not followed")
                        continue
                    if depth + 1 > MAX_DEPTH:
                        self.warnings.append(
                            f"{child_path}: deeper than {MAX_DEPTH}, not followed")
                        continue
                    seen.add(child["at"])
                    stack.append((child, child_path, depth + 1))
                else:
                    yielded += 1
                    yield child_path, child

    def files(self):
        """{path: inode} for every regular file."""
        return {path: node for path, node in self.walk()
                if node["type"] == "file"}


def find_offsets(data, start=0):
    """Offsets of every CramFS superblock, either byte order."""
    found = []
    for magic in (MAGIC_LE, MAGIC_BE):
        at = data.find(magic, start)
        while at != -1:
            # The signature 16 bytes in is what separates a superblock from
            # four bytes that happen to match.
            if data[at + 16:at + 16 + len(SIGNATURE)] == SIGNATURE:
                found.append(at)
            at = data.find(magic, at + 4)
    return sorted(found)
