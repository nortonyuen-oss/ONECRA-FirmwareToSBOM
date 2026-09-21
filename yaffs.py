#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
yaffs - read YAFFS2 (and YAFFS1) images, as written for raw NAND flash.

YAFFS predates UBI and is still found on older and simpler NAND devices:
cameras, DVRs, set-top boxes, early Android. An image is a dump of NAND
pages, each followed by its out-of-band "spare" area, and the spare holds the
tags that make it a filesystem: which object a page belongs to, which chunk
of it, how many bytes are used, and a sequence number saying which copy is
newest. Object headers - name, parent, mode, size, symlink target - are
pages of their own.

There is no superblock, and nothing in an image says what geometry it was
written with. The page size (512 to 16 KiB), the spare size (16 to 512
bytes), where the tags sit in the spare (at 0, or after a two-byte bad-block
marker), the byte order and the YAFFS version all vary with the flash chip
and the tool that built the image. So they are found by trying each
combination and keeping the one under which the image reads as a consistent
filesystem - never by assuming one.

Like JFFS2 it is a log, and the same rules apply:

  * **Newest wins.** A chunk written twice is resolved by sequence number
    (YAFFS2) or serial number (YAFFS1).
  * **Deleted objects are not listed.** An object moved into YAFFS's
    "unlinked" or "deleted" directory is gone from the device, and a YAFFS1
    chunk whose page status marks it deleted is ignored.

Verified against the YAFFS samples published by the unblob project (MIT): 72
YAFFS2 geometries (page 2-16 KiB, spare 16-512 bytes, both byte orders, tags
at 0 and 2), YAFFS1 in both byte orders, hard and soft links, and truncated
images.
"""

import struct

OBJ_FILE, OBJ_SYMLINK, OBJ_DIR, OBJ_HARDLINK, OBJ_SPECIAL = 1, 2, 3, 4, 5
OBJ_TYPES = {1: "file", 2: "symlink", 3: "directory", 4: "hardlink", 5: "other"}
ROOT_ID, UNLINKED_ID, DELETED_ID = 1, 3, 4
EXTRA_HEADER_FLAG = 0x80000000

HEADER_NAME, HEADER_MODE, HEADER_SIZE_LO = 10, 268, 292
HEADER_EQUIV, HEADER_ALIAS, HEADER_SIZE_HI = 296, 300, 496

PAGE_SIZES = (2048, 4096, 8192, 16384, 512, 1024)
SPARE_SIZES = (64, 16, 32, 128, 256, 512)
TAG_OFFSETS = (0, 2)

# Hostile-input caps.
MAX_OBJECTS = 50000
MAX_DEPTH = 32
MAX_FILE_BYTES = 64 * 1024 * 1024
PROBE_CHUNKS = 64


class YAFFSError(Exception):
    pass


def _popcount(value):
    return bin(value).count("1")


class _Geometry:
    def __init__(self, version, page, spare, tag_offset, order):
        self.version, self.page, self.spare = version, page, spare
        self.tag_offset, self.order = tag_offset, order
        self.chunk = page + spare

    def label(self):
        return (f"YAFFS{self.version}, {self.page}-byte pages + {self.spare}-byte "
                f"spare, tags at {self.tag_offset}, "
                f"{'big' if self.order == '>' else 'little'}-endian")

    def tags(self, data, at):
        """(seq, obj_id, chunk_id, n_bytes, deleted) for the chunk at `at`,
        or None if the tags are erased or absent."""
        spare = data[at + self.page:at + self.chunk]
        if self.version == 1:
            if len(spare) < 16:
                return None
            raw = spare[0:4] + spare[6:8] + spare[11:13]
            if raw == b"\xff" * 8:
                return None
            if self.order == "<":
                low, high = struct.unpack("<II", raw)
                chunk_id, serial, n_lsb = low & 0xFFFFF, (low >> 20) & 3, low >> 22
                obj_id, n_msb = high & 0x3FFFF, high >> 30
            else:
                low, high = struct.unpack(">II", raw)
                chunk_id, serial, n_lsb = low >> 12, (low >> 10) & 3, low & 0x3FF
                obj_id, n_msb = high >> 14, high & 3
            n_bytes = n_lsb | (n_msb << 10) if self.page > 1024 else n_lsb
            deleted = _popcount(spare[4]) < 6          # page status
            return serial, obj_id, chunk_id, n_bytes, deleted
        tag = spare[self.tag_offset:self.tag_offset + 16]
        if len(tag) < 12 or tag[:12] == b"\xff" * 12:
            return None
        seq, obj_id, chunk_id = struct.unpack_from(self.order + "III", tag, 0)
        if len(tag) == 16:
            n_bytes, = struct.unpack_from(self.order + "I", tag, 12)
        elif self.order == "<":
            n_bytes = int.from_bytes(tag[12:], "little")   # the low bytes survive
        else:
            n_bytes = None                                  # the high bytes did
        if seq in (0, 0xFFFFFFFF):
            return None
        return seq, obj_id, chunk_id, n_bytes, False


def _header(data, at, order):
    """An object header in the chunk data at `at`, or None if not one."""
    if at + 512 > len(data):
        return None
    kind, parent = struct.unpack_from(order + "II", data, at)
    if kind not in OBJ_TYPES or data[at + 8:at + 10] != b"\xff\xff":
        return None
    raw_name = data[at + HEADER_NAME:at + HEADER_NAME + 256].split(b"\0")[0]
    # Only the root directory has no name; YAFFS1 writes a header for it.
    if not raw_name and not (kind == OBJ_DIR and parent == ROOT_ID):
        return None
    if b"/" in raw_name or len(raw_name) > 255:
        return None
    mode, = struct.unpack_from(order + "I", data, at + HEADER_MODE)
    size_lo, = struct.unpack_from(order + "I", data, at + HEADER_SIZE_LO)
    equiv, = struct.unpack_from(order + "i", data, at + HEADER_EQUIV)
    size_hi, = struct.unpack_from(order + "I", data, at + HEADER_SIZE_HI)
    alias = data[at + HEADER_ALIAS:at + HEADER_ALIAS + 160].split(b"\0")[0]
    size = None
    if kind == OBJ_FILE and size_lo != 0xFFFFFFFF:
        size = size_lo | ((size_hi << 32) if size_hi != 0xFFFFFFFF else 0)
    return {"type": kind, "parent": parent,
            "name": raw_name.decode("utf-8", "replace"), "mode": mode,
            "size": size, "equiv": equiv,
            "alias": alias.decode("utf-8", "replace") if kind == OBJ_SYMLINK else None}


def _score(data, offset, geometry):
    """How many of the first chunks read as valid under a geometry."""
    good = 0
    for index in range(PROBE_CHUNKS):
        at = offset + index * geometry.chunk
        if at + geometry.chunk > len(data):
            break
        tags = geometry.tags(data, at)
        if tags is None:
            continue
        _seq, obj_id, chunk_id, n_bytes, _deleted = tags
        if geometry.version == 2 and chunk_id & EXTRA_HEADER_FLAG:
            chunk_id, obj_id = 0, obj_id & 0x0FFFFFFF
        if not 0 < obj_id < 0x40000:
            return 0
        if chunk_id == 0:
            if _header(data, at, geometry.order) is None:
                return 0
            good += 1
        elif n_bytes is not None and n_bytes > geometry.page:
            return 0
        else:
            good += 1
    return good


def detect_geometry(data, offset=0):
    """The geometry under which `data` at `offset` reads as YAFFS, or None.

    The first chunk of an image is an object header, so only geometries under
    which it parses as one are tried in full.
    """
    best, best_score = None, 0
    for order in ("<", ">"):
        head = _header(data, offset, order)
        if head is None:
            continue
        candidates = [_Geometry(1, 512, 16, 0, order)] + [
            _Geometry(2, page, spare, tag_offset, order)
            for page in PAGE_SIZES for spare in SPARE_SIZES
            for tag_offset in TAG_OFFSETS if spare >= tag_offset + 14]
        for geometry in candidates:
            score = _score(data, offset, geometry)
            if score > best_score:
                best, best_score = geometry, score
    return best if best_score >= 1 else None


class YAFFS:
    """A YAFFS image at `offset`. Same surface as the other readers."""

    def __init__(self, data, offset=0, geometry=None):
        self.data = data
        self.offset = offset
        self.warnings = []
        self.geometry = geometry or detect_geometry(data, offset)
        if self.geometry is None:
            raise YAFFSError("no YAFFS geometry reads this as a filesystem")
        self.byte_order = ("big-endian" if self.geometry.order == ">"
                           else "little-endian")
        self.objects = {}                   # obj_id -> header (newest)
        self.chunks = {}                    # obj_id -> {chunk_id: (key, at, n)}
        self._read()
        if not self.objects:
            raise YAFFSError("no object headers")
        self._files = None

    def _read(self):
        g, data = self.geometry, self.data
        count = (len(data) - self.offset) // g.chunk
        if (len(data) - self.offset) % g.chunk:
            self.warnings.append("the image ends part-way through a chunk; that "
                                 "chunk is not read")
        header_keys = {}
        self.end = self.offset
        for index in range(count):
            at = self.offset + index * g.chunk
            tags = g.tags(data, at)
            if tags is None:
                continue
            key, obj_id, chunk_id, n_bytes, deleted = tags
            if deleted:
                continue
            if g.version == 2 and chunk_id & EXTRA_HEADER_FLAG:
                chunk_id, obj_id = 0, obj_id & 0x0FFFFFFF
            if not 0 < obj_id < 0x40000:
                # Past the end of the filesystem, or not ours at all.
                break
            self.end = at + g.chunk
            # A later chunk in the image is newer at equal sequence numbers:
            # YAFFS writes a block front to back.
            order_key = (key, index) if g.version == 2 else (index,)
            if chunk_id == 0:
                header = _header(data, at, g.order)
                if header is None:
                    self.warnings.append(f"chunk {index}: object {obj_id} header "
                                         "does not parse")
                    continue
                if order_key >= header_keys.get(obj_id, (-1,)):
                    header_keys[obj_id] = order_key
                    self.objects[obj_id] = header
                    if len(self.objects) > MAX_OBJECTS:
                        raise YAFFSError("too many objects")
            else:
                slots = self.chunks.setdefault(obj_id, {})
                previous = slots.get(chunk_id)
                if previous is None or order_key >= previous[0]:
                    slots[chunk_id] = (order_key, at, n_bytes)

    def _path(self, obj_id):
        parts, seen = [], set()
        while obj_id != ROOT_ID:
            if obj_id in seen or len(parts) > MAX_DEPTH:
                return None
            seen.add(obj_id)
            header = self.objects.get(obj_id)
            if header is None or header["parent"] in (UNLINKED_ID, DELETED_ID):
                return None
            parent = header["parent"]
            # Every ancestor must be a directory. A damaged parent field can
            # point at a file, and a path through a file is not a path.
            if parent != ROOT_ID and self.objects.get(parent, {}).get("type") != OBJ_DIR:
                return None
            if not header["name"]:
                return None
            parts.append(header["name"])
            obj_id = parent
        return "/" + "/".join(reversed(parts))

    def walk(self):
        """Yield (path, node) for every non-directory object."""
        deleted = 0
        for obj_id in sorted(self.objects):
            header = self.objects[obj_id]
            if obj_id == ROOT_ID or header["type"] == OBJ_DIR:
                continue
            path = self._path(obj_id)
            if path is None:
                deleted += 1
                continue
            target = obj_id
            if header["type"] == OBJ_HARDLINK:
                target = header["equiv"]
                if self.objects.get(target, {}).get("type") != OBJ_FILE:
                    self.warnings.append(f"{path}: hard link to a missing object")
                    continue
            base = self.objects[target]
            node = {"id": target, "path": path, "type": OBJ_TYPES[base["type"]],
                    "size": self._size(target)}
            if base["type"] == OBJ_SYMLINK:
                node["target"] = base["alias"]
            yield path, node
        if deleted:
            self.warnings.append(f"{deleted} deleted or orphaned object(s) not listed")

    def _size(self, obj_id):
        header = self.objects[obj_id]
        if header["size"] is not None:
            return header["size"]
        slots = self.chunks.get(obj_id, {})
        if not slots:
            return 0
        last = max(slots)
        n = slots[last][2]
        return (last - 1) * self.geometry.page + (n if n is not None
                                                   else self.geometry.page)

    def files(self):
        if self._files is None:
            self._files = {p: n for p, n in self.walk() if n["type"] == "file"}
        return self._files

    def read_file(self, node):
        size = node["size"]
        if size > MAX_FILE_BYTES:
            raise YAFFSError(f"file claims {size} bytes; refusing")
        page = self.geometry.page
        out = bytearray(size)
        for chunk_id, (_key, at, n_bytes) in self.chunks.get(node["id"], {}).items():
            start = (chunk_id - 1) * page
            if start >= size:
                continue
            length = min(page, size - start,
                         n_bytes if n_bytes is not None else page)
            out[start:start + length] = self.data[at:at + length]
        return bytes(out)


def find_offsets(data, alignment=512, limit=8):
    """Where YAFFS images begin: an object header on a page boundary whose
    geometry reads. The first object of an image sits in the root, so its
    parent is 1 - which is the pattern searched for."""
    found = []
    for pattern in (b"\x01\x00\x00\x00\xff\xff", b"\x00\x00\x00\x01\xff\xff"):
        at = data.find(pattern, 4)
        while at != -1 and len(found) < limit:
            start = at - 4
            if start % alignment == 0 and not any(s <= start < e for s, e in found):
                try:
                    image = YAFFS(data, start)
                except YAFFSError:
                    image = None
                if image is not None and len(image.objects) >= 1:
                    found.append((start, image.end))
                    at = data.find(pattern, image.end + 4)
                    continue
            at = data.find(pattern, at + 1)
    return sorted(start for start, _end in found)
