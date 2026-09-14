#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
elf - minimal read-only ELF reader, standard library only.

Reading the binaries inside a root filesystem answers three questions that
nothing else in fw2sbom can:

  * **What architecture is this?** A Linux firmware image has no vector table
    to recognise, so the instruction set was simply reported as "not
    identified". Every ELF header states it outright.

  * **What depends on what?** `DT_NEEDED` is the linker's own record of which
    libraries a binary needs. Resolved against the package database's file
    lists, it turns a flat list of packages into an actual dependency graph -
    structure no string scanner can produce.

  * **What is in an image with no package database?** Many vendor devices ship
    no opkg or dpkg records at all. There, `.comment` (the toolchain), the
    SONAME (a library's own name and version) and `.modinfo` (a kernel
    module's declared version and licence) are what is left.

Deliberately small: enough to read the header, the dynamic table and a handful
of named sections. No symbols, no relocations, no DWARF.

Like the SquashFS reader, this parses untrusted input and never raises on bad
data: a malformed or truncated ELF yields None, or a partial result with the
fields that could be read. Firmware from a customer must not be able to stop
an analysis with a traceback.
"""

import struct

MAGIC = b"\x7fELF"

ELFCLASS32, ELFCLASS64 = 1, 2
ELFDATA2LSB, ELFDATA2MSB = 1, 2

# e_type
ET_NAMES = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}

# e_machine - the ones that turn up in device firmware.
EM_NAMES = {
    2: "SPARC", 3: "x86", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64",
    40: "ARM", 42: "SuperH", 50: "IA-64", 62: "x86-64", 76: "CRIS",
    83: "AVR", 94: "Xtensa", 105: "MSP430", 106: "Blackfin",
    183: "AArch64", 189: "MicroBlaze", 220: "Z80", 243: "RISC-V",
    258: "LoongArch",
}

PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_NOTE = 1, 2, 3, 4
SHT_NOBITS = 8

DT_NULL, DT_NEEDED, DT_STRTAB, DT_STRSZ = 0, 1, 5, 10
DT_SONAME, DT_RPATH, DT_RUNPATH = 14, 15, 29

# Guards. A crafted header can claim millions of sections.
MAX_HEADERS = 4096
MAX_DYNAMIC = 8192
MAX_STRING = 4096
MAX_NEEDED = 256

INTERESTING_SECTIONS = (".comment", ".modinfo", ".note.gnu.build-id",
                        ".note.ABI-tag", ".gnu_debuglink")


def looks_like_elf(head):
    """Cheap test before committing to a full read."""
    return len(head) >= 20 and head[:4] == MAGIC and head[4] in (1, 2)


def _cstr(blob, offset, limit=MAX_STRING):
    if not 0 <= offset < len(blob):
        return None
    end = blob.find(b"\x00", offset, offset + limit)
    if end == -1:
        return None
    try:
        return blob[offset:end].decode("utf-8")
    except UnicodeDecodeError:
        return blob[offset:end].decode("latin-1")


class _Reader:
    """Endian- and width-aware struct access with bounds checking."""

    def __init__(self, data, is64, little):
        self.data = data
        self.is64 = is64
        self.e = "<" if little else ">"

    def u16(self, at):
        return struct.unpack_from(self.e + "H", self.data, at)[0]

    def u32(self, at):
        return struct.unpack_from(self.e + "I", self.data, at)[0]

    def addr(self, at):
        fmt = "Q" if self.is64 else "I"
        return struct.unpack_from(self.e + fmt, self.data, at)[0]

    def fits(self, at, size):
        return 0 <= at and size >= 0 and at + size <= len(self.data)


def parse(data, want_sections=True):
    """Read an ELF file. Returns a dict of what could be read, or None.

    `want_sections` reads .comment and friends, which needs the section header
    table; skipping it is a little cheaper when only the header and dynamic
    information are wanted.
    """
    if not looks_like_elf(data[:20]):
        return None
    elf_class, elf_data = data[4], data[5]
    is64 = elf_class == ELFCLASS64
    little = elf_data == ELFDATA2LSB
    if elf_class not in (ELFCLASS32, ELFCLASS64) or \
            elf_data not in (ELFDATA2LSB, ELFDATA2MSB):
        return None

    r = _Reader(data, is64, little)
    header_size = 64 if is64 else 52
    if len(data) < header_size:
        return None

    try:
        e_type = r.u16(16)
        e_machine = r.u16(18)
        if is64:
            e_phoff, e_shoff = r.addr(32), r.addr(40)
            e_phentsize, e_phnum = r.u16(54), r.u16(56)
            e_shentsize, e_shnum, e_shstrndx = r.u16(58), r.u16(60), r.u16(62)
        else:
            e_phoff, e_shoff = r.addr(28), r.addr(32)
            e_phentsize, e_phnum = r.u16(42), r.u16(44)
            e_shentsize, e_shnum, e_shstrndx = r.u16(46), r.u16(48), r.u16(50)
    except struct.error:
        return None

    info = {
        "class": 64 if is64 else 32,
        "endian": "little" if little else "big",
        "machine_id": e_machine,
        "machine": EM_NAMES.get(e_machine, f"machine-{e_machine}"),
        "type": ET_NAMES.get(e_type, f"type-{e_type}"),
        "soname": None,
        "needed": [],
        "runpath": None,
        "interpreter": None,
        "comment": None,
        "build_id": None,
        "modinfo": {},
        "warnings": [],
    }

    segments = _read_program_headers(r, e_phoff, e_phentsize, e_phnum, info)
    sections = (_read_sections(r, e_shoff, e_shentsize, e_shnum, e_shstrndx,
                               info) if want_sections else {})

    _read_dynamic(r, segments, sections, info)
    if sections:
        _read_named_sections(data, sections, info)
    return info


def _read_program_headers(r, offset, entsize, count, info):
    segments = []
    if not count or count > MAX_HEADERS or entsize < 8:
        return segments
    for i in range(count):
        at = offset + i * entsize
        if not r.fits(at, entsize):
            info["warnings"].append("program header table is truncated")
            break
        try:
            p_type = r.u32(at)
            if r.is64:
                p_offset, p_vaddr = r.addr(at + 8), r.addr(at + 16)
                p_filesz = r.addr(at + 32)
            else:
                p_offset, p_vaddr = r.addr(at + 4), r.addr(at + 8)
                p_filesz = r.addr(at + 16)
        except struct.error:
            break
        segments.append({"type": p_type, "offset": p_offset,
                         "vaddr": p_vaddr, "filesz": p_filesz})
        if p_type == PT_INTERP and r.fits(p_offset, min(p_filesz, MAX_STRING)):
            info["interpreter"] = _cstr(r.data, p_offset)
    return segments


def _read_sections(r, offset, entsize, count, shstrndx, info):
    """{name: (offset, size, type)} for the section header table."""
    sections = {}
    if not count or count > MAX_HEADERS or entsize < 16:
        return sections
    raw = []
    for i in range(count):
        at = offset + i * entsize
        if not r.fits(at, entsize):
            info["warnings"].append("section header table is truncated")
            return sections
        try:
            sh_name, sh_type = r.u32(at), r.u32(at + 4)
            if r.is64:
                sh_offset, sh_size = r.addr(at + 24), r.addr(at + 32)
            else:
                sh_offset, sh_size = r.addr(at + 16), r.addr(at + 20)
        except struct.error:
            return sections
        raw.append((sh_name, sh_type, sh_offset, sh_size))

    if not 0 <= shstrndx < len(raw):
        return sections
    str_offset, str_size = raw[shstrndx][2], raw[shstrndx][3]
    if not r.fits(str_offset, str_size):
        return sections
    names = r.data[str_offset:str_offset + str_size]

    for sh_name, sh_type, sh_offset, sh_size in raw:
        name = _cstr(names, sh_name)
        if name:
            sections[name] = (sh_offset, sh_size, sh_type)
    return sections


def _dynamic_location(r, segments, sections):
    """(offset, size) of the dynamic table, from sections or PT_DYNAMIC."""
    if ".dynamic" in sections:
        offset, size, _t = sections[".dynamic"]
        return offset, size
    for seg in segments:
        if seg["type"] == PT_DYNAMIC:
            return seg["offset"], seg["filesz"]
    return None, None


def _vaddr_to_offset(vaddr, segments, sections):
    """Map a virtual address to a file offset through the PT_LOAD segments."""
    if ".dynstr" in sections:
        return None                       # the caller has a better route
    for seg in segments:
        if seg["type"] != PT_LOAD:
            continue
        if seg["vaddr"] <= vaddr < seg["vaddr"] + seg["filesz"]:
            return seg["offset"] + (vaddr - seg["vaddr"])
    return None


def _read_dynamic(r, segments, sections, info):
    offset, size = _dynamic_location(r, segments, sections)
    if offset is None or not r.fits(offset, size or 0):
        return

    entry_size = 16 if r.is64 else 8
    entries = []
    for i in range(min(size // entry_size, MAX_DYNAMIC)):
        at = offset + i * entry_size
        try:
            tag = r.addr(at)
            val = r.addr(at + entry_size // 2)
        except struct.error:
            break
        if tag == DT_NULL:
            break
        entries.append((tag, val))

    # The dynamic string table: prefer the .dynstr section, fall back to
    # mapping DT_STRTAB's virtual address through the loadable segments.
    strtab_offset = strtab_size = None
    if ".dynstr" in sections:
        strtab_offset, strtab_size, _t = sections[".dynstr"]
    else:
        for tag, val in entries:
            if tag == DT_STRTAB:
                strtab_offset = _vaddr_to_offset(val, segments, sections)
            elif tag == DT_STRSZ:
                strtab_size = val
    if strtab_offset is None or not r.fits(strtab_offset, strtab_size or 0):
        if entries:
            info["warnings"].append("dynamic string table not resolvable")
        return
    strings = r.data[strtab_offset:strtab_offset + strtab_size]

    for tag, val in entries:
        if tag == DT_NEEDED and len(info["needed"]) < MAX_NEEDED:
            name = _cstr(strings, val)
            if name:
                info["needed"].append(name)
        elif tag == DT_SONAME:
            info["soname"] = _cstr(strings, val)
        elif tag in (DT_RPATH, DT_RUNPATH):
            info["runpath"] = _cstr(strings, val)


def _read_named_sections(data, sections, info):
    for name in INTERESTING_SECTIONS:
        entry = sections.get(name)
        if not entry:
            continue
        offset, size, sh_type = entry
        if sh_type == SHT_NOBITS or not size or offset + size > len(data):
            continue
        blob = data[offset:offset + min(size, 64 * 1024)]

        if name == ".comment":
            # A NUL-separated list; several toolchain passes may each add one.
            parts = [p.decode("utf-8", "replace").strip()
                     for p in blob.split(b"\x00") if p.strip()]
            if parts:
                info["comment"] = " | ".join(dict.fromkeys(parts))
        elif name == ".modinfo":
            # Kernel modules declare version, licence and author here.
            for item in blob.split(b"\x00"):
                if b"=" not in item:
                    continue
                key, _, value = item.decode("utf-8", "replace").partition("=")
                key = key.strip()
                if key and key not in info["modinfo"]:
                    info["modinfo"][key] = value.strip()
        elif name == ".note.gnu.build-id":
            # Note: 4-byte namesz, descsz, type, then padded name, then desc.
            if len(blob) >= 16:
                namesz, descsz = struct.unpack_from("<II", blob, 0)
                start = 16 + ((namesz + 3) // 4) * 4 - 4
                if 0 < descsz <= 64 and start + descsz <= len(blob):
                    info["build_id"] = blob[start:start + descsz].hex()


def soname_key(name):
    """A library's identity without its version suffix.

    libcrypto.so.1.1 -> libcrypto.so; used to match a DT_NEEDED entry against
    the file that provides it when the exact filename differs.
    """
    if not name:
        return None
    base = name.rsplit("/", 1)[-1]
    marker = base.find(".so")
    return base[:marker + 3] if marker != -1 else base
