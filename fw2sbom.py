#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fw2sbom - Evidence-based CycloneDX 1.6 SBOM generator for embedded firmware
images (.bin): ARM Cortex-M / Zephyr-style images and MCS-51 (8051) images such as
display-controller / monitor-scaler firmware.

Pipeline:
  0. Container handling: detect packetized/record-framed images (vendor ISP dumps
     of the form [checksum|length|page|sequence][payload chunk] repeated) and
     strip the framing before any content analysis.
  1. Binary fingerprint: `file` output (if available), SHA-256/SHA-1/MD5 hashes,
     and instruction-set identification (ARM Cortex-M vector table, MCS-51 vector
     table + opcode profile).
  2. String extraction (printable ASCII runs).
  3. Signature matching against a curated database of common embedded components
     (Zephyr, FreeRTOS, mbed TLS, lwIP, newlib, MCUboot, littlefs, GCC, ...).
  4. Opacity assessment: entropy / blank-flash-run / byte-distribution tests that
     distinguish an analyzable plaintext image from an encrypted or compressed
     one, so an empty result is reported as "opaque", not as "no components".
  5. Embedded standard data: structural detection (parse + validate, not string
     matching) of standardised data blocks such as VESA E-EDID and DDC/CI MCCS
     capability strings.
  6. Emit a CycloneDX 1.6 JSON SBOM where every component carries evidence
     (matched strings + file offsets) and a confidence score.

The resulting SBOM is *binary-derived*: heuristic, possibly incomplete, and clearly
marked as such in metadata. Runs on any Linux with Python 3.8+ (stdlib only).
"""

import argparse
import collections
import csv
import hashlib
import json
import math
import os
import re
import shutil
import struct
import subprocess
import time
import sys
import uuid
from datetime import datetime, timezone

import container
import elf
import esp32
import fit
import image_input
import evidence_report
import spdx_report
import uefi
import vendor_sbom

TOOL_NAME = "fw2sbom"
TOOL_VERSION = "1.23.0"

MAX_FILE_SIZE = 512 * 1024 * 1024  # refuse anything over 512 MiB
MAX_EVIDENCE_PER_COMPONENT = 8     # cap evidence entries kept per component

# --------------------------------------------------------------------------- #
# Signature database
# --------------------------------------------------------------------------- #
# Signatures live in signatures/*.json rather than in this file, so that the
# database can be updated, audited and extended without touching the analysis
# code, and so a customer can add their own pack. Each pack is
#   {"pack": str, "description": str, "signatures": [ ... ]}
# and each signature is
#   name / supplier / type / purl (versionless base) / description
#   patterns: list of {regex, weight, vgroup (optional: capture group w/ version)}
# Confidence = max(weight of matched patterns) + 0.05 per extra distinct pattern,
# capped at 0.97 (never 1.0 - this is heuristic binary analysis).

SIGNATURE_DIR_NAME = "signatures"
SIGNATURE_ENV_VAR = "FW2SBOM_SIGNATURES"

# Populated on first use by get_signatures(); None means "not loaded yet".
SIGNATURES = None
SIGNATURE_PACKS = []

_VALID_TYPES = {"application", "library", "framework", "operating-system",
                "device", "firmware", "file", "container", "data",
                "device-driver", "platform", "machine-learning-model"}


def _resource_dir():
    """Directory holding bundled data files.

    Both a checkout and the portable package keep them beside this module - the
    portable package is a folder of sources next to an official interpreter, not
    a frozen binary, which is the whole reason it needs no code signature.
    """
    return os.path.dirname(os.path.abspath(__file__))


def _validate_signature(sig, source):
    """Raise ValueError unless `sig` is a usable signature definition."""
    where = f"{source}: signature"
    name = sig.get("name")
    if not name or not isinstance(name, str):
        raise ValueError(f"{where} has no 'name'")
    where = f"{source}: signature '{name}'"

    for key in ("type", "purl", "description"):
        if not sig.get(key) or not isinstance(sig[key], str):
            raise ValueError(f"{where} has no '{key}'")
    if sig["type"] not in _VALID_TYPES:
        raise ValueError(f"{where} has CycloneDX type '{sig['type']}', which is "
                         f"not one of {sorted(_VALID_TYPES)}")
    if not sig["purl"].startswith("pkg:"):
        raise ValueError(f"{where} has purl '{sig['purl']}' (must start with 'pkg:')")
    if "@" in sig["purl"]:
        raise ValueError(f"{where} has a versioned purl '{sig['purl']}'; the "
                         "database stores the versionless base and the version "
                         "is appended per match")

    note = sig.get("version_note")
    if note is not None and (not isinstance(note, str) or not note.strip()):
        raise ValueError(f"{where} has an empty 'version_note'")

    patterns = sig.get("patterns")
    if not patterns or not isinstance(patterns, list):
        raise ValueError(f"{where} has no 'patterns'")
    for i, pat in enumerate(patterns):
        at = f"{where} pattern {i}"
        if not isinstance(pat, dict) or not isinstance(pat.get("regex"), str):
            raise ValueError(f"{at} has no 'regex'")
        try:
            compiled = re.compile(pat["regex"])
        except re.error as e:
            raise ValueError(f"{at} regex does not compile: {e}")
        weight = pat.get("weight")
        if not isinstance(weight, (int, float)) or isinstance(weight, bool):
            raise ValueError(f"{at} has no numeric 'weight'")
        if not 0.0 < weight <= 1.0:
            raise ValueError(f"{at} weight {weight} is outside (0.0, 1.0]")
        vgroup = pat.get("vgroup")
        if vgroup is not None:
            if not isinstance(vgroup, int) or isinstance(vgroup, bool):
                raise ValueError(f"{at} 'vgroup' must be an integer")
            if not 1 <= vgroup <= compiled.groups:
                raise ValueError(f"{at} vgroup {vgroup} but the regex has "
                                 f"{compiled.groups} capture group(s)")


def _load_pack(path):
    """Read and validate one signature pack. Returns (pack_name, signatures)."""
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        raise ValueError(f"{path}: cannot read signature pack: {e}")
    if not isinstance(doc, dict) or not isinstance(doc.get("signatures"), list):
        raise ValueError(f"{path}: expected an object with a 'signatures' list")
    pack = doc.get("pack") or os.path.splitext(os.path.basename(path))[0]
    for sig in doc["signatures"]:
        _validate_signature(sig, os.path.basename(path))
        sig["pack"] = pack
    return pack, doc["signatures"]


def signature_search_path(extra_dirs=None):
    """Directories to load packs from, lowest priority first.

    Built-in packs ship beside the tool. FW2SBOM_SIGNATURES (os.pathsep
    separated) and --signatures let a customer add or override packs without
    editing the shipped ones.
    """
    dirs = [os.path.join(_resource_dir(), SIGNATURE_DIR_NAME)]
    env = os.environ.get(SIGNATURE_ENV_VAR, "")
    dirs += [d for d in env.split(os.pathsep) if d.strip()]
    dirs += list(extra_dirs or [])
    return dirs


def load_signatures(extra_dirs=None, verbose=False):
    """Load every signature pack on the search path into SIGNATURES.

    A later directory may override a signature of the same name from an earlier
    one (that is how a customer pack customises a built-in); a duplicate within
    a single directory is an error, because it is always a mistake.
    """
    global SIGNATURES, SIGNATURE_PACKS
    merged = collections.OrderedDict()
    packs = []
    for directory in signature_search_path(extra_dirs):
        if not os.path.isdir(directory):
            continue
        seen_here = {}
        for filename in sorted(os.listdir(directory)):
            if not filename.endswith(".json"):
                continue
            path = os.path.join(directory, filename)
            pack, sigs = _load_pack(path)
            packs.append(pack)
            for sig in sigs:
                name = sig["name"]
                if name in seen_here:
                    raise ValueError(
                        f"{directory}: signature '{name}' is defined twice "
                        f"({seen_here[name]} and {filename})")
                seen_here[name] = filename
                if name in merged:
                    log(f"signature '{name}' overridden by {path}", verbose)
                merged[name] = sig
            log(f"loaded {len(sigs)} signature(s) from {path}", verbose)

    if not merged:
        searched = os.pathsep.join(signature_search_path(extra_dirs))
        raise ValueError(
            "no signature packs found - the component database is missing, so "
            "any SBOM produced now would be empty for the wrong reason. "
            f"Searched: {searched}")

    SIGNATURES = list(merged.values())
    SIGNATURE_PACKS = sorted(set(packs))
    return SIGNATURES


def get_signatures():
    """The loaded signature database, loading it on first use."""
    if SIGNATURES is None:
        load_signatures()
    return SIGNATURES

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def log(msg, verbose=True):
    if verbose:
        print(f"[fw2sbom] {msg}", file=sys.stderr)


def die(msg, code=1):
    print(f"[fw2sbom] ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def read_binary(path):
    if not os.path.exists(path):
        die(f"input file not found: {path}")
    if os.path.isdir(path):
        die(f"input is a directory, expected a firmware .bin file: {path}")
    size = os.path.getsize(path)
    if size == 0:
        die(f"input file is empty: {path}")
    if size > MAX_FILE_SIZE:
        die(f"input file too large ({size} bytes > {MAX_FILE_SIZE}); refusing to process")
    try:
        with open(path, "rb") as f:
            return f.read()
    except PermissionError:
        die(f"permission denied reading: {path}")
    except OSError as e:
        die(f"cannot read {path}: {e}")


def file_hashes(data):
    return {
        "SHA-512": hashlib.sha512(data).hexdigest(),
        "SHA-256": hashlib.sha256(data).hexdigest(),
        "SHA-1": hashlib.sha1(data).hexdigest(),
        "MD5": hashlib.md5(data).hexdigest(),
    }


def run_file_command(path, verbose=False):
    """Run `file` on the input if available (present on Kali by default)."""
    exe = shutil.which("file")
    if not exe:
        log("`file` command not found; skipping libmagic fingerprint", verbose)
        return None
    try:
        out = subprocess.run(
            [exe, "-b", path], capture_output=True, text=True, timeout=30, check=False
        )
        if out.returncode == 0:
            return out.stdout.strip()
        log(f"`file` returned {out.returncode}: {out.stderr.strip()}", verbose)
    except (subprocess.TimeoutExpired, OSError) as e:
        log(f"`file` invocation failed: {e}", verbose)
    return None


ASCII_RUN_TEMPLATE = rb"[\x20-\x7e]{%d,}"
# A UTF-16LE run is the same printable bytes with a NUL after each one. Vendor
# UI strings, Windows-built toolchain traces and much of UEFI keep version
# information that way, and an ASCII-only scanner sees none of it: the NULs
# break every run into single characters, far below any sane minimum length.
UTF16LE_RUN_TEMPLATE = rb"(?:[\x20-\x7e]\x00){%d,}"


def extract_strings(data, min_len=6):
    """Extract printable strings (ASCII and UTF-16LE) with their byte offsets.

    Returns [(offset, text)] sorted by offset. The two encodings cannot claim
    the same bytes: an ASCII run stops at the first NUL, which is exactly what
    separates the characters of a UTF-16LE run.
    """
    found = [(m.start(), m.group().decode("ascii"))
             for m in re.finditer(ASCII_RUN_TEMPLATE % min_len, data)]
    for m in re.finditer(UTF16LE_RUN_TEMPLATE % min_len, data):
        start, text = m.start(), m.group().decode("utf-16-le")
        # An ASCII string's NUL terminator makes its last character look like
        # the first UTF-16LE unit, so a wide string laid out right after a
        # narrow one is matched one character early. Evidence in this tool
        # quotes the matched string verbatim into an audit document, so drop
        # the borrowed character rather than report text that is not there.
        if start and 0x20 <= data[start - 1] <= 0x7E and len(text) > min_len:
            start, text = start + 2, text[1:]
        found.append((start, text))
    found.sort(key=lambda pair: pair[0])
    return found


def analyze_cortex_m(data):
    """Heuristic Cortex-M vector table check on a raw .bin image."""
    result = {"looks_like_cortex_m": False, "details": []}
    if len(data) < 64:
        result["details"].append("file too small for a vector table")
        return result
    initial_sp, reset = struct.unpack_from("<II", data, 0)
    sp_ok = (
        initial_sp % 4 == 0
        and (0x20000000 <= initial_sp <= 0x20400000   # typical SRAM
             or 0x10000000 <= initial_sp <= 0x10080000  # CCM/SRAM alt
             or 0x24000000 <= initial_sp <= 0x24100000)  # AXI SRAM (H7)
    )
    reset_ok = (reset & 1) == 1 and 0x0 < (reset & ~1) < 0x20000000
    if sp_ok:
        result["details"].append(f"initial SP 0x{initial_sp:08x} points into typical SRAM")
    if reset_ok:
        result["details"].append(f"reset vector 0x{reset:08x} has Thumb bit set")
    plausible = 0
    for i in range(2, 16):
        (vec,) = struct.unpack_from("<I", data, i * 4)
        if vec == 0 or ((vec & 1) == 1 and (vec & ~1) < 0x20000000):
            plausible += 1
    result["details"].append(f"{plausible}/14 plausible exception vectors in slots 2-15")
    result["looks_like_cortex_m"] = sp_ok and reset_ok and plausible >= 10
    return result


def analyze_mcs51(data):
    """Heuristic MCS-51 (8051) detection on a raw code image.

    Two independent signals, both required:
      1. the 8051 interrupt vector table - an LJMP (0x02) at reset (0x0000) and
         at 0x0003 + 8*k, where each ISR slot is 8 bytes apart;
      2. an opcode profile dominated by the handful of instructions that make up
         most of any compiled 8051 image (LCALL/LJMP/MOV DPTR/MOVX/RET).
    """
    result = {"looks_like_mcs51": False, "details": [], "vectors": []}
    if len(data) < 0x40:
        result["details"].append("file too small for an 8051 vector table")
        return result

    vector_names = ["RESET", "INT0", "TIMER0", "INT1", "TIMER1",
                    "SERIAL", "TIMER2", "INT4", "INT5", "INT6"]
    slots = [0x0000] + [3 + 8 * k for k in range(len(vector_names) - 1)]
    for name, off in zip(vector_names, slots):
        if off + 3 <= len(data) and data[off] == 0x02:  # LJMP addr16
            target = (data[off + 1] << 8) | data[off + 2]
            result["vectors"].append({"name": name, "offset": off, "target": target})
    if result["vectors"]:
        listed = ", ".join(f"{v['name']}@0x{v['offset']:04x}->0x{v['target']:04x}"
                           for v in result["vectors"][:6])
        result["details"].append(
            f"{len(result['vectors'])} LJMP interrupt vectors: {listed}")

    counts = collections.Counter(data)
    ratio = sum(counts[op] for op in MCS51_CORE_OPCODES) / len(data)
    result["opcode_ratio"] = round(ratio, 4)
    result["details"].append(
        f"core 8051 opcodes (LCALL/LJMP/MOV DPTR/MOVX/RET) are {ratio:.1%} of all "
        f"bytes (uniform random would be {len(MCS51_CORE_OPCODES) / 256:.1%})")

    result["looks_like_mcs51"] = (len(result["vectors"]) >= MCS51_MIN_VECTORS
                                  and ratio >= MCS51_MIN_OPCODE_RATIO)
    return result


def analyze_architecture(data):
    """Identify the instruction set of a raw firmware image, if we can.

    A declared answer beats a measured one, so a UEFI PE header or an Espressif
    chip ID settles the question outright. Failing that, Cortex-M is tested
    before MCS-51: its vector table is a much stronger constraint, and a Thumb
    image would otherwise be at some risk of matching the 8051 profile.
    """
    cortex = analyze_cortex_m(data)
    mcs51 = {"looks_like_mcs51": False, "details": [], "vectors": []}
    if not cortex["looks_like_cortex_m"]:
        mcs51 = analyze_mcs51(data)

    # Two formats write their instruction set down. A PC BIOS carries it in the
    # PE header of every module it contains; an Espressif image carries a chip
    # ID, which is the only thing that reliably separates the Xtensa parts from
    # the RISC-V ones. Either outranks an opcode statistic.
    firmware = uefi.detect(data)
    machine = (firmware or {}).get("machine")
    espressif = esp32.detect(data)
    fit_image = fit.detect(data)
    fit_arch = fit.declared_architecture(fit_image["images"]) if fit_image else None
    declared = []
    if machine:
        declared.append(
            f"uefi: the PE headers of the firmware modules declare "
            f"{machine['label']}")
        architecture, label = machine["architecture"], machine["label"]
    elif espressif and espressif["core"]:
        declared.append(
            f"espressif: the image header declares chip {espressif['chip']}, "
            f"{espressif['core']} - read from the image, not inferred from the "
            "bytes")
        architecture = ("xtensa" if espressif["core"].startswith("Xtensa")
                        else "riscv")
        label = f"{espressif['core']} ({espressif['chip']})"
    elif fit_arch:
        declared.append(
            f"fit: the image tree declares its kernel for {fit_arch[1]} - read "
            "from the image, not inferred from the bytes")
        architecture, label = fit_arch
    elif firmware:
        # A BIOS whose modules we could not reach: still not a Cortex-M image,
        # and letting a vector-table heuristic claim it would be worse than
        # saying nothing.
        architecture, label = None, None
    elif cortex["looks_like_cortex_m"]:
        architecture, label = "arm-cortex-m", "ARM Cortex-M (Thumb)"
    elif mcs51["looks_like_mcs51"]:
        architecture, label = "mcs-51", "MCS-51 / 8051"
    else:
        architecture, label = None, None

    return {
        "architecture": architecture,
        "label": label,
        # kept flat for backwards compatibility with existing callers
        "looks_like_cortex_m": cortex["looks_like_cortex_m"],
        "espressif": espressif,
        "uefi": firmware,
        # tag each line with the detector that produced it: the detectors run
        # independently and their evidence must not read as one finding
        "details": declared
                   + [f"cortex-m: {d}" for d in cortex["details"]]
                   + [f"mcs-51: {d}" for d in mcs51["details"]],
        "cortex_m": cortex,
        "mcs51": mcs51,
    }


# --------------------------------------------------------------------------- #
# Embedded standard data structures
# --------------------------------------------------------------------------- #
# Not every identifiable thing in a firmware image is a linked software library.
# Display controllers in particular embed standardised *data*: VESA E-EDID blocks
# and DDC/CI capability strings. These are found by parsing and validating the
# structures themselves rather than by matching strings, so they are reported
# separately from the signature hits, with an explicit evidence class.

EDID_MAGIC = b"\x00\xff\xff\xff\xff\xff\xff\x00"
EDID_BLOCK_SIZE = 128


def _edid_descriptor_name(block):
    """The 0xFC 'monitor name' descriptor of an EDID block, if present."""
    for i in range(54, 126, 18):
        if block[i:i + 3] == b"\x00\x00\x00" and block[i + 3] == 0xFC:
            raw = block[i + 5:i + 18].split(b"\n")[0]
            try:
                return raw.decode("ascii").strip()
            except UnicodeDecodeError:
                return None
    return None


def detect_edid_blocks(data):
    """Locate and validate VESA E-EDID blocks (128 bytes, magic + checksum)."""
    blocks = []
    for m in re.finditer(re.escape(EDID_MAGIC), data):
        offset = m.start()
        block = data[offset:offset + EDID_BLOCK_SIZE]
        if len(block) < EDID_BLOCK_SIZE or (sum(block) & 0xFF) != 0:
            continue  # a bad checksum means this is not really an EDID block
        packed = (block[8] << 8) | block[9]
        pnp = "".join(chr(((packed >> shift) & 0x1F) + 64) for shift in (10, 5, 0))
        if not pnp.isalpha() or not pnp.isupper():
            continue
        blocks.append({
            "offset": offset,
            "pnp_id": pnp,
            "product_code": (block[11] << 8) | block[10],
            "serial": int.from_bytes(block[12:16], "little"),
            "week": block[16],
            "version": f"{block[18]}.{block[19]}",
            "manufacture_year": 1990 + block[17] if block[17] else None,
            "extensions": block[126],
            "name": _edid_descriptor_name(block),
            "sha256": hashlib.sha256(block).hexdigest(),
        })
    return blocks


MCCS_VERSION_RX = re.compile(rb"mccs_ver\((\d+\.\d+)\)")
MCCS_CAPABILITY_RX = re.compile(rb"prot\((?:monitor|display)\)type\(([A-Za-z]+)\)")


def detect_mccs(data):
    """Locate VESA MCCS / DDC-CI capability strings and their declared version."""
    found = []
    for m in MCCS_CAPABILITY_RX.finditer(data):
        window = data[m.start():m.start() + 1024]
        version_match = MCCS_VERSION_RX.search(window)
        text = window.split(b"\x00")[0][:220]
        found.append({
            "offset": m.start(),
            "display_type": m.group(1).decode("ascii", "replace"),
            "version": version_match.group(1).decode() if version_match else None,
            "text": text.decode("ascii", "replace"),
        })
    return found


def detect_embedded_standards(data, verbose=False):
    """Structural detection of embedded standard data. Returns component dicts."""
    components = []

    edids = detect_edid_blocks(data)
    if edids:
        versions = sorted({b["version"] for b in edids})
        vendors = sorted({b["pnp_id"] for b in edids})
        names = [b["name"] for b in edids if b["name"]]
        evidence = [
            f"{len(edids)} EDID block(s) with valid 128-byte checksums, "
            f"first at offset 0x{edids[0]['offset']:x}",
            f"EDID structure version(s): {', '.join(versions)}",
            f"PnP manufacturer ID(s): {', '.join(vendors)}",
        ]
        if names:
            evidence.append("monitor name descriptor(s): "
                            + ", ".join(sorted(set(names))[:8]))
        components.append({
            "name": "vesa-e-edid",
            "supplier": "VESA",
            "type": "data",
            "purl": "pkg:generic/vesa-e-edid",
            "description": "VESA Enhanced Extended Display Identification Data "
                           "(E-EDID) blocks embedded in the image",
            "version": max(versions),
            "confidence": 0.95,
            "evidence": evidence,
            "occurrences": [b["offset"] for b in edids],
            "properties": [
                ("fw2sbom:edid_block_count", str(len(edids))),
                ("fw2sbom:edid_versions", ", ".join(versions)),
                ("fw2sbom:edid_pnp_ids", ", ".join(vendors)),
            ],
        })
        if verbose:
            log(f"embedded standard: VESA E-EDID x{len(edids)} "
                f"(v{max(versions)}, vendors {', '.join(vendors)})")

    mccs = detect_mccs(data)
    if mccs:
        version = next((c["version"] for c in mccs if c["version"]), None)
        evidence = [
            f"{len(mccs)} DDC/CI capability string(s), first at "
            f"offset 0x{mccs[0]['offset']:x}",
            f"capability string: {mccs[0]['text'][:160]}",
        ]
        if version:
            evidence.append(f"declared MCCS version from mccs_ver({version})")
        components.append({
            "name": "vesa-mccs",
            "supplier": "VESA",
            "type": "data",
            "purl": "pkg:generic/vesa-mccs",
            "description": "VESA Monitor Control Command Set (MCCS) capability "
                           "string served over DDC/CI",
            "version": version,
            "confidence": 0.95 if version else 0.8,
            "evidence": evidence,
            "occurrences": [c["offset"] for c in mccs],
            "properties": [
                ("fw2sbom:mccs_capability_strings", str(len(mccs))),
                ("fw2sbom:mccs_display_type", mccs[0]["display_type"]),
            ],
        })
        if verbose:
            log(f"embedded standard: VESA MCCS {version or '(version undeclared)'} "
                f"capability string x{len(mccs)}")

    return components


# --------------------------------------------------------------------------- #
# Packetized container detection / de-framing
# --------------------------------------------------------------------------- #
# Some vendors ship "firmware files" that are really a dump of the flash
# programming protocol rather than a flat image: a short file header, then
# fixed-size records of
#     [framing: checksum / length / page / sequence][payload chunk]
# Running a string scanner over such a file is meaningless - the payload bytes
# are chopped up by framing bytes every few dozen bytes.  The detector below is
# generic (no vendor magic): it looks for a record stride that has BOTH a column
# which is constant across every record AND a column that counts up by one per
# record.  Random data and ordinary flat firmware images do not produce that
# combination.

CONTAINER_MIN_STRIDE = 8
CONTAINER_MAX_STRIDE = 256
CONTAINER_MIN_RECORDS = 32        # fewer records than this and "framing" is noise
CONTAINER_PROBE_RECORDS = 256     # records sampled while searching for a stride
CONTAINER_MAX_FRAMING = 8         # widest per-record framing we are willing to strip
CONTAINER_MIN_PAYLOAD = 8         # narrower payload chunks are not worth de-framing
CONTAINER_MIN_COVERAGE = 0.5      # framing must span most of the file
CONTAINER_CONST_RATIO = 0.99      # tolerances for the full-file verification pass
CONTAINER_COUNTER_RATIO = 0.80

# MCS-51 (8051) detection. The listed opcodes - LJMP, LCALL, MOV DPTR,#d16,
# MOVX A,@DPTR, MOVX @DPTR,A, RET - dominate any compiled 8051 image; in a
# uniform random stream the six of them would account for 2.3% of all bytes.
MCS51_CORE_OPCODES = (0x02, 0x12, 0x90, 0xE0, 0xF0, 0x22)
MCS51_MIN_OPCODE_RATIO = 0.08
MCS51_MIN_VECTORS = 3

# Entropy thresholds for the opacity verdict (bits per byte).
OPACITY_HIGH = 7.5                # above this: no usable plaintext expected
OPACITY_STRONG = 7.9              # above this: indistinguishable from ciphertext
OPACITY_MAX_RUN = 8               # a plaintext image always has long 0x00/0xFF runs

COMPRESSION_MAGICS = [
    (b"\x1f\x8b\x08", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"\x5d\x00\x00", "lzma"),
    (b"\x04\x22\x4d\x18", "lz4"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"PK\x03\x04", "zip"),
    (b"hsqs", "squashfs"),
    (b"\x27\x05\x19\x56", "u-boot uImage"),
]


def shannon_entropy(data):
    """Shannon entropy in bits per byte (8.0 == indistinguishable from random)."""
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in collections.Counter(data).values())


def chi_square_uniform(data):
    """Chi-square statistic against a uniform byte distribution (df=255).

    A true random stream scores ~255 +/- 23; a biased one scores much higher, so
    this separates "looks like AES output" from "looks like a homebrew cipher".
    """
    if not data:
        return 0.0
    counts = collections.Counter(data)
    expected = len(data) / 256
    return sum((counts.get(b, 0) - expected) ** 2 / expected for b in range(256))


_NON_PRINTABLE = bytes(b for b in range(256) if not 0x20 <= b < 0x7F)


def longest_identical_run(data):
    """Length of the longest run of one repeated byte value.

    Only runs of two or more are matched: every byte is a run of one, so a
    pattern that also matched those built one match object per byte of the
    image - fourteen million of them for a 14.7 MB router, 2.7 seconds of a
    customer's wait. In random-looking data a repeat occurs at about one byte
    in 256, so this finds the same answer from a few thousand matches.
    """
    if not data:
        return 0
    return max((len(m.group()) for m in re.finditer(rb"(.)\1+", data, re.DOTALL)),
               default=1)


def _crc8(data, poly, init=0):
    crc = init
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


def _xor8(data):
    acc = 0
    for b in data:
        acc ^= b
    return acc


# Candidate per-record checksum algorithms, used to positively identify a
# checksum column - which proves that column is framing, not payload.
CHECKSUM_ALGORITHMS = [
    ("sum8", lambda p: sum(p) & 0xFF),
    ("neg-sum8", lambda p: (-sum(p)) & 0xFF),
    ("xor8", _xor8),
    ("crc8-0x07", lambda p: _crc8(p, 0x07)),
    ("crc8-0x31", lambda p: _crc8(p, 0x31)),
    ("crc8-0x1d", lambda p: _crc8(p, 0x1D)),
]


def _column(data, start, stride, count):
    """The `count` bytes at `start`, `start+stride`, `start+2*stride`, ..."""
    return data[start:start + count * stride:stride]


def _classify_columns(data, base, stride, nrec):
    """Classify each column of a candidate record grid.

    Returns (const, counter, slow): `const` maps column -> constant value,
    `counter` lists columns incrementing by 1 per record (a sequence number),
    `slow` lists columns that mostly repeat but only step upwards (a page/block
    index).  Payload columns fall into none of the three.
    """
    const, counter, slow = {}, [], []
    for j in range(stride):
        col = _column(data, base + j, stride, nrec)
        if len(set(col)) == 1:
            const[j] = col[0]
            continue
        steps = [(col[i + 1] - col[i]) & 0xFF for i in range(len(col) - 1)]
        if not steps:
            continue
        ones, zeros = steps.count(1), steps.count(0)
        if ones >= CONTAINER_COUNTER_RATIO * len(steps):
            counter.append(j)
        elif ones >= 2 and (ones + zeros) >= 0.95 * len(steps):
            slow.append(j)
    return const, counter, slow


def _cyclic_window(columns, stride):
    """Smallest cyclic window [start, start+width) covering all `columns`."""
    cols = sorted(columns)
    if len(cols) == 1:
        return cols[0], 1
    gaps = [(cols[(i + 1) % len(cols)] - cols[i]) % stride for i in range(len(cols))]
    k = gaps.index(max(gaps))
    start = cols[(k + 1) % len(cols)]
    return start, ((cols[k] - start) % stride) + 1


def _checksum_algorithm(data, rec_start, stride, nrec, col, pay_off, pay_width):
    """Name of the checksum algorithm that column `col` satisfies, or None.

    `col` and `pay_off` are offsets relative to the start of a record.
    """
    last = rec_start + (nrec - 1) * stride + max(col, pay_off + pay_width)
    if last >= len(data):
        nrec = max(1, nrec - 1)
    for name, fn in CHECKSUM_ALGORITHMS:
        ok = 0
        for k in range(nrec):
            rec = rec_start + k * stride
            if fn(data[rec + pay_off:rec + pay_off + pay_width]) == data[rec + col]:
                ok += 1
        if ok >= 0.9 * nrec:
            return name
    return None


def _resolve_framing(data, stride, nrec, meta_start, meta_width, target_width):
    """Widen the framing window from `meta_width` to `target_width`.

    Constant and counter columns are provably framing, but a checksum column is
    statistically indistinguishable from payload, so the provable window can be
    too narrow.  `meta_start` is an absolute file offset; the return value is the
    absolute offset of the resolved record start.  Candidates are ranked by:
      1. a verified checksum relation over the resulting payload (decisive),
      2. byte distribution - payload columns share one distribution, a framing
         column usually does not (only discriminates for plaintext payloads),
      3. otherwise assume framing precedes payload, the usual ISP convention,
         and flag the result as ambiguous.
    """
    extra = target_width - meta_width
    if extra <= 0:
        return meta_start, "exact (framing fully identified)"

    payload_width = stride - target_width
    sample = min(nrec, 128)
    # Prefer more framing on the left; candidates[0] is also the tie-break winner.
    candidates = []
    for left in range(extra, -1, -1):
        start = meta_start - left
        added = [start + i for i in range(left)] + \
                [meta_start + meta_width + i for i in range(extra - left)]
        if start >= 0:
            candidates.append((start, added))
    if not candidates:
        return meta_start, "assumed framing-before-payload (ambiguous)"

    for start, added in candidates:
        for col in added:
            alg = _checksum_algorithm(data, start, stride, sample,
                                      col - start, target_width, payload_width)
            if alg:
                return start, f"checksum column verified ({alg})"

    # Columns that are payload under every candidate framing - the reference
    # distribution that a framing column should deviate from.  Every chi-square
    # below is computed over the same number of samples: the statistic scales
    # with the sample count, so a pooled reference would not be comparable to a
    # single column.
    certain = list(range(meta_start + meta_width + extra,
                         meta_start + stride - extra))[:8]
    if len(certain) >= 3:
        reference = sorted(chi_square_uniform(_column(data, c, stride, nrec))
                           for c in certain)
        median = reference[len(reference) // 2]
        spread = sorted(abs(c - median) for c in reference)[len(reference) // 2]
        # The test only discriminates when the payload itself is non-uniform. In
        # an encrypted payload every column is uniform, so the comparison is pure
        # noise and would pick a framing boundary at random.
        if median > 1000:
            scored = sorted(
                (min(abs(chi_square_uniform(_column(data, col, stride, nrec)) - median)
                     for col in added), start)
                for start, added in candidates if added
            )
            if scored and scored[-1][0] > 3 * max(spread, 1.0) and                     (len(scored) == 1 or scored[-1][0] > 3 * max(scored[-2][0], 1.0)):
                return scored[-1][1], "byte-distribution outlier"

    return candidates[0][0], "assumed framing-before-payload (ambiguous)"


def _verify_framing(data, rec_start, stride, const_col, const_val, counter_col):
    """Full-file verification pass. Returns (first_record_offset, record_count)."""
    first = rec_start
    while first - stride >= 0 and data[first - stride + const_col] == const_val:
        first -= stride
    records = (len(data) - first) // stride
    if records < CONTAINER_MIN_RECORDS:
        return None
    col = _column(data, first + const_col, stride, records)
    if col.count(const_val) < CONTAINER_CONST_RATIO * records:
        return None
    if counter_col is not None:
        seq = _column(data, first + counter_col, stride, records)
        steps = [(seq[i + 1] - seq[i]) & 0xFF for i in range(len(seq) - 1)]
        if steps and steps.count(1) < CONTAINER_COUNTER_RATIO * len(steps):
            return None
    return first, records


def detect_packet_container(data, verbose=False, progress=None):
    """Detect fixed-stride record framing. Returns a layout dict, or None.

    Every stride from 8 to 256 is tried at two probe points, and on most
    images - which have no framing at all - that search is the whole of the
    first stage: 3.4 seconds on a 14.7 MB router with nothing to find. So it
    reports per stride tried, which is the only honest answer to "is it still
    doing something?" for a search that is going to come back empty.
    """
    if len(data) < CONTAINER_MIN_STRIDE * CONTAINER_MIN_RECORDS:
        return None

    report = progress or (lambda *_a, **_k: None)
    probes = sorted({min(4096, len(data) // 8), len(data) // 2})
    strides = range(CONTAINER_MIN_STRIDE, CONTAINER_MAX_STRIDE + 1)
    tried, attempts = 0, len(probes) * len(strides)
    best = None
    for probe in probes:
        for stride in strides:
            tried += 1
            if tried % 8 == 0:
                report(tried / attempts, {"kind": "strides", "index": tried,
                                          "count": attempts})
            available = (len(data) - probe) // stride
            if available < CONTAINER_MIN_RECORDS:
                continue
            nrec = min(available, CONTAINER_PROBE_RECORDS)
            const, counter, slow = _classify_columns(data, probe, stride, nrec)
            if not const or not counter:
                continue
            width = len(const) + len(counter) + len(slow)
            if width > CONTAINER_MAX_FRAMING or stride - width < CONTAINER_MIN_PAYLOAD:
                continue
            # Density, so that a multiple of the true stride cannot outscore it;
            # ties then go to the smallest stride.
            density = (2 * len(counter) + len(const) + len(slow)) / stride
            key = (round(density, 6), -stride)
            if best is None or key > best[0]:
                best = (key, stride, probe, const, counter, slow)
    if best is None:
        return None
    _key, stride, probe, const, counter, slow = best

    nrec = min((len(data) - probe) // stride, CONTAINER_PROBE_RECORDS)
    meta_col, meta_width = _cyclic_window(set(const) | set(counter) | set(slow), stride)

    # A constant column whose value equals a plausible payload width is almost
    # certainly a length byte - the strongest framing confirmation available.
    target_width, length_byte = meta_width, None
    for col in sorted(const):
        val = const[col]
        if CONTAINER_MIN_PAYLOAD <= val < stride and \
                CONTAINER_MAX_FRAMING >= stride - val >= meta_width:
            target_width, length_byte = stride - val, (col, val)
            break
    else:
        limit = min(CONTAINER_MAX_FRAMING, stride - CONTAINER_MIN_PAYLOAD)
        for width in range(meta_width, limit + 1):
            payload = stride - width
            if payload & (payload - 1) == 0:  # power of two: the usual chunk size
                target_width = width
                break

    rec_start, resolution = _resolve_framing(
        data, stride, nrec, probe + meta_col, meta_width, target_width)
    payload_width = stride - target_width
    if payload_width < CONTAINER_MIN_PAYLOAD:
        return None

    def relative(column):
        return (probe + column - rec_start) % stride

    const_col = min(const)
    verified = _verify_framing(data, rec_start, stride,
                               relative(const_col), const[const_col],
                               relative(counter[0]) if counter else None)
    if not verified:
        return None
    first, records = verified
    coverage = (records * stride) / len(data)
    if coverage < CONTAINER_MIN_COVERAGE:
        return None

    roles = {}
    for j in range(stride):
        r = relative(j)
        if r >= target_width:
            continue
        if j in const:
            roles[r] = f"const 0x{const[j]:02x}"
        elif j in counter:
            roles[r] = "seq +1/record"
        elif j in slow:
            roles[r] = "page index"
        else:
            roles[r] = "checksum/address?"
    layout = "".join(f"[{roles.get(i, '?')}]" for i in range(target_width))
    layout += f"[payload x{payload_width}]"

    container = {
        "stride": stride,
        "header_bytes": first,
        "records": records,
        "framing_width": target_width,
        "payload_offset": target_width,
        "payload_width": payload_width,
        "payload_bytes": records * payload_width,
        "trailing_bytes": len(data) - (first + records * stride),
        "coverage": round(coverage, 4),
        "length_byte": (f"column {relative(length_byte[0])} = 0x{length_byte[1]:02x}"
                        f" == payload width" if length_byte else None),
        "framing_resolution": resolution,
        "layout": layout,
    }
    if verbose:
        log(f"container: {stride}-byte records, {first}-byte file header, "
            f"{records} records, {target_width}B framing + {payload_width}B payload")
        log(f"container layout: {layout}")
        if container["length_byte"]:
            log(f"container length byte: {container['length_byte']}")
        log(f"container framing resolved by: {resolution}")
    return container


def deframe(data, container):
    """Concatenate the payload chunk of every record, dropping the framing."""
    stride = container["stride"]
    offset, width = container["payload_offset"], container["payload_width"]
    start = container["header_bytes"]
    out = bytearray()
    for k in range(container["records"]):
        record = start + k * stride
        out += data[record + offset:record + offset + width]
    return bytes(out)


def analyze_opacity(payload, architecture=None, progress=None):
    """Decide whether a payload is analyzable plaintext or opaque bytes.

    `architecture` is the instruction set identified by analyze_architecture(); a
    positive identification settles the question, because dense 8-bit MCU code
    legitimately reaches ~7.0 bits/byte and would otherwise be misreported as
    packed or partially compressed.
    """
    # Five statistics, each a full pass over the payload. On a 16 MB region
    # that is seconds of work, so each reports when it has finished - placed
    # by its measured share of the time, moved only when it is actually done.
    report = progress or (lambda *_a, **_k: None)
    entropy = shannon_entropy(payload)
    report(0.16, {"kind": "statistic", "name": "entropy"})
    run = longest_identical_run(payload)
    report(0.75, {"kind": "statistic", "name": "runs"})
    chi2 = chi_square_uniform(payload)
    report(0.91, {"kind": "statistic", "name": "distribution"})
    # Deleting the non-printable bytes and measuring what is left counts the
    # same thing as a per-byte Python loop, in C.
    printable = (len(payload.translate(None, _NON_PRINTABLE))
                 / max(1, len(payload)))

    duplicates = 0
    if len(payload) >= 32:
        blocks = collections.Counter(payload[i:i + 16]
                                     for i in range(0, len(payload) - 15, 16))
        duplicates = sum(c - 1 for c in blocks.values() if c > 1)
    report(1.0, {"kind": "statistic", "name": "blocks"})

    compression = next((name for magic, name in COMPRESSION_MAGICS
                        if payload[:16].startswith(magic)), None)

    reasons = [f"Shannon entropy {entropy:.3f} bits/byte",
               f"longest identical-byte run {run}",
               f"chi-square vs uniform {chi2:.0f} (true random ~255)",
               f"printable-ASCII ratio {printable:.3f}"]

    if architecture:
        verdict, opaque = "plaintext", False
        reasons.append(f"{architecture} machine code identified: the image is "
                       "plaintext regardless of its entropy (dense 8-bit MCU code "
                       "routinely reaches ~7.0 bits/byte)")
    elif entropy < 6.5:
        verdict, opaque = "plaintext", False
        reasons.append("entropy consistent with ordinary code and data")
    elif entropy < OPACITY_HIGH:
        verdict, opaque = "mixed", False
        reasons.append("elevated entropy: packed or partially compressed regions")
    elif compression:
        verdict, opaque = f"compressed ({compression})", True
        reasons.append(f"{compression} container magic at payload start")
    else:
        verdict, opaque = "opaque", True
        if entropy >= OPACITY_STRONG:
            reasons.append("entropy is indistinguishable from ciphertext")
        if run <= OPACITY_MAX_RUN:
            reasons.append(f"no blank-flash runs (longest run {run}); an unencrypted "
                           "image always contains long 0x00/0xff stretches")
        if chi2 > 1000:
            reasons.append("byte distribution measurably biased: more consistent with "
                           "a vendor block/stream cipher than with AES-CBC/GCM")
        if duplicates:
            reasons.append(f"{duplicates} repeated 16-byte aligned block(s): possible "
                           "ECB-mode or repeating-keystream encryption")
        reasons.append("no compression container magic at payload start")

    return {
        "verdict": verdict,
        "opaque": opaque,
        "entropy": round(entropy, 4),
        "longest_run": run,
        "chi_square": round(chi2, 1),
        "printable_ratio": round(printable, 4),
        "duplicate_16b_blocks": duplicates,
        "compression": compression,
        "reasons": reasons,
    }


def summarise_opacity(segments, whole_image):
    """The headline verdict, taken from the segments that hold content.

    Measuring a whole flash dump in one go lets its erased tail outvote what
    is actually in it: 3.6 MB of encrypted kernel beside 60 MB of 0xFF reads
    as 0.74 bits/byte, and the SBOM says "plaintext". The segments know
    better, so when there are segments the headline comes from them.
    """
    judged = [s for s in segments
              if s.get("opacity") and not s.get("blank")]
    if not judged:
        return whole_image

    opaque = [s for s in judged if s["opacity"]["opaque"]]
    if not opaque:
        return whole_image

    worst = max(opaque, key=lambda s: s["opacity"]["entropy"])
    summary = dict(worst["opacity"])
    summary["reasons"] = (
        [f"{len(opaque)} of {len(judged)} content segment(s) could not be "
         f"enumerated; the most opaque is {worst['label']} at offset "
         f"0x{worst['offset']:x}"]
        + list(worst["opacity"]["reasons"]))
    if whole_image and whole_image.get("verdict") != summary["verdict"]:
        summary["whole_image_verdict"] = whole_image["verdict"]
        summary["reasons"].append(
            f"measured over the whole image the verdict would be "
            f"'{whole_image['verdict']}' (entropy "
            f"{whole_image['entropy']:.3f}); that figure is dominated by "
            f"regions that hold no content")
    return summary


def microcode_components(segments):
    """Intel microcode updates, one component per distinct update.

    The same update often appears twice - in the flash and again inside an
    expanded volume - and is one component. Named the way Intel names its
    own files (intel-microcode-06-8e-0c), with the revision as the version,
    because that pair is what Intel's advisories cite. No purl: microcode is
    not a package in any ecosystem.
    """
    found, seen = [], set()
    for segment in segments:
        update = segment.get("microcode")
        if not update:
            continue
        key = (update["cpuid"], update["revision"], update["platforms"])
        if key in seen:
            continue
        seen.add(key)
        also = ", ".join(f"0x{e['cpuid']:x}" for e in update["extended"]
                         if e["cpuid"] != update["cpuid"])
        found.append({
            "name": f"intel-microcode-{update['fms']}",
            "version": f"0x{update['revision']:x}",
            "update": update,
            "confidence": 0.97,
            "evidence": (f"microcode update header at offset "
                         f"0x{update['offset']:x} in {segment['label']}: "
                         f"revision 0x{update['revision']:x}, CPUID "
                         f"0x{update['cpuid']:x}, platform flags "
                         f"0x{update['platforms']:x}, dated {update['date']}; "
                         "the update's checksum verifies"
                         + (f"; also applies to CPUID {also}" if also else "")),
        })
    return found


def structural_components(segments):
    """Components read from a format's own structures rather than from strings.

    These arrive after the opacity measurement, like signature hits do, and
    they settle the same contradiction: a BIOS whose 123 modules we just listed
    is not an image where "static component identification is not possible",
    whatever the entropy of the Management Engine sitting beside them said.
    """
    return (uefi_components(segments) + espressif_components(segments)
            + microcode_components(segments))


def reconcile_opacity(opacity, hits, standards, verbose=False):
    """Settle a contradiction between the opacity verdict and what was found.

    analyze_opacity() runs before signature matching, because matching needs
    the strings and the strings come out of the payload either way. So it can
    call a payload opaque and then the scanner reads component banners straight
    out of it - which is what happens when framing bytes are interleaved into
    otherwise readable data, or when a plaintext region sits in a mostly
    high-entropy image. Reporting "static component identification is not
    possible" directly above a list of identified components is simply wrong.

    Evidence wins over the statistic: an opaque verdict cannot stand once
    components have been read out of the payload. The measurement stays in the
    record, re-labelled as mixed, because high-entropy regions may still hide
    components that were not enumerated. Per-region verdicts are the real fix;
    this keeps the report honest until then.
    """
    if not opacity or not opacity["opaque"]:
        return opacity
    identified = len(hits) + len(standards or [])
    if not identified:
        return opacity

    settled = dict(opacity)
    settled["opaque"] = False
    settled["original_verdict"] = opacity["verdict"]
    settled["verdict"] = "mixed"
    settled["reasons"] = list(opacity["reasons"]) + [
        f"{identified} component(s) were read out of this payload, so it is not "
        f"opaque; the '{opacity['verdict']}' measurement above describes the "
        "image as a whole. High-entropy regions remain and may hide components "
        "that were not enumerated."]
    log(f"opacity verdict '{opacity['verdict']}' downgraded to 'mixed': "
        f"{identified} component(s) were identified in the payload", verbose)
    return settled


# --------------------------------------------------------------------------- #
# Signature matching
# --------------------------------------------------------------------------- #

def match_signatures(strings, verbose=False):
    """Match the signature DB against extracted strings. Returns list of hits."""
    hits = []
    for sig in get_signatures():
        matched_patterns = []  # (pattern_dict, offset, matched_text, version_or_None)
        for pat in sig["patterns"]:
            rx = re.compile(pat["regex"])
            best = None  # (offset, matched_text, version) - prefer hits w/ version
            for offset, s in strings:
                m = rx.search(s)
                if not m:
                    continue
                version = m.group(pat["vgroup"]) if pat.get("vgroup") else None
                if best is None or version:
                    best = (offset, m.group(0), version)
                if version:
                    break
            if best:
                matched_patterns.append((pat, best[0], best[1], best[2]))
        if not matched_patterns:
            continue
        weights = [p[0]["weight"] for p in matched_patterns]
        confidence = min(0.97, max(weights) + 0.05 * (len(matched_patterns) - 1))
        version = next((v for (_, _, _, v) in matched_patterns if v), None)
        hits.append({
            "sig": sig,
            "confidence": round(confidence, 2),
            "version": version,
            "evidence": matched_patterns[:MAX_EVIDENCE_PER_COMPONENT],
        })
        log(f"match: {sig['name']} confidence={confidence:.2f} version={version}", verbose)
    return sorted(hits, key=lambda h: -h["confidence"])


# Zephyr fork tag (printed by the NCS boot banner) -> nRF Connect SDK release family
ZEPHYR_FORK_TO_NCS = {
    "3.2.99-ncs1": "2.2.x/2.3.x",
    "3.3.99-ncs1": "2.4.x",
    "3.4.99-ncs1": "2.5.x",
    "3.5.99-ncs1": "2.6.x",
    "3.6.99-ncs1": "2.7.x",
    "3.6.99-ncs2": "2.7.x",
    "3.7.99-ncs1": "2.8.x",
    "3.7.99-ncs2": "2.9.x",
}

VERSION_TOKEN_RX = re.compile(r"\bv?([0-9]+\.[0-9]+(?:\.[0-9]+)+(?:-[A-Za-z0-9]+)?)\b")


def infer_versions(hits, verbose=False):
    """Second pass: fill in versions that are not captured by a vgroup pattern.

    1. nRF Connect SDK release family inferred from the Zephyr fork tag.
    2. Fallback: a version-like token inside the very string that matched the
       component (e.g. 'littlefs v2.8' when no dedicated pattern captured it).
    Inferred versions are flagged and emitted with reduced confidence.
    """
    by_name = {h["sig"]["name"]: h for h in hits}
    z, n = by_name.get("zephyr"), by_name.get("nrf-connect-sdk")
    if z and n and not n["version"] and z["version"] in ZEPHYR_FORK_TO_NCS:
        n["version"] = ZEPHYR_FORK_TO_NCS[z["version"]]
        n["version_inferred"] = (
            f"inferred from Zephyr fork tag v{z['version']} "
            f"(NCS release mapping table); confirm exact release with the vendor")
        log(f"inferred: nrf-connect-sdk {n['version']} (from zephyr fork tag)", verbose)
    for h in hits:
        if h["version"]:
            continue
        for _pat, _off, text, _v in h["evidence"]:
            m = VERSION_TOKEN_RX.search(text)
            if m:
                h["version"] = m.group(1)
                h["version_inferred"] = (
                    f"version-like token found in matched string '{text}' "
                    f"(not a dedicated version pattern)")
                log(f"inferred: {h['sig']['name']} {h['version']} (same-string token)",
                    verbose)
                break


def confidence_level(c):
    return "high" if c >= 0.8 else "medium" if c >= 0.5 else "low"


# --------------------------------------------------------------------------- #
# Segment analysis
# --------------------------------------------------------------------------- #

def analyze_segments(payload, min_str_len=6, verbose=False, architecture=None,
                     progress=None):
    """Split a payload into containers and analyse each one separately.

    A flat microcontroller image produces exactly one segment covering the
    whole payload, so its analysis is unchanged. A Linux image produces a boot
    header, a decompressed kernel, a filesystem and whatever is left, and each
    is scanned on its own - which is the only way the components inside a
    compressed region are ever seen.

    Returns (segments, rootfs, warnings). Each analysed segment gains
    `strings`, `hits` and `opacity`; `rootfs` is the filesystem contents if one
    was readable.
    """
    report = progress or (lambda *_a, **_k: None)
    log_fn = (lambda msg: log(msg, verbose)) if verbose else None
    report(0.0, {"kind": "walk"})
    segments, warnings = container.walk(payload, verbose, log_fn)
    # Judging every segment's entropy is its own real share of the work - on a
    # BIOS it is most of it, a 16 MB decompressed volume measured byte by byte
    # - and leaving it unreported held the bar still for 4.5 seconds.
    WALKED, JUDGED = 0.05, 0.3

    # Nothing recognised: treat the payload as one segment, exactly as the
    # tool did before containers existed.
    if not segments or all(seg["kind"] == "unclaimed" for seg in segments):
        segments = [{"kind": "image", "offset": 0, "length": len(payload),
                     "label": "firmware image", "content": payload,
                     "expanded": False, "warnings": []}]

    judge_segments(segments, payload, architecture, verbose,
                   progress=lambda f, d=None: report(
                       WALKED + (JUDGED - WALKED) * f, d))

    # Weighted by size, because extracting strings and matching signatures is
    # roughly linear in bytes: a 16 MB decompressed volume and a 24-byte header
    # are not the same amount of work, and counting them as one segment each
    # would have the bar racing through headers and then sitting still.
    def weight(segment):
        body = segment["content"]
        return max(1, len(body) if body is not None else segment["length"])

    total = sum(weight(segment) for segment in segments) or 1
    done = 0
    primary = choose_rootfs(segments)

    rootfs = None
    for index, segment in enumerate(segments, 1):
        low = JUDGED + (1 - JUDGED) * done / total
        high = JUDGED + (1 - JUDGED) * (done + weight(segment)) / total
        detail = {"kind": "segment", "index": index, "count": len(segments),
                  "label": segment["label"]}
        report(low, detail)
        if segment is primary:
            def inner(fraction, sub=None, low=low, high=high, detail=detail):
                report(low + (high - low) * fraction,
                       dict(detail, **(sub or {})))
            rootfs = container.inspect_filesystem(segment, verbose, log_fn,
                                                  progress=inner)
        elif segment["kind"] == "filesystem":
            # A device dump carries a read-only rootfs and, after it, a
            # writable overlay - JFFS2 on NOR flash. Only one is read as the
            # rootfs (choose_rootfs), but the overlay is where packages installed after
            # the factory image land, so its files are scanned too rather than
            # the whole region going unread because it is not first.
            segment["hits"] = secondary_filesystem_hits(segment, min_str_len,
                                                        verbose)
            segment["strings"] = []
            done += weight(segment)
            report(high, detail)
            continue
        done += weight(segment)
        content = segment["content"]
        if content is None:
            segment["strings"], segment["hits"] = [], []
            continue
        segment["strings"] = extract_strings(content, min_str_len)
        segment["hits"] = match_signatures(segment["strings"], False)
        infer_versions(segment["hits"], False)
        if segment["hits"]:
            log(f"segment {segment['label']}: {len(segment['hits'])} component(s) "
                f"from {len(segment['strings'])} strings", verbose)
        report(high, detail)

    segments.extend(unread_files_segment(segment, segment["unread_files"])
                    for segment in list(segments)
                    if segment.get("unread_files"))
    return segments, rootfs, warnings


# A region is blank flash rather than content when almost every byte is an
# erased-flash value. Judging such a region as "plaintext, entropy 0.7" and
# letting it dominate a whole-image verdict is how an encrypted kernel sitting
# next to 60 MB of padding gets reported as plaintext.
BLANK_BYTES = (0x00, 0xFF)
BLANK_RATIO = 0.99


def looks_blank(blob, sample=1 << 20):
    """True when a region is erased flash rather than content."""
    if not blob:
        return True
    window = blob[:sample] if len(blob) > sample else blob
    blank = sum(1 for b in window if b in BLANK_BYTES)
    return blank >= BLANK_RATIO * len(window)


def judge_segments(segments, payload, architecture=None, verbose=False,
                   progress=None):
    """Give every segment its own opacity verdict.

    A firmware image is not one substance. This one is a 64 MB flash dump
    holding a 3.6 MB encrypted kernel and 60 MB of erased flash; measured as a
    whole it reads as 0.74 bits/byte - "plaintext" - and the encryption
    disappears into the padding. Measured per segment, the kernel reads 7.9999
    with no blank runs and 2083 repeated 16-byte blocks, which is what it
    actually is.

    `architecture` applies only to a flat image that is all one segment, and
    only when the instruction set was positively identified. That rule exists
    because dense microcontroller code legitimately reaches ~7 bits/byte and an
    entropy threshold alone calls it encrypted; a recognised vector table
    settles the question that the statistic cannot.
    """
    report = progress or (lambda *_a, **_k: None)
    sizes = [max(1, len(seg["content"]) if seg["content"] is not None
                 else seg["length"]) for seg in segments]
    total, done = sum(sizes) or 1, 0
    for index, segment in enumerate(segments):
        report(done / total, {"kind": "judge", "index": index + 1,
                              "count": len(segments), "label": segment["label"]})
        done += sizes[index]
        if segment["kind"] in ("filesystem", "microcode"):
            # Read structurally; entropy of the compressed image says nothing
            # about whether its contents were enumerable. Microcode is
            # encrypted by design and identified by its header.
            segment["opacity"] = None
            continue
        if segment.get("unread_reason"):
            # Known to hold something that could not be read. Its bytes are
            # not in the payload at its offset, and judging them would only
            # risk calling it blank; the reason it was not read is the verdict.
            segment["opacity"] = None
            continue

        blob = segment["content"]
        if blob is None:
            start = segment["offset"]
            blob = payload[start:start + segment["length"]]
            expanded = False
        else:
            expanded = segment.get("expanded", False)

        if looks_blank(blob):
            segment["blank"] = True
            segment["opacity"] = None
            segment["label"] = (segment["label"] if segment["kind"] != "unclaimed"
                                else "blank flash")
            log(f"segment 0x{segment['offset']:08x}: erased flash, "
                f"{segment['length']} bytes", verbose)
            continue

        # The whole payload as one segment is the case the architecture rule
        # was written for; a region inside a container is not.
        span_low, span_high = (done - sizes[index]) / total, done / total
        segment_detail = {"kind": "judge", "index": index + 1,
                          "count": len(segments), "label": segment["label"]}
        verdict = analyze_opacity(
            blob, architecture if segment["kind"] == "image" else None,
            progress=lambda f, d=None, lo=span_low, hi=span_high,
            base=segment_detail: report(lo + (hi - lo) * f,
                                        dict(base, **(d or {}))))
        # Content we successfully expanded is by definition readable, whatever
        # the compressed form scored.
        if expanded and verdict["opaque"] and not verdict["compression"]:
            verdict = dict(verdict, opaque=False, verdict="plaintext",
                           original_verdict=verdict["verdict"])
        segment["opacity"] = verdict
        if verdict["opaque"]:
            log(f"segment 0x{segment['offset']:08x} ({segment['label']}): "
                f"{verdict['verdict']}, entropy {verdict['entropy']:.3f}", True)
    return segments


def opaque_segments(segments):
    """Segments whose contents could not be enumerated, and why."""
    return [s for s in segments
            if (s.get("opacity") or {}).get("opaque")
            or (s["content"] is None and s["kind"] not in ("filesystem",)
                and not s.get("blank"))]


# --------------------------------------------------------------------------- #
# Vendor-supplied SBOMs
# --------------------------------------------------------------------------- #

def load_vendor_sboms(paths, verbose=False):
    """Read every vendor SBOM named on the command line."""
    documents = []
    for path in paths or []:
        try:
            loaded = vendor_sbom.load(path)
        except vendor_sbom.VendorSBOMError as e:
            die(str(e))
        identity = loaded["document"]
        log(f"vendor SBOM: {identity['format']} from {identity['file']}, "
            f"{len(loaded['components'])} component(s)"
            + (f", subject {identity['subject']}" if identity["subject"] else ""),
            verbose)
        documents.append(loaded)
    return documents


def identified_components(hits, standards, packages, structural=None):
    """Everything this analysis found, flattened for comparison.

    `structural` is whatever came out of a format's own structures rather than
    out of its strings - ESP-IDF's app descriptor, a BIOS's module inventory.
    Leaving those out does not produce a smaller comparison; it produces a
    wrong one, where a vendor naming a module the image visibly contains comes
    back as "declared but not observed".
    """
    found = []
    for item in structural or []:
        found.append({"name": item["name"], "version": item.get("version"),
                      "purl": item.get("purl"), "source": "declared-structure"})
    for hit in hits:
        found.append({"name": hit["sig"]["name"], "version": hit["version"],
                      "purl": hit["sig"]["purl"], "source": "signature"})
    for std in standards or []:
        found.append({"name": std["name"], "version": std["version"],
                      "purl": std["purl"], "source": "embedded-standard"})
    for package in packages or []:
        found.append({"name": package["name"], "version": package["version"],
                      "purl": package["purl"], "source": "package-database"})
    return found


def reconcile_vendor_sboms(documents, hits, standards, packages,
                           verbose=False, structural=None):
    """Compare each vendor document against what the image actually showed.

    A version the vendor declares that the binary contradicts is a finding, and
    quite possibly the most useful one in the report. It is recorded as such
    rather than resolved: this tool is not in a position to decide which of the
    two is right, only to show that they differ.
    """
    report = []
    for loaded in documents:
        agreements, conflicts, vendor_only, _ours_only = vendor_sbom.compare(
            identified_components(hits, standards, packages, structural),
            loaded["components"])
        report.append({"document": loaded["document"],
                       "components": loaded["components"],
                       "agreements": agreements,
                       "conflicts": conflicts,
                       "vendor_only": vendor_only})
        identity = loaded["document"]
        log(f"vendor SBOM {identity['file']}: {len(agreements)} agree, "
            f"{len(conflicts)} conflict, {len(vendor_only)} declared but not "
            f"observed", verbose)
        for conflict in conflicts:
            log(f"  version conflict: {conflict['vendor']['name']} - vendor "
                f"says {conflict['vendor_version']}, the image shows "
                f"{conflict['our_version']}", True)
    return report


# Paths that mark a filesystem as a device's root rather than a data partition.
ROOTFS_MARKERS = ("/etc/os-release", "/usr/lib/os-release",
                  "/usr/lib/opkg/status", "/var/lib/dpkg/status",
                  "/lib/apk/db/installed", "/bin/busybox", "/sbin/init",
                  "/etc/inittab", "/bin/sh")


def choose_rootfs(segments):
    """The filesystem that describes the device, when there is more than one.

    Only one filesystem is read as the rootfs - its package database, its
    release file, its binaries' dependency graph - and the others have their
    files scanned. On a router the first is normally right; in a UBI image the
    order is the volume numbering, and a "configuration" volume can come ahead
    of "rootfs". So the first filesystem that looks like a root wins, and the
    first one of all only when none does.
    """
    filesystems = [s for s in segments if s["kind"] == "filesystem"]
    if len(filesystems) < 2:
        return filesystems[0] if filesystems else None
    for segment in filesystems:
        image = segment.get("filesystem")
        try:
            files = image.files()
        except container.FILESYSTEM_ERRORS:
            continue
        segment["files"] = files          # read once, used again later
        if any(marker in files for marker in ROOTFS_MARKERS):
            return segment
    return filesystems[0]


MAX_UNREAD_LISTED = 3


def unread_files_segment(filesystem, unread):
    """A segment standing for the files of a filesystem that could not be read.

    The filesystem itself was walked, so it is not opaque - but a file whose
    blocks would not decompress (zstd on a Python without it, a damaged node)
    had nothing matched against it, and "no components found in it" is not
    what happened. It becomes an opaque component naming the files and why.
    """
    paths = sorted(unread)
    listed = ", ".join(paths[:MAX_UNREAD_LISTED]) + (
        f" and {len(paths) - MAX_UNREAD_LISTED} more"
        if len(paths) > MAX_UNREAD_LISTED else "")
    reason = (f"{len(paths)} file(s) in {filesystem['label']} could not be "
              f"read: {listed}")
    return {"kind": "unread-files", "offset": filesystem["offset"],
            "length": sum(unread[p]["size"] for p in paths),
            "label": f"{filesystem['label']}: {len(paths)} file(s) not read",
            "content": None, "expanded": False, "unread_reason": reason,
            "opacity": None, "strings": [], "hits": [],
            "warnings": [reason] + [f"{p}: {unread[p]['reason']}"
                                    for p in paths[:MAX_UNREAD_LISTED - 1]]}


def secondary_filesystem_hits(segment, min_str_len=6, verbose=False):
    """Signature hits from every file in a filesystem that is not the rootfs."""
    image = segment.get("filesystem")
    if image is None:
        return []
    try:
        files = segment.get("files") or image.files()
    except container.FILESYSTEM_ERRORS as e:
        segment["warnings"].append(f"filesystem could not be walked: {e}")
        return []
    scan = {"image": image, "files": files, "binaries": {}}
    hits = scan_rootfs_files(scan, min_str_len, verbose)
    if scan.get("unread_files"):
        segment["unread_files"] = scan["unread_files"]
    for hit in hits:
        hit["filesystem"] = segment["label"]
    if hits:
        log(f"{segment['label']}: {len(hits)} component(s) from its files",
            verbose)
    return hits


def scan_rootfs_files(rootfs, min_str_len=6, verbose=False, progress=None):
    """Signature-match the root filesystem files a package database misses.

    Returns hits shaped like match_signatures()' output, each carrying the
    path inside the image it came from. That path is better evidence than a
    byte offset into a decompressed blob: an auditor can go and look at
    /usr/sbin/dropbear, and cannot do anything with "offset 0x3f1a80".
    """
    if not rootfs:
        return []
    best = {}
    files = bytes_read = 0
    for path, blob in container.unclaimed_files(
            rootfs, (lambda m: log(m, verbose)) if verbose else None,
            progress=progress):
        files += 1
        bytes_read += len(blob)
        # A version string inside an executable is the component's own banner,
        # compiled in. The same string in a config file or a script is a human
        # note that may be stale, or may be describing something the device
        # talks to rather than something it contains. Both are worth reporting;
        # they are not worth reporting as if they were the same evidence.
        kind = ("an executable" if elf.looks_like_elf(blob[:20])
                else "a non-executable file")
        for hit in match_signatures(extract_strings(blob, min_str_len)):
            name = hit["sig"]["name"]
            hit["file"] = path
            hit["file_kind"] = kind
            previous = best.get(name)
            if previous is None or hit["confidence"] > previous["confidence"] \
                    or (hit["version"] and not previous["version"]):
                hit["files"] = sorted(set((previous or {}).get("files", []))
                                      | {path})
                best[name] = hit
            else:
                previous["files"] = sorted(set(previous.get("files", []))
                                           | {path})
    hits = sorted(best.values(), key=lambda h: -h["confidence"])
    if files:
        log(f"rootfs: scanned {files} unclaimed file(s) ({bytes_read} bytes), "
            f"{len(hits)} component(s) matched", verbose)
    for hit in hits:
        infer_versions([hit], False)
    return hits


def merge_segment_hits(segments):
    """One component per name, carrying evidence from every segment it is in.

    A library linked into both the kernel and a userland binary is one
    component, not two; but which segments it was found in is evidence worth
    keeping, so the occurrences list names all of them.
    """
    merged = {}
    for segment in segments:
        for hit in segment.get("hits", []):
            name = hit["sig"]["name"]
            hit = dict(hit)
            hit["segment"] = segment["label"]
            hit["segment_offset"] = segment["offset"]
            existing = merged.get(name)
            if existing is None:
                hit["segments"] = [segment["label"]]
                merged[name] = hit
                continue
            existing["segments"].append(segment["label"])
            # Prefer the better-evidenced sighting, and never lose a version.
            if hit["confidence"] > existing["confidence"]:
                hit["segments"] = existing["segments"]
                hit["version"] = existing["version"] or hit["version"]
                merged[name] = hit
            elif hit["version"] and not existing["version"]:
                existing["version"] = hit["version"]
                if hit.get("version_inferred"):
                    existing["version_inferred"] = hit["version_inferred"]
    return sorted(merged.values(), key=lambda h: -h["confidence"])


def merge_hit_lists(primary, extra):
    """Combine two hit lists, keeping the better-evidenced sighting of each.

    A component found both in a decompressed segment and in a specific file
    is one component; the file path is worth keeping either way, because it
    is the more useful of the two locations.
    """
    merged = {hit["sig"]["name"]: hit for hit in primary}
    for hit in extra:
        name = hit["sig"]["name"]
        previous = merged.get(name)
        if previous is None:
            merged[name] = hit
            continue
        if hit.get("files"):
            previous["files"] = sorted(
                set(previous.get("files", [])) | set(hit["files"]))
        if hit["confidence"] > previous["confidence"]:
            hit["files"] = previous["files"]
            hit["segments"] = previous.get("segments", [])
            hit["version"] = previous["version"] or hit["version"]
            merged[name] = hit
        elif hit["version"] and not previous["version"]:
            previous["version"] = hit["version"]
            previous.pop("version_inferred", None)
    return sorted(merged.values(), key=lambda h: -h["confidence"])


def uefi_inventory(segments):
    """The UEFI module inventory carried on the segments, or None."""
    for segment in segments or []:
        if segment.get("uefi"):
            return segment["uefi"]
    return None


def uefi_components(segments):
    """The modules a PC BIOS is built from.

    This is the whole answer for a BIOS. A release build of EDK2 contains no
    library banners at all - not one signature in our database matches a
    published OVMF image - but every module carries the name its build system
    gave it, and a GUID that identifies it exactly even when the name section
    was stripped. Those names are declared by the firmware, not inferred from
    it, which is why they carry package-database confidence.

    The version is whatever the module's own VERSION section says. In EDK2
    practice that is almost always "1.0" and it describes the module, not any
    library inside it - so it is reported when present and never promoted into
    something a CVE feed should match on.
    """
    inventory = uefi_inventory(segments)
    if not inventory:
        return []

    found = []
    for module in inventory["modules"]:
        named = bool(module["name"])
        name = module["name"] or f"UEFI module {module['guid']}"
        evidence = (f"firmware file {module['guid']} of type "
                    f"{module['type']} in firmware volume {module['volume']}")
        if named:
            evidence += "; name declared in its USER_INTERFACE section"
        else:
            evidence += ("; no USER_INTERFACE section, so the GUID is the only "
                         "identity the image gives it")
        found.append({
            "name": name,
            "version": module["version"],
            "guid": module["guid"],
            "module_type": module["type"],
            "volume": module["volume"],
            "size": module["size"],
            "named": named,
            "confidence": 0.97 if named else 0.9,
            "evidence": evidence,
        })
    return found


def uefi_component_type(module_type):
    """Map a firmware file type onto a CycloneDX component type."""
    if module_type in ("driver", "peim", "smm", "combined-peim-driver",
                       "combined-smm-dxe", "mm-standalone"):
        return "device-driver"
    if module_type == "application":
        return "application"
    if module_type == "firmware-volume-image":
        return "container"
    if module_type in ("raw", "freeform"):
        return "data"
    return "firmware"


def boot_container_properties(segments):
    """What a FIT image and OpenWrt's metadata declare about the firmware.

    Both are written by the build system, so they are recorded as declared
    facts: the image tree's own description of each image and whether its
    hashes still match, the board the device tree is for, and the version the
    build stamped on the image - which names the firmware even when its root
    filesystem cannot be read.
    """
    props = []
    for segment in segments:
        image = segment.get("fit")
        if image:
            props.append({"name": "fw2sbom:fit_description",
                          "value": image["description"] or ""})
            for entry in image["images"]:
                checked = [c for c in entry["checks"] if c["ok"] is not None]
                state = ("; ".join(f"{c['algo']} {'verified' if c['ok'] else 'MISMATCH'}"
                                   for c in checked) or "no hash checked")
                props.append({
                    "name": f"fw2sbom:fit_image_{entry['name']}",
                    "value": f"{entry['type']}, {entry['arch'] or 'no arch'}, "
                             f"{entry['compression'] or 'no compression declared'}, "
                             f"{entry['size']} bytes, {entry['placement']}: "
                             f"{entry['description'] or ''} ({state})"})
        if segment.get("device_tree_model"):
            props.append({"name": "fw2sbom:device_tree_model",
                          "value": segment["device_tree_model"]})
        metadata = segment.get("openwrt_metadata")
        if metadata:
            version = metadata.get("version") or {}
            for key in ("dist", "version", "revision", "target", "board"):
                if version.get(key):
                    props.append({"name": f"fw2sbom:openwrt_image_{key}",
                                  "value": str(version[key])})
            devices = metadata.get("supported_devices")
            if isinstance(devices, list) and devices:
                props.append({"name": "fw2sbom:openwrt_supported_devices",
                              "value": ", ".join(str(d) for d in devices[:16])})
    return props


def espressif_image(segments):
    """The Espressif image that describes the firmware, or None.

    A flash dump holds several: a bootloader at 0x1000 and one image per
    application partition. The one carrying an app descriptor is the one that
    describes the product, so it wins over whichever happens to sit lowest in
    the flash - which is always the bootloader, and never has a descriptor.
    """
    images = [s["espressif"] for s in segments or [] if s.get("espressif")]
    return next((i for i in images if i.get("app")),
                images[0] if images else None)


def espressif_components(segments):
    """Components an Espressif image states about itself.

    ESP-IDF writes its own version into esp_app_desc_t, and the header names
    the chip. Both are structural fields rather than strings that happened to
    match a pattern, so they carry the same confidence as a package database
    entry - and neither is invented when the field is blank, which real builds
    often leave it.
    """
    found = []
    for segment in segments or []:
        image = segment.get("espressif")
        if not image:
            continue
        application = image.get("app") or {}
        idf = application.get("idf_version")
        if idf and not any(c["name"] == "esp-idf" for c in found):
            found.append({
                "name": "esp-idf",
                "version": idf,
                "purl": f"pkg:github/espressif/esp-idf@{idf}",
                "supplier": "Espressif Systems",
                "description": "ESP-IDF, the Espressif IoT Development "
                               "Framework the image was built with",
                "evidence": f"esp_app_desc_t at offset "
                            f"0x{image['segments'][0]['offset']:x} declares "
                            f"idf_ver {idf!r}",
                "type": "framework",
            })
        name = application.get("project_name")
        if name and not any(c["name"] == name for c in found):
            found.append({
                "name": name,
                "version": application.get("app_version"),
                "purl": f"pkg:generic/{name}"
                        + (f"@{application['app_version']}"
                           if application.get("app_version") else ""),
                "supplier": None,
                "description": "The application this image was built from, as "
                               "named in its ESP-IDF app descriptor"
                               + (f"; built {application['build_date']}"
                                  if application.get("build_date") else ""),
                "evidence": f"esp_app_desc_t declares project_name {name!r}",
                "type": "application",
            })
    return found


def packages_to_components(rootfs):
    """Turn an on-image package database into component records.

    These are a different class of evidence from a signature match. A version
    banner in a binary is a heuristic; the package manager's status file is the
    build system's own record of what it installed. Confidence is 0.97 - the
    same ceiling everything else obeys, because the file still had to be read
    out of a firmware image that could have been altered.
    """
    if not rootfs or not rootfs.get("packages"):
        return []
    database = rootfs["packages"]
    components = []
    for package in database["packages"]:
        purl = f"{package['purl_type']}/{package['name']}"
        if package["version"]:
            purl += f"@{package['version']}"
        components.append({
            "name": package["name"],
            "version": package["version"],
            "purl": purl,
            "description": package["description"][:400],
            "manager": database["manager"],
            "source_path": database["path"],
            "architecture": package["architecture"],
            "license": package.get("license"),
            "cpe": package.get("cpe"),
            "source": package.get("source"),
            "depends": package.get("depends") or [],
            "confidence": 0.97 if package["version"] else 0.9,
        })
    return components


# --------------------------------------------------------------------------- #
# CycloneDX 1.6 output
# --------------------------------------------------------------------------- #

def detected_format(source, segments):
    """What the file is, in one line, from the structures fw2sbom parsed.

    file(1) gives this on Linux, and the portable package runs on Windows,
    where there is no file(1) - so fw2sbom:file_magic was always empty for
    the customers who use the package. Rather than imitate libmagic, this
    describes what the analysis actually found and read: "U-Boot FIT image +
    SquashFS 4.0 (xz) + OpenWrt image metadata" says more than a magic
    number does. It is its own property, never passed off as file(1)'s.
    """
    parts = []

    def add(text):
        if text and text not in parts:
            parts.append(text)

    if source and source.get("converted"):
        add(f"{source['format']} (reassembled)")
    segments = segments or []
    nested = next((s for s in segments if "expanded_offset" in s), None)
    if nested:
        match = re.search(r"in the (\w+) region", nested["label"])
        add(f"{match.group(1) if match else 'compressed'}-compressed image")
    if any(s.get("region") for s in segments):
        add("Intel flash descriptor")
    volumes = sum(1 for s in segments if s["kind"] == "firmware-volume")
    if volumes:
        add(f"UEFI firmware ({volumes} firmware volume(s))")
    for segment in segments:
        kind, label = segment["kind"], segment["label"]
        short = label.split(" (in the ")[0]
        if segment.get("espressif"):
            add(f"Espressif image ({segment['espressif'].get('chip') or 'ESP32'})")
        elif segment.get("fit"):
            add("U-Boot FIT image")
        elif segment.get("uimage") and kind == "boot-header":
            header = segment["uimage"]
            add(f"U-Boot legacy uImage ({header['os']}/{header['architecture']}, "
                f"{header['compression'] or 'uncompressed'})")
        elif kind == "vendor-header":
            add(short)
        elif kind == "partition-table":
            add(short.split(" (")[0])
        elif kind == "filesystem" and "initramfs" in short:
            add("initramfs (cpio, built into the kernel)" if "inside" in short
                else "initramfs (cpio)")
        elif kind in ("filesystem", "unread-filesystem"):
            if kind == "unread-filesystem":
                short = short.split(":")[-1].split(",")[0].strip() + " (not readable)"
            if "UBI volume" in short:
                add("UBI")
                short = short.split(": ", 1)[-1].split(" (at ")[0]
            add(short.split(" (little-endian)")[0].split(" (big-endian)")[0]
                if short.startswith(("CramFS", "JFFS2", "YAFFS")) else short)
        elif kind == "image-metadata":
            add("OpenWrt image metadata")
    updates = sum(1 for s in segments if s["kind"] == "microcode")
    if updates:
        add(f"{updates} Intel microcode update(s)")
    if not parts and source:
        add(source["format"])
    return " + ".join(parts[:6]) or None


def build_sbom(input_path, data, file_magic, arm_info, hits, min_str_len, n_strings,
               container=None, opacity=None, payload=None, standards=None,
               firmware_version=None, segments=None, rootfs=None, packages=None,
               vendor=None, source=None):
    fname = os.path.basename(input_path)
    hashes = file_hashes(data)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    offset_space = "payload (container framing stripped)" if container else "file"

    fw_props = [
        {"name": "fw2sbom:file_size_bytes", "value": str(len(data))},
        {"name": "fw2sbom:architecture",
         "value": arm_info.get("label") or "unidentified"},
        {"name": "fw2sbom:cortex_m_vector_table",
         "value": "detected" if arm_info["looks_like_cortex_m"] else "not-detected"},
    ]
    if arm_info.get("mcs51"):
        fw_props.append({
            "name": "fw2sbom:mcs51_vector_table",
            "value": "detected" if arm_info["mcs51"]["looks_like_mcs51"]
                     else "not-detected"})
    for d in arm_info["details"]:
        fw_props.append({"name": "fw2sbom:vector_table_detail", "value": d})
    if file_magic:
        fw_props.append({"name": "fw2sbom:file_magic", "value": file_magic})
    described = detected_format(source, segments)
    if described:
        fw_props.append({"name": "fw2sbom:detected_format", "value": described})
    if source and source.get("converted"):
        # Every offset in the evidence below refers to the image we rebuilt,
        # not to the delivered file. Saying so is the difference between a
        # reproducible finding and a confusing one.
        fw_props.append({"name": "fw2sbom:input_format",
                         "value": source["format"]})
        fw_props.append({"name": "fw2sbom:reassembled_bytes",
                         "value": str(len(source["data"]))})
        if source.get("base_address") is not None:
            fw_props.append({"name": "fw2sbom:image_base_address",
                             "value": f"0x{source['base_address']:x}"})
        if source.get("entry_point") is not None:
            fw_props.append({"name": "fw2sbom:entry_point",
                             "value": f"0x{source['entry_point']:x}"})
        if source.get("family_id"):
            fw_props.append({"name": "fw2sbom:uf2_family_id",
                             "value": source["family_id"]})
        if source.get("gaps_filled"):
            fw_props.append({
                "name": "fw2sbom:padding_inserted_bytes",
                "value": str(source["gaps_filled"])})
        for warning in source.get("warnings", [])[:6]:
            fw_props.append({"name": "fw2sbom:input_note", "value": warning})
        fw_props.append({
            "name": "fw2sbom:offset_basis",
            "value": "offsets in this document refer to the reassembled "
                     "image, not to byte positions in the delivered file"})
    for segment in segments or []:
        chain = segment.get("vendor_container")
        if not chain:
            continue
        # Which wrapper a file arrived in is provenance: it says whose tooling
        # produced it, and it is the difference between "we could not read
        # this" and "we did not recognise the 32 bytes at the front".
        fw_props.append({
            "name": "fw2sbom:vendor_container",
            "value": " > ".join(c["label"] for c in chain)})
        for found in chain:
            if found.get("board"):
                fw_props.append({"name": "fw2sbom:vendor_board",
                                 "value": found["board"]})
            for note in found["notes"]:
                fw_props.append({"name": "fw2sbom:vendor_container_note",
                                 "value": note})
        break

    inventory = uefi_inventory(segments)
    if inventory:
        named = sum(1 for m in inventory["modules"] if m["name"])
        fw_props.append({"name": "fw2sbom:uefi_firmware_volumes",
                         "value": str(inventory["volumes"])})
        fw_props.append({"name": "fw2sbom:uefi_modules",
                         "value": str(len(inventory["modules"]))})
        fw_props.append({"name": "fw2sbom:uefi_modules_named",
                         "value": str(named)})
        if inventory["expanded_bytes"]:
            fw_props.append({"name": "fw2sbom:uefi_expanded_bytes",
                             "value": str(inventory["expanded_bytes"])})
        for note in inventory["unreadable"][:MAX_EVIDENCE_PER_COMPONENT]:
            # A section we could not expand hides modules. Saying so is the
            # difference between an incomplete inventory and a wrong one.
            fw_props.append({"name": "fw2sbom:uefi_not_expanded", "value": note})
        for volume in inventory["data_volumes"]:
            fw_props.append({
                "name": "fw2sbom:uefi_data_volume",
                "value": f"{volume['filesystem']} at 0x{volume['offset']:x}, "
                         f"{volume['length']} bytes: holds UEFI variables "
                         "rather than modules and was not enumerated"})

    image = espressif_image(segments)
    if image:
        fw_props.append({"name": "fw2sbom:espressif_chip", "value": image["chip"]})
        if image.get("core"):
            fw_props.append({"name": "fw2sbom:espressif_core",
                             "value": image["core"]})
        fw_props.append({"name": "fw2sbom:espressif_entry_point",
                         "value": f"0x{image['entry_point']:08x}"})
        application = image.get("app") or {}
        for key, label in (("build_date", "build_date"),
                           ("build_time", "build_time"),
                           ("elf_sha256", "application_elf_sha256")):
            if application.get(key):
                fw_props.append({"name": f"fw2sbom:espressif_{label}",
                                 "value": application[key]})

    fw_props.extend(boot_container_properties(segments or []))

    for i, segment in enumerate(segments or [], 1):
        detail = (f"{segment['kind']} at 0x{segment['offset']:x}, "
                  f"{segment['length']} bytes: {segment['label']}")
        if segment.get("blank"):
            detail += " (erased flash, no content)"
        elif segment.get("expanded"):
            detail += f" (expanded to {len(segment['content'] or b'')} bytes)"
        elif segment["content"] is None and segment["kind"] != "filesystem":
            detail += " (not expanded)"
        verdict = segment.get("opacity")
        if verdict:
            detail += (f" [verdict {verdict['verdict']}, entropy "
                       f"{verdict['entropy']:.3f}]")
        for warning in segment.get("warnings", [])[:2]:
            detail += f" [{warning}]"
        fw_props.append({"name": f"fw2sbom:segment_{i}", "value": detail})
    if rootfs:
        fw_props.append({"name": "fw2sbom:rootfs_files",
                         "value": str(rootfs["file_count"])})
        binaries = rootfs.get("binaries") or {}
        if binaries.get("architecture"):
            # A Linux image has no vector table to recognise; the ELF headers
            # inside it are the only place the instruction set is stated.
            fw_props.append({"name": "fw2sbom:rootfs_architecture",
                             "value": binaries["architecture"]})
        if binaries.get("binary_count"):
            fw_props.append({"name": "fw2sbom:rootfs_elf_binaries",
                             "value": str(binaries["binary_count"])})
        if binaries.get("file_dependency_count"):
            fw_props.append({
                "name": "fw2sbom:linked_library_dependencies",
                "value": str(binaries["file_dependency_count"])})
        if binaries.get("modules"):
            fw_props.append({"name": "fw2sbom:kernel_modules",
                             "value": str(len(binaries["modules"]))})
        for toolchain in sorted(binaries.get("toolchains") or {})[:3]:
            fw_props.append({"name": "fw2sbom:rootfs_toolchain",
                             "value": toolchain})
        if rootfs.get("packages"):
            fw_props.append({"name": "fw2sbom:package_database",
                             "value": f"{rootfs['packages']['path']} "
                                      f"({rootfs['packages']['manager']}, "
                                      f"{len(rootfs['packages']['packages'])} entries)"})

    if container:
        fw_props += [
            {"name": "fw2sbom:container", "value": "packetized-record-framing"},
            {"name": "fw2sbom:container_record_stride",
             "value": str(container["stride"])},
            {"name": "fw2sbom:container_file_header_bytes",
             "value": str(container["header_bytes"])},
            {"name": "fw2sbom:container_records", "value": str(container["records"])},
            {"name": "fw2sbom:container_layout", "value": container["layout"]},
            {"name": "fw2sbom:container_payload_bytes",
             "value": str(container["payload_bytes"])},
            {"name": "fw2sbom:container_trailing_bytes",
             "value": str(container["trailing_bytes"])},
            {"name": "fw2sbom:container_coverage", "value": str(container["coverage"])},
            {"name": "fw2sbom:container_framing_resolution",
             "value": container["framing_resolution"]},
        ]
        if container["length_byte"]:
            fw_props.append({"name": "fw2sbom:container_length_byte",
                             "value": container["length_byte"]})
    if opacity:
        fw_props += [
            {"name": "fw2sbom:payload_verdict", "value": opacity["verdict"]},
        ] + ([
            {"name": "fw2sbom:payload_verdict_before_reconciliation",
             "value": opacity["original_verdict"]},
        ] if opacity.get("original_verdict") else []) + [
            {"name": "fw2sbom:payload_entropy_bits_per_byte",
             "value": str(opacity["entropy"])},
            {"name": "fw2sbom:payload_longest_identical_run",
             "value": str(opacity["longest_run"])},
            {"name": "fw2sbom:payload_chi_square", "value": str(opacity["chi_square"])},
            {"name": "fw2sbom:payload_printable_ratio",
             "value": str(opacity["printable_ratio"])},
            {"name": "fw2sbom:payload_duplicate_16b_blocks",
             "value": str(opacity["duplicate_16b_blocks"])},
        ]

    components = []
    dep_refs = []
    for i, hit in enumerate(hits, 1):
        sig, conf = hit["sig"], hit["confidence"]
        ref = f"component-{i}-{sig['name']}"
        exact_version = hit["version"] and not hit.get("version_inferred")
        purl = sig["purl"] + (f"@{hit['version']}" if exact_version else "")
        files_found_in = hit.get("files") or []
        source_file = hit.get("file")
        where = (f"{hit.get('file_kind', 'a file')} in the root filesystem, "
                 f"{source_file}"
                 if source_file
                 else f"the {hit.get('segment') or offset_space}")
        methods = []
        for pat, offset, text, _v in hit["evidence"]:
            methods.append({
                "technique": "binary-analysis",
                "confidence": pat["weight"],
                "value": f"regex '{pat['regex']}' matched '{text}' "
                         f"at offset 0x{offset:x} in {where}",
            })
        comp = {
            "type": sig["type"],
            "bom-ref": ref,
            "name": sig["name"],
            "description": sig["description"],
            "purl": purl,
            "evidence": {
                "identity": [{
                    "field": "name",
                    "confidence": conf,
                    "methods": methods,
                }],
                "occurrences": [{
                    "location": fname,
                    "additionalContext":
                        f"first match at offset 0x{hit['evidence'][0][1]:x} "
                        f"in {where}",
                }],
            },
            "properties": [
                {"name": "fw2sbom:confidence", "value": str(conf)},
                {"name": "fw2sbom:confidence_level", "value": confidence_level(conf)},
                {"name": "fw2sbom:evidence_class", "value": "signature"},
                {"name": "fw2sbom:matched_patterns", "value": str(len(hit["evidence"]))},
            ],
        }
        if sig.get("supplier"):
            comp["supplier"] = {"name": sig["supplier"]}
        if hit.get("segments"):
            comp["properties"].append(
                {"name": "fw2sbom:found_in_segments",
                 "value": ", ".join(hit["segments"])})
        ordered = ([source_file] + [f for f in files_found_in if f != source_file]
                   if source_file else files_found_in)
        for path in ordered[:MAX_EVIDENCE_PER_COMPONENT]:
            comp["evidence"]["occurrences"].append({"location": path})
        if files_found_in:
            comp["properties"].append(
                {"name": "fw2sbom:found_in_files",
                 "value": str(len(files_found_in))})
            comp["properties"].append(
                {"name": "fw2sbom:evidence_file_kind",
                 "value": hit.get("file_kind", "a file")})
        if hit["version"]:
            comp["version"] = hit["version"]
            inferred = hit.get("version_inferred")
            vconf = 0.4 if inferred else conf
            vmethods = ([{"technique": "other", "confidence": vconf,
                          "value": inferred}] if inferred else methods[:1])
            comp["evidence"]["identity"].append({
                "field": "version",
                "confidence": vconf,
                "methods": vmethods,
            })
            comp["properties"].append(
                {"name": "fw2sbom:version_source",
                 "value": "inferred" if inferred else "exact-version-string"})
        else:
            comp["properties"].append(
                {"name": "fw2sbom:version", "value": "unknown (no version string found)"})
            # "we could not find a version" and "this component never carries
            # one" are different findings. Whoever matches this SBOM against a
            # CVE feed needs to know which of the two they are looking at.
            if sig.get("version_note"):
                comp["properties"].append(
                    {"name": "fw2sbom:version_unavailable_reason",
                     "value": sig["version_note"]})
        components.append(comp)
        dep_refs.append(ref)

    for i, std in enumerate(standards or [], 1):
        ref = f"standard-{i}-{std['name']}"
        purl = std["purl"] + (f"@{std['version']}" if std["version"] else "")
        methods = [{"technique": "binary-analysis",
                    "confidence": std["confidence"],
                    "value": e} for e in std["evidence"][:MAX_EVIDENCE_PER_COMPONENT]]
        comp = {
            "type": std["type"],
            "bom-ref": ref,
            "name": std["name"],
            "supplier": {"name": std["supplier"]},
            "description": std["description"],
            "purl": purl,
            "evidence": {
                "identity": [{
                    "field": "name",
                    "confidence": std["confidence"],
                    "methods": methods,
                }],
                "occurrences": [
                    {"location": fname,
                     "additionalContext": f"offset 0x{o:x} of the {offset_space}"}
                    for o in std["occurrences"][:MAX_EVIDENCE_PER_COMPONENT]
                ],
            },
            "properties": [
                {"name": "fw2sbom:confidence", "value": str(std["confidence"])},
                {"name": "fw2sbom:confidence_level",
                 "value": confidence_level(std["confidence"])},
                {"name": "fw2sbom:evidence_class", "value": "embedded-standard-data"},
            ] + [{"name": k, "value": v} for k, v in std["properties"]],
        }
        if std["version"]:
            comp["version"] = std["version"]
            comp["evidence"]["identity"].append({
                "field": "version",
                "confidence": std["confidence"],
                "methods": methods[:1],
            })
            comp["properties"].append({"name": "fw2sbom:version_source",
                                       "value": "parsed-from-structure"})
        components.append(comp)
        dep_refs.append(ref)

    # Packages read from the image's own package database. This is a
    # different class of evidence from a signature match: not a version banner
    # found in a binary, but the package manager's record of what was
    # installed. It is the best component data a Linux firmware image contains.
    for i, package in enumerate(packages or [], 1):
        ref = f"package-{i}-{package['name']}"
        evidence_value = (
            f"listed in {package['source_path']} "
            f"({package['manager']} package database) with version "
            f"{package['version'] or 'unset'}")
        comp = {
            "type": "library",
            "bom-ref": ref,
            "name": package["name"],
            "description": package["description"],
            "purl": package["purl"],
            "evidence": {
                "identity": [{
                    "field": "name",
                    "confidence": package["confidence"],
                    "methods": [{"technique": "filename",
                                 "confidence": package["confidence"],
                                 "value": evidence_value}],
                }],
                "occurrences": [{"location": package["source_path"]}],
            },
            "properties": [
                {"name": "fw2sbom:confidence", "value": str(package["confidence"])},
                {"name": "fw2sbom:confidence_level",
                 "value": confidence_level(package["confidence"])},
                {"name": "fw2sbom:evidence_class", "value": "package-database"},
                {"name": "fw2sbom:package_manager", "value": package["manager"]},
            ],
        }
        if package["architecture"]:
            comp["properties"].append({"name": "fw2sbom:target_architecture",
                                       "value": package["architecture"]})
        if package.get("license"):
            # The package's own declaration, not a guess from file contents.
            comp["licenses"] = [{"license": {"name": package["license"]}}]
            comp["properties"].append({"name": "fw2sbom:license_source",
                                       "value": "package-database"})
        if package.get("cpe"):
            # Declared by the build system that produced the image. Reading a
            # stated identifier is not the same as inferring one, so it is
            # recorded as-is and labelled with where it came from.
            comp["cpe"] = package["cpe"]
            comp["properties"].append({"name": "fw2sbom:cpe_source",
                                       "value": "declared-in-package-database"})
        if package.get("source"):
            comp["properties"].append({"name": "fw2sbom:source_package",
                                       "value": package["source"]})
        if package["version"]:
            comp["version"] = package["version"]
            comp["evidence"]["identity"].append({
                "field": "version",
                "confidence": package["confidence"],
                "methods": [{"technique": "filename",
                             "confidence": package["confidence"],
                             "value": evidence_value}],
            })
            comp["properties"].append({"name": "fw2sbom:version_source",
                                       "value": "package-database"})
        components.append(comp)
        dep_refs.append(ref)

    # The distribution itself, when the rootfs names it.
    release = (rootfs or {}).get("os_release")
    if release:
        ref = "operating-system"
        detail = [f"{k} = {v}" for k, v in sorted(release["fields"].items())]
        components.append({
            "type": "operating-system",
            "bom-ref": ref,
            "name": release["name"],
            "version": release["version"] or "unknown",
            "description": release["description"],
            "evidence": {
                "identity": [{
                    "field": "name",
                    "confidence": 0.97,
                    "methods": [{"technique": "filename", "confidence": 0.97,
                                 "value": f"read from {release['path']}"}],
                }],
                "occurrences": [{"location": release["path"]}],
            },
            "properties": ([
                {"name": "fw2sbom:evidence_class", "value": "os-release-file"},
                {"name": "fw2sbom:confidence", "value": "0.97"},
                {"name": "fw2sbom:confidence_level", "value": "high"},
            ] + [{"name": f"fw2sbom:distribution_detail", "value": d}
                 for d in detail[:12]]),
        })
        dep_refs.append(ref)

    # A BIOS is an inventory of modules, and the image names them itself.
    # No purl is emitted: a UEFI module is not a package in any ecosystem, and
    # inventing pkg:generic/<name> would hand a CVE matcher an identity that
    # does not exist. The GUID is the identity, and it is exact.
    for index, item in enumerate(uefi_components(segments), 1):
        ref = f"uefi-{index}-{item['guid']}"
        comp = {
            "type": uefi_component_type(item["module_type"]),
            "bom-ref": ref,
            "name": item["name"],
            "description": (f"UEFI firmware module of type "
                            f"{item['module_type']}, {item['size']} bytes"),
            "evidence": {
                "identity": [{
                    "field": "name", "confidence": item["confidence"],
                    "methods": [{"technique": "binary-analysis",
                                 "confidence": item["confidence"],
                                 "value": item["evidence"]}],
                }],
                "occurrences": [{"location": fname}],
            },
            "properties": [
                {"name": "fw2sbom:confidence", "value": str(item["confidence"])},
                {"name": "fw2sbom:confidence_level",
                 "value": confidence_level(item["confidence"])},
                {"name": "fw2sbom:evidence_class", "value": "uefi-module"},
                {"name": "fw2sbom:uefi_guid", "value": item["guid"]},
                {"name": "fw2sbom:uefi_module_type", "value": item["module_type"]},
                {"name": "fw2sbom:uefi_volume", "value": item["volume"]},
            ],
        }
        if item["version"]:
            comp["version"] = item["version"]
            comp["properties"].append(
                {"name": "fw2sbom:version_source", "value": "uefi-version-section"})
            comp["properties"].append(
                {"name": "fw2sbom:version_note",
                 "value": "the module's own VERSION section, which describes "
                          "the module and not any library inside it; EDK2 "
                          "builds almost always leave it at 1.0"})
        components.append(comp)
        dep_refs.append(ref)

    # CPU microcode: what Intel's advisories are written against.
    for index, item in enumerate(microcode_components(segments or []), 1):
        update = item["update"]
        ref = f"microcode-{index}-{update['cpuid']:x}-{update['revision']:x}"
        properties = [
            {"name": "fw2sbom:confidence", "value": "0.97"},
            {"name": "fw2sbom:confidence_level", "value": "high"},
            {"name": "fw2sbom:evidence_class", "value": "cpu-microcode"},
            {"name": "fw2sbom:cpuid", "value": f"0x{update['cpuid']:x}"},
            {"name": "fw2sbom:microcode_platform_flags",
             "value": f"0x{update['platforms']:x}"},
            {"name": "fw2sbom:microcode_date", "value": update["date"]},
            {"name": "fw2sbom:version_source", "value": "microcode-header"},
        ]
        if update["extended"]:
            properties.append({"name": "fw2sbom:microcode_also_cpuid",
                               "value": ", ".join(f"0x{e['cpuid']:x}"
                                                  for e in update["extended"])})
        components.append({
            "type": "firmware",
            "bom-ref": ref,
            "supplier": {"name": "Intel"},
            "name": item["name"],
            "version": item["version"],
            "description": (f"Intel CPU microcode update for family "
                            f"{update['family']:x}h model {update['model']:x}h "
                            f"stepping {update['stepping']:x}, {update['size']} bytes"),
            "evidence": {
                "identity": [{
                    "field": "name", "confidence": 0.97,
                    "methods": [{"technique": "binary-analysis", "confidence": 0.97,
                                 "value": item["evidence"]}],
                }],
                "occurrences": [{"location": fname,
                                 "additionalContext": f"offset 0x{update['offset']:x}"}],
            },
            "properties": properties,
        })
        dep_refs.append(ref)

    # What an Espressif image states about itself: the framework version and
    # the application name come out of a struct, not a regex.
    for index, item in enumerate(espressif_components(segments), 1):
        ref = f"espressif-{index}-{item['name']}"
        comp = {
            "type": item["type"],
            "bom-ref": ref,
            "name": item["name"],
            "description": item["description"],
            "purl": item["purl"],
            "evidence": {
                "identity": [{
                    "field": "name", "confidence": 0.97,
                    "methods": [{"technique": "binary-analysis",
                                 "confidence": 0.97, "value": item["evidence"]}],
                }],
                "occurrences": [{"location": fname}],
            },
            "properties": [
                {"name": "fw2sbom:confidence", "value": "0.97"},
                {"name": "fw2sbom:confidence_level", "value": "high"},
                {"name": "fw2sbom:evidence_class",
                 "value": "esp-idf-app-descriptor"},
            ],
        }
        if item["supplier"]:
            comp["supplier"] = {"name": item["supplier"]}
        if item["version"]:
            comp["version"] = item["version"]
            comp["properties"].append({"name": "fw2sbom:version_source",
                                       "value": "app-descriptor"})
        components.append(comp)
        dep_refs.append(ref)

    # Components the vendor declared. These are a different kind of claim from
    # everything above: no offset, no matched string, no confidence from us -
    # a supplier's assertion. Merging them without saying so would turn an
    # evidence-based document into a mixture nobody can audit, so each one
    # names the document it came from and carries no fabricated confidence.
    for document_index, entry in enumerate(vendor or [], 1):
        identity = entry["document"]
        conflicting = {id(c["vendor"]) for c in entry["conflicts"]}
        agreeing = {id(a["vendor"]) for a in entry["agreements"]}
        citation = (f"declared in {identity['file']} ({identity['format']}"
                    + (f", produced by {identity['produced_by']}"
                       if identity["produced_by"] else "")
                    + (f", {identity['timestamp']}" if identity["timestamp"]
                       else "") + ")")
        for i, component in enumerate(entry["components"], 1):
            ref = f"vendor-{document_index}-{i}-{component['name']}"
            properties = [
                {"name": "fw2sbom:evidence_class", "value": "vendor-sbom"},
                {"name": "fw2sbom:source_document", "value": identity["file"]},
                {"name": "fw2sbom:source_format", "value": identity["format"]},
            ]
            if identity.get("identifier"):
                properties.append({"name": "fw2sbom:source_identifier",
                                   "value": identity["identifier"]})
            if id(component) in conflicting:
                conflict = next(c for c in entry["conflicts"]
                                if c["vendor"] is component)
                properties.append(
                    {"name": "fw2sbom:vendor_conflict",
                     "value": f"the vendor declares {conflict['vendor_version']}; "
                              f"this image contains {conflict['our_version']}"})
            elif id(component) in agreeing:
                properties.append({"name": "fw2sbom:vendor_corroborated",
                                   "value": "also observed in this image"})
            else:
                properties.append(
                    {"name": "fw2sbom:vendor_unverified",
                     "value": "declared by the vendor; not observed in this "
                              "image, which neither confirms nor refutes it"})

            component_entry = {
                "type": component["type"],
                "bom-ref": ref,
                "name": component["name"],
                "description": component.get("description")
                               or f"Declared by the firmware vendor in "
                                  f"{identity['file']}",
                "evidence": {
                    "identity": [{
                        "field": "name",
                        # No confidence of our own: we did not observe this.
                        "confidence": 0.0,
                        "methods": [{"technique": "other", "confidence": 0.0,
                                     "value": citation}],
                    }],
                    "occurrences": [{"location": identity["file"]}],
                },
                "properties": properties,
            }
            if component.get("version"):
                component_entry["version"] = component["version"]
            if component.get("purl"):
                component_entry["purl"] = component["purl"]
            if component.get("cpe"):
                component_entry["cpe"] = component["cpe"]
            if component.get("supplier"):
                component_entry["supplier"] = {"name": component["supplier"]}
            if component.get("licenses"):
                component_entry["licenses"] = [
                    {"license": {"name": name}} for name in component["licenses"]]
            components.append(component_entry)
            dep_refs.append(ref)

    for index, segment in enumerate(opaque_segments(segments or []), 1):
        verdict = segment.get("opacity") or {}
        raw_length = segment["length"]
        ref = f"opaque-segment-{index}"
        reasons = list(verdict.get("reasons") or [])
        if (segment["content"] is None and not verdict
                and not segment.get("unread_reason")):
            reasons.append("this region could not be expanded, so its contents "
                           "were never available to analyse")
        for warning in segment.get("warnings", [])[:3]:
            reasons.append(warning)
        components.append({
            "type": "firmware",
            "bom-ref": ref,
            "name": f"{fname}:{segment['label']}",
            "description":
                f"Unenumerable region at offset 0x{segment['offset']:x} "
                f"({raw_length} bytes): {segment['label']}. Its contents are "
                "encrypted, obfuscated or otherwise unavailable to static "
                "analysis, so the components inside it are unknown. Request a "
                "plaintext image or the vendor's own SBOM for this region.",
            "evidence": {
                "identity": [{
                    "field": "name",
                    "confidence": 0.0,
                    "methods": [{"technique": "binary-analysis",
                                 "confidence": 0.0, "value": reason}
                                for reason in reasons[:MAX_EVIDENCE_PER_COMPONENT]]
                              or [{"technique": "binary-analysis",
                                   "confidence": 0.0,
                                   "value": "region not expanded"}],
                }],
                "occurrences": [{
                    "location": fname,
                    "additionalContext":
                        f"offset 0x{segment['offset']:x}, {raw_length} bytes",
                }],
            },
            "properties": [
                {"name": "fw2sbom:opaque", "value": "true"},
                {"name": "fw2sbom:opacity_verdict",
                 "value": verdict.get("verdict", "not expanded")},
                {"name": "fw2sbom:segment_offset",
                 "value": f"0x{segment['offset']:x}"},
                {"name": "fw2sbom:segment_bytes", "value": str(raw_length)},
                {"name": "fw2sbom:analysis_result",
                 "value": "content not enumerable; vendor SBOM required"},
            ] + ([{"name": "fw2sbom:payload_entropy_bits_per_byte",
                   "value": str(verdict["entropy"])}] if verdict else []),
        })
        dep_refs.append(ref)

    if (opacity and opacity["opaque"] and payload is not None
            and not opaque_segments(segments or [])):
        ref = "firmware-payload-opaque"
        encrypted = not opacity["compression"]
        components.append({
            "type": "firmware",
            "bom-ref": ref,
            "name": f"{fname}:payload",
            "description":
                "Unidentified firmware payload. The image content is "
                + ("encrypted or obfuscated" if encrypted else opacity["verdict"])
                + " and cannot be enumerated by static analysis. Its components are "
                  "unknown - request a plaintext image or the vendor's own SBOM from "
                  "the firmware supplier.",
            "hashes": [{"alg": a, "content": h}
                       for a, h in file_hashes(payload).items()],
            "evidence": {
                "identity": [{
                    "field": "name",
                    "confidence": 0.0,
                    "methods": [{
                        "technique": "binary-analysis",
                        "confidence": 0.0,
                        "value": reason,
                    } for reason in opacity["reasons"][:MAX_EVIDENCE_PER_COMPONENT]],
                }],
                "occurrences": [{
                    "location": fname,
                    "additionalContext":
                        f"{len(payload)} payload bytes"
                        + (f" de-framed from {container['records']} records"
                           if container else ""),
                }],
            },
            "properties": [
                {"name": "fw2sbom:opaque", "value": "true"},
                {"name": "fw2sbom:opacity_verdict", "value": opacity["verdict"]},
                {"name": "fw2sbom:analysis_result",
                 "value": "content not enumerable; vendor SBOM required"},
                {"name": "fw2sbom:payload_size_bytes", "value": str(len(payload))},
            ],
        })
        dep_refs.append(ref)

    bom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "lifecycles": [{"phase": "post-build"}],
            "tools": {
                "components": [{
                    "type": "application",
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "description": "Binary fingerprint + string signature SBOM extractor",
                }]
            },
            "component": {
                "type": "firmware",
                "bom-ref": f"firmware:{hashes['SHA-256'][:24]}",
                "name": fname,
                "version": firmware_version or "UNKNOWN",
                "hashes": [{"alg": a, "content": h} for a, h in hashes.items()],
                "properties": fw_props,
            },
            "properties": [
                {"name": "fw2sbom:sbom_type", "value": "binary-derived"},
                {"name": "fw2sbom:analysis_methods",
                 "value": "file(1) magic, packetized-container de-framing, "
                          "printable-string extraction (ASCII and UTF-16LE), "
                          "signature/regex matching, "
                          "instruction-set identification (Cortex-M / MCS-51), "
                          "embedded standard-data parsing (VESA E-EDID, DDC/CI "
                          "MCCS), entropy/opacity analysis"},
                {"name": "fw2sbom:offset_reference", "value": offset_space},
            ] + [
                {"name": "fw2sbom:vendor_sbom",
                 "value": f"{e['document']['file']} ({e['document']['format']}): "
                          f"{len(e['components'])} component(s), "
                          f"{len(e['agreements'])} corroborated, "
                          f"{len(e['conflicts'])} in conflict, "
                          f"{len(e['vendor_only'])} not observed"}
                for e in (vendor or [])
            ] + [
                {"name": "fw2sbom:vendor_version_conflict",
                 "value": f"{c['vendor']['name']}: vendor declares "
                          f"{c['vendor_version']}, image contains "
                          f"{c['our_version']}"}
                for e in (vendor or []) for c in e["conflicts"]
            ] + [
                {"name": "fw2sbom:signature_database_size",
                 "value": str(len(get_signatures()))},
                {"name": "fw2sbom:signature_packs",
                 "value": ", ".join(SIGNATURE_PACKS)},
                {"name": "fw2sbom:strings_extracted", "value": str(n_strings)},
                {"name": "fw2sbom:min_string_length", "value": str(min_str_len)},
                {"name": "fw2sbom:disclaimer",
                 "value": "This SBOM was derived from static analysis of a stripped "
                          "firmware binary. Component identification and versions are "
                          "heuristic (evidence-based) and may be incomplete or "
                          "inaccurate. Absence of a component is not evidence of "
                          "absence."},
                {"name": "fw2sbom:opacity_disclaimer",
                 "value": "An 'opaque' verdict means the payload is encrypted, "
                          "obfuscated or compressed with an unrecognised scheme. No "
                          "static tool can enumerate components in that state; the "
                          "SBOM is therefore metadata-only by necessity and must be "
                          "completed from a vendor-supplied SBOM or plaintext image."},
            ],
        },
        "components": components,
        "dependencies": _dependency_graph(
            f"firmware:{hashes['SHA-256'][:24]}", dep_refs,
            packages or [], rootfs),
    }
    return bom


def _dependency_graph(root_ref, dep_refs, packages, rootfs):
    """CycloneDX dependencies, with real edges where we can establish them.

    Everything hangs off the firmware, as before. On top of that, a Linux
    image tells us two independent things about what depends on what: the
    package manager's declared Depends, and the DT_NEEDED entries the linker
    actually recorded in each binary. Declared dependencies are authoritative
    about intent; DT_NEEDED is evidence of what was really linked. Both are
    used, and a package with neither simply has no outgoing edges rather than
    an invented one.
    """
    by_name = {}
    for i, package in enumerate(packages, 1):
        by_name[package["name"]] = f"package-{i}-{package['name']}"

    edges = {ref: set() for ref in dep_refs}
    if packages:
        resolved = (rootfs or {}).get("binaries", {}).get(
            "package_dependencies", {})
        for package in packages:
            ref = by_name[package["name"]]
            for target in package.get("depends") or []:
                target_ref = by_name.get(target)
                if target_ref and target_ref != ref:
                    edges[ref].add(target_ref)
            for target in resolved.get(package["name"], []):
                target_ref = by_name.get(target)
                if target_ref and target_ref != ref:
                    edges[ref].add(target_ref)

    return ([{"ref": root_ref, "dependsOn": dep_refs}]
            + [{"ref": ref, "dependsOn": sorted(edges.get(ref, ()))}
               for ref in dep_refs])


def build_evidence_context(filename, data, payload, arm_info, container,
                           opacity, hits, standards, sbom_filename):
    """Collect everything the evidence workbook needs into one dict.

    Shared by the CLI and the drag-and-drop service so both deliverable pairs are
    produced by exactly the same analysis.
    """
    matched = {h["sig"]["name"] for h in hits}
    signatures = get_signatures()
    magics = evidence_report.scan_magics(payload)
    banks = evidence_report.analyze_banks(payload)
    return {
        "filename": filename,
        "data": data,
        "hashes": file_hashes(data),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
        "tool_name": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "architecture": arm_info["label"],
        "arch_details": arm_info["details"],
        "container": container,
        "opacity": opacity,
        "hits": hits,
        "standards": standards,
        "all_signatures": signatures,
        "not_found": [s for s in signatures if s["name"] not in matched],
        "magics": magics,
        "banks": banks,
        "bank_size": banks[0]["size"] if banks else evidence_report.BANK_SIZE,
        "edid_blocks": detect_edid_blocks(payload),
        "structural_checks": [
            ("VESA E-EDID block",
             any(s["name"] == "vesa-e-edid" for s in standards)),
            ("VESA MCCS / DDC-CI capability string",
             any(s["name"] == "vesa-mccs" for s in standards)),
            ("ARM Cortex-M vector table", arm_info["looks_like_cortex_m"]),
            ("MCS-51 vector table + opcode profile",
             arm_info.get("mcs51", {}).get("looks_like_mcs51", False)),
            ("Packetized record framing", container is not None),
        ],
        "vendor_hint": None,
        "firmware_version": None,
        "n_confirmed": len(hits),
        "n_standards": len(standards),
        "n_not_found": len(signatures) - len(matched),
        "n_magic_validated": sum(1 for m in magics if m["validated_hits"]),
        "n_magic_rejected": sum(1 for m in magics
                                if m["raw_hits"] and not m["validated_hits"]),
        "sbom_filename": sbom_filename,
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

# Stages of one analysis and each one's share of the bar. The shares are an
# average over a router, a BIOS and an ESP32 flash image, and the true split
# differs a great deal between them - de-framing is 55% of an ESP32 run and 3%
# of a BIOS. So the shares only decide how far along the bar a stage sits; how
# far through a stage the bar moves is always a real count of work done.
PROGRESS_STAGES = (
    ("reading", 20),        # recognising and de-framing the container
    ("architecture", 5),
    ("entropy", 15),        # whole-image statistics
    ("segments", 50),       # walking, extracting, matching, filesystems
    ("sbom", 3),
    ("evidence", 7),        # SPDX rendering and the Excel workbook
)


class Progress:
    """Progress through one analysis, reported as work actually completes.

    Never moved by a timer. A bar that creeps forward on its own and then
    stalls at 90% is a small lie told to make a wait feel shorter, and a tool
    whose whole job is to say what it did and did not read has no business
    telling it. The bar is also monotonic: a stage finishing sooner than its
    share suggested jumps it forward, but nothing ever moves it back.

    With no sink every call is a cheap no-op, so the command line - which has
    its own verbose log - pays nothing for it.
    """

    def __init__(self, sink=None):
        self.sink = sink
        self.percent = 0.0
        self.stage = None
        self.step = 0
        self.detail = None
        self._start = 0.0
        self._weight = 0.0

    def enter(self, key, detail=None):
        start = 0.0
        for index, (name, weight) in enumerate(PROGRESS_STAGES):
            if name == key:
                self.stage, self.step = key, index + 1
                self._start, self._weight = start, float(weight)
                break
            start += weight
        else:
            raise ValueError(f"unknown progress stage {key!r}")
        self.percent = max(self.percent, self._start)
        self.detail = detail
        self._emit()

    def within(self, fraction, detail=None):
        """Move to `fraction` (0..1) of the way through the current stage."""
        fraction = min(1.0, max(0.0, fraction))
        self.percent = max(self.percent, self._start + self._weight * fraction)
        if detail is not None:
            self.detail = detail
        self._emit()

    def span(self, low, high):
        """A callback that maps a nested task's 0..1 onto [low, high] here."""
        def report(fraction, detail=None):
            fraction = min(1.0, max(0.0, fraction))
            self.within(low + (high - low) * fraction, detail)
        return report

    def finish(self):
        self.percent, self.stage, self.step = 100.0, "done", len(PROGRESS_STAGES)
        self.detail = None
        self._emit()

    def state(self):
        return {"stage": self.stage, "step": self.step,
                "steps": len(PROGRESS_STAGES),
                "percent": round(self.percent, 1), "detail": self.detail}

    def _emit(self):
        if self.sink:
            self.sink(self.state())


def run_analysis(delivered, source, name, min_str_len=6, verbose=False,
                 vendor_documents=(), no_deframe=False, firmware_version=None,
                 file_magic=None, progress=None):
    """The whole analysis, from reassembled bytes to a CycloneDX document.

    The CLI, the drag-and-drop service and the test suite all call this. They
    used to each carry their own copy of the sequence, and the copies drifted:
    per-file rootfs scanning arrived in v1.9.0 in the CLI and the tests and
    never reached the service, so for eight releases the browser - the thing
    customers actually use - dropped every component found in a Linux root
    filesystem that had no package database. Which is most CCTV firmware.
    That is the third defect of this shape, and one function is the only fix
    that stops a fourth.

    `delivered` is the file as received and `source` what image_input made of
    it; reading and reassembling stay with the caller, which knows whether it
    has a path. Returns every intermediate the callers report on.
    """
    data = source["data"]
    progress = progress or Progress()

    progress.enter("reading")
    container = None if no_deframe else detect_packet_container(
        data, verbose, progress=progress.span(0.0, 1.0))
    payload = deframe(data, container) if container else data
    if container:
        log(f"de-framed {len(payload)} payload bytes "
            f"({len(data) - len(payload)} bytes of framing/header removed)",
            verbose)

    progress.enter("architecture")
    arm_info = analyze_architecture(payload)
    log(f"architecture: {arm_info['label'] or 'not identified'}", verbose)
    for detail in arm_info["details"]:
        log(f"  {detail}", verbose)

    progress.enter("entropy")
    opacity = analyze_opacity(payload, arm_info["label"],
                              progress=progress.span(0.0, 1.0))
    log(f"payload verdict: {opacity['verdict']} "
        f"(entropy {opacity['entropy']:.3f} bits/byte)", verbose)

    standards = detect_embedded_standards(payload, verbose)

    progress.enter("segments")
    segments, rootfs, seg_warnings = analyze_segments(
        payload, min_str_len, verbose, arm_info["label"],
        progress=progress.span(0.0, 0.85))
    for warning in seg_warnings:
        log(f"container warning: {warning}", True)

    strings = [pair for segment in segments
               for pair in segment.get("strings", [])]
    log(f"extracted {len(strings)} strings across {len(segments)} segment(s) "
        f"(min length {min_str_len})", verbose)

    hits = merge_segment_hits(segments)
    hits = merge_hit_lists(hits, scan_rootfs_files(
        rootfs, min_str_len, verbose, progress=progress.span(0.85, 1.0)))
    if rootfs and rootfs.get("unread_files"):
        segments.append(unread_files_segment(rootfs["segment"],
                                             rootfs["unread_files"]))
    packages = packages_to_components(rootfs)
    for hit in hits:
        log(f"match: {hit['sig']['name']} confidence={hit['confidence']} "
            f"version={hit['version']}", verbose)
    if packages:
        log(f"{len(packages)} package(s) read from the on-image database",
            verbose)

    # Components read out of the payload settle the opacity question, and a
    # package database is the most decisive evidence of all.
    structural = structural_components(segments)
    vendor = reconcile_vendor_sboms(vendor_documents, hits, standards,
                                    packages, verbose, structural)
    opacity = summarise_opacity(segments, opacity)
    opacity = reconcile_opacity(opacity, hits + packages + structural,
                                standards, verbose)
    progress.enter("sbom")
    bom = build_sbom(name, delivered, file_magic, arm_info, hits,
                     min_str_len, len(strings),
                     container=container, opacity=opacity, payload=payload,
                     standards=standards, firmware_version=firmware_version,
                     segments=segments, rootfs=rootfs, packages=packages,
                     vendor=vendor, source=source)
    return {
        "source": source, "data": data, "container": container,
        "payload": payload, "arm_info": arm_info, "opacity": opacity,
        "standards": standards, "segments": segments, "rootfs": rootfs,
        "strings": strings, "hits": hits, "packages": packages,
        "vendor": vendor, "bom": bom, "progress": progress,
    }


# --------------------------------------------------------------------------- #
# Batch
# --------------------------------------------------------------------------- #

# Files a batch never treats as firmware: our own deliverables (a second run
# over the same folder must not analyse the first run's SBOMs) and the usual
# operating-system clutter.
BATCH_SKIP_SUFFIXES = ("_SBOM.cdx.json", "_SBOM.spdx.json", "_Evidence.xlsx",
                       ".cdx.json", ".spdx.json")
BATCH_SKIP_NAMES = ("batch-summary.csv", "batch-summary.json", "Thumbs.db",
                    "desktop.ini", ".DS_Store")


def batch_inputs(directory, recursive=False, exclude=None):
    """Every file in `directory` a batch should analyse, in a stable order."""
    exclude = os.path.abspath(exclude) if exclude else None
    found = []
    for root, dirs, files in os.walk(directory):
        if exclude and os.path.abspath(root).startswith(exclude):
            dirs[:] = []
            continue
        dirs[:] = sorted(d for d in dirs if not d.startswith(".")
                         and not (exclude and os.path.abspath(
                             os.path.join(root, d)) == exclude))
        for name in sorted(files):
            if name.startswith(".") or name in BATCH_SKIP_NAMES:
                continue
            if name.endswith(BATCH_SKIP_SUFFIXES):
                continue
            found.append(os.path.join(root, name))
        if not recursive:
            break
    return found


def batch_stems(paths, directory):
    """An output stem per input, unique even when two inputs share a name.

    firmware.bin and firmware.hex, or sub1/fw.bin and sub2/fw.bin, would
    otherwise write over each other's SBOM - silently, and the later one
    would look like the only one.
    """
    rel = [os.path.relpath(p, directory) for p in paths]
    plain = [os.path.splitext(os.path.basename(r))[0] for r in rel]
    stems = []
    for r, stem in zip(rel, plain):
        if plain.count(stem) == 1:
            stems.append(stem)
        else:
            stems.append(r.replace(os.sep, "__").replace("/", "__"))
    return stems


def analyze_to_files(path, stem, out_dir, fmt="both", pretty=False,
                     evidence=True, min_str_len=6):
    """Analyse one file and write its deliverables; never exits the process.

    Returns a summary row. Errors raise ValueError with a message meant for
    the summary, so one bad file costs the batch that file and nothing else.
    """
    if not os.path.isfile(path):
        raise ValueError("not a file")
    size = os.path.getsize(path)
    if size == 0:
        raise ValueError("the file is empty")
    if size > MAX_FILE_SIZE:
        raise ValueError(f"{size} bytes is over the {MAX_FILE_SIZE}-byte limit")
    with open(path, "rb") as f:
        delivered = f.read()
    try:
        source = image_input.detect_and_load(delivered)
    except image_input.InputFormatError as e:
        raise ValueError(f"cannot read this file: {e}")
    result = run_analysis(delivered, source, path, min_str_len=min_str_len)
    bom = result["bom"]
    base = os.path.join(out_dir, stem)
    written = {}

    def write_json(target, document):
        with open(target, "w", encoding="utf-8") as f:
            json.dump(document, f, indent=2 if pretty else None)
            f.write("\n")
        return os.path.basename(target)

    if fmt in ("cyclonedx", "both"):
        written["cyclonedx"] = write_json(base + "_SBOM.cdx.json", bom)
    if fmt in ("spdx", "both"):
        written["spdx"] = write_json(
            base + "_SBOM.spdx.json",
            spdx_report.build_spdx(bom, path, TOOL_NAME, TOOL_VERSION))
    if evidence:
        context = build_evidence_context(
            os.path.basename(path), source["data"], result["payload"],
            result["arm_info"], result["container"], result["opacity"],
            result["hits"], result["standards"],
            written.get("cyclonedx") or written.get("spdx") or "")
        evidence_report.write_evidence_workbook(base + "_Evidence.xlsx", context, bom)
        written["evidence"] = os.path.basename(base + "_Evidence.xlsx")

    components = bom.get("components", [])
    opaque = sum(1 for c in components
                 if {"name": "fw2sbom:opaque", "value": "true"}
                 in c.get("properties", []))
    rootfs = result["rootfs"] or {}
    architecture = result["arm_info"]["label"] or (
        (rootfs.get("binaries") or {}).get("architecture") or "")
    release = (rootfs.get("os_release") or {}).get("description", "")
    return {"components": len(components) - opaque, "opaque": opaque,
            "architecture": architecture, "distribution": release,
            "format": source["format"], "sha256": hashlib.sha256(delivered).hexdigest(),
            "bytes": size, "outputs": written}


BATCH_COLUMNS = ("file", "status", "sha256", "bytes", "format", "architecture",
                 "distribution", "components", "opaque", "seconds",
                 "cyclonedx", "spdx", "evidence", "error")


def run_batch(args):
    """Analyse every file in a directory; one bad file does not stop the rest.

    Writes each file's deliverables into the output directory, then a
    batch-summary.csv (opens in a spreadsheet) and batch-summary.json. The
    exit code is 0 when every file produced an SBOM and 3 when any did not,
    so a CI job can tell "all good" from "look at the summary".
    """
    directory = args.batch
    if not os.path.isdir(directory):
        die(f"--batch expects a directory: {directory}")
    out_dir = args.out_dir or os.path.join(directory, "fw2sbom-output")
    try:
        os.makedirs(out_dir, exist_ok=True)
    except OSError as e:
        die(f"cannot create output directory {out_dir}: {e}")
    paths = batch_inputs(directory, args.recursive, exclude=out_dir)
    if not paths:
        die(f"no files to analyse in {directory}")
    stems = batch_stems(paths, directory)
    print(f"[fw2sbom] batch: {len(paths)} file(s) from {directory} -> {out_dir}",
          file=sys.stderr)

    rows = []
    for index, (path, stem) in enumerate(zip(paths, stems), 1):
        relative = os.path.relpath(path, directory)
        started = time.perf_counter()
        row = {"file": relative}
        try:
            summary = analyze_to_files(path, stem, out_dir, fmt=args.format,
                                       pretty=args.pretty,
                                       evidence=not args.no_evidence,
                                       min_str_len=args.min_str_len)
        except (ValueError, OSError) as e:
            row.update(status="error", error=str(e))
        except Exception as e:                   # a bug, but not the batch's end
            row.update(status="error", error=f"analysis failed: {e}")
        else:
            outputs = summary.pop("outputs")
            row.update(status="ok", **summary, **outputs)
        row["seconds"] = round(time.perf_counter() - started, 1)
        rows.append(row)
        state = (f"{row['components']} component(s)"
                 + (f", {row['opaque']} opaque" if row.get("opaque") else "")
                 if row["status"] == "ok" else f"ERROR {row['error']}")
        print(f"[fw2sbom] [{index}/{len(paths)}] {relative}: {state} "
              f"({row['seconds']}s)", file=sys.stderr)

    csv_path = os.path.join(out_dir, "batch-summary.csv")
    json_path = os.path.join(out_dir, "batch-summary.json")
    try:
        # utf-8-sig: Excel reads the file names correctly only with the BOM.
        with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=BATCH_COLUMNS, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({"tool": TOOL_NAME, "version": TOOL_VERSION,
                       "directory": os.path.abspath(directory),
                       "files": rows}, f, indent=2)
            f.write("\n")
    except OSError as e:
        die(f"cannot write the batch summary: {e}")

    failed = sum(1 for r in rows if r["status"] != "ok")
    print(f"[fw2sbom] batch done: {len(rows) - failed} of {len(rows)} file(s) "
          f"produced an SBOM; summary -> {csv_path}", file=sys.stderr)
    return 3 if failed else 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Generate an evidence-based CycloneDX 1.6 SBOM from an ARM "
                    "Cortex-M / Zephyr-style firmware .bin via binary fingerprinting.",
        epilog="Example: %(prog)s zephyr.bin -o zephyr.sbom.json --pretty -v",
    )
    ap.add_argument("input", nargs="?",
                    help="firmware image (.bin) to analyze")
    ap.add_argument("--batch", metavar="DIR",
                    help="analyse every file in DIR instead of one input; "
                         "deliverables go to --out-dir (default DIR/fw2sbom-output) "
                         "with a batch-summary.csv and .json. Exit code 3 if any "
                         "file failed.")
    ap.add_argument("--recursive", action="store_true",
                    help="with --batch, include subdirectories")
    ap.add_argument("--no-evidence", action="store_true",
                    help="with --batch, skip the Excel evidence workbooks")
    ap.add_argument("-o", "--output", default=None,
                    help="output SBOM path (default: <input>.cdx.json)")
    ap.add_argument("-d", "--out-dir", metavar="DIR",
                    help="write both deliverables into DIR as <stem>_SBOM.cdx.json "
                         "and <stem>_Evidence.xlsx")
    ap.add_argument("--evidence", metavar="FILE",
                    help="write the Excel evidence/confidence workbook to FILE")
    ap.add_argument("--firmware-version", metavar="VERSION",
                    help="the product firmware version this image is, recorded as "
                         "the SBOM's root component version. Only the vendor knows "
                         "it reliably; without it the root component is UNKNOWN and "
                         "successive releases of a product cannot be told apart "
                         "downstream.")
    ap.add_argument("--min-str-len", type=int, default=6, metavar="N",
                    help="minimum length for extracted strings (default: 6)")
    ap.add_argument("--dump-strings", metavar="FILE",
                    help="also write all extracted strings (offset<TAB>string) to FILE")
    ap.add_argument("--vendor-sbom", metavar="FILE", action="append", default=[],
                    help="merge an SBOM supplied by the firmware vendor "
                         "(CycloneDX or SPDX JSON; repeatable). Its components "
                         "are kept distinct from ours, and any version it "
                         "declares that the image contradicts is reported.")
    ap.add_argument("--signatures", metavar="DIR", action="append", default=[],
                    help="load extra signature packs from DIR (repeatable; also "
                         "honours the FW2SBOM_SIGNATURES environment variable). "
                         "A pack may override a built-in signature of the same name.")
    ap.add_argument("--no-deframe", action="store_true",
                    help="do not detect/strip packetized container framing")
    ap.add_argument("--dump-payload", metavar="FILE",
                    help="write the de-framed payload (framing stripped) to FILE")
    ap.add_argument("--format", choices=("cyclonedx", "spdx", "both"),
                    default="cyclonedx",
                    help="SBOM format to write (default: cyclonedx). 'spdx' emits "
                         "SPDX 2.3 JSON; 'both' writes the two documents from the "
                         "same analysis, so they cannot disagree.")
    ap.add_argument("--pretty", action="store_true", help="indent JSON output")
    ap.add_argument("--fail-if-empty", action="store_true",
                    help="exit with code 2 if no components are identified")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="verbose progress on stderr")
    ap.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    args = ap.parse_args(argv)
    if bool(args.batch) == bool(args.input):
        ap.error("give either one input file or --batch DIR")
    if args.batch and (args.vendor_sbom or args.output or args.evidence
                       or args.firmware_version or args.dump_strings
                       or args.dump_payload):
        ap.error("--batch writes one set of deliverables per file; -o, "
                 "--evidence, --vendor-sbom, --firmware-version and the dump "
                 "options apply to a single input only")

    if args.min_str_len < 3:
        die("--min-str-len must be >= 3 (shorter values produce mostly noise)")

    try:
        signatures = load_signatures(args.signatures, args.verbose)
    except ValueError as e:
        die(str(e))
    log(f"signature database: {len(signatures)} signature(s) "
        f"from pack(s) {', '.join(SIGNATURE_PACKS)}", args.verbose)

    if args.batch:
        if args.format == "cyclonedx" and "--format" not in (argv or sys.argv):
            args.format = "both"                 # a batch is for handing over
        return run_batch(args)

    vendor_documents = load_vendor_sboms(args.vendor_sbom, args.verbose)

    delivered = read_binary(args.input)
    log(f"read {len(delivered)} bytes from {args.input}", args.verbose)

    # A toolchain hands out .elf, a flashing tool hands out .hex or .s19, and a
    # raw .bin is the form you have to know to ask for. Reassemble whichever
    # arrived rather than telling the customer to find objcopy.
    try:
        source = image_input.detect_and_load(
            delivered, args.verbose, lambda m: log(m, True))
    except image_input.InputFormatError as e:
        die(f"{args.input}: {e}")
    data = source["data"]

    file_magic = run_file_command(args.input, args.verbose)
    if file_magic:
        log(f"file(1): {file_magic}", args.verbose)
        if (not source["converted"]
                and any(k in file_magic for k in ("PE32", "Mach-O"))):
            log("WARNING: input looks like a host executable, not firmware; "
                "results may be meaningless", True)

    result = run_analysis(
        delivered, source, args.input, min_str_len=args.min_str_len,
        verbose=args.verbose, vendor_documents=vendor_documents,
        no_deframe=args.no_deframe, firmware_version=args.firmware_version,
        file_magic=file_magic)
    container, payload = result["container"], result["payload"]
    arm_info, opacity = result["arm_info"], result["opacity"]
    standards, segments = result["standards"], result["segments"]
    rootfs, strings = result["rootfs"], result["strings"]
    hits, packages = result["hits"], result["packages"]
    vendor, bom = result["vendor"], result["bom"]

    if args.dump_payload:
        try:
            with open(args.dump_payload, "wb") as f:
                f.write(payload)
        except OSError as e:
            die(f"cannot write payload dump: {e}")

    if args.dump_strings:
        try:
            with open(args.dump_strings, "w", encoding="utf-8") as f:
                for segment in segments:
                    for off, text in segment.get("strings", []):
                        f.write(f"0x{off:08x}\t{segment['label']}\t{text}\n")
        except OSError as e:
            die(f"cannot write strings dump: {e}")

    stem = os.path.splitext(os.path.basename(args.input))[0]
    want_cdx = args.format in ("cyclonedx", "both")
    want_spdx = args.format in ("spdx", "both")
    if args.out_dir:
        try:
            os.makedirs(args.out_dir, exist_ok=True)
        except OSError as e:
            die(f"cannot create output directory {args.out_dir}: {e}")
        base = os.path.join(args.out_dir, stem)
        cdx_path = args.output or base + "_SBOM.cdx.json"
        spdx_path = base + "_SBOM.spdx.json"
        evidence_path = args.evidence or base + "_Evidence.xlsx"
    else:
        default_ext = ".cdx.json" if want_cdx else ".spdx.json"
        chosen = args.output or (args.input + default_ext)
        cdx_path = chosen if want_cdx else None
        spdx_path = chosen if args.format == "spdx" else args.input + ".spdx.json"
        evidence_path = args.evidence
    # With --format both and an explicit -o, -o names the CycloneDX document and
    # the SPDX one sits beside it; silently overwriting one with the other would
    # be worse than a slightly surprising filename.
    if args.format == "both" and args.output:
        spdx_path = os.path.splitext(args.output)[0] + ".spdx.json"

    def write_json(path, document, label):
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(document, f, indent=2 if args.pretty else None)
                f.write("\n")
        except OSError as e:
            die(f"cannot write {label} to {path}: {e}")

    out_path = cdx_path or spdx_path
    if want_cdx:
        write_json(cdx_path, bom, "CycloneDX SBOM")
    if want_spdx:
        write_json(spdx_path,
                   spdx_report.build_spdx(bom, args.input, TOOL_NAME, TOOL_VERSION),
                   "SPDX SBOM")

    if container:
        print(f"[fw2sbom] packetized container: {container['stride']}-byte records, "
              f"{container['records']} records, {container['framing_width']}B framing "
              f"+ {container['payload_width']}B payload "
              f"({container['payload_bytes']} payload bytes)", file=sys.stderr)
        print(f"[fw2sbom]   layout {container['layout']}", file=sys.stderr)

    if source["converted"]:
        print(f"[fw2sbom] input: {source['format']} reassembled into "
              f"{len(data)} bytes"
              + (f" from base 0x{source['base_address']:x}"
                 if source["base_address"] is not None else ""),
              file=sys.stderr)

    chip = espressif_image(segments)
    if chip:
        print(f"[fw2sbom] Espressif {chip['chip']}"
              + (f" ({chip['core']})" if chip.get("core") else "")
              + f", entry 0x{chip['entry_point']:08x}", file=sys.stderr)

    rootfs_arch = (rootfs or {}).get("binaries", {}).get("architecture")
    if arm_info["label"]:
        print(f"[fw2sbom] architecture: {arm_info['label']}", file=sys.stderr)
    elif rootfs_arch:
        print(f"[fw2sbom] architecture: {rootfs_arch} (from ELF headers in the "
              "root filesystem)", file=sys.stderr)

    total = len(hits) + len(standards) + len(packages) + (1 if rootfs and
                                                          rootfs.get("os_release") else 0)
    declared = sum(len(e["components"]) for e in vendor)
    total += len(espressif_components(segments))
    total += len(uefi_components(segments))
    total += len(microcode_components(segments))
    if evidence_path:
        context = build_evidence_context(
            os.path.basename(args.input), data, payload, arm_info, container,
            opacity, hits, standards, os.path.basename(out_path))
        try:
            evidence_report.write_evidence_workbook(evidence_path, context, bom)
        except OSError as e:
            die(f"cannot write evidence workbook to {evidence_path}: {e}")
        print(f"[fw2sbom] evidence workbook -> {evidence_path}", file=sys.stderr)

    written = ([f"CycloneDX 1.6 -> {cdx_path}"] if want_cdx else []) + \
              ([f"SPDX 2.3 -> {spdx_path}"] if want_spdx else [])
    for entry in vendor:
        identity = entry["document"]
        print(f"[fw2sbom] vendor SBOM {identity['file']}: "
              f"{len(entry['components'])} declared, "
              f"{len(entry['agreements'])} corroborated by this image, "
              f"{len(entry['conflicts'])} in conflict, "
              f"{len(entry['vendor_only'])} not observed", file=sys.stderr)
        for conflict in entry["conflicts"]:
            print(f"[fw2sbom]   CONFLICT {conflict['vendor']['name']}: vendor "
                  f"declares {conflict['vendor_version']}, this image contains "
                  f"{conflict['our_version']}", file=sys.stderr)

    unenumerable = opaque_segments(segments)
    summary = f"{total} component(s) identified"
    if declared:
        summary += f", {declared} declared by the vendor"
    if unenumerable:
        # Saying "0 components" without this reads as "there is nothing in
        # this firmware", which is the opposite of what an opaque region means.
        summary += (f"; {len(unenumerable)} region(s) could not be enumerated "
                    f"and are recorded as opaque")
    print(f"[fw2sbom] {summary}", file=sys.stderr)
    for line in written:
        print(f"[fw2sbom]   {line}", file=sys.stderr)
    for segment in segments:
        if segment["kind"] == "image":
            continue
        state = ("expanded" if segment.get("expanded")
                 else "read" if segment["kind"] == "filesystem"
                 else "not read" if segment.get("unread_reason")
                 else "not expanded")
        print(f"[fw2sbom] segment 0x{segment['offset']:08x} "
              f"{segment['label']} ({state})", file=sys.stderr)
    described = detected_format(source, segments)
    if described:
        print(f"[fw2sbom] format: {described}", file=sys.stderr)
    if rootfs and rootfs.get("os_release"):
        release = rootfs["os_release"]
        print(f"[fw2sbom] distribution: {release['description']}", file=sys.stderr)
    chain = next((s["vendor_container"] for s in segments
                  if s.get("vendor_container")), None)
    if chain:
        print("[fw2sbom] vendor container: "
              + " > ".join(c["label"] for c in chain)
              + (f" (board {chain[0]['board']})"
                 if chain[0].get("board") else ""), file=sys.stderr)

    inventory = uefi_inventory(segments)
    if inventory:
        named = sum(1 for m in inventory["modules"] if m["name"])
        print(f"[fw2sbom] {len(inventory['modules'])} UEFI module(s) in "
              f"{inventory['volumes']} firmware volume(s), {named} named by "
              f"the image itself", file=sys.stderr)
        if inventory["expanded_bytes"]:
            print(f"[fw2sbom] {inventory['expanded_bytes']} bytes expanded "
                  "from compressed firmware volumes", file=sys.stderr)
        for note in inventory["unreadable"]:
            print(f"[fw2sbom] not expanded: {note}", file=sys.stderr)
        for volume in inventory["data_volumes"]:
            print(f"[fw2sbom] {volume['filesystem']} at "
                  f"0x{volume['offset']:x} holds UEFI variables, not modules; "
                  "not enumerated", file=sys.stderr)

    if packages:
        database = rootfs["packages"]
        versioned = sum(1 for p in packages if p["version"])
        licensed = sum(1 for p in packages if p.get("license"))
        declared_cpe = sum(1 for p in packages if p.get("cpe"))
        print(f"[fw2sbom] {len(packages)} package(s) from {database['path']} "
              f"({database['manager']}), {versioned} with exact versions, "
              f"{licensed} with a declared licence, {declared_cpe} with a "
              f"declared CPE", file=sys.stderr)
        binaries = (rootfs or {}).get("binaries") or {}
        if binaries.get("binary_count"):
            print(f"[fw2sbom] {binaries['binary_count']} ELF binaries, "
                  f"{binaries['file_dependency_count']} linked library "
                  f"dependencies, {len(binaries['modules'])} kernel modules",
                  file=sys.stderr)
    for h in hits:
        v = h["version"] or "?"
        print(f"[fw2sbom]   {h['sig']['name']:<22} version={v:<12} "
              f"confidence={h['confidence']} ({confidence_level(h['confidence'])})",
              file=sys.stderr)
    for std in standards:
        v = std["version"] or "?"
        print(f"[fw2sbom]   {std['name']:<22} version={v:<12} "
              f"confidence={std['confidence']} "
              f"({confidence_level(std['confidence'])}) [embedded standard data]",
              file=sys.stderr)
    for item in espressif_components(segments):
        v = item["version"] or "?"
        print(f"[fw2sbom]   {item['name']:<22} version={v:<12} "
              f"confidence=0.97 (high) [declared in the image header]",
              file=sys.stderr)
    for item in microcode_components(segments):
        print(f"[fw2sbom]   {item['name']:<22} version={item['version']:<12} "
              f"confidence=0.97 (high) [CPU microcode header, "
              f"{item['update']['date']}]", file=sys.stderr)
    if opacity["opaque"]:
        print(f"[fw2sbom] payload is OPAQUE ({opacity['verdict']}) - static component "
              "identification is not possible:", file=sys.stderr)
        for reason in opacity["reasons"]:
            print(f"[fw2sbom]   - {reason}", file=sys.stderr)
        count = len(unenumerable) or 1
        print(f"[fw2sbom] recorded as {count} opaque component(s); obtain a "
              "plaintext image or the vendor's SBOM to complete the inventory",
              file=sys.stderr)
    elif not total:
        print("[fw2sbom] no known components matched; SBOM contains metadata only",
              file=sys.stderr)
    if not total and args.fail_if_empty:
        sys.exit(2)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        die("interrupted", 130)
