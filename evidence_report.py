#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
evidence_report - Excel evidence / confidence workbook for fw2sbom.

Produces the auditor-facing half of the deliverable pair:

    <out-dir>/<stem>_SBOM.cdx.json     machine-readable CycloneDX 1.6 SBOM
    <out-dir>/<stem>_Evidence.xlsx     human-readable evidence and confidence

The workbook records *negative* evidence as prominently as positive evidence:
which signatures and container magics were scanned for and NOT found, and which
raw magic hits were rejected as false positives. For a CRA-style supply-chain
file, "we looked for BusyBox and it is not there" is a finding; silence is not.

The .xlsx is written with the standard library only (an xlsx is a zip of XML
parts), so fw2sbom keeps its no-pip-dependencies property and stays packageable
with PyInstaller as a single self-contained executable.
"""

import collections
import datetime
import hashlib
import math
import re
import zipfile

BANK_SIZE = 65536          # 64 KiB, the classic 8051/scaler code-bank size
MAX_BANKS = 256            # guard against a pathological bank count on huge files


# --------------------------------------------------------------------------- #
# Minimal XLSX writer (stdlib only)
# --------------------------------------------------------------------------- #

_XML_ESCAPES = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"}
_ILLEGAL_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _esc(text):
    out = _ILLEGAL_XML.sub("", str(text))
    for ch, rep in _XML_ESCAPES.items():
        out = out.replace(ch, rep)
    return out


def _col_name(index):
    """0 -> A, 25 -> Z, 26 -> AA."""
    name = ""
    index += 1
    while index:
        index, rem = divmod(index - 1, 26)
        name = chr(65 + rem) + name
    return name


class Workbook:
    """A tiny write-only .xlsx builder: inline strings, three cell styles."""

    STYLE_PLAIN, STYLE_HEADER, STYLE_TITLE, STYLE_WRAP = 0, 1, 2, 3

    def __init__(self):
        self.sheets = []  # (name, rows, widths, freeze_row)

    def add_sheet(self, name, rows, widths=None, header_row=True, title=None):
        """`rows` is a list of lists. A leading `title` row is styled larger."""
        safe = re.sub(r"[\[\]:*?/\\]", "-", str(name))[:31] or "Sheet"
        body = []
        if title:
            body.append([(title, self.STYLE_TITLE)])
        for i, row in enumerate(rows):
            style = self.STYLE_HEADER if (header_row and i == 0) else self.STYLE_PLAIN
            body.append([(cell, style) for cell in row])
        freeze = (1 if title else 0) + (1 if header_row and rows else 0)
        self.sheets.append((safe, body, widths or [], freeze))

    # -- XML parts ---------------------------------------------------------- #

    def _sheet_xml(self, body, widths, freeze):
        parts = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
                 '<worksheet xmlns="http://schemas.openxmlformats.org/'
                 'spreadsheetml/2006/main">']
        if freeze:
            parts.append('<sheetViews><sheetView workbookViewId="0">'
                         f'<pane ySplit="{freeze}" topLeftCell="A{freeze + 1}" '
                         'activePane="bottomLeft" state="frozen"/>'
                         '</sheetView></sheetViews>')
        if widths:
            cols = "".join(f'<col min="{i + 1}" max="{i + 1}" width="{w}" '
                           'customWidth="1"/>' for i, w in enumerate(widths))
            parts.append(f"<cols>{cols}</cols>")
        parts.append("<sheetData>")
        for r, row in enumerate(body, 1):
            cells = []
            for c, (value, style) in enumerate(row):
                ref = f"{_col_name(c)}{r}"
                if value is None or value == "":
                    cells.append(f'<c r="{ref}" s="{style}"/>')
                elif isinstance(value, bool):
                    cells.append(f'<c r="{ref}" s="{style}" t="inlineStr">'
                                 f"<is><t>{'YES' if value else 'NO'}</t></is></c>")
                elif isinstance(value, (int, float)):
                    cells.append(f'<c r="{ref}" s="{style}"><v>{value}</v></c>')
                else:
                    cells.append(f'<c r="{ref}" s="{style}" t="inlineStr">'
                                 f"<is><t xml:space=\"preserve\">{_esc(value)}"
                                 "</t></is></c>")
            parts.append(f'<row r="{r}">' + "".join(cells) + "</row>")
        parts.append("</sheetData></worksheet>")
        return "".join(parts)

    def _styles_xml(self):
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<styleSheet xmlns="http://schemas.openxmlformats.org/'
            'spreadsheetml/2006/main">'
            '<fonts count="3">'
            '<font><sz val="11"/><name val="Calibri"/></font>'
            '<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>'
            '<font><b/><sz val="14"/><color rgb="FF0D1B46"/><name val="Calibri"/></font>'
            "</fonts>"
            '<fills count="3">'
            '<fill><patternFill patternType="none"/></fill>'
            '<fill><patternFill patternType="gray125"/></fill>'
            '<fill><patternFill patternType="solid">'
            '<fgColor rgb="FF0D1B46"/><bgColor indexed="64"/></patternFill></fill>'
            "</fills>"
            '<borders count="1"><border><left/><right/><top/><bottom/>'
            "<diagonal/></border></borders>"
            '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" '
            'borderId="0"/></cellStyleXfs>'
            '<cellXfs count="4">'
            '<xf xfId="0" numFmtId="0" fontId="0" fillId="0" borderId="0" '
            'applyAlignment="1"><alignment vertical="top"/></xf>'
            '<xf xfId="0" numFmtId="0" fontId="1" fillId="2" borderId="0" '
            'applyFont="1" applyFill="1" applyAlignment="1">'
            '<alignment vertical="center"/></xf>'
            '<xf xfId="0" numFmtId="0" fontId="2" fillId="0" borderId="0" '
            'applyFont="1"/>'
            '<xf xfId="0" numFmtId="0" fontId="0" fillId="0" borderId="0" '
            'applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>'
            "</cellXfs>"
            # a named default style: without it some readers (and Excel's own
            # repair check) complain that the workbook has no Normal style
            '<cellStyles count="1"><cellStyle name="Normal" xfId="0" '
            'builtinId="0"/></cellStyles>'
            '<dxfs count="0"/>'
            '<tableStyles count="0" defaultTableStyle="TableStyleMedium2" '
            'defaultPivotStyle="PivotStyleLight16"/>'
            "</styleSheet>"
        )

    def save(self, path):
        n = len(self.sheets)
        sheet_tags = "".join(
            f'<sheet name="{_esc(name)}" sheetId="{i}" r:id="rId{i}"/>'
            for i, (name, _b, _w, _f) in enumerate(self.sheets, 1))
        workbook = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/'
            'spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/'
            'officeDocument/2006/relationships">'
            f"<sheets>{sheet_tags}</sheets></workbook>")
        wb_rels = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/'
            'package/2006/relationships">'
            + "".join(f'<Relationship Id="rId{i}" Type="http://schemas.'
                      'openxmlformats.org/officeDocument/2006/relationships/'
                      f'worksheet" Target="worksheets/sheet{i}.xml"/>'
                      for i in range(1, n + 1))
            + f'<Relationship Id="rId{n + 1}" Type="http://schemas.openxmlformats.'
              'org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
              "</Relationships>")
        content_types = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/'
            'content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats'
            '-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.'
            'openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            + "".join(f'<Override PartName="/xl/worksheets/sheet{i}.xml" '
                      'ContentType="application/vnd.openxmlformats-officedocument.'
                      'spreadsheetml.worksheet+xml"/>' for i in range(1, n + 1))
            + '<Override PartName="/xl/styles.xml" ContentType="application/vnd.'
              'openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>')
        root_rels = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/'
            '2006/relationships"><Relationship Id="rId1" Type="http://schemas.'
            'openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="xl/workbook.xml"/></Relationships>')

        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("[Content_Types].xml", content_types)
            z.writestr("_rels/.rels", root_rels)
            z.writestr("xl/workbook.xml", workbook)
            z.writestr("xl/_rels/workbook.xml.rels", wb_rels)
            z.writestr("xl/styles.xml", self._styles_xml())
            for i, (_name, body, widths, freeze) in enumerate(self.sheets, 1):
                z.writestr(f"xl/worksheets/sheet{i}.xml",
                           self._sheet_xml(body, widths, freeze))


# --------------------------------------------------------------------------- #
# Container / filesystem magic scan (with validation)
# --------------------------------------------------------------------------- #
# A 2-byte magic in a 576 KiB image is expected to hit by chance ~9 times. The
# scanner therefore separates a raw byte match from a *validated* structure, and
# the workbook reports both - a rejected hit is evidence that the check ran.

def _validate_elf(data, off):
    return data[off + 4:off + 5] in (b"\x01", b"\x02") and \
        data[off + 5:off + 6] in (b"\x01", b"\x02")


def _validate_pe(data, off):
    if off + 0x40 > len(data):
        return False
    lfanew = int.from_bytes(data[off + 0x3C:off + 0x40], "little")
    return data[off + lfanew:off + lfanew + 4] == b"PE\x00\x00"


def _validate_gzip(data, off):
    return data[off + 2:off + 3] == b"\x08"


def _validate_squashfs(data, off):
    size = int.from_bytes(data[off + 40:off + 44], "little")
    return 0 < size <= len(data)


def _always(data, off):
    return True


MAGIC_CHECKS = [
    # (label, magic, validator, note when only a raw hit is found)
    ("ELF", b"\x7fELF", _validate_elf, "4-byte magic without a valid ELF class/endianness"),
    ("PE/DOS", b"MZ", _validate_pe, "Raw 'MZ' byte pair only; no PE header at e_lfanew"),
    ("ZIP", b"PK\x03\x04", _always, None),
    ("GZIP", b"\x1f\x8b", _validate_gzip, "gzip magic without deflate compression method"),
    ("XZ", b"\xfd7zXZ\x00", _always, None),
    ("BZIP2", b"BZh", _always, None),
    ("7-Zip", b"7z\xbc\xaf\x27\x1c", _always, None),
    ("Zstandard", b"\x28\xb5\x2f\xfd", _always, None),
    ("LZ4", b"\x04\x22\x4d\x18", _always, None),
    ("SquashFS little-endian", b"hsqs", _validate_squashfs, "magic without a plausible image size"),
    ("SquashFS big-endian", b"sqsh", _always, None),
    ("UBI erase counter", b"UBI#", _always, None),
    ("JFFS2 little-endian", b"\x85\x19", _always, "Weak 2-byte JFFS2 magic; likely coincidence"),
    ("JFFS2 big-endian", b"\x19\x85", _always, "Weak 2-byte JFFS2 magic; likely coincidence"),
    ("CramFS little-endian", b"\x45\x3d\xcd\x28", _always, None),
    ("CramFS big-endian", b"\x28\xcd\x3d\x45", _always, None),
    ("uImage", b"\x27\x05\x19\x56", _always, None),
    ("Android boot image", b"ANDROID!", _always, None),
    ("Flattened Device Tree", b"\xd0\x0d\xfe\xed", _always, None),
]

# Magics short enough to hit by chance are reported as weak even when the
# validator passes, because the validator itself is weak for these.
WEAK_MAGIC_LENGTH = 2


def scan_magics(data, max_offsets=8):
    """Scan for container/filesystem magics. Returns one record per check."""
    results = []
    for label, magic, validator, weak_note in MAGIC_CHECKS:
        raw, validated = [], []
        for m in re.finditer(re.escape(magic), data):
            off = m.start()
            raw.append(off)
            if len(magic) > WEAK_MAGIC_LENGTH and validator(data, off):
                validated.append(off)
            if len(raw) >= 4096:
                break
        results.append({
            "label": label,
            "magic": magic.hex(),
            "raw_hits": len(raw),
            "validated_hits": len(validated),
            "offsets": (validated or raw)[:max_offsets],
            "note": None if validated else (weak_note if raw else None),
        })
    return results


# --------------------------------------------------------------------------- #
# Bank analysis
# --------------------------------------------------------------------------- #

def analyze_banks(data, bank_size=BANK_SIZE):
    """Per-bank entropy / fill / string statistics for a code-banked image."""
    if len(data) > bank_size * MAX_BANKS:
        bank_size = 1 << max(16, (len(data) // MAX_BANKS).bit_length())
    banks = []
    printable = re.compile(rb"[\x20-\x7e]{6,}")
    for index, start in enumerate(range(0, len(data), bank_size)):
        chunk = data[start:start + bank_size]
        counts = collections.Counter(chunk)
        n = len(chunk)
        entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())
        banks.append({
            "index": index,
            "start": start,
            "end": start + n - 1,
            "size": n,
            "entropy": round(entropy, 4),
            "ff_percent": round(100 * counts[0xFF] / n, 3),
            "zero_percent": round(100 * counts[0x00] / n, 3),
            "strings": len(printable.findall(chunk)),
            "sha256": hashlib.sha256(chunk).hexdigest(),
        })
    return banks


# --------------------------------------------------------------------------- #
# Workbook assembly
# --------------------------------------------------------------------------- #

def _hex_offset(value):
    return f"0x{value:08X}"


def _summary_rows(ctx):
    hashes, opacity = ctx["hashes"], ctx["opacity"]
    container, arch = ctx["container"], ctx["architecture"]
    rows = [
        ["Field", "Value"],
        ["Input file", ctx["filename"]],
        ["Analysed at (UTC)", ctx["timestamp"]],
        ["Tool", f"{ctx['tool_name']} {ctx['tool_version']}"],
        ["Size (bytes)", len(ctx["data"])],
        ["Size (hex)", f"0x{len(ctx['data']):X}"],
        ["MD5", hashes["MD5"]],
        ["SHA-1", hashes["SHA-1"]],
        ["SHA-256", hashes["SHA-256"]],
        ["SHA-512", hashes["SHA-512"]],
        ["Instruction set", arch or "Not identified"],
        ["Payload verdict", opacity["verdict"]],
        ["Entropy (bits/byte)", opacity["entropy"]],
        ["Longest identical-byte run", opacity["longest_run"]],
    ]
    if container:
        rows += [
            ["Packetized container", "YES - framing stripped before analysis"],
            ["  Record stride (bytes)", container["stride"]],
            ["  File header (bytes)", container["header_bytes"]],
            ["  Records", container["records"]],
            ["  Framing / payload per record",
             f"{container['framing_width']}B + {container['payload_width']}B"],
            ["  Payload analysed (bytes)", container["payload_bytes"]],
            ["  Framing resolved by", container["framing_resolution"]],
        ]
    else:
        rows.append(["Packetized container", "NO - analysed as a flat image"])
    rows += [
        ["Version-confirmed third-party components", ctx["n_confirmed"]],
        ["Embedded standard-data components", ctx["n_standards"]],
        ["Signatures scanned and NOT found", ctx["n_not_found"]],
        ["Container/filesystem magics validated", ctx["n_magic_validated"]],
        ["Container/filesystem magics rejected as false positives",
         ctx["n_magic_rejected"]],
        ["Checksum-valid EDID blocks", len(ctx["edid_blocks"])],
        [f"{ctx['bank_size'] // 1024} KiB banks", len(ctx["banks"])],
        ["SBOM policy",
         "Only evidence-backed findings are emitted as components. Versions are "
         "taken from version strings or parsed structures; inferred versions are "
         "flagged and never carried into the purl."],
        ["Important limitation",
         "Binary-derived SBOM. Absence of a detected signature is not proof of "
         "absence: version strings can be stripped, and an encrypted or "
         "obfuscated payload cannot be enumerated by any static tool."],
    ]
    if opacity["opaque"]:
        rows.append(["OPAQUE PAYLOAD",
                     "Component enumeration is not possible; request a plaintext "
                     "image or the vendor's own SBOM."])
    return rows


def _candidate_rows(ctx):
    rows = [["Component", "Vendor", "Version", "Status", "Confidence %",
             "In SBOM?", "Offset", "Evidence"]]
    rows.append([ctx["filename"], ctx["vendor_hint"] or "Unknown",
                 ctx["firmware_version"] or "UNKNOWN",
                 "Confirmed primary firmware file", 100, True, _hex_offset(0),
                 f"File identity by cryptographic hashes (SHA-256 "
                 f"{ctx['hashes']['SHA-256'][:32]}...)"])

    for hit in ctx["hits"]:
        sig = hit["sig"]
        offset = hit["evidence"][0][1] if hit["evidence"] else None
        text = hit["evidence"][0][2] if hit["evidence"] else ""
        status = "Detected by string fingerprint"
        if hit["version"] and not hit.get("version_inferred"):
            status = "Detected, version confirmed"
        elif hit.get("version_inferred"):
            status = "Detected, version inferred"
        rows.append([sig["name"], sig.get("supplier") or "", hit["version"] or "",
                     status, int(round(hit["confidence"] * 100)), True,
                     _hex_offset(offset) if offset is not None else "",
                     f"matched {text!r}"])

    for std in ctx["standards"]:
        rows.append([std["name"], std["supplier"], std["version"] or "",
                     "Detected by structural parsing and validation",
                     int(round(std["confidence"] * 100)), True,
                     _hex_offset(std["occurrences"][0]) if std["occurrences"] else "",
                     std["evidence"][0] if std["evidence"] else ""])

    for sig in ctx["not_found"]:
        rows.append([sig["name"], sig.get("supplier") or "", "",
                     "Not detected by string fingerprint", 0, False, "", ""])
    return rows


def _evidence_rows(ctx):
    rows = [["ID", "Category", "Offset", "Evidence", "Interpretation",
             "Confidence %"]]
    entries = []

    entries.append(("File identity", _hex_offset(0),
                    f"SHA-256={ctx['hashes']['SHA-256']}",
                    "Exact file identity", 100))

    if ctx["architecture"]:
        # arch_details carries lines from BOTH ISA detectors, tagged by prefix;
        # only the ones from the winning detector support the conclusion.
        prefix = "mcs-51: " if "MCS-51" in ctx["architecture"] else "cortex-m: "
        for detail in ctx["arch_details"]:
            supports = detail.startswith(prefix)
            entries.append((
                "Instruction set", _hex_offset(0), detail,
                f"Consistent with {ctx['architecture']}" if supports
                else "Alternative instruction set checked; did not match",
                95 if supports else 0))
    else:
        entries.append(("Instruction set", "", "No Cortex-M or MCS-51 vector "
                        "table matched", "Architecture not identified; "
                        "component analysis continues without it", 0))

    if ctx["container"]:
        c = ctx["container"]
        entries.append(("Container framing", _hex_offset(c["header_bytes"]),
                        c["layout"],
                        f"{c['stride']}-byte records; framing stripped before "
                        f"analysis; resolved by {c['framing_resolution']}",
                        95 if "verified" in c["framing_resolution"] else 70))

    for reason in ctx["opacity"]["reasons"]:
        entries.append(("Payload opacity", "", reason,
                        f"Verdict: {ctx['opacity']['verdict']}",
                        90 if ctx["opacity"]["opaque"] else 80))

    for hit in ctx["hits"]:
        for pat, offset, text, version in hit["evidence"]:
            entries.append(("Software fingerprint", _hex_offset(offset),
                            f"{hit['sig']['name']}: {text!r}",
                            f"regex {pat['regex']!r}"
                            + (f"; version {version}" if version else ""),
                            int(round(pat["weight"] * 100))))

    for std in ctx["standards"]:
        for i, ev in enumerate(std["evidence"]):
            offset = std["occurrences"][0] if std["occurrences"] else None
            entries.append(("Embedded standard data",
                            _hex_offset(offset) if offset is not None else "",
                            f"{std['name']}: {ev}",
                            "Standardised data structure parsed and validated; "
                            "not a linked software library",
                            int(round(std["confidence"] * 100))))

    for magic in ctx["magics"]:
        if magic["validated_hits"]:
            entries.append(("Container magic (validated)",
                            ", ".join(_hex_offset(o) for o in magic["offsets"]),
                            magic["label"],
                            f"{magic['validated_hits']} validated occurrence(s)",
                            90))
        elif magic["raw_hits"]:
            entries.append(("Weak/raw magic hit",
                            ", ".join(_hex_offset(o) for o in magic["offsets"]),
                            magic["label"],
                            magic["note"] or "Raw magic bytes only; structure did "
                            "not validate. Rejected as a false positive.", 10))

    for i, (category, offset, evidence, interpretation, confidence) in \
            enumerate(entries, 1):
        rows.append([i, category, offset, evidence, interpretation, confidence])
    return rows


def _edid_rows(blocks):
    rows = [["Offset", "Checksum OK", "Manufacturer", "Product code", "Serial",
             "Week", "Year", "EDID version", "Extensions", "Monitor name",
             "Block SHA-256"]]
    for b in blocks:
        rows.append([_hex_offset(b["offset"]), "YES", b["pnp_id"],
                     f"0x{b['product_code']:04X}", b.get("serial", ""),
                     b.get("week", ""), b.get("manufacture_year") or "",
                     b["version"], b.get("extensions", 0), b["name"] or "",
                     b.get("sha256", "")])
    return rows


def _bank_rows(banks):
    rows = [["Bank", "Start", "End", "Size", "Entropy", "0xFF %", "0x00 %",
             "ASCII strings (len>=6)", "SHA-256"]]
    for b in banks:
        rows.append([b["index"], _hex_offset(b["start"]), _hex_offset(b["end"]),
                     b["size"], b["entropy"], b["ff_percent"], b["zero_percent"],
                     b["strings"], b["sha256"]])
    return rows


def _coverage_rows(ctx):
    rows = [["Check", "Type", "Validated", "Raw hits", "Offsets / status"]]
    for magic in ctx["magics"]:
        status = ""
        if magic["validated_hits"]:
            status = ", ".join(_hex_offset(o) for o in magic["offsets"])
        elif magic["raw_hits"]:
            status = (magic["note"] or "raw magic only") + ": " + \
                     ", ".join(_hex_offset(o) for o in magic["offsets"])
        else:
            status = "not present"
        rows.append([magic["label"], "container/filesystem magic",
                     magic["validated_hits"], magic["raw_hits"], status])
    for sig in ctx["all_signatures"]:
        hit = next((h for h in ctx["hits"] if h["sig"]["name"] == sig["name"]), None)
        rows.append([sig["name"], "software string fingerprint",
                     1 if hit else 0, len(hit["evidence"]) if hit else 0,
                     f"detected, confidence {hit['confidence']}" if hit
                     else "Not detected by string fingerprint"])
    for name, present in ctx["structural_checks"]:
        rows.append([name, "structural parser", 1 if present else 0,
                     present, "detected" if present else "not present"])
    return rows


def _cyclonedx_rows(ctx, bom):
    return [
        ["CycloneDX field", "Value"],
        ["specVersion", bom["specVersion"]],
        ["bomFormat", bom["bomFormat"]],
        ["serialNumber", bom["serialNumber"]],
        ["root component", bom["metadata"]["component"]["name"]],
        ["root bom-ref", bom["metadata"]["component"]["bom-ref"]],
        ["total component count", len(bom["components"])],
        ["version-confirmed third-party components", ctx["n_confirmed"]],
        ["embedded standard-data components", ctx["n_standards"]],
        ["opaque placeholder components",
         sum(1 for c in bom["components"]
             if any(p["name"] == "fw2sbom:opaque" for p in c.get("properties", [])))],
        ["SBOM file", ctx["sbom_filename"]],
    ]


def build_workbook(ctx, bom):
    """Assemble the evidence workbook from a completed analysis context."""
    wb = Workbook()
    wb.add_sheet("Summary", _summary_rows(ctx), widths=[42, 78],
                 title="Firmware SBOM Evidence / Confidence Report")
    wb.add_sheet("Candidate Components", _candidate_rows(ctx),
                 widths=[26, 20, 14, 34, 13, 10, 14, 70])
    wb.add_sheet("Evidence Register", _evidence_rows(ctx),
                 widths=[6, 26, 30, 70, 60, 13])
    if ctx["edid_blocks"]:
        wb.add_sheet("EDID Profiles", _edid_rows(ctx["edid_blocks"]),
                     widths=[13, 13, 14, 14, 14, 7, 7, 13, 11, 20, 66])
    wb.add_sheet("Bank Analysis", _bank_rows(ctx["banks"]),
                 widths=[7, 13, 13, 10, 10, 9, 9, 14, 66])
    wb.add_sheet("Scan Coverage", _coverage_rows(ctx),
                 widths=[26, 28, 11, 11, 62])
    wb.add_sheet("CycloneDX Summary", _cyclonedx_rows(ctx, bom), widths=[42, 62])
    return wb


def write_evidence_workbook(path, ctx, bom):
    build_workbook(ctx, bom).save(path)
    return path
