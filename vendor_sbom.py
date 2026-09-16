#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vendor_sbom - read an SBOM supplied by the firmware vendor, and compare it.

Static analysis has a hard ceiling. An encrypted image yields an opaque region
and nothing else, and no amount of cleverness changes that: the components are
behind a cipher. The only way past it is the vendor's own SBOM, and under the
CRA a manufacturer is entitled to ask a supplier for one.

Merging that document into ours is not just concatenation. Two things have to
survive the merge:

  * **Provenance.** A component we read out of a binary and a component the
    vendor asserted are different kinds of claim. One has an offset, a matched
    string and a confidence; the other has a supplier's word. An auditor must
    be able to tell them apart at a glance, so every merged component is
    labelled with the document it came from.

  * **Disagreement.** When the vendor says OpenSSL 3.0.8 and the binary says
    3.0.2, that is a finding - possibly the most valuable thing in the report.
    Silently preferring one, or averaging them, destroys it. Both are kept and
    the conflict is recorded.

CycloneDX 1.x and SPDX 2.x JSON are both accepted, because vendors send
whichever their tooling produces.

Standard library only, and hostile-input safe: a vendor's SBOM is a file from
outside, and a malformed one must produce a clear error, never a traceback in
the middle of an analysis.
"""

import json
import os
import re

MAX_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_COMPONENTS = 100_000

# purl and CPE both encode a version; strip it so two spellings of the same
# component compare equal.
_PURL_VERSION = re.compile(r"@[^@/?#]+$")


class VendorSBOMError(Exception):
    """The supplied document cannot be read as an SBOM."""


def _text(value):
    return value.strip() if isinstance(value, str) and value.strip() else None


def _base_purl(purl):
    return _PURL_VERSION.sub("", purl) if purl else None


def normalise_key(name, purl=None):
    """The identity two documents must agree on before they are compared.

    A purl without its version is the strongest key when present; otherwise
    the lower-cased name. Vendors and our own signature database rarely spell
    a name identically ("libopenssl1.1" against "openssl"), so a mismatch here
    means "not obviously the same component", not "definitely different".
    """
    base = _base_purl(purl)
    if base:
        return base.lower()
    return (name or "").strip().lower()


def _keys(name, purl=None):
    """Every key a component may legitimately be found under.

    Plenty of real vendor SBOMs carry no purl at all - supplier-generated SPDX
    especially - and ours almost always do. Keying only on the purl meant those
    documents matched nothing and were reported as "declared but not observed"
    in full, which reads as a clean bill of health when it is really a failure
    to compare. So a component is indexed under its purl *and* its name, and
    the name is what rescues those documents.
    """
    keys = []
    base = _base_purl(purl)
    if base:
        keys.append(base.lower())
    plain = (name or "").strip().lower()
    if plain and plain not in keys:
        keys.append(plain)
    return keys


# --------------------------------------------------------------------------- #
# Readers
# --------------------------------------------------------------------------- #

def _read_cyclonedx(doc):
    components = []
    for entry in doc.get("components") or []:
        if not isinstance(entry, dict):
            continue
        name = _text(entry.get("name"))
        if not name:
            continue
        licences = []
        for item in entry.get("licenses") or []:
            if not isinstance(item, dict):
                continue
            licence = item.get("license") or {}
            licences.append(_text(licence.get("id"))
                            or _text(licence.get("name"))
                            or _text(item.get("expression")))
        supplier = entry.get("supplier") or {}
        components.append({
            "name": name,
            "version": _text(entry.get("version")),
            "purl": _text(entry.get("purl")),
            "cpe": _text(entry.get("cpe")),
            "type": _text(entry.get("type")) or "library",
            "licenses": [x for x in licences if x],
            "supplier": _text(supplier.get("name")),
            "description": _text(entry.get("description")),
        })
    return components


def _read_spdx(doc):
    components = []
    for entry in doc.get("packages") or []:
        if not isinstance(entry, dict):
            continue
        name = _text(entry.get("name"))
        if not name:
            continue
        purl = cpe = None
        for ref in entry.get("externalRefs") or []:
            if not isinstance(ref, dict):
                continue
            kind = (ref.get("referenceType") or "").lower()
            locator = _text(ref.get("referenceLocator"))
            if kind == "purl":
                purl = locator
            elif kind.startswith("cpe23"):
                cpe = locator
        licences = [x for x in (_text(entry.get("licenseConcluded")),
                                _text(entry.get("licenseDeclared")))
                    if x and x.upper() not in ("NOASSERTION", "NONE")]
        supplier = _text(entry.get("supplier")) or ""
        components.append({
            "name": name,
            "version": _text(entry.get("versionInfo")),
            "purl": purl,
            "cpe": cpe,
            "type": "library",
            "licenses": list(dict.fromkeys(licences)),
            "supplier": supplier.split(":", 1)[-1].strip() or None,
            "description": _text(entry.get("description"))
                           or _text(entry.get("summary")),
        })
    return components


def _document_identity(doc, path):
    """Enough about the source document to cite it in the SBOM."""
    if doc.get("bomFormat") == "CycloneDX":
        metadata = doc.get("metadata") or {}
        subject = (metadata.get("component") or {}).get("name")
        tools = metadata.get("tools") or {}
        producers = tools.get("components") if isinstance(tools, dict) else tools
        tool = None
        if isinstance(producers, list) and producers:
            first = producers[0]
            tool = first.get("name") if isinstance(first, dict) else str(first)
        return {
            "format": f"CycloneDX {doc.get('specVersion', '?')}",
            "identifier": _text(doc.get("serialNumber")),
            "subject": _text(subject),
            "produced_by": _text(tool),
            "timestamp": _text(metadata.get("timestamp")),
            "file": os.path.basename(path),
        }
    creation = doc.get("creationInfo") or {}
    creators = creation.get("creators") or []
    return {
        "format": f"SPDX {doc.get('spdxVersion', '?').replace('SPDX-', '')}",
        "identifier": _text(doc.get("documentNamespace")),
        "subject": _text(doc.get("name")),
        "produced_by": next((c for c in creators
                             if isinstance(c, str) and c.startswith("Tool:")),
                            None),
        "timestamp": _text(creation.get("created")),
        "file": os.path.basename(path),
    }


def load(path):
    """Read a vendor SBOM from a file. Returns {document, components}."""
    try:
        size = os.path.getsize(path)
    except OSError as e:
        raise VendorSBOMError(f"cannot open {path}: {e}")
    if size > MAX_DOCUMENT_BYTES:
        raise VendorSBOMError(
            f"{path} is {size} bytes; refusing to read an SBOM that large")
    try:
        with open(path, "rb") as f:
            blob = f.read()
    except OSError as e:
        raise VendorSBOMError(f"cannot open {path}: {e}")
    return loads(blob, path)


def loads(blob, label):
    """Read a vendor SBOM from bytes. `label` names it in every message.

    The drag-and-drop service holds uploads in memory and never writes them to
    disk - a promise printed on its own page - so it needs a way in that does
    not go through a filename.
    """
    if len(blob) > MAX_DOCUMENT_BYTES:
        raise VendorSBOMError(
            f"{label} is {len(blob)} bytes; refusing to read an SBOM that large")
    try:
        doc = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise VendorSBOMError(f"{label} is not readable JSON: {e}")
    if not isinstance(doc, dict):
        raise VendorSBOMError(f"{label} does not contain an SBOM document")

    if doc.get("bomFormat") == "CycloneDX":
        components = _read_cyclonedx(doc)
    elif str(doc.get("spdxVersion", "")).startswith("SPDX-"):
        components = _read_spdx(doc)
    else:
        raise VendorSBOMError(
            f"{label} is neither CycloneDX (no bomFormat) nor SPDX "
            "(no spdxVersion); those are the two formats we can read")

    if len(components) > MAX_COMPONENTS:
        raise VendorSBOMError(
            f"{label} declares {len(components)} components; refusing to merge")
    if not components:
        raise VendorSBOMError(
            f"{label} parsed as {_document_identity(doc, label)['format']} but "
            "lists no components - check it is the right file")

    return {"document": _document_identity(doc, label),
            "components": components}


# --------------------------------------------------------------------------- #
# Comparison
# --------------------------------------------------------------------------- #

def compare(found, vendor_components):
    """Line the vendor's claims up against what the binary actually showed.

    `found` is [{name, version, purl}] for everything this analysis
    identified, whatever the evidence class.

    Returns (agreements, conflicts, vendor_only, ours_only). A conflict - the
    vendor naming a different version from the one compiled into the image -
    is the single most useful thing this comparison produces, and is why the
    two documents are compared rather than merged and forgotten.
    """
    ours = {}
    for item in found:
        for key in _keys(item.get("name"), item.get("purl")):
            ours.setdefault(key, item)

    agreements, conflicts, vendor_only = [], [], []
    matched = []

    for entry in vendor_components:
        mine = None
        for key in _keys(entry.get("name"), entry.get("purl")):
            mine = ours.get(key)
            if mine is not None:
                break
        if mine is None:
            vendor_only.append(entry)
            continue
        matched.append(mine)
        theirs_version = entry.get("version")
        mine_version = mine.get("version")
        if not theirs_version or not mine_version:
            # One side has no version; nothing to disagree about.
            agreements.append({"vendor": entry, "ours": mine,
                               "versions_compared": False})
        elif theirs_version == mine_version:
            agreements.append({"vendor": entry, "ours": mine,
                               "versions_compared": True})
        else:
            conflicts.append({"vendor": entry, "ours": mine,
                              "vendor_version": theirs_version,
                              "our_version": mine_version})

    # One component is indexed under several keys, so "what did the vendor not
    # mention" is asked of the components themselves, not of the index.
    ours_only = []
    for item in found:
        if any(item is m for m in matched):
            continue
        if any(item is already for already in ours_only):
            continue
        ours_only.append(item)
    return agreements, conflicts, vendor_only, ours_only
