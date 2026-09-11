#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
spdx_report - SPDX 2.3 JSON output for fw2sbom.

The CycloneDX document is the richer of the two: it has a first-class
`evidence` object built for exactly what this tool does, and fw2sbom's
confidence scores land there naturally. SPDX 2.3 has no equivalent field, so
none of that can be expressed structurally - it goes into `annotations` and
`comment`, where a human reads it and a machine largely does not.

SPDX is emitted anyway because some customers and reviewers ask for it by name,
and a format they can ingest is worth more than a better format they cannot.
Where the two documents differ, CycloneDX is the authoritative one; that is
stated in the document comment rather than left for someone to discover.

Both documents are produced from the same analysis in the same run, so they can
never disagree about what was found.

stdlib only, like the rest of fw2sbom.
"""

import hashlib
import os
import re
import uuid
from datetime import datetime, timezone

SPDX_VERSION = "SPDX-2.3"
DATA_LICENSE = "CC0-1.0"
NOASSERTION = "NOASSERTION"

# SPDX identifiers allow letters, digits, '.' and '-' only.
_ID_ILLEGAL = re.compile(r"[^A-Za-z0-9.\-]+")

# SPDX checksum algorithm names for the digests fw2sbom computes.
_ALG_NAMES = {"SHA-256": "SHA256", "SHA-1": "SHA1", "MD5": "MD5",
              "SHA-512": "SHA512"}


def _spdx_id(*parts):
    """A valid, unique-per-document SPDXRef built from arbitrary text."""
    joined = "-".join(str(p) for p in parts if p not in (None, ""))
    cleaned = _ID_ILLEGAL.sub("-", joined).strip("-")
    return "SPDXRef-" + (cleaned or "Unnamed")


def _supplier(name):
    """SPDX wants 'Organization: X' or 'Person: X', or NOASSERTION."""
    return f"Organization: {name}" if name else NOASSERTION


def _checksums(hashes):
    return [{"algorithm": _ALG_NAMES[alg], "checksumValue": value}
            for alg, value in (hashes or {}).items() if alg in _ALG_NAMES]


def _annotation(comment, created, tool):
    return {"annotator": f"Tool: {tool}",
            "annotationDate": created,
            "annotationType": "OTHER",
            "comment": comment}


def _evidence_comment(component):
    """Flatten a CycloneDX evidence object into readable text.

    SPDX has nowhere structured to put matched regexes and offsets, and
    dropping them would turn an evidence-based SBOM into a list of assertions.
    """
    lines = []
    for identity in component.get("evidence", {}).get("identity", []):
        field = identity.get("field", "?")
        lines.append(f"{field}: confidence {identity.get('confidence')}")
        for method in identity.get("methods", []):
            # The technique matters as much as the match: "binary-analysis"
            # tells a reader this was read out of an image, not asserted by a
            # build system, and that is the whole caveat on this document.
            technique = method.get("technique", "unknown")
            lines.append(f"  - [{technique}] {method.get('value')}")
    for occurrence in component.get("evidence", {}).get("occurrences", []):
        context = occurrence.get("additionalContext")
        if context:
            lines.append(f"  location: {context}")
    return "\n".join(lines)


def build_spdx(bom, input_path, tool_name, tool_version):
    """Convert a fw2sbom CycloneDX 1.6 document into SPDX 2.3 JSON.

    Conversion rather than a parallel generator: one analysis, one set of
    findings, two renderings. A second code path over the same data is a second
    place for the two documents to drift apart.
    """
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    tool = f"{tool_name}-{tool_version}"
    root = bom["metadata"]["component"]
    name = os.path.basename(input_path)

    bom_props = {p["name"]: p["value"]
                 for p in bom["metadata"].get("properties", [])}
    root_props = {p["name"]: p["value"] for p in root.get("properties", [])}

    root_id = _spdx_id("Firmware", name)
    packages = [{
        "SPDXID": root_id,
        "name": name,
        "versionInfo": root.get("version") or NOASSERTION,
        "downloadLocation": NOASSERTION,
        "filesAnalyzed": False,
        "supplier": NOASSERTION,
        "licenseConcluded": NOASSERTION,
        "licenseDeclared": NOASSERTION,
        "copyrightText": NOASSERTION,
        "checksums": _checksums(
            {h["alg"]: h["content"] for h in root.get("hashes", [])}),
        "primaryPackagePurpose": "FIRMWARE",
        "comment": "\n".join(f"{k} = {v}" for k, v in root_props.items()),
    }]

    relationships = [{
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": root_id,
    }]

    seen = {root_id}
    for index, component in enumerate(bom.get("components", []), 1):
        package_id = _spdx_id(index, component["name"])
        while package_id in seen:                 # names are not guaranteed unique
            index += 1
            package_id = _spdx_id(index, component["name"])
        seen.add(package_id)

        props = {p["name"]: p["value"] for p in component.get("properties", [])}
        version = component.get("version")

        package = {
            "SPDXID": package_id,
            "name": component["name"],
            "versionInfo": version or NOASSERTION,
            "downloadLocation": NOASSERTION,
            "filesAnalyzed": False,
            "supplier": _supplier((component.get("supplier") or {}).get("name")),
            "licenseConcluded": NOASSERTION,
            "licenseDeclared": NOASSERTION,
            "copyrightText": NOASSERTION,
            "description": component.get("description", ""),
        }
        if component.get("hashes"):
            package["checksums"] = _checksums(
                {h["alg"]: h["content"] for h in component["hashes"]})
        if component.get("purl"):
            package["externalRefs"] = [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": component["purl"],
            }]

        # Everything SPDX 2.3 cannot hold structurally, kept where a reader
        # will at least find it.
        comment = [f"{k} = {v}" for k, v in props.items()]
        evidence = _evidence_comment(component)
        if evidence:
            comment.append("evidence:\n" + evidence)
        package["comment"] = "\n".join(comment)

        confidence = props.get("fw2sbom:confidence")
        level = props.get("fw2sbom:confidence_level")
        if confidence is not None:
            package["annotations"] = [_annotation(
                f"fw2sbom identification confidence {confidence} ({level}). "
                "This package was identified by binary analysis, not read from a "
                "build manifest.", created, tool)]

        if not version:
            reason = props.get("fw2sbom:version_unavailable_reason")
            package.setdefault("annotations", []).append(_annotation(
                "No version could be determined. "
                + (reason or "No version string was found in the image."),
                created, tool))

        packages.append(package)
        relationships.append({
            "spdxElementId": root_id,
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": package_id,
        })

    document_comment = (
        "Binary-derived SBOM: components and versions were inferred from static "
        "analysis of a firmware image, not read from a build manifest. Absence of "
        "a component is not evidence of absence.\n\n"
        + bom_props.get("fw2sbom:disclaimer", "") + "\n\n"
        "SPDX 2.3 has no field for per-identification confidence or for the "
        "matched strings and offsets behind each finding, so those are carried in "
        "package comments and annotations. The CycloneDX 1.6 document produced "
        "from the same analysis expresses them structurally and is the "
        "authoritative rendering where the two differ.")

    return {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": DATA_LICENSE,
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{name}-sbom",
        # A document namespace has to be unique per document. Reuse the
        # CycloneDX serial number so the two renderings of one analysis are
        # traceable to each other.
        "documentNamespace": "https://spdx.org/spdxdocs/{}-{}".format(
            _ID_ILLEGAL.sub("-", name),
            bom.get("serialNumber", "urn:uuid:" + str(uuid.uuid4())).rsplit(":", 1)[-1]),
        "creationInfo": {
            "created": created,
            "creators": [f"Tool: {tool}"],
            "comment": "Generated by fw2sbom from static analysis of a firmware "
                       "image. See the document comment for what that implies.",
        },
        "comment": document_comment,
        "packages": packages,
        "relationships": relationships,
    }


def document_digest(document):
    """A stable digest of an SPDX document, ignoring its timestamps.

    Useful for asserting in tests that two runs over the same image produce the
    same findings, when the only differences are the generated dates.
    """
    import json

    copy = json.loads(json.dumps(document))
    copy["creationInfo"]["created"] = ""
    copy["documentNamespace"] = ""
    for package in copy["packages"]:
        for annotation in package.get("annotations", []):
            annotation["annotationDate"] = ""
    return hashlib.sha256(
        json.dumps(copy, sort_keys=True).encode("utf-8")).hexdigest()
