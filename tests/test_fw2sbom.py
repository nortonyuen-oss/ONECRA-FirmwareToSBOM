#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Regression tests for fw2sbom.

The analysis pipeline is a stack of heuristics - vector-table shapes, record
strides, entropy thresholds, regex weights. Heuristics fail quietly: a tuned
constant that stops matching produces a smaller SBOM, not an error, and nobody
notices until a customer's report is wrong. These tests pin the observable
behaviour of every stage against synthetic fixtures with known contents, so a
change that alters a verdict has to say so.

Fixtures are generated on demand by make_fixtures.py into a temporary
directory; nothing here depends on a checked-in binary.

    python -m unittest discover -s tests -v
    python tests/test_fw2sbom.py
"""

import io
import json
import os
import shutil
import struct
import sys
import tempfile
import time
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import container                                        # noqa: E402
import elf                                              # noqa: E402
import evidence_report                                  # noqa: E402
import fw2sbom as core                                   # noqa: E402
import make_fixtures                                     # noqa: E402
import spdx_report                                       # noqa: E402
import squashfs                                          # noqa: E402
import service                                           # noqa: E402


def setUpModule():
    """Generate every fixture once, into a directory removed at the end."""
    global FIXTURE_DIR
    FIXTURE_DIR = tempfile.mkdtemp(prefix="fw2sbom-fixtures-")
    make_fixtures.main(["make_fixtures.py", FIXTURE_DIR])
    core.load_signatures()


def tearDownModule():
    shutil.rmtree(FIXTURE_DIR, ignore_errors=True)


def fixture(name):
    with open(os.path.join(FIXTURE_DIR, name), "rb") as f:
        return f.read()


_ANALYSIS_CACHE = {}


def analyze(name):
    """Run the whole pipeline over a fixture, as the CLI and service both do.

    Cached: container detection alone costs a few seconds per image, and the
    suite asks about the same nine fixtures from several angles. Callers read
    the result and must not mutate it.
    """
    if name not in _ANALYSIS_CACHE:
        _ANALYSIS_CACHE[name] = _analyze_uncached(name)
    return _ANALYSIS_CACHE[name]


def _analyze_uncached(name):
    data = fixture(name)
    container = core.detect_packet_container(data)
    payload = core.deframe(data, container) if container else data
    arch = core.analyze_architecture(payload)
    opacity = core.analyze_opacity(payload, arch["label"])
    standards = core.detect_embedded_standards(payload)
    segments, rootfs, _warnings = core.analyze_segments(payload, 6)
    strings = [pair for seg in segments for pair in seg.get("strings", [])]
    hits = core.merge_segment_hits(segments)
    packages = core.packages_to_components(rootfs)
    opacity = core.reconcile_opacity(opacity, hits + packages, standards)
    bom = core.build_sbom(name, data, None, arch, hits, 6, len(strings),
                          container=container, opacity=opacity,
                          payload=payload, standards=standards,
                          segments=segments, rootfs=rootfs, packages=packages)
    spdx = spdx_report.build_spdx(bom, name, core.TOOL_NAME, core.TOOL_VERSION)
    return {"data": data, "container": container, "payload": payload,
            "arch": arch, "opacity": opacity, "standards": standards,
            "strings": strings, "hits": hits, "bom": bom, "spdx": spdx,
            "segments": segments, "rootfs": rootfs, "packages": packages}


def versions(result):
    """{component name: version} across signature hits and embedded standards."""
    found = {h["sig"]["name"]: h["version"] for h in result["hits"]}
    found.update({s["name"]: s["version"] for s in result["standards"]})
    return found


# --------------------------------------------------------------------------- #

class SignatureDatabaseTest(unittest.TestCase):
    """The shipped signature packs must be loadable and internally sound."""

    def test_packs_load(self):
        sigs = core.load_signatures()
        self.assertGreaterEqual(len(sigs), 30)
        self.assertIn("mcu-rtos", core.SIGNATURE_PACKS)
        self.assertIn("linux", core.SIGNATURE_PACKS)

    def test_names_are_unique(self):
        names = [s["name"] for s in core.get_signatures()]
        self.assertEqual(len(names), len(set(names)), "duplicate signature name")

    def test_every_signature_validates(self):
        # _validate_signature is what the loader enforces; running it again
        # here means a hand-edited pack fails in the test suite, not in front
        # of a customer.
        for sig in core.get_signatures():
            core._validate_signature(sig, f"pack {sig.get('pack')}")

    def test_versionless_signatures_explain_themselves(self):
        """Every signature either captures a version or says why it cannot.

        Some components genuinely put no version anywhere in a stripped image -
        nrfx and the nRF5 DFU transport leave only API symbol names, confirmed
        against a real device image. Inventing a regex for those would be the
        guessing this tool refuses to do. So the rule is not "every signature
        must capture a version", which invites a fake pattern; it is "a
        signature with no version pattern must carry a version_note", which a
        fake pattern cannot satisfy and a reader can check.
        """
        missing = []
        for sig in core.get_signatures():
            if any("vgroup" in p for p in sig["patterns"]):
                continue
            if not sig.get("version_note"):
                missing.append(sig["name"])
        self.assertEqual(
            [], sorted(missing),
            "signatures with neither a version-capturing pattern nor a "
            "version_note explaining why one is impossible")

    def test_version_notes_reach_the_sbom(self):
        """The distinction has to survive into the document, not just the DB."""
        components = analyze("cortexm_rtos.bin")["bom"]["components"]
        cmsis = next(c for c in components if c["name"] == "cmsis")
        props = {p["name"]: p["value"] for p in cmsis["properties"]}
        self.assertNotIn("version", cmsis)
        self.assertIn("fw2sbom:version", props)

    def test_missing_database_is_an_error(self):
        """No packs must fail loudly, never produce an empty SBOM quietly.

        A component database that did not ship is the one failure this tool
        cannot report as "no components found".
        """
        empty = tempfile.mkdtemp(prefix="fw2sbom-nosigs-")
        original = core._resource_dir
        try:
            core._resource_dir = lambda: empty
            with self.assertRaises(ValueError) as caught:
                core.load_signatures()
            self.assertIn("no signature packs found", str(caught.exception))
        finally:
            core._resource_dir = original
            shutil.rmtree(empty, ignore_errors=True)
            core.load_signatures()          # restore the real database

    def test_bad_pack_is_rejected(self):
        bad = tempfile.mkdtemp(prefix="fw2sbom-badsig-")
        try:
            path = os.path.join(bad, "broken.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"pack": "broken", "signatures": [
                    {"name": "x", "type": "library", "purl": "pkg:generic/x",
                     "description": "d",
                     "patterns": [{"regex": "([unclosed", "weight": 0.5}]}]}, f)
            with self.assertRaises(ValueError) as caught:
                core.load_signatures([bad])
            self.assertIn("does not compile", str(caught.exception))
        finally:
            shutil.rmtree(bad, ignore_errors=True)
            core.load_signatures()          # restore the real database

    def test_pack_may_override_a_builtin(self):
        extra = tempfile.mkdtemp(prefix="fw2sbom-override-")
        try:
            with open(os.path.join(extra, "custom.json"), "w",
                      encoding="utf-8") as f:
                json.dump({"pack": "custom", "signatures": [
                    {"name": "busybox", "type": "application",
                     "purl": "pkg:generic/busybox-custom",
                     "description": "customer override",
                     "patterns": [{"regex": "BusyBox", "weight": 0.9}]}]}, f)
            sigs = {s["name"]: s for s in core.load_signatures([extra])}
            self.assertEqual(sigs["busybox"]["purl"], "pkg:generic/busybox-custom")
        finally:
            shutil.rmtree(extra, ignore_errors=True)
            core.load_signatures()


# --------------------------------------------------------------------------- #

class StringExtractionTest(unittest.TestCase):

    def test_ascii_runs(self):
        data = b"\x00\x01hello world\x00\xff"
        self.assertEqual(core.extract_strings(data, 6), [(2, "hello world")])

    def test_utf16le_runs(self):
        data = b"\xff" + "OpenSSL 1.1.1w".encode("utf-16-le") + b"\xff"
        self.assertEqual(core.extract_strings(data, 6), [(1, "OpenSSL 1.1.1w")])

    def test_both_encodings_sorted_by_offset(self):
        data = ("AAAAAAAA".encode("ascii") + b"\x00"
                + "BBBBBBBB".encode("utf-16-le"))
        offsets = [off for off, _ in core.extract_strings(data, 6)]
        self.assertEqual(offsets, sorted(offsets))
        self.assertEqual([s for _, s in core.extract_strings(data, 6)],
                         ["AAAAAAAA", "BBBBBBBB"])

    def test_min_length_is_respected(self):
        self.assertEqual(core.extract_strings(b"\x00abc\x00", 6), [])


# --------------------------------------------------------------------------- #

class ArchitectureTest(unittest.TestCase):

    def test_cortex_m_identified(self):
        result = analyze("cortexm_rtos.bin")
        self.assertEqual(result["arch"]["label"], "ARM Cortex-M (Thumb)")
        self.assertTrue(result["arch"]["looks_like_cortex_m"])

    def test_mcs51_identified(self):
        result = analyze("mcs51_display.bin")
        self.assertEqual(result["arch"]["label"], "MCS-51 / 8051")
        self.assertGreaterEqual(len(result["arch"]["mcs51"]["vectors"]), 3)
        self.assertGreaterEqual(result["arch"]["mcs51"]["opcode_ratio"], 0.08)

    def test_the_two_detectors_are_exclusive(self):
        mcs51 = analyze("mcs51_display.bin")["arch"]
        self.assertFalse(mcs51["looks_like_cortex_m"])
        cortex = analyze("cortexm_rtos.bin")["arch"]
        self.assertFalse(cortex.get("mcs51", {}).get("looks_like_mcs51", False))

    def test_unknown_architecture_is_reported_as_unknown(self):
        for name in ("bare_unknown.bin", "random_flat.bin", "router_uimage.bin"):
            with self.subTest(fixture=name):
                self.assertIsNone(analyze(name)["arch"]["label"])


# --------------------------------------------------------------------------- #

class OpacityTest(unittest.TestCase):

    def test_encrypted_payload_is_opaque(self):
        opacity = analyze("opaque_encrypted.bin")["opacity"]
        self.assertTrue(opacity["opaque"])
        self.assertEqual(opacity["verdict"], "opaque")
        self.assertGreater(opacity["entropy"], core.OPACITY_STRONG)

    def test_opaque_payload_becomes_a_component(self):
        bom = analyze("opaque_encrypted.bin")["bom"]
        opaque = [c for c in bom["components"] if c["type"] == "firmware"]
        self.assertEqual(len(opaque), 1,
                         "an opaque payload must still produce a component, so "
                         "that 'not analyzable' cannot be read as 'no components'")
        self.assertEqual(opaque[0]["evidence"]["identity"][0]["confidence"], 0.0)
        props = {p["name"]: p["value"] for p in opaque[0]["properties"]}
        self.assertEqual(props["fw2sbom:opaque"], "true")

    def test_identified_architecture_settles_the_verdict(self):
        """Dense 8051 code reaches ~7 bits/byte and must not be called packed."""
        result = analyze("mcs51_display.bin")
        self.assertGreater(result["opacity"]["entropy"], 6.5)
        self.assertFalse(result["opacity"]["opaque"])
        self.assertEqual(result["opacity"]["verdict"], "plaintext")

    def test_plain_image_is_plaintext(self):
        self.assertEqual(analyze("cortexm_rtos.bin")["opacity"]["verdict"],
                         "plaintext")

    def test_identified_components_override_an_opaque_verdict(self):
        """A payload we read component banners out of is not opaque.

        packet_back.bin de-frames on the wrong side, so framing bytes stay
        interleaved and the entropy reads as ciphertext - while the scanner
        still recovers every version banner. Reporting both is incoherent.
        """
        result = analyze("packet_back.bin")
        self.assertGreater(len(result["hits"]), 0)
        self.assertFalse(result["opacity"]["opaque"])
        self.assertEqual(result["opacity"]["verdict"], "mixed")
        self.assertEqual(result["opacity"]["original_verdict"], "opaque")
        props = {p["name"]: p["value"]
                 for p in result["bom"]["metadata"]["component"]["properties"]}
        self.assertEqual(
            props["fw2sbom:payload_verdict_before_reconciliation"], "opaque")

    def test_reconciliation_leaves_a_real_opaque_payload_alone(self):
        opacity = core.analyze_opacity(fixture("opaque_encrypted.bin"))
        self.assertIs(opacity, core.reconcile_opacity(opacity, [], []))


# --------------------------------------------------------------------------- #

class ContainerTest(unittest.TestCase):

    def test_framing_first_is_detected_and_stripped(self):
        result = analyze("packet_front.bin")
        container = result["container"]
        self.assertIsNotNone(container, "packetized framing was not detected")
        self.assertEqual(container["stride"], 36)
        self.assertEqual(container["payload_width"], 32)
        self.assertEqual(container["framing_width"], 4)
        self.assertEqual(len(result["payload"]), container["payload_bytes"])
        self.assertEqual(len(result["payload"]) % 32, 0)

    def test_length_byte_is_identified(self):
        container = analyze("packet_front.bin")["container"]
        self.assertIsNotNone(container.get("length_byte"),
                             "the constant column equal to the payload width is "
                             "the strongest framing evidence available")

    def test_de_framed_payload_analyses_like_the_original(self):
        """De-framing must recover the image the records were carved from."""
        framed = analyze("packet_front.bin")
        plain = analyze("cortexm_rtos.bin")
        self.assertEqual(framed["arch"]["label"], plain["arch"]["label"])
        self.assertEqual(versions(framed), versions(plain))

    def test_framing_last_loses_the_first_chunk(self):
        """A documented limitation, pinned so a change to it is deliberate."""
        back = analyze("packet_back.bin")
        front = analyze("packet_front.bin")
        self.assertIsNotNone(back["container"])
        self.assertEqual(len(back["payload"]),
                         len(front["payload"]) - front["container"]["payload_width"])

    def test_random_data_is_not_a_container(self):
        """The false-positive guard: 200 KiB of noise must not de-frame."""
        self.assertIsNone(core.detect_packet_container(fixture("random_flat.bin")))

    def test_flat_image_is_not_a_container(self):
        self.assertIsNone(core.detect_packet_container(fixture("cortexm_rtos.bin")))


# --------------------------------------------------------------------------- #

class SignatureMatchingTest(unittest.TestCase):

    def test_exact_versions_are_captured(self):
        found = versions(analyze("cortexm_rtos.bin"))
        for name, version in [("zephyr", "3.5.99-ncs1"), ("freertos", "10.5.1"),
                              ("mbedtls", "3.4.0"), ("lwip", "2.1.3"),
                              ("littlefs", "2.8.0"),
                              ("gcc-arm-none-eabi", "12.2.0")]:
            with self.subTest(component=name):
                self.assertEqual(found.get(name), version)

    def test_ncs_banner_gives_an_exact_version(self):
        """The NCS boot banner carries the release; prefer it over inference."""
        hits = {h["sig"]["name"]: h for h in analyze("cortexm_rtos.bin")["hits"]}
        ncs = hits["nrf-connect-sdk"]
        self.assertEqual(ncs["version"], "2.6.0")
        self.assertNotIn("version_inferred", ncs)
        self.assertGreaterEqual(ncs["confidence"], 0.9)

    def test_exact_ncs_version_reaches_the_purl(self):
        bom = analyze("cortexm_rtos.bin")["bom"]
        ncs = next(c for c in bom["components"] if c["name"] == "nrf-connect-sdk")
        props = {p["name"]: p["value"] for p in ncs["properties"]}
        self.assertEqual(props["fw2sbom:version_source"], "exact-version-string")
        self.assertTrue(ncs["purl"].endswith("@2.6.0"))

    def test_ncs_release_is_still_inferred_without_a_banner(self):
        """Images built from NCS without a boot banner keep the fork-tag route.

        The mapping table is the only version source for those, so it has to
        stay covered even though the fixture now takes the better path.
        """
        signatures = {s["name"]: s for s in core.get_signatures()}
        zephyr = {"sig": signatures["zephyr"], "confidence": 0.9,
                  "version": "3.5.99-ncs1", "evidence": []}
        ncs = {"sig": signatures["nrf-connect-sdk"], "confidence": 0.6,
               "version": None, "evidence": []}
        core.infer_versions([zephyr, ncs])
        self.assertEqual(ncs["version"], "2.6.x")
        self.assertIn("NCS release mapping table", ncs["version_inferred"])

    def test_inferred_versions_never_reach_the_purl(self):
        """A purl version is read downstream as exact; an inferred one is not."""
        signatures = {s["name"]: s for s in core.get_signatures()}
        hit = {"sig": signatures["nrf-connect-sdk"], "confidence": 0.6,
               "version": "2.6.x", "version_inferred": "from the fork tag",
               "evidence": [(signatures["nrf-connect-sdk"]["patterns"][0],
                             0, "Booting nRF Connect SDK", None)]}
        bom = core.build_sbom("x.bin", b"\x00" * 64, None,
                              {"label": None, "details": [],
                               "looks_like_cortex_m": False},
                              [hit], 6, 0)
        comp = bom["components"][0]
        props = {p["name"]: p["value"] for p in comp["properties"]}
        self.assertEqual(props["fw2sbom:version_source"], "inferred")
        self.assertNotIn("@", comp["purl"])

    def test_exact_versions_do_reach_the_purl(self):
        bom = analyze("cortexm_rtos.bin")["bom"]
        mbedtls = next(c for c in bom["components"] if c["name"] == "mbedtls")
        self.assertTrue(mbedtls["purl"].endswith("@3.4.0"))

    def test_confidence_is_capped_below_certainty(self):
        for hit in analyze("cortexm_rtos.bin")["hits"]:
            self.assertLessEqual(hit["confidence"], 0.97)
            self.assertGreater(hit["confidence"], 0.0)

    def test_utf16_only_banners_are_matched(self):
        """Without UTF-16LE extraction this fixture yields nothing at all."""
        found = versions(analyze("cortexm_utf16.bin"))
        self.assertEqual(found.get("openssl"), "1.1.1w")
        self.assertEqual(found.get("sqlite"), "3.42.0")
        self.assertEqual(found.get("libcurl"), "8.1.2")

    def test_nothing_is_invented_for_an_unknown_image(self):
        result = analyze("bare_unknown.bin")
        self.assertEqual(result["hits"], [])
        self.assertEqual(result["standards"], [])
        self.assertEqual(result["bom"]["components"], [])


# --------------------------------------------------------------------------- #

class EmbeddedStandardsTest(unittest.TestCase):

    def test_edid_blocks_are_parsed(self):
        blocks = core.detect_edid_blocks(fixture("mcs51_display.bin"))
        self.assertEqual(len(blocks), 2)
        self.assertEqual([b["pnp_id"] for b in blocks], ["ABC", "XYZ"])
        self.assertEqual(blocks[0]["version"], "1.4")
        self.assertEqual(blocks[0]["name"], "FIXTURE-24")
        self.assertEqual(blocks[0]["manufacture_year"], 2023)

    def test_mccs_version_is_parsed(self):
        found = versions(analyze("mcs51_display.bin"))
        self.assertEqual(found.get("vesa-mccs"), "2.2")

    def test_standards_are_labelled_as_data_not_libraries(self):
        """An embedded EDID table is not a linked library and must not look
        like one to whoever reads the SBOM."""
        bom = analyze("mcs51_display.bin")["bom"]
        for name in ("vesa-e-edid", "vesa-mccs"):
            comp = next(c for c in bom["components"] if c["name"] == name)
            props = {p["name"]: p["value"] for p in comp["properties"]}
            self.assertEqual(props["fw2sbom:evidence_class"],
                             "embedded-standard-data")
            self.assertEqual(comp["type"], "data")

    def test_a_corrupt_edid_block_is_rejected(self):
        block = bytearray(make_fixtures.edid_block(
            "ABC", 1, 2, 3, 2020, "1.4", "X"))
        block[127] ^= 0xFF                     # break the checksum
        self.assertEqual(core.detect_edid_blocks(bytes(block)), [])


# --------------------------------------------------------------------------- #

class SbomStructureTest(unittest.TestCase):
    """Shape checks that hold for every image, whatever was found in it."""

    ALL = ("cortexm_rtos.bin", "cortexm_utf16.bin", "mcs51_display.bin",
           "packet_front.bin", "packet_back.bin", "opaque_encrypted.bin",
           "random_flat.bin", "router_uimage.bin", "bare_unknown.bin")

    def test_is_valid_cyclonedx_16_json(self):
        for name in self.ALL:
            with self.subTest(fixture=name):
                bom = json.loads(json.dumps(analyze(name)["bom"]))
                self.assertEqual(bom["bomFormat"], "CycloneDX")
                self.assertEqual(bom["specVersion"], "1.6")
                self.assertTrue(bom["serialNumber"].startswith("urn:uuid:"))
                self.assertEqual(bom["metadata"]["component"]["type"], "firmware")

    def test_bom_refs_are_unique_and_dependencies_resolve(self):
        for name in self.ALL:
            with self.subTest(fixture=name):
                bom = analyze(name)["bom"]
                refs = [c["bom-ref"] for c in bom["components"]]
                refs.append(bom["metadata"]["component"]["bom-ref"])
                self.assertEqual(len(refs), len(set(refs)), "duplicate bom-ref")
                known = set(refs)
                for dep in bom["dependencies"]:
                    self.assertIn(dep["ref"], known)
                    for target in dep["dependsOn"]:
                        self.assertIn(target, known)

    def test_every_component_carries_evidence(self):
        for name in self.ALL:
            with self.subTest(fixture=name):
                for comp in analyze(name)["bom"]["components"]:
                    identity = comp["evidence"]["identity"]
                    self.assertTrue(identity, f"{comp['name']} has no identity")
                    for entry in identity:
                        self.assertTrue(entry["methods"],
                                        f"{comp['name']} identity has no method")
                        self.assertGreaterEqual(entry["confidence"], 0.0)
                        self.assertLessEqual(entry["confidence"], 0.97)

    def test_disclaimers_are_always_present(self):
        for name in self.ALL:
            with self.subTest(fixture=name):
                props = {p["name"]: p["value"]
                         for p in analyze(name)["bom"]["metadata"]["properties"]}
                self.assertEqual(props["fw2sbom:sbom_type"], "binary-derived")
                self.assertIn("Absence of a component is not evidence of absence",
                              props["fw2sbom:disclaimer"])

    def test_signature_database_provenance_is_recorded(self):
        """'We scanned for 34 things and found 2' is only auditable if the 34
        is in the file."""
        props = {p["name"]: p["value"]
                 for p in analyze("cortexm_rtos.bin")["bom"]["metadata"]["properties"]}
        self.assertEqual(int(props["fw2sbom:signature_database_size"]),
                         len(core.get_signatures()))
        self.assertIn("mcu-rtos", props["fw2sbom:signature_packs"])

    def test_container_metadata_is_recorded_when_de_framed(self):
        props = {p["name"]: p["value"]
                 for p in analyze("packet_front.bin")["bom"]["metadata"]["component"]["properties"]}
        self.assertEqual(props["fw2sbom:container"], "packetized-record-framing")
        self.assertEqual(props["fw2sbom:container_record_stride"], "36")
        self.assertEqual(props["fw2sbom:offset_reference"]
                         if "fw2sbom:offset_reference" in props else
                         "payload (container framing stripped)",
                         "payload (container framing stripped)")


# --------------------------------------------------------------------------- #

class ContainerTest(unittest.TestCase):
    """Linux images keep everything worth naming inside compressed regions.

    Until the walker existed, a router image produced the correct verdict
    ("compressed") and a completely empty SBOM. These tests pin the capability
    that replaced that.
    """

    def test_uimage_header_is_parsed(self):
        header = container.parse_uimage(fixture("router_uimage.bin"))
        self.assertIsNotNone(header)
        self.assertEqual(header["os"], "Linux")
        self.assertEqual(header["architecture"], "mips")
        self.assertEqual(header["compression"], "gzip")
        self.assertIn("Linux-5.10.110", header["name"])

    def test_segments_are_identified_in_image_order(self):
        segments = analyze("router_uimage.bin")["segments"]
        kinds = [s["kind"] for s in segments]
        self.assertEqual(kinds[0], "boot-header")
        self.assertIn("kernel", kinds)
        self.assertIn("filesystem", kinds)
        offsets = [s["offset"] for s in segments]
        self.assertEqual(offsets, sorted(offsets))

    def test_the_kernel_is_decompressed(self):
        kernel = next(s for s in analyze("router_uimage.bin")["segments"]
                      if s["kind"] == "kernel")
        self.assertTrue(kernel["expanded"])
        self.assertGreater(len(kernel["content"]), kernel["length"])

    def test_components_inside_the_compressed_kernel_are_found(self):
        """The whole point: these strings are unreachable in the raw bytes."""
        found = versions(analyze("router_uimage.bin"))
        self.assertEqual(found.get("linux-kernel"), "5.10.110")
        self.assertEqual(found.get("gcc"), "10.3.0")

    def test_evidence_names_the_segment_a_match_came_from(self):
        bom = analyze("router_uimage.bin")["bom"]
        kernel = next(c for c in bom["components"] if c["name"] == "linux-kernel")
        value = kernel["evidence"]["identity"][0]["methods"][0]["value"]
        self.assertIn("kernel", value.lower())
        props = {p["name"]: p["value"] for p in kernel["properties"]}
        self.assertIn("kernel", props["fw2sbom:found_in_segments"].lower())

    def test_the_segment_map_reaches_the_sbom(self):
        props = {p["name"]: p["value"] for p in
                 analyze("router_uimage.bin")["bom"]["metadata"]["component"]["properties"]}
        segment_props = [v for k, v in props.items() if k.startswith("fw2sbom:segment_")]
        self.assertGreaterEqual(len(segment_props), 3)
        self.assertTrue(any("SquashFS" in v for v in segment_props))

    def test_a_damaged_filesystem_degrades_instead_of_crashing(self):
        """Firmware comes from customers; a bad image must not be a traceback.

        This fixture's SquashFS superblock is valid but its tables point past
        the end of the image. The segment must still be reported, the analysis
        must still finish, and the failure must be written down.
        """
        result = analyze("router_uimage.bin")
        segment = next(s for s in result["segments"]
                       if s["kind"] == "filesystem")
        self.assertIsNotNone(segment.get("filesystem"),
                             "the superblock is valid and must be recognised")
        self.assertEqual(result["packages"], [],
                         "no package database is readable from a broken image")
        self.assertTrue(segment["warnings"],
                        "an unreadable filesystem must record why")
        # And the rest of the image was still analysed.
        self.assertEqual(versions(result).get("linux-kernel"), "5.10.110")

    def test_flat_mcu_images_still_see_one_segment(self):
        """The microcontroller path must be untouched by any of this."""
        for name in ("cortexm_rtos.bin", "mcs51_display.bin", "bare_unknown.bin"):
            with self.subTest(fixture=name):
                segments = analyze(name)["segments"]
                self.assertEqual(len(segments), 1)
                self.assertEqual(segments[0]["kind"], "image")
                self.assertEqual(len(segments[0]["content"]),
                                 len(analyze(name)["payload"]))

    def test_unsupported_compression_is_named_not_hidden(self):
        """lzo/lz4/zstd have no stdlib decompressor; say so, do not skip."""
        with self.assertRaises(ValueError) as caught:
            container._expand("lz4", b"\x00" * 64)
        self.assertIn("lz4", str(caught.exception))


class SquashFSTest(unittest.TestCase):

    def test_superblock_rejects_what_it_cannot_read(self):
        for blob, expected in [
            (b"xxxx" + b"\x00" * 200, "superblock"),
            (b"hsqs" + b"\x00" * 200, "supported"),
        ]:
            with self.subTest(expected=expected):
                with self.assertRaises(squashfs.SquashFSError) as caught:
                    squashfs.SquashFS(blob)
                self.assertIn(expected, str(caught.exception).lower())

    def test_unsupported_compressor_is_named(self):
        blob = bytearray(b"hsqs" + b"\x00" * 200)
        struct.pack_into("<HHHHHH", blob, 20, 3, 17, 0, 1, 4, 0)   # lzo, v4.0
        with self.assertRaises(squashfs.SquashFSError) as caught:
            squashfs.SquashFS(bytes(blob))
        self.assertIn("lzo", str(caught.exception))

    def test_find_offsets(self):
        data = b"..." + squashfs.MAGIC + b"x" * 40 + squashfs.MAGIC
        self.assertEqual(squashfs.find_offsets(data), [3, 47])

    def test_limits_are_set_below_anything_plausible(self):
        """These exist so a crafted image cannot hang or exhaust the analyser."""
        self.assertLessEqual(squashfs.MAX_DEPTH, 128)
        self.assertLessEqual(squashfs.MAX_ENTRIES, 1_000_000)
        self.assertLessEqual(squashfs.MAX_TOTAL_READ, 1024 * 1024 * 1024)


# --------------------------------------------------------------------------- #

class EvidenceWorkbookTest(unittest.TestCase):

    SHEETS = ["Summary", "Candidate Components", "Evidence Register",
              "Bank Analysis", "Scan Coverage", "CycloneDX Summary"]

    def workbook(self, name):
        result = analyze(name)
        context = core.build_evidence_context(
            name, result["data"], result["payload"], result["arch"],
            result["container"], result["opacity"], result["hits"],
            result["standards"], name + ".cdx.json")
        buffer = io.BytesIO()
        evidence_report.build_workbook(context, result["bom"]).save(buffer)
        return buffer.getvalue()

    def test_workbook_is_a_readable_xlsx(self):
        raw = self.workbook("cortexm_rtos.bin")
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            self.assertIsNone(z.testzip())
            names = z.namelist()
            self.assertIn("[Content_Types].xml", names)
            self.assertIn("xl/workbook.xml", names)
            book = z.read("xl/workbook.xml").decode("utf-8")
        for sheet in self.SHEETS:
            self.assertIn(sheet, book, f"missing worksheet: {sheet}")

    def test_edid_sheet_appears_only_when_edid_is_found(self):
        with zipfile.ZipFile(io.BytesIO(self.workbook("mcs51_display.bin"))) as z:
            self.assertIn("EDID Profiles", z.read("xl/workbook.xml").decode())
        with zipfile.ZipFile(io.BytesIO(self.workbook("cortexm_rtos.bin"))) as z:
            self.assertNotIn("EDID Profiles", z.read("xl/workbook.xml").decode())

    def test_negative_evidence_is_recorded(self):
        """Which signatures were scanned and NOT found is itself a finding."""
        result = analyze("cortexm_rtos.bin")
        context = core.build_evidence_context(
            "cortexm_rtos.bin", result["data"], result["payload"],
            result["arch"], result["container"], result["opacity"],
            result["hits"], result["standards"], "x.json")
        self.assertEqual(context["n_not_found"],
                         len(core.get_signatures()) - len(result["hits"]))
        self.assertGreater(context["n_not_found"], 0)
        names = {s["name"] for s in context["not_found"]}
        self.assertIn("busybox", names)

    def test_every_fixture_produces_a_workbook(self):
        for name in SbomStructureTest.ALL:
            with self.subTest(fixture=name):
                self.assertGreater(len(self.workbook(name)), 4096)


# --------------------------------------------------------------------------- #

class ServiceTest(unittest.TestCase):

    def setUp(self):
        service._SBOM_STORE.clear()

    def test_analyze_bytes_matches_the_cli(self):
        """The UI and the CLI must not be able to disagree about an image."""
        data = fixture("cortexm_rtos.bin")
        result = service.analyze_bytes("cortexm_rtos.bin", data)
        cli = analyze("cortexm_rtos.bin")
        self.assertEqual(result["architecture"], cli["arch"]["label"])
        self.assertEqual({c["name"] for c in result["components"]},
                         set(versions(cli)))
        bom = json.loads(result["sbom_json"])
        self.assertEqual(len(bom["components"]), len(cli["bom"]["components"]))

    def test_deliverables_are_produced_in_memory(self):
        result = service.analyze_bytes("mcs51_display.bin",
                                       fixture("mcs51_display.bin"))
        self.assertTrue(result["sbom_filename"].endswith("_SBOM.cdx.json"))
        self.assertTrue(result["spdx_filename"].endswith("_SBOM.spdx.json"))
        self.assertTrue(result["evidence_filename"].endswith("_Evidence.xlsx"))
        with zipfile.ZipFile(io.BytesIO(result["evidence_xlsx"])) as z:
            self.assertIsNone(z.testzip())

    def test_both_sbom_formats_are_offered(self):
        """The UI's two SBOM links must come from one analysis."""
        result = service.analyze_bytes("cortexm_rtos.bin",
                                       fixture("cortexm_rtos.bin"))
        cdx = json.loads(result["sbom_json"])
        spdx = json.loads(result["spdx_json"])
        self.assertEqual(spdx["spdxVersion"], "SPDX-2.3")
        self.assertEqual(len(spdx["packages"]), len(cdx["components"]) + 1)

    def test_spdx_is_downloadable_from_the_store(self):
        service._store_put("abc", {"spdx": "{}", "spdx_name": "x.spdx.json"})
        self.assertEqual(service._store_get("abc")["spdx_name"], "x.spdx.json")

    def test_store_evicts_the_oldest_entry_when_full(self):
        for i in range(service.SBOM_STORE_MAX_ENTRIES + 5):
            service._store_put(f"id{i}", {"json": "{}", "json_name": "a.json"})
        self.assertEqual(len(service._SBOM_STORE),
                         service.SBOM_STORE_MAX_ENTRIES)
        self.assertIsNone(service._store_get("id0"))
        self.assertIsNotNone(service._store_get(
            f"id{service.SBOM_STORE_MAX_ENTRIES + 4}"))

    def test_store_expires_entries_by_age(self):
        service._store_put("old", {"json": "{}", "json_name": "a.json"})
        service._SBOM_STORE["old"]["stored_at"] -= service.SBOM_STORE_TTL_SECONDS + 1
        self.assertIsNone(service._store_get("old"))
        self.assertNotIn("old", service._SBOM_STORE)

    def test_opaque_image_still_returns_a_usable_result(self):
        result = service.analyze_bytes("opaque_encrypted.bin",
                                       fixture("opaque_encrypted.bin"))
        self.assertTrue(result["opacity"]["opaque"])
        self.assertEqual(result["components"], [])
        self.assertGreater(len(json.loads(result["sbom_json"])["components"]), 0)


# --------------------------------------------------------------------------- #

class SchemaValidationTest(unittest.TestCase):
    """Validate against the official CycloneDX 1.6 schema when it is available.

    The schema and jsonschema are optional: fetch them with
    `python tests/fetch_schema.py` (CI does). Without them the test skips
    rather than silently passing.
    """

    SCHEMA_DIR = os.path.join(HERE, "schema")

    @classmethod
    def setUpClass(cls):
        try:
            import jsonschema                            # noqa: F401
        except ImportError:
            raise unittest.SkipTest("jsonschema is not installed")
        path = os.path.join(cls.SCHEMA_DIR, "bom-1.6.schema.json")
        if not os.path.exists(path):
            raise unittest.SkipTest(
                "CycloneDX schema not present; run tests/fetch_schema.py")
        cls.schema_path = path

    def _validator(self):
        """A validator that can resolve the schema's sibling $refs.

        bom-1.6.schema.json refers to spdx and jsf by bare filename, so both
        have to be registered. jsonschema 4.18 replaced RefResolver with the
        `referencing` library; support both so the suite does not break on
        whichever version CI resolves.
        """
        from jsonschema import validators

        with open(self.schema_path, encoding="utf-8") as f:
            schema = json.load(f)
        siblings = {}
        for name in ("spdx.schema.json", "jsf-0.82.schema.json"):
            path = os.path.join(self.SCHEMA_DIR, name)
            if os.path.exists(path):
                with open(path, encoding="utf-8") as f:
                    siblings[name] = json.load(f)

        cls = validators.validator_for(schema)
        try:
            from referencing import Registry, Resource

            # All three schemas declare draft-07; each is registered under its
            # bare filename (how bom-1.6 refers to it) as well as its own $id.
            registry = Registry().with_resources(
                [(name, Resource.from_contents(doc))
                 for name, doc in siblings.items()])
            return cls(schema, registry=registry)
        except ImportError:
            import jsonschema

            store = dict(siblings)
            for name, doc in siblings.items():
                if "$id" in doc:
                    store[doc["$id"]] = doc
            resolver = jsonschema.RefResolver.from_schema(schema, store=store)
            return cls(schema, resolver=resolver)

    def test_every_fixture_sbom_validates(self):
        validator = self._validator()
        for name in SbomStructureTest.ALL:
            with self.subTest(fixture=name):
                errors = sorted(validator.iter_errors(analyze(name)["bom"]),
                                key=lambda e: list(e.path))
                self.assertEqual(
                    [], [f"{list(e.path)}: {e.message}" for e in errors])



# --------------------------------------------------------------------------- #

class SpdxTest(unittest.TestCase):
    """SPDX 2.3 is a second rendering of one analysis, not a second analysis."""

    def test_document_shape(self):
        doc = analyze("cortexm_rtos.bin")["spdx"]
        self.assertEqual(doc["spdxVersion"], "SPDX-2.3")
        self.assertEqual(doc["dataLicense"], "CC0-1.0")
        self.assertEqual(doc["SPDXID"], "SPDXRef-DOCUMENT")
        self.assertTrue(doc["documentNamespace"].startswith("https://"))
        self.assertTrue(doc["creationInfo"]["creators"][0].startswith("Tool: fw2sbom-"))

    def test_spdx_ids_are_valid_and_unique(self):
        for name in SbomStructureTest.ALL:
            with self.subTest(fixture=name):
                doc = analyze(name)["spdx"]
                ids = [p["SPDXID"] for p in doc["packages"]]
                self.assertEqual(len(ids), len(set(ids)), "duplicate SPDXID")
                for spdx_id in ids:
                    self.assertRegex(spdx_id, r"^SPDXRef-[A-Za-z0-9.\-]+$")

    def test_relationships_resolve(self):
        for name in SbomStructureTest.ALL:
            with self.subTest(fixture=name):
                doc = analyze(name)["spdx"]
                known = {p["SPDXID"] for p in doc["packages"]}
                known.add("SPDXRef-DOCUMENT")
                describes = [r for r in doc["relationships"]
                             if r["relationshipType"] == "DESCRIBES"]
                self.assertEqual(len(describes), 1)
                for rel in doc["relationships"]:
                    self.assertIn(rel["spdxElementId"], known)
                    self.assertIn(rel["relatedSpdxElement"], known)

    def test_same_components_as_the_cyclonedx_document(self):
        """The two files are handed to different tools; they must agree."""
        for name in SbomStructureTest.ALL:
            with self.subTest(fixture=name):
                result = analyze(name)
                cdx = {(c["name"], c.get("version")) for c in result["bom"]["components"]}
                spdx = {(p["name"], p["versionInfo"])
                        for p in result["spdx"]["packages"][1:]}
                spdx = {(n, None if v == "NOASSERTION" else v) for n, v in spdx}
                self.assertEqual(cdx, spdx)

    def test_purls_are_carried_as_external_refs(self):
        doc = analyze("cortexm_rtos.bin")["spdx"]
        mbedtls = next(p for p in doc["packages"] if p["name"] == "mbedtls")
        refs = mbedtls["externalRefs"]
        self.assertEqual(refs[0]["referenceType"], "purl")
        self.assertTrue(refs[0]["referenceLocator"].endswith("@3.4.0"))

    def test_evidence_survives_into_comments(self):
        """SPDX has nowhere structured for evidence; it must not be dropped."""
        doc = analyze("cortexm_rtos.bin")["spdx"]
        mbedtls = next(p for p in doc["packages"] if p["name"] == "mbedtls")
        self.assertIn("binary-analysis", mbedtls["comment"])
        self.assertIn("offset", mbedtls["comment"])
        self.assertTrue(any("confidence" in a["comment"]
                            for a in mbedtls["annotations"]))

    def test_missing_version_is_explained(self):
        doc = analyze("cortexm_rtos.bin")["spdx"]
        cmsis = next(p for p in doc["packages"] if p["name"] == "cmsis")
        self.assertEqual(cmsis["versionInfo"], "NOASSERTION")
        self.assertTrue(any("No version could be determined" in a["comment"]
                            for a in cmsis["annotations"]))

    def test_document_states_that_cyclonedx_is_authoritative(self):
        """A reader holding only the SPDX file must learn what it loses."""
        doc = analyze("cortexm_rtos.bin")["spdx"]
        self.assertIn("CycloneDX", doc["comment"])
        self.assertIn("Absence of a component is not evidence of absence",
                      doc["comment"])

    def test_root_package_carries_the_firmware_hashes(self):
        doc = analyze("cortexm_rtos.bin")["spdx"]
        root = doc["packages"][0]
        self.assertEqual(root["primaryPackagePurpose"], "FIRMWARE")
        algorithms = {c["algorithm"] for c in root["checksums"]}
        self.assertIn("SHA256", algorithms)

    def test_opaque_payload_appears_as_a_package(self):
        doc = analyze("opaque_encrypted.bin")["spdx"]
        self.assertEqual(len(doc["packages"]), 2,
                         "the opaque payload must be a package here too, or the "
                         "SPDX reader sees an empty SBOM and reads it as clean")

    def test_rendering_is_stable_across_runs(self):
        """Same image, same findings - only timestamps may differ."""
        first = analyze("cortexm_rtos.bin")["spdx"]
        second = spdx_report.build_spdx(
            analyze("cortexm_rtos.bin")["bom"], "cortexm_rtos.bin",
            core.TOOL_NAME, core.TOOL_VERSION)
        self.assertEqual(spdx_report.document_digest(first),
                         spdx_report.document_digest(second))


class SpdxSchemaValidationTest(unittest.TestCase):
    """Validate against the SPDX specification's own schema when available."""

    @classmethod
    def setUpClass(cls):
        try:
            import jsonschema                            # noqa: F401
        except ImportError:
            raise unittest.SkipTest("jsonschema is not installed")
        path = os.path.join(HERE, "schema", "spdx-2.3.schema.json")
        if not os.path.exists(path):
            raise unittest.SkipTest(
                "SPDX schema not present; run tests/fetch_schema.py")
        cls.schema_path = path

    def test_every_fixture_spdx_validates(self):
        from jsonschema import validators

        with open(self.schema_path, encoding="utf-8") as f:
            schema = json.load(f)
        validator = validators.validator_for(schema)(schema)
        for name in SbomStructureTest.ALL:
            with self.subTest(fixture=name):
                errors = sorted(validator.iter_errors(analyze(name)["spdx"]),
                                key=lambda e: list(e.path))
                self.assertEqual(
                    [], [f"{list(e.path)}: {e.message}" for e in errors])



# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #

class ElfReaderTest(unittest.TestCase):
    """The ELF reader parses untrusted binaries out of customer firmware."""

    @staticmethod
    def minimal_elf(machine=8, elf_class=1, endian=1, elf_type=2):
        """An ELF header with no program or section headers.

        52 bytes for 32-bit and 64 for 64-bit, and the two put e_ehsize
        onwards at different offsets - which is the whole reason the reader
        branches on EI_CLASS, and why a 64-bit header squeezed into 52 bytes
        must be rejected rather than half-read.
        """
        is64 = elf_class == 2
        head = bytearray(64 if is64 else 52)
        head[0:4] = b"ELF"
        head[4], head[5], head[6] = elf_class, endian, 1
        fmt = "<" if endian == 1 else ">"
        struct.pack_into(fmt + "HH", head, 16, elf_type, machine)
        struct.pack_into(fmt + "H", head, 54 if is64 else 40,
                         64 if is64 else 52)          # e_ehsize
        return bytes(head)

    def test_header_fields(self):
        info = elf.parse(self.minimal_elf())
        self.assertEqual(info["machine"], "MIPS")
        self.assertEqual(info["class"], 32)
        self.assertEqual(info["endian"], "little")
        self.assertEqual(info["type"], "EXEC")

    def test_big_endian_and_64_bit_are_read(self):
        info = elf.parse(self.minimal_elf(machine=183, elf_class=2, endian=2,
                                          elf_type=3))
        self.assertEqual(info["machine"], "AArch64")
        self.assertEqual(info["class"], 64)
        self.assertEqual(info["endian"], "big")
        self.assertEqual(info["type"], "DYN")

    def test_non_elf_is_rejected(self):
        for blob in (b"", b"MZ\x90\x00", b"\x7fELX" + b"\x00" * 60,
                     b"\x7fELF" + b"\x09" + b"\x00" * 60):
            with self.subTest(blob=blob[:8]):
                self.assertIsNone(elf.parse(blob))

    def test_truncated_headers_do_not_raise(self):
        """Firmware is untrusted; a short read must not be a traceback."""
        full = self.minimal_elf()
        for cut in range(4, len(full)):
            with self.subTest(length=cut):
                elf.parse(full[:cut])          # must simply not raise

    def test_absurd_header_counts_are_ignored(self):
        blob = bytearray(self.minimal_elf())
        struct.pack_into("<HH", blob, 44, 0xFFFF, 40)   # e_phnum, e_shentsize
        struct.pack_into("<H", blob, 48, 0xFFFF)        # e_shnum
        info = elf.parse(bytes(blob))
        self.assertIsNotNone(info)
        self.assertEqual(info["needed"], [])

    def test_soname_key_strips_the_version(self):
        self.assertEqual(elf.soname_key("libcrypto.so.1.1"), "libcrypto.so")
        self.assertEqual(elf.soname_key("/usr/lib/libz.so.1"), "libz.so")
        self.assertEqual(elf.soname_key("busybox"), "busybox")
        self.assertIsNone(elf.soname_key(None))

    def test_machine_names_cover_the_targets_we_claim(self):
        for machine_id in (8, 40, 183, 62, 243):
            self.assertNotIn("machine-", elf.EM_NAMES[machine_id])


class RealFirmwareTest(unittest.TestCase):
    """Run the whole pipeline over a real vendor image.

    Synthetic fixtures prove the parsers follow the specifications. Only a real
    image proves they survive what a vendor actually shipped, and that is where
    firmware parsing usually breaks. The image is not in git; fetch it with
    `python scripts/fetch-corpus.py` and these tests start running.
    """

    IMAGE = os.path.join(ROOT, "corpus", "router",
                         "openwrt-mt300n-v2-4.3.25.bin")

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(cls.IMAGE):
            raise unittest.SkipTest(
                "corpus image missing; run python scripts/fetch-corpus.py")
        with open(cls.IMAGE, "rb") as f:
            cls.data = f.read()
        cls.segments, cls.rootfs, cls.warnings = core.analyze_segments(
            cls.data, 6)
        cls.hits = core.merge_segment_hits(cls.segments)
        cls.packages = core.packages_to_components(cls.rootfs)

    def test_the_container_is_walked_without_warnings(self):
        self.assertEqual(self.warnings, [])
        kinds = [s["kind"] for s in self.segments]
        self.assertEqual(kinds[:3], ["boot-header", "kernel", "filesystem"])

    def test_the_uimage_header_names_the_kernel(self):
        header = self.segments[0]["uimage"]
        self.assertEqual(header["architecture"], "mips")
        self.assertEqual(header["compression"], "lzma")
        self.assertIn("Linux-5.10.176", header["name"])

    def test_the_kernel_yields_its_version(self):
        found = {h["sig"]["name"]: h["version"] for h in self.hits}
        self.assertEqual(found.get("linux-kernel"), "5.10.176")

    def test_a_mips_build_is_not_called_an_arm_toolchain(self):
        """The generic GCC banner matches any target; the name must not lie."""
        names = {h["sig"]["name"] for h in self.hits}
        self.assertIn("gcc", names)
        self.assertNotIn("gcc-arm-none-eabi", names)

    def test_the_squashfs_rootfs_is_read(self):
        image = next(s for s in self.segments
                     if s["kind"] == "filesystem")["filesystem"]
        self.assertEqual((image.version_major, image.version_minor), (4, 0))
        self.assertEqual(image.compressor, "xz")
        self.assertGreater(self.rootfs["file_count"], 3000)
        self.assertEqual(image.warnings, [])

    def test_the_distribution_is_identified(self):
        release = self.rootfs["os_release"]
        self.assertEqual(release["name"], "OpenWrt")
        self.assertEqual(release["version"], "22.03.4")
        self.assertEqual(release["architecture"], "mipsel_24kc")

    def test_the_package_database_gives_exact_versions(self):
        """The best component data a Linux firmware image contains."""
        self.assertGreater(len(self.packages), 300)
        self.assertTrue(all(p["version"] for p in self.packages),
                        "every opkg entry carries a version")
        by_name = {p["name"]: p["version"] for p in self.packages}
        for name, version in [("busybox", "1.35.0-5"),
                              ("dropbear", "2022.82-2"),
                              ("libopenssl1.1", "1.1.1t-2"),
                              ("zlib", "1.2.11-6"),
                              ("libcurl4", "7.88.1-1")]:
            with self.subTest(package=name):
                self.assertEqual(by_name.get(name), version)

    def test_packages_are_marked_as_database_evidence(self):
        """A package record is not a heuristic and must not read like one."""
        bom = core.build_sbom(
            self.IMAGE, self.data, None,
            {"label": None, "details": [], "looks_like_cortex_m": False},
            self.hits, 6, 0, segments=self.segments, rootfs=self.rootfs,
            packages=self.packages)
        busybox = next(c for c in bom["components"] if c["name"] == "busybox")
        props = {p["name"]: p["value"] for p in busybox["properties"]}
        self.assertEqual(props["fw2sbom:evidence_class"], "package-database")
        self.assertEqual(props["fw2sbom:version_source"], "package-database")
        self.assertTrue(busybox["purl"].startswith("pkg:opkg/busybox@"))

    def test_the_whole_image_produces_a_valid_sbom(self):
        bom = core.build_sbom(
            self.IMAGE, self.data, None,
            {"label": None, "details": [], "looks_like_cortex_m": False},
            self.hits, 6, 0, segments=self.segments, rootfs=self.rootfs,
            packages=self.packages, firmware_version="4.3.25")
        self.assertGreater(len(bom["components"]), 350)
        refs = [c["bom-ref"] for c in bom["components"]]
        self.assertEqual(len(refs), len(set(refs)))
        self.assertEqual(bom["metadata"]["component"]["version"], "4.3.25")
        # The distribution and the kernel are both operating-system components
        # and both belong here: one is what the vendor shipped, the other is
        # what it runs on, and a CVE feed has entries for each.
        operating_systems = {c["name"]: c["version"] for c in bom["components"]
                             if c["type"] == "operating-system"}
        self.assertEqual(operating_systems.get("OpenWrt"), "22.03.4")
        self.assertEqual(operating_systems.get("linux-kernel"), "5.10.176")

    def test_the_architecture_comes_from_the_elf_headers(self):
        """A Linux image has no vector table; this is the only source."""
        binaries = self.rootfs["binaries"]
        self.assertEqual(binaries["architecture"], "MIPS (32-bit little-endian)")
        self.assertGreater(binaries["binary_count"], 400)

    def test_library_dependencies_are_resolved(self):
        binaries = self.rootfs["binaries"]
        self.assertGreater(binaries["file_dependency_count"], 500)
        self.assertGreater(len(binaries["package_dependencies"]), 100)

    def test_kernel_modules_declare_their_licence(self):
        modules = self.rootfs["binaries"]["modules"]
        self.assertGreater(len(modules), 150)
        licensed = [m for m in modules if m["license"]]
        self.assertGreater(len(licensed), 150)

    def test_packages_carry_their_declared_licence(self):
        licensed = [p for p in self.packages if p.get("license")]
        self.assertGreater(len(licensed), 200)
        by_name = {p["name"]: p.get("license") for p in self.packages}
        self.assertEqual(by_name.get("busybox"), "GPL-2.0")
        self.assertEqual(by_name.get("dropbear"), "MIT")

    def test_declared_cpes_are_read_not_invented(self):
        """OpenWrt tags the security-relevant packages with a CPE itself.

        Reading that is not the CPE generation that was cut from the plan: the
        vendor stated it, we pass it through, and the property says so.
        """
        with_cpe = {p["name"]: p["cpe"] for p in self.packages if p.get("cpe")}
        self.assertGreater(len(with_cpe), 40)
        self.assertEqual(with_cpe.get("busybox"),
                         "cpe:2.3:a:busybox:busybox:1.35.0:*:*:*:*:*:*:*")
        self.assertEqual(with_cpe.get("libopenssl1.1"),
                         "cpe:2.3:a:openssl:openssl:1.1.1t:*:*:*:*:*:*:*")

    def test_the_sbom_carries_a_real_dependency_graph(self):
        bom = core.build_sbom(
            self.IMAGE, self.data, None,
            {"label": None, "details": [], "looks_like_cortex_m": False},
            self.hits, 6, 0, segments=self.segments, rootfs=self.rootfs,
            packages=self.packages)
        edges = sum(len(d["dependsOn"]) for d in bom["dependencies"][1:])
        self.assertGreater(edges, 500, "package-to-package edges")
        refs = {c["bom-ref"] for c in bom["components"]}
        refs.add(bom["metadata"]["component"]["bom-ref"])
        for entry in bom["dependencies"]:
            self.assertIn(entry["ref"], refs)
            for target in entry["dependsOn"]:
                self.assertIn(target, refs)
        busybox = next(c for c in bom["components"] if c["name"] == "busybox")
        self.assertEqual(busybox["licenses"][0]["license"]["name"], "GPL-2.0")
        self.assertTrue(busybox["cpe"].startswith("cpe:2.3:a:busybox:"))

    def test_a_real_image_is_analysed_in_reasonable_time(self):
        """A customer waits for this in a browser."""
        start = time.perf_counter()
        core.analyze_segments(self.data, 6)
        self.assertLess(time.perf_counter() - start, 60)


if __name__ == "__main__":
    unittest.main(verbosity=2)
