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
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import evidence_report                                  # noqa: E402
import fw2sbom as core                                   # noqa: E402
import make_fixtures                                     # noqa: E402
import spdx_report                                       # noqa: E402
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
    strings = core.extract_strings(payload, 6)
    hits = core.match_signatures(strings)
    core.infer_versions(hits)
    opacity = core.reconcile_opacity(opacity, hits, standards)
    bom = core.build_sbom(name, data, None, arch, hits, 6, len(strings),
                          container=container, opacity=opacity,
                          payload=payload, standards=standards)
    spdx = spdx_report.build_spdx(bom, name, core.TOOL_NAME, core.TOOL_VERSION)
    return {"data": data, "container": container, "payload": payload,
            "arch": arch, "opacity": opacity, "standards": standards,
            "strings": strings, "hits": hits, "bom": bom, "spdx": spdx}


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

class KnownGapTest(unittest.TestCase):
    """Behaviour we know is wrong and have not fixed yet.

    These assertions exist to be inverted. When the Phase 2 container walker
    lands, this test fails - and that failure is the signal that the roadmap
    item is done, not a regression.
    """

    def test_compressed_linux_firmware_yields_nothing_today(self):
        result = analyze("router_uimage.bin")
        self.assertEqual(
            result["hits"], [],
            "router_uimage.bin now yields components - if the container walker "
            "has landed, invert this test and record it in RELEASE.md")

    def test_but_the_result_is_not_silently_presented_as_complete(self):
        """Even with nothing found, the SBOM must carry its own limitations."""
        bom = analyze("router_uimage.bin")["bom"]
        props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
        self.assertIn("fw2sbom:disclaimer", props)
        self.assertEqual(bom["components"], [])


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
