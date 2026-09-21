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

import hashlib
import io
import json
import os
import random
import shutil
import struct
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile
import zlib
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import container                                        # noqa: E402
import cpio                                             # noqa: E402
import cramfs                                           # noqa: E402
import image_input                                      # noqa: E402
import jffs2                                            # noqa: E402
import lzo                                              # noqa: E402
import elf                                              # noqa: E402
import esp32                                            # noqa: E402
import ext                                              # noqa: E402
import evidence_report                                  # noqa: E402
import fit                                              # noqa: E402
import fw2sbom as core                                   # noqa: E402
import make_fixtures                                     # noqa: E402
import spdx_report                                       # noqa: E402
import squashfs                                          # noqa: E402
import ubi                                              # noqa: E402
import ubifs                                            # noqa: E402
import uefi                                             # noqa: E402
import vendor_container                                 # noqa: E402
import vendor_sbom                                      # noqa: E402
import yaffs                                            # noqa: E402
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
    """The shared pipeline, exactly as the CLI and the service call it.

    This helper used to carry its own copy of the sequence, and it mirrored
    main() - so it passed while the service, which carried a third copy,
    dropped every rootfs component found without a package database. A test
    helper with a private pipeline tests a pipeline the product may not have.
    """
    data = fixture(name)
    source = image_input.detect_and_load(data)
    result = core.run_analysis(data, source, name)
    spdx = spdx_report.build_spdx(result["bom"], name, core.TOOL_NAME,
                                  core.TOOL_VERSION)
    return {"data": data, "container": result["container"],
            "payload": result["payload"], "arch": result["arm_info"],
            "opacity": result["opacity"], "standards": result["standards"],
            "strings": result["strings"], "hits": result["hits"],
            "bom": result["bom"], "spdx": spdx,
            "segments": result["segments"], "rootfs": result["rootfs"],
            "packages": result["packages"]}


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
           "random_flat.bin", "router_uimage.bin", "bare_unknown.bin",
           "encrypted_kernel.bin", "esp32_app.bin", "esp32_flash.bin",
           "uefi_volume.bin", "uefi_flash.bin", "cramfs_rootfs.bin",
           "jffs2_rootfs.bin", "cramfs_jffs2_flash.bin", "ubifs_rootfs.bin",
           "ubi_flash.bin", "fit_initramfs.bin", "fit_sysupgrade.bin",
           "kernel_initramfs.bin", "ext2_rootfs.bin", "ext4_disk.img.gz",
           "yaffs2_rootfs.bin")

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

class SegmentOpacityTest(unittest.TestCase):
    """A firmware image is not one substance, and must not be judged as one.

    encrypted_kernel.bin is a flash dump: a small encrypted kernel followed by
    megabytes of erased flash. Measured in one go the padding outvotes the
    ciphertext and the image reads as low-entropy "plaintext" - so the SBOM
    would say the firmware is plaintext and contains no components, when the
    truth is that its one real region could not be read at all. Reporting
    "nothing is in here" for "we could not open this" is the single failure
    this tool exists to avoid.
    """

    FIXTURE = "encrypted_kernel.bin"

    def segments(self):
        return analyze(self.FIXTURE)["segments"]

    def test_the_whole_image_measurement_would_say_plaintext(self):
        """The premise of the test: the naive measurement is wrong here."""
        whole = core.analyze_opacity(fixture(self.FIXTURE))
        self.assertFalse(whole["opaque"])
        self.assertLess(whole["entropy"], 4.0)

    def test_the_encrypted_segment_is_judged_on_its_own_bytes(self):
        kernel = next(s for s in self.segments() if s["kind"] == "kernel")
        verdict = kernel["opacity"]
        self.assertTrue(verdict["opaque"])
        self.assertGreater(verdict["entropy"], core.OPACITY_STRONG)
        self.assertLessEqual(verdict["longest_run"], core.OPACITY_MAX_RUN)

    def test_erased_flash_is_recognised_as_holding_no_content(self):
        """Padding is not a finding, and must not dilute one either."""
        blank = [s for s in self.segments() if s.get("blank")]
        self.assertTrue(blank, "the 0xFF tail was not recognised")
        self.assertGreater(blank[0]["length"], 1024 * 1024)
        self.assertIsNone(blank[0]["opacity"])

    def test_repeated_blocks_are_reported_as_a_cipher_mode_signal(self):
        """Identical ciphertext blocks say more than "high entropy" does."""
        kernel = next(s for s in self.segments() if s["kind"] == "kernel")
        self.assertGreater(kernel["opacity"]["duplicate_16b_blocks"], 100)
        reasons = " ".join(kernel["opacity"]["reasons"])
        self.assertIn("ECB", reasons)

    def test_the_headline_verdict_comes_from_the_segments(self):
        summary = core.summarise_opacity(
            self.segments(), core.analyze_opacity(fixture(self.FIXTURE)))
        self.assertTrue(summary["opaque"])
        self.assertEqual(summary["whole_image_verdict"], "plaintext")
        self.assertIn("dominated by regions that hold no content",
                      " ".join(summary["reasons"]))

    def test_the_unreadable_region_becomes_a_component(self):
        """"Nothing found" and "could not look" must not produce the same SBOM."""
        bom = analyze(self.FIXTURE)["bom"]
        opaque = [c for c in bom["components"] if c["type"] == "firmware"]
        self.assertEqual(len(opaque), 1)
        props = {p["name"]: p["value"] for p in opaque[0]["properties"]}
        self.assertEqual(props["fw2sbom:opaque"], "true")
        self.assertEqual(props["fw2sbom:segment_offset"], "0x40")
        self.assertGreater(int(props["fw2sbom:segment_bytes"]), 100000)
        self.assertEqual(opaque[0]["evidence"]["identity"][0]["confidence"], 0.0)
        self.assertIn("vendor", opaque[0]["description"].lower())

    def test_an_identified_instruction_set_still_settles_a_flat_image(self):
        """Dense microcontroller code reaches ~7 bits/byte legitimately.

        An entropy threshold alone calls that encrypted; a recognised vector
        table settles what the statistic cannot. Per-segment judging briefly
        dropped the architecture on the way through and reported ordinary
        Cortex-M firmware as an unreadable region - with every test passing,
        because the helper skipped the step main() actually takes.
        """
        for name in ("cortexm_rtos.bin", "cortexm_utf16.bin",
                     "mcs51_display.bin"):
            with self.subTest(fixture=name):
                result = analyze(name)
                self.assertIsNotNone(result["arch"]["label"])
                self.assertFalse(result["opacity"]["opaque"])
                self.assertEqual(core.opaque_segments(result["segments"]), [],
                                 "an identified image has no unreadable region")

    def test_a_flat_mcu_image_is_judged_exactly_as_before(self):
        """One segment covering the payload must behave as it always did."""
        for name, expected in [("cortexm_rtos.bin", False),
                               ("opaque_encrypted.bin", True)]:
            with self.subTest(fixture=name):
                result = analyze(name)
                self.assertEqual(len(result["segments"]), 1)
                self.assertEqual(result["opacity"]["opaque"], expected)


# --------------------------------------------------------------------------- #

class VendorSbomTest(unittest.TestCase):
    """A vendor's SBOM is a different kind of claim, and must stay one.

    Static analysis stops at an encrypted region; the supplier's own document
    is the only way past it. Merging one has to keep two things: which
    document each component came from, and where the vendor's account and the
    binary disagree - that disagreement is often the most useful thing in the
    report, and averaging it away would destroy it.
    """

    CYCLONEDX = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
        "metadata": {
            "timestamp": "2026-01-15T09:00:00Z",
            "component": {"type": "firmware", "name": "EXAMPLE-CAM", "version": "2.0"},
            "tools": {"components": [{"type": "application", "name": "vendor-gen"}]},
        },
        "components": [
            {"type": "library", "name": "mbedtls", "version": "3.4.0",
             "purl": "pkg:github/Mbed-TLS/mbedtls@3.4.0",
             "supplier": {"name": "Example Devices"},
             "licenses": [{"license": {"id": "Apache-2.0"}}]},
            {"type": "library", "name": "lwip", "version": "2.2.0",
             "purl": "pkg:github/lwip-tcpip/lwip@2.2.0"},
            {"type": "library", "name": "example-proprietary-stack",
             "version": "7.1", "purl": "pkg:generic/example-stack@7.1",
             "description": "Closed source; no binary evidence expected"},
        ],
    }

    SPDX = {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT", "name": "EXAMPLE-CAM-2.0",
        "documentNamespace": "https://example.invalid/spdx/cam",
        "creationInfo": {"created": "2026-01-15T09:00:00Z",
                         "creators": ["Tool: vendor-spdx-1.0"]},
        "packages": [
            {"SPDXID": "SPDXRef-1", "name": "littlefs", "versionInfo": "2.8.0",
             "downloadLocation": "NOASSERTION", "copyrightText": "NOASSERTION",
             "licenseConcluded": "BSD-3-Clause",
             "supplier": "Organization: Example Devices",
             "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                               "referenceType": "purl",
                               "referenceLocator": "pkg:github/littlefs-project/littlefs@2.8.0"}]},
        ],
    }

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="fw2sbom-vendor-")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, name, document):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(document, f)
        return path

    # --- reading ---------------------------------------------------------
    def test_reads_cyclonedx(self):
        loaded = vendor_sbom.load(self.write("v.cdx.json", self.CYCLONEDX))
        self.assertEqual(loaded["document"]["format"], "CycloneDX 1.6")
        self.assertEqual(loaded["document"]["produced_by"], "vendor-gen")
        names = [c["name"] for c in loaded["components"]]
        self.assertEqual(names, ["mbedtls", "lwip", "example-proprietary-stack"])
        self.assertEqual(loaded["components"][0]["licenses"], ["Apache-2.0"])
        self.assertEqual(loaded["components"][0]["supplier"], "Example Devices")

    def test_reads_spdx(self):
        loaded = vendor_sbom.load(self.write("v.spdx.json", self.SPDX))
        self.assertTrue(loaded["document"]["format"].startswith("SPDX 2.3"))
        component = loaded["components"][0]
        self.assertEqual(component["name"], "littlefs")
        self.assertEqual(component["version"], "2.8.0")
        self.assertTrue(component["purl"].endswith("@2.8.0"))
        self.assertEqual(component["licenses"], ["BSD-3-Clause"])
        self.assertEqual(component["supplier"], "Example Devices")

    def test_unreadable_documents_are_refused_with_a_reason(self):
        """A vendor's file comes from outside; it must never be a traceback."""
        broken = os.path.join(self.dir, "broken.json")
        with open(broken, "w", encoding="utf-8") as f:
            f.write("{ not json")
        cases = [
            (broken, "not readable JSON"),
            (self.write("empty.json", {"hello": "world"}), "neither CycloneDX"),
            (self.write("nocomp.json", {"bomFormat": "CycloneDX",
                                        "specVersion": "1.6",
                                        "components": []}), "no components"),
            (os.path.join(self.dir, "missing.json"), "cannot open"),
        ]
        for path, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaises(vendor_sbom.VendorSBOMError) as caught:
                    vendor_sbom.load(path)
                self.assertIn(expected, str(caught.exception))

    # --- comparison ------------------------------------------------------
    def test_a_version_the_image_contradicts_is_a_conflict(self):
        """The single most useful thing this comparison produces."""
        result = analyze("cortexm_rtos.bin")
        found = core.identified_components(result["hits"], result["standards"], [])
        loaded = vendor_sbom.load(self.write("v.cdx.json", self.CYCLONEDX))
        agree, conflicts, vendor_only, _ = vendor_sbom.compare(
            found, loaded["components"])

        # mbedtls 3.4.0 is in the fixture and in the document.
        self.assertIn("mbedtls", [a["vendor"]["name"] for a in agree])
        # lwip is 2.1.3 in the image, and the vendor claims 2.2.0.
        conflict = next(c for c in conflicts if c["vendor"]["name"] == "lwip")
        self.assertEqual(conflict["vendor_version"], "2.2.0")
        self.assertEqual(conflict["our_version"], "2.1.3")
        # Nothing in the binary speaks to the proprietary stack either way.
        self.assertIn("example-proprietary-stack",
                      [c["name"] for c in vendor_only])

    def test_matching_is_by_versionless_purl_where_there_is_one(self):
        key = vendor_sbom.normalise_key
        self.assertEqual(key("anything", "pkg:opkg/busybox@1.35.0-5"),
                         key("BusyBox", "pkg:opkg/busybox@1.36.0"))
        self.assertNotEqual(key("a", "pkg:opkg/a@1"), key("b", "pkg:opkg/b@1"))
        self.assertEqual(key("BusyBox", None), key("busybox", None))

    # --- what reaches the document ---------------------------------------
    def merged_bom(self, *documents):
        result = analyze("cortexm_rtos.bin")
        loaded = [vendor_sbom.load(self.write(f"v{i}.json", d))
                  for i, d in enumerate(documents)]
        vendor = core.reconcile_vendor_sboms(
            loaded, result["hits"], result["standards"], [])
        return core.build_sbom(
            "cortexm_rtos.bin", result["data"], None, result["arch"],
            result["hits"], 6, 0, standards=result["standards"],
            segments=result["segments"], vendor=vendor), vendor

    def test_vendor_components_are_labelled_not_blended(self):
        """An auditor must be able to tell an assertion from an observation."""
        bom, _ = self.merged_bom(self.CYCLONEDX)
        vendor = [c for c in bom["components"]
                  if any(p["name"] == "fw2sbom:evidence_class"
                         and p["value"] == "vendor-sbom"
                         for p in c["properties"])]
        self.assertEqual(len(vendor), 3)
        for component in vendor:
            props = {p["name"]: p["value"] for p in component["properties"]}
            self.assertEqual(props["fw2sbom:source_document"], "v0.json")
            # We did not observe these, so we claim no confidence in them.
            self.assertEqual(
                component["evidence"]["identity"][0]["confidence"], 0.0)
            self.assertTrue(
                {"fw2sbom:vendor_conflict", "fw2sbom:vendor_corroborated",
                 "fw2sbom:vendor_unverified"} & set(props),
                "every vendor component must say how it relates to the image")

    def test_the_conflict_is_stated_in_the_document(self):
        bom, _ = self.merged_bom(self.CYCLONEDX)
        metadata = {p["name"]: p["value"] for p in bom["metadata"]["properties"]
                    if p["name"] == "fw2sbom:vendor_version_conflict"}
        self.assertTrue(metadata, "the conflict never reached the metadata")
        self.assertIn("lwip", list(metadata.values())[0])

    def test_several_documents_can_be_merged_at_once(self):
        bom, vendor = self.merged_bom(self.CYCLONEDX, self.SPDX)
        self.assertEqual(len(vendor), 2)
        refs = [c["bom-ref"] for c in bom["components"]]
        self.assertEqual(len(refs), len(set(refs)), "duplicate bom-ref")
        sources = {p["value"] for c in bom["components"] for p in c["properties"]
                   if p["name"] == "fw2sbom:source_document"}
        self.assertEqual(sources, {"v0.json", "v1.json"})

    def test_a_vendor_document_without_purls_still_matches(self):
        """Plenty of supplier SBOMs carry no purl at all - supplier-generated
        SPDX especially. Keying only on the purl meant those documents matched
        nothing and every component came back "declared but not observed",
        which reads as a clean bill of health when it is really a failure to
        compare."""
        ours = [{"name": "mbedtls", "version": "3.4.0",
                 "purl": "pkg:github/Mbed-TLS/mbedtls@3.4.0"}]
        vendor = [{"name": "mbedtls", "version": "3.4.1", "purl": None,
                   "supplier": None, "licenses": [], "bom_ref": "v1"}]
        agreements, conflicts, vendor_only, ours_only = vendor_sbom.compare(
            ours, vendor)
        self.assertEqual(conflicts[0]["our_version"], "3.4.0")
        self.assertEqual([], vendor_only)
        self.assertEqual([], ours_only)
        self.assertEqual([], agreements)

    def test_a_component_matched_once_is_not_also_reported_as_unmentioned(self):
        """It is indexed under both its purl and its name; asking the index
        what went unmatched would count it twice."""
        ours = [{"name": "lwip", "version": "2.1.3",
                 "purl": "pkg:github/lwip-tcpip/lwip@2.1.3"},
                {"name": "zephyr", "version": "3.5.0",
                 "purl": "pkg:github/zephyrproject-rtos/zephyr@3.5.0"}]
        vendor = [{"name": "lwip", "version": "2.1.3", "purl": None,
                   "supplier": None, "licenses": [], "bom_ref": "v1"}]
        _agree, _conflicts, _vendor_only, ours_only = vendor_sbom.compare(
            ours, vendor)
        self.assertEqual([c["name"] for c in ours_only], ["zephyr"])

    def test_the_merged_document_still_validates(self):
        """Merging must not produce something a consumer will reject."""
        bom, _ = self.merged_bom(self.CYCLONEDX, self.SPDX)
        self.assertEqual(bom["specVersion"], "1.6")
        for component in bom["components"]:
            self.assertIn("bom-ref", component)
            self.assertIn("name", component)
            self.assertIn("type", component)


# --------------------------------------------------------------------------- #

def build_intel_hex(payload, base=0x08000000, chunk=32):
    lines, upper = [], None

    def record(kind, address, data):
        body = bytes([len(data), (address >> 8) & 0xFF, address & 0xFF, kind]) + data
        return ":" + (body + bytes([(-sum(body)) & 0xFF])).hex().upper()

    for i in range(0, len(payload), chunk):
        address = base + i
        high = address >> 16
        if high != upper:
            lines.append(record(0x04, 0, high.to_bytes(2, "big")))
            upper = high
        lines.append(record(0x00, address & 0xFFFF, payload[i:i + chunk]))
    lines.append(record(0x01, 0, b""))
    return "\n".join(lines).encode()


def build_srec(payload, base=0x08000000, chunk=32):
    lines = ["S00600004844521B"]
    for i in range(0, len(payload), chunk):
        address, data = base + i, payload[i:i + chunk]
        core_bytes = bytes([4 + len(data) + 1]) + address.to_bytes(4, "big") + data
        lines.append("S3" + (core_bytes
                             + bytes([~sum(core_bytes) & 0xFF])).hex().upper())
    lines.append("S70500000000FA")
    return "\n".join(lines).encode()


def build_uf2(payload, base=0x08000000, family=0xE48BFF56):
    blocks, total = b"", (len(payload) + 255) // 256
    for index in range(total):
        chunk = payload[index * 256:(index + 1) * 256]
        blocks += struct.pack("<8I", 0x0A324655, 0x9E5D5157, 0x00002000,
                              base + index * 256, len(chunk), index, total,
                              family)
        blocks += chunk + b"\x00" * (476 - len(chunk))
        blocks += struct.pack("<I", 0x0AB16F30)
    return blocks


def build_elf_image(segments, machine=40, is64=False, little=True):
    """A linked ELF carrying PT_LOAD segments at absolute addresses."""
    endian = "<" if little else ">"
    ehsize = 64 if is64 else 52
    phentsize = 56 if is64 else 32
    offset = ehsize + phentsize * len(segments)
    body, headers = b"", b""
    for address, blob in segments:
        body += blob
        if is64:
            headers += struct.pack(endian + "IIQQQQQQ", 1, 4, offset, address,
                                   address, len(blob), len(blob), 4)
        else:
            headers += struct.pack(endian + "IIIIIIII", 1, offset, address,
                                   address, len(blob), len(blob), 4, 4)
        offset += len(blob)
    head = bytearray(ehsize)
    head[0:4] = b"\x7fELF"
    head[4], head[5], head[6] = (2 if is64 else 1), (1 if little else 2), 1
    struct.pack_into(endian + "HH", head, 16, 2, machine)
    if is64:
        struct.pack_into(endian + "Q", head, 32, ehsize)
        struct.pack_into(endian + "HHH", head, 52, ehsize, phentsize,
                         len(segments))
    else:
        struct.pack_into(endian + "I", head, 28, ehsize)
        struct.pack_into(endian + "HHH", head, 40, ehsize, phentsize,
                         len(segments))
    return bytes(head) + headers + body


class InputFormatTest(unittest.TestCase):
    """A toolchain hands out .elf; a flashing tool hands out .hex or .s19.

    A raw .bin is the form you have to know to ask for, and telling the person
    holding the firmware to go and find objcopy is not an answer. All four
    must reassemble to the same bytes, and therefore to the same SBOM.
    """

    def payload(self):
        return fixture("cortexm_rtos.bin")

    def test_every_format_reassembles_to_the_same_bytes(self):
        payload = self.payload()
        for label, blob in [
                ("Intel HEX", build_intel_hex(payload)),
                ("Motorola S-record", build_srec(payload)),
                ("UF2", build_uf2(payload)),
                ("ELF", build_elf_image([(0x08000000, payload)]))]:
            with self.subTest(format=label):
                loaded = image_input.detect_and_load(blob)
                self.assertTrue(loaded["converted"])
                self.assertTrue(loaded["format"].startswith(label.split()[0]))
                self.assertEqual(loaded["data"], payload)
                self.assertEqual(loaded["base_address"], 0x08000000)

    def test_raw_input_is_passed_through_untouched(self):
        """An ordinary .bin analysis must be byte-for-byte what it was."""
        payload = self.payload()
        loaded = image_input.detect_and_load(payload)
        self.assertFalse(loaded["converted"])
        self.assertIs(loaded["data"], payload)
        self.assertEqual(loaded["format"], "raw binary")

    def test_gaps_are_filled_with_erased_flash_and_reported(self):
        """What goes between two regions is a decision, and it is recorded."""
        blob = build_elf_image([(0x08000000, b"A" * 64),
                                (0x08000400, b"B" * 64)])
        loaded = image_input.detect_and_load(blob)
        self.assertEqual(len(loaded["data"]), 0x400 + 64)
        self.assertEqual(loaded["data"][:64], b"A" * 64)
        self.assertEqual(loaded["data"][64:0x400], b"\xff" * (0x400 - 64))
        self.assertEqual(loaded["gaps_filled"], 0x400 - 64)
        self.assertTrue(any("erased flash" in w for w in loaded["warnings"]))

    def test_a_corrupt_record_is_refused_with_the_line_number(self):
        """These files come from outside; a bad one must not be a traceback."""
        good = build_intel_hex(b"hello world" * 8)
        lines = good.split(b"\n")
        lines[2] = lines[2][:-2] + b"00"          # break one checksum
        with self.assertRaises(image_input.InputFormatError) as caught:
            image_input.detect_and_load(b"\n".join(lines))
        self.assertIn("checksum", str(caught.exception))
        self.assertIn("line 3", str(caught.exception))

        srec = build_srec(b"hello world" * 8).split(b"\n")
        srec[1] = srec[1][:-2] + b"00"
        with self.assertRaises(image_input.InputFormatError) as caught:
            image_input.detect_and_load(b"\n".join(srec))
        self.assertIn("checksum", str(caught.exception))

    def test_an_object_file_says_why_it_cannot_be_used(self):
        """The message has to tell the user what to go and get instead."""
        with self.assertRaises(image_input.InputFormatError) as caught:
            image_input.detect_and_load(build_elf_image([]))
        message = str(caught.exception)
        self.assertIn("object file", message)
        self.assertIn("linked image", message)

    def test_elf_reads_every_architecture_we_claim(self):
        for machine, name, is64 in [(40, "ARM", False), (8, "MIPS", False),
                                    (243, "RISC-V", True), (94, "Xtensa", False),
                                    (183, "AArch64", True)]:
            with self.subTest(machine=name):
                blob = build_elf_image([(0x1000, b"payload" * 32)],
                                       machine=machine, is64=is64)
                loaded = image_input.detect_and_load(blob)
                self.assertIn(name, loaded["format"])

    def test_a_uf2_with_mixed_families_is_flagged(self):
        payload = b"x" * 512
        mixed = (build_uf2(payload[:256], family=0x1111)
                 + build_uf2(payload[256:], base=0x08000100, family=0x2222))
        loaded = image_input.detect_and_load(mixed)
        self.assertTrue(any("family" in w for w in loaded["warnings"]))


class ReassembledAnalysisTest(unittest.TestCase):
    """Converting the input must not change a single conclusion."""

    def test_the_sbom_is_the_same_whichever_format_arrived(self):
        payload = fixture("cortexm_rtos.bin")
        baseline = analyze("cortexm_rtos.bin")
        expected = {h["sig"]["name"]: h["version"] for h in baseline["hits"]}

        for label, blob in [("hex", build_intel_hex(payload)),
                            ("srec", build_srec(payload)),
                            ("uf2", build_uf2(payload)),
                            ("elf", build_elf_image([(0x08000000, payload)]))]:
            with self.subTest(format=label):
                loaded = image_input.detect_and_load(blob)
                arch = core.analyze_architecture(loaded["data"])
                segments, rootfs, _w = core.analyze_segments(
                    loaded["data"], 6, False, arch["label"])
                hits = core.merge_segment_hits(segments)
                self.assertEqual(
                    {h["sig"]["name"]: h["version"] for h in hits}, expected)

    def test_the_document_says_it_was_reassembled(self):
        """Offsets then refer to the rebuilt image, and must say so."""
        payload = fixture("cortexm_rtos.bin")
        loaded = image_input.detect_and_load(build_intel_hex(payload))
        arch = core.analyze_architecture(loaded["data"])
        segments, rootfs, _w = core.analyze_segments(
            loaded["data"], 6, False, arch["label"])
        bom = core.build_sbom("delivered.hex", build_intel_hex(payload), None,
                              arch, core.merge_segment_hits(segments), 6, 0,
                              segments=segments, source=loaded)
        props = {p["name"]: p["value"]
                 for p in bom["metadata"]["component"]["properties"]}
        self.assertEqual(props["fw2sbom:input_format"], "Intel HEX")
        self.assertEqual(props["fw2sbom:image_base_address"], "0x8000000")
        self.assertIn("reassembled image", props["fw2sbom:offset_basis"])

    def test_hashes_describe_the_delivered_file_not_our_rebuild(self):
        """A customer checksums what they were sent, not what we made of it."""
        payload = fixture("cortexm_rtos.bin")
        delivered = build_intel_hex(payload)
        loaded = image_input.detect_and_load(delivered)
        arch = core.analyze_architecture(loaded["data"])
        segments, _r, _w = core.analyze_segments(loaded["data"], 6, False,
                                                 arch["label"])
        bom = core.build_sbom("delivered.hex", delivered, None, arch,
                              core.merge_segment_hits(segments), 6, 0,
                              segments=segments, source=loaded)
        recorded = {h["alg"]: h["content"]
                    for h in bom["metadata"]["component"]["hashes"]}
        self.assertEqual(recorded["SHA-256"],
                         hashlib.sha256(delivered).hexdigest())
        self.assertNotEqual(recorded["SHA-256"],
                            hashlib.sha256(payload).hexdigest())

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

    def test_an_unreadable_region_is_in_the_document_not_on_the_list(self):
        """The distinction the whole tool rests on: "we could not read this" is
        a finding worth recording, but it is not a component we identified."""
        result = service.analyze_bytes("opaque_encrypted.bin",
                                       fixture("opaque_encrypted.bin"))
        recorded = json.loads(result["sbom_json"])["components"]
        self.assertEqual(result["components"], [])
        self.assertTrue(any(p["name"] == "fw2sbom:opaque"
                            for c in recorded
                            for p in c.get("properties", [])), recorded)

    def test_opaque_image_still_returns_a_usable_result(self):
        result = service.analyze_bytes("opaque_encrypted.bin",
                                       fixture("opaque_encrypted.bin"))
        self.assertTrue(result["opacity"]["opaque"])
        self.assertEqual(result["components"], [])
        self.assertGreater(len(json.loads(result["sbom_json"])["components"]), 0)

    # --- vendor SBOMs through the browser ---------------------------------- #

    VENDOR_DOC = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": {"type": "firmware", "name": "ACME sensor"}},
        "components": [
            {"type": "library", "name": "mbedtls", "version": "3.4.1"},
            {"type": "library", "name": "lwip", "version": "2.1.3"},
            {"type": "library", "name": "wolfssl", "version": "5.6.0"},
        ],
    }

    def _with_vendor(self, extra=()):
        blob = json.dumps(self.VENDOR_DOC).encode("utf-8")
        uploads = [("supplier-a.cdx.json", blob)] + list(extra)
        return service.analyze_bytes("cortexm_rtos.bin",
                                     fixture("cortexm_rtos.bin"), uploads)

    def test_a_vendor_sbom_can_arrive_with_the_firmware(self):
        """The reconciliation was CLI-only until now, which left it out of
        reach of exactly the customers who need it most: an encrypted image
        cannot be read at all, and the supplier's own document is the only way
        to say anything about it."""
        result = self._with_vendor()
        self.assertEqual(len(result["vendor"]), 1)
        doc = result["vendor"][0]
        self.assertEqual(doc["file"], "supplier-a.cdx.json")
        self.assertEqual(doc["format"], "CycloneDX 1.6")
        self.assertEqual(doc["subject"], "ACME sensor")
        self.assertEqual(doc["declared"], 3)

    def test_a_version_the_image_contradicts_is_reported(self):
        """The most useful thing the comparison produces. The fixture contains
        mbed TLS 3.4.0; the vendor claims 3.4.1."""
        doc = self._with_vendor()["vendor"][0]
        self.assertEqual([c["name"] for c in doc["conflicts"]], ["mbedtls"])
        self.assertEqual(doc["conflicts"][0]["vendor_version"], "3.4.1")
        self.assertEqual(doc["conflicts"][0]["our_version"], "3.4.0")
        self.assertEqual([c["name"] for c in doc["not_observed"]], ["wolfssl"])
        self.assertEqual(doc["corroborated"], 1)          # lwip 2.1.3 agrees

    def test_an_unreadable_vendor_document_is_named_not_swallowed(self):
        """"No conflicts found" and "we could not open your supplier's file"
        look identical on screen unless the second one says so."""
        result = self._with_vendor([("broken.json", b"{not json")])
        self.assertEqual(len(result["vendor"]), 1)
        self.assertEqual(len(result["vendor_errors"]), 1)
        self.assertIn("broken.json", result["vendor_errors"][0])
        # and the analysis the customer actually came for still happened
        self.assertTrue(result["components"])

    def test_vendor_components_reach_the_document_labelled(self):
        result = self._with_vendor()
        bom = json.loads(result["sbom_json"])
        declared = [c for c in bom["components"]
                    if any(p["name"] == "fw2sbom:evidence_class"
                           and p["value"] == "vendor-sbom"
                           for p in c.get("properties", []))]
        self.assertEqual({c["name"] for c in declared},
                         {"mbedtls", "lwip", "wolfssl"})
        # and the screen shows exactly what the document contains
        self.assertEqual(len(result["components"]), len(bom["components"]))

    def test_no_vendor_document_means_no_vendor_section(self):
        result = service.analyze_bytes("cortexm_rtos.bin",
                                       fixture("cortexm_rtos.bin"))
        self.assertEqual(result["vendor"], [])
        self.assertEqual(result["vendor_errors"], [])

    def test_several_suppliers_are_compared_separately(self):
        """One product can have several suppliers, and merging their documents
        into one would lose which of them made which claim."""
        second = dict(self.VENDOR_DOC,
                      components=[{"type": "library", "name": "zephyr",
                                   "version": "3.5.99-ncs1"}])
        result = self._with_vendor(
            [("supplier-b.spdx.json", json.dumps(second).encode("utf-8"))])
        self.assertEqual([d["file"] for d in result["vendor"]],
                         ["supplier-a.cdx.json", "supplier-b.spdx.json"])
        self.assertEqual(result["vendor"][1]["corroborated"], 1)

    def test_multipart_keeps_every_value_of_a_repeated_field(self):
        """A dict keyed by field name silently kept only the last vendor file."""
        boundary = b"----fw2sbomtest"
        parts = []
        for name, filename, content in (
                ("file", "firmware.bin", b"\x00\x01"),
                ("vendor", "a.json", b"{}"),
                ("vendor", "b.json", b"[]")):
            parts.append(
                b"--" + boundary + b"\r\n"
                b'Content-Disposition: form-data; name="' + name.encode() +
                b'"; filename="' + filename.encode() + b'"\r\n\r\n' +
                content + b"\r\n")
        body = b"".join(parts) + b"--" + boundary + b"--\r\n"

        fields = service.parse_multipart(body, boundary)
        self.assertEqual([f[0] for f in fields["file"]], ["firmware.bin"])
        self.assertEqual([f[0] for f in fields["vendor"]], ["a.json", "b.json"])
        self.assertEqual(fields["vendor"][1][1], b"[]")

    def test_a_vendor_claim_about_a_uefi_module_is_compared(self):
        """A vendor SBOM for a BIOS names modules, and the comparison has to
        see the module inventory or it answers "declared but not observed" to
        every one of them - a clean bill of health that is really a failure to
        compare. Found by dragging a real BIOS into the real page: PciBusDxe
        came back unobserved while sitting in the list above it.
        """
        vendor = json.dumps({
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "components": [
                {"type": "device-driver", "name": "DxeCore", "version": "2.0"},
                {"type": "device-driver", "name": "PciBusDxe", "version": "1.0"},
                {"type": "library", "name": "zlib", "version": "1.2.13"},
            ],
        }).encode("utf-8")
        result = service.analyze_bytes("uefi_volume.bin", fixture("uefi_volume.bin"),
                                       [("bios-vendor.cdx.json", vendor)])
        doc = result["vendor"][0]
        self.assertEqual([c["name"] for c in doc["conflicts"]], ["DxeCore"])
        self.assertEqual(doc["conflicts"][0]["our_version"], "1.0")
        self.assertEqual(doc["corroborated"], 1)          # PciBusDxe agrees
        self.assertEqual([c["name"] for c in doc["not_observed"]], ["zlib"])

    def test_a_uefi_module_row_says_where_it_came_from(self):
        """123 rows tagged as plain signature hits misrepresents every one of
        them: none of them came from a string match."""
        result = service.analyze_bytes("uefi_volume.bin", fixture("uefi_volume.bin"))
        classes = {row["evidence_class"] for row in result["components"]}
        self.assertEqual(classes, {"uefi-module"})

    def test_the_browser_and_the_command_line_report_the_same_components(self):
        """They share one pipeline now. They did not before, and for eight
        releases the browser dropped every component found by scanning a Linux
        root filesystem that had no package database - most CCTV firmware -
        while the command line and every test reported them correctly.

        Asked of every fixture, because the drift was invisible on the ones
        that happened to carry a package database.
        """
        for name in SbomStructureTest.ALL:
            with self.subTest(fixture=name):
                browser = json.loads(
                    service.analyze_bytes(name, fixture(name))["sbom_json"])
                reference = analyze(name)["bom"]
                self.assertEqual(
                    sorted((c["name"], c.get("version") or "")
                           for c in browser["components"]),
                    sorted((c["name"], c.get("version") or "")
                           for c in reference["components"]))

    def test_a_rootfs_without_a_package_database_still_yields_components(self):
        """The specific case that was lost: nothing but the binaries to go on."""
        result = service.analyze_bytes("cramfs_rootfs.bin",
                                       fixture("cramfs_rootfs.bin"))
        names = {row["name"] for row in result["components"]}
        self.assertIn("busybox", names)
        self.assertIn("mbedtls", names)

    def test_the_page_names_the_architecture_it_knows(self):
        """A Linux image has no vector table, so the instruction set comes from
        the ELF binaries in its root filesystem. The command line always said
        so; the page used only the header-level answer and called a MIPS
        router "unidentified" while the document it handed over named it."""
        result = service.analyze_bytes("cramfs_rootfs.bin",
                                       fixture("cramfs_rootfs.bin"))
        self.assertIn("ARM", result["architecture"])
        self.assertIn("root filesystem", result["architecture"])
        header = service.analyze_bytes("cortexm_rtos.bin",
                                       fixture("cortexm_rtos.bin"))
        self.assertEqual(header["architecture"], "ARM Cortex-M (Thumb)")

    def test_the_screen_list_matches_the_document(self):
        """A customer reads the list in the browser and hands the download to
        an auditor. If the two disagree there is no way to tell which is wrong.

        The screen list used to be assembled from the signature hits, the
        embedded standards and the package database only, so every source added
        after that - vendor SBOMs, os-release files, Espressif app descriptors -
        appeared in the download and not on screen.
        """
        for name in ("esp32_flash.bin", "esp32_app.bin", "router_uimage.bin",
                     "cortexm_rtos.bin", "mcs51_display.bin"):
            with self.subTest(fixture=name):
                result = service.analyze_bytes(name, fixture(name))
                bom = json.loads(result["sbom_json"])
                identified = [
                    c for c in bom["components"]
                    if not any(p["name"] == "fw2sbom:opaque"
                               for p in c.get("properties", []))]
                self.assertEqual(
                    [(row["name"], row["version"])
                     for row in result["components"]],
                    [(c["name"], c.get("version")) for c in identified])

    def test_every_component_says_how_it_was_found(self):
        """evidence_class is what separates "we read this out of a package
        database" from "a string matched a regex"."""
        result = service.analyze_bytes("esp32_flash.bin",
                                       fixture("esp32_flash.bin"))
        classes = {row["evidence_class"] for row in result["components"]}
        self.assertEqual(classes, {"signature", "esp-idf-app-descriptor"})
        for row in result["components"]:
            self.assertIsNotNone(row["confidence"])
            self.assertIn(row["confidence_level"], ("high", "medium", "low"))



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

class EspressifTest(unittest.TestCase):
    """ESP32 parts are in a large share of the IoT devices a customer will send.

    What makes them worth a reader of their own is not the file format: it is
    that the image declares two things a scanner would otherwise have to guess.
    The chip ID gives the instruction set - and nothing else reliably separates
    the Xtensa parts from the RISC-V ones - while ESP-IDF writes its own version
    into a struct, which is evidence of a different quality from a banner string
    that happened to match a regex.

    The fixtures fill in every app-descriptor field. Real builds do not; the
    published Tasmota images fill in only idf_ver, which is why the blank cases
    are pinned here too.
    """

    @classmethod
    def setUpClass(cls):
        cls.app = fixture("esp32_app.bin")
        cls.flash = fixture("esp32_flash.bin")

    # --- the header -------------------------------------------------------- #

    def test_the_chip_id_names_the_part_and_its_core(self):
        image = esp32.parse_image(self.app)
        self.assertEqual(image["chip"], "ESP32")
        self.assertEqual(image["core"], "Xtensa LX6")
        self.assertEqual(image["entry_point"], make_fixtures.ESP_ENTRY)
        self.assertEqual(len(image["segments"]), 3)

    def test_a_risc_v_part_is_not_reported_as_xtensa(self):
        """The whole reason to read this field: an entropy or opcode heuristic
        cannot tell the two cores apart, and a CVE feed cares which it is."""
        patched = bytearray(self.app)
        patched[12:14] = struct.pack("<H", 0x0005)       # ESP32-C3
        image = esp32.parse_image(bytes(patched))
        self.assertEqual(image["chip"], "ESP32-C3")
        self.assertEqual(image["core"], "RISC-V")

    def test_an_unknown_chip_id_is_reported_as_unknown(self):
        """New parts ship faster than this table is updated; an unrecognised ID
        must not become a wrong name."""
        patched = bytearray(self.app)
        patched[12:14] = struct.pack("<H", 0x00FE)
        image = esp32.parse_image(bytes(patched))
        self.assertIn("unknown", image["chip"])
        self.assertIsNone(image["core"])

    def test_a_stray_magic_byte_is_not_an_image(self):
        """0xE9 occurs constantly inside compressed data. Without the entry
        point and segment-table checks every such byte would start an image."""
        noise = bytes([0xE9]) + bytes(range(256)) * 8
        self.assertIsNone(esp32.parse_image(noise))
        self.assertIsNone(esp32.detect(noise))

    def test_a_truncated_image_is_refused_rather_than_raising(self):
        """Firmware arrives half-uploaded; that is a None, not a traceback."""
        for length in (0, 1, 8, esp32.IMAGE_HEADER_SIZE,
                       esp32.IMAGE_HEADER_SIZE + 4, len(self.app) // 2):
            with self.subTest(length=length):
                self.assertIsNone(esp32.parse_image(self.app[:length]))

    # --- the app descriptor ------------------------------------------------ #

    def test_the_app_descriptor_is_read_field_by_field(self):
        app = esp32.parse_image(self.app)["app"]
        self.assertEqual(app["idf_version"], "v5.1.2")
        self.assertEqual(app["project_name"], "fixture-app")
        self.assertEqual(app["app_version"], "1.2.3")
        self.assertEqual(app["build_date"], "Jan  1 2026")
        self.assertEqual(app["build_time"], "00:00:00")
        self.assertEqual(app["elf_sha256"], bytes(range(32)).hex())

    def test_a_blank_field_is_absent_rather_than_an_empty_version(self):
        """Tasmota leaves version, project_name and date empty. An empty string
        reported as a version would be a component versioned as the empty
        string - worse than no component, because a CVE feed would take it
        seriously."""
        blanked = bytearray(self.app)
        start = esp32.parse_image(self.app)["segments"][0]["offset"]
        for offset, width in ((16, 32), (48, 32), (80, 16), (96, 16)):
            blanked[start + offset:start + offset + width] = bytes(width)
        app = esp32.parse_image(bytes(blanked))["app"]
        self.assertIsNone(app["app_version"])
        self.assertIsNone(app["project_name"])
        self.assertIsNone(app["build_date"])
        self.assertEqual(app["idf_version"], "v5.1.2")

    def test_an_image_without_a_descriptor_invents_nothing(self):
        """A second-stage bootloader has no esp_app_desc_t, and neither has a
        plain binary blob flashed by hand."""
        image = esp32.parse_image(
            make_fixtures.esp_image(make_fixtures.rng("no-desc"),
                                    with_descriptor=False))
        self.assertIsNone(image["app"])
        self.assertEqual(core.espressif_components([{"espressif": image}]), [])

    # --- the flash layout -------------------------------------------------- #

    def test_the_partition_table_is_the_segmentation(self):
        found = esp32.detect(self.flash)
        self.assertEqual(found["kind"], "flash")
        self.assertEqual([p["name"] for p in found["partitions"]],
                         ["nvs", "otadata", "factory", "storage"])
        factory = found["partitions"][2]
        self.assertEqual((factory["type"], factory["subtype"]), ("app", "factory"))
        self.assertEqual(found["partitions"][3]["subtype"], "littlefs")
        self.assertTrue(found["bootloader"])
        self.assertEqual([i["partition"] for i in found["images"]], ["factory"])

    def test_an_ota_subtype_is_numbered_not_guessed(self):
        """ota_0 .. ota_15 are a range, not a lookup; an off-by-one here would
        mislabel which slot an image was found in."""
        self.assertEqual(esp32._subtype_name(0, 0x10), "ota_0")
        self.assertEqual(esp32._subtype_name(0, 0x1F), "ota_15")
        self.assertEqual(esp32._subtype_name(0, 0x00), "factory")

    def test_the_segments_follow_the_partitions(self):
        segments, _warnings = container.walk(self.flash)
        labels = [s["label"] for s in segments]
        self.assertTrue(any("bootloader" in label for label in labels), labels)
        for name in ("nvs", "otadata", "factory", "storage"):
            self.assertTrue(any(name in label for label in labels),
                            f"{name} missing from {labels}")
        factory = next(s for s in segments if "factory" in s["label"])
        self.assertEqual(factory["offset"], 0x10000)

    def test_the_app_partition_describes_the_firmware_not_the_bootloader(self):
        """The bootloader sits lowest in the flash and has no descriptor. Taking
        the first image found would report the bootloader's entry point and lose
        the IDF version entirely."""
        segments, _warnings = container.walk(self.flash)
        image = core.espressif_image(segments)
        self.assertIsNotNone(image["app"])
        self.assertEqual(image["app"]["idf_version"], "v5.1.2")

    # --- what reaches the document ----------------------------------------- #

    def test_the_declared_chip_settles_the_architecture(self):
        arch = core.analyze_architecture(self.app)
        self.assertEqual(arch["architecture"], "xtensa")
        self.assertIn("ESP32", arch["label"])
        self.assertTrue(any("declares chip" in d for d in arch["details"]),
                        arch["details"])

    def test_esp_idf_is_a_component_carrying_its_evidence(self):
        bom = analyze("esp32_app.bin")["bom"]
        idf = next(c for c in bom["components"] if c["name"] == "esp-idf")
        self.assertEqual(idf["version"], "v5.1.2")
        self.assertEqual(idf["type"], "framework")
        self.assertEqual(idf["purl"], "pkg:github/espressif/esp-idf@v5.1.2")
        properties = {p["name"]: p["value"] for p in idf["properties"]}
        self.assertEqual(properties["fw2sbom:confidence"], "0.97")
        self.assertEqual(properties["fw2sbom:evidence_class"],
                         "esp-idf-app-descriptor")
        method = idf["evidence"]["identity"][0]["methods"][0]
        self.assertIn("esp_app_desc_t", method["value"])

    def test_the_application_the_image_names_becomes_a_component(self):
        bom = analyze("esp32_app.bin")["bom"]
        app = next(c for c in bom["components"] if c["name"] == "fixture-app")
        self.assertEqual(app["version"], "1.2.3")
        self.assertEqual(app["type"], "application")

    def test_the_document_records_the_chip_and_the_build(self):
        bom = analyze("esp32_flash.bin")["bom"]
        properties = {p["name"]: p["value"]
                      for p in bom["metadata"]["component"]["properties"]}
        self.assertEqual(properties["fw2sbom:espressif_chip"], "ESP32")
        self.assertEqual(properties["fw2sbom:espressif_core"], "Xtensa LX6")
        self.assertEqual(properties["fw2sbom:espressif_build_date"], "Jan  1 2026")
        self.assertEqual(properties["fw2sbom:architecture"], "Xtensa LX6 (ESP32)")
        self.assertEqual(properties["fw2sbom:espressif_application_elf_sha256"],
                         bytes(range(32)).hex())

    def test_a_vendor_claim_about_esp_idf_is_compared_not_ignored(self):
        """A vendor SBOM naming a different IDF version than the image declares
        is exactly the finding this feature exists to surface. The comparison
        used to look only at signature hits, standards and packages, so an
        Espressif image agreed with every vendor document by default."""
        image = esp32.parse_image(fixture("esp32_app.bin"))
        ours = core.espressif_components([{"espressif": image}])
        flattened = core.identified_components([], [], [], ours)
        self.assertIn("esp-idf", [c["name"] for c in flattened])

        vendor = [{"name": "esp-idf", "version": "v5.1.1",
                   "purl": "pkg:github/espressif/esp-idf@v5.1.1",
                   "supplier": None, "licenses": [], "bom_ref": "v1"}]
        _agree, conflicts, _vendor_only, _ours_only = vendor_sbom.compare(
            flattened, vendor)
        self.assertEqual([c["vendor"]["name"] for c in conflicts], ["esp-idf"])
        self.assertEqual(conflicts[0]["our_version"], "v5.1.2")

    def test_the_same_components_appear_in_the_spdx_rendering(self):
        """One analysis, two renderings: a customer choosing SPDX must not get
        a smaller inventory than one choosing CycloneDX."""
        spdx = analyze("esp32_app.bin")["spdx"]
        names = {package["name"] for package in spdx["packages"]}
        self.assertIn("esp-idf", names)
        self.assertIn("fixture-app", names)

    def test_declared_components_are_not_called_unanalysable(self):
        """An image we read the IDF version out of has been analysed, whatever
        the entropy of its code segments says."""
        result = analyze("esp32_app.bin")
        self.assertFalse(result["opacity"]["opaque"], result["opacity"])


# --------------------------------------------------------------------------- #

class UefiTest(unittest.TestCase):
    """A PC BIOS is the one firmware class where string matching finds nothing.

    A published EDK2 release build contains no library banners at all - not one
    signature in the database matches it. What it does contain is an inventory
    the build system wrote down: every module carries its own name, and a GUID
    that identifies it exactly when the name was stripped.

    Most of that inventory is behind an LZMA section. On a real OVMF image 1.4
    MB expands to 16 MB and 112 of the 123 modules are inside it, so a reader
    that does not decompress reports a handful of modules and calls it a BIOS.
    """

    @classmethod
    def setUpClass(cls):
        cls.volume = fixture("uefi_volume.bin")
        cls.flash = fixture("uefi_flash.bin")

    # --- the volume header ------------------------------------------------- #

    def test_a_volume_is_recognised_by_its_checksum_not_its_signature(self):
        """"_FVH" occurs by chance inside compiled code - four times in a 4 MB
        OVMF image. Every UINT16 of a real header sums to zero; code does not."""
        header = uefi.parse_volume_header(self.volume, 0)
        self.assertIsNotNone(header)
        self.assertEqual(header["filesystem"], "FFS2")
        self.assertEqual(header["revision"], 2)
        self.assertEqual(header["length"], len(self.volume))

        broken = bytearray(self.volume)
        broken[60] ^= 0x01                      # one bit, inside the block map
        self.assertIsNone(uefi.parse_volume_header(bytes(broken), 0))

    def test_a_stray_signature_in_code_is_not_a_volume(self):
        noise = bytes(range(256)) * 4
        planted = noise[:40] + b"_FVH" + noise[44:]
        self.assertIsNone(uefi.parse_volume_header(planted, 0))
        self.assertEqual([], uefi.find_volumes(planted))

    def test_a_truncated_image_is_refused_rather_than_raising(self):
        for length in (0, 1, 40, 44, 55, 71, len(self.volume) // 2):
            with self.subTest(length=length):
                self.assertIsNone(uefi.parse_volume_header(
                    self.volume[:length], 0))

    # --- files ------------------------------------------------------------- #

    def test_a_pad_file_is_not_the_end_of_the_volume(self):
        """A pad file's GUID is all 0xFF, which is exactly what erased flash
        looks like. Reading the GUID alone to find the end of a volume stops at
        the first pad - on a published OVMF image that hid every PEI module in
        the firmware, because the PEI volume's second file is a pad."""
        found = uefi.read_modules(self.volume)
        names = [m["name"] for m in found["modules"] if m["name"]]
        self.assertIn("DxeCore", names)
        self.assertIn("PciBusDxe", names)       # sits after a pad file

    def test_the_variable_store_is_not_read_as_modules(self):
        """It shares the volume header with the module volumes but holds UEFI
        variables. Walking it as FFS invents a module out of whatever the NVRAM
        happened to contain - which a real image promptly did."""
        found = uefi.read_modules(self.flash)
        self.assertEqual([v["filesystem"] for v in found["data_volumes"]],
                         ["NVRAM store"])
        self.assertTrue(all(m["volume"] != "0x200000"
                            for m in found["modules"]), found["modules"])

    def test_a_module_without_a_name_keeps_its_guid(self):
        found = uefi.read_modules(self.volume)
        unnamed = [m for m in found["modules"] if not m["name"]]
        self.assertTrue(unnamed)
        for module in unnamed:
            self.assertRegex(module["guid"],
                             r"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-"
                             r"[0-9A-F]{4}-[0-9A-F]{12}$")

    # --- compression ------------------------------------------------------- #

    def test_the_compressed_volume_is_expanded(self):
        """Where a BIOS keeps almost everything."""
        found = uefi.read_modules(self.volume)
        names = [m["name"] for m in found["modules"] if m["name"]]
        self.assertIn("PeiCore", names)          # only inside the LZMA section
        self.assertIn("PlatformPei", names)
        self.assertGreater(found["expanded_bytes"], 0)
        self.assertTrue(found["expansions"])

    def test_a_compression_we_cannot_expand_is_reported_not_skipped(self):
        """Skipping it shrinks the inventory silently, which is the one thing
        this tool must never do: the modules behind it exist."""
        found = uefi.read_modules(self.volume)
        self.assertTrue(any("Tiano" in note for note in found["unreadable"]),
                        found["unreadable"])

    def test_an_lzma_section_claiming_an_absurd_size_is_refused(self):
        """A decompression bomb is a plausible thing to be handed."""
        walk = uefi._Walk()
        payload = b"\x5d\x00\x00\x00\x01" + (2 ** 60).to_bytes(8, "little")
        out, reason = uefi._lzma(payload + b"\x00" * 64, walk)
        self.assertIsNone(out)
        self.assertIn("expansion limit", reason)

    # --- the flash layout -------------------------------------------------- #

    def test_the_descriptor_names_the_regions(self):
        found = uefi.detect(self.flash)
        self.assertEqual(found["kind"], "flash-descriptor")
        regions = {r["name"]: r for r in found["descriptor"]["regions"]}
        self.assertEqual(set(regions),
                         {"descriptor", "bios", "management-engine"})
        self.assertEqual(regions["bios"]["offset"], 0x200000)

    def test_the_management_engine_is_reported_as_unreadable(self):
        """Signed Intel code nobody outside Intel can read. Averaging it into a
        verdict about the firmware describes neither - and calling it plaintext
        because we copied the bytes out of the file would be worse."""
        result = analyze("uefi_flash.bin")
        me = next(s for s in result["segments"]
                  if "management-engine" in s["label"])
        self.assertFalse(me["expanded"], "a slice of the file is not an expansion")
        self.assertTrue(me["opacity"]["opaque"], me["opacity"])

    def test_an_unreadable_region_does_not_deny_the_modules_beside_it(self):
        """The contradiction this whole class of bug produces: "static
        component identification is not possible" printed above an inventory of
        modules we just identified."""
        result = analyze("uefi_flash.bin")
        self.assertTrue(result["bom"]["components"])
        self.assertFalse(result["opacity"]["opaque"], result["opacity"])

    # --- what reaches the document ----------------------------------------- #

    def test_the_pe_headers_settle_the_architecture(self):
        arch = core.analyze_architecture(self.volume)
        self.assertEqual(arch["architecture"], "x86-64")
        self.assertTrue(any("PE headers" in d for d in arch["details"]),
                        arch["details"])

    def test_a_bios_is_not_mistaken_for_a_cortex_m_image(self):
        """A vector-table heuristic has no business claiming a BIOS."""
        arch = core.analyze_architecture(self.flash)
        self.assertNotEqual(arch["architecture"], "arm-cortex-m")
        self.assertNotEqual(arch["architecture"], "mcs-51")

    def test_every_module_becomes_a_component_carrying_its_guid(self):
        bom = analyze("uefi_volume.bin")["bom"]
        dxe = next(c for c in bom["components"] if c["name"] == "DxeCore")
        properties = {p["name"]: p["value"] for p in dxe["properties"]}
        self.assertEqual(properties["fw2sbom:evidence_class"], "uefi-module")
        self.assertEqual(properties["fw2sbom:uefi_module_type"], "dxe-core")
        self.assertRegex(properties["fw2sbom:uefi_guid"], r"^[0-9A-F-]{36}$")
        self.assertEqual(dxe["version"], "1.0")

    def test_no_purl_is_invented_for_a_uefi_module(self):
        """A UEFI module is not a package in any ecosystem. Emitting
        pkg:generic/DxeCore would hand a CVE matcher an identity that does not
        exist anywhere, which is worse than leaving the field out."""
        bom = analyze("uefi_volume.bin")["bom"]
        modules = [c for c in bom["components"]
                   if any(p["name"] == "fw2sbom:evidence_class"
                          and p["value"] == "uefi-module"
                          for p in c.get("properties", []))]
        self.assertTrue(modules)
        for component in modules:
            self.assertNotIn("purl", component)

    def test_the_module_version_is_labelled_as_the_module_s_own(self):
        """EDK2 leaves it at 1.0 almost always. Left unexplained it looks like
        a library version somebody should match against a CVE feed."""
        bom = analyze("uefi_volume.bin")["bom"]
        dxe = next(c for c in bom["components"] if c["name"] == "DxeCore")
        note = next(p["value"] for p in dxe["properties"]
                    if p["name"] == "fw2sbom:version_note")
        self.assertIn("not any library inside it", note)

    def test_the_document_records_what_was_not_read(self):
        bom = analyze("uefi_volume.bin")["bom"]
        properties = [p["value"] for p in bom["metadata"]["component"]["properties"]
                      if p["name"] == "fw2sbom:uefi_not_expanded"]
        self.assertTrue(any("Tiano" in value for value in properties), properties)

    def test_the_inventory_survives_the_spdx_rendering(self):
        spdx = analyze("uefi_volume.bin")["spdx"]
        names = {package["name"] for package in spdx["packages"]}
        self.assertIn("DxeCore", names)
        self.assertIn("PeiCore", names)

    def test_a_bios_is_analysed_in_reasonable_time(self):
        """A customer waits for this in a browser, and a real BIOS expands to
        sixteen times its own size."""
        start = time.perf_counter()
        uefi.read_modules(self.flash)
        self.assertLess(time.perf_counter() - start, 30)


# --------------------------------------------------------------------------- #

class VendorContainerTest(unittest.TestCase):
    """The wrappers vendors bolt on the front of a firmware download.

    These are worth supporting precisely because they are trivial: the payload
    behind the header is firmware the walk already reads, so the only thing
    between a .trx file and a full SBOM is knowing to skip 32 bytes. What the
    reader must not do is guess - a header claimed at the wrong offset does not
    fail loudly, it shifts every later finding and quietly produces nonsense.
    """

    def _trx(self, version, parts=None):
        """A TRX image: magic, length, crc, flags/version, part offsets."""
        count = 4 if version == 2 else 3
        header_size = 16 + count * 4
        parts = parts or [b"kernel-here" * 8, b"rootfs-here" * 8, b"tail" * 8]
        offsets, at, body = [], header_size, b""
        for part in parts:
            offsets.append(at)
            body += part
            at += len(part)
        offsets += [0] * (count - len(offsets))
        total = header_size + len(body)
        head = (b"HDR0" + struct.pack("<III", total, 0x12345678,
                                      (version << 16))
                + struct.pack(f"<{count}I", *offsets))
        return head + body

    def test_a_trx_header_is_read_and_its_parts_located(self):
        for version in (1, 2):
            with self.subTest(version=version):
                found = vendor_container.parse_trx(self._trx(version))
                self.assertEqual(found["version"], version)
                self.assertEqual(found["header_length"], 16 + (4 if version == 2 else 3) * 4)
                self.assertEqual([p["name"] for p in found["parts"]][:2],
                                 ["kernel", "root filesystem"])
                self.assertEqual(found["parts"][0]["offset"], found["header_length"])

    def test_a_stray_magic_is_not_a_container(self):
        """"HDR0" is four bytes of ASCII and turns up inside compressed data."""
        noise = b"HDR0" + bytes(range(256)) * 4
        self.assertIsNone(vendor_container.parse_trx(noise))
        self.assertIsNone(vendor_container.detect(noise))

    def test_a_trx_claiming_more_than_it_has_is_refused(self):
        image = bytearray(self._trx(2))
        struct.pack_into("<I", image, 4, 0x7FFFFFFF)     # declared length
        self.assertIsNone(vendor_container.parse_trx(bytes(image)))

    def test_a_truncated_container_is_refused_rather_than_raising(self):
        image = self._trx(2)
        for length in (0, 4, 16, 20, 31):
            with self.subTest(length=length):
                self.assertIsNone(vendor_container.detect(image[:length]))

    def test_an_shrs_payload_is_not_claimed_to_be_readable(self):
        """D-Link encrypts these. Naming the container does not decrypt it, and
        the payload still has to reach the opacity judgement."""
        payload = bytes(range(256)) * 16
        image = (b"SHRS" + struct.pack(">II", len(payload), len(payload))
                 + b"\x00" * (vendor_container.SHRS_HEADER_SIZE - 12) + payload)
        found = vendor_container.parse_shrs(image)
        self.assertEqual(found["header_length"], 1756)
        self.assertEqual(found["parts"][0]["length"], len(payload))
        self.assertTrue(any("encrypted" in note for note in found["notes"]))

    def test_the_header_is_claimed_and_the_payload_left_to_the_walk(self):
        """The whole design: claim 32 bytes, let the existing scans do the rest.
        Claiming the payload too would hide the filesystem inside it."""
        rootfs = fixture("cramfs_rootfs.bin")
        image = self._trx(2, parts=[b"\x00" * 64, rootfs])
        segments, _warnings = container.walk(image)
        kinds = [s["kind"] for s in segments]
        self.assertIn("vendor-header", kinds)
        self.assertIn("filesystem", kinds)
        header = next(s for s in segments if s["kind"] == "vendor-header")
        self.assertEqual(header["offset"], 0)
        self.assertEqual(header["length"], 32)

    def test_the_container_reaches_the_document(self):
        rootfs = fixture("cramfs_rootfs.bin")
        image = self._trx(2, parts=[b"\x00" * 64, rootfs])
        result = service.analyze_bytes("router.trx", image)
        properties = {p["name"]: p["value"]
                      for p in json.loads(result["sbom_json"])
                      ["metadata"]["component"]["properties"]}
        self.assertEqual(properties["fw2sbom:vendor_container"], "Broadcom TRX v2")


# --------------------------------------------------------------------------- #

class CramFSTest(unittest.TestCase):
    """CramFS is what many small Linux devices use where a router uses SquashFS.

    The reader presents the same surface as the SquashFS one, which is the
    point: package databases, ELF analysis and per-file signature scanning all
    work on a CramFS rootfs without another line of code.
    """

    @classmethod
    def setUpClass(cls):
        cls.image = fixture("cramfs_rootfs.bin")
        cls.fs = cramfs.CramFS(cls.image, 0)

    def test_the_superblock_is_read(self):
        self.assertEqual(self.fs.byte_order, "little-endian")
        self.assertEqual(self.fs.size, len(self.image))
        self.assertEqual(self.fs.name, "fw2sbom-fixture")

    def test_a_stray_magic_is_not_a_filesystem(self):
        """The four magic bytes alone identify nothing; the signature 16 bytes
        in is what settles it."""
        noise = cramfs.MAGIC_LE + bytes(range(256)) * 4
        self.assertEqual([], cramfs.find_offsets(noise))
        with self.assertRaises(cramfs.CramFSError):
            cramfs.CramFS(noise, 0)

    def test_a_truncated_image_is_refused_rather_than_raising(self):
        for length in (0, 4, 40, 75):
            with self.subTest(length=length):
                with self.assertRaises(cramfs.CramFSError):
                    cramfs.CramFS(self.image[:length], 0)

    def test_the_walk_descends_into_subdirectories(self):
        paths = sorted(self.fs.files())
        self.assertEqual(paths, ["/busybox", "/etc/opkg-status", "/etc/os-release"])
        self.assertEqual([], self.fs.warnings)

    def test_file_contents_come_back_whole(self):
        files = self.fs.files()
        release = self.fs.read_file(files["/etc/os-release"])
        self.assertIn(b'VERSION="22.03.4"', release)
        binary = self.fs.read_file(files["/busybox"])
        self.assertTrue(binary.startswith(b"\x7fELF"))
        self.assertIn(b"BusyBox v1.36.1", binary)

    def test_the_offsets_are_counted_in_units_not_bytes(self):
        """namelen counts 4-byte units and so does offset. Reading either as a
        byte count lands in the middle of the image and looks like corruption
        rather than a bug."""
        root = self.fs.root
        self.assertEqual(root["offset"] % 4, 0)
        for _name, node in self.fs.listdir(root):
            self.assertEqual(node["namelen"] % 4, 0)

    # --- what the rest of the pipeline makes of it ------------------------- #

    def test_the_rootfs_is_analysed_like_any_other(self):
        result = analyze("cramfs_rootfs.bin")
        names = {c["name"] for c in result["bom"]["components"]}
        self.assertIn("busybox", names)          # from the binary's banner
        self.assertIn("mbedtls", names)
        self.assertEqual(result["rootfs"]["os_release"]["description"],
                         "OpenWrt 22.03.4")

    def test_the_architecture_comes_from_the_binaries_inside(self):
        result = analyze("cramfs_rootfs.bin")
        self.assertIn("ARM", result["rootfs"]["binaries"]["architecture"])

    def test_a_text_file_that_looks_like_a_package_database_is_not_one(self):
        """/etc/opkg-status holds "Package: busybox / Version: 1.36.1-r2" and is
        not where opkg keeps its database. Treating any such text as a package
        list is how version-less components get manufactured."""
        result = analyze("cramfs_rootfs.bin")
        self.assertEqual([], result["packages"])
        busybox = next(c for c in result["bom"]["components"]
                       if c["name"] == "busybox")
        evidence = busybox["evidence"]["identity"][0]["methods"][0]["value"]
        self.assertIn("busybox", evidence)
        self.assertNotIn("opkg-status", evidence)


# --------------------------------------------------------------------------- #

class ProgressTest(unittest.TestCase):
    """The bar a customer watches while their firmware is analysed.

    It moves only when work actually finishes. A bar that creeps forward on a
    timer and stalls at 90% is a small lie told to make a wait feel shorter,
    and this tool's whole job is to say plainly what it did and did not do.
    """

    def trace(self, name):
        events = []
        data = fixture(name)
        core.run_analysis(data, image_input.detect_and_load(data), name,
                          progress=core.Progress(events.append))
        return events

    def test_the_bar_never_moves_backwards(self):
        for name in ("router_uimage.bin", "uefi_volume.bin", "cramfs_rootfs.bin",
                     "esp32_flash.bin", "cortexm_rtos.bin"):
            with self.subTest(fixture=name):
                percents = [e["percent"] for e in self.trace(name)]
                self.assertTrue(percents)
                self.assertEqual(percents, sorted(percents))
                self.assertLessEqual(percents[-1], 100)

    def test_the_stages_arrive_in_order(self):
        order = [key for key, _share in core.PROGRESS_STAGES]
        seen = []
        for event in self.trace("router_uimage.bin"):
            if event["stage"] not in seen:
                seen.append(event["stage"])
        self.assertEqual(seen, order[:len(seen)])
        self.assertEqual(seen[-1], "sbom")        # the service does the rest

    def test_each_step_is_numbered_against_the_whole(self):
        for event in self.trace("uefi_volume.bin"):
            self.assertEqual(event["steps"], len(core.PROGRESS_STAGES))
            self.assertGreaterEqual(event["step"], 1)

    def test_real_counts_are_reported_while_files_are_read(self):
        """The router's rootfs is where the long wait is, and a customer
        watching "312 / 467" knows it is working; one watching a still bar
        does not."""
        kinds = {(e["detail"] or {}).get("kind")
                 for e in self.trace("cramfs_rootfs.bin")}
        self.assertIn("binaries", kinds)
        self.assertIn("segment", kinds)

    def test_a_count_never_exceeds_its_total(self):
        for event in self.trace("cramfs_rootfs.bin"):
            detail = event["detail"] or {}
            if "count" in detail:
                self.assertLessEqual(detail["index"], detail["count"], detail)

    def test_nothing_is_reported_without_a_sink(self):
        """The command line has its own verbose log and must pay nothing."""
        progress = core.Progress()
        progress.enter("reading")
        progress.within(0.5)
        progress.finish()
        self.assertEqual(progress.percent, 100.0)

    def test_the_percentage_is_clamped(self):
        events = []
        progress = core.Progress(events.append)
        progress.enter("segments")
        progress.within(7.0)
        progress.within(-3.0)
        self.assertEqual([e["percent"] for e in events][-1],
                         events[-2]["percent"])
        self.assertLessEqual(events[-1]["percent"], 100)

    def test_an_unknown_stage_is_a_mistake_not_a_silent_jump(self):
        with self.assertRaises(ValueError):
            core.Progress().enter("decrypting")

    def test_progress_does_not_change_the_answer(self):
        """Reporting is observation. The document must be identical with it
        and without it - which is what lets the command line run without."""
        data = fixture("cramfs_rootfs.bin")
        source = image_input.detect_and_load(data)
        quiet = core.run_analysis(data, source, "x")["bom"]["components"]
        watched = core.run_analysis(data, source, "x",
                                    progress=core.Progress(lambda _s: None))
        self.assertEqual(
            [(c["name"], c.get("version")) for c in quiet],
            [(c["name"], c.get("version"))
             for c in watched["bom"]["components"]])


class AnalysisJobTest(unittest.TestCase):
    """The page starts an analysis, then watches it, over HTTP."""

    @classmethod
    def setUpClass(cls):
        cls.server = service.Server(("127.0.0.1", 0), service.Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def post(self, path, name, blob):
        boundary = "fw2sbomjobtest"
        body = (f"--{boundary}\r\nContent-Disposition: form-data; "
                f'name="file"; filename="{name}"\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n").encode()
        body += blob + f"\r\n--{boundary}--\r\n".encode()
        request = urllib.request.Request(
            self.url(path), data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, json.loads(response.read())

    def poll(self, progress_url, limit=120):
        states = []
        deadline = time.time() + limit
        while time.time() < deadline:
            with urllib.request.urlopen(self.url(progress_url),
                                        timeout=30) as response:
                body = json.loads(response.read())
            states.append(body["state"])
            if body["done"]:
                return body, states
            time.sleep(0.05)
        self.fail("the analysis never reported done")

    def test_starting_answers_at_once_with_a_job(self):
        status, started = self.post("/analyze/start", "fw.bin",
                                    fixture("cramfs_rootfs.bin"))
        self.assertEqual(status, 202)
        self.assertRegex(started["job"], r"^[0-9a-f]{32}$")
        self.assertEqual(started["progress_url"], "/progress/" + started["job"])
        self.poll(started["progress_url"])

    def test_a_job_ends_with_the_same_answer_as_waiting_for_it(self):
        blob = fixture("cramfs_rootfs.bin")
        _status, started = self.post("/analyze/start", "fw.bin", blob)
        final, states = self.poll(started["progress_url"])
        self.assertIsNone(final["error"])
        self.assertEqual(final["state"]["percent"], 100.0)
        self.assertEqual(final["state"]["stage"], "done")

        _status, direct = self.post("/analyze", "fw.bin", blob)
        self.assertEqual(
            sorted((c["name"], c["version"]) for c in final["result"]["components"]),
            sorted((c["name"], c["version"]) for c in direct["components"]))
        percents = [state["percent"] for state in states]
        self.assertEqual(percents, sorted(percents))

    def test_the_finished_job_links_to_downloads_that_work(self):
        _status, started = self.post("/analyze/start", "fw.bin",
                                     fixture("cramfs_rootfs.bin"))
        final, _states = self.poll(started["progress_url"])
        with urllib.request.urlopen(self.url(final["result"]["download_url"]),
                                    timeout=30) as response:
            document = json.loads(response.read())
        self.assertEqual(document["bomFormat"], "CycloneDX")

    def test_a_failure_is_reported_rather_than_left_running(self):
        """A job that dies without saying so leaves the page polling a bar that
        never moves again - the worst thing a progress bar can do."""
        with mock.patch.object(service, "analyze_bytes",
                               side_effect=RuntimeError("the parser fell over")):
            _status, started = self.post("/analyze/start", "fw.bin", b"\x00" * 64)
            final, _states = self.poll(started["progress_url"])
        self.assertTrue(final["done"])
        self.assertIn("the parser fell over", final["error"])
        self.assertIsNone(final["result"])

    def test_an_unknown_job_is_a_404_not_a_hang(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(self.url("/progress/" + "0" * 32), timeout=30)
        self.assertEqual(caught.exception.code, 404)

    def test_the_job_store_is_bounded(self):
        """A service left running must not keep one entry per file anyone ever
        dropped on it - the mistake the result store once made."""
        for _ in range(service.JOBS_MAX + 10):
            service._job_new()
        self.assertLessEqual(len(service._JOBS), service.JOBS_MAX)


# --------------------------------------------------------------------------- #

class JFFS2Test(unittest.TestCase):
    """JFFS2 is a log, not an image: files are rebuilt from every node that
    ever wrote part of them, and deleting one writes a node too.

    The published samples cover the compressors and byte orders. These tests
    cover what makes it a log - the parts a reader written from the node
    layout alone gets wrong.
    """

    @classmethod
    def setUpClass(cls):
        cls.image = fixture("jffs2_rootfs.bin")
        cls.fs = jffs2.JFFS2(cls.image, 0)
        cls.files = cls.fs.files()

    def test_a_deleted_file_is_not_listed(self):
        """An entry pointing at inode 0 is an unlink. Ignoring it resurrects
        every file the device deleted - and lists software that is not there."""
        self.assertNotIn("/bin/dropbear", self.files)
        self.assertEqual(sorted(self.files),
                         ["/bin/busybox", "/etc/motd", "/etc/os-release"])

    def test_a_deleted_binary_does_not_reach_the_sbom(self):
        names = {c["name"] for c in analyze("jffs2_rootfs.bin")["bom"]["components"]}
        self.assertIn("busybox", names)
        self.assertNotIn("dropbear", names)

    def test_the_newest_version_of_a_file_wins(self):
        release = self.fs.read_file(self.files["/etc/os-release"])
        self.assertIn(b'VERSION="22.03.4"', release)
        self.assertNotIn(b"VendorOS", release)

    def test_every_compressor_in_the_fixture_reads_back(self):
        motd = self.fs.read_file(self.files["/etc/motd"])          # LZO
        self.assertEqual(motd, b"The quick brown fox jumps over the lazy dog. " * 60)
        busybox = self.fs.read_file(self.files["/bin/busybox"])    # zlib
        self.assertIn(b"BusyBox v1.36.1", busybox)

    def test_a_stray_magic_without_a_valid_crc_is_not_a_node(self):
        """0x1985 is two bytes and turns up inside compressed data. With no
        superblock, the header CRC is the only thing that tells them apart."""
        noise = b"\x19\x85\xe0\x02" + struct.pack(">I", 64) + b"\x00" * 4 \
            + bytes(range(256)) * 4
        self.assertEqual([], jffs2.find_offsets(noise))
        with self.assertRaises(jffs2.JFFS2Error):
            jffs2.JFFS2(noise, 0)

    def test_a_truncated_image_is_refused_or_read_partially_never_raising_otherwise(self):
        for length in (0, 4, 11, 12, 40, 200, 700):
            with self.subTest(length=length):
                try:
                    partial = jffs2.JFFS2(self.image[:length], 0)
                except jffs2.JFFS2Error:
                    continue
                for node in partial.files().values():
                    try:
                        partial.read_file(node)
                    except jffs2.JFFS2Error:
                        pass

    def test_the_architecture_comes_from_the_binaries(self):
        result = analyze("jffs2_rootfs.bin")
        self.assertIn("MIPS", result["rootfs"]["binaries"]["architecture"])
        self.assertIn("big-endian", result["rootfs"]["binaries"]["architecture"])

    def test_an_overlay_after_the_rootfs_is_still_read(self):
        """A device dump: a read-only rootfs, then a JFFS2 overlay. Only the
        first is read as the rootfs, and before this the second would have gone
        unscanned - taking with it every package installed after the factory
        image."""
        names = {c["name"] for c in analyze("cramfs_jffs2_flash.bin")["bom"]["components"]}
        self.assertIn("busybox", names)          # the rootfs
        self.assertIn("libcurl", names)          # the overlay

    def test_rtime_decompresses_overlapping_repeats(self):
        """A run of one character compresses to four bytes, because the copy
        reads what it has just written."""
        self.assertEqual(jffs2.rtime_decompress(b"A\x00A\x18", 26), b"A" * 26)
        with self.assertRaises(jffs2.JFFS2Error):
            jffs2.rtime_decompress(b"A", 26)


class UBIFSTest(unittest.TestCase):
    """UBIFS keeps an index, and the index - not a scan of every node on the
    flash - is what says which nodes are the filesystem. The published samples
    hold text files and no compressed data but LZO; this fixture holds software,
    every compressor, and a deleted binary still sitting on the flash."""

    @classmethod
    def setUpClass(cls):
        cls.image = fixture("ubifs_rootfs.bin")
        cls.fs = ubifs.UBIFS(cls.image)
        cls.files = cls.fs.files()

    def test_a_deleted_file_is_not_listed(self):
        """Its nodes are on the flash with valid CRCs; the index no longer
        points at them. A reader that scanned nodes would bring it back."""
        self.assertIn(b"SSH-2.0-dropbear_2022.82", self.image)
        self.assertEqual(sorted(self.files),
                         ["/bin/busybox", "/etc/motd", "/etc/notes",
                          "/etc/os-release", "/usr/lib/opkg/status"])

    def test_a_deleted_binary_does_not_reach_the_sbom(self):
        names = {c["name"] for c in analyze("ubifs_rootfs.bin")["bom"]["components"]}
        self.assertIn("busybox", names)
        self.assertNotIn("dropbear", names)

    def test_every_compressor_reads_back(self):
        busybox = self.fs.read_file(self.files["/bin/busybox"])      # zlib, 2 blocks
        self.assertEqual(len(busybox), 5208)
        self.assertIn(b"BusyBox v1.36.1", busybox)
        self.assertEqual(busybox[-256:], bytes(range(256)))
        motd = self.fs.read_file(self.files["/etc/motd"])            # LZO
        self.assertEqual(motd, make_fixtures.LZO_TEXT)
        release = self.fs.read_file(self.files["/etc/os-release"])   # none
        self.assertIn(b'VERSION="23.05.2"', release)

    def test_zstd_reads_where_the_python_has_it(self):
        with open(os.path.join(HERE, "zstd_vectors.json"), encoding="utf-8") as f:
            vector = json.load(f)["vectors"][0]
        node = self.files["/etc/notes"]
        if ubifs._zstd is None:
            with self.assertRaises(ubifs.UBIFSError):
                self.fs.read_file(node)
            return
        notes = self.fs.read_file(node)
        self.assertEqual(hashlib.sha256(notes).hexdigest(), vector["sha256"])

    def test_a_file_that_cannot_be_decompressed_becomes_an_opaque_component(self):
        """The packaged Python is 3.12, which has no zstd. The file must not
        just drop out of the scan: it is a file nobody looked inside."""
        data = fixture("ubifs_rootfs.bin")
        with mock.patch.object(ubifs, "_zstd", None):
            result = core.run_analysis(data, image_input.detect_and_load(data),
                                       "ubifs_rootfs.bin")
        opaque = [c for c in result["bom"]["components"]
                  if {"name": "fw2sbom:opaque", "value": "true"}
                  in c.get("properties", [])]
        self.assertEqual(len(opaque), 1, [c["name"] for c in opaque])
        evidence = json.dumps(opaque[0]["evidence"])
        self.assertIn("/etc/notes", evidence)
        self.assertIn("zstd", evidence)
        self.assertNotIn("could not be expanded", evidence)
        names = {c["name"] for c in result["bom"]["components"]}
        self.assertIn("busybox", names)            # the rest is still read

    def test_the_newest_master_node_wins(self):
        """Each master LEB holds a stale copy pointing at the superblock, then
        the current one. Taking the first would find no index at all."""
        self.assertIn("/bin/busybox", self.files)

    def test_the_pipeline_reads_it_as_a_rootfs(self):
        result = analyze("ubifs_rootfs.bin")
        self.assertEqual(result["rootfs"]["os_release"]["version"], "23.05.2")
        self.assertEqual([p["name"] for p in result["packages"]], ["dnsmasq"])
        self.assertIn("ARM", result["rootfs"]["binaries"]["architecture"])

    def test_a_damaged_superblock_is_refused(self):
        damaged = bytearray(self.image)
        damaged[40] ^= 0xFF
        with self.assertRaises(ubifs.UBIFSError):
            ubifs.UBIFS(bytes(damaged))
        self.assertEqual([], ubifs.find_offsets(bytes(damaged)))

    def test_a_truncated_image_is_refused_or_read_partially_never_raising_otherwise(self):
        leb = make_fixtures.UBIFS_LEB
        for length in (0, 24, 100, 4096, leb, 2 * leb, 3 * leb, 3 * leb + 900):
            with self.subTest(length=length):
                try:
                    partial = ubifs.UBIFS(self.image[:length])
                except ubifs.UBIFSError:
                    continue
                for node in partial.files().values():
                    try:
                        partial.read_file(node)
                    except ubifs.UBIFSError:
                        pass


class UBITest(unittest.TestCase):
    """UBI reassembles volumes from erase blocks scattered by wear levelling.
    The fixture's volume 0 is a UBIFS data partition and volume 1 a CramFS
    rootfs; its blocks are shuffled, and one logical block is present twice."""

    @classmethod
    def setUpClass(cls):
        cls.data = fixture("ubi_flash.bin")
        cls.image = ubi.read_image(cls.data)

    def volume(self, name):
        return next(v for v in self.image["volumes"] if v["name"] == name)

    def test_volumes_are_named_from_the_table_and_empty_slots_ignored(self):
        self.assertEqual([(v["name"], v["type"]) for v in self.image["volumes"]],
                         [("data", "dynamic"), ("rootfs", "dynamic")])
        self.assertEqual(self.image["peb_size"], make_fixtures.UBI_PEB)
        self.assertEqual([], self.image["warnings"])

    def test_the_newer_copy_of_a_logical_block_wins(self):
        self.assertIn(b"stale copy", self.data)
        self.assertNotIn(b"stale copy", self.volume("rootfs")["data"])
        names = {c["name"] for c in analyze("ubi_flash.bin")["bom"]["components"]}
        self.assertNotIn("dropbear", names)

    def test_the_volume_bytes_come_out_in_logical_order(self):
        self.assertEqual(self.volume("rootfs")["data"][:4],
                         struct.pack("<I", make_fixtures.CRAMFS_MAGIC_LE))
        self.assertIsNotNone(ubifs.UBIFS(self.volume("data")["data"]))

    def test_the_rootfs_is_chosen_by_its_contents_not_its_position(self):
        """'data' comes first. Taking the first filesystem as the root would
        read a partition holding one library as the whole device."""
        result = analyze("ubi_flash.bin")
        self.assertEqual(result["rootfs"]["segment"]["ubi_volume"], "rootfs")
        self.assertEqual(result["rootfs"]["os_release"]["version"], "22.03.4")

    def test_the_other_volume_is_still_scanned(self):
        names = {c["name"] for c in analyze("ubi_flash.bin")["bom"]["components"]}
        self.assertIn("busybox", names)          # the rootfs volume
        self.assertIn("libcurl", names)          # the data volume

    def test_a_filesystem_inside_ubi_is_read_through_ubi(self):
        """The raw image has erase-block headers every 16 KiB; read in place,
        a filesystem's blocks past the first would be headers."""
        labels = [s["label"] for s in analyze("ubi_flash.bin")["segments"]
                  if s["kind"] == "filesystem"]
        self.assertEqual(len(labels), 2, labels)
        self.assertTrue(all(l.startswith("UBI volume '") for l in labels), labels)

    def test_a_missing_logical_block_is_filled_not_closed_up(self):
        """Closing the gap would shift every later byte of the volume."""
        pebs = [self.data[i:i + make_fixtures.UBI_PEB]
                for i in range(0, len(self.data), make_fixtures.UBI_PEB)]
        kept = []
        for peb in pebs:
            vid = ubi.parse_vid_header(peb, make_fixtures.UBI_VID_OFFSET)
            if vid and (vid["vol_id"], vid["lnum"]) == (0, 1):
                kept.append(b"\xff" * len(peb))
                continue
            kept.append(peb)
        image = ubi.read_image(b"".join(kept))
        data = next(v for v in image["volumes"] if v["name"] == "data")
        self.assertEqual(data["missing_lebs"], [1])
        self.assertEqual(len(data["data"]), len(self.volume("data")["data"]))
        self.assertTrue(any("missing" in w for w in image["warnings"]))

    def test_a_truncated_image_says_so_and_keeps_what_it_has(self):
        cut = self.data[:len(self.data) - make_fixtures.UBI_PEB - 5000]
        image = ubi.read_image(cut)
        self.assertTrue(any("ends" in w for w in image["warnings"]),
                        image["warnings"])
        self.assertTrue(image["volumes"])

    def test_a_stray_magic_without_a_valid_crc_is_not_an_image(self):
        noise = b"UBI#" + bytes(range(256)) * 8
        self.assertEqual([], ubi.find_offsets(noise))
        with self.assertRaises(ubi.UBIError):
            ubi.read_image(noise)


class FITTest(unittest.TestCase):
    """A FIT documents its own images; the reader's job is to believe the
    documentation where it can be checked, and check it."""

    def test_embedded_images_are_read_as_declared(self):
        image = fit.read_fit(fixture("fit_initramfs.bin"))
        kinds = {i["name"]: (i["type"], i["compression"], i["placement"])
                 for i in image["images"]}
        self.assertEqual(kinds, {"kernel-1": ("kernel", "lzma", "embedded"),
                                 "initrd-1": ("ramdisk", None, "embedded"),
                                 "fdt-1": ("flat_dt", "none", "embedded")})
        for entry in image["images"]:
            self.assertTrue(entry["checks"])
            self.assertTrue(all(c["ok"] for c in entry["checks"]), entry["name"])
        self.assertEqual(image["default_configuration"], "config-1")

    def test_both_external_placements_are_read(self):
        """data-position counts from the start of the FIT, data-offset from
        the end of the tree. Getting either wrong shifts the image and its
        hash stops matching - which is exactly what the check catches."""
        image = fit.read_fit(fixture("fit_sysupgrade.bin"))
        for entry in image["images"]:
            self.assertEqual(entry["placement"], "external")
            self.assertTrue(all(c["ok"] for c in entry["checks"]), entry["name"])
        rootfs = next(i for i in image["images"] if i["name"] == "rootfs-1")
        self.assertEqual(rootfs["offset"], 0x5000)

    def test_a_kernel_is_expanded_by_its_declared_compression(self):
        """The fixture's LZMA kernel starts 0x6d, not the 0x5d a magic scan
        looks for: only the FIT's own word says what it is."""
        blob = fixture("fit_initramfs.bin")
        kernel = next(i for i in fit.read_fit(blob)["images"] if i["type"] == "kernel")
        self.assertEqual(blob[kernel["offset"]], 0x6D)
        names = {c["name"]: c.get("version")
                 for c in analyze("fit_initramfs.bin")["bom"]["components"]}
        self.assertEqual(names.get("linux-kernel"), "5.15.167")

    def test_a_damaged_image_is_reported_by_its_hash(self):
        blob = bytearray(fixture("fit_sysupgrade.bin"))
        blob[0x1000 + 100] ^= 0xFF                     # inside the kernel
        image = fit.read_fit(bytes(blob))
        kernel = next(i for i in image["images"] if i["name"] == "kernel-1")
        self.assertTrue(any(c["ok"] is False for c in kernel["checks"]))
        self.assertTrue(any("does not match" in w for w in image["warnings"]))

    def test_the_architecture_is_declared_by_the_fit(self):
        result = analyze("fit_sysupgrade.bin")
        self.assertEqual(result["arch"]["architecture"], "arm64")
        self.assertTrue(any(d.startswith("fit:") for d in result["arch"]["details"]))

    def test_the_sbom_records_what_the_fit_declares(self):
        props = {p["name"]: p["value"] for p in
                 analyze("fit_sysupgrade.bin")["bom"]["metadata"]["component"]["properties"]}
        self.assertIn("crc32 verified", props["fw2sbom:fit_image_kernel-1"])
        self.assertEqual(props["fw2sbom:device_tree_model"],
                         "fw2sbom Test Board (sysupgrade)")

    def test_a_filesystem_image_is_left_to_the_filesystem_scan(self):
        result = analyze("fit_sysupgrade.bin")
        kinds = [(s["kind"], s["label"]) for s in result["segments"]]
        self.assertIn(("filesystem", "CramFS (little-endian)"), kinds)
        self.assertEqual(result["rootfs"]["os_release"]["version"], "22.03.4")

    def test_a_plain_device_tree_is_not_a_fit(self):
        dtb = make_fixtures.fixture_dtb("board")
        with self.assertRaisesRegex(fit.FITError, "not a FIT"):
            fit.read_fit(dtb)
        self.assertEqual([], fit.find_offsets(dtb))

    def test_a_truncated_or_damaged_tree_never_raises_anything_else(self):
        blob = fixture("fit_initramfs.bin")
        for length in (0, 8, 40, 100, 300, 1000, 5000, 9000):
            with self.subTest(length=length):
                try:
                    fit.read_fit(blob[:length])
                except fit.FITError:
                    pass
        rng = random.Random(7)
        for trial in range(200):
            damaged = bytearray(blob[:0x2915])
            for _ in range(4):
                damaged[rng.randrange(0x40, 0xec)] = rng.randrange(256)
            try:
                fit.read_fit(bytes(damaged))
            except fit.FITError:
                pass


class CPIOTest(unittest.TestCase):
    """The initramfs details the kernel honours and a naive reader misses."""

    @classmethod
    def setUpClass(cls):
        cls.archive = cpio.CPIO(make_fixtures.initramfs_archives())
        cls.files = cls.archive.files()

    def test_every_concatenated_archive_is_read(self):
        """Microcode first, the userland after it. Stopping at the first
        trailer finds one firmware blob and no root filesystem."""
        self.assertEqual(self.archive.archives, 2)
        self.assertIn("/kernel/x86/microcode/GenuineIntel.bin", self.files)
        self.assertIn("/usr/lib/opkg/status", self.files)

    def test_a_later_entry_replaces_an_earlier_one(self):
        release = self.archive.read_file(self.files["/etc/os-release"])
        self.assertIn(b"OpenWrt", release)
        self.assertNotIn(b"Replaced", release)

    def test_hard_links_share_the_data_on_the_last_entry(self):
        sh = self.archive.read_file(self.files["/bin/sh"])
        busybox = self.archive.read_file(self.files["/bin/busybox"])
        self.assertTrue(sh)
        self.assertEqual(sh, busybox)

    def test_names_are_normalised_without_eating_dot_files(self):
        self.assertIn("/.profile", self.files)
        self.assertNotIn("/profile", self.files)
        self.assertEqual(self.archive.entries["/sbin/init"]["target"], "/bin/busybox")
        self.assertEqual(self.archive.entries["/dev/console"]["type"], "other")

    def test_a_truncated_archive_keeps_what_it_read(self):
        data = make_fixtures.initramfs_archives()
        for length in (0, 50, 110, 200, 600, len(data) // 2, len(data) - 10):
            with self.subTest(length=length):
                try:
                    partial = cpio.CPIO(data[:length])
                except cpio.CPIOError:
                    continue
                for node in partial.files().values():
                    partial.read_file(node)

    def test_six_printable_characters_are_not_an_archive(self):
        self.assertIsNone(cpio.find_offset(b"serial 070701 and some text" * 20))

    def test_a_kernel_built_in_initramfs_is_found_and_read(self):
        """No separate rootfs anywhere: the userland is a gzip cpio inside the
        LZMA kernel. It is how a lot of camera firmware ships."""
        result = analyze("kernel_initramfs.bin")
        self.assertIn("inside", next(s["label"] for s in result["segments"]
                                     if s["kind"] == "filesystem"))
        names = {c["name"]: c.get("version") for c in result["bom"]["components"]}
        self.assertEqual(names.get("busybox"), "1.35.0")
        self.assertEqual(names.get("dropbear"), "2020.81")
        self.assertIn("AArch64", result["rootfs"]["binaries"]["architecture"])

    def test_the_kernels_own_empty_initramfs_is_not_a_rootfs(self):
        """/dev, /dev/console and /root, and no files: every kernel carries
        one, and listing it as a filesystem would be noise."""
        empty = make_fixtures.cpio_newc([("dev", 0o040755, b"", 1, 2),
                                         ("dev/console", 0o020600, b"", 2, 1),
                                         ("root", 0o040700, b"", 3, 2)])
        kernel = b"Linux version 6.1.0\x00" * 50 + empty + bytes(1024)
        self.assertIsNone(container._find_initramfs(kernel))

    def test_an_initramfs_ramdisk_is_the_rootfs(self):
        result = analyze("fit_initramfs.bin")
        self.assertEqual(result["rootfs"]["os_release"]["version"], "23.05.5")
        self.assertEqual(sorted(p["name"] for p in result["packages"]),
                         ["dnsmasq", "uhttpd"])


class OpenWrtMetadataTest(unittest.TestCase):

    def test_the_metadata_blocks_are_read_from_the_end(self):
        found = vendor_container.read_openwrt_metadata(fixture("fit_sysupgrade.bin"))
        self.assertEqual(found["metadata"]["version"]["version"], "23.05.5")
        self.assertTrue(found["signature_block"])
        self.assertEqual(found["start"], 0x6000)

    def test_the_sbom_records_the_declared_version(self):
        props = {p["name"]: p["value"] for p in
                 analyze("fit_sysupgrade.bin")["bom"]["metadata"]["component"]["properties"]}
        self.assertEqual(props["fw2sbom:openwrt_image_version"], "23.05.5")
        self.assertEqual(props["fw2sbom:openwrt_image_board"], "fw2sbom_test-board")

    def test_an_image_without_it_has_none(self):
        self.assertIsNone(vendor_container.read_openwrt_metadata(
            fixture("router_uimage.bin")))
        broken = fixture("fit_sysupgrade.bin")[:-1]
        self.assertIsNone(vendor_container.read_openwrt_metadata(broken))


class RealFITTest(unittest.TestCase):
    """OpenWrt 23.05.5 release images for one board, in both FIT shapes.

    Their hashes match the sha256sums OpenWrt publishes, so these are the
    images anyone can download - not something rebuilt here.
    """

    DIRECTORY = os.path.join(ROOT, "corpus", "fit")
    SYSUPGRADE = ("openwrt-23.05.5-mediatek-filogic-xiaomi_mi-router-ax3000t-"
                  "ubootmod-squashfs-sysupgrade.itb")
    RECOVERY = ("openwrt-23.05.5-mediatek-filogic-xiaomi_mi-router-ax3000t-"
                "ubootmod-initramfs-recovery.itb")

    def load(self, name):
        path = os.path.join(self.DIRECTORY, name)
        if not os.path.exists(path):
            self.skipTest(f"{name} missing; run python scripts/fetch-corpus.py")
        with open(path, "rb") as f:
            return f.read()

    def test_every_hash_in_both_images_verifies(self):
        for name in (self.SYSUPGRADE, self.RECOVERY):
            image = fit.read_fit(self.load(name))
            self.assertEqual([], image["warnings"], name)
            for entry in image["images"]:
                self.assertEqual([c["ok"] for c in entry["checks"]], [True, True],
                                 (name, entry["name"]))

    def test_the_recovery_image_is_read_through_its_initramfs(self):
        """Before FIT and cpio support this image gave nine components, most
        of them version-less string matches: the LZMA kernel went unexpanded
        and the initramfs was a blob. It holds a full opkg database."""
        data = self.load(self.RECOVERY)
        result = core.run_analysis(data, image_input.detect_and_load(data),
                                   self.RECOVERY)
        self.assertEqual(result["rootfs"]["os_release"]["version"], "23.05.5")
        self.assertEqual(len(result["packages"]), 147)
        names = {c["name"]: c.get("version") for c in result["bom"]["components"]}
        self.assertEqual(names.get("linux-kernel"), "5.15.167")
        self.assertEqual(result["arm_info"]["architecture"], "arm64")

    def test_every_byte_of_the_sysupgrade_image_is_accounted_for(self):
        data = self.load(self.SYSUPGRADE)
        segments, _rootfs, _w = core.analyze_segments(data, 6)
        self.assertFalse([s["label"] for s in segments if s["kind"] == "unclaimed"
                          and not s.get("blank")])
        metadata = next(s for s in segments if s["kind"] == "image-metadata")
        self.assertEqual(metadata["openwrt_metadata"]["version"]["revision"],
                         "r24106-10cc5fcd00")


class ExtTest(unittest.TestCase):
    """ext2/3/4: the parts of the format the release sample does not reach."""

    @classmethod
    def setUpClass(cls):
        cls.ext2 = ext.Ext(fixture("ext2_rootfs.bin"))
        cls.ext2_files = cls.ext2.files()
        disk = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(
            fixture("ext4_disk.img.gz"))
        table = container.parse_partition_table(disk)
        cls.ext4 = ext.Ext(disk, table["partitions"][1]["offset"])
        cls.ext4_files = cls.ext4.files()

    def test_indirect_and_double_indirect_blocks_are_followed(self):
        """300 KiB in 1 KiB blocks: 12 direct, 256 through the single
        indirect block, the rest through the double. The banner is in the
        last block, which only the double indirect reaches."""
        busybox = self.ext2.read_file(self.ext2_files["/bin/busybox"])
        self.assertEqual(len(busybox), self.ext2_files["/bin/busybox"]["size"])
        self.assertGreater(len(busybox), (12 + 256) * 1024)
        self.assertIn(b"banner at the very end: BusyBox v1.36.1", busybox[-64:])

    def test_a_hole_reads_as_zeros(self):
        sparse = self.ext2.read_file(self.ext2_files["/var/sparse.db"])
        self.assertEqual(sparse[1024:2048], bytes(1024))
        self.assertTrue(sparse[2048:].startswith(b"head of a sparse file"))

    def test_fast_and_slow_symlinks(self):
        links = {p: n.get("target") for p, n in self.ext2.walk() if n["type"] == "symlink"}
        self.assertEqual(links["/sbin/init"], "/bin/busybox")
        self.assertTrue(links["/etc/long-link"].startswith("/usr/share/a/deliberately"))
        self.assertGreater(len(links["/etc/long-link"]), 60)

    def test_a_removed_entry_is_not_listed(self):
        self.assertNotIn("/bin/dropbear", self.ext2_files)

    def test_an_extent_tree_below_the_inode_is_followed(self):
        library = self.ext4.read_file(self.ext4_files["/usr/lib/libcurl.so.4"])
        self.assertIn(b"libcurl/8.4.0", library)
        self.assertEqual(len(library), self.ext4_files["/usr/lib/libcurl.so.4"]["size"])

    def test_an_uninitialised_extent_reads_as_zeros(self):
        data = self.ext4.read_file(self.ext4_files["/opt/preallocated.bin"])
        self.assertTrue(data.startswith(b"written part"))
        self.assertEqual(data[1024:], bytes(1024))

    def test_inline_data_is_read_from_the_inode_and_its_xattr(self):
        release = self.ext4.read_file(self.ext4_files["/etc/os-release"])
        self.assertGreater(len(release), 60)             # past i_block's 60 bytes
        self.assertTrue(release.endswith(b'PRETTY_NAME="OpenWrt 23.05.5"\n'))

    def test_an_indexed_directory_is_listed_completely(self):
        listed = [p for p in self.ext4_files if p.startswith("/usr/share/")]
        self.assertEqual(len(listed), 40)

    def test_an_encrypted_file_is_reported_not_read(self):
        with self.assertRaisesRegex(ext.ExtError, "encrypted"):
            self.ext4.read_file(self.ext4_files["/etc/secret.conf"])
        opaque = [c for c in analyze("ext4_disk.img.gz")["bom"]["components"]
                  if {"name": "fw2sbom:opaque", "value": "true"} in c.get("properties", [])]
        self.assertEqual(len(opaque), 1)
        self.assertIn("/etc/secret.conf", json.dumps(opaque[0]["evidence"]))

    def test_a_journal_needing_recovery_is_reported(self):
        self.assertTrue(any("recovery" in w for w in self.ext4.warnings))

    def test_a_gzipped_disk_image_is_walked_to_its_rootfs(self):
        """OpenWrt ships its x86 images gzipped. Scanned as one expanded blob
        it would give noise; walked, the partition table and both
        filesystems come out, and the rootfs is the one with a root in it."""
        result = analyze("ext4_disk.img.gz")
        kinds = [s["kind"] for s in result["segments"]]
        self.assertIn("partition-table", kinds)
        self.assertEqual(kinds.count("filesystem"), 2)
        self.assertEqual(result["rootfs"]["os_release"]["version"], "23.05.5")
        names = {c["name"]: c.get("version") for c in result["bom"]["components"]}
        self.assertEqual(names.get("libcurl"), "8.4.0")
        self.assertEqual(names.get("linux-kernel"), "6.6.52")   # boot partition

    def test_a_fat_boot_sector_is_not_a_partition_table(self):
        sector = bytearray(1024)
        sector[0:3] = b"\xeb\x3c\x90"
        sector[446:462] = bytes(range(16))              # boot code, not entries
        sector[510:512] = b"\x55\xaa"
        self.assertIsNone(container.parse_partition_table(bytes(sector)))

    def test_a_damaged_filesystem_never_raises_anything_else(self):
        blob = fixture("ext2_rootfs.bin")
        rng = random.Random(11)
        for length in (0, 1100, 2048, 5000, 20000):
            try:
                ext.Ext(blob[:length])
            except ext.ExtError:
                pass
        for trial in range(150):
            damaged = bytearray(blob[:40 * 1024])
            for _ in range(6):
                damaged[rng.randrange(1024, 40 * 1024)] = rng.randrange(256)
            try:
                fs = ext.Ext(bytes(damaged))
                for node in fs.files().values():
                    try:
                        fs.read_file(node)
                    except ext.ExtError:
                        pass
            except ext.ExtError:
                pass


class RealExtTest(unittest.TestCase):
    """OpenWrt 23.05.5 x86-64, as downloaded, and the unblob ext samples."""

    DIRECTORY = os.path.join(ROOT, "corpus")

    def load(self, name):
        path = os.path.join(self.DIRECTORY, name)
        if not os.path.exists(path):
            self.skipTest(f"{name} missing; run python scripts/fetch-corpus.py")
        with open(path, "rb") as f:
            return f.read()

    def test_every_file_matches_the_same_release_in_squashfs(self):
        """1,069 files, compared byte for byte with the same release built as
        SquashFS - a reader checked against another reader, on real data."""
        gunzip = lambda b: zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(b)
        disk = gunzip(self.load("ext/openwrt-23.05.5-x86-64-generic-ext4-combined.img.gz"))
        squash = squashfs.SquashFS(gunzip(self.load(
            "ext/openwrt-23.05.5-x86-64-generic-squashfs-rootfs.img.gz")), 0)
        table = container.parse_partition_table(disk)
        self.assertEqual(len(table["partitions"]), 2)
        rootfs = ext.Ext(disk, table["partitions"][1]["offset"])
        ours, theirs = rootfs.files(), squash.files()
        self.assertEqual(set(ours), set(theirs))
        self.assertEqual(len(ours), 1069)
        for path in ours:
            self.assertEqual(rootfs.read_file(ours[path]),
                             squash.read_file(theirs[path]), path)

    def test_the_gzipped_release_image_gives_its_packages(self):
        data = self.load("ext/openwrt-23.05.5-x86-64-generic-ext4-combined.img.gz")
        result = core.run_analysis(data, image_input.detect_and_load(data), "x86.img.gz")
        self.assertEqual(result["rootfs"]["os_release"]["version"], "23.05.5")
        self.assertEqual(len(result["packages"]), 150)
        self.assertIn("x86-64", result["rootfs"]["binaries"]["architecture"])

    def test_the_unblob_samples_read(self):
        expected = ["/apple.txt", "/banana.txt", "/cherry.txt"]
        for name in ("formats/ext2_1024.bin", "formats/ext3_2048.bin",
                     "formats/ext4_4096.bin"):
            fs = ext.Ext(self.load(name))
            self.assertEqual(sorted(fs.files()), expected, name)
            self.assertEqual(fs.read_file(fs.files()["/apple.txt"]), b"apple\n")
        at = self.load("formats/ext2_at_1024.bin")
        self.assertEqual(ext.find_offsets(at), [1024])

    def test_broken_symlinks_warn_and_never_raise(self):
        fs = ext.Ext(self.load("formats/ext2_badsymlinks.bin"))
        links = {p: n.get("target") for p, n in fs.walk()}
        self.assertEqual(links["/long_fastlink"], "a" * 59)
        self.assertEqual(len(links["/long_link"]), 1023)
        self.assertEqual(links["/high_link"], "a" * 62)      # size field says 4 GiB
        self.assertTrue(fs.warnings)


class YAFFSTest(unittest.TestCase):
    """YAFFS is a log on raw NAND with no superblock: the geometry is found by
    trial, the newest chunk wins, and deleted objects stay deleted."""

    @classmethod
    def setUpClass(cls):
        cls.image = fixture("yaffs2_rootfs.bin")
        cls.fs = yaffs.YAFFS(cls.image)
        cls.files = cls.fs.files()

    def test_the_geometry_is_found_not_assumed(self):
        g = self.fs.geometry
        self.assertEqual((g.version, g.page, g.spare, g.tag_offset, g.order),
                         (2, 2048, 64, 2, ">"))

    def test_a_deleted_binary_is_not_listed_or_scanned(self):
        """Its chunks are still on the flash; its header now sits in the
        deleted directory. Listing it would put software in the SBOM that is
        not on the device."""
        self.assertIn(b"SSH-2.0-dropbear_2019.78", self.image)
        self.assertNotIn("/bin/dropbear", self.files)
        names = {c["name"] for c in analyze("yaffs2_rootfs.bin")["bom"]["components"]}
        self.assertNotIn("dropbear", names)
        self.assertIn("busybox", names)

    def test_the_newest_copy_of_a_chunk_wins(self):
        release = self.fs.read_file(self.files["/etc/os-release"])
        self.assertIn(b"HiLinux 2.0.4", release)
        self.assertNotIn(b"VendorOS", release)

    def test_a_file_across_chunks_reads_whole(self):
        busybox = self.fs.read_file(self.files["/bin/busybox"])
        self.assertEqual(len(busybox), self.files["/bin/busybox"]["size"])
        self.assertGreater(len(busybox), 2048)

    def test_symlinks_keep_their_target(self):
        links = {p: n.get("target") for p, n in self.fs.walk() if n["type"] == "symlink"}
        self.assertEqual(links, {"/bin/sh": "busybox"})

    def test_the_pipeline_reads_it_as_a_rootfs(self):
        result = analyze("yaffs2_rootfs.bin")
        self.assertEqual(result["rootfs"]["os_release"]["version"], "2.0.4")
        self.assertEqual([p["name"] for p in result["packages"]], ["lighttpd"])
        self.assertIn("MIPS", result["rootfs"]["binaries"]["architecture"])

    def test_random_data_is_not_yaffs(self):
        noise = bytes(random.Random(5).randrange(256) for _ in range(64 * 1024))
        self.assertEqual([], yaffs.find_offsets(noise))
        with self.assertRaises(yaffs.YAFFSError):
            yaffs.YAFFS(noise)

    def test_a_damaged_image_never_raises_anything_else(self):
        rng = random.Random(13)
        for length in (0, 100, 2112, 5000, 20000):
            try:
                yaffs.YAFFS(self.image[:length])
            except yaffs.YAFFSError:
                pass
        for trial in range(150):
            damaged = bytearray(self.image)
            for _ in range(8):
                damaged[rng.randrange(len(damaged))] = rng.randrange(256)
            try:
                fs = yaffs.YAFFS(bytes(damaged))
                for node in fs.files().values():
                    try:
                        fs.read_file(node)
                    except yaffs.YAFFSError:
                        pass
            except yaffs.YAFFSError:
                pass


class LZOTest(unittest.TestCase):
    """A decompressor can only be tested against a compressor that is not
    itself. The reference streams come from lzokay, an independent C++
    implementation; see tests/make_lzo_vectors.py."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(HERE, "lzo_vectors.json"), encoding="utf-8") as f:
            cls.vectors = json.load(f)["vectors"]

    def test_every_reference_stream_decodes_exactly(self):
        for vector in self.vectors:
            with self.subTest(vector=vector["name"]):
                out = lzo.decompress(bytes.fromhex(vector["lzo"]), vector["length"])
                self.assertEqual(len(out), vector["length"])
                self.assertEqual(hashlib.sha256(out).hexdigest(), vector["sha256"])

    def test_the_references_exercise_every_instruction(self):
        """A vector set that stopped covering one instruction kind would pass
        while that path broke. So the coverage is itself asserted."""
        source = lzo.__file__
        executed = set()

        def trace(frame, event, arg):
            if frame.f_code.co_filename == source:
                executed.add(frame.f_lineno)
            return trace

        sys.settrace(trace)
        try:
            for vector in self.vectors:
                lzo.decompress(bytes.fromhex(vector["lzo"]), vector["length"])
        finally:
            sys.settrace(None)
        with open(source, encoding="utf-8") as f:
            lines = f.read().splitlines()
        for label, needle in {
                "M1 after a match": "# M1:",
                "M1 after literals": "match(1 + M2_MAX_OFFSET",
                "M2": "# M2:", "M3": "# M3:", "M4": "# M4:",
                "end-of-stream": "# the end-of-stream marker",
                "length extension": "extra += 255",
                "overlapping copy": "out.append(out[start + index])",
                "initial literal run": "t = take() - 17",
                "trailing literals": "literals(trailing)"}.items():
            number = next(i + 1 for i, text in enumerate(lines) if needle in text)
            with self.subTest(instruction=label):
                self.assertTrue(number in executed or number + 1 in executed)

    def test_hostile_streams_are_refused_rather_than_raising_otherwise(self):
        good = bytes.fromhex(next(v["lzo"] for v in self.vectors
                                  if v["name"] == "text"))
        for label, stream in {
                "empty": b"",
                "truncated": good[:len(good) // 2],
                "one byte": good[:1],
                "reference before the start": bytes([18, 0x41, 0x7F, 0xFF]),
                "literal run past the input": bytes([0, 0, 0x40]),
        }.items():
            with self.subTest(stream=label):
                with self.assertRaises(lzo.LZOError):
                    lzo.decompress(stream, 2700)

    def test_output_is_capped(self):
        """A few bytes of LZO can claim megabytes of output."""
        long_run = bytes.fromhex(next(v["lzo"] for v in self.vectors
                                      if v["name"] == "overlapping-run"))
        with self.assertRaises(lzo.LZOError):
            lzo.decompress(long_run, limit=100)

    def test_against_an_independent_implementation_when_available(self):
        """The full differential check. Skipped unless lzallright is installed
        - it is a test tool, never shipped - but run by hand when lzo.py
        changes: pip install lzallright."""
        try:
            import lzallright
        except ImportError:
            self.skipTest("lzallright not installed")
        compressor = lzallright.LZOCompressor()
        generator = random.Random(1985)
        for index in range(200):
            alphabet = generator.choice((2, 4, 16, 64, 256))
            length = generator.choice((1, 17, 300, 4096, 20000, 70000))
            plain = bytes(generator.randrange(alphabet) for _ in range(length))
            with self.subTest(case=index, alphabet=alphabet, length=length):
                packed = compressor.compress(plain)
                self.assertEqual(lzo.decompress(packed, len(plain)), plain)


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


class RealFormatSampleTest(unittest.TestCase):
    """The published format samples, as produced by the real tools.

    The fixtures in this suite are built by code in this repository, so they
    prove the readers agree with the way *we* understand the format. These
    files were produced by mkcramfs and by the vendors' own packers, which is
    a different claim - and the CramFS pair is the sharpest version of it: the
    same contents written in both byte orders, so the two decoders have to
    agree with each other rather than merely with the specification.

    Fetch them with `python scripts/fetch-corpus.py`; these tests skip without.
    """

    DIRECTORY = os.path.join(ROOT, "corpus", "formats")

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(cls.DIRECTORY):
            raise unittest.SkipTest(
                "format samples missing; run python scripts/fetch-corpus.py")

    def sample(self, name):
        path = os.path.join(self.DIRECTORY, name)
        if not os.path.exists(path):
            self.skipTest(f"{name} missing; run python scripts/fetch-corpus.py")
        with open(path, "rb") as f:
            return f.read()

    def test_both_byte_orders_of_cramfs_read_identically(self):
        listings = {}
        for name in ("cramfs_le.bin", "cramfs_be.bin"):
            blob = self.sample(name)
            offsets = cramfs.find_offsets(blob)
            self.assertEqual(len(offsets), 1, name)
            image = cramfs.CramFS(blob, offsets[0])
            files = image.files()
            listings[name] = {path: image.read_file(node)
                              for path, node in files.items()}
            self.assertEqual([], image.warnings, name)
        self.assertEqual(listings["cramfs_le.bin"], listings["cramfs_be.bin"])
        self.assertIn("/apple.txt", listings["cramfs_le.bin"])

    def test_the_vendor_containers_are_recognised(self):
        expected = {
            "netgear_trx_v1.bin": "Broadcom TRX v1",
            "netgear_trx_v2.bin": "Broadcom TRX v2",
            "netgear_chk.bin": "Netgear CHK",
            "dlink_shrs.bin": "D-Link SHRS",
            "instar_bneg.bin": "Instar BNEG",
            "moxa_frm.bin": "Moxa FRM",
        }
        for name, label in expected.items():
            with self.subTest(sample=name):
                found = vendor_container.detect(self.sample(name))
                self.assertIsNotNone(found, name)
                self.assertEqual(found["label"], label)
                for part in found["parts"]:
                    self.assertGreaterEqual(part["offset"],
                                            found["header_length"])

    def test_every_jffs2_variant_reads_identically(self):
        """Both byte orders, both magics, padded or not, and every compressor
        the samples carry - including LZO, through lzo.py."""
        results = {}
        for name in ("jffs2_new_le_zlib.bin", "jffs2_new_be_lzo.bin",
                     "jffs2_old_le_rtime.bin", "jffs2_new_be_nocomp_padded.bin",
                     "jffs2_old_be_lzo_padded.bin"):
            blob = self.sample(name)
            image = jffs2.JFFS2(blob, 0)
            results[name] = {path: image.read_file(node)
                             for path, node in image.files().items()}
        first = next(iter(results.values()))
        self.assertEqual(first["/apple.txt"], b"A" * 25 + b"\n")
        for name, listing in results.items():
            self.assertEqual(listing, first, name)

    def test_a_cramfs_sample_goes_through_the_whole_pipeline(self):
        blob = self.sample("cramfs_le.bin")
        segments, rootfs, _warnings = core.analyze_segments(blob, 6)
        self.assertTrue(any(s["kind"] == "filesystem" for s in segments))
        self.assertIsNotNone(rootfs)

    def test_an_encrypted_payload_is_reported_as_unreadable(self):
        """D-Link's SHRS payload is encrypted. Recognising the wrapper must not
        turn into a claim that what is behind it was read."""
        blob = self.sample("dlink_shrs.bin")
        segments, _rootfs, _warnings = core.analyze_segments(blob, 6)
        header = next(s for s in segments if s["kind"] == "vendor-header")
        self.assertEqual(header["length"], vendor_container.SHRS_HEADER_SIZE)
        payload = [s for s in segments if s["kind"] != "vendor-header"]
        self.assertTrue(payload)
        self.assertTrue(any((s.get("opacity") or {}).get("opaque")
                            for s in payload), [s["label"] for s in payload])

    def test_every_yaffs_geometry_reads_identically(self):
        """Seven of unblob's 79 YAFFS samples are fetched: YAFFS2 at three
        page sizes, both byte orders, both tag positions, a 16-byte spare
        that cuts the tags short, and YAFFS1 in both byte orders."""
        expected = {"/fruits/apple.txt": b"apple\n", "/fruits/cherry.txt": b"cherry\n"}
        for name, geometry in (
                ("yaffs2_2048_64_le.bin", (2, 2048, 64, 2, "<")),
                ("yaffs2_4096_128_be.bin", (2, 4096, 128, 0, ">")),
                ("yaffs2_16384_16_le.bin", (2, 16384, 16, 2, "<"))):
            fs = yaffs.YAFFS(self.sample(name))
            g = fs.geometry
            self.assertEqual((g.version, g.page, g.spare, g.tag_offset, g.order),
                             geometry, name)
            files = fs.files()
            for path, content in expected.items():
                self.assertEqual(fs.read_file(files[path]), content, name)
        for name in ("yaffs1_le.bin", "yaffs1_be.bin"):
            fs = yaffs.YAFFS(self.sample(name))
            self.assertEqual(fs.geometry.version, 1)
            self.assertEqual(sorted(fs.files()),
                             ["/dir/apple.txt", "/dir/banana.txt", "/dir/cherry.txt"])

    def test_yaffs_links_and_a_damaged_parent(self):
        fs = yaffs.YAFFS(self.sample("yaffs1_links.bin"))
        listing = {p: n for p, n in fs.walk()}
        self.assertEqual(fs.read_file(listing["/hardlink"]), b"content\n")
        self.assertEqual(listing["/symlink2"]["target"], "dir/hardlink")
        # A parent field pointing at a file: unblob drops that entry, and so
        # must we - a path through a file is not a path.
        fs = yaffs.YAFFS(self.sample("yaffs2_malformed_be.bin"))
        self.assertNotIn("/fruits/banana.txt", fs.files())
        self.assertFalse([p for p in fs.files() if p.startswith("/fruits/apple.txt/")])
        self.assertIn("/fruits/apple.txt", fs.files())

    def test_ubi_volumes_are_reassembled_and_named(self):
        image = ubi.read_image(self.sample("ubi_fruits.bin"))
        self.assertEqual([(v["name"], v["type"]) for v in image["volumes"]],
                         [("apple", "static"), ("data", "dynamic")])
        apple = image["volumes"][0]["data"]
        self.assertEqual(apple, b"apple1\n")     # static: exactly its data size

    def test_a_real_ubifs_volume_reads_through_lzo(self):
        """706 LZO data nodes from the real toolchain, each decoding to exactly
        its declared size, inside a UBI image cut off mid-block."""
        image = ubi.read_image(self.sample("ubi_orange_truncated.bin"))
        self.assertTrue(image["warnings"])
        volumes = {v["name"]: v for v in image["volumes"]}
        fs = ubifs.UBIFS(volumes["configuration"]["data"])
        sizes = {path: len(fs.read_file(node)) for path, node in fs.files().items()}
        self.assertEqual(sizes, {"/orange1.txt": 1445004, "/orange2.txt": 1445005})
        with self.assertRaisesRegex(ubifs.UBIFSError, "truncated"):
            ubifs.UBIFS(volumes["rootfs"]["data"])

    def test_an_unreadable_ubifs_volume_is_opaque_not_blank(self):
        """The truncated 'rootfs' volume has no index. That is a filesystem we
        could not list - not erased flash, and not a volume with nothing in it."""
        blob = self.sample("ubi_orange_truncated.bin")
        segments, _rootfs, _warnings = core.analyze_segments(blob, 6)
        opaque = core.opaque_segments(segments)
        self.assertEqual(len(opaque), 1, [s["label"] for s in opaque])
        self.assertIn("rootfs", opaque[0]["label"])
        self.assertIn("truncated", opaque[0]["unread_reason"])
        self.assertFalse(opaque[0].get("blank"))

    def test_every_raw_ubifs_sample_reads_identically(self):
        results = {}
        for name in ("ubifs_lzo.bin", "ubifs_zlib.bin", "ubifs_zstd.bin"):
            fs = ubifs.UBIFS(self.sample(name))
            self.assertEqual([], fs.warnings, name)
            results[name] = {path: fs.read_file(node)
                             for path, node in fs.files().items()}
        first = next(iter(results.values()))
        self.assertEqual(first["/banana1.txt"], b"banana1\n")
        self.assertEqual(len(first), 4)
        for name, listing in results.items():
            self.assertEqual(listing, first, name)


class RealBiosTest(unittest.TestCase):
    """The whole pipeline over a published EDK2 build.

    The synthetic fixtures were written from the specifications; this image is
    what the specifications turn into once a real build system has been at it.
    Two defects came straight out of running it: a pad file's all-0xFF GUID
    read as the end of a volume (which hid every PEI module), and the variable
    store walked as if it held modules (which invented one).
    """

    IMAGE = os.path.join(ROOT, "corpus", "uefi", "edk2-ovmf-x64.fd")

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(cls.IMAGE):
            raise unittest.SkipTest(
                "corpus image missing; run python scripts/fetch-corpus.py")
        with open(cls.IMAGE, "rb") as f:
            cls.data = f.read()
        cls.found = uefi.detect(cls.data)
        cls.inventory = uefi.read_modules(cls.data, cls.found["volumes"])

    def test_the_volumes_are_found_and_the_false_ones_are_not(self):
        """Four of the seven "_FVH" strings in this image are inside compiled
        code."""
        self.assertEqual(len(self.found["volumes"]), 3)
        self.assertEqual([v["filesystem"] for v in self.found["volumes"]],
                         ["NVRAM store", "FFS2", "FFS2"])

    def test_the_inventory_is_most_of_a_hundred_modules(self):
        modules = self.inventory["modules"]
        named = [m for m in modules if m["name"]]
        self.assertGreater(len(modules), 100)
        self.assertGreater(len(named), 100)
        names = {m["name"] for m in named}
        for expected in ("DxeCore", "PeiCore", "PciBusDxe", "SecMain"):
            self.assertIn(expected, names)

    def test_the_pei_modules_are_behind_a_pad_file(self):
        """The specific shape that broke the first version: the PEI volume's
        second file is a pad, so a GUID-based end-of-volume test loses the lot."""
        pei = [m["name"] for m in self.inventory["modules"]
               if m["type"] in ("peim", "pei-core") and m["name"]]
        self.assertGreater(len(pei), 5, pei)

    def test_the_variable_store_yields_no_modules(self):
        self.assertEqual([v["filesystem"]
                          for v in self.inventory["data_volumes"]],
                         ["NVRAM store"])

    def test_the_architecture_comes_from_the_pe_headers(self):
        arch = core.analyze_architecture(self.data)
        self.assertEqual(arch["architecture"], "x86-64")

    def test_string_matching_alone_would_have_found_nothing(self):
        """The finding that justifies the whole module: this image contains no
        library banner any signature matches. Everything in its SBOM comes from
        structure - except one OpenSSL symbol, which is only reachable because
        the compressed volume was expanded."""
        plain = core.match_signatures(core.extract_strings(self.data, 6), False)
        self.assertEqual([], plain)

    def test_expanding_the_volume_is_what_finds_the_library(self):
        expansions = self.inventory["expansions"]
        self.assertTrue(expansions)
        found = core.match_signatures(
            core.extract_strings(expansions[0]["data"], 6), False)
        self.assertIn("openssl", {h["sig"]["name"] for h in found})

    def test_a_real_bios_is_analysed_in_reasonable_time(self):
        start = time.perf_counter()
        core.analyze_segments(self.data, 6)
        self.assertLess(time.perf_counter() - start, 60)


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

        # The same image analysed as if it shipped no package database - the
        # common case outside OpenWrt. Walking 14 MB is slow enough that doing
        # it per test method trebled the suite's runtime.
        original = container.read_package_database
        try:
            container.read_package_database = lambda image, files: None
            cls.bare_segments, cls.bare_rootfs, _w = core.analyze_segments(
                cls.data, 6)
            cls.bare_hits = core.scan_rootfs_files(cls.bare_rootfs, 6)
        finally:
            container.read_package_database = original
        cls.bare_merged = core.merge_hit_lists(
            core.merge_segment_hits(cls.bare_segments), cls.bare_hits)

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

    def test_a_package_database_suppresses_per_file_scanning(self):
        """Where the package manager has spoken, do not add heuristics.

        An exact version from the build system cannot be improved on by a
        regex over the same file, and a second opinion that disagrees is
        worse than no second opinion.
        """
        extra = core.scan_rootfs_files(self.rootfs, 6)
        owners = self.rootfs["binaries"]["file_owners"]
        for hit in extra:
            for path in hit.get("files", []):
                self.assertNotIn(path, owners,
                                 "a file a package already accounts for was "
                                 "scanned anyway")

    def test_package_metadata_is_never_scanned(self):
        """opkg's own .control files describe packages we already have.

        Scanning them matches signature names inside Description fields and
        invents version-less components sourced from text files.
        """
        scanned = [path for path, _blob
                   in container.unclaimed_files(self.rootfs)]
        for path in scanned:
            self.assertFalse(path.startswith("/usr/lib/opkg/"),
                             f"scanned package metadata: {path}")

    def test_without_a_package_database_the_files_are_read_instead(self):
        """The case that matters for devices outside OpenWrt.

        Most vendor firmware ships no package database at all, and until the
        root filesystem files were scanned those images produced nothing from
        the rootfs whatsoever. Simulating that here is the only way to test it
        without a second corpus image.
        """
        found = {h["sig"]["name"]: h for h in self.bare_hits}
        self.assertGreater(len(found), 5)

        # Versions cross-checked against the package database, which is
        # ground truth for this image.
        for name, version, path in [
                ("busybox", "1.35.0", "/bin/busybox"),
                ("libcurl", "7.88.1", "/usr/bin/curl"),
                ("zlib", "1.2.11", "/usr/lib/libz.so.1.2.11")]:
            with self.subTest(component=name):
                self.assertIn(name, found)
                self.assertEqual(found[name]["version"], version)
                self.assertIn(path, found[name]["files"])

    def test_evidence_names_the_file_the_match_came_from(self):
        """Not whichever of the component's files happens to sort first.

        Pointing an auditor at a config file for a string that came out of a
        binary elsewhere is a defect in the document, not a cosmetic one.
        """
        bom = core.build_sbom(
            "corpus.bin", self.data, None,
            {"label": None, "details": [], "looks_like_cortex_m": False},
            self.bare_merged, 6, 0, segments=self.bare_segments,
            rootfs=self.bare_rootfs, packages=[])

        openssl = next(c for c in bom["components"] if c["name"] == "openssl")
        value = openssl["evidence"]["identity"][0]["methods"][0]["value"]
        source = openssl["evidence"]["occurrences"][1]["location"]
        self.assertIn(source, value,
                      "the quoted match must name the file it came from")
        self.assertTrue(source.startswith("/usr/bin/openssl"),
                        f"expected the openssl binary, got {source}")

    def test_evidence_distinguishes_executables_from_other_files(self):
        """A banner compiled into a binary and a version in a config file are
        not the same evidence, and the document should not imply they are."""
        kinds = {h.get("file_kind") for h in self.bare_hits}
        self.assertTrue(kinds)
        for kind in kinds:
            self.assertIn(kind, ("an executable", "a non-executable file"))

    def test_a_real_image_is_analysed_in_reasonable_time(self):
        """A customer waits for this in a browser."""
        start = time.perf_counter()
        core.analyze_segments(self.data, 6)
        self.assertLess(time.perf_counter() - start, 60)


if __name__ == "__main__":
    unittest.main(verbosity=2)
