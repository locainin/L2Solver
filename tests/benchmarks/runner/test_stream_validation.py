"""Stream bundles are checked against capture records and bounded windows."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from benchmarks.runner.stream_validation import validate_stream_bundle

from .stream_support import classic_capture, metadata_for, write_bundle


def current_collection_summary():
    return {
        "sections": 0,
        "reported_sections": 0,
        "incomplete_sections": 0,
        "capture_dropped": 0,
        "interface_dropped": 0,
        "packet_block_packets_dropped": 0,
        "packet_blocks_with_unavailable_drop_count": 0,
    }


class StreamValidationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.capture = classic_capture([8, 9, 10, 11, 12, 13])
        self.metadata = metadata_for(self.capture)
        self.bundle, self.manifest, self.exit_code = write_bundle(
            self.root, self.capture, self.metadata,
            [(1, 3, 1), (4, 6, 2)], context_records=2,
        )

    def tearDown(self):
        self.temporary.cleanup()

    def test_overlapping_windows_cover_primary_records(self):
        result = validate_stream_bundle(self.bundle, self.capture, self.metadata, self.exit_code)

        self.assertTrue(result["raw_collection_complete"])
        self.assertTrue(result["analysis_complete"])
        self.assertEqual(result["frames_seen"], 6)
        self.assertEqual(result["pages_checked"], 2)
        self.assertEqual(result["primary_packet_nodes"], 6)

    def test_schema_rejects_noninteger_versions(self):
        manifest_path = self.bundle / "manifest.json"
        for version in (True, 1.0, "1", None):
            with self.subTest(version=version):
                self.manifest["schema_version"] = version
                manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "unsupported stream manifest schema"):
                    validate_stream_bundle(
                        self.bundle, self.capture, self.metadata, self.exit_code
                    )

    def test_accepts_exporter_collection_summary(self):
        self.write_collection_summary({
            "sections": 0,
            "reported_sections": 0,
            "incomplete_sections": 0,
            "capture_dropped": 0,
            "interface_dropped": 0,
        })

        result = validate_stream_bundle(self.bundle, self.capture, self.metadata, self.exit_code)

        self.assertTrue(result["raw_collection_complete"])

    def test_accepts_current_collection_summary_with_packet_block_counters(self):
        self.write_collection_summary(current_collection_summary())

        result = validate_stream_bundle(self.bundle, self.capture, self.metadata, self.exit_code)

        self.assertTrue(result["raw_collection_complete"])
        self.assertTrue(result["analysis_complete"])

    def test_collection_summary_rejects_missing_current_fields(self):
        for field in current_collection_summary():
            with self.subTest(field=field):
                summary = current_collection_summary()
                del summary[field]
                self.write_collection_summary(summary)
                with self.assertRaisesRegex(ValueError, "collection summary fields"):
                    validate_stream_bundle(self.bundle, self.capture, self.metadata, self.exit_code)

    def test_collection_summary_rejects_invalid_packet_block_counters(self):
        for field in ("packet_block_packets_dropped", "packet_blocks_with_unavailable_drop_count"):
            for value in (-1, True, 1.5, None, "1", 2 ** 64):
                with self.subTest(field=field, value=value):
                    summary = current_collection_summary()
                    summary[field] = value
                    self.write_collection_summary(summary)
                    with self.assertRaisesRegex(ValueError, "collection summary"):
                        validate_stream_bundle(self.bundle, self.capture, self.metadata, self.exit_code)

    def test_packet_block_loss_or_unknown_count_makes_analysis_partial(self):
        for field in ("packet_block_packets_dropped", "packet_blocks_with_unavailable_drop_count"):
            with self.subTest(field=field):
                summary = current_collection_summary()
                summary[field] = 1
                self.write_collection_summary(summary)
                manifest_path = self.bundle / "manifest.json"
                manifest = json.loads(manifest_path.read_text())
                manifest["analysis_complete"] = False
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

                result = validate_stream_bundle(self.bundle, self.capture, self.metadata, 3)

                self.assertTrue(result["raw_collection_complete"])
                self.assertFalse(result["analysis_complete"])

    def test_packet_block_loss_or_unknown_count_rejects_complete_analysis_claim(self):
        for field in ("packet_block_packets_dropped", "packet_blocks_with_unavailable_drop_count"):
            with self.subTest(field=field):
                summary = current_collection_summary()
                summary[field] = 1
                self.write_collection_summary(summary)
                with self.assertRaisesRegex(ValueError, "analysis status"):
                    validate_stream_bundle(self.bundle, self.capture, self.metadata, self.exit_code)

    def test_collection_summary_rejects_unknown_fields(self):
        self.write_collection_summary({
            "sections": 0,
            "reported_sections": 0,
            "incomplete_sections": 0,
            "capture_dropped": 0,
            "interface_dropped": 0,
            "unknown": 0,
        })

        with self.assertRaisesRegex(ValueError, "collection summary fields"):
            validate_stream_bundle(self.bundle, self.capture, self.metadata, self.exit_code)

    def test_current_collection_summary_rejects_unknown_fields(self):
        summary = current_collection_summary()
        summary["unknown"] = 0
        self.write_collection_summary(summary)

        with self.assertRaisesRegex(ValueError, "collection summary fields"):
            validate_stream_bundle(self.bundle, self.capture, self.metadata, self.exit_code)

    def test_collection_summary_rejects_inconsistent_counters(self):
        self.write_collection_summary({
            "sections": 0,
            "reported_sections": 1,
            "incomplete_sections": 0,
            "capture_dropped": 0,
            "interface_dropped": 0,
        })

        with self.assertRaisesRegex(ValueError, "collection summary counters"):
            validate_stream_bundle(self.bundle, self.capture, self.metadata, self.exit_code)

    def test_source_incompleteness_preserves_raw_completeness(self):
        self.write_collection_summary({
            "sections": 1,
            "reported_sections": 1,
            "incomplete_sections": 1,
            "capture_dropped": 0,
            "interface_dropped": 0,
        })
        manifest_path = self.bundle / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["analysis_complete"] = False
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        result = validate_stream_bundle(self.bundle, self.capture, self.metadata, 3)

        self.assertTrue(result["raw_collection_complete"])
        self.assertFalse(result["analysis_complete"])

    def write_collection_summary(self, summary):
        manifest_path = self.bundle / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["source"]["collection_summary"] = summary
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    def test_partial_retention_requires_partial_exit(self):
        bundle, _, exit_code = write_bundle(
            self.root / "partial", self.capture, self.metadata,
            [(1, 3, 1), (4, 6, 2)], context_records=2,
            missing_by_page={2: (5,)},
        )

        result = validate_stream_bundle(bundle, self.capture, self.metadata, exit_code)

        self.assertFalse(result["raw_collection_complete"])
        self.assertFalse(result["analysis_complete"])

    def test_packet_omissions_reject_complete_claims(self):
        bundle, _, exit_code = write_bundle(
            self.root / "false-complete", self.capture, self.metadata,
            [(1, 3, 1), (4, 6, 2)], context_records=2,
            missing_by_page={2: (5,)}, raw_collection_complete=True,
        )

        with self.assertRaisesRegex(ValueError, "primary packet|raw collection"):
            validate_stream_bundle(bundle, self.capture, self.metadata, exit_code)

    def test_primary_ranges_require_gapless_coverage(self):
        manifest_path = self.bundle / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["pages"][1]["first_record"] = 5
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "gap|partition|coverage"):
            validate_stream_bundle(self.bundle, self.capture, self.metadata, self.exit_code)

    def test_page_paths_stay_inside_bundle(self):
        manifest_path = self.bundle / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["pages"][0]["path"] = "../outside.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "path|page"):
            validate_stream_bundle(self.bundle, self.capture, self.metadata, self.exit_code)

    def test_page_hash_precedes_case_validation(self):
        page_path = self.bundle / "pages/000001.json"
        page_path.write_bytes(page_path.read_bytes() + b" ")

        with self.assertRaisesRegex(ValueError, "hash"):
            validate_stream_bundle(self.bundle, self.capture, self.metadata, self.exit_code)

    def test_packet_ranges_match_capture_records(self):
        page_path = self.bundle / "pages/000001.json"
        page = json.loads(page_path.read_text())
        page["nodes"][0]["ranges"][0]["offset"] += 1
        page_bytes = json.dumps(page, sort_keys=True).encode("utf-8") + b"\n"
        page_path.write_bytes(page_bytes)
        manifest_path = self.bundle / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["pages"][0]["sha256"] = hashlib.sha256(page_bytes).hexdigest()
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "packet source range|packet bounds"):
            validate_stream_bundle(self.bundle, self.capture, self.metadata, self.exit_code)

    def test_context_window_respects_record_limit(self):
        manifest_path = self.bundle / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["context_records"] = 129
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "context"):
            validate_stream_bundle(self.bundle, self.capture, self.metadata, self.exit_code)

    def test_context_bytes_have_independent_limit(self):
        capture = classic_capture([10, 300 * 1024, 10, 10])
        metadata = metadata_for(capture)
        bundle, _, exit_code = write_bundle(
            self.root / "large-context", capture, metadata,
            [(1, 2, 1), (3, 4, 2)], context_records=1,
        )

        with self.assertRaisesRegex(ValueError, "context.*byte|byte.*context"):
            validate_stream_bundle(bundle, capture, metadata, exit_code)

    def test_primary_window_bytes_are_bounded(self):
        capture = classic_capture([513 * 1024])
        metadata = metadata_for(capture)
        bundle, _, exit_code = write_bundle(
            self.root / "large-primary", capture, metadata,
            [(1, 1, 1)], context_records=0,
        )

        with self.assertRaisesRegex(ValueError, "primary.*byte|byte.*primary"):
            validate_stream_bundle(bundle, capture, metadata, exit_code)

    def test_empty_capture_has_complete_bundle(self):
        capture = classic_capture([])
        metadata = metadata_for(capture)
        bundle, _, exit_code = write_bundle(
            self.root / "empty", capture, metadata, [], context_records=0,
        )

        result = validate_stream_bundle(bundle, capture, metadata, exit_code)

        self.assertEqual(result["frames_seen"], 0)
        self.assertTrue(result["raw_collection_complete"])
        self.assertTrue(result["analysis_complete"])

    def test_rejects_trailing_malformed_capture_bytes(self):
        bundle, manifest, exit_code = write_bundle(
            self.root / "malformed-source", self.capture, self.metadata,
            [(1, 3, 1), (4, 6, 2)], context_records=2,
        )
        capture = self.capture + b"\x00"
        metadata = metadata_for(capture)
        source_id = "sha256:" + metadata["capture_sha256"]
        manifest["source"]["id"] = source_id
        manifest["source"]["length"] = len(capture)
        (bundle / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        for page_entry in manifest["pages"]:
            page_path = bundle / page_entry["path"]
            page = json.loads(page_path.read_text())
            page["sources"][0]["id"] = source_id
            page["sources"][0]["length"] = len(capture)
            for node in page["nodes"]:
                for source_range in node["ranges"]:
                    source_range["source"] = source_id
            page_bytes = json.dumps(page, sort_keys=True).encode("utf-8") + b"\n"
            page_path.write_bytes(page_bytes)
            page_entry["sha256"] = hashlib.sha256(page_bytes).hexdigest()
        (bundle / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "truncated|record|capture"):
            validate_stream_bundle(bundle, capture, metadata, exit_code)


if __name__ == "__main__":
    unittest.main()


def test_manifest_length_uses_verified_size(tmp_path):
    from benchmarks.runner.stream_validation import check_manifest

    capture = classic_capture([8])
    metadata = metadata_for(capture)
    _, manifest, _ = write_bundle(tmp_path, capture, metadata, [(1, 1, 1)], context_records=0)
    # The input loader already authorizes the capture size before this metadata check
    length = 1024 * 1024 * 1024
    manifest["source"]["length"] = length
    metadata["capture_bytes"] = length

    source, *_ = check_manifest(manifest, metadata, length)

    assert source["length"] == length


def test_bundle_budget_counts_all_documents(tmp_path, monkeypatch):
    import pytest

    from benchmarks.runner import stream_validation

    capture = classic_capture([8])
    metadata = metadata_for(capture)
    bundle, manifest, code = write_bundle(tmp_path, capture, metadata, [(1, 1, 1)], context_records=0)
    manifest_bytes = (bundle / "manifest.json").stat().st_size
    page_bytes = sum((bundle / row["path"]).stat().st_size for row in manifest["pages"])
    total = manifest_bytes + page_bytes

    # A page-only allowance must still reject the manifest's document bytes
    monkeypatch.setattr(stream_validation, "MAX_BUNDLE_BYTES", page_bytes)
    with pytest.raises(ValueError, match="bundle.*bytes"):
        validate_stream_bundle(bundle, capture, metadata, code)

    # Keep the same accounting boundary with a small real bundle
    monkeypatch.setattr(stream_validation, "MAX_BUNDLE_BYTES", total)
    result = validate_stream_bundle(bundle, capture, metadata, code)
    assert result["page_bytes"] == page_bytes

    monkeypatch.setattr(stream_validation, "MAX_BUNDLE_BYTES", total - 1)
    with pytest.raises(ValueError, match="bundle.*bytes"):
        validate_stream_bundle(bundle, capture, metadata, code)
