"""Check the five case outcomes and their portable evidence summary."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from benchmarks.runner.catalogue import hash_file
from benchmarks.runner.refine_fixtures import FixtureSizes, generate
from benchmarks.runner.refine_validation import CASE_INPUTS, summarize, validate_case
from benchmarks.refine_benchmark import case_command, collect, prepare


class RefineValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixtures = generate(self.root, FixtureSizes(131072, 4096, 4096, 4096, 4096))
        self.binary = self.root / "candidate"
        self.binary.write_bytes(b"candidate binary identity")
        (self.root / "plan.json").write_text(json.dumps({"source_commit": "c98ac15859d4d4036023364e0a97e0773309b321", "binary_sha256": hash_file(self.binary)}))

    def make_case(self, case):
        output, receipt = self.root / "output" / case, self.root / "receipts" / case
        output.mkdir(parents=True)
        receipt.mkdir(parents=True)
        (output / "summary.txt").write_text("partial\n")
        requirements = {
            "near-eof": [("first.png", "source_range"), ("embedded.zip", "source_range")],
            "encoded": [("encoded-reference.zip", "base64_decode"), ("first.png", "archive_member"), ("second.png", "archive_member")],
            "valid-zip": [("large-valid.zip", "source_range"), ("first.png", "archive_member"), ("second.png", "archive_member")],
            "corrupt-zip": [("first.png", "source_range")],
            "output-limit": [],
        }
        artifacts = []
        for name, kind in requirements[case]:
            shutil.copyfile(self.root / "fixtures" / name, output / name)
            file = self.fixtures["files"][name]
            artifacts.append({"file": name, "byte_length": file["length"], "sha256": file["sha256"],
                              "origins": [{"origin": {"kind": kind}}]})
            if case == "encoded" and name == "encoded-reference.zip":
                artifacts[-1]["origins"].append({"origin": {"kind": "gzip_decompress"}})
        reasons = {
            "near-eof": [{"kind": "source_stream_transform", "reason": "no supported whole-source streaming transformation was identified"}],
            "encoded": [{"kind": "depth_limit"}],
            "valid-zip": [{"kind": "zip_member", "reason": "entry_expanded_byte_limit"}],
            "corrupt-zip": [{"kind": "source_stream_transform", "reason": "no supported whole-source streaming transformation was identified"}],
            "output-limit": [{"kind": "source_stream_transform", "operation": {"kind": "gzip_decompress"},
                              "reason": "stream operation failed: OutputLimitExceeded { limit: 42 }"}],
        }
        source = self.fixtures["files"][CASE_INPUTS[case]]
        manifest = {"complete": False, "sources": [{"sha256": source["sha256"], "omissions": reasons[case]}], "artifacts": artifacts}
        (output / "manifest.json").write_text(json.dumps(manifest))
        info = {"exit_code": 3, "status": None, "duration_seconds": 1,
                "cgroup": {"peak_bytes": 1024, "oom": 0, "oom_kill": 0, "max_events": 0,
                           "memory_max_bytes": 512 * 1024 * 1024, "swap_max_bytes": 0,
                           "cpu_hierarchy": {"effective_visible_quota": {"quota_us": 100000, "period_us": 100000}},
                           "cpu_hierarchy_after": {"effective_visible_quota": {"quota_us": 100000, "period_us": 100000}}},
                "monitor": {"memory_scope": "analyzer_process_only", "peak_sampled_rss_bytes": 512,
                            "io_measurement_scope": "linux_procfs_analyzer_process_only",
                            "process_io_bytes": {"rchar_bytes": source["length"] * 5, "read_bytes": 0}}}
        (receipt / "cgroup.json").write_text(json.dumps(info))
        (receipt / "disk-observation.json").write_text(json.dumps({"samples": 1, "sampling_errors": 0,
                         "disk_stop_requested": False, "peaks_are_lower_bounds": True}))
        (receipt / "stderr.log").write_text(json.dumps({"counters": {"source_read_bytes": source["length"] * 2}}) + "\n")
        return manifest

    def test_all_cases_check_outputs_reasons_and_keep_read_measures_separate(self):
        reports = {}
        for case in CASE_INPUTS:
            with self.subTest(case=case):
                self.make_case(case)
                report = validate_case(self.root, case)
                self.assertEqual(report["source_read_amplification"], 2)
                self.assertEqual(report["binary_rchar_per_source_byte"], 5)
                self.assertFalse(report["manifest_complete"])
                self.assertEqual(report["exit_code"], 3)
                reports[case] = report
        summary = summarize(self.root, self.binary, reports)
        self.assertEqual(summary["source_commit"], "c98ac15859d4d4036023364e0a97e0773309b321")
        self.assertEqual(summary["binary"]["sha256"], hash_file(self.binary))
        self.assertEqual(summary["cases"]["encoded"]["source_path"], "fixtures/encoded-gzip.txt")
        self.assertNotIn(str(self.root), json.dumps(summary))
        self.assertIn("candidate", " ".join(summary["limitations"]).lower())
        self.assertFalse(summary["cases"]["corrupt-zip"]["explicit_corruption_reason"])
        self.binary.write_bytes(b"changed binary")
        with self.assertRaisesRegex(ValueError, "binary"):
            summarize(self.root, self.binary, reports)

    def test_unlisted_outputs_and_inadequate_resource_receipts_are_rejected(self):
        self.make_case("near-eof")
        output = self.root / "output" / "near-eof"
        (output / "unlisted.bin").write_bytes(b"unlisted")
        with self.assertRaisesRegex(ValueError, "output"):
            validate_case(self.root, "near-eof")
        (output / "unlisted.bin").unlink()
        path = self.root / "receipts" / "near-eof" / "cgroup.json"
        receipt = json.loads(path.read_text())
        receipt["cgroup"]["swap_max_bytes"] = "max"
        path.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, "cgroup"):
            validate_case(self.root, "near-eof")
        receipt["cgroup"]["swap_max_bytes"] = 0
        receipt["cgroup"]["cpu_hierarchy_after"]["effective_visible_quota"]["quota_us"] = 200000
        path.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, "CPU"):
            validate_case(self.root, "near-eof")

    def test_collection_is_repeatable_and_does_not_write_partial_success(self):
        for case in CASE_INPUTS:
            self.make_case(case)
        path = self.root / "output" / "output-limit" / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest["sources"][0]["omissions"] = []
        path.write_text(json.dumps(manifest))
        with self.assertRaises(ValueError):
            collect(self.root, self.binary)
        self.assertFalse(any((self.root / "receipts" / case / "case-validation.json").exists() for case in CASE_INPUTS))
        manifest["sources"][0]["omissions"] = [{"kind": "source_stream_transform", "operation": {"kind": "gzip_decompress"},
                                                  "reason": "OutputLimitExceeded { limit: 42 }"}]
        path.write_text(json.dumps(manifest))
        first = collect(self.root, self.binary)
        self.assertEqual(collect(self.root, self.binary), first)

    def test_changed_source_output_and_missing_reason_are_rejected(self):
        manifest = self.make_case("valid-zip")
        path = self.root / "output" / "valid-zip" / "manifest.json"
        manifest["sources"][0]["omissions"] = []
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "omission"):
            validate_case(self.root, "valid-zip")
        manifest["sources"][0]["omissions"] = [{"kind": "zip_member", "reason": "entry_expanded_byte_limit"}]
        path.write_text(json.dumps(manifest))
        (self.root / "output" / "valid-zip" / "first.png").write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "artifact"):
            validate_case(self.root, "valid-zip")
        shutil.copyfile(self.root / "fixtures" / "first.png", self.root / "output" / "valid-zip" / "first.png")
        (self.root / "fixtures" / "large-valid.zip").write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "source"):
            validate_case(self.root, "valid-zip")

    def test_encoded_provenance_must_belong_to_the_recovered_zip(self):
        manifest = self.make_case("encoded")
        manifest["artifacts"][0]["origins"] = [{"origin": {"kind": "base64_decode"}}]
        manifest["artifacts"][1]["origins"].append({"origin": {"kind": "gzip_decompress"}})
        (self.root / "output" / "encoded" / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "provenance"):
            validate_case(self.root, "encoded")

    def test_near_eof_recovery_requires_the_embedded_zip_as_well_as_the_png(self):
        manifest = self.make_case("near-eof")
        manifest["artifacts"] = [artifact for artifact in manifest["artifacts"]
                                 if artifact["file"] != "embedded.zip"]
        output = self.root / "output" / "near-eof"
        (output / "embedded.zip").unlink()
        (output / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "embedded ZIP"):
            validate_case(self.root, "near-eof")

    def test_commands_use_private_directories_and_existing_policy(self):
        for case in CASE_INPUTS:
            with self.subTest(case=case):
                command = case_command(self.root, case, self.binary)
                self.assertIn("--no-cache", command)
                self.assertIn(str(self.root / "fixtures" / CASE_INPUTS[case]), command)
                self.assertIn("TMPDIR=" + str(self.root / "private" / case / "tmp"), command)
                self.assertEqual(command[command.index("--memory-limit") + 1], "32MiB" if case == "output-limit" else "128MiB")

    def test_preparation_requires_an_unambiguous_full_source_commit(self):
        with patch("benchmarks.refine_benchmark.generate", side_effect=AssertionError("fixture generation must not start")):
            for commit in ("c98ac15", "HEAD", "f" * 41):
                with self.subTest(commit=commit), self.assertRaisesRegex(ValueError, "commit"):
                    prepare(self.root / "new", self.binary, commit)


if __name__ == "__main__":
    unittest.main()
