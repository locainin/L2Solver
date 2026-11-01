"""Post-freeze protocol scores use explicit identities and fabricated truth."""

import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from benchmarks.protocol_scoring import FrozenIdentities, main, score_protocol_run
from benchmarks.runner.catalogue import hash_file
from benchmarks.runner.recovery import build_extract_command, validate_export_output
from recovery_support import write_export


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def digest(data):
    return hashlib.sha256(data).hexdigest()


class ProtocolScoringTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.public = self.root / "public"
        self.public.mkdir()
        self.private = self.root / "private"
        self.private.mkdir()
        self.run = self.root / "run"
        self.run.mkdir()
        self.binary = self.root / "binary"
        self.binary.write_bytes(b"frozen test binary")
        self.manifest = self.public / "manifest.json"
        self.oracle = self.private / "oracle.json"
        self.ledger = self.private / "ledger.json"
        self.commit = "a" * 40
        self.expected = b"independently expected bytes"
        (self.private / "expected.bin").write_bytes(self.expected)
        expected = [{"file": "expected.bin", "bytes": len(self.expected), "sha256": digest(self.expected)}]
        cases = [
            ("positive", "heldout", expected, [self.expected], 0, None),
            ("control", "negative", [], [], 0, None),
            ("unsupported", "negative", [], [b"unsupported output"], 0, None),
            ("unknown", "negative", [], [b"unclassified output"], 0, None),
            ("partial-control", "negative", [], [b"partial output"], 3, None),
            ("timeout-positive", "validation", expected, [], None, "timeout"),
        ]
        manifest_cases, truth, rows = [], [], []
        for index, (name, split, wanted, artifacts, code, failure) in enumerate(cases):
            capture = self.public / f"{name}.pcap"
            capture.write_bytes(f"capture-{name}".encode())
            manifest_cases.append({"case_id": name, "capture_file": capture.name,
                                   "capture_sha256": hash_file(capture), "capture_bytes": capture.stat().st_size,
                                   "message_count": None if split == "negative" else 2, "split": split,
                                   "grammar_family_id": None if split == "negative" else f"family-{name}",
                                   "capture_group_id": f"group-{name}"})
            truth.append({"case_id": name, "expected": wanted})
            case_root = self.run / f"case-{index:03d}"
            case_root.mkdir()
            output = case_root / "output"
            row = {"case_id": name, "split": split, "capture_sha256": hash_file(capture),
                   "command": build_extract_command(self.binary, capture, output, profile="normal", jobs=1),
                   "exit_code": code, "process_failure": failure, "process_error": None,
                   "metrics": {}, "progress": {}, "elapsed_seconds": 0.1}
            if failure is None:
                write_export(output, artifact_rows=[{"file": f"artifact-{i}.bin", "bytes": value, "provenance": []}
                                                    for i, value in enumerate(artifacts)])
                if name == "positive":
                    path = output / "manifest.json"
                    document = json.loads(path.read_text())
                    document["l2solver_result"] = {"job": {"recovery_transitions": {
                        "funnel_stages": [{"stage": "observed", "count": 1}],
                        "funnel_omission_reasons": {"memory_admission": 2}}}}
                    write_json(path, document)
                if code == 3:
                    path = output / "manifest.json"
                    document = json.loads(path.read_text())
                    document["export_status"] = "partial"
                    write_json(path, document)
                row["output"] = validate_export_output(output, exit_code=code)
            write_json(case_root / "case.json", row)
            rows.append(row)
        write_json(self.manifest, {"schema_version": 1, "corpus_id": "fabricated", "cases": manifest_cases})
        write_json(self.oracle, {"corpus_id": "fabricated", "cases": truth})
        write_json(self.ledger, {"schema_version": 1, "corpus_id": "fabricated", "cases": [
            {"case_id": "positive", "category": "supported"},
            {"case_id": "control", "category": "negative_control"},
            {"case_id": "unsupported", "category": "unsupported"},
            {"case_id": "partial-control", "category": "negative_control"},
        ]})
        self.receipt = self.run / "blind.json"
        self.blind = {"schema_version": 1, "source_commit": self.commit,
                      "binary_sha256": hash_file(self.binary), "binary_sha256_after": hash_file(self.binary),
                      "manifest_sha256": hash_file(self.manifest), "manifest_sha256_after": hash_file(self.manifest),
                      "private_oracle_read": False, "workers": 1, "cases": rows}
        write_json(self.receipt, self.blind)

    def identities(self, *, ledger=True):
        return FrozenIdentities(source_commit=self.commit, binary_sha256=hash_file(self.binary),
                                manifest_sha256=hash_file(self.manifest), run_sha256=hash_file(self.receipt),
                                oracle_sha256=hash_file(self.oracle),
                                ledger_sha256=hash_file(self.ledger) if ledger else None)

    def score(self, *, ledger=True, identities=None):
        return score_protocol_run(self.manifest, self.run, self.binary, self.oracle,
                                  identities or self.identities(ledger=ledger),
                                  ledger_path=self.ledger if ledger else None)

    def test_classifications_partial_and_runtime_limits_are_not_negative_controls(self):
        result = self.score()
        total = result["totals"]
        self.assertEqual(total["expected_artifacts"], 2)
        self.assertEqual(total["matched_artifacts"], 1)
        self.assertEqual(total["unassessed_expected_artifacts"], 1)
        self.assertEqual(total["negative_controls_total"], 2)
        self.assertEqual(total["negative_controls_assessed"], 1)
        self.assertEqual(total["negative_control_promotions"], 0)
        self.assertEqual(total["negative_control_partial_promotions_observed"], 1)
        self.assertEqual(total["unsupported_cases"], 1)
        self.assertEqual(total["unclassified_cases"], 1)
        self.assertEqual(total["partial_cases"], 1)
        self.assertEqual(total["unassessed_cases"], 2)
        by_id = {row["case_id"]: row for row in result["cases"]}
        self.assertEqual(by_id["control"]["outcome"], "assessed_negative")
        self.assertEqual(by_id["partial-control"]["outcome"], "unassessed_partial")
        self.assertEqual(by_id["timeout-positive"]["outcome"], "unassessed_runtime")
        self.assertIsNone(by_id["timeout-positive"]["matched_artifacts"])
        self.assertEqual(by_id["unsupported"]["category"], "unsupported")
        self.assertEqual(by_id["unknown"]["category"], "unclassified")
        positive = by_id["positive"]
        self.assertEqual(positive["funnel"]["funnel_stages"], [{"stage": "observed", "count": 1}])
        self.assertIsNone(positive["funnel"]["cohorts"])
        self.assertEqual(positive["output"]["artifacts"][0]["sha256"], digest(self.expected))
        self.assertEqual(positive["output"]["artifacts"][0]["byte_length"], len(self.expected))

    def test_legacy_empty_truth_is_unknown_without_explicit_classification(self):
        result = self.score(ledger=False)
        self.assertEqual(result["totals"]["negative_controls_total"], 0)
        self.assertEqual(result["totals"]["negative_controls_assessed"], 0)
        self.assertEqual(result["totals"]["unclassified_cases"], 4)
        self.assertEqual(result["totals"]["matched_artifacts"], 1)

    def test_incompatible_or_duplicate_categories_are_rejected(self):
        ledger = json.loads(self.ledger.read_text())
        ledger["cases"][0]["category"] = "negative_control"
        write_json(self.ledger, ledger)
        with self.assertRaisesRegex(ValueError, "categor"):
            self.score()
        ledger["cases"][0]["category"] = "supported"
        ledger["cases"].append(ledger["cases"][0])
        write_json(self.ledger, ledger)
        with self.assertRaisesRegex(ValueError, "categor|duplicate"):
            self.score()

    def test_changed_capture_binary_output_and_receipt_are_rejected(self):
        frozen = self.identities()
        self.binary.write_bytes(b"different binary")
        with self.assertRaisesRegex(ValueError, "binary"):
            self.score(identities=frozen)
        self.binary.write_bytes(b"frozen test binary")
        capture = self.public / "positive.pcap"
        capture.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "capture"):
            self.score(identities=frozen)
        capture.write_bytes(b"capture-positive")
        artifact = self.run / "case-000" / "output" / "artifact-0.bin"
        artifact.write_bytes(b"x" * len(self.expected))
        with self.assertRaisesRegex(ValueError, "output|artifact"):
            self.score(identities=frozen)
        artifact.write_bytes(self.expected)
        self.receipt.write_text(self.receipt.read_text() + " ")
        with self.assertRaisesRegex(ValueError, "run|receipt"):
            self.score(identities=frozen)

    def test_binary_and_blind_identity_are_checked_before_private_input(self):
        frozen = self.identities()
        self.binary.write_bytes(b"changed")
        self.oracle.unlink()
        with self.assertRaisesRegex(ValueError, "binary"):
            self.score(identities=frozen)

    def test_output_identity_is_checked_before_private_input(self):
        frozen = self.identities()
        artifact = self.run / "case-000" / "output" / "artifact-0.bin"
        artifact.write_bytes(b"x" * len(self.expected))
        self.oracle.unlink()
        with self.assertRaisesRegex(ValueError, "output|artifact"):
            self.score(identities=frozen)

    def test_oracle_and_ledger_must_match_their_frozen_hashes(self):
        frozen = self.identities()
        original = self.oracle.read_text()
        self.oracle.write_text(original + " ")
        with self.assertRaisesRegex(ValueError, "oracle"):
            self.score(identities=frozen)
        self.oracle.write_text(original)
        self.ledger.write_text(self.ledger.read_text() + " ")
        with self.assertRaisesRegex(ValueError, "ledger"):
            self.score(identities=frozen)

    def test_progress_failure_is_unassessed_and_never_a_true_negative(self):
        row = self.blind["cases"][1]
        row["progress_error"] = "progress log was unavailable"
        write_json(self.run / "case-001" / "case.json", row)
        write_json(self.receipt, self.blind)
        result = self.score()
        self.assertEqual(result["totals"]["negative_controls_assessed"], 0)
        control = next(case for case in result["cases"] if case["case_id"] == "control")
        self.assertEqual(control["outcome"], "unassessed_runtime")
        self.assertEqual(control["unassessed_reason"], "progress_unavailable")

    def test_complete_control_promotion_and_missing_output_are_distinct(self):
        root = self.run / "case-001" / "output"
        path = root / "manifest.json"
        manifest = json.loads(path.read_text())
        (root / "unexpected.bin").write_bytes(b"unexpected")
        manifest["artifacts"] = [{"file": "unexpected.bin", "byte_length": 10, "provenance": []}]
        write_json(path, manifest)
        row = self.blind["cases"][1]
        row["output"] = validate_export_output(root, exit_code=0)
        write_json(self.run / "case-001" / "case.json", row)
        write_json(self.receipt, self.blind)
        result = self.score()
        self.assertEqual(result["totals"]["negative_controls_assessed"], 1)
        self.assertEqual(result["totals"]["negative_control_promotions"], 1)
        self.assertEqual(result["cases"][1]["outcome"], "false_promotion")
        del row["output"]
        write_json(self.run / "case-001" / "case.json", row)
        write_json(self.receipt, self.blind)
        result = self.score()
        self.assertEqual(result["totals"]["negative_controls_assessed"], 0)
        self.assertEqual(result["cases"][1]["unassessed_reason"], "output_missing")

    def test_failed_process_with_exit_three_is_not_counted_as_validated_partial(self):
        row = self.blind["cases"][5]
        row["exit_code"] = 3
        write_json(self.run / "case-005" / "case.json", row)
        write_json(self.receipt, self.blind)
        result = self.score()
        self.assertEqual(result["totals"]["partial_cases"], 1)
        self.assertEqual(result["cases"][5]["outcome"], "unassessed_runtime")

    def test_expected_reference_bytes_must_match_the_oracle(self):
        frozen = self.identities()
        (self.private / "expected.bin").write_bytes(b"x" * len(self.expected))
        with self.assertRaisesRegex(ValueError, "oracle artifact"):
            self.score(identities=frozen)

    def test_cli_writes_once_without_overwriting_scored_evidence(self):
        frozen = self.identities()
        output = self.root / "scored.json"
        arguments = ["--manifest", str(self.manifest), "--run-root", str(self.run),
                     "--binary", str(self.binary), "--oracle", str(self.oracle),
                     "--source-commit", frozen.source_commit, "--binary-sha256", frozen.binary_sha256,
                     "--manifest-sha256", frozen.manifest_sha256, "--run-sha256", frozen.run_sha256,
                     "--oracle-sha256", frozen.oracle_sha256, "--ledger", str(self.ledger),
                     "--ledger-sha256", frozen.ledger_sha256, "--output", str(output)]
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(main(arguments), 0)
            before = output.read_bytes()
            self.assertEqual(main(arguments), 1)
        self.assertEqual(output.read_bytes(), before)
        self.assertEqual(json.loads(before)["totals"]["negative_controls_assessed"], 1)


if __name__ == "__main__":
    unittest.main()
