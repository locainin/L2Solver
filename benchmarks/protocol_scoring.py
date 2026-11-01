"""Score frozen blind runs against an independently supplied private oracle."""

import argparse
import json
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from .protocol_evaluation import load_blind_manifest
from .runner.catalogue import hash_file, read_json
from .runner.protocol_truth import compare_protocol_artifacts, load_protocol_truth
from .runner.recovery import build_extract_command, validate_export_output

MAX_RECEIPT_BYTES = 64 * 1024 * 1024
MAX_OUTPUT_BYTES = 256 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


@dataclass(frozen=True)
class FrozenIdentities:
    source_commit: str
    binary_sha256: str
    manifest_sha256: str
    run_sha256: str
    oracle_sha256: str
    ledger_sha256: str | None = None

    def __post_init__(self):
        if not isinstance(self.source_commit, str) or COMMIT.fullmatch(self.source_commit) is None:
            raise ValueError("source commit must be a full Git object ID")
        for digest in (self.binary_sha256, self.manifest_sha256, self.run_sha256, self.oracle_sha256):
            if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
                raise ValueError("frozen SHA-256 identity is invalid")
        if self.ledger_sha256 is not None and (not isinstance(self.ledger_sha256, str)
                                               or SHA256.fullmatch(self.ledger_sha256) is None):
            raise ValueError("classification ledger identity is invalid")


def _verify_file(path, expected, name):
    path = Path(path)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"{name} is unavailable") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{name} is not a regular file")
    if hash_file(path, expected_bytes=metadata.st_size) != expected:
        raise ValueError(f"{name} identity changed")


def _check_run(receipt, manifest, binary, run_root, identities):
    if (not isinstance(receipt, dict) or type(receipt.get("schema_version")) is not int
            or receipt["schema_version"] != 1 or receipt.get("private_oracle_read") is not False
            or type(receipt.get("workers")) is not int or receipt["workers"] != 1
            or receipt.get("source_commit") != identities.source_commit
            or receipt.get("binary_sha256") != identities.binary_sha256
            or receipt.get("binary_sha256_after") != identities.binary_sha256
            or receipt.get("manifest_sha256") != identities.manifest_sha256
            or receipt.get("manifest_sha256_after") != identities.manifest_sha256):
        raise ValueError("run receipt differs from the frozen identities")
    rows = receipt.get("cases")
    if not isinstance(rows, list) or len(rows) != len(manifest.cases):
        raise ValueError("run receipt does not cover the public manifest")
    for index, (case, row) in enumerate(zip(manifest.cases, rows, strict=True)):
        case_root = run_root / f"case-{index:03d}"
        if (not isinstance(row, dict) or row.get("case_id") != case.case_id
                or row.get("split") != case.split or row.get("capture_sha256") != case.capture_sha256
                or "exit_code" not in row or "process_failure" not in row):
            raise ValueError("run case identity differs from the public manifest")
        expected = build_extract_command(binary, case.capture, case_root / "output", profile="normal", jobs=1)
        if row.get("command") != expected:
            raise ValueError("run case command differs from the frozen workload")
        if not case_root.is_dir() or case_root.is_symlink():
            raise ValueError("run case directory is missing or linked")
        case_receipt = case_root / "case.json"
        if case_receipt.is_symlink() or read_json(case_receipt, MAX_RECEIPT_BYTES) != row:
            raise ValueError("individual case receipt differs from the frozen run")
        if row.get("output") is not None:
            _validated_output(case_root / "output", row)
    return rows


def _counts():
    return {"expected_artifacts": 0, "matched_artifacts": 0, "unassessed_expected_artifacts": 0,
            "negative_controls_total": 0,
            "negative_controls_assessed": 0, "negative_control_promotions": 0,
            "negative_control_partial_promotions_observed": 0, "unsupported_cases": 0,
            "unclassified_cases": 0, "partial_cases": 0, "unassessed_cases": 0}


def _unavailable(row):
    if row.get("process_failure") is not None:
        return "process_failure"
    if "progress_error" in row:
        return "progress_unavailable"
    if "output_error" in row:
        return "output_invalid"
    if row.get("exit_code") not in (0, 3):
        return "unexpected_exit"
    if not isinstance(row.get("output"), dict):
        return "output_missing"
    return None


def _funnel(output_directory):
    manifest = read_json(output_directory / "manifest.json", MAX_RECEIPT_BYTES)
    result = manifest.get("l2solver_result") if isinstance(manifest, dict) else None
    job = result.get("job") if isinstance(result, dict) else None
    transitions = job.get("recovery_transitions") if isinstance(job, dict) else None
    transitions = transitions if isinstance(transitions, dict) else {}
    return {name: transitions.get(name) for name in ("funnel_stages", "cohorts", "funnel_omission_reasons")}


def _validated_output(output_directory, row):
    if (not isinstance(row.get("output"), dict) or type(row.get("exit_code")) is not int
            or row["exit_code"] not in (0, 3) or row.get("process_failure") is not None):
        raise ValueError("run claims an invalid output receipt")
    try:
        output = validate_export_output(output_directory, exit_code=row["exit_code"], max_output_bytes=MAX_OUTPUT_BYTES)
    except (OSError, ValueError, TypeError) as error:
        raise ValueError("previously validated output is missing or invalid") from error
    if output != row["output"]:
        raise ValueError("output bytes or validated receipt changed after the run")
    return output


def _score_case(case, row, index, run_root, truth):
    category, expected = truth["category"], truth["expected"]
    details = {"case_id": case.case_id, "split": case.split, "category": category,
               "expected_artifacts": len(expected), "matched_artifacts": None,
               "artifact_count": None, "outcome": "unassessed_runtime",
               "unassessed_reason": _unavailable(row), "exit_code": row.get("exit_code"),
               "elapsed_seconds": row.get("elapsed_seconds"), "metrics": row.get("metrics"),
               "progress": row.get("progress"), "funnel": None, "output": None}
    if details["unassessed_reason"] is not None:
        return details
    output_directory = run_root / f"case-{index:03d}" / "output"
    output = _validated_output(output_directory, row)
    details["output"] = output
    details["artifact_count"] = output["artifact_count"]
    details["funnel"] = _funnel(output_directory)
    details["matched_artifacts"] = compare_protocol_artifacts(output_directory, output, expected)
    if row["exit_code"] == 3:
        details["outcome"] = "unassessed_partial"
        details["unassessed_reason"] = "partial_output"
    elif category == "negative_control":
        details["outcome"] = "assessed_negative" if not output["artifact_count"] else "false_promotion"
    elif category == "supported":
        details["outcome"] = "assessed_supported"
    else:
        details["outcome"] = category
    return details


def _add(counts, details):
    category, outcome = details["category"], details["outcome"]
    counts["expected_artifacts"] += details["expected_artifacts"]
    if details["matched_artifacts"] is not None:
        counts["matched_artifacts"] += details["matched_artifacts"]
    if outcome in ("unassessed_runtime", "unassessed_partial"):
        counts["unassessed_expected_artifacts"] += details["expected_artifacts"]
    counts["negative_controls_total"] += category == "negative_control"
    counts["unsupported_cases"] += category == "unsupported"
    counts["unclassified_cases"] += category == "unclassified"
    counts["partial_cases"] += outcome == "unassessed_partial"
    counts["unassessed_cases"] += outcome in ("unassessed_runtime", "unassessed_partial")
    if category == "negative_control" and outcome in ("assessed_negative", "false_promotion"):
        counts["negative_controls_assessed"] += 1
        counts["negative_control_promotions"] += details["artifact_count"]
    if category == "negative_control" and outcome == "unassessed_partial":
        counts["negative_control_partial_promotions_observed"] += details["artifact_count"]


def score_protocol_run(manifest_path, run_root, binary, oracle_path, identities, *, ledger_path=None):
    manifest_path, run_root, binary, oracle_path = map(Path, (manifest_path, run_root, binary, oracle_path))
    if not isinstance(identities, FrozenIdentities):
        raise TypeError("frozen identities are required")
    if (ledger_path is None) != (identities.ledger_sha256 is None):
        raise ValueError("classification ledger and its frozen hash must be supplied together")
    ledger_path = Path(ledger_path) if ledger_path is not None else None
    _verify_file(binary, identities.binary_sha256, "binary")
    _verify_file(manifest_path, identities.manifest_sha256, "public manifest")
    if run_root.is_symlink() or not run_root.is_dir():
        raise ValueError("run root must be a real directory")
    run_root, binary, manifest_path = run_root.resolve(), binary.resolve(), manifest_path.resolve()
    receipt_path = run_root / "blind.json"
    _verify_file(receipt_path, identities.run_sha256, "run receipt")
    manifest = load_blind_manifest(manifest_path)
    receipt = read_json(receipt_path, MAX_RECEIPT_BYTES)
    rows = _check_run(receipt, manifest, binary, run_root, identities)

    # Private inputs are opened only after the frozen public run is checked
    _verify_file(oracle_path, identities.oracle_sha256, "private oracle")
    if ledger_path is not None:
        _verify_file(ledger_path, identities.ledger_sha256, "classification ledger")
    truth = load_protocol_truth(oracle_path, ledger_path, manifest)
    totals, splits, cases = _counts(), {}, []
    for index, (case, row) in enumerate(zip(manifest.cases, rows, strict=True)):
        details = _score_case(case, row, index, run_root, truth[case.case_id])
        _add(totals, details)
        _add(splits.setdefault(case.split, _counts()), details)
        cases.append(details)

    # Recheck frozen inputs and each capture before reporting any result
    for path, digest, name in ((binary, identities.binary_sha256, "binary"),
                               (manifest_path, identities.manifest_sha256, "public manifest"),
                               (receipt_path, identities.run_sha256, "run receipt"),
                               (oracle_path, identities.oracle_sha256, "private oracle")):
        _verify_file(path, digest, name)
    if ledger_path is not None:
        _verify_file(ledger_path, identities.ledger_sha256, "classification ledger")
    load_blind_manifest(manifest_path)
    for row in truth.values():
        for artifact in row["expected"]:
            if hash_file(artifact["path"], expected_bytes=artifact["byte_length"]) != artifact["sha256"]:
                raise ValueError("oracle artifact changed during scoring")
    return {"schema_version": 1, "corpus_id": manifest.corpus_id,
            "identities": {"source_commit": identities.source_commit, "binary_sha256": identities.binary_sha256,
                           "manifest_sha256": identities.manifest_sha256, "run_sha256": identities.run_sha256,
                           "oracle_sha256": identities.oracle_sha256, "ledger_sha256": identities.ledger_sha256},
            "totals": totals, "splits": splits, "cases": cases,
            "limitations": ["Empty oracle entries without reviewed classification are unclassified",
                            "Partial and runtime-limited results do not establish complete negatives",
                            "Frozen hashes do not themselves prove when the inputs were frozen",
                            "Artifact matches do not measure segmentation precision or generalization"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("manifest", "run-root", "binary", "oracle", "source-commit", "binary-sha256",
                 "manifest-sha256", "run-sha256", "oracle-sha256", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--ledger")
    parser.add_argument("--ledger-sha256")
    args = parser.parse_args(argv)
    try:
        identities = FrozenIdentities(args.source_commit, args.binary_sha256, args.manifest_sha256,
                                      args.run_sha256, args.oracle_sha256, args.ledger_sha256)
        result = score_protocol_run(args.manifest, args.run_root, args.binary, args.oracle, identities,
                                    ledger_path=args.ledger)
        with Path(args.output).open("x", encoding="utf-8") as target:
            json.dump(result, target, indent=2, sort_keys=True)
            target.write("\n")
        print(json.dumps(result["totals"], sort_keys=True))
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"protocol scoring failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
