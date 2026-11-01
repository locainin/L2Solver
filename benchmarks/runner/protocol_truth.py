"""Interpret reviewed protocol truth without inferring empty-list controls."""

import re
from pathlib import Path

from .catalogue import hash_file, local_file, read_json
from .recovery_acceptance import compare_recovery_artifacts

MAX_TRUTH_BYTES = 16 * 1024 * 1024
MAX_EXPECTED = 4096
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
CATEGORIES = {"supported", "negative_control", "unsupported"}


def _classifications(path, manifest):
    if path is None:
        return {}
    ledger = read_json(path, MAX_TRUTH_BYTES)
    if (not isinstance(ledger, dict) or set(ledger) != {"schema_version", "corpus_id", "cases"}
            or type(ledger["schema_version"]) is not int or ledger["schema_version"] != 1
            or ledger["corpus_id"] != manifest.corpus_id or not isinstance(ledger["cases"], list)):
        raise ValueError("classification ledger schema or corpus is invalid")
    known = {case.case_id for case in manifest.cases}
    classifications = {}
    for row in ledger["cases"]:
        if (not isinstance(row, dict) or set(row) != {"case_id", "category"}
                or row["case_id"] not in known or row["case_id"] in classifications
                or row["category"] not in CATEGORIES):
            raise ValueError("invalid or duplicate classification category")
        classifications[row["case_id"]] = row["category"]
    return classifications


def _expected_files(root, values):
    if not isinstance(values, list) or len(values) > MAX_EXPECTED:
        raise ValueError("invalid oracle expected-artifact list")
    result, seen = [], set()
    for value in values:
        if not isinstance(value, dict) or not {"file", "sha256", "bytes"}.issubset(value):
            raise ValueError("invalid oracle artifact")
        length, digest = value["bytes"], value["sha256"]
        if (type(length) is not int or not 0 <= length <= MAX_ARTIFACT_BYTES
                or not isinstance(digest, str) or DIGEST.fullmatch(digest) is None
                or (digest, length) in seen):
            raise ValueError("invalid or duplicate oracle artifact identity")
        path = local_file(root, value["file"])
        if hash_file(path, expected_bytes=length) != digest:
            raise ValueError("oracle artifact bytes do not match its identity")
        seen.add((digest, length))
        result.append({"path": path, "sha256": digest, "byte_length": length})
    return result


def load_protocol_truth(oracle_path, ledger_path, manifest):
    oracle = read_json(oracle_path, MAX_TRUTH_BYTES)
    if (not isinstance(oracle, dict) or oracle.get("corpus_id") != manifest.corpus_id
            or not isinstance(oracle.get("cases"), list)):
        raise ValueError("oracle corpus or case list is invalid")
    known = {case.case_id: case for case in manifest.cases}
    rows = {}
    for row in oracle["cases"]:
        if (not isinstance(row, dict) or row.get("case_id") not in known
                or row["case_id"] in rows or "expected" not in row):
            raise ValueError("oracle has an unknown, duplicate, or invalid case")
        rows[row["case_id"]] = row
    if set(rows) != set(known):
        raise ValueError("oracle does not cover the public case list")
    classifications = _classifications(ledger_path, manifest)
    result = {}
    for case_id, case in known.items():
        expected = _expected_files(Path(oracle_path).parent, rows[case_id]["expected"])
        category = classifications.get(case_id, "supported" if expected else "unclassified")
        if ((category == "supported") != bool(expected)
                or (category == "negative_control" and case.split != "negative")):
            raise ValueError("classification category conflicts with oracle or public split")
        result[case_id] = {"category": category, "expected": expected}
    return result


def _same_bytes(first, second):
    with first.open("rb") as left, second.open("rb") as right:
        while True:
            part = left.read(1024 * 1024)
            if part != right.read(len(part) if part else 1):
                return False
            if not part:
                return True


def compare_protocol_artifacts(output_directory, output, expected):
    if not expected:
        return 0
    oracle = {"schema_version": 1, "artifacts": [
        {"sha256": item["sha256"], "byte_length": item["byte_length"], "members": []}
        for item in expected]}
    acceptance = compare_recovery_artifacts({"output": output}, oracle)
    matched = 0
    for item in expected:
        matches = [artifact for artifact in output["artifacts"]
                   if artifact["sha256"] == item["sha256"] and artifact["byte_length"] == item["byte_length"]]
        if any(_same_bytes(item["path"], output_directory / artifact["file"]) for artifact in matches):
            matched += 1
    if matched != acceptance["counts"]["matched_artifacts"]:
        raise ValueError("artifact digest matches differ from exact bytes")
    return matched
