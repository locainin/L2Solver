"""Blind evaluation manifests keep protocol families and capture groups split."""

import hashlib
import json

import pytest

from benchmarks.protocol_evaluation import BlindEvaluationLimits, load_blind_manifest


def _write_capture(root, name, payload):
    path = root / "captures" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return {
        "capture_file": f"captures/{name}",
        "capture_sha256": hashlib.sha256(payload).hexdigest(),
        "capture_bytes": len(payload),
    }


def _case(root, case_id, split, family_id, group_id, payload=b"capture"):
    return {
        "case_id": case_id,
        **_write_capture(root, f"{case_id}.pcap", payload),
        "message_count": None if split == "negative" else 1,
        "split": split,
        "grammar_family_id": family_id,
        "capture_group_id": group_id,
    }


def _manifest(root, cases):
    path = root / "manifest.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "corpus_id": "sealed-test-corpus-v1",
                "cases": cases,
            }
        ),
        encoding="utf-8",
    )
    return path


def test_blind_manifest_loads_hash_checked_cases_without_oracle_fields(tmp_path):
    cases = [
        _case(tmp_path, "dev-a", "development", "family-a", "group-a"),
        _case(tmp_path, "heldout-b", "heldout", "family-b", "group-b"),
        _case(tmp_path, "negative-a", "negative", None, "negative-group"),
    ]
    manifest_path = _manifest(tmp_path, cases)

    manifest = load_blind_manifest(manifest_path, split="heldout")

    assert manifest.corpus_id == "sealed-test-corpus-v1"
    assert len(manifest.cases) == 1
    case = manifest.cases[0]
    assert case.case_id == "heldout-b"
    assert case.capture.read_bytes() == b"capture"
    assert case.capture_sha256 == hashlib.sha256(b"capture").hexdigest()
    assert case.message_count == 1
    assert not hasattr(case, "expected_output")
    assert not hasattr(case, "grammar_family_id")
    assert not hasattr(case, "capture_group_id")
    assert not hasattr(manifest, "oracle")


@pytest.mark.parametrize(
    "changes",
    [
        {"grammar_family_id": "family-shared"},
        {"capture_group_id": "group-shared"},
    ],
)
def test_blind_manifest_rejects_family_or_capture_group_crossing_splits(
    tmp_path, changes
):
    first = _case(
        tmp_path,
        "first",
        "development",
        changes.get("grammar_family_id", "family-a"),
        changes.get("capture_group_id", "group-a"),
    )
    second = _case(tmp_path, "second", "heldout", "family-b", "group-b")
    second.update(changes)
    _manifest(tmp_path, [first, second])

    with pytest.raises(ValueError, match="crosses splits"):
        load_blind_manifest(tmp_path / "manifest.json")


def test_blind_manifest_requires_family_ids_only_for_protocol_cases(tmp_path):
    positive = _case(tmp_path, "positive", "development", None, "group-a")
    _manifest(tmp_path, [positive])

    with pytest.raises(ValueError, match="grammar family"):
        load_blind_manifest(tmp_path / "manifest.json")

    negative = _case(tmp_path, "negative", "negative", "family-a", "group-b")
    _manifest(tmp_path, [negative])
    with pytest.raises(ValueError, match="negative controls cannot name a grammar"):
        load_blind_manifest(tmp_path / "manifest.json")


def test_blind_manifest_does_not_assign_message_counts_to_negative_controls(tmp_path):
    negative = _case(tmp_path, "negative", "negative", None, "group-a")
    manifest_path = _manifest(tmp_path, [negative])

    manifest = load_blind_manifest(manifest_path)

    assert manifest.cases[0].message_count is None
    negative["message_count"] = 1
    _manifest(tmp_path, [negative])
    with pytest.raises(ValueError, match="negative controls must not claim a message count"):
        load_blind_manifest(manifest_path)


def test_blind_manifest_rejects_duplicate_case_ids_and_unknown_fields(tmp_path):
    first = _case(tmp_path, "same", "development", "family-a", "group-a")
    second = _case(tmp_path, "same", "development", "family-a", "group-b")
    _manifest(tmp_path, [first, second])
    with pytest.raises(ValueError, match="duplicate case"):
        load_blind_manifest(tmp_path / "manifest.json")

    first["expected_sha256"] = hashlib.sha256(b"secret").hexdigest()
    _manifest(tmp_path, [first])
    with pytest.raises(ValueError, match="unsupported case fields"):
        load_blind_manifest(tmp_path / "manifest.json")


def test_blind_manifest_rejects_capture_digest_mismatch(tmp_path):
    case = _case(tmp_path, "sample", "development", "family-a", "group-a")
    (tmp_path / case["capture_file"]).write_bytes(b"changed")
    _manifest(tmp_path, [case])

    with pytest.raises(ValueError, match="capture hash"):
        load_blind_manifest(tmp_path / "manifest.json")


def test_blind_manifest_verifies_captures_outside_the_selected_split(tmp_path):
    development = _case(tmp_path, "development", "development", "family-a", "group-a")
    heldout = _case(tmp_path, "heldout", "heldout", "family-b", "group-b")
    manifest_path = _manifest(tmp_path, [development, heldout])
    (tmp_path / development["capture_file"]).write_bytes(b"changed")

    with pytest.raises(ValueError, match="capture hash"):
        load_blind_manifest(manifest_path, split="heldout")


def test_blind_manifest_rejects_paths_outside_its_root(tmp_path):
    case = _case(tmp_path, "sample", "development", "family-a", "group-a")
    case["capture_file"] = "../outside.pcap"
    _manifest(tmp_path, [case])

    with pytest.raises(ValueError, match="relative"):
        load_blind_manifest(tmp_path / "manifest.json")


def test_blind_manifest_enforces_per_capture_and_aggregate_byte_limits(tmp_path):
    first = _case(tmp_path, "first", "development", "family-a", "group-a", b"1234567")
    second = _case(tmp_path, "second", "development", "family-a", "group-a", b"7654321")
    manifest_path = _manifest(tmp_path, [first, second])

    with pytest.raises(ValueError, match="oversized capture_bytes"):
        load_blind_manifest(
            manifest_path,
            limits=BlindEvaluationLimits(max_capture_bytes=6, max_input_bytes=20),
        )
    with pytest.raises(ValueError, match="aggregate capture bytes"):
        load_blind_manifest(
            manifest_path,
            limits=BlindEvaluationLimits(max_capture_bytes=10, max_input_bytes=13),
        )
