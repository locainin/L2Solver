"""The challenge matrix binds runs to recorded inputs and never starts work."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

import benchmarks.memory_qualification as qualification
from tests.benchmarks.recovery_support import oracle_artifact, provenance, write_export
from tests.benchmarks.runner.test_memory_qualification import make_challenge_trial


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sample_artifacts():
    archive = b"synthetic archive"
    members = [("first.txt", b"first member"), ("second.bin", b"second member")]
    rows = [{"file": "archive.zip", "bytes": archive, "provenance": [provenance("case-1", 1, "record_candidate")]}]
    rows.extend(
        {"file": f"artifact-{index}", "bytes": data,
         "provenance": [provenance("case-1", index, "archive_member", archive_node=1, utf8_name=name)]}
        for index, (name, data) in enumerate(members, start=2)
    )
    return rows, oracle_artifact(archive, members)


def test_prepare_help_describes_the_required_reference_schema():
    result = subprocess.run(
        [sys.executable, "-m", "benchmarks.memory_qualification", "prepare", "--help"],
        check=True, capture_output=True, text=True,
    )
    for field in ("schema_version=2", "capture=", "sha256", "byte_length", "expected_cases", "artifacts="):
        assert field in result.stdout


@pytest.fixture
def matrix_inputs(tmp_path, monkeypatch):
    source = tmp_path / "source"
    (source / "fuzz").mkdir(parents=True)
    (source / "Cargo.lock").write_bytes(b"workspace lock")
    (source / "fuzz" / "Cargo.lock").write_bytes(b"fuzz lock")
    binary = tmp_path / "l2solver"
    binary.write_bytes(b"candidate executable")
    binary.chmod(0o700)
    capture = tmp_path / "challenge.pcap"
    capture.write_bytes(b"challenge bytes")
    monkeypatch.setattr(qualification, "_git_state", lambda _root: ("a" * 40, False))
    rows, artifact_oracle = sample_artifacts()
    artifacts = [{"sha256": digest(row["bytes"]), "byte_length": len(row["bytes"])} for row in rows]
    reference = tmp_path / "reference.json"
    reference.write_text(json.dumps({
        "schema_version": 2,
        "capture": {"sha256": digest(capture.read_bytes()), "byte_length": capture.stat().st_size},
        "expected_cases": 3,
        "artifacts": artifacts,
    }))
    oracle = tmp_path / "oracle.json"
    oracle.write_text(json.dumps({"schema_version": 1, "artifacts": [artifact_oracle]}))
    package = tmp_path / "package.json"
    package.write_text(json.dumps({
        "schema_version": 1,
        "identity": {
            "source_commit": "a" * 40,
            "lock_sha256": digest(b"workspace lock"),
            "fuzz_lock_sha256": digest(b"fuzz lock"),
        },
        "candidate_checks": {"package": {"status": "passed", "binary_sha256": digest(binary.read_bytes())}},
    }))
    return {
        "directory": tmp_path / "matrix", "source_root": source, "binary": binary,
        "capture": capture, "oracle": oracle, "reference": reference, "package_receipt": package,
        "cpu_quota_percent": 200,
        "max_log_bytes": 16 * 1024 * 1024,
    }


def test_preparation_produces_six_scoped_commands_without_running_them(matrix_inputs):
    plan = qualification.prepare_matrix(**matrix_inputs, timeout=180)
    scenarios = plan["scenarios"]
    assert set(scenarios) == {
        f"challenge-{profile}-jobs-{jobs}"
        for profile in ("normal", "deep") for jobs in (1, 2, 4)
    }
    for name, scenario in scenarios.items():
        assert scenario["command"][0] == str(matrix_inputs["binary"].resolve())
        assert "--no-cache" in scenario["command"]
        assert scenario["scope_command"][0:2] == ["systemd-run", "--user"]
        assert "CPUQuota=200%" in scenario["scope_command"]
        assert scenario["scope_command"][scenario["scope_command"].index("--max-log-bytes") + 1] == str(matrix_inputs["max_log_bytes"])
        assert scenario["scope_command"][-len(scenario["command"]):] == scenario["command"]
        assert not (matrix_inputs["directory"] / name / "cgroup.json").exists()


def test_unrun_matrix_is_blocked_and_never_claims_gate_completion(matrix_inputs):
    qualification.prepare_matrix(**matrix_inputs, timeout=180)
    result = qualification.collect_matrix(matrix_inputs["directory"])
    assert result["status"] == "blocked"
    assert all(scenario["status"] == "blocked" for scenario in result["scenarios"].values())
    assert result["memory_gate"] == "incomplete"


def test_modified_binary_after_preparation_invalidates_matrix(matrix_inputs):
    qualification.prepare_matrix(**matrix_inputs, timeout=180)
    matrix_inputs["binary"].write_bytes(b"different executable")
    result = qualification.collect_matrix(matrix_inputs["directory"])
    assert result["status"] == "failed"
    assert "identity" in result["failures"]


def test_modified_capture_after_preparation_invalidates_matrix(matrix_inputs):
    qualification.prepare_matrix(**matrix_inputs, timeout=180)
    capture = matrix_inputs["capture"]
    capture.write_bytes(b"x" * capture.stat().st_size)
    result = qualification.collect_matrix(matrix_inputs["directory"])
    assert result["status"] == "failed"
    assert "identity" in result["failures"]


def test_recorded_command_cannot_claim_another_workload(matrix_inputs):
    qualification.prepare_matrix(**matrix_inputs, timeout=180)
    scenario = matrix_inputs["directory"] / "challenge-normal-jobs-1"
    (scenario / "cgroup.json").write_text(json.dumps({"command": ["different-binary"]}))
    result = qualification.collect_matrix(matrix_inputs["directory"])
    assert result["scenarios"][scenario.name]["status"] == "failed"
    assert "command" in result["scenarios"][scenario.name]["failures"]


def test_preparation_rejects_a_package_for_another_binary(matrix_inputs):
    package = matrix_inputs["package_receipt"]
    receipt = json.loads(package.read_text())
    receipt["candidate_checks"]["package"]["binary_sha256"] = "0" * 64
    package.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="package"):
        qualification.prepare_matrix(**matrix_inputs, timeout=180)
    assert not matrix_inputs["directory"].exists()


@pytest.mark.parametrize("field", ["source_commit", "lock_sha256", "fuzz_lock_sha256"])
def test_preparation_rejects_package_for_different_source_or_locks(matrix_inputs, field):
    package = matrix_inputs["package_receipt"]
    receipt = json.loads(package.read_text())
    receipt["identity"][field] = "f" * len(receipt["identity"][field])
    package.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="package identity"):
        qualification.prepare_matrix(**matrix_inputs, timeout=180)
    assert not matrix_inputs["directory"].exists()


def test_preparation_rejects_a_dirty_source_tree(matrix_inputs, monkeypatch):
    monkeypatch.setattr(qualification, "_git_state", lambda _root: ("a" * 40, True))
    with pytest.raises(ValueError, match="source tree is not clean"):
        qualification.prepare_matrix(**matrix_inputs, timeout=180)
    assert not matrix_inputs["directory"].exists()


def test_preparation_rejects_artifact_references_beyond_the_validator_budget(matrix_inputs):
    reference = matrix_inputs["reference"]
    value = json.loads(reference.read_text())
    value["artifacts"][0]["byte_length"] = 1 << 40
    reference.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="artifact identities"):
        qualification.prepare_matrix(**matrix_inputs, timeout=180)


def test_preparation_rejects_artifact_references_above_the_count_limit(matrix_inputs):
    reference = matrix_inputs["reference"]
    document = json.loads(reference.read_text())
    document["artifacts"] *= 2000
    reference.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="artifact identities"):
        qualification.prepare_matrix(**matrix_inputs, timeout=180)
    assert not matrix_inputs["directory"].exists()


@pytest.mark.parametrize("field,value", [
    ("sha256", "0" * 64), ("sha256", "not-a-hash"),
    ("byte_length", 1), ("byte_length", True), ("byte_length", 0),
])
def test_preparation_rejects_invalid_or_mismatched_capture_identity(matrix_inputs, field, value):
    reference = matrix_inputs["reference"]
    document = json.loads(reference.read_text())
    document["capture"][field] = value
    reference.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="capture"):
        qualification.prepare_matrix(**matrix_inputs, timeout=180)
    assert not matrix_inputs["directory"].exists()


def test_preparation_rejects_a_reference_without_capture_or_case_expectations(matrix_inputs):
    reference = matrix_inputs["reference"]
    document = json.loads(reference.read_text())
    reference.write_text(json.dumps({"schema_version": 1, "artifacts": document["artifacts"]}))
    with pytest.raises(ValueError, match="reference"):
        qualification.prepare_matrix(**matrix_inputs, timeout=180)
    assert not matrix_inputs["directory"].exists()


@pytest.mark.parametrize("value", [None, True, 0, -1, 1.5])
def test_preparation_requires_a_positive_integer_case_count(matrix_inputs, value):
    reference = matrix_inputs["reference"]
    document = json.loads(reference.read_text())
    document["expected_cases"] = value
    reference.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="case"):
        qualification.prepare_matrix(**matrix_inputs, timeout=180)
    assert not matrix_inputs["directory"].exists()


@pytest.mark.parametrize("part", ["artifact", "member"])
def test_preparation_rejects_oracle_items_missing_from_reference(matrix_inputs, part):
    reference = matrix_inputs["reference"]
    document = json.loads(reference.read_text())
    del document["artifacts"][0 if part == "artifact" else 1]
    reference.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="oracle"):
        qualification.prepare_matrix(**matrix_inputs, timeout=180)
    assert not matrix_inputs["directory"].exists()


def test_changing_reference_after_preparation_invalidates_matrix(matrix_inputs):
    qualification.prepare_matrix(**matrix_inputs, timeout=180)
    reference = matrix_inputs["reference"]
    document = json.loads(reference.read_text())
    document["expected_cases"] = 2
    reference.write_text(json.dumps(document))
    result = qualification.collect_matrix(matrix_inputs["directory"])
    assert result["status"] == "failed"
    assert "identity" in result["failures"]


def test_changing_oracle_after_preparation_invalidates_matrix(matrix_inputs):
    qualification.prepare_matrix(**matrix_inputs, timeout=180)
    oracle = matrix_inputs["oracle"]
    document = json.loads(oracle.read_text())
    document["artifacts"][0]["members"].pop()
    oracle.write_text(json.dumps(document))
    result = qualification.collect_matrix(matrix_inputs["directory"])
    assert result["status"] == "failed"
    assert "identity" in result["failures"]


@pytest.mark.parametrize("input_name", ["reference", "oracle", "package_receipt"])
def test_preparation_rejects_an_expectation_file_changed_while_reading(matrix_inputs, monkeypatch, input_name):
    from benchmarks.runner.catalogue import read_json_bytes

    target = matrix_inputs[input_name]

    def change_after_read(path, maximum):
        raw = read_json_bytes(path, maximum)
        if path == target:
            document = json.loads(raw)
            if input_name == "reference":
                document["expected_cases"] = 4
            elif input_name == "oracle":
                document["artifacts"][0]["members"][0]["member_name"] = "other.txt"
            else:
                document["identity"]["source_commit"] = "b" * 40
            target.write_text(json.dumps(document))
        return raw

    monkeypatch.setattr(qualification, "read_json_bytes", change_after_read, raising=False)
    with pytest.raises(ValueError, match="changed"):
        qualification.prepare_matrix(**matrix_inputs, timeout=180)
    assert not matrix_inputs["directory"].exists()


def test_preparation_rejects_an_input_replaced_with_a_directory(matrix_inputs, monkeypatch):
    from benchmarks.runner.catalogue import read_json_bytes

    target = matrix_inputs["reference"]

    def replace_after_read(path, maximum):
        raw = read_json_bytes(path, maximum)
        if path == target:
            target.unlink()
            target.mkdir()
        return raw

    monkeypatch.setattr(qualification, "read_json_bytes", replace_after_read, raising=False)
    with pytest.raises(ValueError, match="regular file"):
        qualification.prepare_matrix(**matrix_inputs, timeout=180)
    assert not matrix_inputs["directory"].exists()


def test_preparation_never_reuses_or_cleans_an_existing_directory(matrix_inputs):
    matrix_inputs["directory"].mkdir()
    marker = matrix_inputs["directory"] / "keep"
    marker.write_text("unchanged")
    with pytest.raises(FileExistsError):
        qualification.prepare_matrix(**matrix_inputs, timeout=180)
    assert marker.read_text() == "unchanged"


def test_cpu_scope_limit_is_observed_separately_from_the_request():
    hierarchy = {
        "limits_complete": False,
        "effective_visible_quota": {"quota_us": 100000, "period_us": 100000},
        "limits": [
            {"path": "/slice/run-owned.scope/workload", "quota_us": None, "period_us": None},
            {"path": "/slice/run-owned.scope", "quota_us": 200000, "period_us": 100000},
            {"path": "/slice", "quota_us": 100000, "period_us": 100000},
            {"path": "/", "quota_us": None, "period_us": None},
        ],
    }
    receipt = {"cgroup": {"hierarchy": {"limits": [{"path": hierarchy["limits"][0]["path"]}]},
                           "cpu_hierarchy": hierarchy, "cpu_hierarchy_after": hierarchy}}
    assert qualification._cpu_scope_status(receipt, 200) == "observed"
    hierarchy["limits"][1]["quota_us"] = 100000
    assert qualification._cpu_scope_status(receipt, 200) == "failed"


def test_missing_cpu_scope_observation_is_blocked():
    assert qualification._cpu_scope_status({"cgroup": {}}, 200) == "blocked"


def test_cpu_observation_from_a_different_cgroup_is_rejected():
    cpu = {
        "limits_complete": False, "effective_visible_quota": {"quota_us": 200000, "period_us": 100000},
        "limits": [
            {"path": "/run-other.scope/workload", "quota_us": None, "period_us": None},
            {"path": "/run-other.scope", "quota_us": 200000, "period_us": 100000},
            {"path": "/", "quota_us": None, "period_us": None},
        ],
    }
    receipt = {"cgroup": {"hierarchy": {"limits": [{"path": "/run-current.scope/workload"}]},
                           "cpu_hierarchy": cpu, "cpu_hierarchy_after": cpu}}
    assert qualification._cpu_scope_status(receipt, 200) == "failed"


def test_collector_checks_real_trial_files_and_keeps_other_trials_blocked(matrix_inputs):
    plan = qualification.prepare_matrix(**matrix_inputs, timeout=180)
    name = "challenge-normal-jobs-4"
    trial = matrix_inputs["directory"] / name
    rows, _ = sample_artifacts()
    write_export(trial / "output", artifact_rows=rows)
    manifest_path = trial / "output" / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest.update({
        "export_status": "partial", "full_source_coverage": {"omitted_frames": 2},
        "discovery_coverage": {"recovery": {"record_learning_frames_not_sampled": 1}},
        "omitted_artifact_references": {"details": [], "unidentified": 0},
        "incomplete_components": [{"component": "capture", "reason": "missing frames"}],
    })
    manifest["evidence"]["coverage"].update({"selected_cases": 3, "retained_cases": 3, "omitted_cases": 0})
    manifest_path.write_text(json.dumps(manifest))
    observed = make_challenge_trial()
    receipt = observed["cgroup_receipt"]
    receipt["command"] = plan["scenarios"][name]["command"]
    receipt["max_log_bytes"] = matrix_inputs["max_log_bytes"]
    cpu = {
        "limits_complete": False, "effective_visible_quota": {"quota_us": 200000, "period_us": 100000},
        "limits": [
            {"path": "/run-owned.scope/workload", "quota_us": None, "period_us": None},
            {"path": "/run-owned.scope", "quota_us": 200000, "period_us": 100000},
            {"path": "/", "quota_us": None, "period_us": None},
        ],
    }
    receipt["cgroup"]["cpu_hierarchy"] = cpu
    receipt["cgroup"]["cpu_hierarchy_after"] = cpu
    memory_hierarchy = receipt["cgroup"]["hierarchy"]
    memory_hierarchy["limits"][0]["path"] = "/run-owned.scope/workload"
    memory_hierarchy["limits"].insert(1, {"path": "/run-owned.scope", "max": "max", "high": "max"})
    receipt["cgroup"]["hierarchy_after"] = memory_hierarchy
    (trial / "cgroup.json").write_text(json.dumps(receipt))
    (trial / "stdout.log").write_bytes(b"")
    memory = observed["progress"]["memory_admission"]
    event = {
        "created_at_unix_ms": 123,
        "phases": [{"phase": "expansion", "message": "Analyzing capture with up to 2 recovery worker(s)"}],
        "counters": {},
        "memory_admission": {
            "limit_bytes": memory["limit_bytes"], "peak_bytes": memory["peak_charged_bytes"],
            "working_sets": {"peak_active_cases": memory["peak_active_cases"], "admitted_cases": memory["admitted_cases"]},
        },
    }
    (trial / "stderr.log").write_text(json.dumps(event) + "\n")

    result = qualification.collect_matrix(matrix_inputs["directory"])

    assert result["status"] == "blocked"
    assert result["scenarios"][name]["status"] == "passed"
    assert result["scenarios"][name]["oracle"]["accepted"] is True
    assert result["scenarios"][name]["progress"]["recovery_worker_pool_size"] == 2
    assert result["scenarios"][name]["output"]["coverage"]["discovery"] == manifest["discovery_coverage"]
    assert result["memory_gate"] == "incomplete"
