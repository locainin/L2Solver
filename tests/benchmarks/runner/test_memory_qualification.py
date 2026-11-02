"""The challenge matrix accepts only observed resource and output evidence."""

from copy import deepcopy

import pytest

from benchmarks.runner.memory_qualification import assess_challenge_trial


def make_challenge_trial():
    artifacts = [
        {"file": f"artifact-{index}", "sha256": f"{index:064x}", "byte_length": index, "origins": []}
        for index in range(1, 4)
    ]
    memory = {
        "samples": 2, "limit_bytes": 536870912, "peak_charged_bytes": 100,
        "peak_active_cases": 2, "admitted_cases": 3,
    }
    hierarchy = {
        "limits_complete": True, "effective_visible_max_bytes": 536870912,
        "effective_visible_high_bytes": None,
        "limits": [
            {"path": "/workload", "max": 536870912, "high": "max"},
            {"path": "/", "max": None, "high": None},
        ],
    }
    kernel = {
        "memory_max_bytes": 536870912, "swap_max_bytes": 0, "peak_bytes": 200,
        "current_bytes": 5, "memory_stat": {"anon": 2, "file": 2, "kernel": 1},
        "event_deltas": {"high": 0, "max": 4, "oom": 0, "oom_kill": 0},
        "events_before": {"high": 0, "max": 0, "oom": 0, "oom_kill": 0},
        "events_after": {"high": 0, "max": 4, "oom": 0, "oom_kill": 0},
        "hierarchy": hierarchy, "hierarchy_after": deepcopy(hierarchy),
        "sampled": {"samples": 3, "peak_current_bytes": 190,
                    "memory_stat_at_peak": {"anon": 100, "file": 80, "kernel": 10}},
    }
    monitor = {
        "log_capture_complete": True, "rss_samples": 3, "peak_sampled_rss_bytes": 150,
        "io_samples": 3, "process_io_bytes": {"rchar_bytes": 1, "wchar_bytes": 2,
                                                   "read_bytes": 0, "write_bytes": 0},
    }
    output = {
        "export_status": "partial", "artifact_count": 3, "artifacts": artifacts,
        "coverage": {
            "full_source": {"omitted_frames": 2},
            "discovery": {"recovery": {"record_learning_frames_not_sampled": 1}},
            "evidence": {"selected_cases": 3, "retained_cases": 3, "omitted_cases": 0},
            "omitted_artifact_references": {"details": [], "unidentified": 0},
            "incomplete_components": [{"component": "capture"}],
        },
    }
    return {
        "cgroup_receipt": {"exit_code": 3, "status": None, "cgroup": kernel, "monitor": monitor},
        "progress": {"memory_admission": memory},
        "output": output,
        "oracle": {"accepted": True},
    }


@pytest.fixture
def challenge_trial():
    return make_challenge_trial()


def identities(trial):
    return [{"sha256": item["sha256"], "byte_length": item["byte_length"]}
            for item in trial["output"]["artifacts"]]


def test_partial_capture_with_exact_artifacts_and_measured_limits_is_accepted(challenge_trial):
    result = assess_challenge_trial(challenge_trial, identities(challenge_trial), jobs=4, expected_cases=3)
    assert result == {"accepted": True, "failures": []}


@pytest.mark.parametrize(("cases", "artifact_count"), [(1, 1), (2, 2), (7, 5)])
def test_trial_accepts_different_caller_supplied_workloads(challenge_trial, cases, artifact_count):
    artifacts = [
        {"file": f"artifact-{index}", "sha256": f"{index:064x}", "byte_length": index, "origins": []}
        for index in range(1, artifact_count + 1)
    ]
    challenge_trial["output"]["artifacts"] = artifacts
    challenge_trial["output"]["artifact_count"] = artifact_count
    evidence = challenge_trial["output"]["coverage"]["evidence"]
    evidence.update(selected_cases=cases, retained_cases=cases)
    memory = challenge_trial["progress"]["memory_admission"]
    memory.update(peak_active_cases=min(2, cases), admitted_cases=cases)
    result = assess_challenge_trial(challenge_trial, identities(challenge_trial), jobs=4, expected_cases=cases)
    assert result == {"accepted": True, "failures": []}


@pytest.mark.parametrize(
    ("path", "value", "failure"),
    [
        (("cgroup_receipt", "cgroup", "event_deltas", "oom"), 1, "cgroup_events"),
        (("cgroup_receipt", "cgroup", "event_deltas", "oom_kill"), 1, "cgroup_events"),
        (("cgroup_receipt", "cgroup", "hierarchy", "limits_complete"), False, "cgroup_hierarchy"),
        (("cgroup_receipt", "cgroup", "sampled", "samples"), 0, "cgroup_samples"),
        (("cgroup_receipt", "monitor", "peak_sampled_rss_bytes"), None, "process_metrics"),
        (("cgroup_receipt", "monitor", "log_capture_complete"), False, "process_metrics"),
        (("progress", "memory_admission", "peak_charged_bytes"), None, "memory_admission"),
        (("progress", "memory_admission", "peak_active_cases"), 5, "memory_admission"),
        (("output", "coverage", "evidence", "omitted_cases"), 1, "case_coverage"),
        (("output", "coverage", "discovery"), None, "omissions"),
        (("output", "coverage", "full_source"), "unknown", "omissions"),
        (("oracle", "accepted"), False, "oracle"),
    ],
)
def test_missing_or_failed_required_evidence_is_not_accepted(challenge_trial, path, value, failure):
    part = challenge_trial
    for name in path[:-1]:
        part = part[name]
    part[path[-1]] = value
    result = assess_challenge_trial(challenge_trial, identities(challenge_trial), jobs=4, expected_cases=3)
    assert not result["accepted"]
    assert failure in result["failures"]


def test_artifact_identity_change_is_rejected(challenge_trial):
    expected = identities(challenge_trial)
    challenge_trial["output"]["artifacts"][0]["sha256"] = "f" * 64
    result = assess_challenge_trial(challenge_trial, expected, jobs=4, expected_cases=3)
    assert "artifact_identities" in result["failures"]


def test_oom_or_tool_failure_is_not_a_partial_success(challenge_trial):
    challenge_trial["cgroup_receipt"]["exit_code"] = 1
    result = assess_challenge_trial(challenge_trial, identities(challenge_trial), jobs=4, expected_cases=3)
    assert "exit_status" in result["failures"]


def test_changed_inherited_limits_are_not_treated_as_one_stable_trial(challenge_trial):
    challenge_trial["cgroup_receipt"]["cgroup"]["hierarchy_after"]["effective_visible_max_bytes"] = 268435456
    result = assess_challenge_trial(challenge_trial, identities(challenge_trial), jobs=4, expected_cases=3)
    assert "cgroup_hierarchy" in result["failures"]


def test_missing_artifact_oracle_does_not_qualify(challenge_trial):
    challenge_trial["oracle"] = None
    result = assess_challenge_trial(challenge_trial, identities(challenge_trial), jobs=4, expected_cases=3)
    assert "oracle" in result["failures"]


def test_exit_and_manifest_status_must_agree(challenge_trial):
    challenge_trial["output"]["export_status"] = "complete"
    result = assess_challenge_trial(challenge_trial, identities(challenge_trial), jobs=4, expected_cases=3)
    assert "exit_status" in result["failures"]


@pytest.mark.parametrize(
    ("path", "failure"),
    [
        (("cgroup_receipt", "exit_code"), "exit_status"),
        (("cgroup_receipt", "cgroup", "swap_max_bytes"), "cgroup_limit"),
        (("output", "coverage", "evidence", "omitted_cases"), "case_coverage"),
    ],
)
def test_boolean_values_are_not_numeric_measurements(challenge_trial, path, failure):
    part = challenge_trial
    for name in path[:-1]:
        part = part[name]
    part[path[-1]] = False
    result = assess_challenge_trial(challenge_trial, identities(challenge_trial), jobs=4, expected_cases=3)
    assert failure in result["failures"]


def test_absent_process_status_is_not_accepted(challenge_trial):
    del challenge_trial["cgroup_receipt"]["status"]
    result = assess_challenge_trial(challenge_trial, identities(challenge_trial), jobs=4, expected_cases=3)
    assert "exit_status" in result["failures"]


def test_admitted_peak_cannot_exceed_the_reported_pool_size(challenge_trial):
    challenge_trial["progress"]["recovery_worker_pool_size"] = 1
    result = assess_challenge_trial(challenge_trial, identities(challenge_trial), jobs=4, expected_cases=3)
    assert "memory_admission" in result["failures"]


@pytest.mark.parametrize("expected_cases", [None, True, 0, -1, 1.5, 2, 4])
def test_case_coverage_requires_the_caller_supplied_positive_count(challenge_trial, expected_cases):
    result = assess_challenge_trial(
        challenge_trial, identities(challenge_trial), jobs=4, expected_cases=expected_cases,
    )
    assert "case_coverage" in result["failures"]


def test_exact_artifact_count_and_identities_follow_the_reference(challenge_trial):
    expected = identities(challenge_trial)
    challenge_trial["output"]["artifact_count"] = 2
    result = assess_challenge_trial(challenge_trial, expected, jobs=4, expected_cases=3)
    assert "artifact_identities" in result["failures"]


def test_empty_artifact_reference_does_not_qualify(challenge_trial):
    challenge_trial["output"]["artifacts"] = []
    challenge_trial["output"]["artifact_count"] = 0
    result = assess_challenge_trial(challenge_trial, [], jobs=4, expected_cases=3)
    assert "artifact_identities" in result["failures"]
