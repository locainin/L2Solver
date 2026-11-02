"""Check the resource and artifact evidence for one challenge matrix run."""

from pathlib import PurePosixPath

from .recovery_acceptance import (
    MAX_EXPECTED_RECOVERY_ARTIFACTS,
    _valid_digest,
    _valid_length,
)

CHALLENGE_MEMORY_BYTES = 512 * 1024 * 1024
_IO_FIELDS = ("rchar_bytes", "wchar_bytes", "read_bytes", "write_bytes")
_EVENT_FIELDS = ("high", "max", "oom", "oom_kill")


def _object(value):
    return value if isinstance(value, dict) else {}


def _count(value, *, positive=False):
    return type(value) is int and value >= (1 if positive else 0)


def _stat(value):
    stat = _object(value)
    return all(_count(stat.get(field)) for field in ("anon", "file", "kernel"))


def _hierarchy_valid(hierarchy):
    hierarchy = _object(hierarchy)
    limits = hierarchy.get("limits")
    if hierarchy.get("limits_complete") is not True or not isinstance(limits, list) or not limits:
        return False
    previous = None
    maxima = []
    highs = []
    for index, row in enumerate(limits):
        row = _object(row)
        path = row.get("path")
        if not isinstance(path, str) or not path.startswith("/"):
            return False
        current = PurePosixPath(path)
        if str(current) != path or (previous is not None and previous.parent != current):
            return False
        for key, values in (("max", maxima), ("high", highs)):
            value = row.get(key)
            if value is None and index == len(limits) - 1 and path == "/":
                continue
            if value == "max":
                continue
            if not _count(value):
                return False
            values.append(value)
        previous = current
    return (
        limits[-1].get("path") == "/"
        and limits[0].get("max") == CHALLENGE_MEMORY_BYTES
        and hierarchy.get("effective_visible_max_bytes") == min(maxima, default=None)
        and hierarchy.get("effective_visible_high_bytes") == min(highs, default=None)
        and _count(hierarchy.get("effective_visible_max_bytes"), positive=True)
        and hierarchy["effective_visible_max_bytes"] <= CHALLENGE_MEMORY_BYTES
    )


def _events_valid(group):
    before = _object(group.get("events_before"))
    after = _object(group.get("events_after"))
    deltas = _object(group.get("event_deltas"))
    if not set(_EVENT_FIELDS).issubset(before) or before.keys() != after.keys() or before.keys() != deltas.keys():
        return False
    # A missing or reset counter cannot be interpreted as a zero-event run
    if not all(
        _count(before[key]) and _count(after[key]) and _count(deltas[key])
        and after[key] - before[key] == deltas[key]
        for key in before
    ):
        return False
    return deltas["oom"] == 0 and deltas["oom_kill"] == 0


def _identities(artifacts):
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= MAX_EXPECTED_RECOVERY_ARTIFACTS:
        return None
    values = []
    for artifact in artifacts:
        artifact = _object(artifact)
        digest = artifact.get("sha256")
        length = artifact.get("byte_length")
        if not _valid_digest(digest) or not _valid_length(length):
            return None
        values.append((digest, length))
    return sorted(values)


def assess_challenge_trial(trial, expected_artifacts, *, jobs, expected_cases):
    """Assess one run after the existing output and oracle validators have run.

    A failed or unavailable measurement is a failed check, not an inferred zero.
    The caller must independently bind the run command, source, and executable.
    """
    trial = _object(trial)
    receipt = _object(trial.get("cgroup_receipt"))
    group = _object(receipt.get("cgroup"))
    monitor = _object(receipt.get("monitor"))
    progress = _object(trial.get("progress"))
    memory = _object(progress.get("memory_admission"))
    output = _object(trial.get("output"))
    coverage = _object(output.get("coverage"))
    evidence = _object(coverage.get("evidence"))
    sampled = _object(group.get("sampled"))
    hierarchy = group.get("hierarchy")
    failures = []

    if (
        "status" not in receipt
        or receipt["status"] is not None
        or type(receipt.get("exit_code")) is not int
        or (receipt["exit_code"], output.get("export_status")) not in ((0, "complete"), (3, "partial"))
    ):
        failures.append("exit_status")
    if (
        group.get("memory_max_bytes") != CHALLENGE_MEMORY_BYTES
        or type(group.get("swap_max_bytes")) is not int
        or group["swap_max_bytes"] != 0
    ):
        failures.append("cgroup_limit")
    if not _hierarchy_valid(hierarchy) or group.get("hierarchy_after") != hierarchy:
        failures.append("cgroup_hierarchy")
    if not _events_valid(group):
        failures.append("cgroup_events")
    if not (
        _count(group.get("peak_bytes"), positive=True)
        and _count(group.get("current_bytes"))
        and _stat(group.get("memory_stat"))
        and _count(sampled.get("samples"), positive=True)
        and _count(sampled.get("peak_current_bytes"), positive=True)
        and _stat(sampled.get("memory_stat_at_peak"))
    ):
        failures.append("cgroup_samples")
    io = _object(monitor.get("process_io_bytes"))
    if not (
        monitor.get("log_capture_complete") is True
        and _count(monitor.get("rss_samples"), positive=True)
        and _count(monitor.get("peak_sampled_rss_bytes"), positive=True)
        and _count(monitor.get("io_samples"), positive=True)
        and all(_count(io.get(field)) for field in _IO_FIELDS)
    ):
        failures.append("process_metrics")
    if not (
        type(jobs) is int and jobs in (1, 2, 4)
        and _count(memory.get("samples"), positive=True)
        and memory.get("limit_bytes") == CHALLENGE_MEMORY_BYTES
        and _count(memory.get("peak_charged_bytes"), positive=True)
        and memory["peak_charged_bytes"] <= CHALLENGE_MEMORY_BYTES
        and _count(memory.get("peak_active_cases"), positive=True)
        and memory["peak_active_cases"] <= jobs
        and _count(memory.get("admitted_cases"), positive=True)
        and memory["admitted_cases"] >= memory["peak_active_cases"]
    ):
        failures.append("memory_admission")
    # An absent progress message leaves the pool size unknown
    pool_size = progress.get("recovery_worker_pool_size")
    if pool_size is not None and not (
        _count(pool_size, positive=True)
        and type(jobs) is int
        and pool_size <= jobs
        and _count(memory.get("peak_active_cases"), positive=True)
        and memory["peak_active_cases"] <= pool_size
    ):
        if "memory_admission" not in failures:
            failures.append("memory_admission")
    if not (
        _count(expected_cases, positive=True)
        and type(evidence.get("selected_cases")) is int and evidence["selected_cases"] == expected_cases
        and type(evidence.get("retained_cases")) is int and evidence["retained_cases"] == expected_cases
        and type(evidence.get("omitted_cases")) is int and evidence["omitted_cases"] == 0
    ):
        failures.append("case_coverage")
    if not (
        all(
            isinstance(coverage.get(key), dict)
            for key in ("full_source", "discovery", "evidence", "omitted_artifact_references")
        )
        and isinstance(coverage.get("incomplete_components"), list)
    ):
        failures.append("omissions")
    expected = _identities(expected_artifacts)
    actual = _identities(output.get("artifacts"))
    if (
        expected is None or actual != expected
        or type(output.get("artifact_count")) is not int
        or output["artifact_count"] != len(expected)
    ):
        failures.append("artifact_identities")
    if _object(trial.get("oracle")).get("accepted") is not True:
        failures.append("oracle")
    return {"accepted": not failures, "failures": failures}
