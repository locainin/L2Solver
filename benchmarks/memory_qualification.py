"""Prepare and collect the fixed six-run challenge memory matrix without executing it."""

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from fractions import Fraction
from pathlib import Path, PurePosixPath

from .runner.catalogue import hash_file, read_json, read_json_bytes, unique_object
from .runner.memory_qualification import (
    CHALLENGE_MEMORY_BYTES,
    _identities,
    assess_challenge_trial,
)
from .runner.process import validate_timeout
from .runner.recovery import build_extract_command, read_progress_log, validate_export_output
from .runner.recovery_acceptance import _read_recovery_oracle, _valid_digest, compare_recovery_artifacts

MAX_RECEIPT_BYTES = 1024 * 1024
_SCENARIOS = tuple((profile, jobs) for profile in ("normal", "deep") for jobs in (1, 2, 4))


def _git_state(root):
    def git(*arguments):
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True, capture_output=True, text=True, shell=False,
        )
        return result.stdout.strip()
    return git("rev-parse", "--verify", "HEAD"), bool(git("status", "--porcelain", "--untracked-files=normal"))


def _file_hash(path, *, expected_bytes=None):
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"input is not a regular file: {path}")
    if expected_bytes is not None and metadata.st_size != expected_bytes:
        raise ValueError(f"input changed while reading: {path}")
    return hash_file(path, expected_bytes=metadata.st_size)


def _input_document(path):
    raw = read_json_bytes(path, MAX_RECEIPT_BYTES)
    document = json.loads(raw, object_pairs_hook=unique_object)
    # Bind the digest to the same bounded bytes used to read the input
    digest = hashlib.sha256(raw).hexdigest()
    if _file_hash(path, expected_bytes=len(raw)) != digest:
        raise ValueError(f"input changed while reading: {path}")
    return document, digest


def _reference(reference):
    if (
        not isinstance(reference, dict)
        or set(reference) != {"schema_version", "capture", "expected_cases", "artifacts"}
        or type(reference["schema_version"]) is not int
        or reference["schema_version"] != 2
    ):
        raise ValueError("invalid memory qualification reference")
    capture = reference["capture"]
    if (
        not isinstance(capture, dict)
        or set(capture) != {"sha256", "byte_length"}
        or not _valid_digest(capture["sha256"])
        or type(capture["byte_length"]) is not int
        or capture["byte_length"] <= 0
    ):
        raise ValueError("reference capture requires a SHA-256 digest and positive byte length")
    if type(reference["expected_cases"]) is not int or reference["expected_cases"] <= 0:
        raise ValueError("reference expected case count must be a positive integer")
    artifact_identities = _identities(reference["artifacts"])
    if artifact_identities is None:
        raise ValueError("reference has invalid artifact identities")
    return reference, set(artifact_identities)


def _inputs(paths):
    source = Path(paths["source_root"])
    binary = Path(paths["binary"])
    capture = Path(paths["capture"])
    package, package_hash = _input_document(Path(paths["package_receipt"]))
    reference, reference_hash = _input_document(Path(paths["reference"]))
    oracle_document, oracle_hash = _input_document(Path(paths["oracle"]))
    expected, reference_identities = _reference(reference)
    oracle = _read_recovery_oracle(oracle_document, MAX_RECEIPT_BYTES)
    if any((item["sha256"], item["byte_length"]) not in reference_identities for item in oracle):
        raise ValueError("oracle artifacts are missing from the artifact reference")
    if any(
        (member["sha256"], member["byte_length"]) not in reference_identities
        for item in oracle
        for member in item["members"]
    ):
        raise ValueError("oracle members are missing from the artifact reference")
    commit, dirty = _git_state(source)
    if dirty:
        raise ValueError("source tree is not clean")
    if not os.access(binary, os.X_OK):
        raise ValueError("candidate binary is not executable")
    if capture.stat().st_size != expected["capture"]["byte_length"]:
        raise ValueError("capture does not match the supplied reference")
    # Bind each planned run to the actual files rather than receipt claims alone
    identity = {
        "source_commit": commit,
        "binary_sha256": _file_hash(binary),
        "capture_sha256": _file_hash(capture),
        "capture_bytes": capture.stat().st_size,
        "lock_sha256": _file_hash(source / "Cargo.lock"),
        "fuzz_lock_sha256": _file_hash(source / "fuzz" / "Cargo.lock"),
        "oracle_sha256": oracle_hash,
        "reference_sha256": reference_hash,
        "package_receipt_sha256": package_hash,
    }
    if (
        identity["capture_sha256"] != expected["capture"]["sha256"]
        or identity["capture_bytes"] != expected["capture"]["byte_length"]
    ):
        raise ValueError("capture does not match the supplied reference")
    package_identity = package.get("identity", {}) if isinstance(package, dict) else {}
    checks = package.get("candidate_checks", {}) if isinstance(package, dict) else {}
    package_check = checks.get("package", {}) if isinstance(checks, dict) else {}
    if not (
        isinstance(package, dict)
        and type(package.get("schema_version")) is int
        and package["schema_version"] == 1
        and isinstance(package_identity, dict)
        and isinstance(package_check, dict)
        and package_check.get("status") == "passed"
        and package_check.get("binary_sha256") == identity["binary_sha256"]
        and all(
            package_identity.get(key) == identity[key]
            for key in ("source_commit", "lock_sha256", "fuzz_lock_sha256")
        )
    ):
        raise ValueError("package identity does not match the actual binary and source")
    return identity, expected, oracle_document


def _scenario_name(profile, jobs):
    return f"challenge-{profile}-jobs-{jobs}"


def _command(paths, directory, profile, jobs):
    command = build_extract_command(
        Path(paths["binary"]), Path(paths["capture"]), directory / "output",
        profile=profile, jobs=jobs,
    )
    command.append("--no-cache")
    return command


def prepare_matrix(
    *, directory, source_root, binary, capture, oracle, reference, package_receipt,
    cpu_quota_percent, timeout, max_log_bytes,
):
    """Create an unused plan and six empty trial directories without launching a process."""
    validate_timeout(timeout)
    if type(cpu_quota_percent) is not int or not 1 <= cpu_quota_percent <= 800:
        raise ValueError("CPU quota must be an integer between 1 and 800 percent")
    if type(max_log_bytes) is not int or max_log_bytes <= 0:
        raise ValueError("log budget must be a positive integer")
    paths = {
        key: str(Path(value).resolve(strict=True))
        for key, value in {
            "source_root": source_root, "binary": binary, "capture": capture,
            "oracle": oracle, "reference": reference, "package_receipt": package_receipt,
        }.items()
    }
    directory = Path(directory)
    directory = directory.parent.resolve(strict=True) / directory.name
    if directory.exists() or directory.is_symlink():
        raise FileExistsError("matrix directory already exists")
    identity, _, _ = _inputs(paths)
    # Never reuse a trial directory or remove it after a failed preparation
    directory.mkdir(mode=0o700)
    scenarios = {}
    harness = Path(__file__).resolve().parent / "cgroup_enforcement.py"
    for profile, jobs in _SCENARIOS:
        name = _scenario_name(profile, jobs)
        trial = directory / name
        trial.mkdir(mode=0o700)
        command = _command(paths, trial, profile, jobs)
        scope_command = [
            "systemd-run", "--user", "--scope", "--quiet", "-p", "Delegate=yes",
            "-p", f"CPUQuota={cpu_quota_percent}%", sys.executable, str(harness),
            "--directory", str(trial), "--memory-max", str(CHALLENGE_MEMORY_BYTES),
            "--timeout", str(timeout), "--max-log-bytes", str(max_log_bytes), "--", *command,
        ]
        scenarios[name] = {
            "profile": profile, "requested_jobs": jobs,
            "command": command, "scope_command": scope_command,
        }
    plan = {
        "schema_version": 1, "directory": str(directory), "paths": paths, "identity": identity,
        "cpu_quota_percent": cpu_quota_percent, "timeout_seconds": timeout,
        "max_log_bytes": max_log_bytes, "scenarios": scenarios,
    }
    with (directory / "plan.json").open("x", encoding="utf-8") as stream:
        json.dump(plan, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    return plan


def _is_regular(path):
    try:
        return stat.S_ISREG(path.lstat().st_mode)
    except FileNotFoundError:
        return False


def _cpu_scope_status(receipt, requested):
    group = receipt.get("cgroup", {}) if isinstance(receipt, dict) else {}
    if not isinstance(group, dict):
        return "blocked"
    before = group.get("cpu_hierarchy")
    after = group.get("cpu_hierarchy_after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        return "blocked"
    if before != after:
        return "failed"
    limits = before.get("limits")
    if not isinstance(limits, list) or len(limits) < 2 or not all(isinstance(row, dict) for row in limits):
        return "blocked"
    memory = group.get("hierarchy")
    memory_limits = memory.get("limits") if isinstance(memory, dict) else None
    if not isinstance(memory_limits, list) or not memory_limits or not isinstance(memory_limits[0], dict):
        return "blocked"
    if limits[0].get("path") != memory_limits[0].get("path"):
        return "failed"
    previous = None
    for row in limits:
        path = row.get("path")
        if not isinstance(path, str) or not path.startswith("/"):
            return "failed"
        current = PurePosixPath(path)
        if str(current) != path or (previous is not None and previous.parent != current):
            return "failed"
        previous = current
    if limits[-1].get("path") != "/":
        return "failed"
    # The owned scope is the workload's parent even when the child lacks cpu.max
    scope = limits[1]
    name = scope.get("path")
    quota, period = scope.get("quota_us"), scope.get("period_us")
    if not isinstance(name, str) or not Path(name).name.startswith("run-") or not name.endswith(".scope"):
        return "failed"
    if quota is None or quota == "max" or period is None:
        return "blocked"
    if type(quota) is not int or type(period) is not int or quota <= 0 or period <= 0:
        return "failed"
    if type(requested) is not int or quota * 100 != requested * period:
        return "failed"
    finite = []
    for row in limits:
        value, interval = row.get("quota_us"), row.get("period_us")
        if value is None and interval is None:
            continue
        if value == "max" and type(interval) is int and interval > 0:
            continue
        if type(value) is not int or type(interval) is not int or value <= 0 or interval <= 0:
            return "failed"
        finite.append({"quota_us": value, "period_us": interval})
    effective = min(finite, key=lambda row: Fraction(row["quota_us"], row["period_us"]), default=None)
    return "observed" if before.get("effective_visible_quota") == effective else "failed"


def _trial(directory, command, jobs, expected, oracle, cpu_quota_percent, max_log_bytes):
    receipt_path = directory / "cgroup.json"
    if not _is_regular(receipt_path):
        return {"status": "blocked", "failures": ["cgroup_receipt_missing"]}
    try:
        receipt = read_json(receipt_path, MAX_RECEIPT_BYTES)
        if (
            not isinstance(receipt, dict)
            or receipt.get("command") != command
            or receipt.get("max_log_bytes") != max_log_bytes
        ):
            return {"status": "failed", "failures": ["command"]}
        if (
            "status" not in receipt
            or receipt["status"] is not None
            or type(receipt.get("exit_code")) is not int
            or receipt["exit_code"] not in (0, 3)
        ):
            return {"status": "failed", "failures": ["exit_status"], "cgroup_receipt": receipt}
        cpu_status = _cpu_scope_status(receipt, cpu_quota_percent)
        if cpu_status != "observed":
            return {
                "status": "blocked" if cpu_status == "blocked" else "failed",
                "failures": ["cpu_quota"], "cgroup_receipt": receipt,
            }
        if not all(_is_regular(directory / name) for name in ("stdout.log", "stderr.log")):
            return {"status": "blocked", "failures": ["logs_missing"], "cgroup_receipt": receipt}
        output_dir = directory / "output"
        if not output_dir.is_dir() or output_dir.is_symlink():
            return {"status": "failed", "failures": ["output_missing"], "cgroup_receipt": receipt}
        progress = read_progress_log(directory / "stderr.log", max_log_bytes)
        output = validate_export_output(output_dir, exit_code=receipt["exit_code"])
        acceptance = compare_recovery_artifacts({"output": output}, oracle)
        observed = {"cgroup_receipt": receipt, "progress": progress, "output": output, "oracle": acceptance}
        assessment = assess_challenge_trial(
            observed, expected["artifacts"], jobs=jobs, expected_cases=expected["expected_cases"]
        )
        return {
            "status": "passed" if assessment["accepted"] else "failed",
            "failures": assessment["failures"], **observed,
        }
    except (OSError, ValueError, TypeError, KeyError) as error:
        return {"status": "failed", "failures": ["invalid_receipt"], "error": str(error)[:2048]}


def _origins(output):
    identities = {}
    for artifact in output["artifacts"]:
        key = (artifact["sha256"], artifact["byte_length"])
        identities.setdefault(key, set()).update(
            json.dumps(origin, sort_keys=True, separators=(",", ":")) for origin in artifact["origins"]
        )
    return identities


def collect_matrix(directory):
    """Read and assess existing trial files; never execute or alter a workload."""
    directory = Path(directory).resolve(strict=True)
    plan = read_json(directory / "plan.json", MAX_RECEIPT_BYTES)
    failures = []
    result = {
        "schema_version": 1, "status": "blocked", "memory_gate": "incomplete",
        "remaining": [
            "cache_restore", "publication", "refinement", "insufficient_budget",
            "independent_evidence_validation",
        ],
        "worker_pool_size": "see each progress receipt; null when the phase message was not observed",
        "failures": failures, "scenarios": {},
    }
    if (
        not isinstance(plan, dict)
        or type(plan.get("schema_version")) is not int
        or plan["schema_version"] != 1
        or plan.get("directory") != str(directory)
        or type(plan.get("cpu_quota_percent")) is not int
        or not 1 <= plan["cpu_quota_percent"] <= 800
        or type(plan.get("max_log_bytes")) is not int
        or plan["max_log_bytes"] <= 0
    ):
        result["status"] = "failed"
        failures.append("plan")
        return result
    paths = plan.get("paths")
    try:
        before, expected, oracle = _inputs(paths)
        if before != plan.get("identity"):
            raise ValueError("identity changed since preparation")
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        result["status"] = "failed"
        failures.append("identity")
        result["error"] = str(error)[:2048]
        return result
    result["identity"] = before
    result["cpu_quota_percent_requested"] = plan.get("cpu_quota_percent")
    for profile, jobs in _SCENARIOS:
        name = _scenario_name(profile, jobs)
        trial = directory / name
        if not trial.is_dir() or trial.is_symlink():
            result["scenarios"][name] = {"status": "blocked", "failures": ["trial_missing"]}
            continue
        command = _command(paths, trial, profile, jobs)
        result["scenarios"][name] = _trial(
            trial, command, jobs, expected, oracle,
            plan["cpu_quota_percent"], plan["max_log_bytes"],
        )
        result["scenarios"][name].update({"profile": profile, "requested_jobs": jobs})
    try:
        after, _, _ = _inputs(paths)
        if after != before:
            failures.append("identity")
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        failures.append("identity")
    scenarios = result["scenarios"]
    # Compare origins only after every scenario has independently validated its output
    if all(scenario["status"] == "passed" for scenario in scenarios.values()):
        normal = [_origins(scenarios[_scenario_name("normal", jobs)]["output"]) for jobs in (1, 2, 4)]
        deep = [_origins(scenarios[_scenario_name("deep", jobs)]["output"]) for jobs in (1, 2, 4)]
        if any(origins != normal[0] for origins in normal[1:]) or any(origins != deep[0] for origins in deep[1:]):
            failures.append("worker_origins")
        if any(not origins.issubset(deep[0].get(identity, set())) for identity, origins in normal[0].items()):
            failures.append("deep_origins")
    if failures or any(scenario["status"] == "failed" for scenario in scenarios.values()):
        result["status"] = "failed"
    elif all(scenario["status"] == "passed" for scenario in scenarios.values()):
        result["status"] = "passed"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    prepare = commands.add_parser("prepare")
    for name in ("directory", "binary", "capture", "oracle", "package-receipt"):
        prepare.add_argument(f"--{name}", type=Path, required=True)
    prepare.add_argument(
        "--reference", type=Path, required=True,
        help=(
            "JSON with schema_version=2, capture={sha256, byte_length}, "
            "expected_cases=<positive integer>, and artifacts=[{sha256, byte_length}, ...]"
        ),
    )
    prepare.add_argument("--cpu-quota-percent", type=int, required=True)
    prepare.add_argument("--timeout", type=float, required=True)
    prepare.add_argument("--max-log-bytes", type=int, required=True)
    collect = commands.add_parser("collect")
    collect.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == "prepare":
            result = prepare_matrix(
                directory=args.directory, source_root=Path(__file__).resolve().parent.parent,
                binary=args.binary, capture=args.capture, oracle=args.oracle, reference=args.reference,
                package_receipt=args.package_receipt, cpu_quota_percent=args.cpu_quota_percent, timeout=args.timeout,
                max_log_bytes=args.max_log_bytes,
            )
            code = 0
        else:
            result = collect_matrix(args.directory)
            code = 0 if result["status"] == "passed" else 1
        print(json.dumps(result, indent=2, sort_keys=True))
        return code
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        print(f"memory matrix: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
