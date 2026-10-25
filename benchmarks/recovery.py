"""Run isolated cold, warm, deep-cache, and interrupted recovery experiments."""

import argparse
import json
import os
import platform
import secrets
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from .runner.catalogue import (
    CatalogueLimits,
    add_catalogue_arguments,
    hash_file,
    load_catalogue,
)
from .runner.execution import check_run_id
from .runner.process import DEFAULT_MAX_LOG_BYTES, run_child, validate_timeout
from .runner.recovery import (
    DEFAULT_MAX_MANIFEST_BYTES,
    DEFAULT_MAX_OUTPUT_BYTES,
    PROFILES,
    SEARCH_PHASES,
    ProgressWatcher,
    build_extract_command,
    cache_snapshot,
    parse_cache_stats,
    read_progress_log,
    validate_export_output,
    xdg_environment,
)

DEFAULT_TIMEOUT_SECONDS = 600


def _process_result(
    command, directory, timeout, max_log_bytes, env, interrupt_when=None
):
    directory.mkdir(parents=True)
    started = time.monotonic()
    code, failure, error, metrics = run_child(
        command,
        directory,
        timeout,
        max_log_bytes=max_log_bytes,
        env=env,
        interrupt_when=interrupt_when,
    )
    elapsed_seconds = time.monotonic() - started
    if failure is not None:
        status = failure
    elif code == 0:
        status = "complete"
    elif code == 3:
        status = "partial"
    elif code == 130:
        status = "interrupted"
    else:
        status = "tool_failure"
    return {
        "command": command,
        "exit_code": code,
        "status": status,
        "error": error,
        "elapsed_seconds": elapsed_seconds,
        "metrics": metrics,
        "stdout_log": str(directory / "stdout.log"),
        "stderr_log": str(directory / "stderr.log"),
    }


def _cache_stats(binary, directory, timeout, max_log_bytes, env):
    command = [str(binary), "cache", "stats"]
    process = _process_result(command, directory, timeout, max_log_bytes, env)
    if process["status"] != "complete":
        raise RuntimeError(f"cache stats failed with status {process['exit_code']}")
    output = (directory / "stdout.log").read_text(encoding="utf-8")
    return {
        "counts": parse_cache_stats(output),
        "elapsed_seconds": process["elapsed_seconds"],
        "metrics": process["metrics"],
        "stdout_log": process["stdout_log"],
        "stderr_log": process["stderr_log"],
    }


def _phase_record(
    name,
    binary,
    sample,
    output,
    process_directory,
    cache_home,
    state_home,
    *,
    profile,
    jobs,
    strict_cache,
    timeout,
    max_log_bytes,
    max_output_bytes,
    max_manifest_bytes,
    interrupt_watcher=None,
    before_stats=None,
):
    cache_before = cache_snapshot(cache_home, state_home, before_stats)
    environment = xdg_environment(cache_home, state_home)
    command = build_extract_command(
        binary,
        sample.capture,
        output,
        profile=profile,
        jobs=jobs,
        strict_cache=strict_cache,
    )
    process = _process_result(
        command,
        process_directory,
        timeout,
        max_log_bytes,
        environment,
        interrupt_watcher.should_interrupt if interrupt_watcher is not None else None,
    )
    progress = read_progress_log(process_directory / "stderr.log", max_log_bytes)
    record = {
        "name": name,
        "profile": profile,
        "jobs": jobs,
        "strict_cache": strict_cache,
        "output_path": str(output),
        "command": command,
        "exit_code": process["exit_code"],
        "status": process["status"],
        "error": process["error"],
        "elapsed_seconds": process["elapsed_seconds"],
        "metrics": process["metrics"],
        "progress": progress,
        "interrupt_event": (
            interrupt_watcher.trigger_event if interrupt_watcher is not None else None
        ),
        "logs": {
            "stdout": process["stdout_log"],
            "stderr": process["stderr_log"],
        },
        "cache_before": cache_before,
    }

    if process["status"] in ("complete", "partial"):
        record["output"] = validate_export_output(
            output,
            exit_code=process["exit_code"],
            max_output_bytes=max_output_bytes,
            max_manifest_bytes=max_manifest_bytes,
        )
    elif output.exists():
        raise ValueError("interrupted or failed export unexpectedly published output")

    stats_directory = process_directory.parent / f"{name}-cache-stats"
    stats = _cache_stats(binary, stats_directory, timeout, max_log_bytes, environment)
    record["cache_after"] = cache_snapshot(cache_home, state_home, stats["counts"])
    record["cache_stats"] = stats
    return record


def _git_output(arguments):
    try:
        result = subprocess.run(
            ["git", "-C", str(Path(__file__).resolve().parents[1]), *arguments],
            check=True,
            capture_output=True,
            text=True,
            shell=False,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return result.stdout.strip()


def _build_identity(binary):
    root = Path(__file__).resolve().parents[1]
    status = _git_output(["status", "--porcelain"])
    rustc = subprocess.run(
        ["rustc", "--version"],
        check=False,
        capture_output=True,
        text=True,
        shell=False,
    )
    rustc_verbose = subprocess.run(
        ["rustc", "-vV"],
        check=False,
        capture_output=True,
        text=True,
        shell=False,
    )
    cargo = subprocess.run(
        ["cargo", "--version"],
        check=False,
        capture_output=True,
        text=True,
        shell=False,
    )
    rustc_target = next(
        (
            line.removeprefix("host: ")
            for line in rustc_verbose.stdout.splitlines()
            if line.startswith("host: ")
        ),
        None,
    )
    return {
        "source_commit": _git_output(["rev-parse", "HEAD"]),
        "source_tree_dirty": None if status is None else bool(status),
        "binary_sha256": hash_file(binary),
        "root_lock_sha256": hash_file(root / "Cargo.lock"),
        "host_rustc": rustc.stdout.strip() if rustc.returncode == 0 else None,
        "host_cargo": cargo.stdout.strip() if cargo.returncode == 0 else None,
        "host_rust_target": rustc_target,
        "host_machine": platform.machine(),
        "logical_cpu_count": os.cpu_count(),
        "host": platform.platform(),
    }


def _write_report(path, report):
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=".recovery-",
        suffix=".tmp",
        delete=False,
    ) as stream:
        temporary = Path(stream.name)
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def run_recovery_benchmark(
    sample,
    binary,
    result_directory,
    *,
    run_id,
    catalogue_path=None,
    profile="normal",
    jobs=None,
    strict_cache=False,
    timeout=DEFAULT_TIMEOUT_SECONDS,
    max_log_bytes=DEFAULT_MAX_LOG_BYTES,
    max_output_bytes=DEFAULT_MAX_OUTPUT_BYTES,
    max_manifest_bytes=DEFAULT_MAX_MANIFEST_BYTES,
    interrupt_phase="transform_discovery",
    minimum_phase_items=1,
):
    check_run_id(run_id)
    validate_timeout(timeout)
    if profile not in PROFILES:
        raise ValueError("profile must be fast, normal, or deep")
    for label, value in (
        ("max_log_bytes", max_log_bytes),
        ("max_output_bytes", max_output_bytes),
        ("max_manifest_bytes", max_manifest_bytes),
    ):
        if type(value) is not int or value <= 0:
            raise ValueError(f"{label} must be a positive integer")
    if jobs is not None and (type(jobs) is not int or jobs <= 0):
        raise ValueError("jobs must be a positive integer")
    if type(strict_cache) is not bool:
        raise ValueError("strict_cache must be a boolean")
    if sys.platform != "linux":
        raise ValueError("recovery benchmark requires Linux process and I/O metrics")
    if interrupt_phase not in SEARCH_PHASES:
        raise ValueError("interrupt phase must name an active recovery search stage")
    if type(minimum_phase_items) is not int or minimum_phase_items <= 0:
        raise ValueError("minimum completed work must be a positive integer")

    binary = Path(binary).resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("binary must be an existing executable file")
    capture_bytes = sample.metadata["capture_bytes"]
    if (
        hash_file(sample.capture, expected_bytes=capture_bytes)
        != sample.metadata["capture_sha256"]
    ):
        raise ValueError("capture changed after catalogue preflight")

    result_directory = Path(result_directory)
    if result_directory.is_symlink():
        raise ValueError("result directory cannot be a symlink")
    result_directory = result_directory.resolve()
    if result_directory.exists():
        raise FileExistsError("recovery result directory already exists")
    result_directory.mkdir(parents=True)
    work = result_directory / "work"
    outputs = work / "outputs"
    processes = work / "processes"
    outputs.mkdir(parents=True)
    processes.mkdir()
    shared_root = work / "shared-xdg"
    shared_cache = shared_root / "cache"
    shared_state = shared_root / "state"
    resume_root = work / "resume-xdg"
    resume_cache = resume_root / "cache"
    resume_state = resume_root / "state"
    for root in (shared_cache, shared_state, resume_cache, resume_state):
        root.parent.mkdir(parents=True, exist_ok=True)

    report_path = result_directory / "recovery.json"
    report = {
        "schema_version": 1,
        "run_id": run_id,
        "status": "running",
        "started_utc": datetime.now(UTC).isoformat(),
        "build": _build_identity(binary),
        "workload": {
            "sample_id": sample.metadata["id"],
            "capture_path": str(sample.capture),
            "capture_sha256": sample.metadata["capture_sha256"],
            "capture_bytes": capture_bytes,
            "catalogue_path": (
                str(Path(catalogue_path).resolve())
                if catalogue_path is not None
                else None
            ),
            "catalogue_sha256": (
                hash_file(Path(catalogue_path).resolve())
                if catalogue_path is not None
                else None
            ),
            "ground_truth": "not measured; the selected catalogue supplies capture identity, not labels",
        },
        "conditions": {
            "timeout_seconds": timeout,
            "max_log_bytes": max_log_bytes,
            "max_output_bytes": max_output_bytes,
            "max_manifest_bytes": max_manifest_bytes,
            "progress": "json",
            "interrupt_phase": interrupt_phase,
            "minimum_phase_items": minimum_phase_items,
            "cache_snapshot_scope": "relative paths and filesystem metadata; file contents excluded",
            "process_metrics_scope": "see each analyzer process receipt",
        },
        "runs": {},
        "interpretation": "Measured recovery execution and retained artifacts; no malware detection or recall claim",
    }
    _write_report(report_path, report)

    try:
        shared_output = outputs / "cold-warm-output"
        cold = _phase_record(
            "cold",
            binary,
            sample,
            shared_output,
            processes / "cold",
            shared_cache,
            shared_state,
            profile=profile,
            jobs=jobs,
            strict_cache=strict_cache,
            timeout=timeout,
            max_log_bytes=max_log_bytes,
            max_output_bytes=max_output_bytes,
            max_manifest_bytes=max_manifest_bytes,
            before_stats={"entries": 0, "entry_bytes": 0, "checkpoints": 0},
        )
        report["runs"]["cold"] = cold
        _write_report(report_path, report)
        if cold["status"] not in ("complete", "partial"):
            raise RuntimeError(f"cold recovery failed with status {cold['status']}")
        if cold["progress"]["cache_hits"] != 0:
            raise RuntimeError("cold run unexpectedly reused cached recovery work")

        if shared_output.is_symlink() or not shared_output.is_dir():
            raise ValueError("cold output is not a driver-owned directory")
        retained_cold_output = outputs / "cold-retained"
        if retained_cold_output.exists() or retained_cold_output.is_symlink():
            raise FileExistsError("cold output retention path already exists")
        os.rename(shared_output, retained_cold_output)
        cold["output_retained_at"] = str(retained_cold_output)
        _write_report(report_path, report)
        warm = _phase_record(
            "warm",
            binary,
            sample,
            shared_output,
            processes / "warm",
            shared_cache,
            shared_state,
            profile=profile,
            jobs=jobs,
            strict_cache=strict_cache,
            timeout=timeout,
            max_log_bytes=max_log_bytes,
            max_output_bytes=max_output_bytes,
            max_manifest_bytes=max_manifest_bytes,
            before_stats=cold["cache_after"]["stats"],
        )
        report["runs"]["warm"] = warm
        _write_report(report_path, report)
        if warm["status"] not in ("complete", "partial"):
            raise RuntimeError(f"warm recovery failed with status {warm['status']}")
        if warm["progress"]["cache_hits"] <= 0:
            raise RuntimeError("warm run did not report a cache hit")
        if not warm["progress"]["index_cache_hit"]:
            raise RuntimeError("warm run did not reuse the capture index")
        warm["same_output_identity_as_cold"] = (
            cold["output"]["files"] == warm["output"]["files"]
        )
        _write_report(report_path, report)

        deep = _phase_record(
            "deep",
            binary,
            sample,
            outputs / "deep-output",
            processes / "deep",
            shared_cache,
            shared_state,
            profile="deep",
            jobs=jobs,
            strict_cache=strict_cache,
            timeout=timeout,
            max_log_bytes=max_log_bytes,
            max_output_bytes=max_output_bytes,
            max_manifest_bytes=max_manifest_bytes,
            before_stats=warm["cache_after"]["stats"],
        )
        report["runs"]["deep"] = deep
        _write_report(report_path, report)
        if deep["status"] not in ("complete", "partial"):
            raise RuntimeError(f"deep recovery failed with status {deep['status']}")
        if not deep["progress"]["index_cache_hit"]:
            raise RuntimeError("deep run did not reuse the capture index")

        watcher = ProgressWatcher(
            interrupt_phase,
            minimum_completed=minimum_phase_items,
            maximum_bytes=max_log_bytes,
        )
        interrupted_output = outputs / "resume-output"
        interrupted = _phase_record(
            "interrupted",
            binary,
            sample,
            interrupted_output,
            processes / "interrupted",
            resume_cache,
            resume_state,
            profile="deep",
            jobs=jobs,
            strict_cache=strict_cache,
            timeout=timeout,
            max_log_bytes=max_log_bytes,
            max_output_bytes=max_output_bytes,
            max_manifest_bytes=max_manifest_bytes,
            interrupt_watcher=watcher,
            before_stats={"entries": 0, "entry_bytes": 0, "checkpoints": 0},
        )
        report["runs"]["interrupted"] = interrupted
        _write_report(report_path, report)
        if interrupted["metrics"]["interrupt_sent"] and interrupted["exit_code"] == 130:
            interrupted["status"] = "interrupted"
            _write_report(report_path, report)
            if interrupted["cache_after"]["stats"]["checkpoints"] <= 0:
                raise RuntimeError(
                    "interrupted run did not leave a resumable checkpoint"
                )
            resumed = _phase_record(
                "resume",
                binary,
                sample,
                interrupted_output,
                processes / "resume",
                resume_cache,
                resume_state,
                profile="deep",
                jobs=jobs,
                strict_cache=strict_cache,
                timeout=timeout,
                max_log_bytes=max_log_bytes,
                max_output_bytes=max_output_bytes,
                max_manifest_bytes=max_manifest_bytes,
                before_stats=interrupted["cache_after"]["stats"],
            )
            report["runs"]["resume"] = resumed
            _write_report(report_path, report)
            if resumed["status"] not in ("complete", "partial"):
                raise RuntimeError(f"resume failed with status {resumed['status']}")
            interrupted_job = interrupted["progress"]["job_created_at_unix_ms"]
            resumed_job = resumed["progress"]["job_created_at_unix_ms"]
            if interrupted_job is None or resumed_job != interrupted_job:
                raise RuntimeError(
                    "resume did not restore the interrupted job checkpoint"
                )
            if not resumed["progress"]["index_cache_hit"]:
                raise RuntimeError("resume did not reuse the capture index")
            report["status"] = "complete"
        elif (
            not interrupted["metrics"]["interrupt_sent"]
            and interrupted["exit_code"] != 130
        ):
            interrupted["observed_process_status"] = interrupted["status"]
            interrupted["status"] = "not_triggered"
            interrupted["reason"] = (
                "selected active search phase was not observed before the process ended"
            )
            report["status"] = "interrupt_not_observed"
        else:
            raise RuntimeError(
                "interruption signal was not observed as exit status 130"
            )
    except (OSError, RuntimeError, TypeError, ValueError, KeyError) as error:
        report["status"] = "failed"
        report["error"] = str(error)[:2048]
    report["finished_utc"] = datetime.now(UTC).isoformat()
    _write_report(report_path, report)
    return report


def parse_arguments(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--catalogue",
        type=Path,
        default=Path("pcap_samples/malware-traffic-analysis.json"),
    )
    parser.add_argument("--sample", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument(
        "--results-directory", type=Path, default=Path("benchmarks/results/recovery")
    )
    parser.add_argument("--run-id")
    parser.add_argument("--profile", choices=PROFILES, default="normal")
    parser.add_argument("--jobs", type=int)
    parser.add_argument("--strict-cache", action="store_true")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--max-log-bytes", type=int, default=DEFAULT_MAX_LOG_BYTES)
    parser.add_argument(
        "--max-output-bytes", type=int, default=DEFAULT_MAX_OUTPUT_BYTES
    )
    parser.add_argument(
        "--max-manifest-bytes", type=int, default=DEFAULT_MAX_MANIFEST_BYTES
    )
    parser.add_argument(
        "--interrupt-phase", choices=SEARCH_PHASES, default="transform_discovery"
    )
    parser.add_argument("--minimum-phase-items", type=int, default=1)
    add_catalogue_arguments(parser)
    return parser.parse_args(arguments)


def main(arguments=None):
    options = parse_arguments(arguments)
    run_id = options.run_id or (
        datetime.now(UTC).strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(3)
    )
    try:
        check_run_id(run_id)
        limits = CatalogueLimits(
            options.max_metadata_bytes,
            options.max_capture_bytes,
            options.max_input_bytes,
        )
        samples = load_catalogue(
            options.catalogue, limits=limits, selected=(options.sample,)
        )
        if len(samples) != 1:
            raise ValueError("recovery benchmark requires exactly one selected source")
        report_directory = options.results_directory / run_id
        report = run_recovery_benchmark(
            samples[0],
            options.binary,
            report_directory,
            run_id=run_id,
            catalogue_path=options.catalogue,
            profile=options.profile,
            jobs=options.jobs,
            strict_cache=options.strict_cache,
            timeout=options.timeout,
            max_log_bytes=options.max_log_bytes,
            max_output_bytes=options.max_output_bytes,
            max_manifest_bytes=options.max_manifest_bytes,
            interrupt_phase=options.interrupt_phase,
            minimum_phase_items=options.minimum_phase_items,
        )
        print(f"Saved {report_directory / 'recovery.json'} ({report['status']})")
        return {"complete": 0, "interrupt_not_observed": 3}.get(report["status"], 1)
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"recovery benchmark: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
