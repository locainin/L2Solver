"""Exercise the archived executable with a known capture and bounded logs."""

import hashlib
import os
import shutil
from pathlib import Path

from benchmarks.qualification.fixture import BODY, http_capture
from benchmarks.runner.catalogue import hash_file, read_json
from benchmarks.runner.process import run_child
from benchmarks.runner.recovery import read_progress_log, validate_export_output

MAX_LOG_BYTES = 1024 * 1024
TIMEOUT_SECONDS = 120


def check_packaged_startup(binary, active, helper, directory):
    """Start both CLIs and confirm the helper refuses an unconnected invocation."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    observed = {}
    for executable, arguments, expected in (
        (binary, ["--version"], 0),
        (active, ["--version"], 0),
        (helper, [], 1),
    ):
        name = Path(executable).name
        logs = directory / name
        logs.mkdir()
        code, status, message, metrics = run_child(
            [str(executable), *arguments], logs, TIMEOUT_SECONDS, max_log_bytes=MAX_LOG_BYTES
        )
        # With no inherited socket, a launched helper must reject the request
        if status is not None or not metrics["log_capture_complete"] or code != expected:
            raise ValueError(f"{name} startup failed: exit {code}, {status}: {message}")
        observed[name] = {"exit_code": code}
    return {"status": "passed", "executables": observed}


def check_export(output, manifest, exit_code, *, required, tshark):
    expected_exit = 3 if required and tshark == "partial" else 0
    if exit_code != expected_exit:
        raise ValueError("unexpected export exit status")
    summary = manifest.get("tshark")
    if (
        not isinstance(summary, dict)
        or summary.get("required") is not required
        or summary.get("status") != tshark
    ):
        raise ValueError(
            "TShark availability or required status was not reported correctly"
        )
    expected = (hashlib.sha256(BODY).hexdigest(), len(BODY))
    if not any(
        (row.get("sha256"), row.get("byte_length")) == expected
        for row in output.get("artifacts", [])
    ):
        raise ValueError("expected exact native artifact was not recovered")


def check_progress(path):
    progress = read_progress_log(path, MAX_LOG_BYTES)
    if progress["events"] == 0 or progress["ignored_lines"]:
        raise ValueError("progress stderr must contain complete JSON events only")
    return progress


def check_stdout(path, *, reused):
    lines = path.read_text(encoding="utf-8").splitlines()
    expected = "Reused " if reused else "Exported "
    if not lines or not lines[0].startswith(expected):
        raise ValueError("stdout did not report the expected publication or reuse")


def _run(
    binary,
    capture,
    destination,
    directory,
    environment,
    *,
    required,
    tshark,
    reused=False,
):
    directory.mkdir()
    command = [
        str(binary),
        "extract",
        str(capture),
        "--output",
        str(destination),
        "--profile",
        "fast",
        "--jobs",
        "1",
        "--progress",
        "json",
    ]
    if required:
        command.append("--require-tshark")
    exit_code, status, message, metrics = run_child(
        command,
        directory,
        TIMEOUT_SECONDS,
        max_log_bytes=MAX_LOG_BYTES,
        env=environment,
    )
    if status is not None or not metrics["log_capture_complete"]:
        raise ValueError(
            f"packaged CLI did not finish with complete logs: {status}: {message}"
        )
    output = validate_export_output(destination, exit_code=exit_code)
    manifest = read_json(destination / "manifest.json", 64 * 1024 * 1024)
    check_export(output, manifest, exit_code, required=required, tshark=tshark)
    progress = check_progress(directory / "stderr.log")
    check_stdout(directory / "stdout.log", reused=reused)
    return {
        "exit_code": exit_code,
        "output": output,
        "progress": progress,
        "metrics": metrics,
    }


def run_packaged_cli(binary, directory):
    """Check extraction, publication, warm reuse and TShark behavior."""
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    capture = directory / "capture.pcap"
    fixture = http_capture()
    capture.write_bytes(fixture)
    empty_path = directory / "empty-path"
    empty_path.mkdir()
    # An empty PATH makes the missing TShark case independent of the host
    environment = {
        **os.environ,
        "PATH": str(empty_path),
        "XDG_CACHE_HOME": str(directory / "cache"),
        "XDG_STATE_HOME": str(directory / "state"),
    }
    cold_output = directory / "cold-output"
    cold = _run(
        binary,
        capture,
        cold_output,
        directory / "cold",
        environment,
        required=False,
        tshark="partial",
    )
    warm = _run(
        binary,
        capture,
        cold_output,
        directory / "warm",
        environment,
        required=False,
        tshark="partial",
        reused=True,
    )
    # Reuse must leave every previously published file intact
    if (
        warm["output"]["files"] != cold["output"]["files"]
        or warm["progress"]["cache_hits"] <= 0
    ):
        raise ValueError(
            "warm publication reuse did not retain the original files and report a cache hit"
        )
    required = _run(
        binary,
        capture,
        directory / "missing-required-output",
        directory / "missing-required",
        environment,
        required=True,
        tshark="partial",
    )

    runs = {"missing_optional": cold, "warm_reuse": warm, "missing_required": required}
    tshark = shutil.which("tshark")
    if tshark is None:
        return {
            "status": "blocked",
            "reason": "real TShark executable not found",
            "runs": runs,
        }

    # Pin the installed tool while the absent cases keep an empty PATH
    tshark_size = Path(tshark).stat().st_size
    tshark_digest = hash_file(Path(tshark), expected_bytes=tshark_size)
    environment["PATH"] = os.environ.get("PATH", "")
    optional = _run(
        binary,
        capture,
        directory / "present-optional-output",
        directory / "present-optional",
        environment,
        required=False,
        tshark="complete",
    )
    required_present = _run(
        binary,
        capture,
        directory / "present-required-output",
        directory / "present-required",
        environment,
        required=True,
        tshark="complete",
    )
    runs.update({"present_optional": optional, "present_required": required_present})
    if (
        hash_file(capture, expected_bytes=len(fixture))
        != hashlib.sha256(fixture).hexdigest()
    ):
        raise ValueError("qualification capture changed during execution")
    if hash_file(Path(tshark), expected_bytes=tshark_size) != tshark_digest:
        raise ValueError("TShark changed during qualification")
    return {
        "status": "passed",
        "tshark_sha256": tshark_digest,
        "runs": runs,
    }
