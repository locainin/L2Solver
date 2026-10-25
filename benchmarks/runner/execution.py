"""Run an existing analyzer with a deadline and save each evidence receipt."""

import json
import mmap
import os
import re
import sqlite3
import time
from pathlib import Path

from .catalogue import hash_file, read_json
from .index_validation import validate_index_output
from .process import DEFAULT_MAX_LOG_BYTES, run_child, validate_timeout
from .stream_validation import validate_stream_bundle
from .validation import ValidationLimit, validate_case

MAX_CASE_BYTES = 64 * 1024 * 1024


def write_json_new(path, document):
    # Exclusive creation keeps earlier runs reviewable
    with path.open("x", encoding="utf-8") as stream:
        json.dump(document, stream, indent=2, sort_keys=True)
        stream.write("\n")


def check_run_id(run_id):
    if not isinstance(run_id, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", run_id
    ):
        raise ValueError("run id must be a bounded ASCII directory component")


def artifact_bytes(directory):
    # Measure retained files, including logs, before the result receipt is published
    return sum(
        path.stat().st_size
        for path in directory.rglob("*")
        if path.is_file() and not path.is_symlink()
    )


def validate_output(directory, sample, exit_code):
    document = read_json(directory / "case.json", MAX_CASE_BYTES)
    with (
        sample.capture.open("rb") as stream,
        mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as capture,
    ):
        return validate_case(document, capture, sample.metadata, exit_code)


def validate_stream_output(directory, sample, exit_code):
    with (
        sample.capture.open("rb") as stream,
        mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as capture,
    ):
        return validate_stream_bundle(
            directory / "bundle", capture, sample.metadata, exit_code
        )


def run_sample(
    sample, binary, run_id, timeout, mode="case", max_log_bytes=DEFAULT_MAX_LOG_BYTES
):
    check_run_id(run_id)
    validate_timeout(timeout)
    if (
        not isinstance(max_log_bytes, int)
        or isinstance(max_log_bytes, bool)
        or max_log_bytes <= 0
    ):
        raise ValueError("log budget must be a positive byte count")
    if mode not in ("case", "stream", "index"):
        raise ValueError("benchmark mode must be case, stream, or index")
    # Keep one resolved executable argument for every index pipeline stage
    binary_argument = str(Path(binary).resolve())
    binary = Path(binary_argument)
    parent = sample.capture.parent / "runs"
    if parent.is_symlink():
        raise ValueError("runs directory cannot be a symlink")
    parent.mkdir(exist_ok=True)
    directory = parent / run_id
    directory.mkdir()
    subcommand = "build" if mode == "case" else "stream"
    command = [
        str(binary),
        "workbench",
        subcommand,
        os.path.relpath(sample.capture, directory),
    ]
    if mode == "case":
        command.extend(("--output", "case.json"))
    else:
        command.extend(("--directory", "bundle"))
    result = {
        "schema_version": 1,
        "run_id": run_id,
        "sample_id": sample.metadata["id"],
        "mode": mode,
        "source": sample.metadata,
        "binary_name": binary.name,
        "binary_sha256": hash_file(binary),
        "timeout_seconds": timeout,
        "max_log_bytes": max_log_bytes,
        "arguments": command[1:],
        "exit_code": None,
        "status": "tool_failure",
        "analyzer_elapsed_seconds": 0.0,
        "validation_seconds": 0.0,
    }
    started = time.monotonic()
    if mode == "index":
        result["binary_argument"] = binary_argument
        return run_index_pipeline(sample, binary, directory, timeout, result, started)
    analyzer_started = time.monotonic()
    try:
        code, failure, error, metrics = run_child(
            command, directory, timeout, max_log_bytes=max_log_bytes
        )
        result["analyzer_metrics"] = metrics
        result.update(
            exit_code=code, analyzer_elapsed_seconds=time.monotonic() - analyzer_started
        )
        if failure is not None:
            result.update(status=failure, error=error)
        elif code not in (0, 3):
            result["error"] = (
                "Analyzer returned an unexpected exit status; inspect stderr.log"
            )
        else:
            validation_start = time.monotonic()
            try:
                if mode == "case":
                    result["validation"] = validate_output(directory, sample, code)
                    result["case_bytes"] = (directory / "case.json").stat().st_size
                    result["case_sha256"] = hash_file(directory / "case.json")
                else:
                    result["validation"] = validate_stream_output(
                        directory, sample, code
                    )
                    bundle = directory / "bundle"
                    bundle_files = [
                        bundle / "manifest.json",
                        *sorted((bundle / "pages").iterdir()),
                    ]
                    result["bundle_bytes"] = sum(
                        path.stat().st_size for path in bundle_files
                    )
                    result["manifest_sha256"] = hash_file(bundle / "manifest.json")
                result["status"] = "complete" if code == 0 else "partial"
            except ValidationLimit as error:
                result.update(status="validation_limit", error=str(error))
            except (
                ValueError,
                OSError,
                KeyError,
                TypeError,
                IndexError,
                RecursionError,
            ) as error:
                result.update(status="evidence_failure", error=str(error)[:2048])
            result["validation_seconds"] = time.monotonic() - validation_start
    except OSError as error:
        result.update(
            analyzer_elapsed_seconds=time.monotonic() - analyzer_started,
            error=str(error)[:2048],
        )
    result["elapsed_seconds"] = time.monotonic() - started
    result["artifact_bytes"] = artifact_bytes(directory)
    write_json_new(directory / "result.json", result)
    return result


def run_index_pipeline(sample, binary, directory, timeout, result, started):
    # Each fact export goes straight to its own file
    source_path = os.path.relpath(sample.capture, directory)
    commands = {
        "index": [
            str(binary),
            "workbench",
            "index",
            source_path,
            "--directory",
            "index",
        ],
        "verify": [
            str(binary),
            "workbench",
            "indexed",
            "index",
            "verify",
            "--output",
            "verify.json",
        ],
        "flows": [
            str(binary),
            "workbench",
            "indexed",
            "index",
            "flows",
            "--output",
            "flows.jsonl",
        ],
        "relationships": [
            str(binary),
            "workbench",
            "indexed",
            "index",
            "relationships",
            "--output",
            "relationships.jsonl",
        ],
    }
    result["arguments"] = commands["index"][1:]
    result["stages"] = {}
    result["scope"] = {
        "raw_index": "One source's retained bytes, packet locators, and observed tuple facts",
        "deep_analysis": "Indexed source verification plus exact packet and exported fact row checks",
        "flows": "Source-scoped tuple facts; complete sessions and host attribution are not established",
        "relationships": "Exact capture-order co-occurrences; causal attribution is not established",
        "collection_quality": "Source-reported counters; absent reports leave capture loss unknown",
        "application_analysis": "not_performed",
        "detection": "not_performed",
    }
    stages_complete = True
    for stage, command in commands.items():
        if not run_index_stage(stage, command, directory, timeout, result):
            stages_complete = False
            break
    result["analyzer_elapsed_seconds"] = sum(
        stage["elapsed_seconds"] for stage in result["stages"].values()
    )
    if stages_complete:
        try:
            if hash_file(binary) != result["binary_sha256"]:
                result.update(
                    status="evidence_failure",
                    error="analyzer executable changed during index run",
                )
            else:
                validate_index_stage_outputs(sample, directory, result)
        except OSError as error:
            result.update(status="evidence_failure", error=str(error)[:2048])
    result["elapsed_seconds"] = time.monotonic() - started
    result["artifact_bytes"] = artifact_bytes(directory)
    write_json_new(directory / "result.json", result)
    return result


def run_index_stage(stage, command, directory, timeout, result):
    started = time.monotonic()
    try:
        code, failure, error, metrics = run_child(
            command,
            directory,
            timeout,
            log_prefix=stage,
            max_log_bytes=result["max_log_bytes"],
        )
    except OSError as error:
        result["stages"][stage] = {
            "arguments": command[1:],
            "exit_code": None,
            "elapsed_seconds": time.monotonic() - started,
            "binary_argument": result["binary_argument"],
            "binary_sha256": result["binary_sha256"],
            "source_sha256": result["source"]["capture_sha256"],
        }
        result.update(status="tool_failure", error=str(error)[:2048])
        return False
    result["stages"][stage] = {
        "analyzer_metrics": metrics,
        "arguments": command[1:],
        "exit_code": code,
        "elapsed_seconds": time.monotonic() - started,
        "binary_argument": result["binary_argument"],
        "binary_sha256": result["binary_sha256"],
        "source_sha256": result["source"]["capture_sha256"],
    }
    result["exit_code"] = code
    if failure is not None:
        result.update(status=failure, error=error)
        return False
    if code != 0:
        result.update(
            status="tool_failure",
            error=f"Index {stage} stage returned an unexpected exit status; inspect {stage}.stderr.log",
        )
        return False
    return True


def validate_index_stage_outputs(sample, directory, result):
    validation_start = time.monotonic()
    try:
        result["validation"] = validate_index_output(directory, sample)
        result["status"] = "complete"
    except ValidationLimit as error:
        result.update(status="validation_limit", error=str(error))
    except (
        ValueError,
        OSError,
        KeyError,
        TypeError,
        IndexError,
        RecursionError,
        sqlite3.Error,
    ) as error:
        result.update(status="evidence_failure", error=str(error)[:2048])
    result["validation_seconds"] = time.monotonic() - validation_start
