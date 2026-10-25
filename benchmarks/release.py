"""Run pinned corpus release gates through the existing benchmark pipeline."""

import argparse
import re
import secrets
import stat
import sys
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from . import run
from .runner.catalogue import (
    CatalogueLimits,
    add_catalogue_arguments,
    hash_file,
    load_catalogues,
    read_json,
)
from .runner.execution import check_run_id, write_json_new
from .runner.process import DEFAULT_MAX_LOG_BYTES, validate_timeout


def _catalogue_hash(path, limits):
    information = path.stat()
    if not stat.S_ISREG(information.st_mode):
        raise ValueError(f"catalogue is not a regular file: {path}")
    if information.st_size > limits.max_metadata_bytes:
        raise ValueError(f"catalogue exceeds the metadata byte budget: {path}")
    # Pin the complete file without allowing growth to extend the approved read
    return hash_file(path, expected_bytes=information.st_size)


def load_baseline(path, maximum):
    document = read_json(path, maximum)
    if (
        not isinstance(document, dict)
        or type(document.get("schema_version")) is not int
        or document.get("schema_version") != 1
        or document.get("passed") is not True
    ):
        raise ValueError("baseline must be a successful version 1 release receipt")
    rows = document.get("coverage")
    if not isinstance(rows, list) or not rows:
        raise ValueError("baseline must contain nonempty verified coverage")
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            raise TypeError("baseline coverage rows must be objects")
        source, mode = row.get("source_sha256"), row.get("mode")
        if (
            not isinstance(source, str)
            or not re.fullmatch(r"[0-9a-f]{64}", source)
            or mode not in ("index", "stream", "case")
        ):
            raise ValueError("baseline coverage requires a valid source hash and mode")
        frames, retained = row.get("frames_seen"), row.get("retained_records")
        if (
            type(frames) is not int
            or type(retained) is not int
            or frames < 0
            or retained != frames
            or row.get("retention_complete") is not True
        ):
            raise ValueError(
                "baseline coverage must establish complete source retention"
            )
        if (
            not isinstance(row.get("sample_id"), str)
            or not row["sample_id"]
            or row.get("status") not in ("complete", "partial")
        ):
            raise ValueError(
                "baseline coverage requires a sample identity and validated status"
            )
        analysis = row.get("analysis_complete")
        if mode in ("case", "stream") and type(analysis) is not bool:
            raise ValueError("application baseline analysis coverage must be boolean")
        if mode == "index" and analysis is not None:
            raise ValueError("index baseline analysis coverage must be null or absent")
        key = (source, mode)
        if key in seen:
            raise ValueError("baseline repeats the same source and mode")
        seen.add(key)
    return document


def compare_coverage(current, baseline):
    """Only compare the same source bytes and report concrete coverage regressions."""
    by_key = {(row["source_sha256"], row["mode"]): row for row in current}
    by_alias = {(row["sample_id"], row["mode"]): row for row in current}
    issues = []
    for previous in baseline:
        key = (previous["source_sha256"], previous["mode"])
        row = by_key.get(key)
        if row is None:
            alias = (previous["sample_id"], previous["mode"])
            reason = (
                "baseline source changed; coverage is not comparable"
                if alias in by_alias
                else "baseline workload missing"
            )
            issues.append(f"{reason}: {key}")
        else:
            before, after = previous["retained_records"], row["retained_records"]
            if before is not None and (after is None or after < before):
                issues.append(f"retention regressed: {key}: {before} to {after}")
            if (
                previous.get("analysis_complete") is True
                and row.get("analysis_complete") is not True
            ):
                issues.append(f"analysis coverage regressed: {key}")
    return issues


def coverage_rows(summary):
    rows = []
    for result in summary["results"]:
        validation = result.get("validation", {})
        mode = result["mode"]
        if mode == "index":
            frames = retained = validation.get("packet_rows_checked")
            analysis = None
        elif mode == "stream":
            frames = validation.get("frames_seen")
            retained = validation.get("primary_packet_nodes")
            analysis = validation.get("analysis_complete")
        else:
            frames = validation.get("packet_records")
            retained = validation.get("retained_packet_records")
            analysis = validation.get("collection_complete")
        metrics = [
            result.get("analyzer_metrics", {}),
            *(
                stage.get("analyzer_metrics", {})
                for stage in result.get("stages", {}).values()
            ),
        ]
        rss = [
            value["peak_sampled_rss_bytes"]
            for value in metrics
            if value.get("peak_sampled_rss_bytes") is not None
        ]
        rows.append(
            {
                "sample_id": result["sample_id"],
                "mode": mode,
                "binary_sha256": result.get("binary_sha256"),
                "stage_binary_sha256s": {
                    name: stage.get("binary_sha256")
                    for name, stage in result.get("stages", {}).items()
                },
                "source_sha256": result["source"]["capture_sha256"],
                "status": result["status"],
                "frames_seen": frames,
                "retained_records": retained,
                "retention_complete": frames is not None and retained == frames,
                "analysis_complete": analysis,
                "reported_raw_collection_complete": validation.get(
                    "raw_collection_complete"
                ),
                "analyzer_elapsed_seconds": result["analyzer_elapsed_seconds"],
                "validation_seconds": result["validation_seconds"],
                "peak_sampled_analyzer_rss_bytes": max(rss) if rss else None,
                "memory_scope": "single_analyzer_process_samples_excluding_descendants",
                "artifact_bytes": result.get("artifact_bytes"),
            }
        )
    return rows


def arguments(values):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--catalogue", type=Path, action="append", required=True)
    parser.add_argument("--mode", choices=("index", "stream", "case"), action="append")
    parser.add_argument(
        "--directory", type=Path, required=True, help="New release artifact directory"
    )
    parser.add_argument("--run-id")
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--max-baseline-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--max-log-bytes", type=int, default=DEFAULT_MAX_LOG_BYTES)
    add_catalogue_arguments(parser)
    return parser.parse_args(values)


def execute(options):
    validate_timeout(options.timeout)
    limits = CatalogueLimits(
        options.max_metadata_bytes, options.max_capture_bytes, options.max_input_bytes
    )
    if options.max_log_bytes <= 0 or options.max_baseline_bytes <= 0:
        raise ValueError("release reader and log budgets must be positive")
    catalogues = [path.resolve() for path in options.catalogue]
    modes = options.mode or ["index", "stream"]
    if len(set(catalogues)) != len(catalogues) or len(set(modes)) != len(modes):
        raise ValueError(
            "duplicate catalogue or mode would repeat the same release work"
        )
    binary = options.binary.resolve(strict=True)
    binary_hash = hash_file(binary)
    stem = options.run_id or datetime.now(UTC).strftime(
        "%Y%m%dT%H%M%S"
    ) + "-" + secrets.token_hex(3)
    baseline = (
        load_baseline(options.baseline, options.max_baseline_bytes)
        if options.baseline
        else None
    )
    catalogue_hashes = {path: _catalogue_hash(path, limits) for path in catalogues}
    prepared = []
    groups = load_catalogues(catalogues, limits=limits)
    for index, (catalogue, samples) in enumerate(zip(catalogues, groups, strict=True)):
        for mode in modes:
            run_id = f"{stem}-c{index}-{mode}"
            check_run_id(run_id)
            prepared.append((catalogue, samples, mode, run_id))
    # Earlier artifacts remain untouched; all subruns belong to this new directory
    options.directory.mkdir(parents=True, exist_ok=False)
    directory = options.directory.resolve()
    seen, sources, stages, coverage, aliases = set(), {}, [], [], []
    for catalogue, samples, mode, run_id in prepared:
        selected = []
        for sample in samples:
            source_hash = sample.metadata["capture_sha256"]
            sources[str(sample.capture)] = (source_hash, sample.metadata["capture_bytes"])
            key = (mode, source_hash)
            if key in seen:
                aliases.append(
                    {
                        "mode": mode,
                        "sample_id": sample.metadata["id"],
                        "source_sha256": source_hash,
                    }
                )
            else:
                seen.add(key)
                selected.append(sample.metadata["id"])
        if not selected:
            continue
        argv = [
            "--catalogue",
            str(catalogue),
            "--binary",
            str(binary),
            "--mode",
            mode,
            "--run-id",
            run_id,
            "--results-directory",
            str(directory),
            "--timeout",
            str(options.timeout),
            "--max-log-bytes",
            str(options.max_log_bytes),
        ]
        # Revalidate selected captures just before use under the same recorded policy
        for field, value in asdict(limits).items():
            argv.extend(["--" + field.replace("_", "-"), str(value)])
        for sample_id in selected:
            argv.extend(["--sample", sample_id])
        code = run.main(argv)
        path = directory / f"{run_id}.json"
        stages.append(
            {
                "arguments": argv,
                "exit_code": code,
                "catalogue_sha256_before": catalogue_hashes[catalogue],
                "catalogue_sha256": _catalogue_hash(catalogue, limits),
                "summary": path.name if path.is_file() else None,
                "summary_sha256": hash_file(path) if path.is_file() else None,
            }
        )
        if path.is_file():
            coverage.extend(coverage_rows(read_json(path, options.max_baseline_bytes)))
    issues = compare_coverage(coverage, baseline["coverage"]) if baseline else []
    integrity = []
    for path, (expected, size) in sources.items():
        row = {"path": path, "before_sha256": expected, "after_sha256": None}
        try:
            row["after_sha256"] = hash_file(Path(path), expected_bytes=size)
        except (ValueError, OSError) as error:
            # Preserve the failed release receipt when a source changes or disappears
            row["error"] = str(error)
        integrity.append(row)
    binary_after = hash_file(binary)
    passed = bool(coverage) and all(stage["exit_code"] == 0 for stage in stages)
    passed &= all(
        row["status"] in ("complete", "partial") and row["retention_complete"]
        for row in coverage
    )
    passed &= all(
        row["binary_sha256"] == binary_hash
        and all(value == binary_hash for value in row["stage_binary_sha256s"].values())
        for row in coverage
    )
    actual_workset = [(row["mode"], row["source_sha256"]) for row in coverage]
    workset_complete = len(actual_workset) == len(seen) and set(actual_workset) == seen
    passed &= workset_complete and all(
        stage["catalogue_sha256_before"] == stage["catalogue_sha256"]
        for stage in stages
    )
    passed &= not issues and binary_after == binary_hash
    passed &= all(
        source["before_sha256"] == source["after_sha256"] for source in integrity
    )
    report = {
        "schema_version": 1,
        "passed": passed,
        "input_limits": asdict(limits),
        "binary_sha256": binary_hash,
        "binary_sha256_after": binary_after,
        "stages": stages,
        "coverage": coverage,
        "workset_complete": workset_complete,
        "duplicate_source_aliases": aliases,
        "source_integrity": integrity,
        "baseline_issues": issues,
        "interpretation": "Validated source retention and measured analysis coverage; partial analysis and unknown acquisition quality remain explicit; this does not score malware detection accuracy",
    }
    write_json_new(directory / "release.json", report)
    print(
        f"Release gate {'passed' if passed else 'failed'}: {directory / 'release.json'}"
    )
    return 0 if passed else 1


def main(values=None):
    try:
        return execute(arguments(values))
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(f"release: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
