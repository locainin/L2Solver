"""Run the local capture catalogue: python3 -m benchmarks.run --help."""

import argparse
import secrets
import sys
from collections import Counter
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from .runner.catalogue import CatalogueLimits, add_catalogue_arguments, load_catalogue
from .runner.execution import check_run_id, run_sample, write_json_new
from .runner.process import DEFAULT_MAX_LOG_BYTES, validate_timeout


def parse_arguments(arguments=None):
    parser = argparse.ArgumentParser(
        description="Run bounded capture analyses and verify retained evidence"
    )
    parser.add_argument(
        "--catalogue",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--results-directory", type=Path, default=Path("benchmarks/results")
    )
    parser.add_argument("--mode", choices=("case", "stream", "index"), default="case")
    parser.add_argument(
        "--binary", type=Path, required=True, help="Existing l2solver executable"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=120,
        help="Finite positive seconds per analyzer process",
    )
    parser.add_argument(
        "--max-log-bytes",
        type=int,
        default=DEFAULT_MAX_LOG_BYTES,
        help="Per-stream analyzer log budget",
    )
    parser.add_argument(
        "--run-id",
        help="New run directory name; defaults to a UTC timestamp and random suffix",
    )
    parser.add_argument(
        "--sample",
        action="append",
        default=[],
        help="Run only this sample id; may be repeated",
    )
    add_catalogue_arguments(parser)
    return parser.parse_args(arguments)


def main(arguments=None):
    arguments = parse_arguments(arguments)
    run_id = arguments.run_id or datetime.now(UTC).strftime(
        "%Y%m%dT%H%M%S"
    ) + "-" + secrets.token_hex(3)
    try:
        check_run_id(run_id)
        limits = CatalogueLimits(
            arguments.max_metadata_bytes, arguments.max_capture_bytes, arguments.max_input_bytes
        )
        samples = load_catalogue(arguments.catalogue, limits=limits, selected=arguments.sample)
        if not arguments.binary.is_file():
            raise ValueError("binary must be an existing executable file")
        validate_timeout(arguments.timeout)
        # Preflight every destination before starting, keeping this run internally consistent
        results_directory = arguments.results_directory
        if results_directory.is_symlink():
            raise ValueError("results directory cannot be a symlink")
        results_directory.mkdir(parents=True, exist_ok=True)
        aggregate = results_directory / f"{run_id}.json"
        if aggregate.exists() or any(
            (sample.capture.parent / "runs" / run_id).exists() for sample in samples
        ):
            raise ValueError("run id already exists; choose a new run id")
        results = []
        for sample in samples:
            result = run_sample(
                sample,
                arguments.binary,
                run_id,
                arguments.timeout,
                mode=arguments.mode,
                max_log_bytes=arguments.max_log_bytes,
            )
            results.append(result)
            print(
                f"{result['sample_id']}: {result['status']} ({result['elapsed_seconds']:.3f}s)",
                flush=True,
            )
        interpretation = "Source integrity and bounded analysis coverage; no malware detection accuracy labels"
        if arguments.mode == "index":
            interpretation = (
                "Raw index integrity, packet locator agreement, and source-scoped tuple/co-occurrence facts; "
                "no complete application analysis or detection verdict"
            )
        summary = {
            "schema_version": 1,
            "run_id": run_id,
            "samples": len(results),
            "input_limits": asdict(limits),
            "outcomes": dict(Counter(result["status"] for result in results)),
            "results": results,
            "interpretation": interpretation,
        }
        write_json_new(aggregate, summary)
        print(f"Saved {aggregate}")
        return (
            0
            if all(result["status"] in ("complete", "partial") for result in results)
            else 1
        )
    except (ValueError, OSError, TypeError, KeyError) as error:
        print(f"benchmark: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
