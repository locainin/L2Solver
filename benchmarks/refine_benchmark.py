"""Prepare, run, and collect five bounded file-refinement benchmark cases."""

import argparse
import json
import re
import sys
from pathlib import Path

from . import cgroup_enforcement
from .runner.refine_disk import DiskObserver
from .runner.refine_fixtures import FixtureSizes, generate
from .runner.refine_validation import CASE_INPUTS, MAX_DOCUMENT, require_cpu_bound, summarize, validate_case
from .runner.catalogue import hash_file, read_json

MIB = 1024 * 1024
DISK_STOP = 6 * 1024 * MIB


def _write_json(path, value):
    with path.open("x", encoding="utf-8") as target:
        json.dump(value, target, indent=2, sort_keys=True)
        target.write("\n")


def case_command(root, case, binary):
    if case not in CASE_INPUTS:
        raise ValueError("unknown refinement case")
    private = Path(root) / "private" / case
    variables = [("TMPDIR", "tmp"), ("XDG_CONFIG_HOME", "config"),
                 ("XDG_CACHE_HOME", "cache"), ("XDG_STATE_HOME", "state"),
                 ("XDG_DATA_HOME", "data"), ("XDG_RUNTIME_DIR", "runtime")]
    environment = [f"{name}={private / directory}" for name, directory in variables]
    memory, reads = ("32MiB", "24MiB") if case == "output-limit" else ("128MiB", "4GiB")
    return ["env", *environment, str(binary), "refine", str(Path(root) / "fixtures" / CASE_INPUTS[case]),
            "--output", str(Path(root) / "output" / case), "--profile", "normal", "--no-cache",
            "--progress", "json", "--jobs", "1", "--memory-limit", memory, "--source-read-limit", reads]


def prepare(root, binary, source_commit):
    root = Path(root)
    if re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", source_commit) is None:
        raise ValueError("source commit must be a full lowercase Git object ID")
    if root.exists() and (not root.is_dir() or any(root.iterdir())):
        raise ValueError("benchmark directory must be empty")
    root.mkdir(parents=True, exist_ok=True)
    digest = hash_file(binary)
    generate(root, FixtureSizes())
    for directory in ("private", "output", "receipts"):
        (root / directory).mkdir()
    _write_json(root / "plan.json", {"source_commit": source_commit, "binary_sha256": digest})


def run_case(root, binary, case):
    if case not in CASE_INPUTS:
        raise ValueError("unknown refinement case")
    require_cpu_bound(cgroup_enforcement.cpu_hierarchy_limits(cgroup_enforcement.delegated_scope()))
    plan = read_json(root / "plan.json", MAX_DOCUMENT)
    fixtures = read_json(root / "fixtures.json", MAX_DOCUMENT)
    source = root / "fixtures" / CASE_INPUTS[case]
    if (hash_file(binary) != plan["binary_sha256"]
            or hash_file(source, expected_bytes=fixtures["files"][source.name]["length"]) != fixtures["files"][source.name]["sha256"]):
        raise ValueError("binary or source identity changed")
    private = root / "private" / case
    private.mkdir()
    for name in ("tmp", "config", "cache", "state", "data", "runtime"):
        (private / name).mkdir(mode=0o700)
    receipt_dir = root / "receipts" / case
    receipt_dir.mkdir()
    observer = DiskObserver(root, private / "tmp", DISK_STOP)

    def sample(workload):
        pids = (workload / "cgroup.procs").read_text(encoding="ascii").split()
        observer.sample(pids)

    try:
        return cgroup_enforcement.run_in_scope(receipt_dir, 512 * MIB, 900, 8 * MIB,
                                               case_command(root, case, binary), workload_sample=sample)
    finally:
        _write_json(receipt_dir / "disk-observation.json", observer.result())


def collect(root, binary):
    reports = {case: validate_case(root, case) for case in CASE_INPUTS}
    summary = summarize(root, binary, reports)
    documents = [(root / "receipts" / case / "case-validation.json", report)
                 for case, report in reports.items()]
    documents.append((root / "qualification-summary.json", summary))
    # Check every existing file before writing any new one
    for path, value in documents:
        if path.is_symlink() or (path.exists() and read_json(path, MAX_DOCUMENT) != value):
            raise ValueError("existing collection evidence differs")
    for path, value in documents:
        if not path.exists():
            _write_json(path, value)
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--directory", type=Path, required=True)
    prepare_parser.add_argument("--binary", type=Path, required=True)
    prepare_parser.add_argument("--source-commit", required=True)
    prepare_parser.add_argument("--full", action="store_true", required=True,
                                help="explicitly create the large benchmark fixtures")
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--directory", type=Path, required=True)
    run_parser.add_argument("--binary", type=Path, required=True)
    run_parser.add_argument("--case", choices=CASE_INPUTS, required=True)
    collect_parser = subparsers.add_parser("collect")
    collect_parser.add_argument("--directory", type=Path, required=True)
    collect_parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        root, binary = args.directory.resolve(), args.binary.resolve(strict=True)
        if args.action == "prepare":
            prepare(root, binary, args.source_commit)
        elif args.action == "run":
            receipt = run_case(root, binary, args.case)
            print(json.dumps({"exit_code": receipt["exit_code"], "status": receipt["status"]}))
        else:
            collect(root, binary)
    except (OSError, ValueError, KeyError) as error:
        print(f"refinement benchmark failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
