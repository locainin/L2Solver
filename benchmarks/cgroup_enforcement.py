"""Measure an owned command under a delegated Linux cgroup v2 memory cap."""

import argparse
import json
import os
import sys
import time
from pathlib import Path

from runner.process import DEFAULT_MAX_LOG_BYTES, run_child, validate_timeout


def delegated_scope():
    """Reject shared or nondelegated scopes before changing any cgroup settings."""
    if sys.platform != "linux":
        raise ValueError("cgroup enforcement requires Linux")
    entries = Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines()
    unified = [line[3:] for line in entries if line.startswith("0::/")]
    if len(unified) != 1:
        raise ValueError("unified cgroup path is unavailable")
    root = Path("/sys/fs/cgroup")
    scope = (root / unified[0].lstrip("/")).resolve(strict=True)
    scope.relative_to(root)
    if not (scope.name.startswith("run-") and scope.name.endswith(".scope")):
        raise ValueError("a dedicated transient systemd scope is required")
    if scope.stat().st_uid != os.getuid():
        raise ValueError("transient scope is not delegated to this user")
    processes = (scope / "cgroup.procs").read_text(encoding="ascii").split()
    if processes != [str(os.getpid())]:
        raise ValueError("transient scope contains other processes")
    if "memory" not in (scope / "cgroup.controllers").read_text().split():
        raise ValueError("memory controller is not delegated")
    return scope


def event_counts(group):
    return {
        key: int(value)
        for key, value in (
            line.split() for line in (group / "memory.events").read_text().splitlines()
        )
    }


def run_in_scope(directory, memory_max, timeout, max_log_bytes, command):
    """Run a single command with a separate kernel limit and bounded log capture."""
    validate_timeout(timeout)
    if memory_max <= 0 or max_log_bytes <= 0 or not command:
        raise ValueError("positive memory and log caps and a command are required")
    if not directory.is_dir():
        raise ValueError("the output directory must already exist")
    scope = delegated_scope()

    # Keep the observer outside the capped group so an OOM cannot erase its receipt
    observer = scope / "observer"
    observer.mkdir()
    (observer / "cgroup.procs").write_text(str(os.getpid()), encoding="ascii")
    (scope / "cgroup.subtree_control").write_text("+memory", encoding="ascii")
    workload = scope / "workload"
    workload.mkdir()
    try:
        (workload / "memory.max").write_text(str(memory_max), encoding="ascii")
        (workload / "memory.swap.max").write_text("0", encoding="ascii")
        (workload / "memory.oom.group").write_text("1", encoding="ascii")
        effective_max = int((workload / "memory.max").read_text())
        if effective_max != memory_max:
            raise ValueError("kernel memory cap differs from the requested cap")
        initial_events = event_counts(workload)

        # Move the launcher before exec so the monitor samples the analyzer PID
        launch = (
            "import os,sys; "
            "open(sys.argv[1], 'w', encoding='ascii').write(str(os.getpid())); "
            "os.execvp(sys.argv[2], sys.argv[2:])"
        )
        start = time.monotonic()
        exit_code, status, message, metrics = run_child(
            [sys.executable, "-c", launch, str(workload / "cgroup.procs"), *command],
            directory,
            timeout,
            max_log_bytes=max_log_bytes,
        )
        duration = time.monotonic() - start
        final_events = event_counts(workload)
        cgroup = {
            "memory_max_bytes": effective_max,
            "swap_max_bytes": 0,
            "peak_bytes": int((workload / "memory.peak").read_text()),
            "oom": final_events["oom"] - initial_events["oom"],
            "oom_kill": final_events["oom_kill"] - initial_events["oom_kill"],
            "max_events": final_events["max"] - initial_events["max"],
        }
        receipt = {
            "command": command,
            "exit_code": exit_code,
            "status": status,
            "message": message,
            "duration_seconds": duration,
            "max_log_bytes": max_log_bytes,
            "monitor": metrics,
            "cgroup": cgroup,
        }
        with (directory / "cgroup.json").open("x", encoding="utf-8") as output:
            json.dump(receipt, output, indent=2, sort_keys=True)
            output.write("\n")
        return receipt
    finally:
        # Only remove the owned empty group; never signal unrelated processes
        workload.rmdir()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--memory-max", type=int, required=True)
    parser.add_argument("--timeout", type=float, required=True)
    parser.add_argument("--max-log-bytes", type=int, default=DEFAULT_MAX_LOG_BYTES)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    command = arguments.command
    if command and command[0] == "--":
        command = command[1:]
    try:
        run_in_scope(
            arguments.directory.resolve(),
            arguments.memory_max,
            arguments.timeout,
            arguments.max_log_bytes,
            command,
        )
    except (OSError, ValueError) as error:
        print(f"cgroup enforcement failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
