"""Measure an owned command under a delegated Linux cgroup v2 memory cap."""

import argparse
import json
import os
import sys
import time
from fractions import Fraction
from pathlib import Path

if __package__:
    from .runner.process import DEFAULT_MAX_LOG_BYTES, run_child, validate_timeout
else:
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


def read_counts(path):
    counts = {}
    for line in path.read_text(encoding="ascii").splitlines():
        fields = line.split()
        if len(fields) != 2 or fields[0] in counts or not fields[1].isdigit():
            raise ValueError(f"invalid cgroup counts in {path.name}")
        counts[fields[0]] = int(fields[1])
    return counts


def event_counts(group):
    return read_counts(group / "memory.events")


def event_deltas(before, after):
    required = {"high", "max", "oom", "oom_kill"}
    if (
        not required.issubset(before)
        or before.keys() != after.keys()
        or any(after[key] < before[key] for key in before)
    ):
        raise ValueError("cgroup memory events are incomplete or decreased")
    return {key: after[key] - value for key, value in before.items()}


def _read_limit(group, name):
    try:
        value = (group / f"memory.{name}").read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return None
    if value == "max":
        return value
    if not value.isdigit():
        raise ValueError(f"invalid memory.{name} limit")
    return int(value)


def _hierarchy(group, root):
    root = root.resolve(strict=True)
    group = group.resolve(strict=True)
    group.relative_to(root)
    while True:
        relative = group.relative_to(root)
        yield group, "/" if group == root else "/" + relative.as_posix()
        if group == root:
            break
        group = group.parent


def hierarchy_limits(group, root=Path("/sys/fs/cgroup")):
    """Observe limits in the visible hierarchy without changing any ancestor."""
    limits = []
    complete = True
    for group, path in _hierarchy(group, root):
        maximum = _read_limit(group, "max")
        high = _read_limit(group, "high")
        if path != "/" and (maximum is None or high is None):
            complete = False
        limits.append({"path": path, "max": maximum, "high": high})
    finite_max = [item["max"] for item in limits if type(item["max"]) is int]
    finite_high = [item["high"] for item in limits if type(item["high"]) is int]
    return {
        "limits": limits,
        "limits_complete": complete,
        "effective_visible_max_bytes": min(finite_max, default=None),
        "effective_visible_high_bytes": min(finite_high, default=None),
    }


def cpu_hierarchy_limits(group, root=Path("/sys/fs/cgroup")):
    """Observe visible CPU quotas without assuming hidden ancestors are unlimited."""
    limits = []
    finite = []
    complete = True
    for group, path in _hierarchy(group, root):
        try:
            fields = (group / "cpu.max").read_text(encoding="ascii").split()
        except FileNotFoundError:
            quota, period = None, None
            if path != "/":
                complete = False
        else:
            if (
                len(fields) != 2
                or (fields[0] != "max" and not fields[0].isdigit())
                or (fields[0] != "max" and fields[0].isdigit() and int(fields[0]) == 0)
                or not fields[1].isdigit()
                or int(fields[1]) == 0
            ):
                raise ValueError("invalid cgroup cpu.max")
            quota = "max" if fields[0] == "max" else int(fields[0])
            period = int(fields[1])
            if type(quota) is int:
                finite.append({"quota_us": quota, "period_us": period})
        limits.append({"path": path, "quota_us": quota, "period_us": period})
    effective = min(
        finite, key=lambda value: Fraction(value["quota_us"], value["period_us"]), default=None
    )
    return {"limits": limits, "limits_complete": complete, "effective_visible_quota": effective}


class CgroupSamples:
    """Sample usage and retain the stat values nearest the largest sample."""

    def __init__(self, group):
        self.group = group
        self.samples = 0
        self.peak_current = None
        self.stat_at_peak = None
        self.next_sample = None

    def sample(self):
        now = time.monotonic()
        if self.next_sample is not None and now < self.next_sample:
            return
        current = (self.group / "memory.current").read_text(encoding="ascii").strip()
        if not current.isdigit():
            raise ValueError("invalid cgroup memory.current")
        current = int(current)
        stat = read_counts(self.group / "memory.stat")
        self.samples += 1
        self.next_sample = now + 0.05
        if self.peak_current is None or current > self.peak_current:
            self.peak_current = current
            self.stat_at_peak = stat

    def result(self):
        return {
            "samples": self.samples,
            "peak_current_bytes": self.peak_current,
            "memory_stat_at_peak": self.stat_at_peak,
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
        initial_limits = hierarchy_limits(workload)
        initial_cpu_limits = cpu_hierarchy_limits(workload)
        samples = CgroupSamples(workload)

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
            sample=samples.sample,
        )
        duration = time.monotonic() - start
        final_events = event_counts(workload)
        deltas = event_deltas(initial_events, final_events)
        final_limits = hierarchy_limits(workload)
        final_cpu_limits = cpu_hierarchy_limits(workload)
        current = (workload / "memory.current").read_text(encoding="ascii").strip()
        if not current.isdigit():
            raise ValueError("invalid cgroup memory.current")
        cgroup = {
            "memory_max_bytes": effective_max,
            "swap_max_bytes": 0,
            "peak_bytes": int((workload / "memory.peak").read_text()),
            "current_bytes": int(current),
            "memory_stat": read_counts(workload / "memory.stat"),
            "sampled": samples.result(),
            "events_before": initial_events,
            "events_after": final_events,
            "event_deltas": deltas,
            "hierarchy": initial_limits,
            "hierarchy_after": final_limits,
            "cpu_hierarchy": initial_cpu_limits,
            "cpu_hierarchy_after": final_cpu_limits,
            "oom": deltas["oom"],
            "oom_kill": deltas["oom_kill"],
            "max_events": deltas["max"],
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
