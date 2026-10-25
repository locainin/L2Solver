"""Monitor owned analyzer processes with explicit time and log budgets."""

import math
import os
import signal
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

try:
    import resource
except ImportError:
    resource = None

DEFAULT_MAX_LOG_BYTES = 1024 * 1024
_LOG_READ_CHUNK_BYTES = 64 * 1024
_PROCESS_IO_FIELDS = ("rchar", "wchar", "read_bytes", "write_bytes")
_HAS_WAITID_WNOWAIT = os.name == "posix" and all(
    hasattr(os, name)
    for name in ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT")
)
_PROCESS_CLEANUP_SCOPE = (
    "owned_process_group"
    if _HAS_WAITID_WNOWAIT
    else "owned_group_while_leader_running"
    if os.name == "posix"
    else "analyzer_process"
)


@dataclass
class _CapturedStream:
    name: str
    pipe: BinaryIO
    log: BinaryIO
    path: Path
    retained_bytes: int = 0
    eof: bool = False


def validate_timeout(timeout):
    try:
        valid = not isinstance(timeout, bool) and timeout > 0 and math.isfinite(timeout)
    except (TypeError, OverflowError):
        valid = False
    if not valid:
        raise ValueError(
            "timeout must be finite, positive and representable in seconds"
        )


def stop_owned_processes(child):
    # Each POSIX analyzer starts a new session, so its group contains only owned work
    if child.returncode is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(child.pid, signal.SIGKILL)
        elif child.poll() is None:
            child.kill()
    except ProcessLookupError:
        pass
    child.wait()


def _child_exit_observed(child):
    # WNOWAIT keeps the leader unreaped until its owned process group is signaled
    if _HAS_WAITID_WNOWAIT:
        status = os.waitid(
            os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT
        )
        return status is not None and status.si_pid == child.pid
    return child.poll() is not None


def sampled_rss(pid):
    # Missing procfs or an exited process leaves a measurement unavailable, not zero
    try:
        for line in (
            Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines()
        ):
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


def _sampled_process_io(pid):
    # Linux procfs separates syscall bytes from storage-layer bytes
    try:
        counters = {}
        for line in Path(f"/proc/{pid}/io").read_text(encoding="ascii").splitlines():
            name, value = line.split(":", maxsplit=1)
            if name in _PROCESS_IO_FIELDS:
                counters[name] = int(value.strip())
        if any(name not in counters for name in _PROCESS_IO_FIELDS):
            return None
        return {
            "rchar_bytes": counters["rchar"],
            "wchar_bytes": counters["wchar"],
            "read_bytes": counters["read_bytes"],
            "write_bytes": counters["write_bytes"],
        }
    except (OSError, ValueError):
        return None


def _sample_process_io(metrics, pid):
    observed = _sampled_process_io(pid)
    if observed is None:
        return
    previous = metrics["process_io_bytes"] or {}
    metrics["process_io_bytes"] = {
        name: max(value, previous.get(name, 0)) for name, value in observed.items()
    }
    metrics["io_samples"] += 1


def _child_cpu_usage():
    # RUSAGE_CHILDREN is available on Unix and measured after Popen reaps the analyzer
    if resource is None:
        return None
    try:
        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    except OSError:
        return None
    return usage.ru_utime, usage.ru_stime


def _log_path_matches(stream):
    # The analyzer can edit its working directory, so retain the original log inode
    try:
        retained = os.fstat(stream.log.fileno())
        current = stream.path.stat(follow_symlinks=False)
    except OSError:
        return False
    return (
        stat.S_ISREG(current.st_mode)
        and (retained.st_dev, retained.st_ino)
        == (
            current.st_dev,
            current.st_ino,
        )
        and retained.st_size == stream.retained_bytes
    )


def _capture_available(stream, maximum_logs, deadline=None):
    # Nonblocking reads let cleanup return even when an escaped helper holds a pipe open
    while not stream.eof:
        if deadline is not None and time.monotonic() >= deadline:
            return False, "deadline"
        if not _log_path_matches(stream):
            return False, f"Analyzer {stream.name} log was removed or replaced"
        remaining = maximum_logs - stream.retained_bytes
        read_size = min(_LOG_READ_CHUNK_BYTES, remaining + 1)
        try:
            data = os.read(stream.pipe.fileno(), read_size)
        except BlockingIOError:
            return False, None
        except InterruptedError:
            continue
        if not data:
            stream.eof = True
            return False, None

        retained = min(len(data), remaining)
        if retained:
            if not _log_path_matches(stream):
                return False, f"Analyzer {stream.name} log was removed or replaced"
            try:
                written = stream.log.write(data[:retained])
                if written != retained:
                    return False, f"Analyzer {stream.name} log was not fully retained"
                stream.log.flush()
            except OSError as error:
                return (
                    False,
                    f"Analyzer {stream.name} log could not be retained: {error}",
                )
            stream.retained_bytes += retained
        if len(data) > retained:
            return False, f"Analyzer {stream.name} log budget exceeded"
        if deadline is not None and time.monotonic() >= deadline:
            return False, "deadline"
        return True, None
    return False, None


def _drain_available(stream, maximum_logs, deadline=None):
    data_read = False
    while True:
        read_data, issue = _capture_available(stream, maximum_logs, deadline)
        data_read |= read_data
        if issue is not None or not read_data:
            return data_read, issue


def _stop_result(child, streams, status, message, metrics):
    _sample_process_io(metrics, child.pid)
    stop_owned_processes(child)
    if any(not _log_path_matches(stream) for stream in streams):
        status, message = "tool_failure", "Analyzer log was removed or replaced"
        metrics["log_capture_complete"] = False
    return child.returncode, status, message, metrics


def _timeout_result(child, streams, metrics):
    return _stop_result(
        child, streams, "timeout", "Analyzer deadline exceeded", metrics
    )


def monitor(child, streams, deadline, maximum_logs):
    metrics = {
        "peak_sampled_rss_bytes": None,
        "rss_samples": 0,
        "memory_scope": "analyzer_process_only",
        "sampling_interval_seconds": 0.05,
        "process_cleanup_scope": _PROCESS_CLEANUP_SCOPE,
        "log_capture_complete": False,
        "user_cpu_seconds": None,
        "system_cpu_seconds": None,
        "cpu_measurement_scope": "rusage_children_delta_for_waited_children",
        "process_io_bytes": None,
        "io_measurement_scope": "linux_procfs_analyzer_process_only",
        "io_samples": 0,
    }
    while True:
        # A process observed after its deadline cannot be accepted as a successful run
        if time.monotonic() >= deadline:
            return _timeout_result(child, streams, metrics)
        rss = sampled_rss(child.pid)
        if rss is not None:
            metrics["rss_samples"] += 1
            metrics["peak_sampled_rss_bytes"] = max(
                rss, metrics["peak_sampled_rss_bytes"] or 0
            )
        _sample_process_io(metrics, child.pid)
        data_read = False
        for stream in streams:
            if not _log_path_matches(stream):
                return _stop_result(
                    child,
                    streams,
                    "tool_failure",
                    f"Analyzer {stream.name} log was removed or replaced",
                    metrics,
                )
            read_data, issue = _drain_available(stream, maximum_logs, deadline)
            data_read |= read_data
            if issue == "deadline":
                return _timeout_result(child, streams, metrics)
            if issue is not None:
                return _stop_result(child, streams, "tool_failure", issue, metrics)

        # Recheck after the poll; a scheduler delay must not turn a late exit into success
        exited = _child_exit_observed(child)
        if time.monotonic() >= deadline:
            return _timeout_result(child, streams, metrics)
        if exited:
            # Drain the bounded configured tail, then require pipe EOF before accepting the logs
            for stream in streams:
                _, issue = _drain_available(stream, maximum_logs, deadline)
                if issue == "deadline":
                    return _timeout_result(child, streams, metrics)
                if issue is not None:
                    return _stop_result(child, streams, "tool_failure", issue, metrics)
            if time.monotonic() >= deadline:
                return _timeout_result(child, streams, metrics)
            if any(not _log_path_matches(stream) for stream in streams):
                return _stop_result(
                    child,
                    streams,
                    "tool_failure",
                    "Analyzer log was removed or replaced",
                    metrics,
                )
            if any(not stream.eof for stream in streams):
                return _stop_result(
                    child,
                    streams,
                    "tool_failure",
                    "Analyzer log capture was incomplete after process exit",
                    metrics,
                )
            metrics["log_capture_complete"] = True
            _sample_process_io(metrics, child.pid)
            stop_owned_processes(child)
            return child.returncode, None, None, metrics
        if not data_read:
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))


def run_child(
    command, directory, timeout, log_prefix=None, max_log_bytes=DEFAULT_MAX_LOG_BYTES
):
    validate_timeout(timeout)
    if (
        not isinstance(max_log_bytes, int)
        or isinstance(max_log_bytes, bool)
        or max_log_bytes <= 0
    ):
        raise ValueError("log budget must be a positive byte count")
    deadline = time.monotonic() + timeout
    prefix = f"{log_prefix}." if log_prefix else ""
    cpu_before = _child_cpu_usage()
    with (
        (directory / f"{prefix}stdout.log").open("xb") as stdout,
        (directory / f"{prefix}stderr.log").open("xb") as stderr,
    ):
        child = subprocess.Popen(
            command,
            cwd=directory,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=os.name == "posix",
            bufsize=0,
        )
        streams = [
            _CapturedStream(
                "stdout", child.stdout, stdout, directory / f"{prefix}stdout.log"
            ),
            _CapturedStream(
                "stderr", child.stderr, stderr, directory / f"{prefix}stderr.log"
            ),
        ]
        try:
            for stream in streams:
                os.set_blocking(stream.pipe.fileno(), False)
            result = monitor(child, streams, deadline, max_log_bytes)
        finally:
            # Also stop descendants still in the owned group after completion or cancellation
            stop_owned_processes(child)
            for stream in streams:
                stream.pipe.close()
        if cpu_before is not None:
            cpu_after = _child_cpu_usage()
            if cpu_after is not None:
                result[3]["user_cpu_seconds"] = max(
                    0.0, cpu_after[0] - cpu_before[0]
                )
                result[3]["system_cpu_seconds"] = max(
                    0.0, cpu_after[1] - cpu_before[1]
                )
        if any(not _log_path_matches(stream) for stream in streams):
            result[3]["log_capture_complete"] = False
            return (
                child.returncode,
                "tool_failure",
                "Analyzer log was removed or replaced",
                result[3],
            )
        return result
