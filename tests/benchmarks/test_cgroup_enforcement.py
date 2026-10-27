"""A delegated cgroup must enforce its cap without limiting the monitor."""

import json
import signal
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "benchmarks" / "cgroup_enforcement.py"


@pytest.fixture
def delegated_user_scope():
    probe = (
        "import sys; "
        f"sys.path.insert(0, {str(HARNESS.parent)!r}); "
        "from cgroup_enforcement import delegated_scope; delegated_scope()"
    )
    command = [
        "systemd-run",
        "--user",
        "--scope",
        "--quiet",
        "-p",
        "Delegate=yes",
        sys.executable,
        "-c",
        probe,
    ]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=10, check=False
        )
    except FileNotFoundError:
        pytest.skip("systemd-run is unavailable")
    if result.returncode:
        pytest.skip("a delegated user scope is unavailable")


def run_under_limit(directory, limit_bytes, allocation_bytes):
    command = [
        "systemd-run",
        "--user",
        "--scope",
        "--quiet",
        "-p",
        "Delegate=yes",
        sys.executable,
        str(HARNESS),
        "--directory",
        str(directory),
        "--memory-max",
        str(limit_bytes),
        "--timeout",
        "10",
        "--",
        sys.executable,
        "-c",
        f"import time; allocation = bytearray({allocation_bytes}); time.sleep(0.3)",
    ]
    return subprocess.run(
        command, capture_output=True, text=True, timeout=20, check=False
    )


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux cgroup v2")
def test_delegated_limit_kills_allocation_only_when_cap_is_exceeded(
    tmp_path, delegated_user_scope
):
    allocation = 96 * 1024 * 1024
    below_cap = tmp_path / "below"
    above_cap = tmp_path / "above"
    below_cap.mkdir()
    above_cap.mkdir()

    roomy = run_under_limit(below_cap, 256 * 1024 * 1024, allocation)
    assert roomy.returncode == 0, roomy.stderr
    roomy_receipt = json.loads((below_cap / "cgroup.json").read_text())
    assert roomy_receipt["exit_code"] == 0
    assert roomy_receipt["cgroup"]["oom_kill"] == 0
    assert roomy_receipt["monitor"]["rss_samples"] > 0
    assert roomy_receipt["monitor"]["io_samples"] > 0

    constrained = run_under_limit(above_cap, 64 * 1024 * 1024, allocation)
    assert constrained.returncode == 0, constrained.stderr
    receipt = json.loads((above_cap / "cgroup.json").read_text())
    assert receipt["exit_code"] == -signal.SIGKILL
    assert receipt["cgroup"]["memory_max_bytes"] == 64 * 1024 * 1024
    assert receipt["cgroup"]["oom_kill"] > 0
    assert receipt["monitor"]["log_capture_complete"] is True
    assert receipt["duration_seconds"] > 0


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux cgroup v2")
def test_unscoped_invocation_rejects_before_running_command(tmp_path):
    marker = tmp_path / "marker"
    command = [
        sys.executable,
        str(HARNESS),
        "--directory",
        str(tmp_path),
        "--memory-max",
        "67108864",
        "--timeout",
        "5",
        "--",
        sys.executable,
        "-c",
        f"from pathlib import Path; Path({str(marker)!r}).touch()",
    ]
    result = subprocess.run(
        command, capture_output=True, text=True, timeout=10, check=False
    )

    assert result.returncode != 0
    assert not marker.exists()
    assert not (tmp_path / "cgroup.json").exists()


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux cgroup v2")
def test_explicit_log_budget_retains_verbose_child_output(
    tmp_path, delegated_user_scope
):
    log_bytes = 1_100_000
    command = [
        "systemd-run",
        "--user",
        "--scope",
        "--quiet",
        "-p",
        "Delegate=yes",
        sys.executable,
        str(HARNESS),
        "--directory",
        str(tmp_path),
        "--memory-max",
        "268435456",
        "--timeout",
        "10",
        "--max-log-bytes",
        "2097152",
        "--",
        sys.executable,
        "-c",
        f"import os; os.write(2, b'x' * {log_bytes})",
    ]
    result = subprocess.run(
        command, capture_output=True, text=True, timeout=20, check=False
    )

    assert result.returncode == 0, result.stderr
    receipt = json.loads((tmp_path / "cgroup.json").read_text())
    assert receipt["exit_code"] == 0
    assert receipt["monitor"]["log_capture_complete"] is True
    assert (tmp_path / "stderr.log").stat().st_size == log_bytes
