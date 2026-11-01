"""A delegated cgroup must enforce its cap without limiting the monitor."""

import json
import signal
import subprocess
import sys
from pathlib import Path

import pytest

from benchmarks import cgroup_enforcement

ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "benchmarks" / "cgroup_enforcement.py"


def test_invalid_working_directory_is_rejected_before_scope_or_child(tmp_path, monkeypatch):
    def unexpected_scope():
        pytest.fail("invalid working directory reached cgroup setup")

    monkeypatch.setattr(cgroup_enforcement, "delegated_scope", unexpected_scope)
    marker = tmp_path / "child-started"
    with pytest.raises(ValueError, match="working directory"):
        cgroup_enforcement.run_in_scope(
            tmp_path,
            128 * 1024 * 1024,
            5,
            1024,
            [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"],
            working_directory=tmp_path / "missing",
        )
    assert not marker.exists()
    assert not (tmp_path / "stdout.log").exists()
    assert not (tmp_path / "cgroup.json").exists()


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux cgroup v2")
@pytest.mark.parametrize("explicit", [True, False], ids=["explicit", "default"])
def test_owned_scope_records_resolved_working_directory(tmp_path, monkeypatch, explicit):
    try:
        cgroup_enforcement.delegated_scope()
    except (OSError, ValueError):
        pytest.skip("requires an exclusive delegated transient scope")

    output = tmp_path / "results"
    output.mkdir()
    work = tmp_path / "source" if explicit else output
    working_directory = []
    if explicit:
        work.mkdir()
        alias = tmp_path / "source-link"
        alias.symlink_to(work, target_is_directory=True)
        working_directory = ["--working-directory", str(alias)]
    (work / "fixture.py").write_text("VALUE = 'relative import'\n")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cgroup_enforcement",
            "--directory", str(output),
            *working_directory,
            "--memory-max", "268435456",
            "--timeout", "5",
            "--", sys.executable, "-c",
            "import fixture; from pathlib import Path; "
            "Path('child.txt').write_text(fixture.VALUE); print(fixture.VALUE)",
        ],
    )

    assert cgroup_enforcement.main() == 0
    receipt = json.loads((output / "cgroup.json").read_text())
    assert receipt["working_directory"] == str(work.resolve())
    assert receipt["exit_code"] == 0
    assert receipt["monitor"]["log_capture_complete"] is True
    assert (work / "child.txt").read_text() == "relative import"
    assert (output / "stdout.log").read_text() == "relative import\n"
    if explicit:
        assert not (work / "stdout.log").exists()


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
