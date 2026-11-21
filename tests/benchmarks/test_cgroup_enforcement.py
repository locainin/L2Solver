"""A delegated cgroup must enforce its cap without limiting the monitor."""

import json
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from benchmarks import cgroup_enforcement
from benchmarks.memory_qualification import _trial

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


def run_in_delegated_scope(command, *, timeout=20):
    return subprocess.run(
        ["systemd-run", "--user", "--scope", "--quiet", "-p", "Delegate=yes", *command],
        capture_output=True, text=True, timeout=timeout, check=False,
    )


@pytest.fixture
def delegated_user_scope():
    probe = (
        "import sys; "
        f"sys.path.insert(0, {str(HARNESS.parent)!r}); "
        "from cgroup_enforcement import delegated_scope; delegated_scope()"
    )
    try:
        result = run_in_delegated_scope([sys.executable, "-c", probe], timeout=10)
    except FileNotFoundError:
        pytest.skip("systemd-run is unavailable")
    if result.returncode:
        pytest.skip("a delegated user scope is unavailable")


def run_under_limit(directory, limit_bytes, allocation_bytes):
    command = [
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
    return run_in_delegated_scope(command)


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
    result = run_in_delegated_scope(command)

    assert result.returncode == 0, result.stderr
    receipt = json.loads((tmp_path / "cgroup.json").read_text())
    assert receipt["exit_code"] == 0
    assert receipt["monitor"]["log_capture_complete"] is True
    assert (tmp_path / "stderr.log").stat().st_size == log_bytes


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux cgroup v2")
@pytest.mark.parametrize(
    ("parent_exits", "nested"),
    [(True, False), (False, False), (True, True)],
    ids=["completed", "timed-out", "nested-cgroup"],
)
def test_owned_scope_stops_detached_descendants(
    tmp_path, delegated_user_scope, parent_exits, nested
):
    delayed_write = """
import os, pathlib, time
if NESTED:
    path = next(line[4:] for line in pathlib.Path('/proc/self/cgroup').read_text().splitlines()
                if line.startswith('0::/'))
    child = pathlib.Path('/sys/fs/cgroup') / path / 'nested'
    child.mkdir()
    (child / 'cgroup.procs').write_text(str(os.getpid()))
pathlib.Path('descendant-started').write_text(str(os.getpid()))
time.sleep(1.5)
pathlib.Path('late-write').write_text('unexpected')
""".replace("NESTED", str(nested))
    workload = f"""
import pathlib, subprocess, sys, time
subprocess.Popen([sys.executable, '-c', {delayed_write!r}],
                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                 stderr=subprocess.DEVNULL, start_new_session=True)
while not pathlib.Path('descendant-started').exists():
    time.sleep(0.005)
time.sleep({0 if parent_exits else 10})
"""
    command = [
        sys.executable, str(HARNESS), "--directory", str(tmp_path),
        "--memory-max", "268435456", "--timeout", "1", "--",
        sys.executable, "-c", workload,
    ]
    # A process outside the owned scope must remain untouched
    unrelated = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        result = run_in_delegated_scope(command, timeout=10)
        # Give an escaped child time to write before checking cleanup
        time.sleep(1.8)
        assert result.returncode == 0, result.stderr
        assert (tmp_path / "descendant-started").exists()
        assert not (tmp_path / "late-write").exists()
        assert unrelated.poll() is None
        receipt = json.loads((tmp_path / "cgroup.json").read_text())
        assert receipt["status"] == (None if parent_exits else "timeout")
        assert receipt["exit_code"] == (0 if parent_exits else -signal.SIGKILL)
    finally:
        unrelated.terminate()
        unrelated.wait(timeout=5)


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux cgroup v2")
def test_missing_kill_control_refuses_to_launch_workload(tmp_path, delegated_user_scope):
    launcher = """
import errno, os, sys
from unittest.mock import patch
from benchmarks import cgroup_enforcement

real_open = os.open
def without_cgroup_kill(path, *args, **kwargs):
    if os.fspath(path).endswith('/cgroup.kill'):
        raise FileNotFoundError(errno.ENOENT, 'missing cgroup.kill', path)
    return real_open(path, *args, **kwargs)

sys.argv = ['cgroup_enforcement', '--directory', sys.argv[1], '--memory-max',
            '268435456', '--timeout', '5', '--', sys.executable, '-c',
            "from pathlib import Path; Path('child-started').touch()"]
with patch.object(os, 'open', side_effect=without_cgroup_kill):
    raise SystemExit(cgroup_enforcement.main())
"""
    result = run_in_delegated_scope([sys.executable, "-c", launcher, str(tmp_path)], timeout=10)

    assert result.returncode != 0
    assert "cgroup.kill" in result.stderr
    assert not (tmp_path / "child-started").exists()
    assert not (tmp_path / "cgroup.json").exists()


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux cgroup v2")
@pytest.mark.parametrize("child_exit", [0, 3, None], ids=["complete", "partial", "timeout"])
def test_cleanup_failure_receipt_cannot_qualify(tmp_path, delegated_user_scope, child_exit):
    finish = "time.sleep(10)" if child_exit is None else f"sys.exit({child_exit})"
    workload = f"""
import pathlib, subprocess, sys, time
subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(1.5)'],
                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                 stderr=subprocess.DEVNULL, start_new_session=True)
pathlib.Path('descendant-started').touch()
{finish}
"""
    launcher = f"""
import os, sys
from unittest.mock import patch
from benchmarks import cgroup_enforcement

output_directory = sys.argv[1]
real_write = os.write
def fail_kill(fd, data):
    if os.readlink(f'/proc/self/fd/{{fd}}').endswith('/cgroup.kill'):
        assert not os.path.exists(os.path.join(output_directory, 'cgroup.json'))
        raise PermissionError('kill refused for test')
    return real_write(fd, data)

sys.argv = ['cgroup_enforcement', '--directory', sys.argv[1], '--memory-max',
            '268435456', '--timeout', '0.5', '--', sys.executable, '-c', {workload!r}]
with patch.object(os, 'write', side_effect=fail_kill):
    raise SystemExit(cgroup_enforcement.main())
"""
    result = run_in_delegated_scope([sys.executable, "-c", launcher, str(tmp_path)], timeout=10)
    # The test child exits on its own after the injected failure
    time.sleep(1.5)

    assert result.returncode != 0
    assert "kill refused for test" in result.stderr
    assert (tmp_path / "descendant-started").exists()
    receipt = json.loads((tmp_path / "cgroup.json").read_text())
    assert receipt["status"] == ("timeout" if child_exit is None else "tool_failure")
    assert receipt["exit_code"] == (-signal.SIGKILL if child_exit is None else child_exit)
    assert "kill refused for test" in receipt["cleanup_error"]
    assessment = _trial(
        tmp_path, receipt["command"], 1, {}, {}, 100, receipt["max_log_bytes"]
    )
    assert assessment["status"] == "failed"
    assert assessment["failures"] == ["exit_status"]


@pytest.mark.parametrize("contents", ["", "frozen 0\n", "populated 2\n", "populated 0\npopulated 1\n"])
def test_cleanup_rejects_invalid_population_state(tmp_path, contents):
    workload = tmp_path / "workload"
    workload.mkdir()
    (workload / "cgroup.events").write_text(contents)

    with pytest.raises(ValueError):
        cgroup_enforcement._cleanup_workload(workload)

    assert workload.is_dir()
    assert not (workload / "cgroup.kill").exists()


def test_cleanup_reports_missing_kill_control(tmp_path):
    workload = tmp_path / "workload"
    workload.mkdir()
    (workload / "cgroup.events").write_text("populated 1\n")

    with pytest.raises(FileNotFoundError):
        cgroup_enforcement._cleanup_workload(workload)

    assert workload.is_dir()


def test_cleanup_times_out_if_group_stays_populated(tmp_path, monkeypatch):
    workload = tmp_path / "workload"
    workload.mkdir()
    (workload / "cgroup.events").write_text("populated 1\n")
    (workload / "cgroup.kill").touch()
    monkeypatch.setattr(cgroup_enforcement, "_CLEANUP_TIMEOUT_SECONDS", 0.05)

    started = time.monotonic()
    with pytest.raises(TimeoutError, match="populated"):
        cgroup_enforcement._cleanup_workload(workload)

    assert time.monotonic() - started < 1
    assert (workload / "cgroup.kill").read_text() == "1"
    assert workload.is_dir()
