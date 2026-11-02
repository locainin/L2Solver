"""Exercise installer command selection without running Cargo or sudo in a test."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def fake_tools(tmp_path):
    commands = tmp_path / "commands"
    commands.mkdir()
    stub = commands / "tool-stub"
    stub.write_text(f"#!{sys.executable}\n" + r'''
import json
import os
from pathlib import Path
import shutil
import sys

name = Path(sys.argv[0]).name
args = sys.argv[1:]
base = Path(os.environ["L2_TEST_STUB_ROOT"])
with (base / "calls.jsonl").open("a") as stream:
    stream.write(json.dumps([name, *args]) + "\n")
if name == "pkg-config":
    if "--exists" in args and os.environ.get("L2_TEST_NO_PCAP"):
        sys.exit(1)
    if "--variable=completionsdir" in args:
        print(base / "prefix/share/bash-completion/completions")
elif name == "cargo" and "--version" not in args:
    (base / "built").touch()
    for executable in ("l2solver", "l2solver-active", "l2solver-active-helper"):
        binary = base / executable
        binary.write_text(f"#!{sys.executable}\nimport sys\nprint('fixture 1' if '--version' in sys.argv else 'completion')\n")
        binary.chmod(0o755)
        print(json.dumps({"reason": "compiler-artifact", "executable": str(binary), "target": {"name": executable}}))
elif name == "sudo" and "--payload" in args:
    payload = Path(args[args.index("--payload") + 1])
    shutil.copyfile(payload / "receipt.json", base / "receipt.json")
elif name in ("cargo", "rustc"):
    print(f"{name} fixture")
elif name == "git" and "rev-parse" in args:
    print("fixture-tree" if "HEAD^{tree}" in args else "fixture-source")
elif name == "git" and "status" in args:
    print(os.environ.get("L2_TEST_GIT_STATUS", ""))
    if os.environ.get("L2_TEST_DIRTY_AFTER_BUILD") and (base / "built").exists():
        print("?? crates/l2-cli/src/created_during_build.rs")
elif name == "ldd" and os.environ.get("L2_TEST_MISSING_LIBRARY") == Path(args[0]).name:
    message = "libmissing.so.0 => not found" if os.environ.get("LC_ALL") == "C" else "libmissing.so.0 => missing (localized)"
    print(message, file=sys.stderr if os.environ.get("L2_TEST_MISSING_ON_STDERR") else sys.stdout)
elif name == "ldd" and os.environ.get("L2_TEST_DYNAMIC_SQLITE") == Path(args[0]).name:
    print("libsqlite3.so.0 => /usr/lib/libsqlite3.so.0 (0x0001)")
''')
    stub.chmod(0o755)
    for name in ("cargo", "rustc", "cc", "git", "sudo", "ldd", "pkg-config"):
        (commands / name).symlink_to(stub)
    return tmp_path, commands


def invoke_installer(fake_tools, *options, no_pcap=False, extra_env=None):
    base, commands = fake_tools
    environment = dict(os.environ, PATH=str(commands), L2_TEST_STUB_ROOT=str(base))
    if no_pcap:
        environment["L2_TEST_NO_PCAP"] = "1"
    environment.update(extra_env or {})
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts/build_install.py"), "--prefix", str(base / "prefix"), *options],
        env=environment, text=True, capture_output=True, timeout=20, check=False,
    )


def calls(base):
    path = base / "calls.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


@pytest.mark.parametrize("live", [False, True])
def test_installer_uses_locked_release_and_passes_discovered_paths_to_both_privileged_steps(fake_tools, live):
    if os.geteuid() == 0:
        pytest.skip("source installer must be invoked as an unprivileged user")
    base, _ = fake_tools
    result = invoke_installer(fake_tools, *(('--live',) if live else ()))
    assert result.returncode == 0, result.stderr
    recorded = calls(base)
    build = next(command for command in recorded if command[:2] == ["cargo", "build"])
    assert "--release" in build and "--locked" in build and "--bins" in build
    assert all(package in build for package in ("l2-cli", "l2-active-cli", "l2-active-linux"))
    assert ("l2-cli/live" in build) is live
    assert "--all-features" not in build
    sudo = [command for command in recorded if command[0] == "sudo"]
    assert len(sudo) == 2
    assert "--check" in sudo[0] and "--payload" in sudo[1]
    for command in sudo:
        assert "bash=share/bash-completion/completions" in command
        assert "zsh=share/zsh/site-functions" in command
        assert "fish=share/fish/vendor_completions.d" in command
    receipt = json.loads((base / "receipt.json").read_text())
    assert receipt["profile"] == "release" and receipt["live"] is live
    assert receipt["source"] == "fixture-source"
    assert receipt["source_tree"] == "fixture-tree"
    assert receipt["source_dirty"] is False


@pytest.mark.parametrize("name", ["l2solver", "l2solver-active", "l2solver-active-helper"])
@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_installer_rejects_missing_library_even_when_ldd_returns_success(fake_tools, name, stream):
    if os.geteuid() == 0:
        pytest.skip("source installer must be invoked as an unprivileged user")
    base, _ = fake_tools
    env = {"L2_TEST_MISSING_LIBRARY": name}
    if stream == "stderr":
        env["L2_TEST_MISSING_ON_STDERR"] = "1"
    result = invoke_installer(fake_tools, extra_env=env)
    assert result.returncode != 0
    assert "libmissing.so.0 => not found" in result.stderr
    assert not any(command[0] == "sudo" and "--payload" in command for command in calls(base))


def test_installer_rejects_system_sqlite_dependency_even_if_installed(fake_tools):
    if os.geteuid() == 0:
        pytest.skip("source installer must be invoked as an unprivileged user")
    base, _ = fake_tools
    result = invoke_installer(fake_tools, extra_env={"L2_TEST_DYNAMIC_SQLITE": "l2solver"})
    assert result.returncode != 0
    assert "libsqlite3.so.0" in result.stderr
    assert not any(command[0] == "sudo" and "--payload" in command for command in calls(base))


@pytest.mark.parametrize("status", [" M crates/l2-cli/src/main.rs", "M  crates/l2-cli/src/main.rs", "?? crates/l2-cli/src/new_module.rs"])
def test_installer_marks_tracked_or_untracked_source_changes_dirty(fake_tools, status):
    if os.geteuid() == 0:
        pytest.skip("source installer must be invoked as an unprivileged user")
    base, _ = fake_tools
    result = invoke_installer(fake_tools, extra_env={"L2_TEST_GIT_STATUS": status})
    assert result.returncode == 0, result.stderr
    assert json.loads((base / "receipt.json").read_text())["source_dirty"] is True


def test_installer_marks_source_dirty_when_untracked_file_appears_during_build(fake_tools):
    if os.geteuid() == 0:
        pytest.skip("source installer must be invoked as an unprivileged user")
    base, _ = fake_tools
    result = invoke_installer(fake_tools, extra_env={"L2_TEST_DIRTY_AFTER_BUILD": "1"})
    assert result.returncode == 0, result.stderr
    assert json.loads((base / "receipt.json").read_text())["source_dirty"] is True


def test_live_install_stops_before_build_when_libpcap_is_missing(fake_tools):
    if os.geteuid() == 0:
        pytest.skip("source installer must be invoked as an unprivileged user")
    base, _ = fake_tools
    result = invoke_installer(fake_tools, "--live", no_pcap=True)
    assert result.returncode != 0
    assert "install libpcap development files" in result.stderr
    assert not any(command[:2] == ["cargo", "build"] for command in calls(base))
    assert not any(command[0] == "sudo" for command in calls(base))


def test_live_install_reports_missing_pkg_config_before_build(fake_tools):
    if os.geteuid() == 0:
        pytest.skip("source installer must be invoked as an unprivileged user")
    base, commands = fake_tools
    (commands / "pkg-config").unlink()
    result = invoke_installer(fake_tools, "--live")
    assert result.returncode != 0
    assert "missing dependency: pkg-config" in result.stderr
    assert not any(command[:2] == ["cargo", "build"] for command in calls(base))
    assert not any(command[0] == "sudo" for command in calls(base))
