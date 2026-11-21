"""Exercise installer command selection without running Cargo or sudo in a test."""
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

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
    target = Path(os.environ.get("CARGO_TARGET_DIR", base))
    (base / "target-dir.txt").write_text(os.environ.get("CARGO_TARGET_DIR", ""))
    (base / "build-dir.txt").write_text(os.environ.get("CARGO_BUILD_BUILD_DIR", ""))
    for executable in ("l2solver", "l2solver-active", "l2solver-active-helper"):
        binary = target / executable
        binary.write_text(f"#!{sys.executable}\nimport sys\nprint('fixture 1' if '--version' in sys.argv else 'completion')\n")
        binary.chmod(0o755)
        print(json.dumps({"reason": "compiler-artifact", "executable": str(binary), "target": {"name": executable}}))
elif name in ("cargo", "rustc"):
    print(f"{name} fixture")
elif name == "git" and os.environ.get("L2_TEST_NO_CHECKOUT"):
    print("fatal: not a git repository", file=sys.stderr)
    sys.exit(128)
elif name == "git" and "rev-parse" in args:
    print("fixture-tree" if "HEAD^{tree}" in args else "fixture-source")
elif name == "git" and "status" in args:
    print(os.environ.get("L2_TEST_GIT_STATUS", ""))
    if os.environ.get("L2_TEST_DIRTY_AFTER_BUILD") and (base / "built").exists():
        print("?? crates/l2-cli/src/created_during_build.rs")
    if os.environ.get("L2_TEST_SWAP_AFTER_BUILD") and (base / "built").exists():
        binary = Path((base / "target-dir.txt").read_text() or base) / "l2solver"
        binary.write_text(f"#!{sys.executable}\nimport sys\nprint('replacement version' if '--version' in sys.argv else 'replacement completion')\n")
        binary.chmod(0o755)
elif name == "ldd" and os.environ.get("L2_TEST_MISSING_LIBRARY") == Path(args[0]).name:
    message = "libmissing.so.0 => not found" if os.environ.get("LC_ALL") == "C" else "libmissing.so.0 => missing (localized)"
    print(message, file=sys.stderr if os.environ.get("L2_TEST_MISSING_ON_STDERR") else sys.stdout)
elif name == "ldd" and os.environ.get("L2_TEST_DYNAMIC_SQLITE") == Path(args[0]).name:
    print("libsqlite3.so.0 => /usr/lib/libsqlite3.so.0 (0x0001)")
elif name == "ldd" and os.environ.get("L2_TEST_SWAP_DURING_COPY") and Path(args[0]).name == "l2solver-active":
    binary = Path((base / "target-dir.txt").read_text() or base) / "l2solver"
    binary.write_text(f"#!{sys.executable}\nimport sys\nprint('replacement version' if '--version' in sys.argv else 'replacement completion')\n")
    binary.chmod(0o755)
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
        [sys.executable, str(ROOT / "scripts/build_install.py"), "--output", str(base / "output"), "--prefix", str(base / "prefix"), *options],
        env=environment, text=True, capture_output=True, timeout=20, check=False,
    )


def calls(base):
    path = base / "calls.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def test_installer_builds_payload_without_documentation_and_keeps_notice(fake_tools):
    if os.geteuid() == 0:
        pytest.skip("source installer must be invoked as an unprivileged user")
    base, _ = fake_tools
    result = invoke_installer(fake_tools)
    assert result.returncode == 0, result.stderr
    payload = base / "output/payload"
    assert sorted(path.name for path in payload.iterdir()) == sorted([
        "l2solver", "l2solver-active", "l2solver-active-helper",
        "bash", "zsh", "fish", "NOTICE-JEMALLOC.txt", "receipt.json",
    ])
    assert (payload / "NOTICE-JEMALLOC.txt").read_bytes() == (ROOT / "NOTICE-JEMALLOC.txt").read_bytes()
    assert all((payload / name).stat().st_mode & 0o777 == 0o644
               for name in ("l2solver", "l2solver-active", "l2solver-active-helper"))
    manifest = json.loads((base / "output/manifest.json").read_text())
    assert manifest == {"schema": 1, "files": {
        path.name: {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size}
        for path in payload.iterdir()
    }}


@pytest.mark.parametrize("live", [False, True])
def test_builder_uses_locked_release_without_privilege(fake_tools, live):
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
    assert not any(command[0] == "sudo" for command in recorded)
    assert "--completion-dir bash=share/bash-completion/completions" in result.stdout
    assert "--completion-dir zsh=share/zsh/site-functions" in result.stdout
    assert "--completion-dir fish=share/fish/vendor_completions.d" in result.stdout
    receipt = json.loads((base / "output/payload/receipt.json").read_text())
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
    assert json.loads((base / "output/payload/receipt.json").read_text())["source_dirty"] is True


def test_installer_marks_source_dirty_when_untracked_file_appears_during_build(fake_tools):
    if os.geteuid() == 0:
        pytest.skip("source installer must be invoked as an unprivileged user")
    base, _ = fake_tools
    result = invoke_installer(fake_tools, extra_env={"L2_TEST_DIRTY_AFTER_BUILD": "1"})
    assert result.returncode == 0, result.stderr
    assert json.loads((base / "output/payload/receipt.json").read_text())["source_dirty"] is True


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


def test_installer_requires_a_checkout_before_privileged_checks_or_build(fake_tools):
    if os.geteuid() == 0:
        pytest.skip("source installer must be invoked as an unprivileged user")
    base, _ = fake_tools
    result = invoke_installer(fake_tools, extra_env={"L2_TEST_NO_CHECKOUT": "1"})
    assert result.returncode != 0
    assert "Git checkout" in result.stderr
    assert "clone" in result.stderr
    recorded = calls(base)
    assert not any(command[0] == "sudo" for command in recorded)
    assert not any(command[:2] == ["cargo", "build"] for command in recorded)


def test_staged_main_drives_receipt_and_completion(fake_tools):
    base, _ = fake_tools
    result = invoke_installer(fake_tools, extra_env={"L2_TEST_SWAP_DURING_COPY": "1"})
    assert result.returncode == 0, result.stderr
    assert (base / "output/payload/bash").read_text().strip() == "completion"
    assert json.loads((base / "output/payload/receipt.json").read_text())["version"] == "fixture 1"


def test_build_uses_private_target(fake_tools):
    base, _ = fake_tools
    result = invoke_installer(fake_tools)
    assert result.returncode == 0, result.stderr
    assert not Path((base / "target-dir.txt").read_text()).exists()
    assert (base / "build-dir.txt").read_text() == (base / "target-dir.txt").read_text()


def test_builder_does_not_require_sudo(fake_tools):
    base, commands = fake_tools
    (commands / "sudo").unlink()
    result = invoke_installer(fake_tools)
    assert result.returncode == 0, result.stderr
    assert not any(command[0] == "sudo" for command in calls(base))


def test_changed_artifact_stops_publication(fake_tools):
    base, _ = fake_tools
    result = invoke_installer(fake_tools, extra_env={"L2_TEST_SWAP_AFTER_BUILD": "1"})
    assert result.returncode != 0
    assert not any(command[0] == "sudo" and "--payload" in command for command in calls(base))


def test_existing_output_is_not_overwritten(fake_tools):
    base, _ = fake_tools
    output = base / "output"
    output.mkdir()
    (output / "keep").write_text("original")
    result = invoke_installer(fake_tools)
    assert result.returncode != 0
    assert (output / "keep").read_text() == "original"
    assert not any(command[:2] == ["cargo", "build"] for command in calls(base))


def test_proposed_manifest_keeps_cargo_artifact_identities(tmp_path):
    spec = importlib.util.spec_from_file_location("build_install_test", ROOT / "scripts/build_install.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    for name in builder.system_install.PAYLOAD_FILES:
        (tmp_path / name).write_text("fixture")
    artifacts = {name: {"sha256": "a" * 64, "size": 123} for name in builder.BINARIES}
    manifest = builder.payload_manifest(tmp_path, artifacts)
    assert {name: manifest["files"][name] for name in builder.BINARIES} == artifacts
    assert manifest["files"]["fish"] == {
        "sha256": hashlib.sha256(b"fixture").hexdigest(), "size": len(b"fixture"),
    }


def test_builder_help_requires_independent_review():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/build_install.py"), "--help"],
        text=True, capture_output=True, check=True,
    )
    help_text = " ".join(result.stdout.split())
    assert "independently verify" in help_text
    assert "trusted" in help_text
