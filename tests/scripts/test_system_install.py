"""Exercise publication and removal without modifying system installation paths."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def installer():
    spec = importlib.util.spec_from_file_location("system_install", ROOT / "scripts/system_install.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def payload(tmp_path):
    source = tmp_path / "payload"
    source.mkdir()
    for name in ("l2solver", "l2solver-active", "l2solver-active-helper"):
        (source / name).write_text("#!/bin/sh\nprintf 'installed fixture\\n'\n")
        (source / name).chmod(0o755)
    for name in ("bash", "zsh", "fish", "README.md", "install.md", "NOTICE-JEMALLOC.txt", "receipt.json"):
        (source / name).write_text('{}' if name == "receipt.json" else name)
    return source


def test_install_upgrade_and_independent_uninstall(installer, payload, tmp_path):
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, False)
    binary = prefix / "bin/l2solver"
    assert subprocess.check_output([binary], cwd=tmp_path) == b"installed fixture\n"
    first = binary.resolve()
    installer.install(payload, prefix, False)
    assert binary.resolve() == first
    (payload / "l2solver").write_text("#!/bin/sh\nprintf 'upgraded fixture\\n'\n")
    installer.install(payload, prefix, False)
    assert subprocess.check_output([binary]) == b"upgraded fixture\n"
    # The copied uninstaller must be sufficient after the checkout is unavailable
    copied = prefix / "bin/l2solver-uninstall"
    assert b"def uninstall" in copied.read_bytes()
    installer.uninstall(prefix)
    assert not binary.exists()
    assert not (prefix / "bin/l2solver-active-helper").exists()
    assert not (prefix / "share/l2solver").exists()


@pytest.mark.parametrize("kind", ["file", "symlink", "parent_symlink"])
def test_foreign_paths_are_preserved(installer, payload, tmp_path, kind):
    prefix = tmp_path / "prefix"
    prefix.mkdir()
    foreign = tmp_path / "foreign"
    foreign.write_text("keep")
    if kind == "parent_symlink":
        (prefix / "bin").symlink_to(tmp_path, target_is_directory=True)
    else:
        (prefix / "bin").mkdir()
        target = prefix / "bin/l2solver"
        if kind == "file":
            target.write_text("keep")
        else:
            target.symlink_to(foreign)
    with pytest.raises((ValueError, OSError)):
        installer.install(payload, prefix, False)
    assert foreign.read_text() == "keep"
    assert not (prefix / "share/l2solver/current").exists()


def test_modified_install_refuses_upgrade_and_removal(installer, payload, tmp_path):
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, False)
    (prefix / "bin/l2solver").resolve().write_text("local edit")
    for action in (lambda: installer.install(payload, prefix, False), lambda: installer.uninstall(prefix)):
        with pytest.raises(ValueError, match="modified"):
            action()
    assert (prefix / "bin/l2solver").read_text() == "local edit"


def test_failed_switch_keeps_old_pair(installer, payload, tmp_path, monkeypatch):
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, False)
    old = (prefix / "bin/l2solver").resolve()
    (payload / "l2solver").write_text("new")
    replace = installer.os.replace

    def fail_switch(source, destination):
        if Path(destination).name == "current":
            raise PermissionError("switch denied")
        return replace(source, destination)

    monkeypatch.setattr(installer.os, "replace", fail_switch)
    with pytest.raises(PermissionError):
        installer.install(payload, prefix, False)
    assert (prefix / "bin/l2solver").resolve() == old
    installer.uninstall(prefix)


def test_manifest_traversal_never_deletes_foreign_file(installer, payload, tmp_path):
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, False)
    foreign = tmp_path / "foreign"
    foreign.write_text("keep")
    manifest = prefix / "share/l2solver/manifest.json"
    data = json.loads(manifest.read_text())
    data["generations"]["../../.."]= {}
    manifest.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        installer.uninstall(prefix)
    assert foreign.read_text() == "keep"


def test_capability_failure_does_not_publish(installer, payload, tmp_path, monkeypatch):
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, False)
    old = (prefix / "bin/l2solver").resolve()

    def reject(_):
        raise OSError("file capabilities unavailable")

    monkeypatch.setattr(installer, "enable_capability", reject)
    with pytest.raises(OSError, match="capabilities unavailable"):
        installer.install(payload, prefix, True)
    assert (prefix / "bin/l2solver").resolve() == old
    installer.uninstall(prefix)


def test_uninstaller_requires_root_before_reading_paths(tmp_path):
    result = subprocess.run(["python3", ROOT / "scripts/system_install.py", "--uninstall", "--prefix", tmp_path], capture_output=True)
    if os.geteuid() != 0:
        assert result.returncode != 0
        assert b"root" in result.stderr


def test_uninstaller_infers_prefix_without_checkout(installer, payload, tmp_path):
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, False)
    script = prefix / "bin/l2solver-uninstall"
    # Root admission is tested separately; parser defaults must remain relocatable
    assert installer.installed_prefix(script) == prefix


def test_explicit_active_policy_only_targets_helper(installer, payload, tmp_path, monkeypatch):
    enabled = []
    monkeypatch.setattr(installer, "enable_capability", lambda path: enabled.append(path.name))
    installer.install(payload, tmp_path / "prefix", True)
    assert enabled == ["l2solver-active-helper"]


def test_default_reinstall_revokes_previous_helper_privilege(installer, payload, tmp_path, monkeypatch):
    prefix = tmp_path / "prefix"
    monkeypatch.setattr(installer, "enable_capability", lambda _: None)
    installer.install(payload, prefix, True)
    revoked = []
    monkeypatch.setattr(installer, "disable_capability", lambda path: revoked.append(path))
    installer.install(payload, prefix, False)
    assert revoked
    assert all(path.name == "l2solver-active-helper" for path in revoked)


def test_reinstall_of_earlier_generation_switches_complete_set(installer, payload, tmp_path):
    prefix = tmp_path / "prefix"
    original = (payload / "l2solver").read_bytes()
    installer.install(payload, prefix, False)
    old = (prefix / "bin/l2solver").resolve()
    (payload / "l2solver").write_text("second version")
    installer.install(payload, prefix, False)
    (payload / "l2solver").write_bytes(original)
    installer.install(payload, prefix, False)
    assert (prefix / "bin/l2solver").resolve() == old
