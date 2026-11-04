"""Exercise bounded generation retention and explicit retirement."""
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from test_system_install import installer, legacy_installation, payload


def install_version(installer, payload, prefix, version, *, active=False):
    (payload / "receipt.json").write_text(f'{{"version": "{version}"}}\n')
    installer.install(payload, prefix, active)
    return (prefix / "bin/l2solver").resolve().parent


def link_targets(installer, prefix):
    return {
        name: os.readlink(prefix / name)
        for name in installer.read_manifest(prefix)["links"]
    }


def test_default_retention_limit_allows_a_distinct_upgrade(installer):
    assert isinstance(installer.MAX_GENERATIONS, int)
    assert installer.MAX_GENERATIONS >= 2


def test_full_retention_refuses_new_generation_without_changing_installation(
    installer, payload, tmp_path, monkeypatch,
):
    monkeypatch.setattr(installer, "MAX_GENERATIONS", 2, raising=False)
    capabilities = {}
    capability_operations = []

    def enable(helper):
        capability_operations.append(("enable", helper))
        capabilities[helper] = b"enabled"

    def disable(helper):
        capability_operations.append(("disable", helper))
        capabilities.pop(helper, None)

    monkeypatch.setattr(installer, "read_capability", lambda helper: capabilities.get(helper))
    monkeypatch.setattr(installer, "enable_capability", enable)
    monkeypatch.setattr(installer, "disable_capability", disable)
    prefix = tmp_path / "prefix"
    old = install_version(installer, payload, prefix, "old")
    current = install_version(installer, payload, prefix, "current", active=True)
    manifest = prefix / "share/l2solver/manifest.json"
    original_manifest = manifest.read_bytes()
    original_links = link_targets(installer, prefix)
    original_capabilities = capabilities.copy()
    capability_operations.clear()
    (payload / "receipt.json").write_text('{"version": "new"}\n')

    # A refused upgrade must not change the selected helper's authority
    with pytest.raises(ValueError, match="(?i)(limit|retir)"):
        installer.install(payload, prefix, False)

    assert manifest.read_bytes() == original_manifest
    assert link_targets(installer, prefix) == original_links
    assert (prefix / "bin/l2solver").resolve().parent == current
    assert old.is_dir() and current.is_dir()
    assert capabilities == original_capabilities
    assert capability_operations == []
    assert not list((prefix / "share").glob(".l2solver-*"))


def test_reinstalling_current_and_old_generations_succeeds_at_limit(
    installer, payload, tmp_path, monkeypatch,
):
    monkeypatch.setattr(installer, "MAX_GENERATIONS", 2, raising=False)
    prefix = tmp_path / "prefix"
    old = install_version(installer, payload, prefix, "old")
    current = install_version(installer, payload, prefix, "current")

    # Reusing owned bytes does not need an additional retention slot
    assert install_version(installer, payload, prefix, "current") == current
    assert install_version(installer, payload, prefix, "old") == old
    assert set(installer.read_manifest(prefix)["generations"]) == {old.name, current.name}
    assert (old / "l2solver-active-helper").is_file()
    assert (current / "l2solver-active-helper").is_file()


def test_retirement_revokes_inactive_helpers_and_preserves_current_generation(
    installer, payload, tmp_path, monkeypatch,
):
    monkeypatch.setattr(installer, "MAX_GENERATIONS", 3, raising=False)
    prefix = tmp_path / "prefix"
    old = install_version(installer, payload, prefix, "old")
    older = install_version(installer, payload, prefix, "older")
    current = install_version(installer, payload, prefix, "current")
    original_links = link_targets(installer, prefix)
    # Model privileged helpers without requiring root for the test
    capabilities = {
        old / "l2solver-active-helper": b"enabled",
        older / "l2solver-active-helper": b"enabled",
        current / "l2solver-active-helper": b"enabled",
    }
    revoked = []

    def record_revocation(helper):
        # The inode must still exist when its file capability is removed
        assert helper.is_file()
        revoked.append(helper)
        capabilities.pop(helper, None)

    monkeypatch.setattr(installer, "read_capability", lambda helper: capabilities.get(helper))
    monkeypatch.setattr(installer, "disable_capability", record_revocation)
    installer.retire_inactive(prefix)

    assert set(revoked) == {
        old / "l2solver-active-helper",
        older / "l2solver-active-helper",
    }
    assert not old.exists() and not older.exists()
    assert (current / "l2solver-active-helper").is_file()
    assert (prefix / "bin/l2solver").resolve().parent == current
    assert link_targets(installer, prefix) == original_links
    assert set(installer.read_manifest(prefix)["generations"]) == {current.name}
    assert capabilities == {current / "l2solver-active-helper": b"enabled"}

    # A second retirement has no inactive generation to remove
    installer.retire_inactive(prefix)
    assert (current / "l2solver").is_file()
    next_generation = install_version(installer, payload, prefix, "next")
    assert set(installer.read_manifest(prefix)["generations"]) == {
        current.name, next_generation.name,
    }


def test_retirement_removes_recorded_legacy_files(installer, payload, tmp_path):
    prefix = tmp_path / "prefix"
    legacy = legacy_installation(installer, payload, prefix)
    current = install_version(installer, payload, prefix, "current")

    installer.retire_inactive(prefix)

    assert not legacy.exists()
    assert (current / "l2solver").is_file()
    assert set(installer.read_manifest(prefix)["generations"]) == {current.name}


def test_retirement_refuses_unrecognized_files_before_changing_anything(
    installer, payload, tmp_path, monkeypatch,
):
    prefix = tmp_path / "prefix"
    old = install_version(installer, payload, prefix, "old")
    current = install_version(installer, payload, prefix, "current")
    manifest = prefix / "share/l2solver/manifest.json"
    before = manifest.read_bytes()
    foreign = old / "unmanaged"
    foreign.write_text("keep")
    revoked = []
    monkeypatch.setattr(installer, "disable_capability", revoked.append)

    with pytest.raises(ValueError, match="modified"):
        installer.retire_inactive(prefix)

    assert foreign.read_text() == "keep"
    assert (old / "l2solver-active-helper").is_file()
    assert (prefix / "bin/l2solver").resolve().parent == current
    assert manifest.read_bytes() == before
    assert revoked == []


def test_failed_capability_revocation_keeps_inactive_generation_for_retry(
    installer, payload, tmp_path, monkeypatch,
):
    prefix = tmp_path / "prefix"
    old = install_version(installer, payload, prefix, "old")
    current = install_version(installer, payload, prefix, "current")
    old_helper = old / "l2solver-active-helper"
    capabilities = {old_helper: b"enabled"}

    def refuse_revocation(helper):
        if helper == old_helper:
            raise PermissionError("capability revocation denied")
        capabilities.pop(helper, None)

    monkeypatch.setattr(installer, "read_capability", lambda helper: capabilities.get(helper))
    monkeypatch.setattr(installer, "disable_capability", lambda helper: capabilities.pop(helper, None))
    with monkeypatch.context() as fault:
        fault.setattr(installer, "disable_capability", refuse_revocation)
        with pytest.raises(PermissionError, match="capability revocation denied"):
            installer.retire_inactive(prefix)

    assert old_helper.is_file() and old_helper in capabilities
    assert (prefix / "bin/l2solver").resolve().parent == current
    installer.retire_inactive(prefix)
    assert not old.exists()
    assert not capabilities
    assert set(installer.read_manifest(prefix)["generations"]) == {current.name}


@pytest.mark.parametrize("interrupt_on", ["first_file", "helper"])
def test_interrupted_retirement_resumes_after_one_file_was_removed(
    installer, payload, tmp_path, monkeypatch, interrupt_on,
):
    prefix = tmp_path / "prefix"
    old = install_version(installer, payload, prefix, "old")
    current = install_version(installer, payload, prefix, "current")
    removed = []
    unlink = os.unlink
    remove = os.remove

    def interrupt_after_removal(operation):
        def checked_unlink(path, *args, **kwargs):
            name = Path(os.fsdecode(path)).name
            result = operation(path, *args, **kwargs)
            # The deletion succeeded but the caller did not receive its result
            if name in installer.FILES and (
                interrupt_on == "first_file" or name == "l2solver-active-helper"
            ):
                removed.append(name)
                raise OSError("simulated retirement interruption")
            return result
        return checked_unlink

    with monkeypatch.context() as fault:
        fault.setattr(os, "unlink", interrupt_after_removal(unlink))
        fault.setattr(os, "remove", interrupt_after_removal(remove))
        with pytest.raises(OSError, match="simulated retirement interruption"):
            installer.retire_inactive(prefix)

    assert len(removed) == 1
    assert (prefix / "bin/l2solver").resolve().parent == current
    assert (current / "l2solver-active-helper").is_file()
    if interrupt_on == "helper":
        assert not (old / "l2solver-active-helper").exists()
    installer.retire_inactive(prefix)
    assert not old.exists()
    assert (current / "l2solver").is_file()
    assert set(installer.read_manifest(prefix)["generations"]) == {current.name}


def test_routine_upgrades_keep_generation_of_a_running_old_client(
    installer, payload, tmp_path, monkeypatch,
):
    monkeypatch.setattr(installer, "MAX_GENERATIONS", 3, raising=False)
    shutil.copyfile(shutil.which("sleep"), payload / "l2solver-active")
    prefix = tmp_path / "prefix"
    old = install_version(installer, payload, prefix, "old")
    client = subprocess.Popen([old / "l2solver-active", "60"])
    try:
        install_version(installer, payload, prefix, "second")
        install_version(installer, payload, prefix, "third")

        assert client.poll() is None
        # Derive the helper from the old process's executable path
        executable = Path(os.readlink(f"/proc/{client.pid}/exe"))
        assert executable == old / "l2solver-active"
        assert executable.with_name("l2solver-active-helper").is_file()
        assert old.name in installer.read_manifest(prefix)["generations"]
    finally:
        client.terminate()
        client.wait(timeout=5)


def test_quarantine_moves_corrupt_inactive_generation_without_removing_unknown_files(
    installer, payload, tmp_path, monkeypatch,
):
    prefix = tmp_path / "prefix"
    old = install_version(installer, payload, prefix, "old")
    current = install_version(installer, payload, prefix, "current")
    (old / "l2solver").write_text("locally changed")
    (old / "unrecognized").write_text("keep for inspection")
    revoked = []
    monkeypatch.setattr(installer, "disable_capability", lambda helper: revoked.append(helper))

    installer.quarantine_inactive(prefix, old.name)

    saved = prefix / "share/.l2solver-quarantine" / old.name
    assert not old.exists()
    assert (saved / "l2solver").read_text() == "locally changed"
    assert (saved / "unrecognized").read_text() == "keep for inspection"
    assert saved.stat().st_mode & 0o777 == 0o700
    assert revoked == [old / "l2solver-active-helper"]
    assert (prefix / "bin/l2solver").resolve().parent == current
    assert set(installer.read_manifest(prefix)["generations"]) == {current.name}


def test_quarantine_refuses_symlink_helper_without_touching_target(installer, payload, tmp_path):
    prefix = tmp_path / "prefix"
    old = install_version(installer, payload, prefix, "old")
    install_version(installer, payload, prefix, "current")
    foreign = tmp_path / "foreign"
    foreign.write_text("keep")
    (old / "l2solver-active-helper").unlink()
    (old / "l2solver-active-helper").symlink_to(foreign)
    with pytest.raises(ValueError, match="modified|unsafe"):
        installer.quarantine_inactive(prefix, old.name)
    assert foreign.read_text() == "keep"
    assert old.is_dir()


def test_quarantine_refuses_to_mutate_when_current_generation_is_corrupt(installer, payload, tmp_path):
    prefix = tmp_path / "prefix"
    old = install_version(installer, payload, prefix, "old")
    current = install_version(installer, payload, prefix, "current")
    (current / "l2solver").write_text("modified current")
    original_mode = old.stat().st_mode & 0o777
    with pytest.raises(ValueError, match="modified"):
        installer.quarantine_inactive(prefix, old.name)
    assert old.is_dir() and old.stat().st_mode & 0o777 == original_mode


def test_retirement_option_does_not_run_uninstall(installer, tmp_path, monkeypatch):
    prefix = tmp_path / "prefix"
    calls = []
    monkeypatch.setattr(installer.os, "geteuid", lambda: 0)
    monkeypatch.setattr(installer, "safe_parents", lambda _: None)
    monkeypatch.setattr(installer, "retire_inactive", lambda path: calls.append(path))
    monkeypatch.setattr(installer, "uninstall", lambda _: pytest.fail("unexpected uninstall"))
    monkeypatch.setattr(installer.sys, "argv", ["l2solver-uninstall", "--prefix", str(prefix), "--retire-inactive"])
    installer.main()
    assert calls == [prefix]


def test_revoke_active_works_when_retention_is_full(installer, payload, tmp_path, monkeypatch):
    monkeypatch.setattr(installer, "MAX_GENERATIONS", 2)
    capabilities = {}
    monkeypatch.setattr(installer, "read_capability", lambda path: capabilities.get(path))
    monkeypatch.setattr(installer, "enable_capability", lambda path: capabilities.__setitem__(path, b"enabled"))
    monkeypatch.setattr(installer, "disable_capability", lambda path: capabilities.pop(path, None))
    prefix = tmp_path / "prefix"
    install_version(installer, payload, prefix, "old")
    current = install_version(installer, payload, prefix, "current", active=True)
    helper = current / "l2solver-active-helper"
    assert capabilities[helper] == b"enabled"
    installer.revoke_active(prefix)
    assert helper not in capabilities
    assert (prefix / "bin/l2solver").resolve().parent == current


def test_retirement_recovery_rejects_missing_current_file(installer, payload, tmp_path, monkeypatch):
    prefix = tmp_path / "prefix"
    old = install_version(installer, payload, prefix, "old")
    current = install_version(installer, payload, prefix, "current")
    unlink = Path.unlink

    def fail_old_deletion(path, *args, **kwargs):
        if path.parent == old:
            raise OSError("injected deletion failure")
        return unlink(path, *args, **kwargs)

    with monkeypatch.context() as fault:
        fault.setattr(Path, "unlink", fail_old_deletion)
        with pytest.raises(OSError, match="injected deletion failure"):
            installer.retire_inactive(prefix)
    (current / "l2solver").unlink()
    with pytest.raises(ValueError, match="modified"):
        installer.retire_inactive(prefix)
    assert old.is_dir()


def test_retention_limit_bounds_installed_bytes_and_hash_work_for_fixed_payload_sizes(
    installer, payload, tmp_path, monkeypatch,
):
    limit = 4
    monkeypatch.setattr(installer, "MAX_GENERATIONS", limit)
    prefix = tmp_path / "prefix"
    sizes = []
    for version in range(limit):
        generation = install_version(installer, payload, prefix, f"version-{version}")
        sizes.append(sum(path.stat().st_size for path in generation.iterdir()))
    base = prefix / "share/l2solver"
    before = sum(path.stat().st_size for generation in base.iterdir() if generation.is_dir() and not generation.is_symlink() for path in generation.iterdir())
    with pytest.raises(ValueError, match="generation limit"):
        install_version(installer, payload, prefix, "version-4")
    after = sum(path.stat().st_size for generation in base.iterdir() if generation.is_dir() and not generation.is_symlink() for path in generation.iterdir())
    assert after == before == sum(sizes)
    assert after <= limit * max(sizes)

    hashed = []
    digest = installer.digest

    def count_hashes(path):
        hashed.append(path)
        return digest(path)

    monkeypatch.setattr(installer, "digest", count_hashes)
    assert len(installer.read_manifest(prefix)["generations"]) == limit
    assert len(hashed) == limit * len(installer.FILES)


def test_revoke_active_does_not_depend_on_intact_inactive_generation(
    installer, payload, tmp_path, monkeypatch,
):
    capabilities = {}
    monkeypatch.setattr(installer, "read_capability", lambda path: capabilities.get(path))
    monkeypatch.setattr(installer, "enable_capability", lambda path: capabilities.__setitem__(path, b"enabled"))
    monkeypatch.setattr(installer, "disable_capability", lambda path: capabilities.pop(path, None))
    prefix = tmp_path / "prefix"
    old = install_version(installer, payload, prefix, "old")
    current = install_version(installer, payload, prefix, "current", active=True)
    (old / "l2solver").write_text("damaged inactive executable")
    helper = current / "l2solver-active-helper"
    assert capabilities[helper] == b"enabled"
    installer.revoke_active(prefix)
    assert helper not in capabilities


def test_unrelated_install_does_not_resume_retirement_under_restarted_old_client(
    installer, payload, tmp_path, monkeypatch,
):
    shutil.copyfile(shutil.which("sleep"), payload / "l2solver-active")
    prefix = tmp_path / "prefix"
    old = install_version(installer, payload, prefix, "old")
    install_version(installer, payload, prefix, "current")
    store = installer.store_transaction

    def interrupt_after_retirement_intent(path, data):
        store(path, data)
        if data["op"] == "retire" and data["phase"] == "prepared":
            raise OSError("interrupted after retirement intent")

    with monkeypatch.context() as fault:
        fault.setattr(installer, "store_transaction", interrupt_after_retirement_intent)
        with pytest.raises(OSError, match="interrupted after retirement intent"):
            installer.retire_inactive(prefix)
    client = subprocess.Popen([old / "l2solver-active", "60"])
    try:
        with pytest.raises(ValueError, match="retire-inactive"):
            installer.install(payload, prefix, False)
        assert client.poll() is None
        assert (old / "l2solver-active-helper").is_file()
    finally:
        client.terminate()
        client.wait(timeout=5)
    installer.retire_inactive(prefix)
    assert not old.exists()


def test_reselecting_retained_generation_keeps_its_directory_accessible_before_switch(
    installer, payload, tmp_path, monkeypatch,
):
    prefix = tmp_path / "prefix"
    old = install_version(installer, payload, prefix, "old")
    install_version(installer, payload, prefix, "current")
    (payload / "receipt.json").write_text('{"version": "old"}\n')
    link = Path.symlink_to
    observed = []

    def inspect_before_switch(path, target, *args, **kwargs):
        if path.name == ".current-new":
            observed.append(old.stat().st_mode & 0o777)
        return link(path, target, *args, **kwargs)

    monkeypatch.setattr(Path, "symlink_to", inspect_before_switch)
    installer.install(payload, prefix, False)
    assert observed == [0o755]
    assert (old / "l2solver-active-helper").is_file()


def test_active_reselection_requires_retirement_and_fresh_helper_inode(installer, payload, tmp_path, monkeypatch):
    capabilities = {}
    monkeypatch.setattr(installer, "read_capability", lambda path: capabilities.get(path))
    monkeypatch.setattr(installer, "enable_capability", lambda path: capabilities.__setitem__(path, b"enabled"))
    monkeypatch.setattr(installer, "disable_capability", lambda path: capabilities.pop(path, None))
    prefix = tmp_path / "prefix"
    old = install_version(installer, payload, prefix, "old", active=True)
    current = install_version(installer, payload, prefix, "current", active=True)
    old_helper = old / "l2solver-active-helper"
    current_helper = current / "l2solver-active-helper"
    old_fd = os.open(old_helper, os.O_RDONLY)
    try:
        old_manifest = (prefix / "share/l2solver/manifest.json").read_bytes()
        old_capabilities = capabilities.copy()
        (payload / "receipt.json").write_text('{"version": "old"}\n')
        with pytest.raises(ValueError, match="--retire-inactive"):
            installer.install(payload, prefix, True)
        assert (prefix / "share/l2solver/manifest.json").read_bytes() == old_manifest
        assert (prefix / "bin/l2solver").resolve().parent == current
        assert capabilities == old_capabilities == {current_helper: b"enabled"}
        assert not list((prefix / "share").glob(".l2solver-*"))

        # Explicit retirement releases the old inode before making a fresh one
        installer.retire_inactive(prefix)
        assert os.fstat(old_fd).st_nlink == 0
        selected = install_version(installer, payload, prefix, "old", active=True)
        fresh_helper = selected / "l2solver-active-helper"
        assert os.stat(fresh_helper).st_ino != os.fstat(old_fd).st_ino
        assert capabilities == {fresh_helper: b"enabled"}
    finally:
        os.close(old_fd)


def test_reenabling_current_active_generation_remains_available(installer, payload, tmp_path, monkeypatch):
    capabilities = {}
    monkeypatch.setattr(installer, "read_capability", lambda path: capabilities.get(path))
    monkeypatch.setattr(installer, "enable_capability", lambda path: capabilities.__setitem__(path, b"enabled"))
    monkeypatch.setattr(installer, "disable_capability", lambda path: capabilities.pop(path, None))
    prefix = tmp_path / "prefix"
    current = install_version(installer, payload, prefix, "current", active=True)
    helper = current / "l2solver-active-helper"
    installer.revoke_active(prefix)
    assert helper not in capabilities
    assert install_version(installer, payload, prefix, "current", active=True) == current
    assert capabilities == {helper: b"enabled"}
