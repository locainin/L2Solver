"""Exercise publication and removal without modifying system installation paths."""
import hashlib
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
    for name in ("bash", "zsh", "fish", "NOTICE-JEMALLOC.txt", "receipt.json"):
        (source / name).write_text('{}' if name == "receipt.json" else name)
    return source


def legacy_installation(installer, payload, prefix):
    # Recreate the previous schema and file modes without relying on Git history
    names = (
        "l2solver", "l2solver-active", "l2solver-active-helper", "l2solver-uninstall",
        "bash", "zsh", "fish", "README.md", "install.md", "NOTICE-JEMALLOC.txt", "receipt.json",
    )
    base = prefix / "share/l2solver"
    directory = base / "legacy-fixture"
    directory.mkdir(parents=True)
    hashes = {}
    for name in names:
        if name == "l2solver-uninstall":
            contents = b"#!/bin/sh\nexit 0\n"
        elif name in ("README.md", "install.md"):
            contents = name.encode()
        else:
            contents = (payload / name).read_bytes()
        entry = directory / name
        entry.write_bytes(contents)
        entry.chmod(0o755 if name in (*installer.BINARIES, "l2solver-uninstall") else 0o644)
        hashes[name] = hashlib.sha256(contents).hexdigest()
    generation = hashlib.sha256(json.dumps([hashes, False], sort_keys=True).encode()).hexdigest()
    directory.rename(base / generation)
    directory = base / generation
    destinations = installer.links(prefix)
    for relative, target in destinations.items():
        link = prefix / relative
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(target)
    (base / "current").symlink_to(generation)
    manifest = base / "manifest.json"
    manifest.write_text(json.dumps({"schema": 1, "links": destinations, "generations": {generation: hashes}}))
    manifest.chmod(0o600)
    return directory


def test_legacy_generation_upgrades_without_docs_and_uninstalls_all_generations(installer, payload, tmp_path):
    prefix = tmp_path / "prefix"
    old = legacy_installation(installer, payload, prefix)

    installer.install(payload, prefix, False)

    current = (prefix / "bin/l2solver").resolve().parent
    assert current != old
    assert {entry.name for entry in current.iterdir()} == {
        "l2solver", "l2solver-active", "l2solver-active-helper", "l2solver-uninstall",
        "bash", "zsh", "fish", "NOTICE-JEMALLOC.txt", "receipt.json",
    }
    manifest = installer.read_manifest(prefix)
    assert set(manifest["generations"]) == {old.name, current.name}
    assert set(manifest["generations"][old.name]) == {entry.name for entry in old.iterdir()}
    assert set(manifest["generations"][current.name]) == {entry.name for entry in current.iterdir()}
    installer.uninstall(prefix)
    assert not (prefix / "share/l2solver").exists()
    assert not os.path.lexists(prefix / "bin/l2solver")


def test_legacy_generation_can_be_uninstalled_without_upgrade(installer, payload, tmp_path):
    prefix = tmp_path / "prefix"
    legacy_installation(installer, payload, prefix)
    installer.uninstall(prefix)
    assert not (prefix / "share/l2solver").exists()
    assert not os.path.lexists(prefix / "bin/l2solver")


def test_mixed_generations_keep_current_install_when_legacy_file_changes(installer, payload, tmp_path):
    prefix = tmp_path / "prefix"
    old = legacy_installation(installer, payload, prefix)
    installer.install(payload, prefix, False)
    current = (prefix / "bin/l2solver").resolve()
    (old / "README.md").write_text("modified")

    with pytest.raises(ValueError, match="modified"):
        installer.uninstall(prefix)
    assert (prefix / "bin/l2solver").resolve() == current
    assert current.is_file()
    assert old.is_dir()


@pytest.mark.parametrize("damage", ["missing_readme", "missing_install", "extra_manifest", "extra_file", "changed_file", "mode", "symlink", "invalid_hashes"])
def test_unsafe_legacy_generation_blocks_upgrade_and_uninstall(installer, payload, tmp_path, damage):
    prefix = tmp_path / "prefix"
    directory = legacy_installation(installer, payload, prefix)
    manifest = prefix / "share/l2solver/manifest.json"
    data = json.loads(manifest.read_text())
    hashes = data["generations"][directory.name]
    if damage in ("missing_readme", "missing_install"):
        name = "README.md" if damage == "missing_readme" else "install.md"
        del hashes[name]
        (directory / name).unlink()
        manifest.write_text(json.dumps(data))
    elif damage == "extra_manifest":
        hashes["foreign"] = hashlib.sha256(b"keep").hexdigest()
        (directory / "foreign").write_bytes(b"keep")
        manifest.write_text(json.dumps(data))
    elif damage == "extra_file":
        (directory / "foreign").write_bytes(b"keep")
    elif damage == "changed_file":
        (directory / "README.md").write_text("modified")
    elif damage == "mode":
        (directory / "README.md").chmod(0o600)
    elif damage == "symlink":
        (directory / "README.md").unlink()
        (directory / "README.md").symlink_to(tmp_path / "foreign")
    else:
        data["generations"][directory.name] = list(hashes)
        manifest.write_text(json.dumps(data))
    before = manifest.read_bytes()
    for action in (lambda: installer.install(payload, prefix, False), lambda: installer.uninstall(prefix)):
        with pytest.raises(ValueError):
            action()
        assert manifest.read_bytes() == before
        assert (prefix / "bin/l2solver").is_symlink()
        assert directory.exists()
    if damage in ("extra_manifest", "extra_file"):
        assert (directory / "foreign").read_bytes() == b"keep"


def test_failed_new_payload_keeps_legacy_generation(installer, payload, tmp_path):
    prefix = tmp_path / "prefix"
    old = legacy_installation(installer, payload, prefix)
    (payload / "NOTICE-JEMALLOC.txt").unlink()
    with pytest.raises(ValueError, match="invalid payload file"):
        installer.install(payload, prefix, False)
    assert (prefix / "bin/l2solver").resolve().parent == old
    assert set(installer.read_manifest(prefix)["generations"]) == {old.name}


def test_fresh_install_needs_no_documentation(installer, payload, tmp_path):
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, False)
    current = (prefix / "bin/l2solver").resolve().parent
    assert (current / "NOTICE-JEMALLOC.txt").is_file()
    assert (current / "receipt.json").is_file()
    assert not (current / "README.md").exists()
    assert not (current / "install.md").exists()
    installer.uninstall(prefix)


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


@pytest.mark.parametrize("first_install", [True, False])
def test_interrupt_after_pointer_switch_keeps_new_generation_and_manifest(installer, payload, tmp_path, monkeypatch, first_install):
    prefix = tmp_path / "prefix"
    old = None
    if not first_install:
        installer.install(payload, prefix, False)
        old = (prefix / "bin/l2solver").resolve()
    (payload / "l2solver").write_text("new executable")
    replace = installer.os.replace

    def interrupt_after_switch(source, destination):
        replace(source, destination)
        if Path(destination).name == "current":
            raise KeyboardInterrupt("interrupted after pointer switch")

    monkeypatch.setattr(installer.os, "replace", interrupt_after_switch)
    with pytest.raises(KeyboardInterrupt, match="interrupted after pointer switch"):
        installer.install(payload, prefix, False)
    assert (prefix / "bin/l2solver").resolve() != old
    assert (prefix / "bin/l2solver").read_text() == "new executable"
    assert installer.read_manifest(prefix) is not None


def test_unknown_switch_outcome_keeps_both_generations_for_inspection(installer, payload, tmp_path, monkeypatch):
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, False)
    old = (prefix / "bin/l2solver").resolve()
    (payload / "l2solver").write_text("new executable")
    replace = installer.os.replace
    readlink = installer.os.readlink
    switched = False

    def interrupt_after_switch(source, destination):
        nonlocal switched
        replace(source, destination)
        if Path(destination).name == "current":
            switched = True
            raise OSError("switch result lost")

    def fail_readlink(path, *args, **kwargs):
        if switched and Path(path).name == "current":
            raise PermissionError("current generation cannot be read")
        return readlink(path, *args, **kwargs)

    with monkeypatch.context() as fault:
        fault.setattr(installer.os, "replace", interrupt_after_switch)
        fault.setattr(installer.os, "readlink", fail_readlink)
        with pytest.raises(ValueError, match="publication outcome unknown"):
            installer.install(payload, prefix, False)
    assert old.is_file()
    assert (prefix / "bin/l2solver").read_text() == "new executable"
    assert len(installer.read_manifest(prefix)["generations"]) == 2


def test_reinstall_current_generation_does_not_replace_current_pointer(installer, payload, tmp_path, monkeypatch):
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, False)
    current = (prefix / "bin/l2solver").resolve()
    replace = installer.os.replace

    def refuse_pointer_replacement(source, destination):
        if Path(destination).name == "current":
            pytest.fail("current pointer did not need replacement")
        return replace(source, destination)

    monkeypatch.setattr(installer.os, "replace", refuse_pointer_replacement)
    installer.install(payload, prefix, False)
    assert (prefix / "bin/l2solver").resolve() == current


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


def force_unrevoked_generation(installer, payload, prefix, monkeypatch, descriptors=None):
    retained = []
    revoke = installer.disable_capability

    def fail_after_enabling(helper):
        # Verification may fail after the helper acquired file authority
        retained.append(helper)
        if descriptors is not None:
            descriptors.append(os.open(helper, os.O_RDONLY))
        raise ValueError("capability verification failed")

    def fail_revoke(helper):
        if retained and helper == retained[0]:
            raise PermissionError("capability revocation denied")
        revoke(helper)

    with monkeypatch.context() as fault:
        fault.setattr(installer, "enable_capability", fail_after_enabling)
        fault.setattr(installer, "disable_capability", fail_revoke)
        with pytest.raises(ValueError, match="rollback incomplete.*revocation denied") as raised:
            installer.install(payload, prefix, True)
    return retained[0], str(raised.value)


@pytest.mark.parametrize("first_install", [True, False])
def test_failed_capability_revocation_keeps_owned_helper_and_manifest(
    installer, payload, tmp_path, monkeypatch, first_install,
):
    prefix = tmp_path / "prefix"
    old = None
    if not first_install:
        installer.install(payload, prefix, False)
        old = (prefix / "bin/l2solver").resolve()
        (payload / "l2solver").write_text("new executable")
    descriptors = []
    try:
        helper, diagnostic = force_unrevoked_generation(installer, payload, prefix, monkeypatch, descriptors)
        manifest_path = prefix / "share/l2solver/manifest.json"
        manifest = json.loads(manifest_path.read_text())
        assert str(helper) in diagnostic
        assert helper.is_file() and os.fstat(descriptors[0]).st_nlink == 1
        assert helper.parent.stat().st_mode & 0o777 == 0o700
        assert helper.parent.name in manifest["generations"]
        assert installer.digest(helper) == manifest["generations"][helper.parent.name][helper.name]
        if first_install:
            assert not os.path.lexists(prefix / "share/l2solver/current")
            assert all(os.path.lexists(prefix / path) for path in manifest["links"])
        else:
            assert (prefix / "bin/l2solver").resolve() == old
            assert installer.read_manifest(prefix) == manifest
            installer.uninstall(prefix)
            assert not helper.exists()
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def prepare_quarantined_generation(installer, payload, prefix, monkeypatch):
    original = (payload / "l2solver").read_bytes()
    installer.install(payload, prefix, False)
    old = (prefix / "bin/l2solver").resolve()
    (payload / "l2solver").write_text("new executable")
    with monkeypatch.context() as setup:
        setup.setattr(installer, "enable_capability", lambda _: None)
        installer.install(payload, prefix, True)
    helper = (prefix / "bin/l2solver-active-helper").resolve()
    (payload / "l2solver").write_bytes(original)
    installer.install(payload, prefix, False)
    (payload / "l2solver").write_text("new executable")
    helper.parent.chmod(0o700)
    return old, helper


def test_retained_quarantined_generation_requires_retirement_before_active_selection(
    installer, payload, tmp_path, monkeypatch,
):
    prefix = tmp_path / "prefix"
    old, helper = prepare_quarantined_generation(installer, payload, prefix, monkeypatch)
    monkeypatch.setattr(installer, "enable_capability", lambda _: pytest.fail("retained helper must not be enabled"))
    with pytest.raises(ValueError, match="--retire-inactive"):
        installer.install(payload, prefix, True)
    assert (prefix / "bin/l2solver").resolve() == old
    assert helper.parent.stat().st_mode & 0o777 == 0o700
    installer.uninstall(prefix)


def test_failed_revoke_after_failed_switch_removes_temporary_pointer(installer, payload, tmp_path, monkeypatch):
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, False)
    old = (prefix / "bin/l2solver").resolve()
    (payload / "l2solver").write_text("new executable")
    selected = []
    revoke = installer.disable_capability
    replace = installer.os.replace

    def enable(helper):
        selected.append(helper)

    def fail_revoke(helper):
        if selected and helper == selected[0]:
            raise PermissionError("capability revocation denied")
        revoke(helper)

    def fail_switch(source, destination):
        if Path(destination).name == "current":
            raise PermissionError("switch denied")
        return replace(source, destination)

    with monkeypatch.context() as fault:
        fault.setattr(installer, "enable_capability", enable)
        fault.setattr(installer, "disable_capability", fail_revoke)
        fault.setattr(installer.os, "replace", fail_switch)
        with pytest.raises(ValueError, match="switch denied; rollback incomplete.*revocation denied"):
            installer.install(payload, prefix, True)
    assert (prefix / "bin/l2solver").resolve() == old
    assert selected[0].parent.stat().st_mode & 0o777 == 0o700
    assert not os.path.lexists(prefix / "share/l2solver/.current-new")
    assert selected[0].parent.name in installer.read_manifest(prefix)["generations"]
    installer.uninstall(prefix)


def test_old_helper_revocation_failure_preserves_current_pair(installer, payload, tmp_path, monkeypatch):
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, False)
    old_binary = (prefix / "bin/l2solver").resolve()
    old_helper = (prefix / "bin/l2solver-active-helper").resolve()
    (payload / "l2solver").write_text("new executable")
    revoke = installer.disable_capability

    def deny_old_helper(path):
        if path == old_helper:
            raise PermissionError("old helper capability cannot be removed")
        revoke(path)

    monkeypatch.setattr(installer, "disable_capability", deny_old_helper)
    with pytest.raises(PermissionError, match="old helper capability"):
        installer.install(payload, prefix, False)
    assert (prefix / "bin/l2solver").resolve() == old_binary
    assert (prefix / "bin/l2solver-active-helper").resolve() == old_helper
    assert installer.read_manifest(prefix)["generations"].keys() == {old_binary.parent.name}


def test_interrupt_after_old_capability_removal_restores_original_xattr(installer, payload, tmp_path, monkeypatch):
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, False)
    old = (prefix / "bin/l2solver").resolve()
    old_helper = (prefix / "bin/l2solver-active-helper").resolve()
    (payload / "l2solver").write_text("new executable")
    capabilities = {old_helper: b"original capability"}

    def interrupt_after_remove(path):
        capabilities.pop(path, None)
        if path == old_helper:
            raise KeyboardInterrupt("interrupted immediately after removal")

    monkeypatch.setattr(installer, "read_capability", lambda path: capabilities.get(path))
    monkeypatch.setattr(installer, "disable_capability", interrupt_after_remove)
    monkeypatch.setattr(installer.os, "setxattr", lambda path, _name, value: capabilities.__setitem__(path, value))
    with pytest.raises(KeyboardInterrupt, match="interrupted immediately"):
        installer.install(payload, prefix, False)
    assert (prefix / "bin/l2solver").resolve() == old
    assert capabilities[old_helper] == b"original capability"


def test_sync_failure_after_switch_reports_new_pair_is_active(installer, payload, tmp_path, monkeypatch):
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, False)
    old = (prefix / "bin/l2solver").resolve()
    (payload / "l2solver").write_text("new executable")
    sync = installer.os.fsync

    def fail_new_generation_sync(fd):
        current = prefix / "share/l2solver/current"
        if (Path(f"/proc/self/fd/{fd}").resolve() == current.parent
                and current.resolve().name != old.parent.name):
            raise OSError("injected directory sync failure")
        return sync(fd)

    monkeypatch.setattr(installer.os, "fsync", fail_new_generation_sync)
    with pytest.raises(ValueError, match="new installation is active.*sync"):
        installer.install(payload, prefix, False)
    assert (prefix / "bin/l2solver").resolve() != old
    assert installer.read_manifest(prefix) is not None


def test_capability_restore_failure_is_reported_as_incomplete_rollback(installer, payload, tmp_path, monkeypatch):
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, False)
    old = (prefix / "bin/l2solver").resolve()
    (payload / "l2solver").write_text("new executable")
    replace = installer.os.replace

    def fail_switch(source, destination):
        if Path(destination).name == "current":
            raise PermissionError("pointer switch denied")
        return replace(source, destination)

    def fail_restore(_path, _value):
        raise PermissionError("capability restoration denied")

    monkeypatch.setattr(installer.os, "replace", fail_switch)
    monkeypatch.setattr(installer, "restore_capability", fail_restore)
    with pytest.raises(ValueError, match="pointer switch denied; rollback incomplete:.*capability restoration denied"):
        installer.install(payload, prefix, False)
    assert (prefix / "bin/l2solver").resolve() == old
    assert installer.read_manifest(prefix) is not None


def test_uninstaller_requires_root_before_reading_paths(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("requires an unprivileged caller to check root admission")
    result = subprocess.run(["python3", ROOT / "scripts/system_install.py", "--uninstall", "--prefix", tmp_path], capture_output=True)
    assert result.returncode != 0
    assert b"root" in result.stderr


def test_uninstaller_infers_prefix_from_installed_symlink(installer, payload, tmp_path):
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


def test_uninstall_revokes_helper_authority_before_removal(installer, payload, tmp_path, monkeypatch):
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, False)
    revoked = []

    def revoke(path):
        assert path.is_file()
        revoked.append(path)

    monkeypatch.setattr(installer, "disable_capability", revoke)
    installer.uninstall(prefix)
    assert len(revoked) == 1


def test_uninstall_preserves_recorded_completion_locations_when_directories_change(installer, payload, tmp_path):
    prefix = tmp_path / "prefix"
    # The first installation selects existing alternative completion directories
    for relative in ("etc/bash_completion.d", "share/zsh/functions/Completion", "share/fish/completions"):
        (prefix / relative).mkdir(parents=True)
    installer.install(payload, prefix, False)
    recorded = json.loads((prefix / "share/l2solver/manifest.json").read_text())["links"]
    # New preferred directories must not invalidate the already-owned links
    for relative in ("share/bash-completion/completions", "share/zsh/site-functions", "share/fish/vendor_completions.d"):
        (prefix / relative).mkdir(parents=True)
    installer.uninstall(prefix)
    assert all(not os.path.lexists(prefix / relative) for relative in recorded)
    assert not (prefix / "share/l2solver").exists()


def test_completion_destinations_use_validated_discovered_paths(installer, payload, tmp_path):
    prefix = tmp_path / "prefix"
    selected = {
        "bash": "share/custom/bash",
        "zsh": "share/custom/zsh",
        "fish": "share/custom/fish",
    }
    installer.install(payload, prefix, False, completion_dirs=selected)
    assert (prefix / "share/custom/bash/l2solver").is_symlink()
    assert (prefix / "share/custom/zsh/_l2solver").is_symlink()
    assert (prefix / "share/custom/fish/l2solver.fish").is_symlink()
    installer.uninstall(prefix)


@pytest.mark.parametrize("directory", ["../outside", "/tmp/outside", "share/l2solver", "share/l2solver/nested"])
def test_completion_destinations_reject_unsafe_or_owned_tree_paths(installer, payload, tmp_path, directory):
    prefix = tmp_path / "prefix"
    selected = {
        "bash": directory,
        "zsh": "share/zsh/site-functions",
        "fish": "share/fish/vendor_completions.d",
    }
    with pytest.raises(ValueError):
        installer.install(payload, prefix, False, completion_dirs=selected)
    assert not (prefix / "share/l2solver").exists()


@pytest.mark.parametrize("relative", ["../foreign/l2solver", "share/../foreign/l2solver", "share/l2solver/l2solver"])
def test_manifest_rejects_forged_completion_links_without_removing_files(installer, payload, tmp_path, relative):
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, False)
    manifest = prefix / "share/l2solver/manifest.json"
    data = json.loads(manifest.read_text())
    bash = next(item for item in data["links"] if item.endswith("/completions/l2solver"))
    data["links"][relative] = data["links"].pop(bash)
    manifest.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        installer.uninstall(prefix)
    assert os.path.lexists(prefix / bash)
    assert os.path.lexists(prefix / "bin/l2solver")


@pytest.mark.parametrize("values", [
    ["bash=share/bash", "zsh=share/zsh"],
    ["bash=share/bash", "zsh=share/zsh", "fish=share/fish", "fish=share/other"],
    ["bash=share/bash", "zsh=share/zsh", "other=share/fish"],
])
def test_completion_selection_rejects_missing_duplicate_or_unknown_shell(installer, values):
    with pytest.raises(ValueError):
        installer.parse_completion_dirs(values)


def test_root_equivalent_prefix_is_rejected_before_destination_access(installer, monkeypatch):
    monkeypatch.setattr(installer.os, "geteuid", lambda: 0)
    monkeypatch.setattr(installer.sys, "argv", ["system_install.py", "--check", "--prefix", "/tmp/.."])
    monkeypatch.setattr(installer, "safe_parents", lambda _: pytest.fail("destination inspected before prefix rejection"))
    with pytest.raises(SystemExit):
        installer.main()


def test_capability_verification_does_not_trust_path(installer, monkeypatch, tmp_path):
    helper = tmp_path / "l2solver-active-helper"
    commands = []
    monkeypatch.setattr(installer.shutil, "which", lambda _: str(tmp_path / "untrusted-getcap"))
    monkeypatch.setattr(installer.subprocess, "run", lambda command, **_: commands.append(command))

    def capture(command, **_):
        commands.append(command)
        return f"{helper} cap_net_raw=ep\n"

    monkeypatch.setattr(installer.subprocess, "check_output", capture)
    installer.enable_capability(helper)
    assert commands[1][0] in ("/usr/sbin/getcap", "/usr/bin/getcap")
