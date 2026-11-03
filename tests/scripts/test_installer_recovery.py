"""Exercise recovery after a publisher exits without running Python cleanup."""
import errno
import importlib.machinery
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from test_system_install import installer


ROOT = Path(__file__).resolve().parents[2]
PUBLISHER = ROOT / "scripts/system_install.py"


@pytest.fixture
def payload(tmp_path):
    result = tmp_path / "payload"
    result.mkdir()
    for name in ("l2solver", "l2solver-active", "l2solver-active-helper", "bash", "zsh", "fish", "NOTICE-JEMALLOC.txt", "receipt.json"):
        (result / name).write_text(name)
    return result


# Exit immediately after a real filesystem mutation, leaving no exception cleanup
CRASH_SCRIPT = r'''
import importlib.util
import os
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location("publisher", sys.argv[1])
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)
payload, prefix, action, point = Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], sys.argv[5]
replace, symlink, unlink, copyfile = os.replace, Path.symlink_to, Path.unlink, installer.copy_payload

def fail_after_replace(source, destination):
    replace(source, destination)
    if point == Path(destination).name:
        os._exit(91)

def fail_after_link(path, target, *args, **kwargs):
    symlink(path, target, *args, **kwargs)
    if point == "first-link" and path == prefix / "bin/l2solver":
        os._exit(91)

def fail_after_unlink(path, *args, **kwargs):
    unlink(path, *args, **kwargs)
    if action == "uninstall" and (str(path.relative_to(prefix)) == point or path.name == point):
        os._exit(91)

def fail_after_copy(source, destination, *args, **kwargs):
    result = copyfile(source, destination, *args, **kwargs)
    if point == "stage-copy":
        os._exit(91)
    return result

installer.os.replace = fail_after_replace
Path.symlink_to = fail_after_link
Path.unlink = fail_after_unlink
installer.copy_payload = fail_after_copy
if action == "install":
    installer.install(payload, prefix, False)
else:
    installer.uninstall(prefix)
raise SystemExit("fault did not occur")
'''


def crash(payload, prefix, action, point):
    result = subprocess.run(
        [sys.executable, "-c", CRASH_SCRIPT, str(PUBLISHER), str(payload), str(prefix), action, point],
        text=True, capture_output=True, check=False, timeout=20,
    )
    assert result.returncode == 91, result.stderr


@pytest.mark.parametrize("point", ["stage-copy", "first-link", "manifest.json", "current"])
def test_first_install_recovers_after_process_exit(installer, payload, tmp_path, point):
    prefix = tmp_path / "prefix"
    crash(payload, prefix, "install", point)
    installer.recover(prefix)
    if point == "current":
        assert (prefix / "bin/l2solver").read_text() == "l2solver"
    else:
        assert not os.path.lexists(prefix / "bin/l2solver")
    installer.install(payload, prefix, False)
    assert installer.read_manifest(prefix) is not None
    installer.uninstall(prefix)


@pytest.mark.parametrize("point", ["stage-copy", "manifest.json", "current"])
def test_upgrade_recovers_around_publication_point(installer, payload, tmp_path, point):
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, False)
    old = (prefix / "bin/l2solver").resolve()
    (payload / "l2solver").write_text("new client")
    crash(payload, prefix, "install", point)
    installer.recover(prefix)
    if point == "current":
        assert (prefix / "bin/l2solver").read_text() == "new client"
    else:
        assert (prefix / "bin/l2solver").resolve() == old
    installer.install(payload, prefix, False)
    assert (prefix / "bin/l2solver").read_text() == "new client"
    installer.uninstall(prefix)


@pytest.mark.parametrize("point", ["bin/l2solver", "current", "l2solver-active-helper", "manifest.json"])
def test_interrupted_uninstall_keeps_removal_entrypoint_and_resumes(installer, payload, tmp_path, point):
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, False)
    crash(payload, prefix, "uninstall", point)
    uninstaller = prefix / "bin/l2solver-uninstall"
    assert uninstaller.is_file()
    assert installer.installed_prefix(uninstaller) == prefix
    installer.uninstall(prefix)
    assert not os.path.lexists(uninstaller)
    assert not (prefix / "share/l2solver").exists()


def test_recovery_refuses_foreign_replacement_of_owned_link(installer, payload, tmp_path):
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, False)
    crash(payload, prefix, "uninstall", "bin/l2solver")
    foreign = prefix / "bin/l2solver"
    foreign.write_text("unrelated file")
    with pytest.raises(ValueError, match="modified|foreign"):
        installer.uninstall(prefix)
    assert foreign.read_text() == "unrelated file"
    assert (prefix / "bin/l2solver-uninstall").is_file()


def use_test_capabilities(installer):
    attribute = "user.l2solver-test-capability"

    def read(helper):
        try:
            return os.getxattr(helper, attribute)
        except OSError as error:
            if error.errno == errno.ENODATA:
                return None
            raise

    def disable(helper):
        if read(helper) is not None:
            os.removexattr(helper, attribute)

    def restore(helper, value):
        if value is None:
            disable(helper)
        else:
            os.setxattr(helper, attribute, value)

    installer.read_capability = read
    installer.disable_capability = disable
    installer.restore_capability = restore
    installer.enable_capability = lambda helper: os.setxattr(helper, attribute, b"enabled")


CAPABILITY_CRASH_SCRIPT = r'''
import importlib.util
import os
from pathlib import Path
import sys

sys.path.insert(0, sys.argv[1])
from test_installer_recovery import use_test_capabilities
spec = importlib.util.spec_from_file_location("publisher", sys.argv[2])
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)
use_test_capabilities(installer)
payload, prefix, point = Path(sys.argv[3]), Path(sys.argv[4]), sys.argv[5]
old = (prefix / "bin/l2solver-active-helper").resolve()
disable, enable = installer.disable_capability, installer.enable_capability

def interrupted_disable(helper):
    disable(helper)
    if point == "old-revoked" and helper == old:
        os._exit(92)

def interrupted_enable(helper):
    enable(helper)
    if point == "new-enabled":
        os._exit(92)

installer.disable_capability = interrupted_disable
installer.enable_capability = interrupted_enable
installer.install(payload, prefix, True)
raise SystemExit("fault did not occur")
'''


@pytest.mark.parametrize("point", ["old-revoked", "new-enabled"])
def test_upgrade_restores_old_capability_after_abrupt_exit(installer, payload, tmp_path, point):
    use_test_capabilities(installer)
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, True)
    old = (prefix / "bin/l2solver-active-helper").resolve()
    (payload / "l2solver").write_text("new client")
    result = subprocess.run(
        [sys.executable, "-c", CAPABILITY_CRASH_SCRIPT, str(Path(__file__).parent), str(PUBLISHER),
         str(payload), str(prefix), point], text=True, capture_output=True, check=False, timeout=20,
    )
    assert result.returncode == 92, result.stderr
    installer.recover(prefix)
    assert (prefix / "bin/l2solver-active-helper").resolve() == old
    assert installer.read_capability(old) == b"enabled"
    assert set(installer.read_manifest(prefix)["generations"]) == {old.parent.name}
    installer.uninstall(prefix)


def test_quarantine_recovers_after_generation_move(installer, payload, tmp_path):
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, False)
    old = (prefix / "bin/l2solver").resolve().parent
    (payload / "l2solver").write_text("new client")
    installer.install(payload, prefix, False)
    (old / "l2solver").write_text("modified old client")
    script = r'''
import importlib.util
import os
from pathlib import Path
import sys
spec = importlib.util.spec_from_file_location("publisher", sys.argv[1])
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)
rename = Path.rename
def interrupted_rename(path, destination):
    result = rename(path, destination)
    if Path(destination).parent.name == ".l2solver-quarantine":
        os._exit(93)
    return result
Path.rename = interrupted_rename
installer.quarantine_inactive(Path(sys.argv[2]), sys.argv[3])
'''
    result = subprocess.run(
        [sys.executable, "-c", script, str(PUBLISHER), str(prefix), old.name],
        text=True, capture_output=True, check=False, timeout=20,
    )
    assert result.returncode == 93, result.stderr
    installer.quarantine_inactive(prefix, old.name)
    saved = prefix / "share/.l2solver-quarantine" / old.name
    assert (saved / "l2solver").read_text() == "modified old client"
    assert old.name not in installer.read_manifest(prefix)["generations"]
    installer.uninstall(prefix)


def test_manifest_with_restrictive_private_mode_remains_usable(installer, payload, tmp_path):
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, False)
    manifest = prefix / "share/l2solver/manifest.json"
    manifest.chmod(0o400)
    assert installer.read_manifest(prefix) is not None
    installer.uninstall(prefix)


def test_uninstall_unlink_failure_can_be_retried_without_touching_other_files(
    installer, payload, tmp_path, monkeypatch,
):
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, False)
    foreign = prefix / "bin/unrelated"
    foreign.write_text("keep")
    unlink = Path.unlink

    def deny_one(path, *args, **kwargs):
        if path == prefix / "bin/l2solver-active":
            raise PermissionError("injected unlink failure")
        return unlink(path, *args, **kwargs)

    with monkeypatch.context() as fault:
        fault.setattr(Path, "unlink", deny_one)
        with pytest.raises(PermissionError, match="injected unlink failure"):
            installer.uninstall(prefix)
    assert foreign.read_text() == "keep"
    assert (prefix / "bin/l2solver-uninstall").is_file()
    installer.uninstall(prefix)
    assert foreign.read_text() == "keep"


def test_payload_symlink_swap_is_refused_before_copy(installer, payload, tmp_path, monkeypatch):
    prefix = tmp_path / "prefix"
    source = payload / "l2solver"
    foreign = tmp_path / "foreign"
    foreign.write_text("sensitive data")
    is_symlink = Path.is_symlink
    swapped = False

    def swap_after_check(path):
        nonlocal swapped
        result = is_symlink(path)
        if path == source and not swapped:
            swapped = True
            source.unlink()
            source.symlink_to(foreign)
        return result

    monkeypatch.setattr(Path, "is_symlink", swap_after_check)
    with pytest.raises((ValueError, OSError)):
        installer.install(payload, prefix, False)
    assert swapped
    assert foreign.read_text() == "sensitive data"
    assert not os.path.lexists(prefix / "bin/l2solver")


def test_same_generation_commit_survives_exit_before_journal_cleanup(installer, payload, tmp_path):
    use_test_capabilities(installer)
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, True)
    helper = (prefix / "bin/l2solver-active-helper").resolve()
    installer.revoke_active(prefix)
    assert installer.read_capability(helper) is None
    script = r'''
import importlib.util
import os
from pathlib import Path
import sys
sys.path.insert(0, sys.argv[1])
from test_installer_recovery import use_test_capabilities
spec = importlib.util.spec_from_file_location("publisher", sys.argv[2])
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)
use_test_capabilities(installer)
unlink = Path.unlink
def interrupt_before_journal_cleanup(path, *args, **kwargs):
    if path.name == ".l2solver-transaction":
        os._exit(94)
    return unlink(path, *args, **kwargs)
Path.unlink = interrupt_before_journal_cleanup
installer.install(Path(sys.argv[3]), Path(sys.argv[4]), True)
'''
    result = subprocess.run(
        [sys.executable, "-c", script, str(Path(__file__).parent), str(PUBLISHER), str(payload), str(prefix)],
        text=True, capture_output=True, check=False, timeout=20,
    )
    assert result.returncode == 94, result.stderr
    installer.recover(prefix)
    assert installer.read_capability(helper) == b"enabled"
    installer.uninstall(prefix)


def test_payload_directory_swap_cannot_redirect_privileged_copy(installer, payload, tmp_path, monkeypatch):
    prefix = tmp_path / "prefix"
    substitute = tmp_path / "substitute"
    substitute.mkdir()
    for source in payload.iterdir():
        (substitute / source.name).write_text("foreign bytes")
    moved = payload.with_name("original-payload")
    is_symlink = Path.is_symlink
    swapped = False

    def swap_parent_after_check(path):
        nonlocal swapped
        result = is_symlink(path)
        if path == payload / "l2solver" and not swapped:
            swapped = True
            payload.rename(moved)
            payload.symlink_to(substitute, target_is_directory=True)
        return result

    monkeypatch.setattr(Path, "is_symlink", swap_parent_after_check)
    installer.install(payload, prefix, False)
    assert swapped
    assert (prefix / "bin/l2solver").read_text() == "l2solver"
    installer.uninstall(prefix)


def test_revoke_active_is_not_undone_by_pending_upgrade_rollback(installer, payload, tmp_path):
    use_test_capabilities(installer)
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, False)
    inactive = (prefix / "bin/l2solver").resolve()
    original = inactive.read_bytes()
    (payload / "l2solver").write_text("current client")
    installer.install(payload, prefix, True)
    helper = (prefix / "bin/l2solver-active-helper").resolve()
    (payload / "l2solver").write_text("new client")
    result = subprocess.run(
        [sys.executable, "-c", CAPABILITY_CRASH_SCRIPT, str(Path(__file__).parent), str(PUBLISHER),
         str(payload), str(prefix), "new-enabled"], text=True, capture_output=True, check=False, timeout=20,
    )
    assert result.returncode == 92, result.stderr
    inactive.write_text("damaged inactive executable")
    installer.revoke_active(prefix)
    inactive.write_bytes(original)
    installer.recover(prefix)
    assert installer.read_capability(helper) is None
    installer.uninstall(prefix)


def test_new_helper_stays_private_until_pointer_switch(installer, payload, tmp_path):
    use_test_capabilities(installer)
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, True)
    (payload / "l2solver").write_text("new client")
    script = r'''
import importlib.util
import os
from pathlib import Path
import sys
sys.path.insert(0, sys.argv[1])
from test_installer_recovery import use_test_capabilities
spec = importlib.util.spec_from_file_location("publisher", sys.argv[2])
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)
use_test_capabilities(installer)
symlink = Path.symlink_to
def interrupt_before_switch(path, target, *args, **kwargs):
    symlink(path, target, *args, **kwargs)
    if path.name == ".current-new":
        os._exit(95)
Path.symlink_to = interrupt_before_switch
installer.install(Path(sys.argv[3]), Path(sys.argv[4]), True)
'''
    result = subprocess.run(
        [sys.executable, "-c", script, str(Path(__file__).parent), str(PUBLISHER), str(payload), str(prefix)],
        text=True, capture_output=True, check=False, timeout=20,
    )
    assert result.returncode == 95, result.stderr
    pending = json.loads((prefix / "share/.l2solver-transaction").read_text())
    selected = prefix / "share/l2solver" / pending["selected"]
    assert installer.read_capability(selected / "l2solver-active-helper") == b"enabled"
    assert selected.stat().st_mode & 0o777 == 0o700
    installer.recover(prefix)
    assert not selected.exists()
    installer.uninstall(prefix)


def test_uninstaller_retries_last_unlink_after_journal_cleanup(installer, payload, tmp_path, monkeypatch):
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, False)
    uninstaller = prefix / "bin/l2solver-uninstall"
    unlink = Path.unlink

    def deny_final_unlink(path, *args, **kwargs):
        if path == uninstaller and not path.is_symlink():
            raise PermissionError("final uninstaller unlink denied")
        return unlink(path, *args, **kwargs)

    with monkeypatch.context() as fault:
        fault.setattr(Path, "unlink", deny_final_unlink)
        with pytest.raises(PermissionError, match="final uninstaller unlink denied"):
            installer.uninstall(prefix)
    assert uninstaller.is_file()
    assert not (prefix / "share/l2solver").exists()
    assert not (prefix / "share/.l2solver-transaction").exists()
    loader = importlib.machinery.SourceFileLoader("final_uninstaller", str(uninstaller))
    spec = importlib.util.spec_from_loader("final_uninstaller", loader)
    last_uninstaller = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(last_uninstaller)
    last_uninstaller.uninstall(prefix)
    assert not os.path.lexists(uninstaller)


def test_exit_after_last_unlink_leaves_no_transaction_to_block_reinstall(installer, payload, tmp_path):
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, False)
    crash(payload, prefix, "uninstall", "bin/l2solver-uninstall")
    assert not os.path.lexists(prefix / "bin/l2solver-uninstall")
    assert not (prefix / "share/.l2solver-transaction").exists()
    installer.install(payload, prefix, False)
    installer.uninstall(prefix)


def test_install_requires_explicit_uninstall_retry_after_interrupted_removal(installer, payload, tmp_path):
    prefix = tmp_path / "prefix"
    installer.install(payload, prefix, False)
    old_helper = (prefix / "bin/l2solver-active-helper").resolve()
    crash(payload, prefix, "uninstall", "bin/l2solver")
    with pytest.raises(ValueError, match="--uninstall"):
        installer.install(payload, prefix, False)
    assert old_helper.is_file()
    assert (prefix / "bin/l2solver-uninstall").is_file()
    installer.uninstall(prefix)
