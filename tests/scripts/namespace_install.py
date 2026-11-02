"""Exercise the real privileged entry point inside an isolated tmpfs and chroot."""
import errno
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

# Use the same synthetic HTTP builder as package qualification
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from benchmarks.qualification.fixture import http_capture


def run(command, *, success=True):
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if success is True and result.returncode != 0:
        raise AssertionError(f"command failed: {command!r}\n{result.stdout}\n{result.stderr}")
    if success is False and result.returncode == 0:
        raise AssertionError(f"command unexpectedly succeeded: {command!r}")
    return result


def real_lifecycle(root, checkout, payload, selection, execute, publish, cap, resolved):
    def unprivileged(*args, success=True):
        return run([
            "chroot", "--userspec=65534:65534", str(root), "/usr/bin/env",
            "PATH=/local/bin:/usr/bin:/bin", "HOME=/tmp", *args,
        ], success=success)

    # The mounted views and veth pair are private to this user and network namespace
    assert set(os.listdir(root / "sys/class/net")) == {"lo"}
    run(["ip", "link", "add", "l2left", "type", "veth", "peer", "name", "l2right"])
    for name, address in (("l2left", "198.18.0.1/24"), ("l2right", "198.18.0.2/24")):
        run(["ip", "address", "add", address, "dev", name])
        run(["ip", "link", "set", "dev", name, "up"])
    (root / "stage/synthetic.pcap").write_bytes(http_capture())
    for shell in ("bash", "zsh", "fish"):
        completion = unprivileged("/stage/payload/l2solver", "completions", shell).stdout
        (payload / shell).write_text(completion)

    publish("--check", "--prefix", "/local", *selection)
    publish("--payload", "/stage/payload", "--prefix", "/local", *selection)
    first = resolved("/local/bin/l2solver")
    first_helper = resolved("/local/bin/l2solver-active-helper")
    assert first.rsplit("/", 1)[0] == first_helper.rsplit("/", 1)[0]
    assert "l2solver " in unprivileged("l2solver", "--version").stdout
    assert "l2solver-active " in unprivileged("l2solver-active", "--version").stdout
    assert "IP 192.0.2.10 -> 192.0.2.20 protocol=6" in unprivileged("l2solver", "inspect", "/stage/synthetic.pcap").stdout
    assert "arp" in unprivileged("l2solver", "active", "--help").stdout
    for shell, path in (
        ("bash", "/local/share/custom/bash/l2solver"),
        ("zsh", "/local/share/custom/zsh/_l2solver"),
        ("fish", "/local/share/custom/fish/l2solver.fish"),
    ):
        assert (root / path.lstrip("/")).read_text() == (payload / shell).read_text()
        if shutil.which(shell):
            unprivileged(shell, "-n", path)

    probe = ["arp", "probe", "--interface", "l2left", "--target", "198.18.0.2", "--timeout-ms", "2000"]
    denied = unprivileged("l2solver-active", *probe, success=False)
    assert "cap_net_raw" in denied.stderr.lower() or "permitted" in denied.stderr.lower()
    assert not cap(first_helper)

    # A new receipt and opt-in make a distinct, complete matching generation
    (payload / "receipt.json").write_text('{"release":"second"}\n')
    publish("--payload", "/stage/payload", "--prefix", "/local", *selection, "--enable-active")
    second = resolved("/local/bin/l2solver")
    second_helper = resolved("/local/bin/l2solver-active-helper")
    assert first != second and second.rsplit("/", 1)[0] == second_helper.rsplit("/", 1)[0]
    assert cap(second_helper) == f"{second_helper} cap_net_raw=ep"
    assert not cap(first_helper)
    assert not cap(resolved("/local/bin/l2solver"))
    assert not cap(resolved("/local/bin/l2solver-active"))
    assert "IP 192.0.2.10 -> 192.0.2.20 protocol=6" in unprivileged("l2solver", "inspect", "/stage/synthetic.pcap").stdout
    result = unprivileged("l2solver-active", *probe, success=None)
    assert result.returncode in (0, 3), result.stderr
    assert "198.18.0.2" in result.stdout
    assert "Send called: true; socket acceptance: confirmed" in result.stdout
    assert "Helper cleanup: confirmed" in result.stdout
    # The retained old executable must still choose its own unprivileged helper
    old_client = first.rsplit("/", 1)[0] + "/l2solver-active"
    denied = unprivileged(old_client, *probe, success=False)
    assert "cap_net_raw" in denied.stderr.lower() or "permitted" in denied.stderr.lower()

    publish("--payload", "/stage/payload", "--prefix", "/local", *selection)
    assert not cap(second_helper)
    assert not cap(resolved("/local/bin/l2solver-active-helper"))
    unprivileged("l2solver", "--version")
    (root / "stage/system_install.py").unlink()
    execute("/local/bin/l2solver-uninstall")
    assert not (root / "local/share/l2solver").exists()
    for path in (
        "local/bin/l2solver", "local/bin/l2solver-active", "local/bin/l2solver-active-helper",
        "local/bin/l2solver-uninstall", "local/share/custom/bash/l2solver",
        "local/share/custom/zsh/_l2solver", "local/share/custom/fish/l2solver.fish",
    ):
        assert not os.path.lexists(root / path)
    assert (root / "stage/synthetic.pcap").is_file()
    print("real executable installer lifecycle passed")


def main():
    scratch = Path(sys.argv[1])
    checkout = Path(sys.argv[2])
    parent_uid = int(sys.argv[3])
    parent_namespaces = json.loads(sys.argv[4])
    assert os.geteuid() == 0
    uid_map = [line.split() for line in Path("/proc/self/uid_map").read_text().splitlines()]
    assert ["0", str(parent_uid), "1"] in uid_map
    for name, parent in parent_namespaces.items():
        assert os.stat(f"/proc/self/ns/{name}").st_ino != parent
    root = scratch / "root"
    root.mkdir()
    # This tmpfs and every bind mount exist only in the private mount namespace
    binaries = Path(sys.argv[5]) if len(sys.argv) > 5 else None
    # Payload and three installed generations coexist during the real lifecycle
    size = str(sum((binaries / name).stat().st_size for name in (
        "l2solver", "l2solver-active", "l2solver-active-helper",
    )) * 4 + 64 * 1024 * 1024) if binaries else "32m"
    run(["mount", "-t", "tmpfs", "-o", f"size={size},mode=755", "tmpfs", str(root)])
    (root / "usr").mkdir()
    run(["mount", "--bind", "/usr", str(root / "usr")])
    run(["mount", "-o", "remount,bind,ro", str(root / "usr")])
    for name in ("bin", "sbin", "lib", "lib64"):
        source = Path("/") / name
        if source.is_symlink():
            (root / name).symlink_to(os.readlink(source))
        elif source.is_dir():
            (root / name).mkdir()
            run(["mount", "--bind", str(source), str(root / name)])
            run(["mount", "-o", "remount,bind,ro", str(root / name)])
    (root / "stage/payload").mkdir(parents=True)
    if binaries:
        for name in ("proc", "sys", "dev", "tmp"):
            (root / name).mkdir()
        (root / "tmp").chmod(0o1777)
        run(["mount", "-t", "proc", "-o", "nosuid,nodev,noexec", "proc", str(root / "proc")])
        run(["mount", "-t", "sysfs", "-o", "ro,nosuid,nodev,noexec", "sysfs", str(root / "sys")])
        (root / "dev/null").touch()
        run(["mount", "--bind", "/dev/null", str(root / "dev/null")])
    publisher = root / "stage/system_install.py"
    shutil.copyfile(checkout / "scripts/system_install.py", publisher)
    payload = root / "stage/payload"
    if binaries:
        for name in ("l2solver", "l2solver-active", "l2solver-active-helper"):
            shutil.copyfile(binaries / name, payload / name)
            (payload / name).chmod(0o755)
    else:
        for name in ("l2solver", "l2solver-active"):
            (payload / name).write_text("#!/bin/sh\nprintf 'first fixture\\n'\n")
        # An actual ELF inode allows the kernel to enforce file capability settings
        shutil.copyfile("/usr/bin/true", payload / "l2solver-active-helper")
    for name in ("bash", "zsh", "fish", "NOTICE-JEMALLOC.txt", "receipt.json"):
        (payload / name).write_text("{}" if name == "receipt.json" else name)
    prefix = "/local"
    selection = [
        "--completion-dir", "bash=share/custom/bash",
        "--completion-dir", "zsh=share/custom/zsh",
        "--completion-dir", "fish=share/custom/fish",
    ]

    def execute(*args, success=True):
        return run(["chroot", str(root), *args], success=success)

    def publish(*args, success=True):
        return execute("/usr/bin/python3", "-I", "/stage/system_install.py", *args, success=success)

    getcap = "/usr/sbin/getcap" if (root / "usr/sbin/getcap").exists() else "/usr/bin/getcap"
    capsh = "/usr/sbin/capsh" if (root / "usr/sbin/capsh").exists() else "/usr/bin/capsh"

    def cap(path):
        return execute(getcap, path).stdout.strip()

    def resolved(path):
        return execute("/usr/bin/readlink", "-f", path).stdout.strip()

    if binaries:
        real_lifecycle(root, checkout, payload, selection, execute, publish, cap, resolved)
        return

    # Unmanaged destinations are left untouched by the preflight
    foreign = root / "foreign/bin/l2solver"
    foreign.parent.mkdir(parents=True)
    foreign.write_text("unmanaged")
    publish("--check", "--prefix", "/foreign", success=False)
    assert foreign.read_text() == "unmanaged"
    assert not (root / "foreign/share/l2solver").exists()

    publish("--check", "--prefix", prefix, *selection)
    publish("--payload", "/stage/payload", "--prefix", prefix, *selection)
    assert execute("/local/bin/l2solver").stdout == "first fixture\n"
    assert (root / "local/share/custom/zsh/_l2solver").is_symlink()
    first = (root / "local/bin/l2solver").resolve()
    publish("--payload", "/stage/payload", "--prefix", prefix, *selection)
    assert (root / "local/bin/l2solver").resolve() == first
    assert not cap(resolved("/local/bin/l2solver-active-helper"))
    # Fail verification after a real setcap, then deny revocation during rollback
    capability_failure = root / "stage/fail_capability_cleanup.py"
    capability_failure.write_text('''\
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, "/stage")
import system_install

prefix = Path(sys.argv[1])
enable = system_install.enable_capability
disable = system_install.disable_capability
retained = []

def fail_verification(helper):
    enable(helper)
    retained.append(helper)
    raise ValueError("injected verification failure")

def deny_revoke(helper):
    if retained and helper == retained[0]:
        raise PermissionError("injected revocation failure")
    disable(helper)

system_install.enable_capability = fail_verification
system_install.disable_capability = deny_revoke
try:
    system_install.install(Path("/stage/payload"), prefix, True)
except ValueError as error:
    assert "rollback incomplete" in str(error)
    assert str(retained[0]) in str(error)
else:
    raise AssertionError("capability cleanup unexpectedly succeeded")

helper = retained[0]
assert helper.is_file()
assert helper.parent.stat().st_mode & 0o777 == 0o700
assert os.getxattr(helper, "security.capability")
manifest = json.loads((prefix / "share/l2solver/manifest.json").read_text())
assert helper.parent.name in manifest["generations"]
print(json.dumps({"helper": str(helper)}))
''')
    first_failure = json.loads(execute(
        "/usr/bin/python3", "-I", "/stage/fail_capability_cleanup.py", "/revoke-first",
    ).stdout)
    failed_first_helper = first_failure["helper"]
    assert cap(failed_first_helper) == f"{failed_first_helper} cap_net_raw=ep"
    assert not os.path.lexists(root / "revoke-first/share/l2solver/current")
    # The incomplete first install remains isolated and needs administrator inspection
    os.removexattr(root / failed_first_helper.lstrip("/"), "security.capability")

    publish("--payload", "/stage/payload", "--prefix", "/revoke-upgrade", "--enable-active")
    old_upgrade_helper = resolved("/revoke-upgrade/bin/l2solver-active-helper")
    (payload / "receipt.json").write_text('{"release":"changed"}')
    failed_upgrade = json.loads(execute(
        "/usr/bin/python3", "-I", "/stage/fail_capability_cleanup.py", "/revoke-upgrade",
    ).stdout)
    failed_upgrade_helper = failed_upgrade["helper"]
    assert cap(failed_upgrade_helper) == f"{failed_upgrade_helper} cap_net_raw=ep"
    assert resolved("/revoke-upgrade/bin/l2solver-active-helper") == old_upgrade_helper
    assert cap(old_upgrade_helper) == f"{old_upgrade_helper} cap_net_raw=ep"
    # A retry reuses the quarantined generation after rechecking its capability
    publish("--payload", "/stage/payload", "--prefix", "/revoke-upgrade", "--enable-active")
    assert resolved("/revoke-upgrade/bin/l2solver-active-helper") == failed_upgrade_helper
    assert (root / failed_upgrade_helper.lstrip("/")).parent.stat().st_mode & 0o777 == 0o755
    assert not cap(old_upgrade_helper)
    helper_fd = os.open(root / failed_upgrade_helper.lstrip("/"), os.O_RDONLY)
    hidden_publisher = publisher.with_name("system_install.hidden")
    publisher.rename(hidden_publisher)
    try:
        execute("/revoke-upgrade/bin/l2solver-uninstall")
    finally:
        hidden_publisher.rename(publisher)
    try:
        os.getxattr(helper_fd, "security.capability")
        raise AssertionError("uninstaller left capability on the open helper inode")
    except OSError as error:
        assert error.errno == errno.ENODATA
    finally:
        os.close(helper_fd)
    assert not (root / "revoke-upgrade/share/l2solver").exists()
    (payload / "receipt.json").write_text("{}")

    (payload / "l2solver").write_text("#!/bin/sh\nprintf 'upgraded fixture\\n'\n")
    publish("--payload", "/stage/payload", "--prefix", prefix, *selection, "--enable-active")
    assert execute("/local/bin/l2solver").stdout == "upgraded fixture\n"
    helper = resolved("/local/bin/l2solver-active-helper")
    assert cap(helper) == f"{helper} cap_net_raw=ep"
    assert not cap(resolved("/local/bin/l2solver"))
    assert not cap(resolved("/local/bin/l2solver-active"))
    # A failed staged upgrade retains the prior executable and its authority
    (payload / "receipt.json").unlink()
    publish("--payload", "/stage/payload", "--prefix", prefix, *selection, success=False)
    assert resolved("/local/bin/l2solver-active-helper") == helper
    assert cap(helper) == f"{helper} cap_net_raw=ep"
    assert execute("/local/bin/l2solver").stdout == "upgraded fixture\n"
    assert not list((root / "local/share").glob(".l2solver-*"))
    (payload / "receipt.json").write_text("{}")
    # A failed pointer switch must restore the old helper's real capability
    switch_failure = root / "stage/fail_switch.py"
    switch_failure.write_text('''\
import os
from pathlib import Path
import sys

sys.path.insert(0, "/stage")
import system_install

replace = os.replace
def fail_switch(source, destination):
    if Path(destination).name == "current":
        raise PermissionError("injected pointer switch failure")
    return replace(source, destination)

system_install.os.replace = fail_switch
try:
    system_install.install(Path("/stage/payload"), Path("/local"), False)
except PermissionError as error:
    assert "injected pointer switch failure" in str(error)
else:
    raise AssertionError("pointer switch unexpectedly succeeded")
''')
    execute("/usr/bin/python3", "-I", "/stage/fail_switch.py")
    assert resolved("/local/bin/l2solver-active-helper") == helper
    assert cap(helper) == f"{helper} cap_net_raw=ep"
    assert execute("/local/bin/l2solver").stdout == "upgraded fixture\n"
    # Switching to the default policy revokes the former helper's real xattr
    publish("--payload", "/stage/payload", "--prefix", prefix, *selection)
    assert not cap(helper)
    assert not cap(resolved("/local/bin/l2solver-active-helper"))
    publish("--payload", "/stage/payload", "--prefix", prefix, *selection, "--enable-active")
    helper = resolved("/local/bin/l2solver-active-helper")
    assert cap(helper) == f"{helper} cap_net_raw=ep"
    # A lack of CAP_SETFCAP must refuse publication of a separate active install
    denied = execute(
        capsh, "--drop=cap_setfcap", "--", "-c",
        "/usr/bin/python3 -I /stage/system_install.py --payload /stage/payload --prefix /blocked --enable-active",
        success=False,
    )
    assert denied.returncode != 0
    assert "capabilit" in denied.stderr.lower()
    assert not (root / "blocked/share/l2solver/current").exists()
    # Direct invocation without root is refused before the destination is read
    denied = run([
        "chroot", "--userspec=65534:65534", str(root), "/usr/bin/python3", "-I",
        "/stage/system_install.py", "--uninstall", "--prefix", prefix,
    ], success=False)
    assert "requires root" in denied.stderr
    # The installed command must remove the active capability with no source copy
    helper_fd = os.open(root / helper.lstrip("/"), os.O_RDONLY)
    publisher.unlink()
    execute("/local/bin/l2solver-uninstall")
    try:
        os.getxattr(helper_fd, "security.capability")
        raise AssertionError("uninstaller left capability on the open helper inode")
    except OSError as error:
        assert error.errno == errno.ENODATA
    finally:
        os.close(helper_fd)
    assert not (root / "local/share/l2solver").exists()
    assert not os.path.lexists(root / "local/bin/l2solver")
    assert not os.path.lexists(root / "local/bin/l2solver-active-helper")
    print("private installer lifecycle passed")


if __name__ == "__main__":
    main()
