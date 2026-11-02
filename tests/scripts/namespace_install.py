"""Exercise the real privileged entry point inside an isolated tmpfs and chroot."""
import errno
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def run(command, *, success=True):
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if success and result.returncode != 0:
        raise AssertionError(f"command failed: {command!r}\n{result.stdout}\n{result.stderr}")
    if not success and result.returncode == 0:
        raise AssertionError(f"command unexpectedly succeeded: {command!r}")
    return result


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
    run(["mount", "-t", "tmpfs", "-o", "size=32m,mode=755", "tmpfs", str(root)])
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
    publisher = root / "stage/system_install.py"
    shutil.copyfile(checkout / "scripts/system_install.py", publisher)
    payload = root / "stage/payload"
    for name in ("l2solver", "l2solver-active"):
        (payload / name).write_text("#!/bin/sh\nprintf 'first fixture\\n'\n")
    # An actual ELF inode allows the kernel to enforce file capability settings
    shutil.copyfile("/usr/bin/true", payload / "l2solver-active-helper")
    for name in ("bash", "zsh", "fish", "README.md", "install.md", "NOTICE-JEMALLOC.txt", "receipt.json"):
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
    (payload / "l2solver").write_text("#!/bin/sh\nprintf 'upgraded fixture\\n'\n")
    publish("--payload", "/stage/payload", "--prefix", prefix, *selection, "--enable-active")
    assert execute("/local/bin/l2solver").stdout == "upgraded fixture\n"
    helper = resolved("/local/bin/l2solver-active-helper")
    assert cap(helper) == f"{helper} cap_net_raw=ep"
    assert not cap(resolved("/local/bin/l2solver"))
    assert not cap(resolved("/local/bin/l2solver-active"))
    # A failed staged upgrade retains the prior executable and its authority
    (payload / "README.md").unlink()
    publish("--payload", "/stage/payload", "--prefix", prefix, *selection, success=False)
    assert resolved("/local/bin/l2solver-active-helper") == helper
    assert cap(helper) == f"{helper} cap_net_raw=ep"
    assert execute("/local/bin/l2solver").stdout == "upgraded fixture\n"
    assert not list((root / "local/share").glob(".l2solver-*"))
    (payload / "README.md").write_text("README.md")
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
