"""Own one verified disposable network namespace and veth pair for tests."""

import importlib.util
import os
import subprocess
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
NAMESPACE_FIXTURE = HERE.parents[2] / "l2-active-linux/tests/fixtures/namespace.py"
SPEC = importlib.util.spec_from_file_location("l2_owned_namespace", NAMESPACE_FIXTURE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("namespace verifier is unavailable")
ns = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ns)

CLIENT_MAC = "02:00:00:00:00:01"
PEER_MAC = "02:00:00:00:00:02"


def require_owned_scope(net_fd, indices):
    current_net = ns.open_namespace("net")
    try:
        if ns.identity(current_net) != ns.identity(net_fd):
            raise RuntimeError("network namespace changed during the packet test")
    finally:
        os.close(current_net)
    ns.require_pair(indices)


def next_packet(capture, expected, deadline):
    for _ in range(64):
        if time.monotonic() >= deadline:
            break
        try:
            packet = capture.recv(65_535)
        except TimeoutError:
            continue
        if packet == expected:
            return
    raise RuntimeError("expected packet was not observed on the owned veth")


def child(raw_fds, parent_uid, command, exercise, success):
    names = ("user", "mnt", "net")
    parent_fds = dict(zip(names, raw_fds, strict=True))
    parent_net = ns.identity(parent_fds["net"])
    net_fd = ns.prove_scope(parent_fds, parent_uid)
    indices = None
    cleanup = False
    try:
        ns.require_loopback_only()
        # Sysfs follows the proved private network namespace for link checks
        ns.command("mount", "--make-rprivate", "/")
        ns.command("mount", "-t", "sysfs", "sysfs", "/sys")
        if set(os.listdir("/sys/class/net")) != {"lo"}:
            raise RuntimeError("sysfs does not show the isolated namespace")
        ns.command(
            "ip", "link", "add", ns.SOURCE, "type", "veth", "peer", "name", ns.PEER
        )
        current = ns.links()
        indices = {name: current[name]["ifindex"] for name in (ns.SOURCE, ns.PEER)}
        ns.require_pair(indices)
        for name, mac in ((ns.SOURCE, CLIENT_MAC), (ns.PEER, PEER_MAC)):
            ns.command("ip", "link", "set", "dev", name, "address", mac)
            ns.command("ip", "link", "set", "dev", name, "addrgenmode", "none")
            ns.command("ip", "link", "set", "dev", name, "up")
        ns.require_pair(indices)
        exercise(net_fd, indices, command, parent_net)
    finally:
        if indices is not None:
            require_owned_scope(net_fd, indices)
            ns.command("ip", "link", "del", "dev", ns.SOURCE)
            ns.require_loopback_only()
            cleanup = True
        os.close(net_fd)
    if not cleanup:
        raise RuntimeError("owned interface cleanup was not confirmed")
    print(f"{success} cleanup_confirmed=true")


def parent(entry, command):
    names = ("user", "mnt", "net")
    fds = [ns.open_namespace(name) for name in names]
    try:
        args = [
            "unshare",
            "--user",
            "--map-root-user",
            "--net",
            "--mount",
            "--fork",
            "--kill-child=KILL",
            sys.executable,
            str(entry),
            "--child",
            *(str(fd) for fd in fds),
            str(os.getuid()),
            *command,
        ]
        result = subprocess.run(
            args, check=False, pass_fds=fds, capture_output=True, text=True, timeout=20
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"isolated fixture failed: {result.stderr} {result.stdout}"
            )
        print(result.stdout.strip())
    finally:
        for fd in fds:
            os.close(fd)
