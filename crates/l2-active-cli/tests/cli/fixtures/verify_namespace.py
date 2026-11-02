"""Prove a CLI child can only reach the fixture's private veth devices."""

import fcntl
import importlib.util
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
HARNESS = HERE.parents[3] / "l2-active-linux/tests/fixtures/namespace.py"
SPEC = importlib.util.spec_from_file_location("l2_namespace", HARNESS)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("namespace verifier is unavailable")
ns = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ns)


def verify():
    parent = (int(os.environ["L2_TEST_PARENT_NET_DEVICE"]), int(os.environ["L2_TEST_PARENT_NET_INODE"]))
    fds = {name: ns.open_namespace(name) for name in ("user", "mnt", "net")}
    try:
        for name, kind in (("user", ns.CLONE_NEWUSER), ("mnt", ns.CLONE_NEWNS), ("net", ns.CLONE_NEWNET)):
            ns.expect_namespace_type(fds[name], kind)
        if ns.identity(fds["net"]) == parent or os.getuid() != 0:
            raise RuntimeError("namespace or user mapping did not change")
        # The fixture maps one calling user to root in a new user namespace
        mapping = Path("/proc/thread-self/uid_map").read_text(encoding="ascii").split()
        if len(mapping) != 3 or mapping[0] != "0" or mapping[2] != "1":
            raise RuntimeError("namespace does not have the fixture's single-user mapping")
        # Both namespaces must be owned by the same private user namespace
        for name in ("mnt", "net"):
            owner = fcntl.ioctl(fds[name], ns.NS_GET_USERNS)
            try:
                if ns.identity(owner) != ns.identity(fds["user"]):
                    raise RuntimeError("namespace has a foreign owner")
            finally:
                os.close(owner)

        # Permit only the fixture's veth pair and its optional VLAN topology
        links = ns.links()
        base = {"lo", ns.SOURCE, ns.PEER}
        vlan = {"l2bridge0", "l2ctrl0", "l2test0", "l2peer37", "l2peer38"}
        if set(links) not in (base, base | vlan) or set(os.listdir("/sys/class/net")) != set(links):
            raise RuntimeError("unexpected interface inventory")
        parents = {ns.SOURCE: ns.PEER, ns.PEER: ns.SOURCE}
        kinds = {ns.SOURCE: "veth", ns.PEER: "veth"}
        if set(links) == base | vlan:
            kinds.update({"l2bridge0": "bridge", **{name: "vlan" for name in vlan - {"l2bridge0"}}})
            parents.update({"l2ctrl0": ns.SOURCE, "l2test0": ns.SOURCE,
                            "l2peer37": ns.PEER, "l2peer38": ns.PEER})
        for name, kind in kinds.items():
            if links[name].get("linkinfo", {}).get("info_kind") != kind:
                raise RuntimeError("unexpected interface kind")
            # A peer in another namespace cannot be the fixture's local pair
            if kind == "veth" and "link_netnsid" in links[name]:
                raise RuntimeError("veth peer is outside the private namespace")
            index = int(Path("/sys/class/net", name, "ifindex").read_text(encoding="ascii"))
            if index != links[name].get("ifindex"):
                raise RuntimeError("interface identity changed")
            # Check each peer or VLAN parent against its current interface index
            if name in parents:
                peer = int(Path("/sys/class/net", name, "iflink").read_text(encoding="ascii"))
                if peer != links[parents[name]].get("ifindex"):
                    raise RuntimeError("interface parent changed")
    finally:
        for fd in fds.values():
            os.close(fd)


if __name__ == "__main__":
    try:
        verify()
    except (KeyError, OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"unproved private namespace: {error}", file=sys.stderr)
        sys.exit(1)
