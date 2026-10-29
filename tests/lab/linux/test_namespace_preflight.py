#!/usr/bin/env python3
"""Check a transient namespace without creating links or packet sockets."""

import fcntl
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import unittest


# These are Linux nsfs ioctl values and namespace type flags
NS_GET_USERNS = 0xB701
NS_GET_NSTYPE = 0xB703
CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000
REQUIRED_CAPABILITIES = (1 << 12) | (1 << 13) | (1 << 21)


class IdentityError(Exception):
    """The observed namespace does not meet the probe's identity checks."""


def identity(fd):
    metadata = os.fstat(fd)
    return [metadata.st_dev, metadata.st_ino]


def require_type(fd, namespace_type):
    if fcntl.ioctl(fd, NS_GET_NSTYPE) != namespace_type:
        raise IdentityError("namespace descriptor has the wrong type")


def require_network_owner(network_fd, user_fd):
    owner_fd = fcntl.ioctl(network_fd, NS_GET_USERNS)
    try:
        require_type(owner_fd, CLONE_NEWUSER)
        if identity(owner_fd) != identity(user_fd):
            raise IdentityError("network namespace owner did not match")
    finally:
        os.close(owner_fd)


def namespace_evidence(parent_net_fd, parent_user_fd):
    # The parent descriptors pin real kernel objects rather than supplied IDs
    require_type(parent_net_fd, CLONE_NEWNET)
    require_type(parent_user_fd, CLONE_NEWUSER)
    with open("/proc/self/ns/net", "rb") as network, open(
        "/proc/self/ns/user", "rb"
    ) as user:
        require_type(network.fileno(), CLONE_NEWNET)
        require_type(user.fileno(), CLONE_NEWUSER)
        child_net = identity(network.fileno())
        child_user = identity(user.fileno())
        if child_net == identity(parent_net_fd):
            raise IdentityError("network namespace did not change")
        if child_user == identity(parent_user_fd):
            raise IdentityError("user namespace did not change")

        # The owner check ties the new network namespace to the new user namespace
        require_network_owner(network.fileno(), user.fileno())
        return {"network": child_net, "user": child_user}


def child_probe(parent_net_fd, parent_user_fd):
    evidence = namespace_evidence(parent_net_fd, parent_user_fd)
    with open("/proc/self/ns/net", "rb") as network, open(
        "/proc/self/ns/user", "rb"
    ) as user:
        # Real current descriptors must be rejected as parent identities
        for net_fd, user_fd in (
            (network.fileno(), parent_user_fd),
            (parent_net_fd, user.fileno()),
        ):
            try:
                namespace_evidence(net_fd, user_fd)
            except IdentityError:
                continue
            raise IdentityError("matching namespace identity was accepted")
        try:
            require_network_owner(network.fileno(), parent_user_fd)
        except IdentityError:
            pass
        else:
            raise IdentityError("parent user namespace was accepted as network owner")

    # Query the interface list only after the fresh namespace is verified
    links = socket.if_nameindex()
    if links != [(1, "lo")]:
        raise IdentityError("new network namespace has an unexpected link")
    status = Path("/proc/self/status").read_text(encoding="utf-8")
    effective = next(
        int(line.split()[1], 16)
        for line in status.splitlines()
        if line.startswith("CapEff:")
    )
    if effective & REQUIRED_CAPABILITIES != REQUIRED_CAPABILITIES:
        raise IdentityError("required child namespace capabilities are missing")
    evidence.update({"links": links, "effective_capabilities": f"{effective:x}"})
    return evidence


class NamespacePreflightTests(unittest.TestCase):
    def test_current_namespace_and_wrong_type_are_rejected(self):
        with open("/proc/self/ns/net", "rb") as network, open(
            "/proc/self/ns/user", "rb"
        ) as user:
            with self.subTest("current network namespace"):
                with self.assertRaisesRegex(IdentityError, "network namespace did not change"):
                    namespace_evidence(network.fileno(), user.fileno())
            with self.subTest("wrong namespace type"):
                with self.assertRaisesRegex(IdentityError, "wrong type"):
                    namespace_evidence(user.fileno(), user.fileno())

    def test_fresh_network_is_owned_by_fresh_user_namespace_and_has_only_loopback(self):
        with open("/proc/self/ns/net", "rb") as network, open(
            "/proc/self/ns/user", "rb"
        ) as user:
            parent_net = identity(network.fileno())
            parent_user = identity(user.fileno())
            # The child receives pinned parent handles and cannot choose their values
            result = subprocess.run(
                [
                    "unshare",
                    "--user",
                    "--map-root-user",
                    "--net",
                    "--fork",
                    "--kill-child=KILL",
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--child",
                    str(network.fileno()),
                    str(user.fileno()),
                ],
                pass_fds=(network.fileno(), user.fileno()),
                capture_output=True,
                timeout=15,
            )
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        evidence = json.loads(result.stdout)
        self.assertNotEqual(evidence["network"], parent_net)
        self.assertNotEqual(evidence["user"], parent_user)
        self.assertEqual(evidence["links"], [[1, "lo"]])
        print("namespace preflight:", json.dumps(evidence))


if __name__ == "__main__":
    # The ioctl constants below are qualified on Linux x86-64
    if sys.platform != "linux" or platform.machine() != "x86_64":
        raise SystemExit("namespace preflight currently supports Linux x86-64 only")
    if len(sys.argv) == 4 and sys.argv[1] == "--child":
        print(json.dumps(child_probe(int(sys.argv[2]), int(sys.argv[3]))))
    else:
        unittest.main()
