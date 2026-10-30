"""Receive synthetic LLDP and CDP frames on the proved test veth only."""

import os
from pathlib import Path
import socket
import struct
import time

GROUPS = (
    bytes.fromhex("0180c200000e"),
    bytes.fromhex("0180c2000003"),
    bytes.fromhex("0180c2000000"),
    bytes.fromhex("01000ccccccc"),
)


def main():
    parent = (int(os.environ["L2_TEST_PARENT_NET_DEVICE"]), int(os.environ["L2_TEST_PARENT_NET_INODE"]))
    current = os.stat("/proc/thread-self/ns/net")
    if (current.st_dev, current.st_ino) == parent:
        raise RuntimeError("receiver must be in the proved private namespace")
    interface = os.environ["L2_TEST_DISCOVERY_INTERFACE"]
    if interface != "l2src0":
        raise RuntimeError("unexpected fixture interface")
    index = socket.if_nametoindex(interface)
    if index != int(os.environ["L2_MEMBERSHIP_INDEX"]):
        raise RuntimeError("fixture interface index changed")
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as link:
        link.bind((interface, 0))
        link.settimeout(0.1)
        # Linux packet membership requests use a six-byte multicast address
        for group in GROUPS:
            request = struct.pack("=iHH8s", index, 0, len(group), group + bytes(2))
            link.setsockopt(263, 1, request)
        Path(os.environ["L2_TEST_DISCOVERY_READY"]).write_text("ready", encoding="ascii")
        seen = set()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and len(seen) < len(GROUPS):
            try:
                packet = link.recv(65535)
            except TimeoutError:
                continue
            if packet[:6] in GROUPS and packet[6:12] == bytes.fromhex("020000000002"):
                seen.add(packet[:6])
        if seen != set(GROUPS):
            raise RuntimeError(f"missing discovery destinations: {len(seen)} of {len(GROUPS)}")
        Path(os.environ["L2_TEST_DISCOVERY_OBSERVED"]).write_text("observed", encoding="ascii")


if __name__ == "__main__":
    main()
