"""Exercise global NDP route admission only in a proved owned namespace."""

import importlib.util
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "l2_owned_veth", HERE.parents[1] / "support/owned_veth.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("namespace verifier is unavailable")
owned = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(owned)
ns = owned.ns
SOURCE = "2001:db8:1::1"
TARGET = "2001:db8:1::2"


def packets():
    # Construct the solicitation and advertisement independently with Scapy
    from scapy.all import (
        Ether, ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6NDOptDstLLAddr,
        ICMPv6NDOptSrcLLAddr, IPv6, raw,
    )

    request = raw(
        Ether(src=owned.CLIENT_MAC, dst="33:33:ff:00:00:02")
        / IPv6(src=SOURCE, dst="ff02::1:ff00:2", hlim=255)
        / ICMPv6ND_NS(tgt=TARGET)
        / ICMPv6NDOptSrcLLAddr(lladdr=owned.CLIENT_MAC)
    )
    reply = raw(
        Ether(src=owned.PEER_MAC, dst=owned.CLIENT_MAC)
        / IPv6(src=TARGET, dst=SOURCE, hlim=255)
        / ICMPv6ND_NA(R=0, S=1, O=1, tgt=TARGET)
        / ICMPv6NDOptDstLLAddr(lladdr=owned.PEER_MAC)
    )
    return request, reply


def configure(case, net_fd, indices):
    owned.require_owned_scope(net_fd, indices)
    ns.command("ip", "-6", "addr", "add", f"{SOURCE}/64", "dev", ns.SOURCE, "nodad", "noprefixroute")
    owned.require_owned_scope(net_fd, indices)
    if case in ("direct", "route_removed"):
        ns.command("ip", "-6", "route", "add", "2001:db8:1::/64", "dev", ns.SOURCE)
    elif case == "gateway":
        ns.command("ip", "-6", "route", "add", f"{TARGET}/128", "via", "fe80::2", "dev", ns.SOURCE)
    elif case == "other_interface":
        ns.command("ip", "-6", "route", "add", f"{TARGET}/128", "dev", ns.PEER)
    elif case != "no_route":
        raise RuntimeError("unknown route test case")


def is_solicitation(packet):
    return (
        len(packet) >= 55
        and packet[6:12] == bytes.fromhex("020000000001")
        and packet[12:14] == bytes.fromhex("86dd")
        and packet[20] == 58
        and packet[54] == 135
    )


def exercise(net_fd, indices, command, parent_net):
    if not command:
        raise RuntimeError("an independent test command is required")
    case = os.environ.get("L2_TEST_NDP_GLOBAL_CASE", "")
    configure(case, net_fd, indices)
    request, reply = packets()
    with (
        tempfile.TemporaryDirectory(prefix="l2-global-ndp-") as directory,
        socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as peer,
        socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as client,
    ):
        peer.bind((ns.PEER, 0))
        client.bind((ns.SOURCE, 0))
        peer.settimeout(0.05)
        client.settimeout(0.05)
        ready = Path(directory) / "ready"
        go = Path(directory) / "go"
        environment = os.environ.copy()
        environment.update({
            "L2_TEST_PARENT_NET_DEVICE": str(parent_net[0]),
            "L2_TEST_PARENT_NET_INODE": str(parent_net[1]),
            "L2_TEST_NDP_INTERFACE": ns.SOURCE,
            "L2_TEST_NDP_READY": str(ready),
            "L2_TEST_NDP_GO": str(go),
        })
        # Both witnesses are armed before the real helper may transmit
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
        count = 0
        removed = False
        try:
            deadline = time.monotonic() + 8
            for _ in range(160):
                if time.monotonic() >= deadline:
                    raise RuntimeError("global NDP command exceeded the fixture deadline")
                if case == "route_removed" and ready.exists() and not removed:
                    owned.require_owned_scope(net_fd, indices)
                    ns.command("ip", "-6", "route", "del", "2001:db8:1::/64", "dev", ns.SOURCE)
                    go.write_text("removed", encoding="ascii")
                    removed = True
                try:
                    observed = peer.recv(65_535)
                except TimeoutError:
                    if process.poll() is not None:
                        break
                    continue
                if not is_solicitation(observed):
                    continue
                count += 1
                if case != "direct" or observed != request or count != 1:
                    raise RuntimeError("unexpected global neighbor solicitation")
                owned.require_owned_scope(net_fd, indices)
                if peer.send(reply) != len(reply):
                    raise RuntimeError("partial advertisement send")
                owned.next_packet(client, reply, deadline)
            stdout, stderr = process.communicate(timeout=2)
            expected = 1 if case == "direct" else 0
            if process.returncode != 0 or count != expected or (case == "route_removed" and not removed):
                raise RuntimeError(
                    f"global NDP case failed: case={case}, requests={count}, removed={removed}, exit={process.returncode}, stdout={stdout.decode(errors='replace')}, stderr={stderr.decode(errors='replace')}"
                )
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=2)


if __name__ == "__main__":
    try:
        if len(sys.argv) >= 6 and sys.argv[1] == "--child":
            owned.child(
                [int(value) for value in sys.argv[2:5]], int(sys.argv[5]), sys.argv[6:],
                exercise, "route_case_confirmed=true",
            )
        elif len(sys.argv) > 2 and sys.argv[1] == "--":
            owned.parent(__file__, sys.argv[2:])
        else:
            raise RuntimeError("usage: global_veth.py -- COMMAND ARG ...")
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(f"global NDP fixture error: {error}", file=sys.stderr)
        sys.exit(1)
