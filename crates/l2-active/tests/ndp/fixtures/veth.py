"""Witness link-local NDP only inside a verified disposable veth namespace."""

import importlib.util
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

# The shared verifier must not write bytecode into the source tree
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
HARNESS = HERE.parents[1] / "support/owned_veth.py"
SPEC = importlib.util.spec_from_file_location("l2_owned_veth", HARNESS)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("namespace verifier is unavailable")
owned = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(owned)
ns = owned.ns
SOURCE = "fe80::1"
TARGET = "fe80::2"


def frames():
    # Scapy independently constructs checksums and the solicited-node address
    from scapy.all import (
        Ether,
        ICMPv6ND_NA,
        ICMPv6ND_NS,
        ICMPv6NDOptDstLLAddr,
        ICMPv6NDOptSrcLLAddr,
        IPv6,
        raw,
    )

    request = raw(
        Ether(src=owned.CLIENT_MAC, dst="33:33:ff:00:00:02")
        / IPv6(src=SOURCE, dst="ff02::1:ff00:2", hlim=255)
        / ICMPv6ND_NS(tgt=TARGET)
        / ICMPv6NDOptSrcLLAddr(lladdr=owned.CLIENT_MAC)
    )
    advertisement = raw(
        Ether(src=owned.PEER_MAC, dst=owned.CLIENT_MAC)
        / IPv6(src=TARGET, dst=SOURCE, hlim=255)
        / ICMPv6ND_NA(R=0, S=1, O=1, tgt=TARGET)
        / ICMPv6NDOptDstLLAddr(lladdr=owned.PEER_MAC)
    )
    return request, advertisement


def filter_noise():
    # Build candidates independently so each scope boundary is visible
    from scapy.all import (
        Ether,
        ICMPv6ND_NA,
        ICMPv6NDOptDstLLAddr,
        IPv6,
        IPv6ExtHdrFragment,
        raw,
    )

    ethernet = Ether(src=owned.PEER_MAC, dst=owned.CLIENT_MAC)
    ipv6 = IPv6(src=TARGET, dst=SOURCE, hlim=255)
    option = ICMPv6NDOptDstLLAddr(lladdr=owned.PEER_MAC)
    fragmented = raw(
        ethernet
        / ipv6
        / IPv6ExtHdrFragment(nh=58, id=7)
        / ICMPv6ND_NA(R=0, S=1, O=1, tgt=TARGET)
        / option
    )
    other_target = raw(
        ethernet / ipv6 / ICMPv6ND_NA(R=0, S=1, O=1, tgt="fe80::3") / option
    )
    bad_hop = raw(
        ethernet
        / IPv6(src=TARGET, dst=SOURCE, hlim=254)
        / ICMPv6ND_NA(R=0, S=1, O=1, tgt=TARGET)
        / option
    )
    return {
        "fragment": fragmented,
        "other-target": other_target,
        "bad-hop": bad_hop,
    }


def is_client_solicitation(packet):
    return (
        len(packet) >= 55
        and packet[6:12] == bytes.fromhex("020000000001")
        and packet[12:14] == bytes.fromhex("86dd")
        and packet[20] == 58
        and packet[54] == 135
    )


def exchange_command(peer, client, net_fd, indices, command, parent_net, request, advertisement):
    environment = os.environ.copy()
    environment.update({
        "L2_TEST_PARENT_NET_DEVICE": str(parent_net[0]),
        "L2_TEST_PARENT_NET_INODE": str(parent_net[1]),
        "L2_TEST_NDP_INTERFACE": ns.SOURCE,
    })
    # The peer and client witnesses are armed before the command may send
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
    count = 0
    try:
        deadline = time.monotonic() + 8
        for _ in range(160):
            if time.monotonic() >= deadline:
                raise RuntimeError("NDP command exceeded the fixture deadline")
            try:
                observed = peer.recv(65_535)
            except TimeoutError:
                if process.poll() is not None:
                    break
                continue
            if not is_client_solicitation(observed):
                continue
            if observed != request:
                raise RuntimeError("NDP solicitation did not match the independent encoding")
            count += 1
            if count == 1:
                candidate_name = os.environ.get("L2_TEST_NDP_FILTER_NOISE")
                if candidate_name is not None:
                    candidate = filter_noise().get(candidate_name)
                    if candidate is None:
                        raise RuntimeError("unknown NDP filter candidate")
                    # The unfiltered witness proves the candidate reached the client
                    owned.require_owned_scope(net_fd, indices)
                    if peer.send(candidate) != len(candidate):
                        raise RuntimeError("partial owned-veth filter candidate send")
                    owned.next_packet(client, candidate, deadline)
                    print(f"filter_noise_witnessed={candidate_name}")
                owned.require_owned_scope(net_fd, indices)
                if peer.send(advertisement) != len(advertisement):
                    raise RuntimeError("partial owned-veth advertisement send")
                owned.next_packet(client, advertisement, deadline)
        stdout, stderr = process.communicate(timeout=2)
        if process.returncode != 0 or count != 1:
            raise RuntimeError(
                f"NDP command failed: requests={count}, exit={process.returncode}, stdout={stdout.decode(errors='replace')}, stderr={stderr.decode(errors='replace')}"
            )
        owned.require_selected_test(command, stdout)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=2)


def exercise(net_fd, indices, command, parent_net):
    # Address assignment affects only the already-enrolled source veth
    owned.require_owned_scope(net_fd, indices)
    ns.command("ip", "-6", "addr", "add", f"{SOURCE}/64", "dev", ns.SOURCE, "nodad")
    owned.require_owned_scope(net_fd, indices)
    request, advertisement = frames()
    with (
        socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as peer,
        socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as client,
    ):
        peer.bind((ns.PEER, 0))
        client.bind((ns.SOURCE, 0))
        peer.settimeout(0.05)
        client.settimeout(0.05)
        if command:
            exchange_command(peer, client, net_fd, indices, command, parent_net, request, advertisement)
            return
        # First verify both witness sockets and the independent response frame
        if client.send(request) != len(request):
            raise RuntimeError("partial owned-veth solicitation send")
        deadline = time.monotonic() + 3
        owned.next_packet(peer, request, deadline)
        owned.require_owned_scope(net_fd, indices)
        if peer.send(advertisement) != len(advertisement):
            raise RuntimeError("partial owned-veth advertisement send")
        owned.next_packet(client, advertisement, deadline)


if __name__ == "__main__":
    try:
        if len(sys.argv) >= 6 and sys.argv[1] == "--child":
            owned.child(
                [int(value) for value in sys.argv[2:5]],
                int(sys.argv[5]),
                sys.argv[6:],
                exercise,
                "request_captured=true advertisement_captured=true",
            )
        elif len(sys.argv) == 1:
            owned.parent(__file__, [])
        elif len(sys.argv) > 2 and sys.argv[1] == "--":
            owned.parent(__file__, sys.argv[2:])
        else:
            raise RuntimeError("usage: veth.py [-- COMMAND ARG ...]")
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(f"isolated NDP fixture error: {error}", file=sys.stderr)
        sys.exit(1)
