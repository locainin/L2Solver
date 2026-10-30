"""Exercise a DHCP responder only inside a verified disposable veth namespace."""

import importlib.util
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

# Importing the shared namespace verifier must not write into its source tree
sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
HARNESS = HERE.parents[1] / "support/owned_veth.py"
SPEC = importlib.util.spec_from_file_location("l2_owned_veth", HARNESS)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("owned veth harness is unavailable")
owned = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(owned)

ns = owned.ns
require_owned_scope = owned.require_owned_scope
next_packet = owned.next_packet
CLIENT_MAC = owned.CLIENT_MAC
SERVER_MAC = owned.PEER_MAC
SERVER_IP = "192.0.2.1"
OFFERED_IP = "192.0.2.10"


def response(request):
    if len(request) != 342:
        return None
    # Import packet tooling only after the isolated namespace has been proved
    from scapy.all import BOOTP, DHCP, IP, UDP, Ether, Raw, raw

    packet = Ether(request)
    if not all(packet.haslayer(layer) for layer in (IP, UDP, BOOTP, DHCP)):
        return None
    ip, udp, bootp = packet[IP], packet[UDP], packet[BOOTP]
    if (
        packet.src != CLIENT_MAC
        or packet.dst != "ff:ff:ff:ff:ff:ff"
        or ip.src != "0.0.0.0"
        or ip.dst != "255.255.255.255"
        or udp.sport != 68
        or udp.dport != 67
        or bootp.op != 1
        or bootp.htype != 1
        or bootp.hlen != 6
        or bootp.xid == 0
        or bytes(bootp.chaddr)[:6] != bytes.fromhex(CLIENT_MAC.replace(":", ""))
    ):
        return None
    if ("message-type", 1) not in packet[DHCP].options:
        return None

    # Independently rebuild the exact admitted Discover, including checksums
    discover = BOOTP(
        op=1, htype=1, hlen=6, xid=bootp.xid, flags=0x8000, chaddr=bytes(bootp.chaddr)
    )
    discover_options = DHCP(options=[("message-type", "discover"), "end"])
    discover_payload = raw(discover) + bytes.fromhex("63825363") + raw(discover_options)
    discover_payload += bytes(max(0, 300 - len(discover_payload)))
    expected = raw(
        Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255", id=0, ttl=64)
        / UDP(sport=68, dport=67)
        / Raw(load=discover_payload)
    )
    if request != expected:
        return None

    # Construct one Offer using the actual request's transaction and client MAC
    offer = BOOTP(
        op=2,
        htype=1,
        hlen=6,
        xid=bootp.xid,
        yiaddr=OFFERED_IP,
        chaddr=bytes(bootp.chaddr),
    )
    options = DHCP(
        options=[
            ("message-type", "offer"),
            ("server_id", SERVER_IP),
            ("lease_time", 3600),
            "end",
        ]
    )
    payload = raw(offer) + bytes.fromhex("63825363") + raw(options)
    payload += bytes(max(0, 300 - len(payload)))
    return raw(
        Ether(src=SERVER_MAC, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=SERVER_IP, dst="255.255.255.255", id=0, ttl=64)
        / UDP(sport=67, dport=68)
        / Raw(load=payload)
    )


def exercise(net_fd, indices, command, parent_net):
    require_owned_scope(net_fd, indices)
    reference_request = (HERE / "discover.bin").read_bytes()
    expected_offer = (HERE / "offer.bin").read_bytes()
    with (
        socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as peer,
        socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as client,
    ):
        peer.bind((ns.PEER, 0))
        client.bind((ns.SOURCE, 0))
        peer.settimeout(0.05)
        client.settimeout(0.05)
        if not command:
            require_owned_scope(net_fd, indices)
            if client.send(reference_request) != len(reference_request):
                raise RuntimeError("partial owned-veth Discover send")
            deadline = time.monotonic() + 3
            next_packet(peer, reference_request, deadline)
            reply = response(reference_request)
            if reply != expected_offer:
                raise RuntimeError(
                    "independent responder did not construct the expected Offer"
                )
            require_owned_scope(net_fd, indices)
            if peer.send(reply) != len(reply):
                raise RuntimeError("partial owned-veth Offer send")
            next_packet(client, reply, deadline)
            return
        exercise_command(peer, client, net_fd, indices, command, parent_net)


def exercise_command(peer, client, net_fd, indices, command, parent_net):
    environment = os.environ.copy()
    environment["L2_TEST_PARENT_NET_DEVICE"] = str(parent_net[0])
    environment["L2_TEST_PARENT_NET_INODE"] = str(parent_net[1])
    environment["L2_TEST_DHCP_INTERFACE"] = ns.SOURCE
    environment["L2_TEST_DHCP_FIXTURE"] = str(HERE)
    # The command runs only after both packet witnesses are armed
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment
    )
    count = 0
    try:
        deadline = time.monotonic() + 8
        for _ in range(160):
            if time.monotonic() >= deadline:
                raise RuntimeError("DHCP command exceeded the fixture deadline")
            try:
                request = peer.recv(65_535)
            except TimeoutError:
                if process.poll() is not None:
                    break
                continue
            reply = response(request)
            if reply is None:
                continue
            count += 1
            if count == 1:
                require_owned_scope(net_fd, indices)
                if peer.send(reply) != len(reply):
                    raise RuntimeError("partial owned-veth Offer send")
                next_packet(client, reply, deadline)
        stdout, stderr = process.communicate(timeout=2)
        if process.returncode != 0 or count != 1:
            raise RuntimeError(
                f"DHCP command failed: requests={count}, exit={process.returncode}, stdout={stdout.decode(errors='replace')}, stderr={stderr.decode(errors='replace')}"
            )
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=2)


if __name__ == "__main__":
    try:
        if len(sys.argv) >= 6 and sys.argv[1] == "--child":
            owned.child(
                [int(value) for value in sys.argv[2:5]],
                int(sys.argv[5]),
                sys.argv[6:],
                exercise,
                "request_captured=true offer_captured=true",
            )
        elif len(sys.argv) == 1:
            owned.parent(__file__, [])
        elif len(sys.argv) > 2 and sys.argv[1] == "--":
            owned.parent(__file__, sys.argv[2:])
        else:
            raise RuntimeError("usage: veth.py [-- COMMAND ARG ...]")
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(f"isolated fixture error: {error}", file=sys.stderr)
        sys.exit(1)
