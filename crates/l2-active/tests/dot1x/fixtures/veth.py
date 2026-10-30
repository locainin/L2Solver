"""Exchange a synthetic EAPOL Start and Request in a proved private veth."""

import importlib.util
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
HARNESS = HERE.parents[1] / "support/owned_veth.py"
SPEC = importlib.util.spec_from_file_location("l2_owned_veth", HARNESS)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("owned veth harness is unavailable")
owned = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(owned)
ns = owned.ns


def response(start):
    # Scapy is used only after the fixture proves the owned network namespace
    from scapy.all import EAP, EAPOL, Ether, raw

    if start != (HERE / "start.bin").read_bytes():
        return None
    packet = Ether(start)
    if (
        not packet.haslayer(EAPOL)
        or packet.src != owned.CLIENT_MAC
        or packet.dst != "01:80:c2:00:00:03"
        or packet[EAPOL].version != 2
        or packet[EAPOL].type != 1
        or packet[EAPOL].len != 0
    ):
        return None
    # The request destination comes from the Start actually seen on the peer
    frame = raw(
        Ether(src=owned.PEER_MAC, dst=packet.src, type=0x888E)
        / EAPOL(version=2, type=0)
        / EAP(code=1, id=41, type=1)
    )
    return frame + bytes(max(0, 60 - len(frame)))


def excluded_frames():
    # Synthetic response data is used only inside the proved private namespace
    from scapy.all import EAP, EAPOL, Ether, Raw, raw

    unicast = Ether(src=owned.PEER_MAC, dst=owned.CLIENT_MAC, type=0x888E)
    group = Ether(src=owned.PEER_MAC, dst="01:80:c2:00:00:03", type=0x888E)
    packets = [
        unicast
        / EAPOL(version=2, type=0)
        / EAP(code=2, id=41, type=1)
        / Raw(b"fixture"),
        unicast / EAPOL(version=2, type=3, len=0),
        group / EAPOL(version=2, type=1, len=1) / Raw(b"x"),
    ]
    for packet in packets:
        frame = raw(packet)
        yield frame + bytes(max(0, 60 - len(frame)))


def exercise(net_fd, indices, command, parent_net):
    owned.require_owned_scope(net_fd, indices)
    reference_start = (HERE / "start.bin").read_bytes()
    expected_request = (HERE / "request.bin").read_bytes()
    with (
        socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as peer,
        socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as client,
    ):
        peer.bind((ns.PEER, 0))
        client.bind((ns.SOURCE, 0))
        peer.settimeout(0.05)
        client.settimeout(0.05)
        if not command:
            owned.require_owned_scope(net_fd, indices)
            if client.send(reference_start) != len(reference_start):
                raise RuntimeError("partial owned-veth Start send")
            deadline = time.monotonic() + 3
            owned.next_packet(peer, reference_start, deadline)
            request = response(reference_start)
            if request != expected_request:
                raise RuntimeError(
                    "independent responder produced an unexpected Request"
                )
            owned.require_owned_scope(net_fd, indices)
            if peer.send(request) != len(request):
                raise RuntimeError("partial owned-veth Request send")
            owned.next_packet(client, request, deadline)
            return
        exercise_command(peer, client, net_fd, indices, command, parent_net)


def exercise_command(peer, client, net_fd, indices, command, parent_net):
    environment = os.environ.copy()
    environment["L2_TEST_PARENT_NET_DEVICE"] = str(parent_net[0])
    environment["L2_TEST_PARENT_NET_INODE"] = str(parent_net[1])
    environment["L2_TEST_DOT1X_INTERFACE"] = ns.SOURCE
    environment["L2_TEST_DOT1X_FIXTURE"] = str(HERE)
    # Arm both packet witnesses before the tested command can send
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment
    )
    count = 0
    try:
        deadline = time.monotonic() + 8
        for _ in range(160):
            if time.monotonic() >= deadline:
                raise RuntimeError("EAPOL command exceeded the fixture deadline")
            try:
                start = peer.recv(65_535)
            except TimeoutError:
                if process.poll() is not None:
                    break
                continue
            request = response(start)
            if request is None:
                continue
            count += 1
            if count == 1:
                for excluded in excluded_frames():
                    owned.require_owned_scope(net_fd, indices)
                    if peer.send(excluded) != len(excluded):
                        raise RuntimeError("partial privacy-negative frame send")
                    owned.next_packet(client, excluded, deadline)
                owned.require_owned_scope(net_fd, indices)
                if peer.send(request) != len(request):
                    raise RuntimeError("partial owned-veth Request send")
                owned.next_packet(client, request, deadline)
        stdout, stderr = process.communicate(timeout=2)
        if process.returncode != 0 or count != 1:
            raise RuntimeError(
                f"EAPOL command failed: starts={count}, exit={process.returncode}, stdout={stdout.decode(errors='replace')}, stderr={stderr.decode(errors='replace')}"
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
                "start_captured=true request_captured=true",
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
