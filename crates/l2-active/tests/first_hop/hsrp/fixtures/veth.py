"""Deliver HSRP frames only inside a proved disposable veth namespace."""

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
HARNESS = HERE.parents[2] / "support/owned_veth.py"
SPEC = importlib.util.spec_from_file_location("l2_owned_veth", HARNESS)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("owned veth harness is unavailable")
owned = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(owned)
ns = owned.ns


def inject(peer, witness, net_fd, indices, deadline, names):
    for name in names:
        frame = (HERE / name).read_bytes()
        # Pin the pair again immediately before every synthetic transmit
        owned.require_owned_scope(net_fd, indices)
        if peer.send(frame) != len(frame):
            raise RuntimeError("partial private-veth HSRP send")
        owned.next_packet(witness, frame, deadline)


def wait_for_ready(process, ready, deadline):
    while time.monotonic() < deadline:
        if ready.is_file():
            return
        if process.poll() is not None:
            break
        time.sleep(0.01)
    raise RuntimeError("HSRP command did not become ready in the private namespace")


def read_peer_watch(watch):
    try:
        _frame, address = watch.recvfrom(65_535)
    except TimeoutError:
        return False
    # The peer's own injections are outgoing and are not client transmissions
    if address[2] != socket.PACKET_OUTGOING:
        raise RuntimeError("unexpected client transmission on the owned veth")
    return True


def verify_no_client_send(watch, process, deadline):
    finished_at = None
    while time.monotonic() < deadline:
        read_peer_watch(watch)
        if process.poll() is not None:
            if finished_at is None:
                finished_at = time.monotonic() + 0.15
            elif time.monotonic() >= finished_at:
                return
    raise RuntimeError("HSRP command exceeded the private fixture deadline")


def exercise_command(peer, witness, watch, net_fd, indices, command, parent_net):
    with tempfile.TemporaryDirectory(prefix="l2-hsrp-fixture-") as sync_dir:
        environment = os.environ.copy()
        environment["L2_TEST_PARENT_NET_DEVICE"] = str(parent_net[0])
        environment["L2_TEST_PARENT_NET_INODE"] = str(parent_net[1])
        environment["L2_TEST_HSRP_INTERFACE"] = ns.SOURCE
        environment["L2_TEST_HSRP_FIXTURE"] = str(HERE)
        environment["L2_TEST_HSRP_SYNC_DIR"] = sync_dir
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment
        )
        try:
            deadline = time.monotonic() + 8
            wait_for_ready(process, Path(sync_dir) / "ready", deadline)
            inject(
                peer,
                witness,
                net_fd,
                indices,
                deadline,
                ("bad-ttl.bin", "other-group.bin", "hsrp-v2.bin", "advertisement.bin"),
            )
            verify_no_client_send(watch, process, deadline)
            stdout, stderr = process.communicate(timeout=2)
            if process.returncode != 0:
                raise RuntimeError(
                    f"HSRP command failed: exit={process.returncode}, stdout={stdout.decode(errors='replace')}, stderr={stderr.decode(errors='replace')}"
                )
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=2)


def exercise(net_fd, indices, command, parent_net):
    owned.require_owned_scope(net_fd, indices)
    with (
        socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as peer,
        socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as witness,
        socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as watch,
    ):
        peer.bind((ns.PEER, 0))
        witness.bind((ns.SOURCE, 0))
        watch.bind((ns.PEER, 0))
        witness.settimeout(0.05)
        watch.settimeout(0.05)
        if not command:
            inject(peer, witness, net_fd, indices, time.monotonic() + 3, ("advertisement.bin",))
            for _ in range(64):
                if not read_peer_watch(watch):
                    return
            raise RuntimeError("owned peer queue did not drain")
        exercise_command(peer, witness, watch, net_fd, indices, command, parent_net)


if __name__ == "__main__":
    try:
        if len(sys.argv) >= 6 and sys.argv[1] == "--child":
            owned.child(
                [int(value) for value in sys.argv[2:5]],
                int(sys.argv[5]),
                sys.argv[6:],
                exercise,
                "messages_delivered=true no_client_send=true",
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
