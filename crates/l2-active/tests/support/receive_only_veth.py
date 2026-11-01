"""Run fixed receive-only packet fixtures inside an owned private veth pair."""

import importlib.util
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "l2_owned_veth", Path(__file__).with_name("owned_veth.py")
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("owned veth harness is unavailable")
owned = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(owned)
ns = owned.ns


def inject(peer, witness, net_fd, indices, deadline, fixture_dir, names):
    for name in names:
        frame = (fixture_dir / name).read_bytes()
        # Recheck the owned pair immediately before each synthetic transmit
        owned.require_owned_scope(net_fd, indices)
        if peer.send(frame) != len(frame):
            raise RuntimeError("partial private-veth frame send")
        owned.next_packet(witness, frame, deadline)


def wait_for_ready(process, ready, deadline):
    while time.monotonic() < deadline:
        if ready.is_file():
            return
        if process.poll() is not None:
            break
        time.sleep(0.01)
    raise RuntimeError("receive-only command did not become ready in the private namespace")


def read_peer_watch(watch):
    try:
        _frame, address = watch.recvfrom(65_535)
    except TimeoutError:
        return False
    # The peer sees its own fixture injections as outgoing, not as client sends
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
    raise RuntimeError("receive-only command exceeded the private fixture deadline")


def exercise_command(
    peer, witness, watch, net_fd, indices, command, parent_net, fixture_dir, prefix, names
):
    with tempfile.TemporaryDirectory(prefix=f"l2-{prefix.lower()}-fixture-") as sync_dir:
        environment = os.environ.copy()
        environment["L2_TEST_PARENT_NET_DEVICE"] = str(parent_net[0])
        environment["L2_TEST_PARENT_NET_INODE"] = str(parent_net[1])
        environment[f"L2_TEST_{prefix}_INTERFACE"] = ns.SOURCE
        environment[f"L2_TEST_{prefix}_FIXTURE"] = str(fixture_dir)
        environment[f"L2_TEST_{prefix}_SYNC_DIR"] = sync_dir
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment
        )
        try:
            deadline = time.monotonic() + 8
            # Start injection only after the client confirms capture is ready
            wait_for_ready(process, Path(sync_dir) / "ready", deadline)
            inject(peer, witness, net_fd, indices, deadline, fixture_dir, names)
            verify_no_client_send(watch, process, deadline)
            process.communicate(timeout=2)
            if process.returncode != 0:
                # Client output can contain captured packet data
                raise RuntimeError(f"receive-only command failed: exit={process.returncode}")
        finally:
            if process.poll() is None:
                # Failed clients are reaped before the owned pair is removed
                process.kill()
                process.communicate(timeout=2)


def exercise(net_fd, indices, command, parent_net, fixture_dir, prefix, names, self_test_name):
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
            inject(
                peer, witness, net_fd, indices, time.monotonic() + 3, fixture_dir, (self_test_name,)
            )
            for _ in range(64):
                if not read_peer_watch(watch):
                    return
            raise RuntimeError("owned peer queue did not drain")
        exercise_command(
            peer, witness, watch, net_fd, indices, command, parent_net, fixture_dir, prefix, names
        )


def main(entry, fixture_dir, prefix, names, success, self_test_name="valid.bin"):
    if len(sys.argv) >= 6 and sys.argv[1] == "--child":

        def run_child(net_fd, indices, command, parent_net):
            exercise(
                net_fd, indices, command, parent_net, fixture_dir, prefix, names, self_test_name
            )

        owned.child(
            [int(value) for value in sys.argv[2:5]],
            int(sys.argv[5]),
            sys.argv[6:],
            run_child,
            success,
        )
    elif len(sys.argv) == 1:
        owned.parent(entry, [])
    elif len(sys.argv) > 2 and sys.argv[1] == "--":
        owned.parent(entry, sys.argv[2:])
    else:
        raise RuntimeError("usage: veth.py [-- COMMAND ARG ...]")
