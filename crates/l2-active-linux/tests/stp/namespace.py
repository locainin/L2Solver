"""Exercise a receive-only STP helper inside a verified disposable veth."""

import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
CRATES = HERE.parents[2]
HARNESS = CRATES / "l2-active/tests/support/owned_veth.py"
SPEC = importlib.util.spec_from_file_location("l2_owned_veth", HARNESS)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("owned veth harness is unavailable")
owned = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(owned)
ns = owned.ns
GROUP = "0180c2000000"


def memberships(ifindex):
    result = {}
    for line in Path("/proc/net/dev_mcast").read_text(encoding="ascii").splitlines():
        fields = line.split()
        if len(fields) != 5:
            raise RuntimeError("invalid multicast membership record")
        if int(fields[0]) == ifindex:
            result[fields[4]] = int(fields[2])
    return result


def interface_flags():
    return int(Path("/sys/class/net", ns.SOURCE, "flags").read_text(encoding="ascii"), 16)


def packet():
    source = bytes.fromhex(owned.PEER_MAC.replace(":", ""))
    fixture = (CRATES / "l2-active/tests/fixtures/stp-configuration.bin").read_bytes()
    if len(fixture) != 52:
        raise RuntimeError("unexpected STP fixture length")
    return (fixture[:6] + source + fixture[12:]).ljust(60, bytes(1))


def exercise(net_fd, indices, command, parent_net):
    if not command:
        raise RuntimeError("STP fixture requires the helper test command")
    owned.require_owned_scope(net_fd, indices)
    baseline = memberships(indices[ns.SOURCE])
    flags = interface_flags()
    frame = packet()
    with tempfile.TemporaryDirectory(prefix="l2-stp-fixture-") as directory:
        ready = Path(directory) / "ready"
        observed = Path(directory) / "observed"
        environment = os.environ.copy()
        environment.update({
            "L2_TEST_PARENT_NET_DEVICE": str(parent_net[0]),
            "L2_TEST_PARENT_NET_INODE": str(parent_net[1]),
            "L2_TEST_STP_INTERFACE": ns.SOURCE,
            "L2_TEST_STP_READY": str(ready),
            "L2_TEST_STP_OBSERVED": str(observed),
        })
        with (
            socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as peer,
            socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as witness,
        ):
            peer.bind((ns.PEER, 0))
            witness.bind((ns.SOURCE, 0))
            peer.settimeout(0.05)
            witness.settimeout(0.05)
            process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment
            )
            try:
                deadline = time.monotonic() + 8
                while not ready.is_file():
                    if process.poll() is not None:
                        raise RuntimeError("STP receiver exited before readiness")
                    if time.monotonic() >= deadline:
                        raise RuntimeError("STP receiver readiness deadline elapsed")
                    time.sleep(0.005)
                if observed.exists():
                    raise RuntimeError("STP observation was acknowledged before send")
                during = memberships(indices[ns.SOURCE])
                expected = dict(baseline)
                expected[GROUP] = expected.get(GROUP, 0) + 1
                if during != expected or interface_flags() & 0x300 != flags & 0x300:
                    raise RuntimeError("STP helper joined unexpected groups or changed link mode")
                owned.require_owned_scope(net_fd, indices)
                if peer.send(frame) != len(frame):
                    raise RuntimeError("partial STP fixture frame send")
                owned.next_packet(witness, frame, deadline)
                stdout, stderr = process.communicate(timeout=8)
                if process.returncode != 0 or not observed.is_file():
                    raise RuntimeError(
                        f"STP receiver failed: {stderr.decode(errors='replace')} {stdout.decode(errors='replace')}"
                    )
                for _ in range(64):
                    try:
                        received = peer.recv(65_535)
                    except TimeoutError:
                        break
                    if received[6:12] == bytes.fromhex(owned.CLIENT_MAC.replace(":", "")):
                        raise RuntimeError("receive-only STP endpoint transmitted a frame")
                if memberships(indices[ns.SOURCE]) != baseline:
                    raise RuntimeError("STP multicast membership was not released")
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
                "stp_emitted=true stp_observed=true memberships_restored=true",
            )
        elif len(sys.argv) > 2 and sys.argv[1] == "--":
            owned.parent(__file__, sys.argv[2:])
        else:
            raise RuntimeError("usage: namespace.py -- COMMAND ARG ...")
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(f"isolated STP fixture error: {error}", file=sys.stderr)
        sys.exit(1)
