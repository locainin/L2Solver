"""Test fixed VRRP and MPLS socket filters inside a proved private veth."""

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
CRATES = HERE.parents[2]
SPEC = importlib.util.spec_from_file_location("l2_filter_namespace", HERE / "namespace.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("filter namespace fixture is unavailable")
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)
owned = fixture.owned
ns = owned.ns


def replace(frame, offset, value):
    updated = bytearray(frame)
    updated[offset : offset + len(value)] = value
    return bytes(updated)


def vrrp_frames(selected):
    directory = CRATES / "l2-active/tests/first_hop/vrrp/fixtures"
    valid = (directory / "valid.bin").read_bytes()
    v2 = (directory / "v2-auth.bin").read_bytes()
    other = (directory / "other-vrid.bin").read_bytes()
    zero_vrid = (directory / "zero-vrid.bin").read_bytes()
    single_byte = replace(valid, 16, bytes.fromhex("0015"))
    accepted = [
        (directory / name).read_bytes()
        for name in (
            "valid.bin",
            "options.bin",
            "maximum.bin",
            "bad-ttl.bin",
            "pseudo.bin",
            "fragment.bin",
            "sender-anomaly.bin",
            "bad-source.bin",
            "bad-type.bin",
            "zero-count.bin",
        )
    ]
    # These candidate fields are checked by the core after the native filter
    accepted.extend(
        [
            replace(valid, 20, bytes.fromhex("8000")),
            replace(valid, 16, bytes.fromhex("ffff")),
            replace(valid, 16, bytes.fromhex("0016")),
        ]
    )
    # Non-initial fragments cannot reveal the original VRRP version reliably
    disguised_v2_fragment = replace(replace(v2, 20, bytes.fromhex("0001")), 34, b"\x31")
    rejected = [
        v2,
        disguised_v2_fragment,
        replace(valid, 20, bytes.fromhex("0001")),
        replace(valid, 14, bytes([0x65])),
        replace(valid, 14, bytes([0x44])),
        replace(valid, 16, bytes.fromhex("0013")),
        replace(valid, 16, bytes.fromhex("0014")),
        replace(valid, 5, b"\x13"),
        replace(valid, 33, b"\x13"),
        replace(valid, 23, b"\x11"),
        replace(valid, 12, bytes.fromhex("86dd")),
        valid[:34],
    ]
    if selected:
        rejected.extend([other, zero_vrid, single_byte])
        accepted.remove((directory / "maximum.bin").read_bytes())
    else:
        accepted.extend([other, zero_vrid, single_byte])
    return accepted, rejected, valid


def mpls_frames():
    directory = CRATES / "l2-active/tests/mpls/fixtures"
    valid = (directory / "valid.bin").read_bytes()
    accepted = [
        (directory / name).read_bytes()
        for name in ("valid.bin", "zero-ttl.bin", "mna.bin", "short.bin", "no-payload.bin")
    ]
    accepted.append(replace(valid, 6, bytes(6)))
    rejected = [
        (directory / "foreign.bin").read_bytes(),
        (directory / "upstream.bin").read_bytes(),
        replace(valid, 0, bytes.fromhex("01005e800000")),
        replace(valid, 12, bytes.fromhex("0800")),
    ]
    return accepted, rejected, valid


def frames(profile):
    if profile == "vrrp-any":
        accepted, rejected, outgoing = vrrp_frames(False)
    elif profile == "vrrp-42":
        accepted, rejected, outgoing = vrrp_frames(True)
    elif profile == "mpls":
        accepted, rejected, outgoing = mpls_frames()
    else:
        raise RuntimeError("unsupported fixed filter test profile")
    # The witness checks the stripped tag and kernel VLAN metadata separately
    tagged = accepted[0][:12] + bytes.fromhex("81000007") + accepted[0][12:]
    rejected.append(tagged)
    return accepted, rejected, outgoing


def wait_marker(path, process, deadline):
    while not path.is_file():
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=2)
            raise RuntimeError(
                f"filter child exited: {stderr.decode(errors='replace')} "
                f"{stdout.decode(errors='replace')}"
            )
        if time.monotonic() >= deadline:
            raise RuntimeError(f"filter child did not signal {path.name}")
        time.sleep(0.005)


def exercise(net_fd, indices, command, parent_net):
    if len(command) < 2:
        raise RuntimeError("filter fixture requires a profile and test command")
    profile, *command = command
    owned.require_owned_scope(net_fd, indices)
    accepted, rejected, outgoing = frames(profile)
    with tempfile.TemporaryDirectory(prefix="l2-fixed-filter-") as name:
        directory = Path(name)
        (directory / "count").write_text(str(len(accepted)), encoding="ascii")
        for index, packet in enumerate(accepted):
            (directory / f"expected-{index}").write_bytes(packet)
        environment = os.environ.copy()
        environment.update(
            {
                "L2_TEST_PARENT_NET_DEVICE": str(parent_net[0]),
                "L2_TEST_PARENT_NET_INODE": str(parent_net[1]),
                "L2_TEST_FILTER_INTERFACE": ns.SOURCE,
                "L2_TEST_FILTER_DIRECTORY": str(directory),
            }
        )
        with (
            socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as peer,
            socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as local,
            socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as witness,
        ):
            peer.bind((ns.PEER, 0))
            local.bind((ns.SOURCE, 0))
            witness.bind((ns.SOURCE, 0))
            witness.setsockopt(263, 8, 1)
            witness.settimeout(0.05)
            process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment
            )
            try:
                deadline = time.monotonic() + 8
                wait_marker(directory / "ready", process, deadline)
                traffic = [(packet, peer) for packet in rejected]
                traffic.append((outgoing, local))
                traffic.extend((packet, peer) for packet in accepted)
                for packet, sender in traffic:
                    # Every send is limited to the already-proved veth pair
                    owned.require_owned_scope(net_fd, indices)
                    if sender.send(packet) != len(packet):
                        raise RuntimeError("partial private-veth packet send")
                    fixture.witness_frame(witness, packet, deadline)
                wait_marker(directory / "observed", process, deadline)
                stdout, stderr = process.communicate(timeout=2)
                if process.returncode != 0:
                    raise RuntimeError(
                        f"filter child failed: {stderr.decode(errors='replace')} "
                        f"{stdout.decode(errors='replace')}"
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
                "fixed_filter_checked=true",
            )
        elif len(sys.argv) > 3 and sys.argv[2] == "--":
            owned.parent(__file__, [sys.argv[1], *sys.argv[3:]])
        else:
            raise RuntimeError("usage: first_hop_mpls.py PROFILE -- COMMAND ARG ...")
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(f"isolated filter fixture error: {error}", file=sys.stderr)
        sys.exit(1)
