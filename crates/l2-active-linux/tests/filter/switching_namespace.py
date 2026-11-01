"""Witness switching kernel filters inside a proved private veth namespace."""

import importlib.util
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("l2_filter_fixture", HERE / "namespace.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("filter fixture is unavailable")
base = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(base)


def changed(frame, offset, data):
    result = bytearray(frame)
    result[offset : offset + len(data)] = data
    return bytes(result)


def tagged(frame, protocol):
    return frame[:12] + protocol.to_bytes(2, "big") + b"\x00\x07" + frame[12:]


def frames():
    crates = HERE.parents[2]
    fixtures = crates / "l2-active/tests/switching/fixtures"
    dtp = (fixtures / "dtp.bin").read_bytes()
    vtp = (fixtures / "vtp-summary.bin").read_bytes()
    isl = (crates / "l2-active/tests/isl/fixtures/valid.bin").read_bytes()
    unrelated = bytes.fromhex("0200000000010200000000020800") + b"private-not-scoped".ljust(46, b"-")
    result = []
    for selected, other in ((dtp, vtp), (vtp, dtp)):
        accepted = [
            selected,
            changed(selected, 6, b"\x01"),
            changed(selected, 12, b"\x00\xff"),
            changed(selected, 12, b"\x00\x08"),
            changed(selected, 22, b"\xff"),
        ]
        rejected = [
            unrelated,
            other,
            changed(selected, 5, b"\xcd"),
            changed(selected, 19, b"\x0d"),
            changed(selected, 12, b"\x05\xdd"),
            changed(selected, 12, b"\x00\x07"),
            tagged(selected, 0x8100),
            tagged(selected, 0x88A8),
        ]
        result.append((accepted, rejected, selected))
    accepted = []
    for first in (1, 3):
        for user in range(16):
            accepted.append(changed(changed(isl, 0, bytes([first])), 5, bytes([user])))
    accepted.extend([
        changed(isl, 6, b"\x01"),
        changed(isl, 14, b"\x00"),
        changed(isl, 12, b"\x00\x00"),
        changed(isl, 12, b"\x03\xff"),
    ])
    rejected = [
        unrelated,
        changed(isl, 0, b"\x05"),
        changed(isl, 4, b"\x01"),
        changed(isl, 5, b"\x10"),
        changed(isl, 5, b"\xf0"),
        tagged(isl, 0x8100),
        tagged(isl, 0x88A8),
    ]
    result.append((accepted, rejected, isl))
    return result


def witness_frame(witness, frame, deadline):
    protocol = int.from_bytes(frame[12:14], "big")
    tagged_frame = protocol in (0x8100, 0x88A8)
    stripped = frame[:12] + frame[16:] if tagged_frame else frame
    for _ in range(64):
        if time.monotonic() >= deadline:
            break
        try:
            data, controls, _, _ = witness.recvmsg(65_535, socket.CMSG_SPACE(20))
        except TimeoutError:
            continue
        if tagged_frame and data == frame:
            return
        if data != stripped:
            continue
        if not tagged_frame:
            return
        for level, kind, control in controls:
            if level == 263 and kind == 8 and len(control) >= 20:
                status, _, _, _, _, tci, tpid = struct.unpack("=IIIHHHH", control[:20])
                if status & (1 << 4) and tci == 7 and (not status & (1 << 6) or tpid == protocol):
                    return
    raise RuntimeError("expected packet or VLAN metadata was not observed")


base.frames = frames
base.witness_frame = witness_frame

if __name__ == "__main__":
    try:
        if len(sys.argv) >= 6 and sys.argv[1] == "--child":
            base.owned.child(
                [int(value) for value in sys.argv[2:5]],
                int(sys.argv[5]),
                sys.argv[6:],
                base.exercise,
                "switching_filters_checked=true",
            )
        elif len(sys.argv) > 2 and sys.argv[1] == "--":
            base.owned.parent(__file__, sys.argv[2:])
        else:
            raise RuntimeError("usage: switching_namespace.py -- COMMAND ARG ...")
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(f"isolated switching filter fixture error: {error}", file=sys.stderr)
        sys.exit(1)
