"""Check a silent helper only within a verified private veth namespace."""

import importlib.util
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
HARNESS = HERE.parents[3] / "l2-active/tests/support/owned_veth.py"
SPEC = importlib.util.spec_from_file_location("l2_owned_veth", HARNESS)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("owned veth harness is unavailable")
owned = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(owned)
ns = owned.ns


def exercise(net_fd, indices, command, parent_net):
    if not command:
        raise RuntimeError("a test child is required")
    owned.require_owned_scope(net_fd, indices)
    ns.command("ip", "address", "add", "192.0.2.1/24", "dev", ns.SOURCE)
    environment = os.environ.copy()
    environment.update({
        "L2_TEST_PARENT_NET_DEVICE": str(parent_net[0]),
        "L2_TEST_PARENT_NET_INODE": str(parent_net[1]),
        "L2_TEST_ACTIVE_INTERFACE": ns.SOURCE,
        "L2_TEST_ACTIVE_TARGET": "192.0.2.2",
    })
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as peer:
        peer.bind((ns.PEER, 0))
        peer.settimeout(0.05)
        # The witness is active before the client can open the silent helper
        owned.require_owned_scope(net_fd, indices)
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment, start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 12
            finished_at = None
            while finished_at is None or time.monotonic() < finished_at:
                if time.monotonic() >= deadline:
                    raise RuntimeError("silent-helper child exceeded the fixture deadline")
                if process.poll() is not None and finished_at is None:
                    finished_at = time.monotonic() + 0.15
                try:
                    peer.recv(65_535)
                except TimeoutError:
                    continue
                raise RuntimeError("silent-helper test sent a packet")
            stdout, stderr = process.communicate(timeout=2)
            if process.returncode != 0:
                raise RuntimeError(f"silent-helper child failed: {stderr.decode(errors='replace')}")
            if b"test result: ok. 1 passed; 0 failed;" not in stdout:
                raise RuntimeError("expected one child test to pass")
        finally:
            if process.poll() is None:
                # Reap the whole test session before removing its private links
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate(timeout=2)


if __name__ == "__main__":
    try:
        if len(sys.argv) >= 6 and sys.argv[1] == "--child":
            owned.child(
                [int(value) for value in sys.argv[2:5]], int(sys.argv[5]), sys.argv[6:],
                exercise, "silent_helper_no_send=true",
            )
        elif len(sys.argv) > 2 and sys.argv[1] == "--":
            owned.parent(__file__, sys.argv[2:])
        else:
            raise RuntimeError("usage: silent_helper_veth.py -- COMMAND ARG ...")
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(f"silent-helper fixture error: {error}", file=sys.stderr)
        sys.exit(1)
