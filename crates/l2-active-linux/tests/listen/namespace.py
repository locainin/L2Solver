"""Exercise discovery only inside a proved private owned-veth namespace."""

import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fixtures"))
import namespace as fixture

LLDP = bytes.fromhex(
    "0180c200000e02000000000288cc021307696e646570656e64656e742d737769746368"
    "0408054769312f302f31060200780000"
).ljust(60, bytes(1))
CDP = bytes.fromhex(
    "01000ccccccc0200000000020023aaaa0300000c20000278e6be0001000c737769746368"
    "2d610003000b4769312f302f31"
).ljust(60, bytes(1))


def parent(mode, command):
    names = ("user", "mnt", "net")
    fds = [fixture.open_namespace(name) for name in names]
    try:
        args = [
            "unshare", "--user", "--map-root-user", "--net", "--mount", "--fork",
            sys.executable, __file__, "child", mode,
            *(str(fd) for fd in fds), str(os.getuid()), "--", *command,
        ]
        result = subprocess.run(args, pass_fds=fds, capture_output=True, text=True, timeout=20)
        if result.returncode != 0:
            raise RuntimeError(f"isolated membership fixture failed: {result.stderr} {result.stdout}")
        print(result.stdout.strip())
    finally:
        for fd in fds:
            os.close(fd)


def memberships(index):
    lines = Path("/proc/net/dev_mcast").read_text(encoding="ascii").splitlines()
    groups = {"0180c200000e", "0180c2000003", "0180c2000000", "01000ccccccc"}
    entries = (line.split() for line in lines)
    return sorted(fields for fields in entries if fields and int(fields[0]) == index and fields[-1] in groups)


def exercise_capture(command, environment, indices):
    baseline = memberships(indices[fixture.SOURCE])
    with tempfile.TemporaryDirectory(prefix="l2-discovery-fixture-") as directory:
        ready = Path(directory) / "ready"
        observed = Path(directory) / "observed"
        sent = Path(directory) / "sent"
        environment.update({
            "L2_TEST_DISCOVERY_INTERFACE": fixture.SOURCE,
            "L2_TEST_DISCOVERY_READY": str(ready),
            "L2_TEST_DISCOVERY_OBSERVED": str(observed),
            "L2_TEST_DISCOVERY_SENT": str(sent),
        })
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as peer:
            peer.bind((fixture.PEER, 0))
            peer.settimeout(0.02)
            process = subprocess.Popen(command, env=environment, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, start_new_session=True)
            try:
                deadline = time.monotonic() + 5
                while not ready.exists():
                    if process.poll() is not None:
                        stdout, stderr = process.communicate(timeout=5)
                        raise RuntimeError(f"receiver exited before readiness: {stderr.decode(errors='replace')} {stdout.decode(errors='replace')}")
                    if time.monotonic() >= deadline:
                        raise RuntimeError("receiver readiness deadline elapsed")
                    time.sleep(0.005)
                if observed.exists():
                    raise RuntimeError("premature observation acknowledgement")
                fixture.require_pair(indices)
                for scope in (14, 3, 0):
                    frame = LLDP[:5] + bytes([scope]) + LLDP[6:]
                    if peer.send(frame) != len(frame):
                        raise RuntimeError("partial LLDP fixture frame send")
                if peer.send(CDP) != len(CDP):
                    raise RuntimeError("partial CDP fixture frame send")
                sent.write_text("sent", encoding="ascii")
                stdout, stderr = process.communicate(timeout=10)
                if not observed.is_file():
                    raise RuntimeError("receiver omitted observation acknowledgement")
                if process.returncode != 0:
                    raise RuntimeError(f"discovery receiver failed: {stderr.decode(errors='replace')} {stdout.decode(errors='replace')}")
                # Check that the tested endpoint did not send discovery traffic
                for _ in range(64):
                    try:
                        packet = peer.recv(65535)
                    except TimeoutError:
                        break
                    if packet[6:12] == bytes.fromhex("020000000001") and (
                        packet[12:14] == bytes.fromhex("88cc") or packet[14:22] == bytes.fromhex("aaaa0300000c2000")
                    ):
                        raise RuntimeError("receive-only endpoint sent a discovery frame")
                if memberships(indices[fixture.SOURCE]) != baseline:
                    raise RuntimeError("discovery multicast memberships were not released")
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.communicate(timeout=5)


def child(mode, command, raw_fds, parent_uid):
    names = ("user", "mnt", "net")
    parent_fds = dict(zip(names, raw_fds, strict=True))
    parent_net = fixture.identity(parent_fds["net"])
    net_fd = fixture.prove_scope(parent_fds, parent_uid)
    indices = None
    cleanup = False
    try:
        fixture.require_loopback_only()
        # Mount sysfs only after the user, mount, and network ownership checks
        fixture.command("mount", "--make-rprivate", "/")
        fixture.command("mount", "-t", "sysfs", "sysfs", "/sys")
        if set(os.listdir("/sys/class/net")) != {"lo"}:
            raise RuntimeError("sysfs does not show the isolated namespace")
        fixture.command("ip", "link", "add", fixture.SOURCE, "type", "veth", "peer", "name", fixture.PEER)
        current = fixture.links()
        indices = {name: current[name]["ifindex"] for name in (fixture.SOURCE, fixture.PEER)}
        fixture.require_pair(indices)
        for name, mac in ((fixture.SOURCE, "02:00:00:00:00:01"), (fixture.PEER, "02:00:00:00:00:02")):
            fixture.command("ip", "link", "set", "dev", name, "address", mac)
            fixture.command("ip", "link", "set", "dev", name, "addrgenmode", "none")
            fixture.command("ip", "link", "set", "dev", name, "up")
        fixture.require_pair(indices)
        environment = os.environ.copy()
        environment.update({
            "L2_MEMBERSHIP_PARENT_DEVICE": str(parent_net[0]),
            "L2_MEMBERSHIP_PARENT_INODE": str(parent_net[1]),
            "L2_MEMBERSHIP_INDEX": str(indices[fixture.SOURCE]),
            "L2_MEMBERSHIP_PEER_INDEX": str(indices[fixture.PEER]),
            "L2_TEST_PARENT_NET_DEVICE": str(parent_net[0]),
            "L2_TEST_PARENT_NET_INODE": str(parent_net[1]),
        })
        if mode == "membership":
            test = "listen::membership::tests::owned_namespace_child_joins_and_releases_only_fixed_groups"
            result = subprocess.run([*command, "--ignored", "--exact", test], env=environment, capture_output=True, text=True, timeout=10)
            if result.returncode != 0 or "1 passed" not in result.stdout:
                raise RuntimeError(f"membership child failed: {result.stderr} {result.stdout}")
        else:
            exercise_capture(command, environment, indices)
    finally:
        if indices is not None:
            current_net = fixture.open_namespace("net")
            try:
                if fixture.identity(current_net) != fixture.identity(net_fd):
                    raise RuntimeError("network namespace changed before cleanup")
            finally:
                os.close(current_net)
            fixture.require_pair(indices)
            fixture.command("ip", "link", "del", "dev", fixture.SOURCE)
            fixture.require_loopback_only()
            cleanup = True
        os.close(net_fd)
    if not cleanup:
        raise RuntimeError("owned interface cleanup was not confirmed")
    if mode == "membership":
        print("memberships=true cleanup=true")
    else:
        print("lldp_sent=3 cdp_sent=1 cleanup=true")


if __name__ == "__main__":
    try:
        if len(sys.argv) == 2:
            parent("membership", [sys.argv[1]])
        elif len(sys.argv) >= 3 and sys.argv[1] == "--":
            parent("capture", sys.argv[2:])
        elif len(sys.argv) >= 9 and sys.argv[1] == "child" and sys.argv[2] in ("membership", "capture") and sys.argv[7] == "--":
            child(sys.argv[2], sys.argv[8:], [int(value) for value in sys.argv[3:6]], int(sys.argv[6]))
        else:
            raise RuntimeError("invalid fixture invocation")
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(f"membership fixture error: {error}", file=sys.stderr)
        sys.exit(1)
