"""Run one packet test in a proved, disposable Linux namespace."""

import fcntl
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time

NS_GET_USERNS = 0xB701
NS_GET_NSTYPE = 0xB703
CLONE_NEWNS = 0x00020000
CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000
SOURCE = "l2src0"
PEER = "l2dst0"
SOURCE_MAC = bytes.fromhex("020000000001")
PEER_MAC = bytes.fromhex("020000000002")
SOURCE_IP = socket.inet_aton("192.0.2.1")
PEER_IP = socket.inet_aton("192.0.2.2")
QUIET_IP = socket.inet_aton("192.0.2.3")
DOWN_IP = socket.inet_aton("192.0.2.4")
BACKLOG_IP = socket.inet_aton("192.0.2.5")


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=5)


def identity(fd):
    info = os.fstat(fd)
    return info.st_dev, info.st_ino


def open_namespace(name):
    return os.open(f"/proc/thread-self/ns/{name}", os.O_RDONLY | os.O_CLOEXEC)


def expect_namespace_type(fd, expected):
    if fcntl.ioctl(fd, NS_GET_NSTYPE) != expected:
        raise RuntimeError("unexpected namespace descriptor type")


def prove_scope(parent_fds, parent_uid):
    current = {name: open_namespace(name) for name in ("user", "mnt", "net")}
    try:
        expected_types = {"user": CLONE_NEWUSER, "mnt": CLONE_NEWNS, "net": CLONE_NEWNET}
        for name, expected in expected_types.items():
            expect_namespace_type(parent_fds[name], expected)
            expect_namespace_type(current[name], expected)
            if identity(parent_fds[name]) == identity(current[name]):
                raise RuntimeError(f"{name} namespace did not change")
        for name in ("mnt", "net"):
            owner = fcntl.ioctl(current[name], NS_GET_USERNS)
            try:
                if identity(owner) != identity(current["user"]):
                    raise RuntimeError(f"{name} namespace has a foreign owner")
            finally:
                os.close(owner)
        with open("/proc/thread-self/uid_map", encoding="ascii") as stream:
            mapping = [line.split() for line in stream]
        if mapping != [["0", str(parent_uid), "1"]] or os.getuid() != 0:
            raise RuntimeError("unexpected user namespace mapping")
        # Keep the network descriptor to detect an accidental namespace change
        return os.dup(current["net"])
    finally:
        for fd in current.values():
            os.close(fd)
        for fd in parent_fds.values():
            os.close(fd)


def links():
    data = json.loads(command("ip", "-j", "-d", "link", "show").stdout)
    return {item["ifname"]: item for item in data}


def require_loopback_only():
    current = links()
    if set(current) != {"lo"} or current["lo"].get("ifindex") != 1:
        raise RuntimeError("new network namespace is not loopback-only")


def require_pair(indices):
    current = links()
    if set(current) != {"lo", SOURCE, PEER}:
        raise RuntimeError("unexpected namespace interface inventory")
    for name in (SOURCE, PEER):
        entry = current[name]
        if entry.get("ifindex") != indices[name] or entry.get("linkinfo", {}).get("info_kind") != "veth":
            raise RuntimeError("owned veth identity changed")
    with open(f"/sys/class/net/{SOURCE}/iflink", encoding="ascii") as stream:
        source_peer = int(stream.read().strip())
    with open(f"/sys/class/net/{PEER}/iflink", encoding="ascii") as stream:
        peer_source = int(stream.read().strip())
    if source_peer != indices[PEER] or peer_source != indices[SOURCE]:
        raise RuntimeError("veth peer relationship changed")


def arp_frame(destination, sender, operation, sender_ip, target_mac, target_ip):
    ethernet = destination + sender + bytes.fromhex("0806")
    arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, operation, sender, sender_ip, target_mac, target_ip)
    return ethernet + arp + bytes(18)


def exercise_cli(capture, executable, helper, request, reply):
    args = [executable, "--format", "json", "arp", "probe", "--interface", SOURCE, "--target", "192.0.2.2", "--timeout-ms", "700", "--helper", helper]
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    count = 0
    try:
        deadline = time.monotonic() + 4
        for _ in range(128):
            if time.monotonic() >= deadline:
                raise RuntimeError("CLI packet test deadline elapsed")
            try:
                packet = capture.recv(65535)
            except TimeoutError:
                if process.poll() is not None:
                    break
                continue
            if packet == request:
                count += 1
                if count == 1 and capture.send(reply) != len(reply):
                    raise RuntimeError("partial CLI test reply send")
        stdout, stderr = process.communicate(timeout=5)
        if process.returncode != 0 or count != 1:
            raise RuntimeError(f"CLI packet test failed: requests={count}, exit={process.returncode}, stdout={stdout.decode(errors='replace')}, stderr={stderr.decode(errors='replace')}")
        report = json.loads(stdout)
        if (report.get("status") != "observed" or report.get("completion") != "complete"
                or report.get("stop_reason") != "deadline"
                or report.get("tx", {}).get("accepted_packets") != 1
                or report.get("tx", {}).get("accepted_bytes") != 60
                or report.get("cleanup", {}).get("confirmed") is not True
                or not any(item.get("mac") == "02:00:00:00:00:02" for item in report.get("replies", []))):
            raise RuntimeError(f"CLI did not report the independently observed request and reply: {report}")
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)


def exercise(runner, helper, parent_net, indices):
    request = arp_frame(bytes([255]) * 6, SOURCE_MAC, 1, SOURCE_IP, bytes(6), PEER_IP)
    quiet_request = arp_frame(bytes([255]) * 6, SOURCE_MAC, 1, SOURCE_IP, bytes(6), QUIET_IP)
    down_request = arp_frame(bytes([255]) * 6, SOURCE_MAC, 1, SOURCE_IP, bytes(6), DOWN_IP)
    backlog_request = arp_frame(bytes([255]) * 6, SOURCE_MAC, 1, SOURCE_IP, bytes(6), BACKLOG_IP)
    reply = arp_frame(SOURCE_MAC, PEER_MAC, 2, PEER_IP, SOURCE_MAC, SOURCE_IP)
    environment = os.environ.copy()
    environment["L2_TEST_PARENT_NET_DEVICE"] = str(parent_net[0])
    environment["L2_TEST_PARENT_NET_INODE"] = str(parent_net[1])
    environment["L2_TEST_ACTIVE_HELPER"] = helper
    # Queue only candidates admitted by each probe's locked ARP filter
    stale = reply
    backlog_stale = arp_frame(SOURCE_MAC, PEER_MAC, 2, BACKLOG_IP, SOURCE_MAC, SOURCE_IP)
    # Both witnesses are armed before any tested helper can transmit
    with tempfile.TemporaryDirectory(prefix="l2-active-fixture-") as sync_dir, socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as capture, socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as witness:
        environment["L2_TEST_SYNC_DIR"] = sync_dir
        capture.bind((PEER, 0))
        capture.settimeout(0.05)
        witness.bind((SOURCE, 0))
        witness.settimeout(0.1)
        process = subprocess.Popen([runner, "--ignored", "--exact", "owned_namespace_child_performs_one_arp_probe", "--nocapture"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
        request_count = 0
        quiet_count = 0
        down_count = 0
        backlog_count = 0
        injected = False
        try:
            deadline = time.monotonic() + 6
            for _ in range(256):
                if time.monotonic() >= deadline:
                    raise RuntimeError("packet fixture deadline elapsed")
                if os.path.exists(os.path.join(sync_dir, "ready")) and not injected:
                    if capture.send(stale) != len(stale):
                        raise RuntimeError("partial queued-frame send")
                    observed = False
                    for _ in range(64):
                        try:
                            if witness.recv(65535) == stale:
                                observed = True
                                break
                        except TimeoutError:
                            continue
                    if not observed:
                        raise RuntimeError("queued frame did not reach the selected endpoint")
                    with open(os.path.join(sync_dir, "go"), "w", encoding="ascii") as signal:
                        signal.write("go")
                    injected = True
                try:
                    packet = capture.recv(65535)
                except TimeoutError:
                    if process.poll() is not None:
                        break
                    continue
                if packet == request:
                    request_count += 1
                    if request_count == 1 and capture.send(reply) != len(reply):
                        raise RuntimeError("partial independent reply send")
                elif packet == quiet_request:
                    quiet_count += 1
                elif packet == backlog_request:
                    backlog_count += 1
                    if capture.send(backlog_stale) != len(backlog_stale):
                        raise RuntimeError("partial backlog-frame send")
                    observed = False
                    for _ in range(64):
                        try:
                            if witness.recv(65535) == backlog_stale:
                                observed = True
                                break
                        except TimeoutError:
                            continue
                    if not observed:
                        raise RuntimeError("backlog frame did not reach the selected endpoint")
                    with open(os.path.join(sync_dir, "backlog"), "w", encoding="ascii") as signal:
                        signal.write("ready")
                elif packet == down_request:
                    down_count += 1
                    require_pair(indices)
                    command("ip", "link", "set", "dev", SOURCE, "down")
            stdout, stderr = process.communicate(timeout=5)
            if request_count != 1 or quiet_count != 1 or down_count != 1 or backlog_count != 1 or not injected or process.returncode != 0:
                raise RuntimeError(f"packet test failed: request_count={request_count}, quiet_count={quiet_count}, down_count={down_count}, backlog_count={backlog_count}, injected={injected}, exit={process.returncode}, stdout={stdout.decode(errors='replace')}, stderr={stderr.decode(errors='replace')}")
            require_pair(indices)
            command("ip", "link", "set", "dev", SOURCE, "up")
            cli = os.environ.get("L2_TEST_ACTIVE_CLI")
            if cli:
                exercise_cli(capture, cli, helper, request, reply)
            return bool(cli)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)


def child(runner, helper, raw_fds, parent_uid):
    names = ("user", "mnt", "net")
    parent_fds = dict(zip(names, raw_fds, strict=True))
    parent_net = identity(parent_fds["net"])
    net_fd = prove_scope(parent_fds, parent_uid)
    indices = None
    cleanup = False
    try:
        require_loopback_only()
        # A private mount namespace makes this sysfs view follow the owned netns
        command("mount", "--make-rprivate", "/")
        command("mount", "-t", "sysfs", "sysfs", "/sys")
        if set(os.listdir("/sys/class/net")) != {"lo"}:
            raise RuntimeError("sysfs does not show the isolated namespace")
        command("ip", "link", "add", SOURCE, "type", "veth", "peer", "name", PEER)
        current = links()
        indices = {name: current[name]["ifindex"] for name in (SOURCE, PEER)}
        require_pair(indices)
        command("ip", "link", "set", "dev", SOURCE, "address", "02:00:00:00:00:01")
        command("ip", "link", "set", "dev", PEER, "address", "02:00:00:00:00:02")
        command("ip", "link", "set", "dev", SOURCE, "addrgenmode", "none")
        command("ip", "link", "set", "dev", PEER, "addrgenmode", "none")
        command("ip", "address", "add", "192.0.2.1/29", "dev", SOURCE)
        command("ip", "address", "add", "192.0.2.2/29", "dev", PEER)
        command("ip", "link", "set", "dev", SOURCE, "up")
        command("ip", "link", "set", "dev", PEER, "up")
        require_pair(indices)
        cli_verified = exercise(runner, helper, parent_net, indices)
    finally:
        if indices is not None:
            current_net = open_namespace("net")
            try:
                if identity(current_net) != identity(net_fd):
                    raise RuntimeError("network namespace changed before cleanup")
            finally:
                os.close(current_net)
            require_pair(indices)
            command("ip", "link", "del", "dev", SOURCE)
            require_loopback_only()
            cleanup = True
        os.close(net_fd)
    if not cleanup:
        raise RuntimeError("owned interface cleanup was not confirmed")
    print(f"request_captured=true cleanup_confirmed=true cli_verified={str(cli_verified).lower()}")


def parent(runner, helper):
    names = ("user", "mnt", "net")
    fds = [open_namespace(name) for name in names]
    try:
        args = ["unshare", "--user", "--map-root-user", "--net", "--mount", "--fork", sys.executable, __file__, "child", runner, helper, *(str(fd) for fd in fds), str(os.getuid())]
        result = subprocess.run(args, pass_fds=fds, capture_output=True, text=True, timeout=20)
        if result.returncode != 0:
            raise RuntimeError(f"isolated namespace fixture failed: {result.stderr} {result.stdout}")
        print(result.stdout.strip())
    finally:
        for fd in fds:
            os.close(fd)


if __name__ == "__main__":
    try:
        if len(sys.argv) == 3:
            parent(sys.argv[1], sys.argv[2])
        elif len(sys.argv) == 8 and sys.argv[1] == "child":
            child(sys.argv[2], sys.argv[3], [int(value) for value in sys.argv[4:7]], int(sys.argv[7]))
        else:
            raise RuntimeError("invalid fixture invocation")
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(f"isolated fixture error: {error}", file=sys.stderr)
        sys.exit(1)
