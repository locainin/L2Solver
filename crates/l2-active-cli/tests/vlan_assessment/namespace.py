"""Exercise a controlled canary across owned VLANs in a private namespace."""

import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
HARNESS = HERE.parents[2] / "l2-active-linux/tests/vlan/namespace.py"
SPEC = importlib.util.spec_from_file_location("l2_owned_vlan", HARNESS)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("owned VLAN harness is unavailable")
vlan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vlan)
owned = vlan.owned
ns = owned.ns

BRIDGE = "l2bridge0"
CONTROL = "l2ctrl0"
TEST = "l2test0"
PEER_CONTROL = "l2peer37"
PEER_TEST = "l2peer38"
CANARY_MAC = "02:00:00:00:00:09"
TARGET = socket.inet_aton("192.0.2.3")


def require_namespace(net_fd):
    current = ns.open_namespace("net")
    try:
        if ns.identity(current) != ns.identity(net_fd):
            raise RuntimeError("network namespace changed during VLAN assessment")
    finally:
        os.close(current)


def require_scope(net_fd, pair, created, forwarded):
    require_namespace(net_fd)
    links = ns.links()
    if set(links) != {"lo", ns.SOURCE, ns.PEER, *created}:
        raise RuntimeError("unexpected interface inventory in VLAN assessment fixture")
    for name in (ns.SOURCE, ns.PEER):
        item = links[name]
        if item.get("ifindex") != pair[name] or item.get("linkinfo", {}).get("info_kind") != "veth":
            raise RuntimeError("owned veth identity changed")
    for name, (index, kind) in created.items():
        item = links.get(name, {})
        if item.get("ifindex") != index or item.get("linkinfo", {}).get("info_kind") != kind:
            raise RuntimeError(f"owned interface identity changed: {name}")
    for name, parent in ((ns.SOURCE, pair[ns.PEER]), (ns.PEER, pair[ns.SOURCE]),
                         (CONTROL, pair[ns.SOURCE]), (TEST, pair[ns.SOURCE]),
                         (PEER_CONTROL, pair[ns.PEER]), (PEER_TEST, pair[ns.PEER])):
        if int(Path("/sys/class/net", name, "iflink").read_text(encoding="ascii")) != parent:
            raise RuntimeError(f"owned link parent changed: {name}")
    for name, attached in ((PEER_CONTROL, True), (PEER_TEST, forwarded)):
        master = Path("/sys/class/net", name, "master", "ifindex")
        actual = int(master.read_text(encoding="ascii")) if master.exists() else None
        expected = created[BRIDGE][0] if attached else None
        if actual != expected:
            raise RuntimeError(f"unexpected bridge membership: {name}")


def add(created, name, kind, parent=None, vid=None):
    command = ["ip", "link", "add"]
    if parent is not None:
        command.extend(["link", parent])
    command.extend(["name", name, "type", kind])
    if vid is not None:
        command.extend(["id", str(vid)])
    ns.command(*command)
    entry = ns.links().get(name)
    if entry is None or entry.get("linkinfo", {}).get("info_kind") != kind:
        raise RuntimeError(f"new owned interface was not found: {name}")
    created[name] = (entry["ifindex"], kind)


def run_case(runner, helper, parent_net, net_fd, pair, created, forwarded, raw=False):
    require_scope(net_fd, pair, created, forwarded)
    case = "forwarded_raw" if forwarded and raw else "forwarded" if forwarded else "isolated"
    environment = os.environ.copy()
    environment.update({
        "L2_TEST_PARENT_NET_DEVICE": str(parent_net[0]),
        "L2_TEST_PARENT_NET_INODE": str(parent_net[1]),
        "L2_TEST_ACTIVE_HELPER": helper,
        "L2_TEST_VLAN_ASSESSMENT_CASE": case,
        "L2_ACTIVE_CLI_TEST_CHILD": "vlan_canary",
    })
    control_request = ns.arp_frame(bytes([255]) * 6, ns.SOURCE_MAC, 1,
                                   socket.inet_aton("192.0.2.1"), bytes(6), TARGET)
    test_request = ns.arp_frame(bytes([255]) * 6, ns.SOURCE_MAC, 1,
                                socket.inet_aton("192.0.2.2"), bytes(6), TARGET)
    expected = [vlan.tagged(control_request, "802.1Q", 37),
                vlan.tagged(test_request, "802.1Q", 38),
                vlan.tagged(control_request, "802.1Q", 37)]
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as capture:
        capture.bind((ns.PEER, 0))
        capture.setsockopt(vlan.SOL_PACKET, vlan.PACKET_AUXDATA, 1)
        capture.settimeout(0.04)
        process = subprocess.Popen(
            [runner, "--exact", "namespace_tests::real_vlan_canary_assessment_observes_forwarding_and_keeps_silence_inconclusive", "--nocapture"],
            env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            deadline = time.monotonic() + 8
            observed = []
            while len(observed) < len(expected) and time.monotonic() < deadline:
                try:
                    packet, representation = vlan.packet_with_auxiliary_tag(capture)
                except TimeoutError:
                    if process.poll() is not None:
                        break
                    continue
                if packet == expected[len(observed)]:
                    observed.append(representation)
                elif packet in expected:
                    raise RuntimeError("canary requests arrived in the wrong order")
            stdout, stderr = process.communicate(timeout=8)
            if (process.returncode != 0 or len(observed) != len(expected)
                    or b"test result: ok. 1 passed; 0 failed;" not in stdout):
                raise RuntimeError(f"{case} assessment failed: witnessed={observed}, "
                                   f"stderr={stderr.decode(errors='replace')}, stdout={stdout.decode(errors='replace')}")
            require_scope(net_fd, pair, created, forwarded)
            print(f"{case}_case=true request_representations={','.join(observed)}")
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=2)


def exercise(net_fd, pair, command, parent_net):
    if len(command) != 2:
        raise RuntimeError("VLAN canary fixture requires a test runner and helper")
    runner, helper = command
    owned.require_owned_scope(net_fd, pair)
    created = {}
    try:
        add(created, BRIDGE, "bridge")
        add(created, CONTROL, "vlan", ns.SOURCE, 37)
        add(created, TEST, "vlan", ns.SOURCE, 38)
        add(created, PEER_CONTROL, "vlan", ns.PEER, 37)
        add(created, PEER_TEST, "vlan", ns.PEER, 38)
        require_namespace(net_fd)
        ns.command("ip", "link", "set", "dev", BRIDGE, "address", CANARY_MAC)
        ns.command("ip", "link", "set", "dev", PEER_CONTROL, "master", BRIDGE)
        ns.command("ip", "link", "set", "dev", PEER_TEST, "master", BRIDGE)
        for name in (CONTROL, TEST, PEER_CONTROL, PEER_TEST, BRIDGE):
            ns.command("ip", "link", "set", "dev", name, "addrgenmode", "none")
            ns.command("ip", "link", "set", "dev", name, "up")
        ns.command("ip", "address", "add", "192.0.2.1/29", "dev", CONTROL)
        ns.command("ip", "address", "add", "192.0.2.2/29", "dev", TEST)
        ns.command("ip", "address", "add", "192.0.2.3/29", "dev", BRIDGE)
        # Only the bridge may answer for its canary address in this namespace
        Path("/proc/sys/net/ipv4/conf/all/arp_ignore").write_text("1\n", encoding="ascii")
        # The isolated peer receives sources also assigned within this namespace
        Path("/proc/sys/net/ipv4/conf", BRIDGE, "accept_local").write_text("1\n", encoding="ascii")
        require_scope(net_fd, pair, created, True)
        run_case(runner, helper, parent_net, net_fd, pair, created, True)
        run_case(runner, helper, parent_net, net_fd, pair, created, True, raw=True)
        require_scope(net_fd, pair, created, True)
        ns.command("ip", "link", "set", "dev", PEER_TEST, "nomaster")
        require_scope(net_fd, pair, created, False)
        run_case(runner, helper, parent_net, net_fd, pair, created, False)
    finally:
        require_namespace(net_fd)
        # Remove only interfaces whose names, indices, and kinds still match
        for name, (index, kind) in reversed(tuple(created.items())):
            current = ns.links().get(name, {})
            if current.get("ifindex") != index or current.get("linkinfo", {}).get("info_kind") != kind:
                raise RuntimeError(f"owned interface changed before cleanup: {name}")
            ns.command("ip", "link", "del", "dev", name)
        owned.require_owned_scope(net_fd, pair)


if __name__ == "__main__":
    try:
        if len(sys.argv) >= 6 and sys.argv[1] == "--child":
            owned.child([int(value) for value in sys.argv[2:5]], int(sys.argv[5]),
                        sys.argv[6:], exercise, "vlan_canary_fixture_passed=true")
        elif len(sys.argv) == 3:
            owned.parent(__file__, sys.argv[1:])
        else:
            raise RuntimeError("usage: namespace.py TEST_RUNNER HELPER")
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(f"isolated VLAN canary fixture error: {error}", file=sys.stderr)
        sys.exit(1)
