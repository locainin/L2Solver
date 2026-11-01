"""Check tagged ARP only inside a verified private veth namespace."""

import importlib.util
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
HARNESS = HERE.parents[2] / "l2-active/tests/support/owned_veth.py"
SPEC = importlib.util.spec_from_file_location("l2_owned_veth", HARNESS)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("owned veth harness is unavailable")
owned = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(owned)
ns = owned.ns
VLAN = "l2vlan0"
VID = 37
WRONG_VID = 38
SOL_PACKET = 263
PACKET_AUXDATA = 8
TP_STATUS_VLAN_VALID = 1 << 4
TP_STATUS_VLAN_TPID_VALID = 1 << 6


def require_vlan_scope(net_fd, indices, vlan_index, protocol):
    current_net = ns.open_namespace("net")
    try:
        if ns.identity(current_net) != ns.identity(net_fd):
            raise RuntimeError("network namespace changed during VLAN test")
    finally:
        os.close(current_net)
    links = ns.links()
    if set(links) != {"lo", ns.SOURCE, ns.PEER, VLAN}:
        raise RuntimeError("unexpected VLAN fixture interface inventory")
    for name in (ns.SOURCE, ns.PEER):
        if links[name].get("ifindex") != indices[name] or links[name].get("linkinfo", {}).get("info_kind") != "veth":
            raise RuntimeError("owned veth identity changed")
    for name, expected in ((ns.SOURCE, indices[ns.PEER]), (ns.PEER, indices[ns.SOURCE]), (VLAN, indices[ns.SOURCE])):
        if int(Path("/sys/class/net", name, "iflink").read_text(encoding="ascii")) != expected:
            raise RuntimeError("owned link parent or peer changed")
    vlan = links[VLAN]
    detail = vlan.get("linkinfo", {})
    data = detail.get("info_data", {})
    if (vlan.get("ifindex") != vlan_index or detail.get("info_kind") != "vlan"
            or data.get("id") != VID or data.get("protocol") != protocol):
        raise RuntimeError(f"VLAN identity changed: {vlan}")


def tagged(frame, protocol, vid):
    tpid = {"802.1Q": 0x8100, "802.1ad": 0x88A8}[protocol]
    return frame[:12] + struct.pack("!HH", tpid, vid) + frame[12:]


def packet_with_auxiliary_tag(capture):
    packet, ancillary, flags, _ = capture.recvmsg(65_535, socket.CMSG_SPACE(20))
    if flags & socket.MSG_CTRUNC:
        raise RuntimeError("truncated packet auxiliary data")
    records = [data for level, kind, data in ancillary if level == SOL_PACKET and kind == PACKET_AUXDATA]
    if len(records) != 1 or len(records[0]) < 20:
        raise RuntimeError("missing or ambiguous packet auxiliary data")
    status, _, _, _, _, tci, tpid = struct.unpack("=IIIHHHH", records[0][:20])
    if status & TP_STATUS_VLAN_VALID:
        if not status & TP_STATUS_VLAN_TPID_VALID:
            tpid = 0x8100
        # Linux may move the VLAN header from the frame into auxiliary data
        return packet[:12] + struct.pack("!HH", tpid, tci) + packet[12:], "auxiliary"
    return packet, "unmodified"


def find_packet(capture, expected, deadline, process=None, auxiliary=False):
    samples = []
    for _ in range(256):
        if process is not None and process.poll() is not None:
            stdout, stderr = process.communicate(timeout=2)
            raise RuntimeError(f"VLAN child exited before expected packet: {stderr.decode(errors='replace')} {stdout.decode(errors='replace')}; samples={samples}")
        if time.monotonic() >= deadline:
            return None
        try:
            packet, representation = (packet_with_auxiliary_tag(capture) if auxiliary
                                      else (capture.recv(65_535), "unmodified"))
        except TimeoutError:
            continue
        if packet == expected:
            return representation
        if process is not None and packet[6:12] == ns.SOURCE_MAC and len(samples) < 4:
            samples.append(packet.hex())
    return None


def wait_ready(ready, process, deadline):
    while not ready.exists():
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=2)
            raise RuntimeError(f"VLAN child exited before synchronization: {stderr.decode(errors='replace')} {stdout.decode(errors='replace')}")
        if time.monotonic() >= deadline:
            raise RuntimeError("VLAN synchronization deadline elapsed")
        time.sleep(0.005)


def change_case(case, process, peer, lower, logical, request, reply, protocol, ready, go, net_fd, indices, vlan_index):
    deadline = time.monotonic() + 5
    if case in ("after_reply", "after_limit", "rename_after_reply"):
        representation = find_packet(peer, tagged(request, protocol, VID), deadline, process, auxiliary=True)
        if representation is None:
            raise RuntimeError("missing tagged request before the receive change")
        print(f"tagged_request_representation={representation}")
        frame = tagged(reply, protocol, VID)
        if peer.send(frame) != len(frame):
            raise RuntimeError("partial tagged reply send")
        if not find_packet(lower, frame, deadline, auxiliary=True) or not find_packet(logical, reply, deadline):
            raise RuntimeError("correct reply did not reach both VLAN witnesses")
    renamed = False
    try:
        if case != "deny_off":
            wait_ready(ready, process, deadline)
            require_vlan_scope(net_fd, indices, vlan_index, protocol)
            if case == "rename_after_reply":
                ns.command("ip", "link", "set", "dev", VLAN, "name", "l2moved0")
                renamed = True
            else:
                ns.command("ip", "link", "set", "dev", VLAN, "type", "vlan", "reorder_hdr", "off")
            go.write_text("go", encoding="ascii")
        stdout, stderr = process.communicate(timeout=5)
        if case not in ("after_reply", "after_limit", "rename_after_reply") and find_packet(peer, tagged(request, protocol, VID), time.monotonic() + 0.2, auxiliary=True):
            raise RuntimeError("helper transmitted after VLAN scope became unsupported")
        if process.returncode != 0:
            raise RuntimeError(f"VLAN admission/change check failed: {stderr.decode(errors='replace')} {stdout.decode(errors='replace')}")
    finally:
        if renamed:
            ns.command("ip", "link", "set", "dev", "l2moved0", "name", VLAN)


def exchange(command, parent_net, protocol, net_fd, indices, vlan_index):
    environment = os.environ.copy()
    environment.update({
        "L2_TEST_PARENT_NET_DEVICE": str(parent_net[0]),
        "L2_TEST_PARENT_NET_INODE": str(parent_net[1]),
        "L2_TEST_ACTIVE_HELPER": command[1],
    })
    request = ns.arp_frame(bytes([255]) * 6, ns.SOURCE_MAC, 1, ns.SOURCE_IP, bytes(6), ns.PEER_IP)
    reply = ns.arp_frame(ns.SOURCE_MAC, ns.PEER_MAC, 2, ns.PEER_IP, ns.SOURCE_MAC, ns.SOURCE_IP)
    case = os.environ.get("L2_TEST_VLAN_CASE", "normal")
    with (
        tempfile.TemporaryDirectory(prefix="l2-vlan-fixture-") as directory,
        socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as peer,
        socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as lower,
        socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as logical,
    ):
        peer.bind((ns.PEER, 0))
        lower.bind((ns.SOURCE, 0))
        logical.bind((VLAN, 0))
        peer.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
        lower.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
        peer.settimeout(0.03)
        lower.settimeout(0.03)
        logical.settimeout(0.03)
        ready = Path(directory) / "ready"
        go = Path(directory) / "go"
        environment.update({"L2_TEST_VLAN_READY": str(ready), "L2_TEST_VLAN_GO": str(go)})
        child = ("owned_vlan_child_rejects_wrong_vid_and_observes_matching_reply" if case == "normal"
                 else "owned_vlan_child_checks_reorder_admission_and_changes")
        process = subprocess.Popen(
            [command[0], "--ignored", "--exact", child, "--nocapture"],
            env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            if case != "normal":
                change_case(case, process, peer, lower, logical, request, reply, protocol,
                            ready, go, net_fd, indices, vlan_index)
                return
            deadline = time.monotonic() + 8
            for vid in (WRONG_VID, VID):
                representation = find_packet(peer, tagged(request, protocol, VID), deadline, process, auxiliary=True)
                if representation is None:
                    if process.poll() is not None:
                        stdout, stderr = process.communicate(timeout=2)
                        raise RuntimeError(f"VLAN child exited before a tagged request: {stderr.decode(errors='replace')} {stdout.decode(errors='replace')}")
                    raise RuntimeError("lower peer did not capture the expected 64-byte tagged request")
                print(f"tagged_request_representation={representation}")
                frame = tagged(reply, protocol, vid)
                if peer.send(frame) != len(frame):
                    raise RuntimeError("partial tagged reply send")
                if not find_packet(lower, frame, min(deadline, time.monotonic() + 0.2), auxiliary=True):
                    raise RuntimeError("tagged reply did not reach the lower interface")
                delivered = find_packet(logical, reply, min(deadline, time.monotonic() + 0.2))
                if (delivered is not None) != (vid == VID):
                    raise RuntimeError(f"logical VLAN delivery disagreed with VID {vid}: {delivered}")
            stdout, stderr = process.communicate(timeout=8)
            if process.returncode != 0:
                raise RuntimeError(f"VLAN receiver failed: {stderr.decode(errors='replace')} {stdout.decode(errors='replace')}")
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=2)


def exercise(net_fd, indices, command, parent_net):
    if len(command) != 3 or command[0] not in ("802.1Q", "802.1ad"):
        raise RuntimeError("VLAN fixture requires a supported protocol, runner and helper")
    protocol = command[0]
    owned.require_owned_scope(net_fd, indices)
    ns.command("ip", "link", "add", "link", ns.SOURCE, "name", VLAN, "type", "vlan", "protocol", protocol, "id", str(VID))
    vlan_index = ns.links()[VLAN]["ifindex"]
    try:
        require_vlan_scope(net_fd, indices, vlan_index, protocol)
        ns.command("ip", "link", "set", "dev", VLAN, "addrgenmode", "none")
        if os.environ.get("L2_TEST_VLAN_CASE") == "deny_off":
            ns.command("ip", "link", "set", "dev", VLAN, "type", "vlan", "reorder_hdr", "off")
        ns.command("ip", "address", "add", "192.0.2.1/29", "dev", VLAN)
        ns.command("ip", "link", "set", "dev", VLAN, "up")
        require_vlan_scope(net_fd, indices, vlan_index, protocol)
        exchange(command[1:], parent_net, protocol, net_fd, indices, vlan_index)
    finally:
        require_vlan_scope(net_fd, indices, vlan_index, protocol)
        ns.command("ip", "link", "del", "dev", VLAN)
        owned.require_owned_scope(net_fd, indices)


if __name__ == "__main__":
    try:
        if len(sys.argv) >= 6 and sys.argv[1] == "--child":
            owned.child(
                [int(value) for value in sys.argv[2:5]], int(sys.argv[5]), sys.argv[6:],
                exercise, "vlan_fixture_passed=true",
            )
        elif len(sys.argv) == 4:
            owned.parent(__file__, sys.argv[1:])
        else:
            raise RuntimeError("usage: namespace.py PROTOCOL TEST_RUNNER HELPER")
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(f"isolated VLAN fixture error: {error}", file=sys.stderr)
        sys.exit(1)
