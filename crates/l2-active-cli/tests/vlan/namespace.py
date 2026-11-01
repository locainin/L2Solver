"""Check VLAN capability reporting inside a verified disposable namespace."""

import importlib.util
import json
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
vlan_fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vlan_fixture)
owned = vlan_fixture.owned
ns = owned.ns
VLAN = vlan_fixture.VLAN
VID = vlan_fixture.VID


def frontend_command(frontend):
    main = os.environ.get("L2_TEST_MAIN_BINARY")
    return [main, "active"] if main else [frontend]


def probe(frontend, helper, net_fd, indices, vlan_index, protocol, expected):
    vlan_fixture.require_vlan_scope(net_fd, indices, vlan_index, protocol)
    request = ns.arp_frame(bytes([255]) * 6, ns.SOURCE_MAC, 1, ns.SOURCE_IP, bytes(6), ns.PEER_IP)
    reply = ns.arp_frame(ns.SOURCE_MAC, ns.PEER_MAC, 2, ns.PEER_IP, ns.SOURCE_MAC, ns.SOURCE_IP)
    with (socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as peer,
          socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as lower,
          socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as logical):
        peer.bind((ns.PEER, 0))
        lower.bind((ns.SOURCE, 0))
        logical.bind((VLAN, 0))
        for capture in (peer, lower):
            capture.setsockopt(vlan_fixture.SOL_PACKET, vlan_fixture.PACKET_AUXDATA, 1)
        for capture in (peer, lower, logical):
            capture.settimeout(0.03)
        process = subprocess.Popen(
            frontend_command(frontend) + [
                "arp", "probe", "--interface", VLAN, "--target", socket.inet_ntoa(ns.PEER_IP),
                "--source-ip", socket.inet_ntoa(ns.SOURCE_IP), "--timeout-ms", "2500", "--format", "json",
                "--helper", helper,
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            wire_request = vlan_fixture.tagged(request, protocol, VID)
            representation = vlan_fixture.find_packet(peer, wire_request, time.monotonic() + 5, process, auxiliary=True)
            if representation is None:
                raise RuntimeError("tagged ARP request was not observed on the owned peer")
            vlan_fixture.require_vlan_scope(net_fd, indices, vlan_index, protocol)
            for reply_vid in (vlan_fixture.WRONG_VID, VID):
                wire_reply = vlan_fixture.tagged(reply, protocol, reply_vid)
                if peer.send(wire_reply) != len(wire_reply):
                    raise RuntimeError("partial tagged ARP reply")
                deadline = time.monotonic() + 0.25
                if not vlan_fixture.find_packet(lower, wire_reply, deadline, auxiliary=True):
                    raise RuntimeError("tagged ARP reply did not reach the lower link")
                received = vlan_fixture.find_packet(logical, reply, deadline)
                if (received is not None) != (reply_vid == VID):
                    raise RuntimeError(f"logical VLAN delivery disagreed with VID {reply_vid}")
            stdout, stderr = process.communicate(timeout=6)
            if process.returncode != 0:
                raise RuntimeError(f"VLAN probe failed: {stderr.decode(errors='replace')} {stdout.decode(errors='replace')}")
            report = json.loads(stdout)
            if (report.get("scope", {}).get("vlan") != expected
                    or report.get("scope", {}).get("scope_validation") != "sampled"
                    or report.get("scope", {}).get("ifindex") != vlan_index
                    or report.get("completion") != "complete"
                    or report.get("cleanup", {}).get("confirmed") is not True
                    or len(report.get("replies", [])) != 1
                    or report["replies"][0].get("frame_hex") != reply.hex()):
                raise RuntimeError(f"VLAN probe scope or evidence did not match: {report}")
            print(f"tagged_request_representation={representation} wrong_vid_excluded=true reply_captured=true")
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=2)


def exercise(net_fd, indices, command, _parent_net):
    if len(command) not in (2, 3) or command[0] not in ("802.1Q", "802.1ad"):
        raise RuntimeError("VLAN report fixture requires a protocol, frontend and optional helper")
    protocol, frontend = command[:2]
    helper = command[2] if len(command) == 3 else None
    owned.require_owned_scope(net_fd, indices)
    ns.command("ip", "link", "add", "link", ns.SOURCE, "name", VLAN,
               "type", "vlan", "protocol", protocol, "id", str(VID))
    vlan_index = ns.links()[VLAN]["ifindex"]
    try:
        vlan_fixture.require_vlan_scope(net_fd, indices, vlan_index, protocol)
        ns.command("ip", "address", "add", "192.0.2.1/29", "dev", VLAN)
        ns.command("ip", "link", "set", "dev", VLAN, "up")
        for reorders in (True, False):
            if not reorders:
                ns.command("ip", "link", "set", "dev", VLAN, "type", "vlan", "reorder_hdr", "off")
            vlan_fixture.require_vlan_scope(net_fd, indices, vlan_index, protocol)
            result = subprocess.run(
                frontend_command(frontend) + ["capabilities", "--interface", VLAN, "--format", "json"],
                check=True, capture_output=True, text=True, timeout=8,
            )
            report = json.loads(result.stdout)
            parent = os.stat(Path("/sys/class/net", ns.SOURCE))
            namespace_device, namespace_inode = ns.identity(net_fd)
            expected = {
                "id": VID,
                "protocol": protocol,
                "parent": {
                    "ifindex": indices[ns.SOURCE],
                    "namespace_device": namespace_device,
                    "namespace_inode": namespace_inode,
                    "interface_device": parent.st_dev,
                    "interface_inode": parent.st_ino,
                },
                "reorders_headers": reorders,
            }
            if report.get("vlan") != expected or report.get("scope_validation") != "sampled":
                raise RuntimeError(f"VLAN report did not match the kernel scope: {report}")
            if report.get("ifindex") != vlan_index:
                raise RuntimeError("VLAN report selected a different interface")
            if reorders and helper is not None:
                probe(frontend, helper, net_fd, indices, vlan_index, protocol, expected)
    finally:
        vlan_fixture.require_vlan_scope(net_fd, indices, vlan_index, protocol)
        ns.command("ip", "link", "del", "dev", VLAN)
        owned.require_owned_scope(net_fd, indices)


if __name__ == "__main__":
    try:
        if len(sys.argv) >= 6 and sys.argv[1] == "--child":
            owned.child(
                [int(value) for value in sys.argv[2:5]], int(sys.argv[5]), sys.argv[6:],
                exercise, "vlan_report_passed=true",
            )
        elif len(sys.argv) in (2, 3):
            for protocol in ("802.1Q", "802.1ad"):
                owned.parent(__file__, [protocol, *sys.argv[1:]])
        else:
            raise RuntimeError("usage: namespace.py FRONTEND [HELPER]")
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(f"isolated VLAN report fixture error: {error}", file=sys.stderr)
        sys.exit(1)
