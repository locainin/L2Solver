"""Capture independent RTM_GETLINK replies for isolated VLAN devices."""

import importlib.util
import os
import socket
import struct
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("l2_vlan_fixture", Path(__file__).resolve().parent / "namespace.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("VLAN fixture is unavailable")
vlan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vlan)
owned = vlan.owned
ns = owned.ns


def get_link(index):
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as channel:
        channel.bind((0, 0))
        channel.settimeout(1)
        port = channel.getsockname()[0]
        request = struct.pack("=IHHII", 32, 18, 1, 7, port) + struct.pack("=BBHiII", 0, 0, 0, index, 0, 0)
        if channel.sendto(request, (0, 0)) != len(request):
            raise RuntimeError("partial RTM_GETLINK request")
        response, peer = channel.recvfrom(65_535)
    if len(response) < 16:
        raise RuntimeError("short RTM_GETLINK response")
    length, kind, flags, sequence, destination = struct.unpack("=IHHII", response[:16])
    if (peer != (0, 0) or length != len(response) or kind != 16 or flags != 0
            or sequence != 7 or destination != port):
        raise RuntimeError("unexpected RTM_GETLINK response envelope")
    return response.hex()


def check_protocol(net_fd, indices, protocol, prefix):
    owned.require_owned_scope(net_fd, indices)
    ns.command("ip", "link", "add", "link", ns.SOURCE, "name", vlan.VLAN,
               "type", "vlan", "protocol", protocol, "id", str(vlan.VID))
    index = ns.links()[vlan.VLAN]["ifindex"]
    try:
        vlan.require_vlan_scope(net_fd, indices, index, protocol)
        print(f"{prefix}_index={index}")
        print(f"{prefix}_on={get_link(index)}")
        if protocol == "802.1Q":
            ns.command("ip", "link", "set", "dev", vlan.VLAN, "type", "vlan", "reorder_hdr", "off")
            vlan.require_vlan_scope(net_fd, indices, index, protocol)
            print(f"q_off={get_link(index)}")
    finally:
        vlan.require_vlan_scope(net_fd, indices, index, protocol)
        ns.command("ip", "link", "del", "dev", vlan.VLAN)
        owned.require_owned_scope(net_fd, indices)


def exercise(net_fd, indices, command, parent_net):
    if command:
        check_pin(net_fd, indices, command, parent_net)
        return
    del parent_net
    print(f"parent={indices[ns.SOURCE]}")
    check_protocol(net_fd, indices, "802.1Q", "q")
    check_protocol(net_fd, indices, "802.1ad", "ad")


def run_pin_child(command, parent_net, indices, case, interface):
    environment = os.environ.copy()
    environment.update({
        "L2_TEST_PARENT_NET_DEVICE": str(parent_net[0]),
        "L2_TEST_PARENT_NET_INODE": str(parent_net[1]),
        "L2_TEST_VLAN_PARENT_INDEX": str(indices[ns.SOURCE]),
        "L2_TEST_VLAN_PIN_CASE": case,
        "L2_TEST_VLAN_INTERFACE": interface,
        "L2_ACTIVE_LINUX_TEST_CHILD": "vlan-pin",
    })
    result = subprocess.run(
        [*command, "--exact", "vlan::pin_tests::vlan_pin_retains_parent_and_rejects_stale_or_stacked_scope", "--nocapture"],
        env=environment, capture_output=True, text=True, timeout=8,
    )
    vlan.require_child_pass(result.returncode, result.stdout, result.stderr, "VLAN pin check")


def check_pin(net_fd, indices, command, parent_net):
    owned.require_owned_scope(net_fd, indices)
    ns.command("ip", "link", "add", "link", ns.SOURCE, "name", vlan.VLAN,
               "type", "vlan", "protocol", "802.1Q", "id", str(vlan.VID))
    index = ns.links()[vlan.VLAN]["ifindex"]
    try:
        vlan.require_vlan_scope(net_fd, indices, index, "802.1Q")
        run_pin_child(command, parent_net, indices, "normal", vlan.VLAN)
        vlan.require_vlan_scope(net_fd, indices, index, "802.1Q")
        ns.command("ip", "link", "add", "link", vlan.VLAN, "name", "l2stack0",
                   "type", "vlan", "id", "38")
        stack = ns.links()["l2stack0"]
        try:
            if (stack.get("linkinfo", {}).get("info_kind") != "vlan"
                    or int(Path("/sys/class/net/l2stack0/iflink").read_text()) != index):
                raise RuntimeError("stacked VLAN does not belong to the owned VLAN")
            run_pin_child(command, parent_net, indices, "stacked", "l2stack0")
        finally:
            current = ns.links()
            if current.get("l2stack0", {}).get("ifindex") != stack["ifindex"]:
                raise RuntimeError("stacked VLAN changed before cleanup")
            ns.command("ip", "link", "del", "dev", "l2stack0")
        vlan.require_vlan_scope(net_fd, indices, index, "802.1Q")
    finally:
        vlan.require_vlan_scope(net_fd, indices, index, "802.1Q")
        ns.command("ip", "link", "del", "dev", vlan.VLAN)
        owned.require_owned_scope(net_fd, indices)


if __name__ == "__main__":
    try:
        if len(sys.argv) >= 6 and sys.argv[1] == "--child":
            owned.child([int(value) for value in sys.argv[2:5]], int(sys.argv[5]),
                        sys.argv[6:], exercise, "kernel_vlan_replies=true")
        elif len(sys.argv) == 1:
            owned.parent(__file__, [])
        elif len(sys.argv) > 2 and sys.argv[1] == "--":
            owned.parent(__file__, sys.argv[2:])
        else:
            raise RuntimeError("invalid metadata fixture invocation")
    except (OSError, RuntimeError, ValueError) as error:
        print(f"isolated VLAN metadata fixture error: {error}", file=sys.stderr)
        sys.exit(1)
