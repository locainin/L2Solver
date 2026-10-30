"""Check fixed capture filters only inside a verified disposable veth."""

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
CRATES = HERE.parents[2]
HARNESS = CRATES / "l2-active/tests/support/owned_veth.py"
SPEC = importlib.util.spec_from_file_location("l2_owned_veth", HARNESS)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("owned veth harness is unavailable")
owned = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(owned)
ns = owned.ns


def mutate(frame, offset, value):
    result = bytearray(frame)
    result[offset : offset + len(value)] = value
    return bytes(result)


def witness_frame(witness, frame, deadline):
    tagged = frame[12:14] == bytes.fromhex("8100")
    stripped = frame[:12] + frame[16:] if tagged else frame
    for _ in range(64):
        if time.monotonic() >= deadline:
            break
        try:
            data, controls, _, _ = witness.recvmsg(65_535, socket.CMSG_SPACE(20))
        except TimeoutError:
            continue
        if data != stripped:
            continue
        if not tagged:
            return
        for level, kind, control in controls:
            if level == 263 and kind == 8 and len(control) >= 20:
                status, _, _, _, _, tci, _ = struct.unpack("=IIIHHHH", control[:20])
                if status & (1 << 4) and tci == 7:
                    return
    raise RuntimeError("expected packet or stripped VLAN metadata was not observed")


def frames():
    # The external packet encoder is loaded only inside the proved namespace
    from scapy.all import ARP, Ether, ICMPv6ND_NA, ICMPv6ND_NS
    from scapy.all import ICMPv6NDOptDstLLAddr, ICMPv6NDOptSrcLLAddr, IP, IPv6, LLC, SNAP, Dot3, raw
    from scapy.layers.inet import IPOption_EOL, IPOption_NOP
    from scapy.contrib.cdp import CDPMsgDeviceID, CDPMsgPortID, CDPv2_HDR

    local = owned.CLIENT_MAC
    peer = owned.PEER_MAC
    arp = raw(Ether(src=peer, dst=local) / ARP(op=2, hwsrc=peer, psrc="192.0.2.2", hwdst=local, pdst="192.0.2.1")).ljust(60, bytes(1))
    arp_request = raw(Ether(src=local, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=local, psrc="192.0.2.1", hwdst="00:00:00:00:00:00", pdst="192.0.2.2")).ljust(60, bytes(1))
    arp_wrong_target = mutate(arp, 28, bytes.fromhex("c0000203"))
    arp_broadcast_reply = mutate(arp, 0, bytes.fromhex("ffffffffffff"))
    arp_other_client = mutate(mutate(arp, 0, bytes.fromhex("ffffffffffff")), 38, bytes.fromhex("c0000203"))
    arp_other_destination = mutate(arp, 5, bytes([3]))
    arp_other_target_mac = mutate(mutate(arp, 0, bytes.fromhex("ffffffffffff")), 37, bytes([3]))
    arp_inbound_request = mutate(arp, 21, bytes([1]))
    arp_bad_header = mutate(arp, 15, bytes([0]))

    dhcp = (CRATES / "l2-active/tests/dhcp/fixtures/offer.bin").read_bytes()
    dhcp_request = (CRATES / "l2-active/tests/dhcp/fixtures/discover.bin").read_bytes()
    dhcp_wrong_transaction = mutate(dhcp, 46, bytes.fromhex("87654321"))
    dhcp_other_client = mutate(dhcp, 75, bytes([3]))
    dhcp_other_destination = mutate(dhcp, 0, bytes.fromhex("020000000003"))
    dhcp_bad_checksum = mutate(dhcp, 24, bytes([dhcp[24] ^ 1]))
    dhcp_options_packet = Ether(dhcp)
    dhcp_options_packet[IP].options = [IPOption_NOP(), IPOption_NOP(), IPOption_NOP(), IPOption_EOL()]
    del dhcp_options_packet[IP].ihl
    del dhcp_options_packet[IP].len
    del dhcp_options_packet[IP].chksum
    dhcp_options = raw(dhcp_options_packet)
    dhcp_bad_ihl = mutate(dhcp, 14, bytes([0x44]))
    dhcp_fragment = mutate(dhcp, 20, bytes.fromhex("2000"))
    dhcp_bad_port = mutate(dhcp, 36, bytes.fromhex("0043"))

    ndp = raw(Ether(src=peer, dst=local) / IPv6(src="fe80::2", dst="fe80::1", hlim=255) / ICMPv6ND_NA(tgt="fe80::2", S=1, O=1) / ICMPv6NDOptDstLLAddr(lladdr=peer))
    ndp_request = raw(Ether(src=local, dst="33:33:ff:00:00:02") / IPv6(src="fe80::1", dst="ff02::1:ff00:2", hlim=255) / ICMPv6ND_NS(tgt="fe80::2") / ICMPv6NDOptSrcLLAddr(lladdr=local))
    ndp_wrong_target = mutate(ndp, 77, bytes([3]))
    ndp_wrong_prefix = mutate(ndp, 62, bytes([0xfd]))
    ndp_wrong_type = mutate(ndp, 54, bytes([134]))
    ndp_other_destination = mutate(ndp, 5, bytes([3]))
    ndp_other_client = mutate(ndp, 53, bytes([3]))
    ndp_bad_hop = mutate(ndp, 21, bytes([254]))

    eap = (CRATES / "l2-active/tests/dot1x/fixtures/request.bin").read_bytes()
    eap_start = (CRATES / "l2-active/tests/dot1x/fixtures/start.bin").read_bytes()
    eap_response = mutate(eap, 18, bytes([2]))
    eapol_key = mutate(eap, 15, bytes([3]))
    nonempty_start = mutate(eap_start, 16, bytes.fromhex("0001"))
    eap_bad_version = mutate(eap, 14, bytes([0]))
    eap_group_request = mutate(eap, 0, bytes.fromhex("0180c2000003"))
    eap_other_destination = mutate(eap, 5, bytes([3]))
    eap_foreign_start = mutate(eap_start, 11, bytes([2]))
    eap_spoofed_start = mutate(eap_start, 18, b"private inbound data")

    lldp = (CRATES / "l2-active/tests/fixtures/lldp-advertisement.bin").read_bytes()
    lldp = mutate(lldp, 6, bytes.fromhex(peer.replace(":", "")))
    lldp_wrong_scope = mutate(lldp, 5, bytes([15]))
    lldp_bad_tlv = mutate(lldp, 14, bytes([0xff]))
    lldp_nearest_non_tpmr = mutate(lldp, 5, bytes([3]))
    lldp_nearest_customer = mutate(lldp, 5, bytes([0]))
    cdp = raw(Dot3(dst="01:00:0c:cc:cc:cc", src=peer) / LLC(dsap=0xaa, ssap=0xaa, ctrl=3) / SNAP(OUI=0x00000c, code=0x2000) / CDPv2_HDR(ttl=120, msg=[CDPMsgDeviceID(val=b"switch-a"), CDPMsgPortID(iface=b"Gi1/0/1")])).ljust(60, bytes(1))
    cdp_wrong_scope = mutate(cdp, 5, bytes([0xcd]))

    stp = (CRATES / "l2-active/tests/fixtures/stp-configuration.bin").read_bytes()
    stp = mutate(stp, 6, bytes.fromhex(peer.replace(":", ""))).ljust(60, bytes(1))
    stp_other_llc = mutate(stp, 14, bytes([0x43]))
    stp_other_group = mutate(stp, 5, bytes([14]))
    stp_bad_protocol = mutate(stp, 17, bytes([1]))

    unrelated_ip = bytes.fromhex("02000000000102000000000208004500002e0000000040060000c0000201c0000202") + b"private unrelated traffic"
    cases = [
        ([arp, arp_broadcast_reply, arp_bad_header], [unrelated_ip, arp_wrong_target, arp_other_client, arp_other_destination, arp_other_target_mac, arp_inbound_request], arp_request),
        ([dhcp, dhcp_bad_checksum, dhcp_options], [unrelated_ip, dhcp_wrong_transaction, dhcp_other_client, dhcp_other_destination, dhcp_bad_ihl, dhcp_fragment, dhcp_bad_port], dhcp_request),
        ([ndp, ndp_bad_hop], [unrelated_ip, ndp_wrong_target, ndp_wrong_prefix, ndp_wrong_type, ndp_other_destination, ndp_other_client, ndp_request], ndp_request),
        ([eap, eap_bad_version, eap_group_request], [unrelated_ip, eap_response, eapol_key, nonempty_start, eap_other_destination, eap_foreign_start, eap_spoofed_start], eap_start),
        ([lldp, lldp_bad_tlv, cdp, lldp_nearest_non_tpmr, lldp_nearest_customer], [unrelated_ip, lldp_wrong_scope, cdp_wrong_scope], lldp),
        ([stp, stp_bad_protocol], [unrelated_ip, stp_other_llc, stp_other_group], stp),
    ]
    # Each profile must reject a tag stripped into kernel VLAN metadata
    for accepted, rejected, _ in cases:
        frame = accepted[0]
        rejected.append(frame[:12] + bytes.fromhex("81000007") + frame[12:])
    return cases


def exercise(net_fd, indices, command, parent_net):
    if not command:
        raise RuntimeError("filter fixture requires the test command")
    owned.require_owned_scope(net_fd, indices)
    cases = frames()
    with tempfile.TemporaryDirectory(prefix="l2-filter-fixture-") as directory:
        directory = Path(directory)
        for index, (accepted, _, _) in enumerate(cases):
            (directory / f"count-{index}").write_text(str(len(accepted)), encoding="ascii")
            for item, packet in enumerate(accepted):
                (directory / f"expected-{index}-{item}").write_bytes(packet)
        environment = os.environ.copy()
        environment.update({
            "L2_TEST_PARENT_NET_DEVICE": str(parent_net[0]),
            "L2_TEST_PARENT_NET_INODE": str(parent_net[1]),
            "L2_TEST_FILTER_INTERFACE": ns.SOURCE,
            "L2_TEST_FILTER_DIRECTORY": str(directory),
        })
        with (
            socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as peer,
            socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as local_sender,
            socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as witness,
        ):
            peer.bind((ns.PEER, 0))
            local_sender.bind((ns.SOURCE, 0))
            witness.bind((ns.SOURCE, 0))
            witness.setsockopt(263, 8, 1)
            peer.settimeout(0.05)
            witness.settimeout(0.05)
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
            try:
                deadline = time.monotonic() + 15
                for index, (accepted, rejected, outgoing) in enumerate(cases):
                    ready = directory / f"ready-{index}"
                    while not ready.is_file():
                        if process.poll() is not None:
                            stdout, stderr = process.communicate(timeout=2)
                            raise RuntimeError(f"filter child exited: {stderr.decode(errors='replace')} {stdout.decode(errors='replace')}")
                        if time.monotonic() >= deadline:
                            raise RuntimeError(f"filter {index} did not become ready")
                        time.sleep(0.005)
                    traffic = [(packet, peer) for packet in rejected]
                    traffic.append((outgoing, local_sender))
                    traffic.extend((packet, peer) for packet in accepted)
                    for packet, sender in traffic:
                        owned.require_owned_scope(net_fd, indices)
                        if sender.send(packet) != len(packet):
                            raise RuntimeError("partial packet send")
                        # An unfiltered witness proves that rejected frames reached the device
                        witness_frame(witness, packet, deadline)
                    done = directory / f"observed-{index}"
                    while not done.is_file():
                        if process.poll() is not None:
                            stdout, stderr = process.communicate(timeout=2)
                            raise RuntimeError(f"filter child exited: {stderr.decode(errors='replace')} {stdout.decode(errors='replace')}")
                        if time.monotonic() >= deadline:
                            raise RuntimeError(f"filter {index} did not finish")
                        time.sleep(0.005)
                stdout, stderr = process.communicate(timeout=3)
                if process.returncode != 0:
                    raise RuntimeError(f"filter child failed: {stderr.decode(errors='replace')} {stdout.decode(errors='replace')}")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=2)


if __name__ == "__main__":
    try:
        if len(sys.argv) >= 6 and sys.argv[1] == "--child":
            owned.child(
                [int(value) for value in sys.argv[2:5]], int(sys.argv[5]), sys.argv[6:],
                exercise, "filters_checked=true",
            )
        elif len(sys.argv) > 2 and sys.argv[1] == "--":
            owned.parent(__file__, sys.argv[2:])
        else:
            raise RuntimeError("usage: namespace.py -- COMMAND ARG ...")
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(f"isolated filter fixture error: {error}", file=sys.stderr)
        sys.exit(1)
