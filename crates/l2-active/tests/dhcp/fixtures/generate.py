"""Generate synthetic DHCP fixtures offline with Scapy, without opening sockets."""

from pathlib import Path

from scapy.all import BOOTP, DHCP, Ether, IP, UDP, Raw, raw

OUTPUT = Path(__file__).resolve().parent
CLIENT = "02:00:00:00:00:01"
SERVER = "02:00:00:00:00:02"
OTHER_SERVER = "02:00:00:00:00:03"
TRANSACTION = 0x12345678
COOKIE = bytes.fromhex("63825363")


def frame(*, kind, transaction=TRANSACTION, client=CLIENT, server=SERVER,
          server_ip="192.0.2.1", server_id="192.0.2.1", options=None,
          ip_flags=0, ip_fragment=0, udp_sport=None, udp_dport=68,
          udp_checksum=None, destination_mac=None,
          destination_ip=None, boot_file=b"", server_name=b"", offered_ip="192.0.2.10",
          hardware_type=1, hardware_len=6, relay_ip="0.0.0.0", opcode=2, cookie=COOKIE):
    discover = kind == "discover"
    if discover:
        ethernet = Ether(src=client, dst="ff:ff:ff:ff:ff:ff")
        ip = IP(src="0.0.0.0", dst="255.255.255.255", id=0, ttl=64)
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(op=1, htype=1, hlen=6, xid=transaction,
                      flags=0x8000, chaddr=bytes.fromhex(client.replace(":", "")))
        option_bytes = raw(DHCP(options=[("message-type", "discover"), "end"]))
    else:
        ethernet = Ether(src=server, dst=destination_mac or "ff:ff:ff:ff:ff:ff")
        ip = IP(src=server_ip, dst=destination_ip or "255.255.255.255", id=0, ttl=64, flags=ip_flags, frag=ip_fragment)
        udp = UDP(sport=67 if udp_sport is None else udp_sport, dport=udp_dport, chksum=udp_checksum)
        bootp = BOOTP(op=opcode, htype=hardware_type, hlen=hardware_len, xid=transaction,
                      yiaddr=offered_ip, chaddr=bytes.fromhex(client.replace(":", "")),
                      file=boot_file, sname=server_name, giaddr=relay_ip)
        option_bytes = options if options is not None else raw(DHCP(options=[
            ("message-type", "offer"), ("server_id", server_id), ("lease_time", 3600), "end"
        ]))
    payload = raw(bootp) + cookie + option_bytes
    payload += b"\x00" * max(0, 300 - len(payload))
    return raw(ethernet / ip / udp / Raw(load=payload))


fixtures = {
    "discover.bin": frame(kind="discover"),
    "offer.bin": frame(kind="offer"),
    "wrong-xid.bin": frame(kind="offer", transaction=TRANSACTION + 1),
    "wrong-client.bin": frame(kind="offer", client="02:00:00:00:00:09"),
    "unexpected-server.bin": frame(kind="offer", server=OTHER_SERVER,
                                    server_ip="192.0.2.2", server_id="192.0.2.2"),
    "wrong-port.bin": frame(kind="offer", udp_sport=68),
    "wrong-destination-port.bin": frame(kind="offer", udp_dport=67),
    "wrong-destination-mac.bin": frame(kind="offer", destination_mac="02:00:00:00:00:09"),
    "wrong-destination-ip.bin": frame(kind="offer", destination_mac=CLIENT, destination_ip="192.0.2.99"),
    "invalid-source-ip.bin": frame(kind="offer", server_ip="0.0.0.0"),
    "invalid-source-mac.bin": frame(kind="offer", server="01:00:00:00:00:02"),
    "nonzero-fragment-offset.bin": frame(kind="offer", ip_fragment=1),
    "relay-offer.bin": frame(kind="offer", server_ip="192.0.2.99", relay_ip="192.0.2.254"),
    "bad-cookie.bin": frame(kind="offer", cookie=bytes.fromhex("63825362")),
    "bad-opcode.bin": frame(kind="offer", opcode=1),
    "duplicate-type.bin": frame(kind="offer", options=bytes.fromhex(
        "3501023501053604c0000201330400000e10ff")),
    "overload-duplicate.bin": frame(kind="offer", options=bytes.fromhex(
        "3501023401013604c0000201330400000e10ff"),
        boot_file=bytes.fromhex("3604c0000202ff")),
    "bad-overload.bin": frame(kind="offer", options=bytes.fromhex(
        "3501023401043604c0000201330400000e10ff")),
    "zero-udp-checksum.bin": frame(kind="offer", udp_checksum=0),
    "unicast-offer.bin": frame(kind="offer", destination_mac=CLIENT, destination_ip="192.0.2.10"),
    "bad-hardware-type.bin": frame(kind="offer", hardware_type=6),
    "bad-hardware-length.bin": frame(kind="offer", hardware_len=5),
    "invalid-offered-ip.bin": frame(kind="offer", offered_ip="0.0.0.0"),
    "missing-server.bin": frame(kind="offer", options=bytes.fromhex("350102330400000e10ff")),
    "missing-lease.bin": frame(kind="offer", options=bytes.fromhex("3501023604c0000201ff")),
    "file-overload.bin": frame(kind="offer", options=bytes.fromhex("350102340101ff"),
                                boot_file=bytes.fromhex("3604c0000201330400000e10ff")),
    "zero-overload.bin": frame(kind="offer", options=bytes.fromhex(
        "3501023401003604c0000201330400000e10ff")),
    "overloaded-options.bin": frame(kind="offer", options=bytes.fromhex("350102340103ff"),
                                    boot_file=bytes.fromhex("3604c0000201ff"),
                                    server_name=bytes.fromhex("330400000e10ff")),
    "option-limit.bin": frame(kind="offer", options=bytes.fromhex("c800") * 125 + bytes.fromhex(
        "3501023604c0000201330400000e10ff")),
    "option-over-limit.bin": frame(kind="offer", options=bytes.fromhex("c800") * 126 + bytes.fromhex(
        "3501023604c0000201330400000e10ff")),
    "extra-options.bin": frame(kind="offer", options=bytes.fromhex(
        "00c804010203043604c0000201330400000e10350102ff")),
    "fragment.bin": frame(kind="offer", ip_flags="MF"),
    "reserved-ip-flag.bin": frame(kind="offer", ip_flags=4),
    "dont-fragment.bin": frame(kind="offer", ip_flags="DF"),
    "duplicate-server.bin": frame(kind="offer", options=bytes.fromhex(
        "3501023604c00002013604c0000202ff")),
    "missing-end.bin": frame(kind="offer", options=bytes.fromhex("3501023604c0000201")),
    "truncated-option.bin": frame(kind="offer", options=bytes.fromhex(
        "3501023604c000020137ff") + bytes(60)),
}
for name, data in fixtures.items():
    (OUTPUT / name).write_bytes(data)

# A bounded sequence of independent server claims exercises the observation cap
many = b"".join(frame(kind="offer", server_ip=f"192.0.2.{host}",
                      server_id=f"192.0.2.{host}", offered_ip="192.0.2.200")
                for host in range(1, 66))
(OUTPUT / "many-offers.bin").write_bytes(many)
