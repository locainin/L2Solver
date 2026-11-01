"""Generate independent synthetic VRRPv3 frames with Scapy 2.8.0."""

from pathlib import Path

from scapy.all import IP, Ether, Raw, VRRP, VRRPv3, raw
from scapy.utils import checksum

HERE = Path(__file__).resolve().parent
PEER = "192.0.2.1"
GROUP = "224.0.0.18"
DESTINATION = "01:00:5e:00:00:12"
ADDRESSES = ["192.0.2.254", "198.51.100.254"]


def padded(frame):
    encoded = raw(frame)
    return encoded + bytes(max(0, 60 - len(encoded)))


def advertisement(
    *,
    vrid=42,
    priority=110,
    reserved=0,
    ttl=255,
    sender=None,
    source=PEER,
    flags=0,
    kind=1,
    addresses=ADDRESSES,
    pseudo=False,
    extra=b"",
    options=b"",
    ip_length=None,
):
    sender = sender or f"00:00:5e:00:01:{vrid:02x}"
    vrrp = VRRPv3(
        vrid=vrid,
        priority=priority,
        res=reserved,
        adv=100,
        type=kind,
        addrlist=addresses,
        chksum=0,
    )
    if pseudo:
        vrrp.chksum = None
    ethernet = Ether(src=sender, dst=DESTINATION)
    ip = IP(
        src=source,
        dst=GROUP,
        ttl=ttl,
        proto=112,
        flags=flags,
        id=0,
        options=options,
        len=ip_length,
    )
    frame = bytearray(raw(ethernet / ip / vrrp))
    body_start = 14 + (frame[14] & 0x0F) * 4
    checksum_start = body_start + 6
    if not pseudo:
        # IPv4 context lets Scapy encode address bytes before the RFC checksum
        frame[checksum_start : checksum_start + 2] = checksum(
            bytes(frame[body_start:])
        ).to_bytes(2, "big")
    if extra:
        return padded(ethernet / ip / Raw(bytes(frame[body_start:]) + extra))
    return padded(bytes(frame))


zero_count = bytearray(advertisement())
zero_count[37] = 0
zero_count[40:42] = bytes(2)
zero_count[40:42] = checksum(bytes(zero_count[34:42])).to_bytes(2, "big")

fixtures = {
    "v2-auth.bin": padded(
        Ether(src="00:00:5e:00:01:2a", dst=DESTINATION)
        / IP(src=PEER, dst=GROUP, ttl=255, proto=112, id=0)
        / VRRP(
            vrid=42,
            authtype=1,
            addrlist=ADDRESSES,
            auth1=int.from_bytes(b"VRRP", "big"),
            auth2=int.from_bytes(b"auth", "big"),
        )
    ),
    "valid.bin": advertisement(),
    "pseudo.bin": advertisement(pseudo=True),
    "other-vrid.bin": advertisement(vrid=43),
    "sender-anomaly.bin": advertisement(sender="02:00:00:00:00:02"),
    "reserved.bin": advertisement(reserved=15),
    "relinquish.bin": advertisement(priority=0),
    "bad-ttl.bin": advertisement(ttl=254),
    "fragment.bin": advertisement(flags="MF"),
    "bad-source.bin": advertisement(source="0.0.0.0"),
    "zero-vrid.bin": advertisement(vrid=0),
    "zero-count.bin": bytes(zero_count),
    "bad-type.bin": advertisement(kind=2),
    "extra-ip.bin": advertisement(extra=b"extra"),
    "options.bin": advertisement(options=b"\x01" * 4),
    "maximum.bin": advertisement(
        vrid=255,
        options=b"\x01" * 40,
        addresses=[f"198.18.{index // 254}.{index % 254 + 1}" for index in range(255)],
    ),
    "short-ip.bin": advertisement(ip_length=20),
}
for name, frame in fixtures.items():
    (HERE / name).write_bytes(frame)
