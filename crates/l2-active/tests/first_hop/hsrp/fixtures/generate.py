"""Generate independent HSRP Ethernet frames with Scapy 2.8.0."""

from pathlib import Path

from scapy.all import Ether, IP, Raw, UDP, raw
from scapy.layers.hsrp import HSRP, HSRPv2

HERE = Path(__file__).resolve().parent
AUTHENTICATION = b"AuthP@ss"
PADDING = b"PAD-SECRET"


def advertisement(*, options=b"", extension=b"", group=0, ttl=1):
    ethernet = Ether(src="02:00:00:00:00:02", dst="01:00:5e:00:00:02")
    ip = IP(src="192.0.2.2", dst="224.0.0.2", ttl=ttl, options=options)
    udp = UDP(sport=1985, dport=1985)
    hsrp = HSRP(
        version=0,
        opcode=0,
        state=16,
        hellotime=3,
        holdtime=10,
        priority=120,
        group=group,
        auth=AUTHENTICATION,
        virtualIP="192.0.2.1",
    )
    packet = ethernet / ip / udp / hsrp
    if extension:
        packet /= Raw(extension)
    # Padding lies outside the declared IP and UDP lengths
    return raw(packet) + PADDING


def version_two():
    return raw(
        Ether(src="02:00:00:00:00:02", dst="01:00:5e:00:00:66")
        / IP(src="192.0.2.2", dst="224.0.0.102", ttl=1)
        / UDP(sport=1985, dport=1985)
        / HSRPv2(version=2, group=256, virtualIP="192.0.2.1")
    )


fixtures = {
    "advertisement.bin": advertisement(),
    "ip-options.bin": advertisement(options=b"\x01" * 4),
    "max-ip-options.bin": advertisement(options=b"\x01" * 40),
    "extension.bin": advertisement(extension=b"TRAILER-SECRET"),
    "hsrp-v2.bin": version_two(),
    "other-group.bin": advertisement(group=255),
    "bad-ttl.bin": advertisement(ttl=2),
}
for name, content in fixtures.items():
    (HERE / name).write_bytes(content)
