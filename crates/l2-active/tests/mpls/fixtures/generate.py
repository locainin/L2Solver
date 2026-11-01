"""Generate independent synthetic MPLS stacks with Scapy."""

from pathlib import Path

from scapy.all import Ether, Raw, raw
from scapy.contrib.mpls import MPLS

HERE = Path(__file__).resolve().parent
DESTINATION = "02:00:00:00:00:01"
SOURCE = "02:00:00:00:00:02"
PAYLOAD = b"SENSITIVE-PAYLOAD-" + bytes(20)


def frame(entries, payload=PAYLOAD, destination=DESTINATION, ethertype=0x8847):
    packet = Ether(dst=destination, src=SOURCE, type=ethertype)
    for label, tc, bottom, ttl in entries:
        packet = packet / MPLS(label=label, cos=tc, s=bottom, ttl=ttl)
    if payload:
        packet = packet / Raw(payload)
    return raw(packet)


fixtures = {
    "valid.bin": frame([(100, 5, 0, 64), (1_048_575, 7, 1, 1)]),
    "zero-ttl.bin": frame([(100, 5, 0, 0), (1_048_575, 7, 1, 1)]),
    "foreign.bin": frame(
        [(100, 5, 0, 64), (1_048_575, 7, 1, 1)], destination="02:00:00:00:00:03"
    ),
    "upstream.bin": frame(
        [(100, 5, 0, 64), (1_048_575, 7, 1, 1)], ethertype=0x8848
    ),
    "max-depth.bin": frame(
        [(16 + index, 0, int(index == 15), 64) for index in range(16)]
    ),
    "over-depth.bin": frame(
        [(16 + index, 0, int(index == 16), 64) for index in range(17)]
    ),
    "short.bin": raw(
        Ether(dst=DESTINATION, src=SOURCE, type=0x8847) / Raw(b"\x00\x01")
    ),
    "no-payload.bin": frame([(100, 0, 1, 64)], b""),
    "null-v4.bin": frame([(0, 0, 1, 64)]),
    "null-v6.bin": frame([(2, 0, 1, 64)]),
    "bad-null.bin": frame([(0, 0, 0, 64), (100, 0, 1, 64)]),
    "bad-alert.bin": frame([(1, 0, 1, 64)]),
    "implicit-null.bin": frame([(3, 0, 1, 64)]),
    "mna.bin": frame([(100, 0, 0, 64), (4, 0, 0, 64), (0, 0, 1, 64)]),
    "eli.bin": frame([(100, 0, 0, 64), (7, 0, 0, 64), (101, 0, 1, 64)]),
    "extension.bin": frame([(100, 0, 0, 64), (15, 0, 0, 64), (0, 0, 1, 64)]),
}

for name, contents in fixtures.items():
    (HERE / name).write_bytes(contents)
