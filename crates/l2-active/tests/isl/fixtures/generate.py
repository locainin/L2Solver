"""Generate ISL fixtures from Cisco's header layout and Scapy Ethernet."""

from pathlib import Path
from struct import pack
from zlib import crc32

from scapy.all import Dot3, Ether, IP, Raw, UDP, raw

HERE = Path(__file__).resolve().parent

# Scapy builds the inner Ethernet packet independently of the Rust parser
inner = raw(
    Ether(src="02:00:00:00:00:31", dst="02:00:00:00:00:32")
    / IP(src="192.0.2.31", dst="192.0.2.32")
    / UDP(sport=12345, dport=54321)
    / Raw(b"PRIVATE-USER-CONTENT")
)
inner += bytes(max(0, 60 - len(inner)))
inner += pack("<I", crc32(inner))

# Cisco's length includes the 12-byte ISL suffix and entire inner frame
body = b"\xaa\xaa\x03\x00\x00\x0c" + pack("!HHH", (37 << 1) | 1, 17, 0) + inner
valid = raw(Dot3(dst="01:00:0c:00:00:03", src="02:00:00:00:00:02", len=len(body)) / Raw(body))


def altered(index, value):
    result = bytearray(valid)
    result[index] = value
    return bytes(result)


fixtures = {
    "valid.bin": valid,
    "other-prefix.bin": altered(4, 1),
    "unsupported-media.bin": altered(5, 0x13),
    "malformed-llc.bin": altered(14, 0),
    "unsupported-length.bin": valid[:12] + b"\x00\x00" + valid[14:],
}
for name, content in fixtures.items():
    (HERE / name).write_bytes(content)
