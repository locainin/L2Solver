"""Create a small capture with a known native HTTP body."""

import struct

BODY = b"l2solver packaged candidate fixture\n"


def _checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _frame(sequence, flags, payload):
    source = bytes((192, 0, 2, 10))
    destination = bytes((192, 0, 2, 20))
    length = 20 + len(payload)
    tcp = (
        struct.pack("!HHIIBBHHH", 40000, 80, sequence, 0, 0x50, flags, 1024, 0, 0)
        + payload
    )
    # Real packet checksums keep the fixture usable by independent tools
    pseudo = source + destination + struct.pack("!BBH", 0, 6, length)
    tcp = tcp[:16] + struct.pack("!H", _checksum(pseudo + tcp)) + tcp[18:]
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + length, 1, 0, 64, 6, 0, source, destination
    )
    header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
    return b"\x00" * 12 + b"\x08\x00" + header + tcp


def http_capture():
    request = (
        b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: "
        + str(len(BODY)).encode("ascii")
        + b"\r\n\r\n"
        + BODY
    )
    frames = (_frame(100, 0x02, b""), _frame(101, 0x18, request))
    capture = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for number, frame in enumerate(frames):
        capture.extend(struct.pack("<IIII", 1, number, len(frame), len(frame)))
        capture.extend(frame)
    return bytes(capture)
