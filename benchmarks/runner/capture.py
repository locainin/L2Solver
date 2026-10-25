"""Independent PCAP record bounds; no application or network parsing."""

import struct
from collections import deque
from dataclasses import dataclass

CAPTURE_READ_CHUNK_BYTES = 64 * 1024


class SeekableCapture:
    """Bounded random reads over one seekable capture file."""

    def __init__(self, stream):
        self._stream = stream
        stream.seek(0, 2)
        self._length = stream.tell()
        self._cache_offset = -1
        self._cache = b""

    def __len__(self):
        return self._length

    def __getitem__(self, key):
        if isinstance(key, slice):
            start, end, step = key.indices(self._length)
            if step != 1:
                raise ValueError("capture scanner requires contiguous slices")
            return self.read_range(start, max(0, end - start))
        index = key if key >= 0 else self._length + key
        return self.read_range(index, 1)[0]

    def read_range(self, offset, length):
        if type(offset) is not int or type(length) is not int or offset < 0 or length < 0:
            raise ValueError("capture range must use nonnegative integers")
        if offset > self._length or length > self._length - offset:
            raise ValueError("capture range exceeds the source")
        if length > CAPTURE_READ_CHUNK_BYTES:
            raise ValueError("capture range exceeds the bounded read size")
        if length == 0:
            return b""
        if self._contains(offset, length):
            return self._cached_range(offset, length)
        self._load_window(offset)
        if self._contains(offset, length):
            return self._cached_range(offset, length)
        return self._read_across_windows(offset, length)

    def iter_chunks(self, offset, length):
        if type(offset) is not int or type(length) is not int or offset < 0 or length < 0:
            raise ValueError("capture range must use nonnegative integers")
        if offset > self._length or length > self._length - offset:
            raise ValueError("capture range exceeds the source")
        while length:
            size = min(CAPTURE_READ_CHUNK_BYTES, length)
            yield self.read_range(offset, size)
            offset += size
            length -= size

    def _contains(self, offset, length):
        return self._cache_offset <= offset and offset + length <= self._cache_offset + len(self._cache)

    def _cached_range(self, offset, length):
        start = offset - self._cache_offset
        return self._cache[start:start + length]

    def _load_window(self, offset):
        self._cache_offset = offset - offset % CAPTURE_READ_CHUNK_BYTES
        window_length = min(CAPTURE_READ_CHUNK_BYTES, self._length - self._cache_offset)
        self._stream.seek(self._cache_offset)
        self._cache = self._stream.read(window_length)
        if len(self._cache) != window_length:
            raise ValueError("capture source ended during a bounded read")

    def _read_across_windows(self, offset, length):
        value = bytearray(length)
        written = 0
        while written < length:
            if not self._contains(offset + written, 1):
                self._load_window(offset + written)
            available = self._cache_offset + len(self._cache) - offset - written
            size = min(length - written, available)
            start = offset + written - self._cache_offset
            value[written:written + size] = self._cache[start:start + size]
            written += size
        return bytes(value)


@dataclass(frozen=True)
class Packet:
    offset: int
    length: int
    original_length: int
    link_type: int
    timestamp: dict | None
    timestamp_source_offset: int | None


@dataclass(frozen=True)
class PacketIndex:
    records: list
    total: int

    def __len__(self):
        return self.total

    def __getitem__(self, index):
        if not 0 <= index < len(self.records):
            raise ValueError("packet annotation exceeds the retained index prefix")
        return self.records[index]


@dataclass(frozen=True)
class PacketWindow:
    total: int
    first_record: int
    records: list

    def __len__(self):
        return self.total

    def __getitem__(self, index):
        record_number = index + 1
        last_record = self.first_record + len(self.records) - 1
        if not self.first_record <= record_number <= last_record:
            raise ValueError("packet annotation is outside the retained stream window")
        return self.records[record_number - self.first_record]


def integer(data, offset, format_):
    try:
        return struct.unpack(format_, data[offset:offset + struct.calcsize(format_)])[0]
    except struct.error as error:
        raise ValueError("truncated capture field") from error


def packet_index(data):
    records, total = [], 0
    for packet in iter_packets(data):
        # Keep only the prefix used by ordinary case validation
        if total < 65536:
            records.append(packet)
        total += 1
    return PacketIndex(records, total)


def iter_packets(data):
    magic = bytes(data[:4])
    formats = {b"\xd4\xc3\xb2\xa1": ("<", 6), b"\xa1\xb2\xc3\xd4": (">", 6),
               b"\x4d\x3c\xb2\xa1": ("<", 9), b"\xa1\xb2\x3c\x4d": (">", 9)}
    if magic in formats:
        source = classic_packets(data, *formats[magic])
    elif magic == b"\x0a\x0d\x0d\x0a":
        source = ng_packets(data)
    else:
        raise ValueError("unsupported capture magic")
    yield from source


def iter_packet_windows(data, windows, context_records, expected_total):
    source = iter(iter_packets(data))
    history = deque(maxlen=context_records)
    next_primary = 1

    for first_record, last_record, context_first_record in windows:
        if first_record != next_primary or last_record < first_record:
            raise ValueError("stream primary page ranges do not form a consecutive partition")
        if not max(1, first_record - context_records) <= context_first_record <= first_record:
            raise ValueError("stream context window exceeds its record bound")

        # Previously parsed records supply only the bounded context overlap
        window = [(number, packet) for number, packet in history
                  if context_first_record <= number < first_record]
        if len(window) != first_record - context_first_record:
            raise ValueError("stream context window is not retained from prior records")

        for number in range(first_record, last_record + 1):
            try:
                packet = next(source)
            except StopIteration as error:
                raise ValueError("stream page range exceeds capture records") from error
            window.append((number, packet))
            if context_records:
                history.append((number, packet))
        next_primary = last_record + 1
        yield PacketWindow(expected_total, context_first_record,
                           [packet for _, packet in window])

    observed_total = next_primary - 1
    if observed_total != expected_total:
        raise ValueError("stream page ranges do not cover the declared source record count")
    try:
        next(source)
    except StopIteration:
        return
    raise ValueError("capture contains packet records outside declared stream windows")


def timestamp(ticks, radix, exponent, offset=0):
    return {"ticks": ticks, "radix": radix, "exponent": exponent, "offset_seconds": offset}


def classic_packets(data, endian, exponent):
    if len(data) < 24 or struct.unpack(endian + "HH", data[4:8]) != (2, 4):
        raise ValueError("unsupported classic PCAP header")
    link_type = integer(data, 20, endian + "I") & 0xFFFF
    cursor = 24
    while cursor < len(data):
        if len(data) - cursor < 16:
            raise ValueError("truncated classic PCAP record")
        seconds, fraction, captured, original = struct.unpack(
            endian + "IIII", data[cursor:cursor + 16]
        )
        start, end = cursor + 16, cursor + 16 + captured
        if end > len(data) or fraction >= 10 ** exponent or original < captured:
            raise ValueError("invalid classic PCAP record bounds or timestamp")
        yield Packet(start, captured, original, link_type,
                     timestamp(seconds * 10 ** exponent + fraction, 10, exponent), cursor)
        cursor = end


def options(data, start, end, endian):
    values = {}
    while start < end:
        if end - start < 4:
            raise ValueError("truncated PCAPNG option")
        code, length = struct.unpack(endian + "HH", data[start:start + 4])
        start += 4
        if code == 0:
            if length != 0:
                raise ValueError("invalid PCAPNG end option")
            break
        if start + length > end:
            raise ValueError("PCAPNG option exceeds its block")
        if code in (9, 14) and code in values:
            raise ValueError("duplicate PCAPNG clock option")
        if code in (9, 14):
            values[code] = bytes(data[start:start + length])
        start += (length + 3) & ~3
    return values


def ng_packets(data):
    interfaces, cursor, endian = [], 0, None
    while cursor < len(data):
        if len(data) - cursor < 12:
            raise ValueError("truncated PCAPNG block")
        if bytes(data[cursor:cursor + 4]) == b"\x0a\x0d\x0d\x0a":
            order = bytes(data[cursor + 8:cursor + 12])
            endian = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(order)
            interfaces = []
        if endian is None:
            raise ValueError("PCAPNG section byte order is missing")
        kind, length = struct.unpack(endian + "II", data[cursor:cursor + 8])
        end = cursor + length
        if length < 12 or length % 4 or end > len(data) or integer(data, end - 4, endian + "I") != length:
            raise ValueError("invalid PCAPNG block bounds")
        if kind == 0x0A0D0D0A:
            if length < 28 or integer(data, cursor + 12, endian + "H") != 1:
                raise ValueError("unsupported PCAPNG section")
        elif kind == 1:
            if length < 20:
                raise ValueError("truncated PCAPNG interface")
            clock = options(data, cursor + 16, end - 4, endian)
            resolution = clock.get(9, b"\x06")
            offset = clock.get(14, b"\x00" * 8)
            if len(resolution) != 1 or len(offset) != 8:
                raise ValueError("invalid PCAPNG clock option")
            if len(interfaces) == 65536:
                raise ValueError("PCAPNG interface budget exceeded")
            radix, exponent = (2, resolution[0] & 0x7F) if resolution[0] & 0x80 else (10, resolution[0])
            interfaces.append((integer(data, cursor + 8, endian + "H"),
                               integer(data, cursor + 12, endian + "I"), radix, exponent,
                               struct.unpack(endian + "q", offset)[0]))
        elif kind in (2, 3, 6):
            yield ng_packet(data, cursor, end, kind, endian, interfaces)
        cursor = end


def ng_packet(data, start, end, kind, endian, interfaces):
    header_length = 12 if kind == 3 else 28
    if end - start < header_length + 4:
        raise ValueError("truncated PCAPNG packet")
    interface = 0 if kind == 3 else integer(data, start + 8, endian + ("H" if kind == 2 else "I"))
    if interface >= len(interfaces):
        raise ValueError("PCAPNG packet references a missing interface")
    link, snaplen, radix, exponent, offset = interfaces[interface]
    if kind == 3:
        original = integer(data, start + 8, endian + "I")
        captured = min(original, snaplen) if snaplen else original
        time = None
        if start + 12 + ((captured + 3) & ~3) != end - 4:
            raise ValueError("invalid simple PCAPNG packet length")
    else:
        high, low, captured, original = struct.unpack(
            endian + "IIII", data[start + 12:start + 28]
        )
        time = timestamp((high << 32) | low, radix, exponent, offset)
    if captured > original or start + header_length + ((captured + 3) & ~3) > end - 4:
        raise ValueError("PCAPNG packet exceeds its block")
    timestamp_offset = start + 12 if kind == 6 else None
    return Packet(start + header_length, captured, original, link, time, timestamp_offset)
