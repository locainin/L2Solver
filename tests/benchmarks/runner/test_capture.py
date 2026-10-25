"""Synthetic PCAP and PCAPNG files exercise the independent record index."""

import hashlib
import io
import struct
import unittest

from benchmarks.runner.capture import iter_packets, packet_index


def block(kind, body):
    length = len(body) + 12
    return struct.pack("<II", kind, length) + body + struct.pack("<I", length)


class CaptureTests(unittest.TestCase):
    def test_scanner_bounds_all_capture_reads(self):
        from benchmarks.runner.capture import CAPTURE_READ_CHUNK_BYTES, SeekableCapture

        class TrackingReader(io.BytesIO):
            def __init__(self, data):
                super().__init__(data)
                self.largest_read = 0

            def read(self, size=-1):
                self.largest_read = max(self.largest_read, size)
                return super().read(size)

        payload = b"z" * 8192
        header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        record = struct.pack("<IIII", 1, 0, len(payload), len(payload)) + payload
        capture_bytes = header + record * 256
        reader = TrackingReader(capture_bytes)
        capture = SeekableCapture(reader)

        self.assertEqual(sum(1 for _ in iter_packets(capture)), 256)
        crossing = CAPTURE_READ_CHUNK_BYTES - 3
        self.assertEqual(capture.read_range(crossing, 20), capture_bytes[crossing:crossing + 20])
        digest = hashlib.sha256()
        for chunk in capture.iter_chunks(0, len(capture)):
            digest.update(chunk)
        self.assertEqual(digest.digest(), hashlib.sha256(capture_bytes).digest())
        self.assertLessEqual(reader.largest_read, CAPTURE_READ_CHUNK_BYTES)

    def test_classic_index_bounds_retained_records(self):
        capture = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        capture += struct.pack("<IIII", 1, 0, 0, 0) * 65537
        index = packet_index(capture)
        self.assertEqual(len(index), 65537)
        self.assertEqual(len(index.records), 65536)
        self.assertEqual(index[0].timestamp_source_offset, 24)
        with self.assertRaisesRegex(ValueError, "prefix"):
            _ = index[65536]

    def test_pcapng_options_preserve_data_bounds(self):
        capture = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
        options = struct.pack("<HH", 9, 1) + b"\x89\x00\x00\x00"
        options += struct.pack("<HHq", 14, 8, -5) + b"\x00" * 4
        capture += block(1, struct.pack("<HHI", 1, 0, 65535) + options)
        start = len(capture) + 28
        capture += block(6, struct.pack("<IIIII", 0, 1, 2, 3, 3) + b"abc\x00")
        index = packet_index(capture)
        self.assertEqual(len(index), 1)
        self.assertEqual((index[0].offset, index[0].length), (start, 3))
        self.assertEqual(index[0].timestamp, {"ticks": (1 << 32) | 2, "radix": 2,
                                              "exponent": 9, "offset_seconds": -5})
        self.assertEqual(index[0].timestamp_source_offset, start - 16)

    def test_simple_packet_has_no_timestamp(self):
        capture = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
        capture += block(1, struct.pack("<HHI", 1, 0, 65535))
        capture += block(3, struct.pack("<I", 3) + b"abc\x00")

        packet = packet_index(capture)[0]

        self.assertIsNone(packet.timestamp)
        self.assertIsNone(packet.timestamp_source_offset)

    def test_truncated_pcapng_packet_is_rejected(self):
        capture = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
        capture += block(1, struct.pack("<HHI", 1, 0, 65535))
        capture += block(6, struct.pack("<IIIII", 0, 0, 0, 100, 100))
        with self.assertRaisesRegex(ValueError, "exceeds"):
            packet_index(capture)
