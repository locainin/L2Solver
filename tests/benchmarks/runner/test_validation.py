"""Evidence validation is independent of protocol interpretation."""

import base64
import copy
import hashlib
import struct
import unittest

from support import add_mapped_node, case_for, digest

from benchmarks.runner.capture import packet_index
from benchmarks.runner.validation import decoded_blobs, validate_case


def pcapng_block(kind, body):
    length = len(body) + 12
    return struct.pack("<II", kind, length) + body + struct.pack("<I", length)


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.capture = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        self.capture += struct.pack("<IIII", 1, 0, 6, 6) + b"abcdef"
        self.source = {"capture_sha256": digest(self.capture), "capture_bytes": len(self.capture)}
        self.case = case_for(self.source, self.capture)

    def test_packet_blobs_preserve_literal_mappings(self):
        result = validate_case(self.case, self.capture, self.source, 0)
        self.assertEqual(result["packet_records"], 1)
        self.assertEqual(result["literal_nodes_checked"], 1)

    def test_schema_rejects_noninteger_versions(self):
        for version in (True, 1.0, "1", None):
            with self.subTest(version=version):
                self.case["schema_version"] = version
                with self.assertRaisesRegex(ValueError, "unsupported evidence schema"):
                    validate_case(self.case, self.capture, self.source, 0)

    def test_large_blobs_match_across_packets(self):
        expected_length = 1024 * 1024 + 1
        full_frame_lengths = [65_535] * (expected_length // 65_535)
        remaining_length = expected_length - sum(full_frame_lengths)
        if remaining_length:
            full_frame_lengths.append(remaining_length)
        frames = [bytes([index + 1]) * length
                  for index, length in enumerate(full_frame_lengths)]
        capture = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1)
        for number, frame in enumerate(frames, 1):
            capture += struct.pack("<IIII", number, 0, len(frame), len(frame)) + frame

        source = {"capture_sha256": digest(capture), "capture_bytes": len(capture)}
        source_id = "sha256:" + source["capture_sha256"]
        records = packet_index(capture).records
        packet_nodes = []
        packet_blobs = []
        mappings = []
        output_offset = 0
        for number, packet in enumerate(records, 1):
            data = capture[packet.offset:packet.offset + packet.length]
            blob_id = "sha256:" + digest(data)
            packet_blobs.append({"id": blob_id,
                                 "bytes_base64": base64.b64encode(data).decode("ascii")})
            timestamp_ranges = [{
                "source": source_id,
                "packet": number,
                "offset": packet.timestamp_source_offset,
                "length": 8,
            }]
            packet_nodes.append({
                "id": number,
                "kind": "packet",
                "blob": blob_id,
                "ranges": [{"source": source_id, "packet": number,
                            "offset": packet.offset, "length": packet.length}],
                "details": {"record": number, "link_type": packet.link_type,
                            "captured_length": packet.length, "timestamp": packet.timestamp,
                            "timestamp_source_ranges": timestamp_ranges},
            })
            mappings.append({"offset": output_offset,
                             "range": {"source": source_id, "packet": number,
                                       "offset": packet.offset, "length": packet.length}})
            output_offset += packet.length

        case = {
            "schema_version": 1,
            "collection_complete": True,
            "sources": [{"id": source_id, "label": "capture.pcap", "aliases": [],
                         "kind": "capture", "length": len(capture), "blob": None}],
            "blobs": packet_blobs,
            "nodes": packet_nodes + [{
                "id": len(packet_nodes) + 1,
                "kind": "capture_summary",
                "blob": None,
                "ranges": [],
                "details": {"frames_seen": len(records), "retained_frames": len(records),
                            "omitted_frames": 0, "omitted_fragments": 0,
                            "omitted_tcp_records": 0, "omitted_sequence_ranges": 0,
                            "reconstruction_complete": True},
            }],
            "edges": [],
            "limitations": [],
        }
        add_mapped_node(case, b"".join(frames), mappings)

        result = validate_case(case, capture, source, 0)

        self.assertEqual(result["supporting_bytes_compared"], expected_length * 2)

    def test_decoded_blob_respects_aggregate_budget(self):
        data = b"x" * (16 * 1024 * 1024 + 1)
        document = {"blobs": [{
            "id": "sha256:" + digest(data),
            "bytes_base64": base64.b64encode(data).decode("ascii"),
        }]}

        with self.assertRaisesRegex(ValueError, "aggregate decoded byte bound"):
            decoded_blobs(document)

    def test_encoded_blob_bounded_before_decoding(self):
        maximum_encoded_length = 4 * ((16 * 1024 * 1024 + 2) // 3)
        document = {"blobs": [{"id": "unused", "bytes_base64": "!" * (maximum_encoded_length + 4)}]}

        with self.assertRaisesRegex(ValueError, "aggregate encoded byte bound"):
            decoded_blobs(document)

    def test_blob_sum_respects_aggregate_budget(self):
        blobs = []
        for data in (b"x" * (8 * 1024 * 1024), b"y" * (8 * 1024 * 1024 + 1)):
            blobs.append({"id": "sha256:" + digest(data),
                          "bytes_base64": base64.b64encode(data).decode("ascii")})

        with self.assertRaisesRegex(ValueError, "aggregate blob bound exceeded"):
            decoded_blobs({"blobs": blobs})

    def test_rejects_duplicate_blob_content_ids(self):
        blob = {"id": "sha256:" + digest(b"abc"), "bytes_base64": "YWJj"}

        with self.assertRaisesRegex(ValueError, "duplicate blob"):
            decoded_blobs({"blobs": [blob, blob.copy()]})

    def test_valid_hashes_cannot_hide_mismatches(self):
        source_range = copy.deepcopy(self.case["nodes"][0]["ranges"][0])
        source_range["length"] = 2
        add_mapped_node(self.case, b"ZZ", [{"offset": 0, "range": source_range}])
        with self.assertRaisesRegex(ValueError, "literal bytes"):
            validate_case(self.case, self.capture, self.source, 0)

    def test_mapping_covers_every_recovered_byte(self):
        source_range = copy.deepcopy(self.case["nodes"][0]["ranges"][0])
        source_range["length"] = 1
        add_mapped_node(self.case, b"ab", [{"offset": 0, "range": source_range}])
        with self.assertRaisesRegex(ValueError, "unmapped"):
            validate_case(self.case, self.capture, self.source, 0)

    def test_packet_annotations_match_record_bounds(self):
        self.case["nodes"][0]["ranges"][0]["offset"] = 24
        with self.assertRaisesRegex(ValueError, "packet bounds"):
            validate_case(self.case, self.capture, self.source, 0)

    def test_classic_timestamps_use_record_headers(self):
        details = self.case["nodes"][0]["details"]
        timestamp_range = details["timestamp_source_ranges"][0]
        self.assertEqual(timestamp_range, {
            "source": "sha256:" + self.source["capture_sha256"],
            "packet": 1, "offset": 24, "length": 8,
        })
        validate_case(self.case, self.capture, self.source, 0)

    def test_rejects_wrong_timestamp_source_locators(self):
        expected = self.case["nodes"][0]["details"]["timestamp_source_ranges"][0]
        mutations = (
            {**expected, "offset": 40},
            {**expected, "length": 7},
            {**expected, "packet": 2},
            {**expected, "packet": True},
            {**expected, "source": "sha256:" + hashlib.sha256(b"other").hexdigest()},
        )
        for timestamp_range in mutations:
            with self.subTest(timestamp_range=timestamp_range):
                case = copy.deepcopy(self.case)
                case["nodes"][0]["details"]["timestamp_source_ranges"] = [timestamp_range]
                with self.assertRaisesRegex(ValueError, "timestamp source"):
                    validate_case(case, self.capture, self.source, 0)

    def test_epb_timestamps_use_block_headers(self):
        section = pcapng_block(0x0A0D0D0A,
                               struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
        interface = pcapng_block(1, struct.pack("<HHI", 1, 0, 65535))
        block_start = len(section) + len(interface)
        epb = pcapng_block(6, struct.pack("<IIIII", 0, 1, 7, 3, 3) + b"abc\x00")
        capture = section + interface + epb
        metadata = {"capture_sha256": digest(capture), "capture_bytes": len(capture)}
        case = case_for(metadata, capture, timestamp_source_offset=block_start + 12)

        timestamp_range = case["nodes"][0]["details"]["timestamp_source_ranges"][0]
        self.assertEqual(timestamp_range["offset"], block_start + 12)
        self.assertEqual(timestamp_range["length"], 8)
        validate_case(case, capture, metadata, 0)

    def test_absent_timestamps_omit_source_locators(self):
        section = pcapng_block(0x0A0D0D0A,
                               struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
        interface = pcapng_block(1, struct.pack("<HHI", 1, 0, 65535))
        simple_packet = pcapng_block(3, struct.pack("<I", 3) + b"abc\x00")
        capture = section + interface + simple_packet
        metadata = {"capture_sha256": digest(capture), "capture_bytes": len(capture)}
        case = case_for(metadata, capture, timestamp_source_offset=None)

        self.assertIsNone(case["nodes"][0]["details"]["timestamp"])
        self.assertEqual(case["nodes"][0]["details"]["timestamp_source_ranges"], [])
        validate_case(case, capture, metadata, 0)

        case["nodes"][0]["details"]["timestamp_source_ranges"] = [{
            "source": "sha256:" + metadata["capture_sha256"],
            "packet": 1, "offset": 0, "length": 8,
        }]
        with self.assertRaisesRegex(ValueError, "timestamp source"):
            validate_case(case, capture, metadata, 0)

    def test_complete_exit_rejects_partial_collection(self):
        self.case["collection_complete"] = False
        with self.assertRaisesRegex(ValueError, "exit status"):
            validate_case(self.case, self.capture, self.source, 0)
        result = validate_case(self.case, self.capture, self.source, 3)
        self.assertFalse(result["collection_complete"])

    def test_checks_blob_content_hashes(self):
        self.case["blobs"][0]["bytes_base64"] = "YWJjZGVn"
        with self.assertRaisesRegex(ValueError, "blob hash"):
            validate_case(self.case, self.capture, self.source, 0)

    def test_partial_graph_allows_omitted_nodes(self):
        self.case["collection_complete"] = False
        self.case["nodes"] = [dict(self.case["nodes"][1], id=1)]
        result = validate_case(self.case, self.capture, self.source, 3)
        self.assertEqual(result["retained_packet_records"], 0)

    def test_ftp_arguments_select_claimed_bytes(self):
        source_range = copy.deepcopy(self.case["nodes"][0]["ranges"][0])
        add_mapped_node(self.case, b"abcdef", [{"offset": 0, "range": source_range}])
        self.case["nodes"][2]["kind"] = "tcp_byte_run"
        argument_range = dict(source_range, offset=42, length=2)
        self.case["nodes"].append({"id": 5, "kind": "ftp_filename_argument",
            "blob": self.case["nodes"][2]["blob"], "ranges": [argument_range],
            "details": {"tcp_byte_run_node": 3, "run_range": {"offset": 3, "length": 2}}})
        with self.assertRaisesRegex(ValueError, "literal bytes"):
            validate_case(self.case, self.capture, self.source, 0)

    def test_complete_case_rejects_reconstruction_omissions(self):
        self.case["nodes"][1]["details"]["reconstruction_complete"] = False
        self.case["nodes"][1]["details"]["omitted_fragments"] = 1
        with self.assertRaisesRegex(ValueError, "reconstruction"):
            validate_case(self.case, self.capture, self.source, 0)

    def test_build_case_requires_capture_summary(self):
        self.case["nodes"].pop()
        with self.assertRaisesRegex(ValueError, "summary"):
            validate_case(self.case, self.capture, self.source, 0)

    def test_ftp_references_require_original_occurrences(self):
        capture = self.capture[:24] + struct.pack("<IIII", 1, 0, 12, 12) + b"abcdefabcdef"
        metadata = {"capture_sha256": digest(capture), "capture_bytes": len(capture)}
        case = case_for(metadata, capture)
        source_range = dict(case["nodes"][0]["ranges"][0], length=6)
        add_mapped_node(case, b"abcdef", [{"offset": 0, "range": source_range}])
        run = case["nodes"][2]
        run["kind"] = "tcp_byte_run"
        case["nodes"].append({"id": 5, "kind": "ftp_control_candidate", "blob": run["blob"],
            "ranges": [dict(source_range, offset=46)],
            "details": {"tcp_byte_run_node": run["id"], "run_range": {"offset": 0, "length": 6}}})
        with self.assertRaisesRegex(ValueError, "parent.*mapping"):
            validate_case(case, capture, metadata, 0)
