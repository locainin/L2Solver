"""Small generated evidence for the benchmark's independent byte checks."""

import base64
import hashlib
import json
import struct
from pathlib import Path

from benchmarks.runner.capture import packet_index


def digest(data):
    return hashlib.sha256(data).hexdigest()


def program(root, body):
    path = root / "analyzer"
    path.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    path.chmod(0o700)
    return path


def write_sample(root: Path, name="generated", year=2020):
    sample = root / "corpus" / str(year) / name
    sample.mkdir(parents=True)
    payload = b"abcdef"
    capture = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    capture += struct.pack("<IIII", 7, 123, len(payload), len(payload)) + payload
    (sample / "capture.pcap").write_bytes(capture)
    source = {
        "schema_version": 1,
        "id": name,
        "year": year,
        "capture_file": "capture.pcap",
        "capture_sha256": digest(capture),
        "capture_bytes": len(capture),
        "source_url": "https://example.org/source",
        "archive_url": "https://example.org/capture.zip",
        "archive_sha256": digest(b"archive"),
        "archive_bytes": 10,
        "archive_member": "traffic.pcap",
        "acquired_utc": "2026-01-01T00:00:00Z",
        "description": "Generated capture",
    }
    (sample / "source.json").write_text(json.dumps(source), encoding="utf-8")
    catalogue = root / "catalogue.json"
    catalogue.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "sources": [str((sample / "source.json").relative_to(root))],
                "description": "Generated catalogue",
            }
        ),
        encoding="utf-8",
    )
    return catalogue, sample, source, capture


def case_for(source, capture, timestamp_source_offset=24):
    source_id = "sha256:" + source["capture_sha256"]
    packet = packet_index(capture)[0]
    data = capture[packet.offset : packet.offset + packet.length]
    blob_id = "sha256:" + digest(data)
    timestamp_ranges = []
    if timestamp_source_offset is not None and packet.timestamp is not None:
        timestamp_ranges.append(
            {
                "source": source_id,
                "packet": 1,
                "offset": timestamp_source_offset,
                "length": 8,
            }
        )
    return {
        "schema_version": 1,
        "collection_complete": True,
        "sources": [
            {
                "id": source_id,
                "label": "capture.pcap",
                "aliases": [],
                "kind": "capture",
                "length": len(capture),
                "blob": None,
            }
        ],
        "blobs": [
            {"id": blob_id, "bytes_base64": base64.b64encode(data).decode("ascii")}
        ],
        "nodes": [
            {
                "id": 1,
                "kind": "packet",
                "blob": blob_id,
                "ranges": [
                    {
                        "source": source_id,
                        "packet": 1,
                        "offset": packet.offset,
                        "length": packet.length,
                    }
                ],
                "details": {
                    "record": 1,
                    "link_type": packet.link_type,
                    "captured_length": packet.length,
                    "timestamp": packet.timestamp,
                    "timestamp_source_ranges": timestamp_ranges,
                },
            },
            {
                "id": 2,
                "kind": "capture_summary",
                "blob": None,
                "ranges": [],
                "details": {
                    "frames_seen": 1,
                    "retained_frames": 1,
                    "omitted_frames": 0,
                    "reconstruction_complete": True,
                    "omitted_fragments": 0,
                    "omitted_tcp_records": 0,
                    "omitted_sequence_ranges": 0,
                },
            },
        ],
        "edges": [],
        "limitations": [],
    }


def add_mapped_node(case, data, mappings):
    node_id = len(case["nodes"]) + 1
    data_id = "sha256:" + digest(data)
    receipt_bytes = json.dumps(mappings).encode()
    receipt_id = "sha256:" + digest(receipt_bytes)
    additions = [
        {"id": data_id, "bytes_base64": base64.b64encode(data).decode()},
        {"id": receipt_id, "bytes_base64": base64.b64encode(receipt_bytes).decode()},
    ]
    existing = {blob["id"] for blob in case["blobs"]}
    case["blobs"].extend(blob for blob in additions if blob["id"] not in existing)
    case["nodes"].extend(
        [
            {
                "id": node_id,
                "kind": "http_body",
                "blob": data_id,
                "ranges": [entry["range"] for entry in mappings],
                "details": {},
            },
            {
                "id": node_id + 1,
                "kind": "byte_mapping_receipt",
                "blob": receipt_id,
                "ranges": [],
                "details": {"output_node": node_id, "representation": "json_blob"},
            },
        ]
    )
    case["edges"].append(
        {
            "from": node_id,
            "to": node_id + 1,
            "relation": "mapped_by",
            "status": "observed",
            "reason": "Literal test mapping",
        }
    )
