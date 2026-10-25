"""Small PCAP and bundle fixtures for independent stream validation."""

import base64
import hashlib
import json
import struct
from pathlib import Path

from benchmarks.runner.capture import packet_index


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def classic_capture(frame_lengths):
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 1024 * 1024, 1)
    records = []
    for number, length in enumerate(frame_lengths, 1):
        frame = (f"frame-{number}:".encode() + bytes([number]))[:length].ljust(length, b"x")
        records.append(struct.pack("<IIII", number, 0, length, length) + frame)
    return header + b"".join(records)


def metadata_for(capture):
    return {"id": "generated", "capture_sha256": sha256(capture), "capture_bytes": len(capture)}


def build_page_case(capture, metadata, frames, total_frames, window_first, last_record,
                    missing_records=()):
    source_id = "sha256:" + metadata["capture_sha256"]
    nodes = []
    blobs = []
    blob_ids = set()
    packet_numbers = []

    for number in range(window_first, last_record + 1):
        if number in missing_records:
            continue
        packet = frames[number - 1]
        data = capture[packet.offset:packet.offset + packet.length]
        blob_id = "sha256:" + sha256(data)
        if blob_id not in blob_ids:
            blobs.append({"id": blob_id, "bytes_base64": base64.b64encode(data).decode("ascii")})
            blob_ids.add(blob_id)
        node_id = len(nodes) + 1
        timestamp_ranges = []
        if packet.timestamp is not None and packet.timestamp_source_offset is not None:
            timestamp_ranges.append({
                "source": source_id,
                "packet": number,
                "offset": packet.timestamp_source_offset,
                "length": 8,
            })
        nodes.append({
            "id": node_id,
            "kind": "packet",
            "blob": blob_id,
            "ranges": [{
                "source": source_id,
                "packet": number,
                "offset": packet.offset,
                "length": packet.length,
            }] if packet.length else [],
            "details": {"record": number, "link_type": packet.link_type,
                        "captured_length": packet.length, "timestamp": packet.timestamp,
                        "timestamp_source_ranges": timestamp_ranges},
        })
        packet_numbers.append(number)

    record_window_length = last_record - window_first + 1
    retained = len(packet_numbers)
    nodes.append({
        "id": len(nodes) + 1,
        "kind": "capture_summary",
        "blob": None,
        "ranges": [],
        "details": {
            "frames_seen": total_frames,
            "retained_frames": retained,
            "omitted_frames": record_window_length - retained,
            "omitted_fragments": 0,
            "omitted_tcp_records": 0,
            "omitted_sequence_ranges": 0,
            "reconstruction_complete": retained == record_window_length,
            "record_window": {"first": window_first, "last": last_record},
            "outside_scope_frames": total_frames - record_window_length,
        },
    })
    complete = retained == record_window_length
    case = {
        "schema_version": 1,
        "collection_complete": complete,
        "sources": [{"id": source_id, "label": "capture.pcap", "aliases": [],
                     "kind": "capture", "length": len(capture), "blob": None}],
        "blobs": blobs,
        "nodes": nodes,
        "edges": [],
        "limitations": [],
    }
    return case, packet_numbers, complete


def write_bundle(root: Path, capture, metadata, page_ranges, context_records,
                 missing_by_page=None, raw_collection_complete=None):
    bundle = root / "bundle"
    pages_dir = bundle / "pages"
    pages_dir.mkdir(parents=True)
    frames = packet_index(capture).records
    total_frames = len(frames)
    missing_by_page = missing_by_page or {}
    manifest_pages = []
    all_primary_packets = set()
    raw_complete = True
    analysis_complete = True

    for index, (first_record, last_record, context_first_record) in enumerate(page_ranges, 1):
        page_case, packet_numbers, complete = build_page_case(
            capture, metadata, frames, total_frames, context_first_record, last_record,
            missing_by_page.get(index, ()),
        )
        page_path = f"pages/{index:06}.json"
        page_bytes = json.dumps(page_case, sort_keys=True).encode("utf-8") + b"\n"
        (bundle / page_path).write_bytes(page_bytes)
        primary_numbers = set(range(first_record, last_record + 1))
        packet_number_set = set(packet_numbers)
        all_primary_packets.update(primary_numbers & packet_number_set)
        raw_complete = raw_complete and primary_numbers <= packet_number_set
        analysis_complete = analysis_complete and complete
        manifest_pages.append({
            "path": page_path,
            "sha256": sha256(page_bytes),
            "first_record": first_record,
            "last_record": last_record,
            "context_first_record": context_first_record,
            "packet_nodes": len(packet_numbers),
            "collection_complete": complete,
        })

    if raw_collection_complete is not None:
        raw_complete = raw_collection_complete
    source_id = "sha256:" + metadata["capture_sha256"]
    manifest = {
        "schema_version": 1,
        "source": {"id": source_id, "label": "capture.pcap",
                    "length": len(capture), "frames": total_frames},
        "raw_collection_complete": raw_complete,
        "analysis_complete": analysis_complete,
        "context_records": context_records,
        "pages": manifest_pages,
        "limitations": [],
    }
    (bundle / "manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
    exit_code = 0 if raw_complete and analysis_complete else 3
    return bundle, manifest, exit_code
