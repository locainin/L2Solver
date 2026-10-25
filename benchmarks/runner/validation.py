"""Check retained evidence against capture bytes without the Rust parsers."""

import base64
import hashlib
import json
from collections import Counter

from .capture import packet_index
from .catalogue import unique_object

LITERAL_KINDS = {"packet", "tcp_byte_run", "udp_payload", "udp_trailing_bytes", "http_body"}
MAX_BLOB_TOTAL_BYTES = 16 * 1024 * 1024
MAX_BLOB_BASE64_BYTES = 4 * ((MAX_BLOB_TOTAL_BYTES + 2) // 3)


class ValidationLimit(ValueError):
    """The independent oracle stopped before reaching an integrity conclusion."""


class WorkBudget:
    def __init__(self):
        self.remaining = 512 * 1024 * 1024

    def charge(self, units):
        if units > self.remaining:
            raise ValidationLimit("independent validation work budget exceeded")
        self.remaining -= units


def require(condition, message):
    if not condition:
        raise ValueError(message)


def bounded_integer(value, maximum, name):
    require(type(value) is int and 0 <= value <= maximum, f"invalid {name}")
    return value


def decoded_blobs(case):
    require(len(case["blobs"]) <= 65792, "too many blobs")
    blobs, total = {}, 0
    for blob in case["blobs"]:
        encoded = blob["bytes_base64"]
        require(isinstance(encoded, str) and len(encoded) <= MAX_BLOB_BASE64_BYTES,
                "blob exceeds aggregate encoded byte bound")
        try:
            data = base64.b64decode(encoded, validate=True)
        except (ValueError, base64.binascii.Error) as error:
            raise ValueError("invalid blob base64") from error
        require(base64.b64encode(data).decode("ascii") == encoded, "noncanonical blob base64")
        require(len(data) <= MAX_BLOB_TOTAL_BYTES, "blob exceeds aggregate decoded byte bound")
        require(blob["id"] == "sha256:" + hashlib.sha256(data).hexdigest(), "blob hash mismatch")
        require(blob["id"] not in blobs, "duplicate blob id")
        total += len(data)
        require(total <= MAX_BLOB_TOTAL_BYTES, "aggregate blob bound exceeded")
        blobs[blob["id"]] = data
    return blobs


def check_range(range_, source_id, capture, packets):
    require(range_["source"] == source_id, "range references another source")
    start = bounded_integer(range_["offset"], len(capture), "source offset")
    length = bounded_integer(range_["length"], len(capture) - start, "source length")
    packet = range_["packet"]
    if packet is not None:
        bounded_integer(packet, len(packets), "packet annotation")
        require(packet > 0, "zero packet annotation")
        record = packets[packet - 1]
        require(record.offset <= start and start + length <= record.offset + record.length,
                "source range violates independent packet bounds")
    return start, length


def check_packet(node, data, packets, source_id):
    number = node["details"]["record"]
    bounded_integer(number, len(packets), "packet record")
    require(number > 0, "zero packet record")
    packet = packets[number - 1]
    require(len(data) == packet.length, "packet blob length mismatch")
    require(node["details"].get("link_type") == packet.link_type, "packet link type mismatch")
    # Timestamp fields are checked when present, including clocks with binary resolution
    if "timestamp" in node["details"]:
        observed = node["details"]["timestamp"]
        if packet.timestamp is None:
            require(observed is None, "invented packet timestamp")
        else:
            require(isinstance(observed, dict) and all(observed.get(key) == value
                    for key, value in packet.timestamp.items()), "packet timestamp mismatch")
    expected_timestamp_ranges = []
    if packet.timestamp is not None and packet.timestamp_source_offset is not None:
        expected_timestamp_ranges.append({
            "source": source_id,
            "packet": number,
            "offset": packet.timestamp_source_offset,
            "length": 8,
        })
    observed_timestamp_ranges = node["details"].get("timestamp_source_ranges")
    require(isinstance(observed_timestamp_ranges, list),
            "packet timestamp source ranges must be an array")
    for range_ in observed_timestamp_ranges:
        require(isinstance(range_, dict)
                and set(range_) == {"source", "packet", "offset", "length"}
                and isinstance(range_["source"], str)
                and type(range_["packet"]) is int
                and type(range_["offset"]) is int
                and type(range_["length"]) is int,
                "invalid packet timestamp source range")
    require(observed_timestamp_ranges == expected_timestamp_ranges,
            "packet timestamp source ranges mismatch independent record bounds")
    if packet.length:
        require(len(node["ranges"]) == 1, "packet must retain its exact source range")
        range_ = node["ranges"][0]
        require(range_["offset"] == packet.offset and range_["length"] == packet.length
                and range_["packet"] == number, "packet source range mismatch")
    return number


def mappings_for(node, nodes, blobs, mapping_edges):
    if node["id"] in mapping_edges:
        receipt = nodes[mapping_edges[node["id"]]]
        require(receipt["kind"] == "byte_mapping_receipt", "mapped_by target is not a receipt")
        require(receipt["details"].get("output_node") == node["id"], "receipt output mismatch")
        mappings = json.loads(blobs[receipt["blob"]], object_pairs_hook=unique_object)
        require(isinstance(mappings, list) and len(mappings) <= 1024, "invalid mapping count")
        require([entry["range"] for entry in mappings] == node["ranges"], "receipt source ranges mismatch")
        return mappings
    require(len(node["ranges"]) <= 1, "literal node needs an output-offset mapping receipt")
    return [{"offset": 0, "range": range_} for range_ in node["ranges"]]


def compare_literal(data, mappings, capture, packets, source_id, budget):
    budget.charge(len(data) + sum(entry["range"]["length"] for entry in mappings))
    coverage, compared = bytearray(len(data)), 0
    for mapping in mappings:
        start, length = check_range(mapping["range"], source_id, capture, packets)
        offset = bounded_integer(mapping["offset"], len(data), "output offset")
        require(length <= len(data) - offset, "mapping exceeds output bytes")
        require(data[offset:offset + length] == capture[start:start + length], "literal bytes mismatch")
        coverage[offset:offset + length] = b"\x01" * length
        compared += length
    require(all(coverage), "unmapped literal output bytes")
    return compared


def graph_index(case):
    require(len(case["nodes"]) <= 65536 and len(case["edges"]) <= 131072, "graph budget exceeded")
    nodes, mappings = {}, {}
    for expected, node in enumerate(case["nodes"], 1):
        require(node["id"] == expected, "noncanonical node ids")
        nodes[expected] = node
    for edge in case["edges"]:
        require(edge["from"] in nodes and edge["to"] in nodes, "dangling evidence edge")
        if edge["relation"] == "mapped_by":
            require(edge["from"] not in mappings, "duplicate mapping receipt edge")
            mappings[edge["from"]] = edge["to"]
    return nodes, mappings


def compare_ftp_reference(node, nodes, blobs, capture, packets, source_id, mapping_edges, budget):
    details = node["details"]
    parent = nodes[details["tcp_byte_run_node"]]
    require(parent["kind"] == "tcp_byte_run" and parent["blob"] == node["blob"],
            "FTP reference must use its retained TCP run blob")
    data = blobs[parent["blob"]]
    range_ = details["run_range"]
    offset = bounded_integer(range_["offset"], len(data), "FTP run offset")
    length = bounded_integer(range_["length"], len(data) - offset, "FTP run length")
    if node["kind"] == "ftp_data_candidate":
        require(offset == 0 and length == len(data) and node["ranges"] == parent["ranges"],
                "FTP data reference differs from its TCP run")
        return 0
    mappings, cursor = [], 0
    for source_range in node["ranges"]:
        mappings.append({"offset": cursor, "range": source_range})
        cursor += source_range["length"]
    compared = compare_literal(data[offset:offset + length], mappings, capture, packets, source_id, budget)
    parent_mappings = mappings_for(parent, nodes, blobs, mapping_edges)
    budget.charge(16 * len(mappings) * len(parent_mappings))
    for mapping in mappings:
        target = offset + mapping["offset"]
        source_range = mapping["range"]
        # Earliest FTP provenance may select a subset of retransmitted parent observations
        require(any(entry["offset"] <= target
                    and target + source_range["length"] <= entry["offset"] + entry["range"]["length"]
                    and source_range["source"] == entry["range"]["source"]
                    and source_range["packet"] == entry["range"]["packet"]
                    and source_range["offset"] == entry["range"]["offset"] + target - entry["offset"]
                    for entry in parent_mappings), "FTP source range is not a projection of its parent run mapping")
    return compared


def check_literal_nodes(capture, packets, source_id, blobs, nodes, mapping_edges, window=None, budget=None):
    literal_nodes, compared, packet_numbers = 0, 0, []
    budget = budget or WorkBudget()
    require(sum(len(node["ranges"]) for node in nodes.values()) <= 131072, "total range budget exceeded")
    for node in nodes.values():
        require(node["blob"] is None or node["blob"] in blobs, "node references a missing blob")
        require(len(node["ranges"]) <= 1024, "node range budget exceeded")
        for range_ in node["ranges"]:
            check_range(range_, source_id, capture, packets)
        if node["kind"] in ("ftp_control_candidate", "ftp_filename_argument", "ftp_data_candidate"):
            compared += compare_ftp_reference(node, nodes, blobs, capture, packets, source_id, mapping_edges, budget)
            literal_nodes += 1
            continue
        if node["kind"] not in LITERAL_KINDS and node["id"] not in mapping_edges:
            continue
        require(node["blob"] is not None, "literal node has no blob")
        data = blobs[node["blob"]]
        if node["kind"] == "packet":
            packet_numbers.append(check_packet(node, data, packets, source_id))
        mappings = mappings_for(node, nodes, blobs, mapping_edges)
        compared += compare_literal(data, mappings, capture, packets, source_id, budget)
        literal_nodes += 1
    if window is None:
        require(packet_numbers == list(range(1, len(packet_numbers) + 1)),
                "retained packets are not a prefix")
    else:
        first_record, last_record = window
        require(packet_numbers == sorted(set(packet_numbers)), "page packets are not in unique record order")
        require(all(first_record <= number <= last_record for number in packet_numbers),
                "page packet is outside its record window")
    return literal_nodes, compared, len(packet_numbers), packet_numbers


def check_summary(case, packets, retained, window=None):
    summaries = [node["details"] for node in case["nodes"] if node["kind"] == "capture_summary"]
    require(len(summaries) == 1, "build case requires exactly one capture summary")
    summary = summaries[0]
    for name in ("frames_seen", "retained_frames", "omitted_frames", "omitted_fragments",
                 "omitted_tcp_records", "omitted_sequence_ranges"):
        bounded_integer(summary[name], 2 ** 64 - 1, name)
    if window is None:
        selected_first, selected_last = 1, len(packets)
    else:
        selected_first, selected_last = window
        expected_window = {"first": selected_first, "last": selected_last}
        record_window = summary.get("record_window")
        require(isinstance(record_window, dict) and set(record_window) == {"first", "last"}
                and type(record_window["first"]) is int and type(record_window["last"]) is int
                and record_window == expected_window, "capture summary record window mismatch")
        selected_count = selected_last - selected_first + 1
        outside_scope = bounded_integer(summary.get("outside_scope_frames"), 2 ** 64 - 1,
                                        "outside-scope frame count")
        require(outside_scope == len(packets) - selected_count,
                "capture summary outside-scope count mismatch")
    selected_count = selected_last - selected_first + 1
    require(summary["frames_seen"] == len(packets) and retained <= summary["retained_frames"] <= selected_count
            and summary["omitted_frames"] == selected_count - summary["retained_frames"],
            "capture summary count mismatch")
    if window is not None:
        require(retained == summary["retained_frames"], "page retained frame count mismatch")
    require(type(summary["reconstruction_complete"]) is bool, "invalid reconstruction completeness")
    omissions = sum(summary[name] for name in ("omitted_fragments", "omitted_tcp_records", "omitted_sequence_ranges"))
    if summary["reconstruction_complete"]:
        require(omissions == 0, "reconstruction completeness contradicts reported omissions")
    if case["collection_complete"]:
        require(summary["reconstruction_complete"] and omissions == 0 and summary["omitted_frames"] == 0,
                "collection completeness contradicts reconstruction omissions")
        require(retained == selected_count, "complete case omitted packet records")
    return summary


def validate_case(case, capture, metadata, exit_code):
    require(len(capture) == metadata["capture_bytes"]
            and hashlib.sha256(capture).hexdigest() == metadata["capture_sha256"], "capture hash mismatch")
    packets = packet_index(capture)
    result, _ = validate_case_records(case, capture, metadata, exit_code, packets)
    return result


def validate_case_window(case, capture, metadata, exit_code, packets, window, budget=None):
    require(len(capture) == metadata["capture_bytes"], "capture length mismatch")
    result, packet_numbers = validate_case_records(
        case, capture, metadata, exit_code, packets, window, budget)
    return result, packet_numbers


def validate_case_records(case, capture, metadata, exit_code, packets, window=None, budget=None):
    require(type(case["schema_version"]) is int and case["schema_version"] == 1,
            "unsupported evidence schema")
    require(type(case["collection_complete"]) is bool, "invalid collection_complete")
    require(exit_code in (0, 3) and (exit_code == 0) == case["collection_complete"],
            "exit status contradicts collection completeness")
    source_id = "sha256:" + metadata["capture_sha256"]
    require(len(case["sources"]) == 1 and case["sources"][0]["id"] == source_id
            and case["sources"][0]["length"] == len(capture)
            and case["sources"][0]["kind"] == "capture", "case capture source mismatch")
    blobs = decoded_blobs(case)
    nodes, mapping_edges = graph_index(case)
    literal_nodes, compared, retained, packet_numbers = check_literal_nodes(
        capture, packets, source_id, blobs, nodes, mapping_edges, window, budget)
    counts = Counter(node["kind"] for node in nodes.values())
    summary = check_summary(case, packets, retained, window)
    result = {
        "collection_complete": case["collection_complete"], "packet_records": len(packets),
        "retained_packet_records": retained, "blobs_checked": len(blobs),
        "literal_nodes_checked": literal_nodes, "supporting_bytes_compared": compared,
        "nodes": len(nodes), "edges": len(case["edges"]), "node_counts": dict(sorted(counts.items())),
        "ambiguous_tcp_episodes": sum(node["kind"] == "tcp_episode"
            and node["details"].get("generation_ambiguous") is True for node in nodes.values()),
        "capture_summary": summary,
        "limitations": case["limitations"],
    }
    return result, packet_numbers
