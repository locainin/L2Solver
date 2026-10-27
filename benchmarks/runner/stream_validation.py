"""Validate bounded streaming bundles against one sequential capture pass."""

import hashlib
import json
import re
from pathlib import Path

from .capture import iter_packet_windows
from .catalogue import read_json_bytes, unique_object
from .index_validation import LEGACY_SUMMARY_FIELDS, SUMMARY_FIELDS
from .validation import WorkBudget, require, validate_case_window

MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_PAGE_BYTES = 64 * 1024 * 1024
MAX_BUNDLE_BYTES = 8 * 1024 * 1024 * 1024
MAX_PAGES = 16_384
MAX_CONTEXT_RECORDS = 128
MAX_CONTEXT_BYTES = 256 * 1024
MAX_PRIMARY_RECORDS = 768
MAX_PRIMARY_BYTES = 512 * 1024
MAX_FRAMES = 2 ** 32 - 1
MAX_LIMITATIONS = 1024
MAX_LIMITATION_LENGTH = 2048
SHA256 = re.compile(r"[0-9a-f]{64}")
MANIFEST_FIELDS = {
    "schema_version", "source", "raw_collection_complete", "analysis_complete",
    "context_records", "pages", "limitations",
}
SOURCE_FIELDS = {"id", "label", "length", "frames"}
CURRENT_SOURCE_FIELDS = SOURCE_FIELDS | {"collection_summary"}
MAX_COLLECTION_COUNTER = 2 ** 64 - 1
PAGE_FIELDS = {
    "path", "sha256", "first_record", "last_record", "context_first_record",
    "packet_nodes", "collection_complete",
}


def bounded_integer(value, maximum, name, minimum=0):
    require(type(value) is int and minimum <= value <= maximum, f"invalid {name}")
    return value


def bounded_strings(values, name):
    require(isinstance(values, list) and len(values) <= MAX_LIMITATIONS, f"invalid {name}")
    for value in values:
        require(isinstance(value, str) and len(value) <= MAX_LIMITATION_LENGTH,
                f"invalid {name} entry")


def check_collection_summary(summary):
    require(isinstance(summary, dict) and set(summary) in (LEGACY_SUMMARY_FIELDS, SUMMARY_FIELDS),
            "unsupported stream collection summary fields")
    counters = {
        name: bounded_integer(summary[name], MAX_COLLECTION_COUNTER,
                              f"collection summary {name}")
        for name in sorted(summary)
    }
    require(counters["reported_sections"] <= counters["sections"]
            and counters["incomplete_sections"] <= counters["reported_sections"],
            "invalid stream collection summary counters")
    return counters


def check_bundle_directory(bundle):
    require(not bundle.is_symlink() and bundle.is_dir(), "stream bundle is not a regular directory")
    entries = {entry.name: entry for entry in bundle.iterdir()}
    require(set(entries) == {"manifest.json", "pages"}, "stream bundle has unexpected entries")
    require(not entries["manifest.json"].is_symlink(), "stream manifest cannot be a symlink")
    pages_directory = entries["pages"]
    require(not pages_directory.is_symlink() and pages_directory.is_dir(),
            "stream pages path is not a regular directory")
    return pages_directory


def check_manifest(manifest, metadata, capture_length):
    require(isinstance(manifest, dict) and set(manifest) == MANIFEST_FIELDS,
            "unsupported stream manifest fields")
    require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 1,
            "unsupported stream manifest schema")
    require(type(manifest["raw_collection_complete"]) is bool, "invalid raw collection status")
    require(type(manifest["analysis_complete"]) is bool, "invalid analysis status")
    context_records = bounded_integer(manifest["context_records"], MAX_CONTEXT_RECORDS,
                                     "context record limit")
    source = manifest["source"]
    require(isinstance(source, dict) and set(source) in (SOURCE_FIELDS, CURRENT_SOURCE_FIELDS),
            "unsupported stream source fields")
    source_collection_complete = True
    if "collection_summary" in source:
        summary = check_collection_summary(source["collection_summary"])
        # Packet-block loss or an unknown count also marks source analysis partial
        source_collection_complete = not any(summary.get(name, 0) for name in (
            "incomplete_sections", "packet_block_packets_dropped",
            "packet_blocks_with_unavailable_drop_count",
        ))
    expected_id = "sha256:" + metadata["capture_sha256"]
    require(source["id"] == expected_id, "stream source id mismatch")
    require(isinstance(source["label"], str) and 0 < len(source["label"]) <= 4096,
            "invalid stream source label")
    # The input policy has already authorized this actual capture length
    require(type(source["length"]) is int
            and source["length"] == capture_length == metadata["capture_bytes"],
            "stream source length mismatch")
    frames = bounded_integer(source["frames"], MAX_FRAMES, "stream source frame count")
    pages = manifest["pages"]
    require(isinstance(pages, list) and len(pages) <= MAX_PAGES, "stream page count exceeds bound")
    bounded_strings(manifest["limitations"], "stream limitations")
    return source, frames, context_records, pages, source_collection_complete


def check_page_entry(page, index, previous_last, frames, context_records):
    require(isinstance(page, dict) and set(page) == PAGE_FIELDS,
            "unsupported stream page fields")
    expected_path = f"pages/{index:06}.json"
    require(page["path"] == expected_path, "invalid stream page path or order")
    require(isinstance(page["sha256"], str) and SHA256.fullmatch(page["sha256"]),
            "invalid stream page hash")
    first_record = bounded_integer(page["first_record"], MAX_FRAMES,
                                   "page first record", minimum=1)
    last_record = bounded_integer(page["last_record"], MAX_FRAMES,
                                  "page last record", minimum=first_record)
    context_first = bounded_integer(page["context_first_record"], MAX_FRAMES,
                                    "page context first record", minimum=1)
    packet_nodes = bounded_integer(page["packet_nodes"], MAX_PRIMARY_RECORDS + MAX_CONTEXT_RECORDS,
                                   "page packet node count")
    require(type(page["collection_complete"]) is bool, "invalid page completion status")
    require(first_record == previous_last + 1, "stream page primary ranges have a gap or overlap")
    require(last_record <= frames, "stream page exceeds source frame count")
    require(last_record - first_record + 1 <= MAX_PRIMARY_RECORDS,
            "stream primary page exceeds record bound")
    require(max(1, first_record - context_records) <= context_first <= first_record,
            "stream page context exceeds record bound")
    require(last_record - context_first + 1 <= MAX_PRIMARY_RECORDS + MAX_CONTEXT_RECORDS,
            "stream selected page window exceeds record bound")
    require(packet_nodes <= last_record - context_first + 1,
            "stream page packet node count exceeds its window")
    return first_record, last_record, context_first


def read_page(bundle, relative_path, expected_hash, document_total):
    page_path = bundle / relative_path
    require(not page_path.is_symlink() and page_path.resolve().is_relative_to(bundle.resolve()),
            "stream page escapes bundle directory")
    try:
        page_size = page_path.stat().st_size
    except OSError as error:
        raise ValueError("stream page is missing") from error
    require(0 < page_size <= MAX_PAGE_BYTES, "stream page size exceeds bound")
    document_total += page_size
    require(document_total <= MAX_BUNDLE_BYTES, "stream bundle document bytes exceed bound")
    with page_path.open("rb") as stream:
        raw = stream.read(MAX_PAGE_BYTES + 1)
    require(len(raw) == page_size and len(raw) <= MAX_PAGE_BYTES, "stream page size changed or exceeds bound")
    require(hashlib.sha256(raw).hexdigest() == expected_hash, "stream page hash mismatch")
    page = json.loads(raw, object_pairs_hook=unique_object)
    return page, page_size, document_total


def validate_stream_bundle(bundle, capture, metadata, exit_code):
    bundle = Path(bundle)
    pages_directory = check_bundle_directory(bundle)
    manifest_path = bundle / "manifest.json"
    require(manifest_path.resolve().is_relative_to(bundle.resolve()),
            "stream manifest escapes bundle directory")
    manifest_bytes = read_json_bytes(manifest_path, MAX_MANIFEST_BYTES)
    manifest_size = len(manifest_bytes)
    manifest = json.loads(manifest_bytes, object_pairs_hook=unique_object)
    del manifest_bytes
    require(len(capture) == metadata["capture_bytes"]
            and hashlib.sha256(capture).hexdigest() == metadata["capture_sha256"],
            "capture hash mismatch")
    source, frames, context_records, pages, source_collection_complete = check_manifest(
        manifest, metadata, len(capture))
    require((frames == 0) == (len(pages) == 0), "empty source and page list disagree")
    require(not any(entry.is_symlink() for entry in pages_directory.iterdir()),
            "stream page directory contains a symlink")

    windows = []
    previous_last = 0
    for index, page in enumerate(pages, 1):
        first_record, last_record, context_first = check_page_entry(
            page, index, previous_last, frames, context_records)
        windows.append((first_record, last_record, context_first))
        previous_last = last_record
    require(previous_last == frames, "stream page primary ranges do not cover source records")
    expected_files = {Path(page["path"]).name for page in pages}
    page_entries = list(pages_directory.iterdir())
    require(all(entry.is_file() for entry in page_entries)
            and expected_files == {entry.name for entry in page_entries},
            "stream page directory has missing or extra files")

    raw_complete = True
    analysis_complete = source_collection_complete
    document_total = manifest_size
    packet_nodes_total = 0
    primary_packet_nodes = 0
    checked_pages = 0
    budget = WorkBudget()
    packet_windows = iter_packet_windows(capture, windows, context_records, frames)

    for entry, packets in zip(pages, packet_windows, strict=True):
        page, _, document_total = read_page(
            bundle, entry["path"], entry["sha256"], document_total)
        first_record = entry["first_record"]
        last_record = entry["last_record"]
        context_first = entry["context_first_record"]
        require(sum(packets[number - 1].length for number in range(context_first, first_record))
                <= MAX_CONTEXT_BYTES, "stream context byte bound exceeded")
        require(sum(packets[number - 1].length for number in range(first_record, last_record + 1))
                <= MAX_PRIMARY_BYTES, "stream primary page byte bound exceeded")
        validation, packet_numbers = validate_case_window(
            page, capture, metadata, 0 if page["collection_complete"] else 3,
            packets, (context_first, last_record), budget,
        )
        require(page["sources"][0]["label"] == source["label"],
                "stream page source label mismatch")
        require(validation["retained_packet_records"] == entry["packet_nodes"],
                "manifest page packet node count mismatch")
        require(page["collection_complete"] == entry["collection_complete"],
                "manifest page completion status mismatch")
        primary_nodes = {number for number in packet_numbers if first_record <= number <= last_record}
        primary_complete = len(primary_nodes) == last_record - first_record + 1
        raw_complete = raw_complete and primary_complete
        analysis_complete = analysis_complete and page["collection_complete"]
        primary_packet_nodes += len(primary_nodes)
        packet_nodes_total += len(packet_numbers)
        checked_pages += 1

    # Exhaustion performs the independent parser's final EOF and record-count checks
    try:
        next(packet_windows)
    except StopIteration:
        pass
    require(manifest["raw_collection_complete"] == raw_complete,
            "manifest raw collection status contradicts primary packet coverage")
    require(manifest["analysis_complete"] == analysis_complete,
            "manifest analysis status contradicts page reports")
    complete = raw_complete and analysis_complete
    require(exit_code in (0, 3) and (exit_code == 0) == complete,
            "stream exit status contradicts completion flags")

    return {
        "raw_collection_complete": raw_complete,
        "analysis_complete": analysis_complete,
        "frames_seen": frames,
        "pages_checked": checked_pages,
        "packet_nodes": packet_nodes_total,
        "primary_packet_nodes": primary_packet_nodes,
        "page_bytes": document_total - manifest_size,
        "limitations": manifest["limitations"],
    }
