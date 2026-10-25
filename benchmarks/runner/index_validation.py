"""Independently compare indexed packet and fact rows using bounded source reads."""

import hashlib
import ipaddress
import json
import os
import sqlite3
import stat
from contextlib import closing
from pathlib import Path

from .capture import SeekableCapture, iter_packets
from .catalogue import hash_file, read_json, unique_object
from .validation import require

MAX_INDEX_JSON_BYTES = 1024 * 1024
MAX_FACT_LINE_BYTES = 1024 * 1024
INDEX_DB_CACHE_KIB = 8192
MAX_SCOPE_JSON_BYTES = 64 * 1024
U64_MAX = (1 << 64) - 1
INDEX_SCHEMA_VERSION = 5
INDEX_FIELDS = {"schema_version", "format", "inventory", "sources"}
INVENTORY_FIELDS = {
    "sources", "bytes", "packets", "flows", "dns_exchanges", "dns_addresses",
    "unsupported_transport_packets", "collection_summary",
    "sources_with_unknown_collection_quality", "limitations",
}
SOURCE_FIELDS = {
    "source_id", "bytes", "packets", "transport_packets",
    "unsupported_transport_packets", "collection_summary",
}
SUMMARY_FIELDS = {
    "sections", "reported_sections", "incomplete_sections", "capture_dropped",
    "interface_dropped",
}
FLOW_FIELDS = {
    "id", "source_id", "scope", "protocol", "endpoint_a", "port_a", "endpoint_b",
    "port_b", "first_packet", "last_packet", "packets", "payload_bytes",
}
RELATIONSHIP_FIELDS = {
    "source_id", "request_packet", "response_packet", "destination_packet",
    "destination_flow", "answer_address", "answer_range", "association", "questions",
    "answer_owner_wire",
}
RANGE_FIELDS = {"source", "packet", "offset", "length"}
FLOW_QUERY = (
    "SELECT f.id,s.sha256,c.value,f.protocol,f.a,f.ap,f.b,f.bp,MIN(p.number),"
    "MAX(p.number),COUNT(*),SUM(p.payload_length) FROM flows f "
    "JOIN sources s ON s.id=f.source JOIN scopes c ON c.id=f.scope "
    "JOIN packets p ON p.flow=f.id GROUP BY f.id ORDER BY f.id"
)
# Keep the projection aligned with the index API and compare it row by row to JSONL
RELATIONSHIP_QUERY = (
    "WITH candidates AS ("
    "SELECT d.source,d.response,d.offset,f.id,MIN(p.number) AS destination_packet "
    "FROM dns_addresses d CROSS JOIN flows f "
    "JOIN packets p ON p.flow=f.id AND p.number>d.response "
    "WHERE f.source=d.source AND f.scope=d.scope AND f.a=d.requester AND f.b=d.address "
    "AND p.direction=0 GROUP BY d.source,d.response,d.offset,f.id "
    "UNION ALL "
    "SELECT d.source,d.response,d.offset,f.id,MIN(p.number) AS destination_packet "
    "FROM dns_addresses d CROSS JOIN flows f "
    "JOIN packets p ON p.flow=f.id AND p.number>d.response "
    "WHERE f.source=d.source AND f.scope=d.scope AND f.b=d.requester AND f.a=d.address "
    "AND p.direction=1 GROUP BY d.source,d.response,d.offset,f.id) "
    "SELECT s.sha256,d.request,d.response,MIN(c.destination_packet),c.id,d.address,d.offset,"
    "d.length,d.status,x.questions,d.owner FROM candidates c "
    "JOIN dns_addresses d ON d.source=c.source AND d.response=c.response AND d.offset=c.offset "
    "JOIN dns_exchanges x ON x.source=d.source AND x.response=d.response "
    "JOIN sources s ON s.id=d.source "
    "GROUP BY d.source,d.response,d.offset,c.id "
    "ORDER BY d.source,d.response,d.offset,c.id"
)


def validate_index_output(directory, sample):
    directory = Path(directory)
    index_directory = directory / "index"
    _regular_directory(index_directory, "index directory")
    database = _regular_file(index_directory / "index.sqlite", "index database")
    manifest = read_json(_regular_file(index_directory / "manifest.json", "index manifest"),
                         MAX_INDEX_JSON_BYTES)
    stdout_receipt = read_json(_regular_file(directory / "index.stdout.log", "index receipt"),
                               MAX_INDEX_JSON_BYTES)
    require(stdout_receipt == manifest, "index receipt output disagrees with its manifest")

    expected_id = "sha256:" + sample.metadata["capture_sha256"]
    inventory, source = _check_receipt(manifest, sample.metadata, expected_id)
    _check_verification(directory, inventory)
    retained_source_hash = _check_retained_source(index_directory, expected_id, source["bytes"])

    with sample.capture.open("rb") as source_file:
        before = os.fstat(source_file.fileno())
        require(before.st_size == source["bytes"], "source byte length changed after indexing")
        capture = SeekableCapture(source_file)
        source_hash = _hash_source(capture, source["bytes"])
        require(source_hash == sample.metadata["capture_sha256"],
                "source hash differs from catalogue")
        counts = _check_index_facts(
            database, directory, capture, expected_id, source, inventory
        )
        require(_same_file_state(before, os.fstat(source_file.fileno())),
                "source file changed during validation")

    return {
        "source_sha256": source_hash,
        "retained_source_sha256": retained_source_hash,
        "source_bytes": source["bytes"],
        "packet_rows_checked": counts["packets"],
        "flow_rows_checked": counts["flows"],
        "relationship_rows_checked": counts["relationships"],
        "collection_summary": source["collection_summary"],
        "flows_file": {"bytes": counts["flow_bytes"], "sha256": counts["flow_hash"]},
        "relationships_file": {
            "bytes": counts["relationship_bytes"],
            "sha256": counts["relationship_hash"],
        },
    }


def _check_verification(directory, inventory):
    verification = read_json(_regular_file(directory / "verify.json", "deep verification report"),
                             MAX_INDEX_JSON_BYTES)
    require(isinstance(verification, dict) and set(verification) == {"verified", "inventory"},
            "invalid deep verification report")
    require(verification["verified"] is True, "indexed source verification did not succeed")
    require(verification["inventory"] == inventory, "verified inventory changed after indexing")


def _check_index_facts(database, directory, capture, expected_id, source, inventory):
    uri = database.resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA temp_store=FILE")
        connection.execute(f"PRAGMA cache_size=-{INDEX_DB_CACHE_KIB}")
        source_number = _source_number(connection, source, expected_id)
        _check_fact_storage_bounds(connection)
        packet_count = _compare_packet_rows(connection, source_number, capture)
        require(packet_count == source["packets"] == inventory["packets"],
                "source packet count disagrees with the independent record scan")
        require(connection.execute("SELECT COUNT(*) FROM packets").fetchone()[0] == packet_count,
                "index contains packet rows outside its only source")
        flow_total = connection.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
        address_total = connection.execute("SELECT COUNT(*) FROM dns_addresses").fetchone()[0]
        exchange_total = connection.execute("SELECT COUNT(*) FROM dns_exchanges").fetchone()[0]
        require(flow_total == inventory["flows"], "indexed flow count disagrees with inventory")
        require(address_total == inventory["dns_addresses"],
                "indexed DNS address count disagrees with inventory")
        require(exchange_total == inventory["dns_exchanges"],
                "indexed DNS exchange count disagrees with inventory")

        flow_path = _regular_file(directory / "flows.jsonl", "flow output")
        flow_count, flow_bytes, flow_hash = _check_flows(
            connection, flow_path, source["bytes"], packet_count
        )
        require(flow_count == flow_total, "flow export rows disagree with indexed flow rows")
        relationship_path = _regular_file(
            directory / "relationships.jsonl", "relationship output"
        )
        relationship_count, relationship_bytes, relationship_hash = _check_relationships(
            connection, relationship_path, capture, expected_id, packet_count, source["bytes"]
        )
    return {
        "packets": packet_count,
        "flows": flow_count,
        "relationships": relationship_count,
        "flow_bytes": flow_bytes,
        "flow_hash": flow_hash,
        "relationship_bytes": relationship_bytes,
        "relationship_hash": relationship_hash,
    }


def _check_fact_storage_bounds(connection):
    limits = (
        ("SELECT EXISTS(SELECT 1 FROM scopes WHERE value IS NULL OR length(value)>?)",
         (MAX_SCOPE_JSON_BYTES,), "indexed scope exceeds its storage bound"),
        (("SELECT EXISTS(SELECT 1 FROM dns_exchanges "
          "WHERE questions IS NULL OR length(questions)>?)"),
         (MAX_FACT_LINE_BYTES,), "indexed DNS questions exceed their storage bound"),
        (("SELECT EXISTS(SELECT 1 FROM dns_addresses WHERE address IS NULL "
          "OR length(address) NOT IN (4,16) OR owner IS NULL OR length(owner)>255)"),
         (), "indexed DNS address fields exceed their storage bounds"),
    )
    for query, parameters, message in limits:
        require(connection.execute(query, parameters).fetchone()[0] == 0, message)


def _source_number(connection, source, expected_id):
    row = connection.execute(
        "SELECT id,bytes,packets FROM sources WHERE sha256=?", (expected_id,)
    ).fetchone()
    require(row is not None, "indexed source row is missing")
    require(connection.execute("SELECT COUNT(*) FROM sources").fetchone()[0] == 1,
            "index contains unexpected source rows")
    require(row[1] == source["bytes"] and row[2] == source["packets"],
            "indexed source row counts mismatch")
    return row[0]


def _compare_packet_rows(connection, source_number, capture):
    # Walk source records and SQL locators together without retaining packet rows
    packets = iter(iter_packets(capture))
    statement = connection.execute(
        "SELECT number,offset,length,original_length,sha256 FROM packets "
        "WHERE source=? ORDER BY number", (source_number,)
    )
    checked = 0
    for row in statement:
        packet = next(packets, None)
        require(packet is not None, "index contains more packet rows than the source")
        checked += 1
        number, offset, length, original_length, digest = row
        require(number == checked and (offset, length, original_length)
                == (packet.offset, packet.length, packet.original_length),
                f"indexed packet locator mismatch at record {checked}")
        require(_packet_hash(capture, packet.offset, packet.length) == digest,
                f"indexed packet bytes mismatch at record {checked}")
    require(next(packets, None) is None, "source contains packet records missing from index")
    return checked


def _packet_hash(capture, offset, length):
    digest = hashlib.sha256()
    for chunk in capture.iter_chunks(offset, length):
        digest.update(chunk)
    return digest.digest()


def _hash_source(capture, length):
    digest = hashlib.sha256()
    for chunk in capture.iter_chunks(0, length):
        digest.update(chunk)
    return digest.hexdigest()


def _check_flows(connection, path, source_bytes, packet_count):
    rows = iter(connection.execute(FLOW_QUERY))
    exported = iter(_records(path))
    count = 0
    for row in rows:
        actual = next(exported, None)
        require(actual is not None, "flow export is missing an indexed flow row")
        expected = _flow_record(row)
        _validate_flow_record(actual, packet_count, source_bytes)
        require(actual == expected, "flow export row disagrees with its indexed flow row")
        count += 1
    require(next(exported, None) is None, "flow export contains an extra row")
    return count, *_file_facts(path)


def _flow_record(row):
    return {
        "id": row[0],
        "source_id": row[1],
        "scope": json.loads(row[2]),
        "protocol": row[3],
        "endpoint_a": str(ipaddress.ip_address(row[4])),
        "port_a": row[5],
        "endpoint_b": str(ipaddress.ip_address(row[6])),
        "port_b": row[7],
        "first_packet": row[8],
        "last_packet": row[9],
        "packets": row[10],
        "payload_bytes": row[11],
    }


def _validate_flow_record(flow, packet_count, source_bytes):
    require(set(flow) == FLOW_FIELDS, "unsupported flow fields")
    _integer(flow["id"], "flow ID", minimum=1)
    require(isinstance(flow["source_id"], str), "flow source must be a source ID")
    require(isinstance(flow["scope"], dict), "flow scope must be an object")
    _integer(flow["protocol"], "flow protocol", maximum=255)
    for name in ("port_a", "port_b"):
        _integer(flow[name], f"flow {name}", maximum=65535)
    address_a = ipaddress.ip_address(flow["endpoint_a"])
    address_b = ipaddress.ip_address(flow["endpoint_b"])
    require(address_a.version == address_b.version, "flow endpoints use different address families")
    first = _integer(flow["first_packet"], "flow first packet", minimum=1)
    last = _integer(flow["last_packet"], "flow last packet", minimum=first)
    packets = _integer(flow["packets"], "flow packet count", minimum=1)
    require(last <= packet_count and packets <= last - first + 1,
            "flow packet range exceeds indexed source records")
    payload_bytes = _integer(flow["payload_bytes"], "flow payload bytes")
    require(payload_bytes <= source_bytes, "flow payload bytes exceed source byte length")


def _check_relationships(connection, path, capture, expected_id, packet_count, capture_length):
    rows = iter(connection.execute(RELATIONSHIP_QUERY))
    exported = iter(_records(path))
    packet_cursor = _PacketCursor(capture)
    count = 0
    for row in rows:
        actual = next(exported, None)
        require(actual is not None, "relationship export is missing an indexed relationship row")
        expected = _relationship_record(row, expected_id, packet_count, capture_length,
                                        capture, packet_cursor)
        _validate_relationship_record(actual, expected_id, packet_count, capture_length)
        require(actual == expected, "relationship export row disagrees with indexed DNS and flow facts")
        count += 1
    require(next(exported, None) is None, "relationship export contains an extra row")
    return count, *_file_facts(path)


def _relationship_record(row, expected_id, packet_count, capture_length, capture, packet_cursor):
    source_id, request, response, destination, flow_id, address = row[:6]
    offset, length, association, questions_json, owner = row[6:]
    require(source_id == expected_id, "indexed relationship references another source")
    response = _integer(response, "relationship response packet", minimum=1)
    destination = _integer(destination, "relationship destination packet", minimum=1)
    require(response < destination <= packet_count,
            "indexed relationship packet order is outside the source")
    if request is not None:
        _integer(request, "relationship request packet", minimum=1)
        require(request < response, "indexed relationship request is not before its response")
    address = bytes(address)
    require(len(address) in (4, 16), "indexed DNS answer has an invalid IP address length")
    offset = _integer(offset, "DNS answer offset")
    length = _integer(length, "DNS answer length", minimum=1)
    packet = packet_cursor.at(response)
    require(packet.offset <= offset and offset + length <= packet.offset + packet.length,
            "DNS answer range exceeds its response packet")
    require(offset <= capture_length and length <= capture_length - offset,
            "DNS answer range exceeds source bytes")
    require(length == len(address), "DNS answer range length differs from its address bytes")
    require(capture.read_range(offset, length) == address,
            "DNS answer bytes disagree with the source range")
    questions = json.loads(questions_json)
    require(isinstance(questions, list), "indexed DNS questions are not a list")
    require(isinstance(association, str) and 0 < len(association) <= 64,
            "invalid indexed DNS association")
    return {
        "source_id": source_id,
        "request_packet": request,
        "response_packet": response,
        "destination_packet": destination,
        "destination_flow": flow_id,
        "answer_address": str(ipaddress.ip_address(address)),
        "answer_range": {
            "source": expected_id,
            "packet": response,
            "offset": offset,
            "length": length,
        },
        "association": association,
        "questions": questions,
        "answer_owner_wire": list(bytes(owner)),
    }


def _validate_relationship_record(relationship, expected_id, packet_count, capture_length):
    require(set(relationship) == RELATIONSHIP_FIELDS, "unsupported relationship fields")
    require(relationship["source_id"] == expected_id,
            "relationship references another source")
    response = _integer(relationship["response_packet"], "response packet", minimum=1)
    destination = _integer(relationship["destination_packet"], "destination packet", minimum=1)
    require(response < destination <= packet_count, "relationship packet order is invalid")
    request = relationship["request_packet"]
    if request is not None:
        _integer(request, "request packet", minimum=1)
        require(request < response, "relationship request is not before its response")
    _integer(relationship["destination_flow"], "destination flow", minimum=1)
    require(isinstance(relationship["answer_address"], str),
            "relationship answer must be an IP address string")
    ipaddress.ip_address(relationship["answer_address"])
    require(isinstance(relationship["association"], str)
            and 0 < len(relationship["association"]) <= 64,
            "invalid relationship association")
    require(isinstance(relationship["questions"], list), "invalid relationship questions")
    owner = relationship["answer_owner_wire"]
    require(isinstance(owner, list)
            and all(type(byte) is int and 0 <= byte <= 255 for byte in owner),
            "invalid relationship owner bytes")
    _validate_answer_range(relationship["answer_range"], expected_id, response,
                           capture_length)


def _validate_answer_range(range_, expected_id, response_packet, capture_length):
    require(isinstance(range_, dict) and set(range_) == RANGE_FIELDS,
            "invalid relationship answer range")
    packet = _integer(range_["packet"], "answer range packet", minimum=1)
    require(range_["source"] == expected_id and packet == response_packet,
            "relationship answer range source or packet mismatch")
    offset = _integer(range_["offset"], "answer range offset")
    length = _integer(range_["length"], "answer range length", minimum=1)
    require(offset <= capture_length and length <= capture_length - offset,
            "relationship answer range exceeds source bytes")


class _PacketCursor:
    """Resolve monotonic packet references in one source scan."""

    def __init__(self, capture):
        self._source = iter(iter_packets(capture))
        self._number = 0
        self._packet = None

    def at(self, number):
        require(number >= self._number, "relationship rows are not ordered by response packet")
        while self._number < number:
            self._packet = next(self._source, None)
            self._number += 1
            require(self._packet is not None,
                    "relationship response packet exceeds source records")
        return self._packet


def _check_receipt(receipt, metadata, expected_id):
    require(isinstance(receipt, dict) and set(receipt) == INDEX_FIELDS,
            "unsupported index manifest fields")
    version = _integer(receipt["schema_version"], "index schema version", minimum=1,
                       maximum=2**32 - 1)
    require(version == INDEX_SCHEMA_VERSION, "unsupported index schema version")
    require(receipt["format"] == "l2solver_index", "unsupported index format")
    inventory = receipt["inventory"]
    require(isinstance(inventory, dict) and set(inventory) == INVENTORY_FIELDS,
            "unsupported index inventory fields")
    for name in (
        "sources", "bytes", "packets", "flows", "dns_exchanges", "dns_addresses",
        "unsupported_transport_packets", "sources_with_unknown_collection_quality",
    ):
        _integer(inventory[name], f"inventory {name}")
    _check_summary(inventory["collection_summary"])
    require(isinstance(inventory["limitations"], list)
            and all(isinstance(item, str) and len(item) <= 2048
                    for item in inventory["limitations"]),
            "invalid inventory limitations")
    require(inventory["sources"] == 1 and inventory["bytes"] == metadata["capture_bytes"],
            "index inventory source count or byte length mismatch")
    require(inventory["unsupported_transport_packets"] <= inventory["packets"],
            "invalid unsupported packet count")
    sources = receipt["sources"]
    require(isinstance(sources, list) and len(sources) == 1,
            "index must contain one source receipt")
    source = sources[0]
    require(isinstance(source, dict) and set(source) == SOURCE_FIELDS,
            "unsupported index source receipt fields")
    require(source["source_id"] == expected_id, "index source identity mismatch")
    for name in ("bytes", "packets", "transport_packets", "unsupported_transport_packets"):
        _integer(source[name], f"source {name}")
    _check_summary(source["collection_summary"])
    require(source["bytes"] == metadata["capture_bytes"], "index source byte length mismatch")
    require(source["bytes"] == inventory["bytes"] and source["packets"] == inventory["packets"],
            "source receipt disagrees with index inventory")
    require(source["unsupported_transport_packets"] == inventory["unsupported_transport_packets"],
            "source transport count disagrees with index inventory")
    require(source["transport_packets"] + source["unsupported_transport_packets"]
            == source["packets"], "source transport counts do not cover packet records")
    require(source["collection_summary"] == inventory["collection_summary"],
            "source collection summary disagrees with index inventory")
    return inventory, source


def _check_summary(summary):
    require(isinstance(summary, dict) and set(summary) == SUMMARY_FIELDS,
            "invalid collection summary")
    for name in SUMMARY_FIELDS:
        _integer(summary[name], f"collection summary {name}")
    require(summary["reported_sections"] <= summary["sections"]
            and summary["incomplete_sections"] <= summary["reported_sections"],
            "inconsistent collection summary counters")


def _check_retained_source(index_directory, expected_id, expected_bytes):
    source_directory = index_directory / "sources"
    _regular_directory(source_directory, "retained source directory")
    digest = expected_id.removeprefix("sha256:")
    source_path = _regular_file(source_directory / f"{digest}.pcap", "retained source")
    entries = iter(source_directory.iterdir())
    require(next(entries, None) == source_path and next(entries, None) is None,
            "retained source directory contains unexpected entries")
    require(source_path.stat().st_size == expected_bytes, "retained source byte length mismatch")
    require(hash_file(source_path) == digest, "retained source hash mismatch")
    return digest


def _records(path):
    # Keep one bounded JSONL row in memory at a time
    with path.open("rb") as stream:
        while True:
            line = stream.readline(MAX_FACT_LINE_BYTES + 1)
            if not line:
                return
            require(len(line) <= MAX_FACT_LINE_BYTES and line.endswith(b"\n"),
                    "fact row exceeds line bound or lacks its newline")
            value = json.loads(line, object_pairs_hook=unique_object)
            require(isinstance(value, dict), "fact row must be a JSON object")
            yield value


def _file_facts(path):
    return path.stat().st_size, hash_file(path)


def _regular_file(path, name):
    try:
        file_stat = path.lstat()
    except OSError as error:
        raise ValueError(f"missing {name}") from error
    require(stat.S_ISREG(file_stat.st_mode), f"{name} is not a regular file")
    return path


def _regular_directory(path, name):
    try:
        directory_stat = path.lstat()
    except OSError as error:
        raise ValueError(f"missing {name}") from error
    require(stat.S_ISDIR(directory_stat.st_mode), f"{name} is not a regular directory")


def _integer(value, name, minimum=0, maximum=U64_MAX):
    require(type(value) is int and minimum <= value <= maximum, f"invalid {name}")
    return value


def _same_file_state(first, second):
    return (first.st_dev, first.st_ino, first.st_size, first.st_mtime_ns, first.st_ctime_ns) == (
        second.st_dev, second.st_ino, second.st_size, second.st_mtime_ns, second.st_ctime_ns
    )
