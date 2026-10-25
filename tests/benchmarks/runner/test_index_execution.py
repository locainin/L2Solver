"""Index mode retains, verifies, and streams facts without collecting rows."""

import hashlib
import ipaddress
import json
import struct
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from support import write_sample

from benchmarks.runner import execution as runner_execution
from benchmarks.runner.capture import iter_packets
from benchmarks.runner.catalogue import load_catalogue
from benchmarks.runner.execution import run_sample

DEFAULT_SCOPE = {"section": 0, "interface": 0, "vlans": []}


def program(root, capture, metadata, packets, flows, relationships, *,
            database_flows=None, database_relationships=None, database_dns_scope=None,
            database_destination_direction=None,
            changed_capture=None, exit_stage=None, locator_delta=0,
            change_binary_stage=None):
    path = root / "analyzer"
    source_id = "sha256:" + metadata["capture_sha256"]
    database_flows = flows if database_flows is None else database_flows
    database_relationships = relationships if database_relationships is None else database_relationships
    scopes, scope_ids = [], {}

    def scope_id(value):
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        if encoded not in scope_ids:
            scope_ids[encoded] = len(scope_ids) + 1
            scopes.append((scope_ids[encoded], encoded))
        return scope_ids[encoded]

    for flow in database_flows:
        scope_id(flow["scope"])
    for relationship in database_relationships:
        flow = next(flow for flow in database_flows
                    if flow["id"] == relationship["destination_flow"])
        scope_id(flow["scope"])
    if database_dns_scope is not None:
        scope_id(database_dns_scope)
    flow_rows = [
        (flow["id"], 1, scope_id(flow["scope"]), flow["protocol"],
         ipaddress.ip_address(flow["endpoint_a"]).packed, flow["port_a"],
         ipaddress.ip_address(flow["endpoint_b"]).packed, flow["port_b"])
        for flow in database_flows
    ]
    flow_by_id = {flow["id"]: flow for flow in database_flows}
    packet_flows, packet_directions, packet_payloads = {}, {}, {}
    for flow in database_flows:
        for number in range(flow["first_packet"], flow["last_packet"] + 1):
            packet_flows[number] = flow["id"]
            packet_directions[number] = 0
            packet_payloads[number] = 0
        packet_payloads[flow["first_packet"]] = flow["payload_bytes"]
    for relationship in database_relationships:
        flow = flow_by_id[relationship["destination_flow"]]
        answer = ipaddress.ip_address(relationship["answer_address"]).packed
        first = ipaddress.ip_address(flow["endpoint_a"]).packed
        if first == answer:
            packet_directions[relationship["destination_packet"]] = 1
        else:
            packet_directions[relationship["destination_packet"]] = 0
        packet_flows[relationship["destination_packet"]] = flow["id"]
        if database_destination_direction is not None:
            packet_directions[relationship["destination_packet"]] = database_destination_direction
    packet_rows = [
        (number, packet.offset, packet.length, packet.original_length,
         hashlib.sha256(capture[packet.offset:packet.offset + packet.length]).digest(),
         packet_flows.get(number), packet_payloads.get(number, 0),
         packet_directions.get(number, 0))
        for number, packet in enumerate(packets, 1)
    ]
    address_rows = {}
    exchanges = {}
    for relationship in database_relationships:
        flow = flow_by_id[relationship["destination_flow"]]
        scope = scope_id(flow["scope"] if database_dns_scope is None else database_dns_scope)
        response = relationship["response_packet"]
        answer_range = relationship["answer_range"]
        address_rows[(response, answer_range["offset"])] = (
            1, scope, response, relationship["request_packet"],
            ipaddress.ip_address(flow["endpoint_a"]).packed,
            ipaddress.ip_address(relationship["answer_address"]).packed,
            answer_range["offset"], answer_range["length"],
            relationship["association"], bytes(relationship["answer_owner_wire"]),
        )
        exchanges[response] = (
            1, response, relationship["request_packet"],
            relationship["association"], json.dumps(relationship["questions"]),
        )
    summary = {
        "sections": 0,
        "reported_sections": 0,
        "incomplete_sections": 0,
        "capture_dropped": 0,
        "interface_dropped": 0,
    }
    inventory = {
        "sources": 1,
        "bytes": len(capture),
        "packets": len(packets),
        "flows": len(database_flows),
        "dns_exchanges": len(exchanges),
        "dns_addresses": len(address_rows),
        "unsupported_transport_packets": len(packets),
        "collection_summary": summary,
        "sources_with_unknown_collection_quality": 1,
        "limitations": ["collection quality unknown"],
    }
    receipt = {
        "schema_version": 5,
        "format": "l2solver_index",
        "inventory": inventory,
        "sources": [{
            "source_id": source_id,
            "bytes": len(capture),
            "packets": len(packets),
            "transport_packets": 0,
            "unsupported_transport_packets": len(packets),
            "collection_summary": summary,
        }],
    }
    verify = {"verified": True, "inventory": inventory}
    payload = repr({
        "capture": capture,
        "source_id": source_id,
        "receipt": receipt,
        "verify": verify,
        "packets": [
            (number, packet.offset, packet.length, packet.original_length,
             hashlib.sha256(capture[packet.offset:packet.offset + packet.length]).digest())
            for number, packet in enumerate(packets, 1)
        ],
        "flows": flows,
        "relationships": relationships,
        "scopes": scopes,
        "flow_rows": flow_rows,
        "packet_rows": packet_rows,
        "dns_addresses": list(address_rows.values()),
        "dns_exchanges": list(exchanges.values()),
        "changed_capture": changed_capture,
        "exit_stage": exit_stage,
        "locator_delta": locator_delta,
        "change_binary_stage": change_binary_stage,
    })
    body = f"""import json, pathlib, sqlite3, sys
fixture = {payload}
args = sys.argv[1:]
if args[1] == 'index':
    assert args[0] == 'workbench'
    assert args[3:] == ['--directory', 'index']
    assert pathlib.Path(args[2]).is_file()
    root = pathlib.Path('index')
    (root / 'sources').mkdir(parents=True)
    (root / 'manifest.json').write_text(json.dumps(fixture['receipt']), encoding='utf-8')
    connection = sqlite3.connect(root / 'index.sqlite')
    connection.executescript('CREATE TABLE sources(id INTEGER PRIMARY KEY, sha256 TEXT, bytes INTEGER, packets INTEGER); CREATE TABLE scopes(id INTEGER PRIMARY KEY, value BLOB); CREATE TABLE packets(source INTEGER, number INTEGER, offset INTEGER, length INTEGER, original_length INTEGER, sha256 BLOB, flow INTEGER, payload_length INTEGER, direction INTEGER, PRIMARY KEY(source, number)); CREATE TABLE flows(id INTEGER PRIMARY KEY, source INTEGER, scope INTEGER, protocol INTEGER, a BLOB, ap INTEGER, b BLOB, bp INTEGER); CREATE TABLE dns_exchanges(source INTEGER, response INTEGER, request INTEGER, status TEXT, questions TEXT); CREATE TABLE dns_addresses(source INTEGER, scope INTEGER, response INTEGER, request INTEGER, requester BLOB, address BLOB, offset INTEGER, length INTEGER, status TEXT, owner BLOB);')
    connection.execute('INSERT INTO sources VALUES(1, ?, ?, ?)', (fixture['source_id'], len(fixture['capture']), len(fixture['packets'])))
    connection.executemany('INSERT INTO scopes VALUES(?, ?)', fixture['scopes'])
    connection.executemany('INSERT INTO flows VALUES(?, ?, ?, ?, ?, ?, ?, ?)', fixture['flow_rows'])
    connection.executemany('INSERT INTO dns_exchanges VALUES(?, ?, ?, ?, ?)', fixture['dns_exchanges'])
    connection.executemany('INSERT INTO dns_addresses VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', fixture['dns_addresses'])
    packet_rows = fixture['packet_rows']
    if fixture['locator_delta']:
        packet_rows = [(number, offset + fixture['locator_delta'], length, original, digest,
                        flow, payload, direction)
                       for number, offset, length, original, digest, flow, payload, direction
                       in packet_rows]
    connection.executemany('INSERT INTO packets VALUES(1, ?, ?, ?, ?, ?, ?, ?, ?)', packet_rows)
    connection.commit()
    connection.close()
    (root / 'sources' / (fixture['source_id'][7:] + '.pcap')).write_bytes(fixture['capture'])
    print(json.dumps(fixture['receipt']), end='')
    if fixture['changed_capture'] is not None:
        pathlib.Path(args[2]).write_bytes(fixture['changed_capture'])
elif args[1] == 'indexed':
    assert args[0] == 'workbench' and args[2] == 'index'
    operation = args[3]
    output = pathlib.Path(args[args.index('--output') + 1])
    if fixture['exit_stage'] == operation:
        sys.exit(4)
    if operation == 'verify':
        output.write_text(json.dumps(fixture['verify']), encoding='utf-8')
    elif operation == 'flows':
        output.write_text(''.join(json.dumps(item) + '\\n' for item in fixture['flows']), encoding='utf-8')
    elif operation == 'relationships':
        output.write_text(''.join(json.dumps(item) + '\\n' for item in fixture['relationships']), encoding='utf-8')
    else:
        raise AssertionError(operation)
    if fixture['change_binary_stage'] == operation:
        pathlib.Path(__file__).write_text('changed executable')
else:
    raise AssertionError(args)
"""
    path.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    path.chmod(0o700)
    return path


def packet_sample(root, payloads=(b"\xc0\x00\x02\x02", b"destination")):
    catalogue, sample, metadata, _ = write_sample(root)
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    records = b"".join(
        struct.pack("<IIII", number, 0, len(payload), len(payload)) + payload
        for number, payload in enumerate(payloads, 1)
    )
    capture = header + records
    capture_path = sample / "capture.pcap"
    capture_path.write_bytes(capture)
    metadata["capture_sha256"] = hashlib.sha256(capture).hexdigest()
    metadata["capture_bytes"] = len(capture)
    (sample / "source.json").write_text(json.dumps(metadata), encoding="utf-8")
    packets = list(iter_packets(capture))
    return catalogue, sample, metadata, capture, packets


def sample_facts(metadata, packets):
    source_id = "sha256:" + metadata["capture_sha256"]
    first = packets[0]
    return [
        {
            "id": 1,
            "source_id": source_id,
            "scope": DEFAULT_SCOPE,
            "protocol": 17,
            "endpoint_a": "192.0.2.1",
            "port_a": 53,
            "endpoint_b": "192.0.2.2",
            "port_b": 80,
            "first_packet": 1,
            "last_packet": 2,
            "packets": 2,
            "payload_bytes": 12,
        }
    ], [
        {
            "source_id": source_id,
            "request_packet": None,
            "response_packet": 1,
            "destination_packet": 2,
            "destination_flow": 1,
            "answer_address": "192.0.2.2",
            "answer_range": {
                "source": source_id,
                "packet": 1,
                "offset": first.offset,
                "length": 4,
            },
            "association": "unmatched_response",
            "questions": [],
            "answer_owner_wire": [0],
        }
    ]


class IndexExecutionTests(unittest.TestCase):
    def test_verifies_and_streams_source_facts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, sample, metadata, capture, packets = packet_sample(root)
            flows, relationships = sample_facts(metadata, packets)
            binary = program(root, capture, metadata, packets, flows, relationships)

            validate = runner_execution.validate_index_output

            def slow_validation(*arguments):
                time.sleep(0.05)
                return validate(*arguments)

            with patch("benchmarks.runner.execution.validate_index_output",
                       side_effect=slow_validation):
                result = run_sample(load_catalogue(catalogue)[0], binary, "index-one", 5,
                                    mode="index")

            self.assertEqual(result["status"], "complete")
            self.assertEqual(result["binary_sha256"], hashlib.sha256(binary.read_bytes()).hexdigest())
            self.assertEqual(result["source"]["capture_sha256"], metadata["capture_sha256"])
            self.assertEqual(
                [result["stages"][name]["exit_code"] for name in
                 ("index", "verify", "flows", "relationships")],
                [0, 0, 0, 0],
            )
            self.assertEqual(
                {stage["binary_argument"] for stage in result["stages"].values()},
                {result["binary_argument"]},
            )
            self.assertTrue(all(stage["source_sha256"] == metadata["capture_sha256"]
                                for stage in result["stages"].values()))
            self.assertEqual(result["validation"]["packet_rows_checked"], 2)
            self.assertEqual(result["validation"]["flow_rows_checked"], 1)
            self.assertEqual(result["validation"]["relationship_rows_checked"], 1)
            self.assertGreaterEqual(result["elapsed_seconds"], result["analyzer_elapsed_seconds"])
            self.assertGreaterEqual(result["elapsed_seconds"], result["validation_seconds"])
            self.assertGreaterEqual(result["elapsed_seconds"] - result["analyzer_elapsed_seconds"],
                                    0.04)
            self.assertGreaterEqual(result["validation_seconds"], 0.04)
            self.assertEqual(result["scope"]["detection"], "not_performed")
            self.assertIn("unknown", result["scope"]["collection_quality"])
            self.assertTrue((sample / "runs/index-one/index/index.sqlite").is_file())
            self.assertTrue((sample / "runs/index-one/flows.jsonl").is_file())
            self.assertTrue((sample / "runs/index-one/relationships.jsonl").is_file())

    def test_rejects_mismatched_packet_locators(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture, packets = packet_sample(root)
            flows, relationships = sample_facts(metadata, packets)
            sample = load_catalogue(catalogue)[0]
            altered = program(
                root, capture, metadata, packets, flows, relationships, locator_delta=1,
            )

            result = run_sample(sample, altered, "bad-locator", 5, mode="index")

            self.assertEqual(result["status"], "evidence_failure")
            self.assertIn("locator", result["error"])

    def test_rejects_oversized_flow_payload_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture, packets = packet_sample(root)
            flows, relationships = sample_facts(metadata, packets)
            flows[0]["payload_bytes"] = len(capture) + 1
            binary = program(root, capture, metadata, packets, flows, relationships)

            result = run_sample(load_catalogue(catalogue)[0], binary, "oversized-flow", 5,
                                mode="index")

            self.assertEqual(result["status"], "evidence_failure")
            self.assertIn("source byte", result["error"])

    def test_rejects_noncanonical_flow_endpoints(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture, packets = packet_sample(root)
            flows, relationships = sample_facts(metadata, packets)
            canonical_flows = [dict(flows[0])]
            flows[0]["endpoint_a"] = "198.51.100.7"
            binary = program(root, capture, metadata, packets, flows, relationships,
                             database_flows=canonical_flows)

            result = run_sample(load_catalogue(catalogue)[0], binary, "altered-endpoint", 5,
                                mode="index")

            self.assertEqual(result["status"], "evidence_failure")
            self.assertIn("flow", result["error"])

    def test_rejects_missing_flow_export_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture, packets = packet_sample(root)
            flows, relationships = sample_facts(metadata, packets)
            binary = program(root, capture, metadata, packets, [], relationships,
                             database_flows=flows)

            result = run_sample(load_catalogue(catalogue)[0], binary, "missing-flow-row", 5,
                                mode="index")

            self.assertEqual(result["status"], "evidence_failure")
            self.assertIn("flow export", result["error"])

    def test_rejects_extra_flow_export_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture, packets = packet_sample(root)
            flows, relationships = sample_facts(metadata, packets)
            extra = dict(flows[0], id=2, endpoint_a="192.0.2.3")
            binary = program(root, capture, metadata, packets, [*flows, extra], relationships,
                             database_flows=flows)

            result = run_sample(load_catalogue(catalogue)[0], binary, "extra-flow-row", 5,
                                mode="index")

            self.assertEqual(result["status"], "evidence_failure")
            self.assertIn("extra row", result["error"])

    def test_rejects_changed_flow_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture, packets = packet_sample(root)
            flows, relationships = sample_facts(metadata, packets)
            flows[0]["scope"] = {"section": 0, "interface": 1, "vlans": []}
            binary = program(root, capture, metadata, packets, flows, relationships,
                             database_flows=[dict(flows[0], scope=DEFAULT_SCOPE)])

            result = run_sample(load_catalogue(catalogue)[0], binary, "altered-scope", 5,
                                mode="index")

            self.assertEqual(result["status"], "evidence_failure")
            self.assertIn("flow", result["error"])

    def test_rejects_relationships_with_missing_flows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture, packets = packet_sample(root)
            flows, relationships = sample_facts(metadata, packets)
            canonical = [dict(relationships[0])]
            relationships[0]["destination_flow"] = 999
            binary = program(root, capture, metadata, packets, flows, relationships,
                             database_relationships=canonical)

            result = run_sample(load_catalogue(catalogue)[0], binary, "missing-flow", 5,
                                mode="index")

            self.assertEqual(result["status"], "evidence_failure")
            self.assertIn("relationship", result["error"])

    def test_rejects_destination_flow_membership_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture, packets = packet_sample(
                root, payloads=(b"\xc0\x00\x02\x02", b"destination-a", b"destination-b"),
            )
            flows, relationships = sample_facts(metadata, packets)
            second = dict(flows[0], id=2, first_packet=3, last_packet=3, packets=1,
                          endpoint_a="192.0.2.3")
            canonical = [dict(relationships[0])]
            relationships[0]["destination_flow"] = 2
            binary = program(root, capture, metadata, packets, [flows[0], second], relationships,
                             database_relationships=canonical)

            result = run_sample(load_catalogue(catalogue)[0], binary, "wrong-flow-membership", 5,
                                mode="index")

            self.assertEqual(result["status"], "evidence_failure")
            self.assertIn("relationship", result["error"])

    def test_rejects_dns_flow_scope_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture, packets = packet_sample(root)
            flows, relationships = sample_facts(metadata, packets)
            binary = program(
                root, capture, metadata, packets, flows, relationships,
                database_dns_scope={"section": 0, "interface": 1, "vlans": []},
            )

            result = run_sample(load_catalogue(catalogue)[0], binary, "wrong-dns-scope", 5,
                                mode="index")

            self.assertEqual(result["status"], "evidence_failure")
            self.assertIn("relationship", result["error"])

    def test_rejects_wrong_relationship_packet_direction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture, packets = packet_sample(root)
            flows, relationships = sample_facts(metadata, packets)
            binary = program(root, capture, metadata, packets, flows, relationships,
                             database_destination_direction=1)

            result = run_sample(load_catalogue(catalogue)[0], binary, "wrong-direction", 5,
                                mode="index")

            self.assertEqual(result["status"], "evidence_failure")
            self.assertIn("relationship", result["error"])

    def test_rejects_relationships_from_another_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture, packets = packet_sample(root)
            flows, relationships = sample_facts(metadata, packets)
            relationships[0]["source_id"] = "sha256:" + "a" * 64
            binary = program(root, capture, metadata, packets, flows, relationships,
                             database_relationships=sample_facts(metadata, packets)[1])

            result = run_sample(load_catalogue(catalogue)[0], binary, "wrong-source", 5,
                                mode="index")

            self.assertEqual(result["status"], "evidence_failure")
            self.assertIn("source", result["error"])

    def test_rejects_invalid_relationship_capture_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture, packets = packet_sample(root)
            flows, relationships = sample_facts(metadata, packets)
            canonical = [dict(relationships[0])]
            relationships[0]["destination_packet"] = 1
            binary = program(root, capture, metadata, packets, flows, relationships,
                             database_relationships=canonical)

            result = run_sample(load_catalogue(catalogue)[0], binary, "wrong-order", 5,
                                mode="index")

            self.assertEqual(result["status"], "evidence_failure")
            self.assertIn("order", result["error"])

    def test_rejects_mismatched_dns_answer_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture, packets = packet_sample(root)
            flows, relationships = sample_facts(metadata, packets)
            flows[0]["endpoint_b"] = "192.0.2.3"
            relationships[0]["answer_address"] = "192.0.2.3"
            binary = program(root, capture, metadata, packets, flows, relationships)

            result = run_sample(load_catalogue(catalogue)[0], binary, "wrong-dns-bytes", 5,
                                mode="index")

            self.assertEqual(result["status"], "evidence_failure")
            self.assertIn("answer bytes", result["error"])

    def test_rejects_missing_relationship_export_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture, packets = packet_sample(root)
            flows, relationships = sample_facts(metadata, packets)
            binary = program(root, capture, metadata, packets, flows, [],
                             database_relationships=relationships)

            result = run_sample(load_catalogue(catalogue)[0], binary, "missing-relationship", 5,
                                mode="index")

            self.assertEqual(result["status"], "evidence_failure")
            self.assertIn("relationship", result["error"])

    def test_rejects_extra_relationship_export_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture, packets = packet_sample(root)
            flows, relationships = sample_facts(metadata, packets)
            extra = dict(relationships[0], destination_packet=1)
            binary = program(root, capture, metadata, packets, flows, [*relationships, extra],
                             database_relationships=relationships)

            result = run_sample(load_catalogue(catalogue)[0], binary, "extra-relationship", 5,
                                mode="index")

            self.assertEqual(result["status"], "evidence_failure")
            self.assertIn("relationship", result["error"])

    def test_rejects_relationship_ranges_crossing_packets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture, packets = packet_sample(root)
            flows, relationships = sample_facts(metadata, packets)
            relationships[0]["answer_range"]["offset"] = packets[0].offset + packets[0].length - 1
            relationships[0]["answer_range"]["length"] = 2
            binary = program(root, capture, metadata, packets, flows, relationships)

            result = run_sample(load_catalogue(catalogue)[0], binary, "bad-range", 5, mode="index")

            self.assertEqual(result["status"], "evidence_failure")
            self.assertIn("packet", result["error"])

    def test_requires_string_encoded_relationship_addresses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture, packets = packet_sample(root)
            flows, relationships = sample_facts(metadata, packets)
            relationships[0]["answer_address"] = 3221225986
            binary = program(root, capture, metadata, packets, flows, relationships)

            result = run_sample(load_catalogue(catalogue)[0], binary, "numeric-address", 5,
                                mode="index")

            self.assertEqual(result["status"], "evidence_failure")
            self.assertIn("string", result["error"])

    def test_preserves_failing_stage_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture, packets = packet_sample(root)
            flows, relationships = sample_facts(metadata, packets)
            binary = program(
                root, capture, metadata, packets, flows, relationships, exit_stage="verify",
            )

            result = run_sample(load_catalogue(catalogue)[0], binary, "verify-failed", 5, mode="index")

            self.assertEqual(result["status"], "tool_failure")
            self.assertEqual(result["stages"]["verify"]["exit_code"], 4)
            self.assertNotIn("flows", result["stages"])

    def test_rejects_executable_mutation_during_pipeline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture, packets = packet_sample(root)
            flows, relationships = sample_facts(metadata, packets)
            binary = program(
                root, capture, metadata, packets, flows, relationships,
                change_binary_stage="relationships",
            )

            result = run_sample(load_catalogue(catalogue)[0], binary, "binary-changed", 5,
                                mode="index")

            self.assertEqual(result["status"], "evidence_failure")
            self.assertIn("executable changed", result["error"])

    def test_rejects_source_mutation_after_ingest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture, packets = packet_sample(root)
            flows, relationships = sample_facts(metadata, packets)
            binary = program(
                root, capture, metadata, packets, flows, relationships,
                changed_capture=b"X" * len(capture),
            )

            result = run_sample(load_catalogue(catalogue)[0], binary, "source-changed", 5, mode="index")

            self.assertEqual(result["status"], "evidence_failure")
            self.assertIn("source hash", result["error"])

    def test_allows_multiple_dns_destination_flows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalogue, _, metadata, capture, packets = packet_sample(
                root, payloads=(b"\xc0\x00\x02\x02", b"destination-a", b"destination-b"),
            )
            flows, relationships = sample_facts(metadata, packets)
            second_flow = dict(flows[0], id=2, first_packet=3, last_packet=3, packets=1,
                               port_a=53001)
            second_relationship = dict(relationships[0], destination_packet=3, destination_flow=2)
            binary = program(
                root, capture, metadata, packets, [*flows, second_flow],
                [*relationships, second_relationship],
            )

            result = run_sample(load_catalogue(catalogue)[0], binary, "many-destinations", 5,
                                mode="index")

            self.assertEqual(result["status"], "complete", result.get("error"))
            self.assertEqual(result["validation"]["relationship_rows_checked"], 2)


if __name__ == "__main__":
    unittest.main()
