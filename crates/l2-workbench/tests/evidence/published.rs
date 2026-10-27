use l2_workbench::evidence::{
    Case, Edge, EvidenceStatus, PublishedCaseUsage, PublishedEvidenceLimits, SourceRange,
    decode_published_evidence, write_published_case as write_case_with_budget,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    io::{self, Cursor, Write},
};

type TestResult = Result<(), Box<dyn Error>>;

fn write_published_case<W: Write>(
    case: &Case,
    scope: &Value,
    ordinal: u64,
    writer: W,
) -> io::Result<PublishedCaseUsage> {
    write_case_with_budget(case, scope, ordinal, writer, None)
}

#[derive(Serialize)]
struct Metadata {
    schema_version: u32,
    collection_complete: bool,
    blob_byte_limit: Option<usize>,
}

#[derive(Serialize)]
struct BlobRecord<'a> {
    id: &'a str,
    byte_length: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    inline_payload: Option<Value>,
}

#[derive(Serialize)]
struct CanonicalRecord<'a> {
    case_id: &'a str,
    scope: &'a Value,
    metadata: Metadata,
    sources: &'a [l2_workbench::evidence::Source],
    blobs: Vec<BlobRecord<'a>>,
    nodes: &'a [l2_workbench::evidence::Node],
    edges: &'a [Edge],
    limitations: &'a [String],
}

fn canonical(
    case: &Case,
    scope: &Value,
    ordinal: u64,
) -> Result<(String, Vec<u8>), Box<dyn Error>> {
    let placeholder = format!("case-{}", "0".repeat(64));
    let blobs = case
        .blobs()
        .iter()
        .map(|blob| {
            let inline = case.nodes().iter().any(|node| {
                node.blob.as_deref() == Some(blob.id.as_str())
                    && node.details.get("representation").and_then(Value::as_str)
                        == Some("json_blob")
            });
            Ok(BlobRecord {
                id: &blob.id,
                byte_length: blob.bytes.len(),
                inline_payload: inline
                    .then(|| serde_json::from_slice(&blob.bytes))
                    .transpose()?,
            })
        })
        .collect::<Result<Vec<_>, serde_json::Error>>()?;
    let mut record = CanonicalRecord {
        case_id: &placeholder,
        scope,
        metadata: Metadata {
            schema_version: case.schema_version(),
            collection_complete: case.collection_complete(),
            blob_byte_limit: case.blob_byte_limit(),
        },
        sources: case.sources(),
        blobs,
        nodes: case.nodes(),
        edges: case.edges(),
        limitations: case.limitations(),
    };
    let mut encoded = serde_json::to_vec(&record)?;
    encoded.push(b'\n');
    let mut hash = Sha256::new();
    hash.update(b"l2solver-export-case-v2\0");
    hash.update(ordinal.to_be_bytes());
    hash.update(&encoded);
    let id = format!("case-{:x}", hash.finalize());
    record.case_id = &id;
    encoded = serde_json::to_vec(&record)?;
    encoded.push(b'\n');
    Ok((id, encoded))
}

fn fixture() -> Result<Case, Box<dyn Error>> {
    let mut case = Case::new();
    let a = case.add_source("one.pcap", "capture", 100, &"a".repeat(64), None)?;
    let b = case.add_source("two.pcap", "capture", 100, &"b".repeat(64), None)?;
    let first = case.add_bytes_node(
        "candidate",
        b"same bytes",
        vec![
            SourceRange {
                source: a,
                packet: Some(7),
                offset: 2,
                length: 3,
            },
            SourceRange {
                source: b,
                packet: None,
                offset: 8,
                length: 5,
            },
        ],
        json!({"description":"shared descriptive value"}),
    )?;
    let second = case.add_bytes_node(
        "receipt",
        br#"{"items":[3,2,1],"optional":null}"#,
        Vec::new(),
        json!({"representation":"json_blob","output_node":first}),
    )?;
    for status in [EvidenceStatus::Hypothesis, EvidenceStatus::Observed] {
        case.add_edge(Edge {
            from: first,
            to: second,
            relation: "derived_from".into(),
            status,
            reason: "the repeated explanation describes this exact relationship".into(),
        })?;
    }
    case.add_limitation("one recorded limitation")?;
    Ok(case)
}

fn replace_record_value(
    encoded: &[u8],
    kind: &str,
    pointer: &str,
    value: Value,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut records = std::str::from_utf8(encoded)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    let record = records
        .iter_mut()
        .find(|record| record.get("record").and_then(Value::as_str) == Some(kind))
        .ok_or("record is missing")?;
    *record
        .pointer_mut(pointer)
        .ok_or("record field is missing")? = value;
    let mut output = Vec::new();
    for record in records {
        serde_json::to_writer(&mut output, &record)?;
        output.push(b'\n');
    }
    Ok(output)
}

#[test]
fn normalized_roundtrip_preserves_canonical_bytes_and_case_identity() -> TestResult {
    let case = fixture()?;
    let scope = json!({"kind":"flow","flow_id":7});
    let (expected_id, expected) = canonical(&case, &scope, 2)?;
    let mut normalized = Vec::new();
    let usage = write_published_case(&case, &scope, 2, &mut normalized)?;
    let mut decoded = Vec::new();
    decode_published_evidence(
        4,
        Cursor::new(&normalized),
        &mut decoded,
        PublishedEvidenceLimits::new(64 * 1024 * 1024, 16 * 1024 * 1024),
    )?;
    assert_eq!(usage.case_id, expected_id);
    assert_eq!(
        decoded, expected,
        "the canonical v2 graph and ordered edges must be unchanged"
    );
    Ok(())
}

#[test]
fn version_three_fixture_remains_readable_after_compact_node_encoding() -> TestResult {
    let mut case = Case::new();
    case.add_node(
        "candidate",
        None,
        Vec::new(),
        json!({"description":"shared","index":5}),
    )?;
    case.add_limitation("kept")?;
    let (_, expected) = canonical(&case, &json!({"kind":"test"}), 1)?;
    let mut decoded = Vec::new();
    decode_published_evidence(
        3,
        Cursor::new(include_bytes!("fixtures/published-v3.jsonl")),
        &mut decoded,
        PublishedEvidenceLimits::new(100_000, 10_000),
    )?;
    assert_eq!(decoded, expected);
    Ok(())
}

#[test]
fn writer_emits_compact_version_four_details_and_preserves_the_canonical_graph() -> TestResult {
    let case = fixture()?;
    let scope = json!({"kind":"flow","flow_id":9});
    let (_, expected) = canonical(&case, &scope, 1)?;
    let mut encoded = Vec::new();
    write_published_case(&case, &scope, 1, &mut encoded)?;
    let records = std::str::from_utf8(&encoded)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    let header = records.first().ok_or("header is missing")?;
    assert_eq!(header.pointer("/value/version"), Some(&json!(4)));
    let node = records
        .iter()
        .find(|record| record.get("record") == Some(&json!("node")))
        .ok_or("node is missing")?;
    assert!(node.pointer("/value/4").and_then(Value::as_array).is_some());
    let mut decoded = Vec::new();
    decode_published_evidence(
        4,
        Cursor::new(encoded),
        &mut decoded,
        PublishedEvidenceLimits::new(1_000_000, 100_000),
    )?;
    assert_eq!(decoded, expected);
    Ok(())
}

#[test]
fn compact_details_roundtrip_empty_and_non_object_json_values() -> TestResult {
    let mut case = Case::new();
    for details in [
        json!({}),
        json!(null),
        json!([0, [1, 2]]),
        json!("shared"),
        json!(false),
    ] {
        case.add_node("candidate", None, Vec::new(), details)?;
    }
    let scope = json!({});
    let (_, expected) = canonical(&case, &scope, 1)?;
    let mut encoded = Vec::new();
    write_published_case(&case, &scope, 1, &mut encoded)?;
    let mut decoded = Vec::new();
    decode_published_evidence(
        4,
        Cursor::new(encoded),
        &mut decoded,
        PublishedEvidenceLimits::new(1_000_000, 100_000),
    )?;
    assert_eq!(decoded, expected);
    Ok(())
}

#[test]
fn repeated_receipt_object_shapes_are_shared_and_roundtrip_exactly() -> TestResult {
    let rows = (0..300)
        .map(|index| {
            json!({
                "source_index": index,
                "input_range": {"start": index, "end": index + 1},
                "candidate_description": "one repeated field layout",
            })
        })
        .collect::<Vec<_>>();
    let payload = serde_json::to_vec(&json!({"assembly":{"groups":rows},"inputs":[{}, {}, null]}))?;
    let mut case = Case::new();
    case.add_bytes_node(
        "record_parse_receipt",
        &payload,
        Vec::new(),
        json!({"representation":"json_blob"}),
    )?;
    let scope = json!({});
    let (_, expected) = canonical(&case, &scope, 1)?;
    let mut encoded = Vec::new();
    write_published_case(&case, &scope, 1, &mut encoded)?;
    assert!(std::str::from_utf8(&encoded)?.contains("\"schema_payload\""));
    let mut decoded = Vec::new();
    decode_published_evidence(
        4,
        Cursor::new(encoded),
        &mut decoded,
        PublishedEvidenceLimits::new(1_000_000, 500_000),
    )?;
    assert_eq!(decoded, expected);
    Ok(())
}

#[test]
fn schema_receipts_keep_duplicate_keys_empty_objects_and_scalar_roots() -> TestResult {
    for payload in [
        r#"{"z":1,"a":[{},{},{"z":1,"a":2,"z":3}],"z":4}"#,
        r#"{"a":1,"\u0061":2,"quote\"}x":[{"inner":"escaped\\value"}],"sp ace":{"\n":"brace } string"}}"#,
        "null",
        r#""escaped\ntext""#,
        "[[],{},[null,false,2.5]]",
    ] {
        let mut case = Case::new();
        case.add_bytes_node(
            "record_parse_receipt",
            payload.as_bytes(),
            Vec::new(),
            json!({"representation":"json_blob"}),
        )?;
        let (_, expected) = canonical(&case, &json!({}), 1)?;
        let mut encoded = Vec::new();
        write_published_case(&case, &json!({}), 1, &mut encoded)?;
        let mut decoded = Vec::new();
        decode_published_evidence(
            4,
            Cursor::new(encoded),
            &mut decoded,
            PublishedEvidenceLimits::new(1_000_000, 100_000),
        )?;
        assert_eq!(decoded, expected, "receipt {payload}");
    }
    Ok(())
}

#[test]
fn deeply_nested_receipt_uses_inline_payload_and_roundtrips() -> TestResult {
    let payload = format!("{}0{}", "[".repeat(80), "]".repeat(80));
    let mut case = Case::new();
    case.add_bytes_node(
        "record_parse_receipt",
        payload.as_bytes(),
        Vec::new(),
        json!({"representation":"json_blob"}),
    )?;
    let (_, expected) = canonical(&case, &json!({}), 1)?;
    let mut encoded = Vec::new();
    write_published_case(&case, &json!({}), 1, &mut encoded)?;
    assert!(!std::str::from_utf8(&encoded)?.contains("\"schema_payload\""));
    let mut decoded = Vec::new();
    decode_published_evidence(
        4,
        Cursor::new(encoded),
        &mut decoded,
        PublishedEvidenceLimits::new(1_000_000, 100_000),
    )?;
    assert_eq!(decoded, expected);
    Ok(())
}

#[test]
fn schema_depth_boundary_and_quoted_brackets_are_handled_correctly() -> TestResult {
    for (depth, uses_schema) in [(56_usize, true), (57, false)] {
        let payload = format!(
            "{}\"[{{\\\"quoted\\\"}}]\"{}",
            "[".repeat(depth),
            "]".repeat(depth)
        );
        let mut case = Case::new();
        case.add_bytes_node(
            "record_parse_receipt",
            payload.as_bytes(),
            Vec::new(),
            json!({"representation":"json_blob"}),
        )?;
        let (_, expected) = canonical(&case, &json!({}), 1)?;
        let mut encoded = Vec::new();
        write_published_case(&case, &json!({}), 1, &mut encoded)?;
        assert_eq!(
            std::str::from_utf8(&encoded)?.contains("\"schema_payload\""),
            uses_schema
        );
        let mut decoded = Vec::new();
        decode_published_evidence(
            4,
            Cursor::new(encoded),
            &mut decoded,
            PublishedEvidenceLimits::new(1_000_000, 100_000),
        )?;
        assert_eq!(decoded, expected);
    }
    Ok(())
}

#[test]
fn receipt_shapes_beyond_the_dictionary_cap_remain_inline_and_roundtrip() -> TestResult {
    let rows = (0..1_100)
        .map(|index| json!({(format!("field_{index}")):index}))
        .collect::<Vec<_>>();
    let payload = serde_json::to_vec(&json!({"rows":rows}))?;
    let mut case = Case::new();
    case.add_bytes_node(
        "record_parse_receipt",
        &payload,
        Vec::new(),
        json!({"representation":"json_blob"}),
    )?;
    let (_, expected) = canonical(&case, &json!({}), 1)?;
    let mut encoded = Vec::new();
    write_published_case(&case, &json!({}), 1, &mut encoded)?;
    assert!(
        std::str::from_utf8(&encoded)?.contains("[2,"),
        "extra shapes should use inline keys"
    );
    let mut decoded = Vec::new();
    decode_published_evidence(
        4,
        Cursor::new(encoded),
        &mut decoded,
        PublishedEvidenceLimits::new(1_000_000, 500_000),
    )?;
    assert_eq!(decoded, expected);
    Ok(())
}

#[test]
fn decoder_rejects_missing_receipt_schema_and_field_values() -> TestResult {
    let mut case = Case::new();
    case.add_bytes_node(
        "record_parse_receipt",
        br#"{"rows":[{"x":1}]}"#,
        Vec::new(),
        json!({"representation":"json_blob"}),
    )?;
    let mut encoded = Vec::new();
    write_published_case(&case, &json!({}), 1, &mut encoded)?;
    for (description, root) in [
        ("missing schema reference", json!([1, 999_999, []])),
        ("missing field values", json!([1, 0, []])),
    ] {
        let invalid = replace_record_value(&encoded, "blob", "/value/schema_payload/root", root)?;
        assert!(
            decode_published_evidence(
                4,
                Cursor::new(invalid),
                Vec::new(),
                PublishedEvidenceLimits::new(1_000_000, 100_000)
            )
            .is_err(),
            "{description}"
        );
    }
    Ok(())
}

#[test]
fn normalized_records_share_repeated_relations_and_reasons() -> TestResult {
    let mut case = fixture()?;
    let repeated = "the repeated explanation describes this exact relationship";
    for _ in 0..100 {
        case.add_edge(Edge {
            from: 1,
            to: 2,
            relation: "derived_from".into(),
            status: EvidenceStatus::Observed,
            reason: repeated.into(),
        })?;
    }
    let mut normalized = Vec::new();
    write_published_case(&case, &json!({}), 1, &mut normalized)?;
    assert_eq!(
        normalized
            .windows(repeated.len())
            .filter(|item| *item == repeated.as_bytes())
            .count(),
        1
    );
    Ok(())
}

#[test]
fn normalized_nodes_share_repeated_description_strings_without_losing_values() -> TestResult {
    let mut case = Case::new();
    let description = "the same source-backed candidate description";
    for index in 0..100 {
        case.add_node(
            "candidate",
            None,
            Vec::new(),
            json!({
                "description": description,
                "index": index,
                "nested": ["retained", index],
                "optional": null,
            }),
        )?;
    }
    let scope = json!({"kind":"test"});
    let (_, expected) = canonical(&case, &scope, 1)?;
    let mut normalized = Vec::new();
    write_published_case(&case, &scope, 1, &mut normalized)?;
    assert_eq!(
        normalized
            .windows(description.len())
            .filter(|item| *item == description.as_bytes())
            .count(),
        1
    );
    let mut decoded = Vec::new();
    decode_published_evidence(
        4,
        Cursor::new(normalized),
        &mut decoded,
        PublishedEvidenceLimits::new(1_000_000, 100_000),
    )?;
    assert_eq!(decoded, expected);
    Ok(())
}

#[test]
fn noncanonical_receipt_json_keeps_the_canonical_v2_identity_and_payload() -> TestResult {
    let mut case = Case::new();
    case.add_bytes_node(
        "receipt",
        br#" { "z": 1, "a": [null, "\u0061", 1.0], "z": 2 } "#,
        Vec::new(),
        json!({"representation":"json_blob"}),
    )?;
    let scope = json!({});
    let (case_id, expected) = canonical(&case, &scope, 1)?;
    let mut normalized = Vec::new();
    let usage = write_published_case(&case, &scope, 1, &mut normalized)?;
    let mut decoded = Vec::new();
    decode_published_evidence(
        4,
        Cursor::new(normalized),
        &mut decoded,
        PublishedEvidenceLimits::new(1_000_000, 100_000),
    )?;
    assert_eq!(usage.case_id, case_id);
    assert_eq!(decoded, expected);
    Ok(())
}

#[test]
fn nested_receipt_scalars_and_duplicate_keys_match_legacy_canonical_json() -> TestResult {
    for payload in [
        "null",
        "true",
        "-0.0",
        r#""\u0061\n""#,
        r#"{"z":{"z":1,"a":2},"a":{"x":null,"x":false},"c":[{"q":1},[1e+02,-0.0,0.00],"\u0061",false,null]}"#,
    ] {
        let mut case = Case::new();
        case.add_bytes_node(
            "receipt",
            payload.as_bytes(),
            Vec::new(),
            json!({"representation":"json_blob"}),
        )?;
        let scope = json!({});
        let (_, expected) = canonical(&case, &scope, 1)?;
        let mut normalized = Vec::new();
        write_published_case(&case, &scope, 1, &mut normalized)?;
        let mut decoded = Vec::new();
        decode_published_evidence(
            4,
            Cursor::new(normalized),
            &mut decoded,
            PublishedEvidenceLimits::new(1_000_000, 100_000),
        )?;
        assert_eq!(decoded, expected, "payload {payload}");
    }
    Ok(())
}

#[test]
fn decoder_rejects_reordered_case_ordinals() -> TestResult {
    let case = fixture()?;
    let mut encoded = Vec::new();
    write_published_case(&case, &json!({}), 2, &mut encoded)?;
    write_published_case(&case, &json!({}), 1, &mut encoded)?;
    assert!(
        decode_published_evidence(
            4,
            Cursor::new(encoded),
            Vec::new(),
            PublishedEvidenceLimits::new(1_000_000, 100_000)
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn decoder_rejects_a_forged_case_with_an_invalid_source_id() -> TestResult {
    let case = fixture()?;
    let source_id = &case
        .sources()
        .first()
        .ok_or("fixture source is missing")?
        .id;
    let (_, canonical) = canonical(&case, &json!({}), 1)?;
    let mut canonical = String::from_utf8(canonical)?
        .replace(source_id, "bad-source-id")
        .into_bytes();
    let mut encoded = Vec::new();
    write_published_case(&case, &json!({}), 1, &mut encoded)?;
    let mut records = std::str::from_utf8(&encoded)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    let source = records
        .iter_mut()
        .find(|record| record.get("record") == Some(&json!("source")))
        .ok_or("source is missing")?;
    *source
        .pointer_mut("/value/id")
        .ok_or("source ID is missing")? = json!("bad-source-id");
    let limits = PublishedEvidenceLimits::new(1_000_000, 100_000);
    let id_bytes = canonical.get_mut(12..81).ok_or("canonical ID is missing")?;
    id_bytes.copy_from_slice(format!("case-{}", "0".repeat(64)).as_bytes());
    let mut digest = Sha256::new();
    digest.update(b"l2solver-export-case-v2\0");
    digest.update(1_u64.to_be_bytes());
    digest.update(canonical);
    let id = format!("case-{:x}", digest.finalize());
    let header = records.first_mut().ok_or("header is missing")?;
    *header
        .pointer_mut("/value/case_id")
        .ok_or("header ID is missing")? = json!(id);
    let mut forged = Vec::new();
    for record in records {
        serde_json::to_writer(&mut forged, &record)?;
        forged.push(b'\n');
    }
    assert!(decode_published_evidence(4, Cursor::new(forged), Vec::new(), limits).is_err());
    Ok(())
}

#[test]
fn decoder_rejects_dangling_references_truncation_and_limits() -> TestResult {
    let mut encoded = Vec::new();
    write_published_case(&fixture()?, &json!({}), 1, &mut encoded)?;
    let invalid = replace_record_value(&encoded, "edge", "/value/2", json!(999_999))?;
    let limits = PublishedEvidenceLimits::new(64 * 1024 * 1024, 16 * 1024 * 1024);
    assert!(decode_published_evidence(4, Cursor::new(invalid), Vec::new(), limits).is_err());
    assert!(
        decode_published_evidence(
            4,
            Cursor::new(
                encoded
                    .get(..encoded.len().saturating_sub(1))
                    .ok_or("missing final byte")?
            ),
            Vec::new(),
            limits
        )
        .is_err()
    );
    assert!(
        decode_published_evidence(
            4,
            Cursor::new(&encoded),
            Vec::new(),
            PublishedEvidenceLimits::new(32, 32)
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn decoder_rejects_a_source_range_with_a_missing_source_reference() -> TestResult {
    let mut encoded = Vec::new();
    write_published_case(&fixture()?, &json!({}), 1, &mut encoded)?;
    let invalid = replace_record_value(&encoded, "node", "/value/3/0/0", json!(999_999))?;
    assert!(
        decode_published_evidence(
            4,
            Cursor::new(invalid),
            Vec::new(),
            PublishedEvidenceLimits::new(1_000_000, 100_000)
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn decoder_stops_reading_when_the_stream_limit_is_reached() -> TestResult {
    let mut encoded = Vec::new();
    write_published_case(&fixture()?, &json!({}), 1, &mut encoded)?;
    let mut input = Cursor::new(encoded);
    assert!(
        decode_published_evidence(
            4,
            &mut input,
            Vec::new(),
            PublishedEvidenceLimits::new(32, 16 * 1024 * 1024),
        )
        .is_err()
    );
    assert!(
        input.position() <= 33,
        "the reader must reject the stream before buffering a larger record"
    );
    Ok(())
}

#[test]
fn legacy_version_two_records_remain_stream_readable() -> TestResult {
    let scope = json!({"kind":"flow","flow_id":7});
    let (_, legacy) = canonical(&fixture()?, &scope, 1)?;
    let mut decoded = Vec::new();
    decode_published_evidence(
        2,
        Cursor::new(&legacy),
        &mut decoded,
        PublishedEvidenceLimits::new(64 * 1024 * 1024, 16 * 1024 * 1024),
    )?;
    assert_eq!(decoded, legacy);
    Ok(())
}

#[test]
fn publication_scratch_uses_shared_lease_and_reports_pressure() -> TestResult {
    use l2_workbench::job::{MemoryBudget, MemoryClass, MemoryError};
    let case = fixture()?;
    let tight = MemoryBudget::new(1);
    let error = l2_workbench::evidence::write_published_case(
        &case,
        &json!({}),
        1,
        Vec::new(),
        Some(&tight),
    )
    .err()
    .ok_or("a too-small shared budget unexpectedly admitted publication")?;
    assert!(
        error
            .get_ref()
            .is_some_and(|cause| cause.downcast_ref::<MemoryError>().is_some())
    );
    assert_eq!(tight.snapshot()?.used(MemoryClass::Publication), 0);

    let budget = MemoryBudget::new(8 * 1024 * 1024);
    let mut encoded = Vec::new();
    l2_workbench::evidence::write_published_case(
        &case,
        &json!({}),
        1,
        &mut encoded,
        Some(&budget),
    )?;
    let usage = budget.snapshot()?;
    assert!(
        usage.peak_bytes > 0,
        "publication scratch must be charged while it is live"
    );
    assert_eq!(
        usage.used(MemoryClass::Publication),
        0,
        "all scratch leases must be released"
    );
    Ok(())
}

#[test]
fn dictionary_pressure_reports_typed_failure_and_admission_keeps_wire_bytes_stable() -> TestResult {
    use l2_workbench::job::{MemoryBudget, MemoryClass, MemoryError};
    let mut case = Case::new();
    let node = case.add_node("candidate", None, Vec::new(), json!({}))?;
    for index in 0..80 {
        case.add_edge(Edge {
            from: node,
            to: node,
            relation: "supports".into(),
            status: EvidenceStatus::Observed,
            reason: format!("distinct finding {index}"),
        })?;
    }
    let scope = json!({"kind":"test"});
    let budget = MemoryBudget::new(2_048);
    let mut interrupted = Vec::new();
    let error = l2_workbench::evidence::write_published_case(
        &case,
        &scope,
        1,
        &mut interrupted,
        Some(&budget),
    )
    .err()
    .ok_or("dictionary pressure unexpectedly completed a Case")?;
    assert!(
        error
            .get_ref()
            .is_some_and(|cause| cause.downcast_ref::<MemoryError>().is_some())
    );
    assert!(interrupted.is_empty());
    assert!(budget.snapshot()?.rejected > 0);
    assert_eq!(budget.snapshot()?.used(MemoryClass::Publication), 0);
    let mut unrestricted = Vec::new();
    write_published_case(&case, &scope, 1, &mut unrestricted)?;
    let mut admitted = Vec::new();
    let sufficient = MemoryBudget::new(1_000_000);
    l2_workbench::evidence::write_published_case(
        &case,
        &scope,
        1,
        &mut admitted,
        Some(&sufficient),
    )?;
    assert_eq!(admitted, unrestricted);
    Ok(())
}

#[test]
fn schema_pressure_reports_typed_failure_and_admission_keeps_wire_bytes_stable() -> TestResult {
    use l2_workbench::job::{MemoryBudget, MemoryClass, MemoryError};
    let rows = (0..80)
        .map(|index| json!({(format!("field_{index}")):index}))
        .collect::<Vec<_>>();
    let payload = serde_json::to_vec(&json!({"rows":rows}))?;
    let mut case = Case::new();
    case.add_bytes_node(
        "record_parse_receipt",
        &payload,
        Vec::new(),
        json!({"representation":"json_blob"}),
    )?;
    let scope = json!({});
    let budget = MemoryBudget::new(12_000);
    let mut interrupted = Vec::new();
    let error = l2_workbench::evidence::write_published_case(
        &case,
        &scope,
        1,
        &mut interrupted,
        Some(&budget),
    )
    .err()
    .ok_or("schema pressure unexpectedly completed a Case")?;
    assert!(
        error
            .get_ref()
            .is_some_and(|cause| cause.downcast_ref::<MemoryError>().is_some())
    );
    assert!(!interrupted.ends_with(b"{\"record\":\"end\"}\n"));
    assert!(budget.snapshot()?.rejected > 0);
    assert_eq!(budget.snapshot()?.used(MemoryClass::Publication), 0);
    let mut unrestricted = Vec::new();
    write_published_case(&case, &scope, 1, &mut unrestricted)?;
    let mut admitted = Vec::new();
    let sufficient = MemoryBudget::new(1_000_000);
    l2_workbench::evidence::write_published_case(
        &case,
        &scope,
        1,
        &mut admitted,
        Some(&sufficient),
    )?;
    assert_eq!(admitted, unrestricted);
    Ok(())
}
