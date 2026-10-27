use l2_workbench::evidence::{
    Case, Edge, EvidenceStatus, PublishedEvidenceLimits, SourceRange, decode_published_evidence,
    write_published_case,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{error::Error, io::Cursor};

type TestResult = Result<(), Box<dyn Error>>;

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

#[test]
fn normalized_roundtrip_preserves_canonical_bytes_and_case_identity() -> TestResult {
    let case = fixture()?;
    let scope = json!({"kind":"flow","flow_id":7});
    let (expected_id, expected) = canonical(&case, &scope, 2)?;
    let mut normalized = Vec::new();
    let usage = write_published_case(&case, &scope, 2, &mut normalized)?;
    let mut decoded = Vec::new();
    decode_published_evidence(
        3,
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
        3,
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
        3,
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
            3,
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
            3,
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
    assert!(decode_published_evidence(3, Cursor::new(forged), Vec::new(), limits).is_err());
    Ok(())
}

#[test]
fn decoder_rejects_dangling_references_truncation_and_limits() -> TestResult {
    let mut encoded = Vec::new();
    write_published_case(&fixture()?, &json!({}), 1, &mut encoded)?;
    let mut records = std::str::from_utf8(&encoded)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    let edge = records
        .iter_mut()
        .find(|record| record["record"] == "edge")
        .ok_or("edge missing")?;
    *edge
        .get_mut("value")
        .and_then(Value::as_array_mut)
        .and_then(|items| items.get_mut(2))
        .ok_or("edge dictionary reference is missing")? = json!(999_999);
    let mut invalid = Vec::new();
    for record in records {
        serde_json::to_writer(&mut invalid, &record)?;
        invalid.push(b'\n');
    }
    let limits = PublishedEvidenceLimits::new(64 * 1024 * 1024, 16 * 1024 * 1024);
    assert!(decode_published_evidence(3, Cursor::new(invalid), Vec::new(), limits).is_err());
    assert!(
        decode_published_evidence(
            3,
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
            3,
            Cursor::new(&encoded),
            Vec::new(),
            PublishedEvidenceLimits::new(32, 32)
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
            3,
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
