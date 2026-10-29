use super::{canonical, replace_record_value, write_published_case};
use l2_workbench::evidence::{Case, PublishedEvidenceLimits, decode_published_evidence};
use serde_json::{Value, json};
use std::io::Cursor;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn shared_frame_case() -> TestResult<Case> {
    let mut case = Case::new();
    let bytes = b"frame bytes shared by both records";
    let digest = l2_workbench::sha256(bytes);
    case.add_bytes_node(
        "custom_protocol_frame",
        bytes,
        Vec::new(),
        json!({"sha256":digest,"digest_alias":digest,"index":0}),
    )?;
    case.add_bytes_node(
        "custom_protocol_frame",
        bytes,
        Vec::new(),
        json!({"sha256":digest,"index":1}),
    )?;
    case.add_node("unbound", None, Vec::new(), json!({"sha256":digest}))?;
    case.add_bytes_node(
        "custom_protocol_frame",
        bytes,
        Vec::new(),
        json!({"sha256":"0".repeat(64)}),
    )?;
    Ok(case)
}

fn encode(case: &Case) -> TestResult<Vec<u8>> {
    let mut encoded = Vec::new();
    write_published_case(case, &json!({"kind":"reference_test"}), 1, &mut encoded)?;
    Ok(encoded)
}

fn records(encoded: &[u8]) -> TestResult<Vec<Value>> {
    Ok(std::str::from_utf8(encoded)?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<Vec<_>, _>>()?)
}

fn field_name<'a>(entry: &'a Value, dictionary: &'a [Value]) -> Option<&'a str> {
    let key = entry.get(0)?;
    match key.as_u64().and_then(|index| usize::try_from(index).ok()) {
        Some(index) => dictionary.get(index)?.as_str(),
        None => key.as_str(),
    }
}

#[test]
fn blob_table_references_and_digest_details_recover_the_canonical_case() -> TestResult<()> {
    let case = shared_frame_case()?;
    let encoded = encode(&case)?;
    let records = records(&encoded)?;
    let header = records.first().ok_or("header is missing")?;
    assert_eq!(header.pointer("/value/version"), Some(&json!(5)));
    let dictionary = header
        .pointer("/value/strings")
        .and_then(Value::as_array)
        .ok_or("dictionary is missing")?;
    for node_id in [1, 2] {
        let node = records
            .iter()
            .find(|record| {
                record.get("record") == Some(&json!("node"))
                    && record.pointer("/value/0") == Some(&json!(node_id))
            })
            .ok_or("frame node is missing")?;
        assert_eq!(node.pointer("/value/2"), Some(&json!(0)));
        let fields = node
            .pointer("/value/4/1")
            .and_then(Value::as_array)
            .ok_or("details are missing")?;
        let digest = fields
            .iter()
            .find(|field| field_name(field, dictionary) == Some("sha256"))
            .ok_or("digest field is missing")?;
        assert_eq!(digest.get(1), Some(&json!(2)));
        assert_eq!(digest.get(2), Some(&Value::Null));
    }
    let (_, expected) = canonical(&case, &json!({"kind":"reference_test"}), 1)?;
    let mut decoded = Vec::new();
    decode_published_evidence(
        5,
        Cursor::new(encoded),
        &mut decoded,
        PublishedEvidenceLimits::new(1_000_000, 100_000),
    )?;
    assert_eq!(
        decoded, expected,
        "references must recover every original node and detail"
    );
    Ok(())
}

#[test]
fn blob_references_reject_invalid_indices_and_missing_digest_sources() -> TestResult<()> {
    let encoded = encode(&shared_frame_case()?)?;
    let limits = PublishedEvidenceLimits::new(1_000_000, 100_000);
    for value in [json!(9999), Value::Null] {
        let invalid = replace_record_value(&encoded, "node", "/value/2", value)?;
        assert!(decode_published_evidence(5, Cursor::new(invalid), Vec::new(), limits).is_err());
    }
    Ok(())
}

#[test]
fn changing_a_valid_blob_index_rejects_the_changed_case_identity() -> TestResult<()> {
    let mut case = shared_frame_case()?;
    case.add_bytes_node("other_frame", b"different bytes", Vec::new(), json!({}))?;
    let encoded = encode(&case)?;
    let changed = replace_record_value(&encoded, "node", "/value/2", json!(1))?;
    let error = decode_published_evidence(
        5,
        Cursor::new(changed),
        Vec::new(),
        PublishedEvidenceLimits::new(1_000_000, 100_000),
    )
    .err()
    .ok_or("changing a blob reference must change the Case identity")?;
    assert!(error.to_string().contains("identity does not match"));
    Ok(())
}

#[test]
fn version_four_rejects_version_five_blob_indices() -> TestResult<()> {
    let encoded = encode(&shared_frame_case()?)?;
    let forged = replace_record_value(&encoded, "header", "/value/version", json!(4))?;
    assert!(
        decode_published_evidence(
            4,
            Cursor::new(forged),
            Vec::new(),
            PublishedEvidenceLimits::new(1_000_000, 100_000),
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn version_five_accepts_inline_blob_ids_without_changing_the_case() -> TestResult<()> {
    let case = shared_frame_case()?;
    let encoded = encode(&case)?;
    let blob_id = case
        .node(1)
        .and_then(|node| node.blob.as_deref())
        .ok_or("frame blob is missing")?;
    let inline = replace_record_value(&encoded, "node", "/value/2", json!(blob_id))?;
    let (_, expected) = canonical(&case, &json!({"kind":"reference_test"}), 1)?;
    let mut decoded = Vec::new();
    decode_published_evidence(
        5,
        Cursor::new(inline),
        &mut decoded,
        PublishedEvidenceLimits::new(1_000_000, 100_000),
    )?;
    assert_eq!(decoded, expected);
    Ok(())
}

#[test]
fn digest_reference_rejects_a_non_null_payload() -> TestResult<()> {
    let encoded = encode(&shared_frame_case()?)?;
    let parsed = records(&encoded)?;
    let header = parsed.first().ok_or("header is missing")?;
    let dictionary = header
        .pointer("/value/strings")
        .and_then(Value::as_array)
        .ok_or("dictionary is missing")?;
    let node = parsed
        .iter()
        .find(|record| record.get("record") == Some(&json!("node")))
        .ok_or("frame node is missing")?;
    let fields = node
        .pointer("/value/4/1")
        .and_then(Value::as_array)
        .ok_or("details are missing")?;
    let index = fields
        .iter()
        .position(|field| field_name(field, dictionary) == Some("sha256"))
        .ok_or("digest field is missing")?;
    let invalid = replace_record_value(
        &encoded,
        "node",
        &format!("/value/4/1/{index}/2"),
        json!("unexpected"),
    )?;
    assert!(
        decode_published_evidence(
            5,
            Cursor::new(invalid),
            Vec::new(),
            PublishedEvidenceLimits::new(1_000_000, 100_000)
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn expanded_digest_references_cannot_exceed_the_node_detail_limit() -> TestResult<()> {
    let encoded = encode(&shared_frame_case()?)?;
    // The encoded references are small, but each expands to a full digest
    let fields: Vec<Value> = (0..80)
        .map(|index| json!([format!("digest_{index}"), 2, null]))
        .collect();
    let oversized = replace_record_value(&encoded, "node", "/value/4/1", json!(fields))?;
    let error = decode_published_evidence(
        5,
        Cursor::new(oversized),
        Vec::new(),
        PublishedEvidenceLimits::new(1_000_000, 100_000),
    )
    .err()
    .ok_or("expanded details must respect the node detail limit")?;
    assert!(error.to_string().contains("node details have"));
    Ok(())
}

#[test]
fn version_four_rejects_version_five_digest_references() -> TestResult<()> {
    let encoded = include_bytes!("fixtures/published-v4.jsonl");
    let parsed = records(encoded)?;
    let header = parsed.first().ok_or("header is missing")?;
    let dictionary = header
        .pointer("/value/strings")
        .and_then(Value::as_array)
        .ok_or("dictionary is missing")?;
    let node = parsed
        .iter()
        .find(|record| record.get("record") == Some(&json!("node")))
        .ok_or("frame node is missing")?;
    let mut fields = node
        .pointer("/value/4/1")
        .and_then(Value::as_array)
        .ok_or("details are missing")?
        .clone();
    let digest = fields
        .iter_mut()
        .find(|field| field_name(field, dictionary) == Some("sha256"))
        .ok_or("digest field is missing")?;
    let key = digest.get(0).cloned().ok_or("digest key is missing")?;
    *digest = json!([key, 2, null]);
    let forged = replace_record_value(encoded, "node", "/value/4/1", json!(fields))?;
    let error = decode_published_evidence(
        4,
        Cursor::new(forged),
        Vec::new(),
        PublishedEvidenceLimits::new(1_000_000, 100_000),
    )
    .err()
    .ok_or("version four must not accept version five digest references")?;
    assert!(
        error
            .to_string()
            .contains("invalid evidence detail field kind")
    );
    Ok(())
}

#[test]
fn previous_version_four_receipts_remain_readable() -> TestResult<()> {
    let mut case = Case::new();
    let frame = b"legacy frame bytes";
    case.add_bytes_node(
        "custom_protocol_frame",
        frame,
        Vec::new(),
        json!({"sha256":l2_workbench::sha256(frame),"frame_index":0}),
    )?;
    case.add_bytes_node(
        "record_parse_receipt",
        br#"{"groups":[{"index":1},{"index":2}]}"#,
        Vec::new(),
        json!({"representation":"json_blob"}),
    )?;
    let (_, expected) = canonical(&case, &json!({"kind":"legacy_v4"}), 1)?;
    let mut decoded = Vec::new();
    decode_published_evidence(
        4,
        Cursor::new(include_bytes!("fixtures/published-v4.jsonl")),
        &mut decoded,
        PublishedEvidenceLimits::new(1_000_000, 100_000),
    )?;
    assert_eq!(decoded, expected);
    Ok(())
}
