use super::service::{self, RecordServiceInput};
use l2_workbench::{
    evidence::{Case, Node},
    protocol::{RecordLimits, RecordSchema},
};
use serde_json::Value;
use std::error::Error;

const fn schema_bytes() -> &'static [u8] {
    br#"{
        "records_offset":1,
        "count":{"kind":"field","field":{"offset":0,"width":1,"byte_order":"big_endian"}},
        "identifier":{"offset":0,"width":2},
        "sequence":{"offset":2,"width":2,"byte_order":"big_endian"},
        "length":{"offset":4,"width":2,"byte_order":"big_endian"},
        "data_offset":6,
        "length_meaning":"payload_bytes",
        "sequence_base":0,
        "terminal_sequence":4
    }"#
}

fn add_record(bytes: &mut Vec<u8>, sequence: u16) {
    bytes.extend_from_slice(b"A1");
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.push(b'x');
}

fn find_node(case: &Case, id: u64) -> Result<&Node, Box<dyn Error>> {
    case.nodes()
        .iter()
        .find(|node| node.id == id)
        .ok_or_else(|| format!("missing node {id}").into())
}

fn make_input_case(sequences: &[u16]) -> Result<(Case, u64), Box<dyn Error>> {
    let mut bytes = vec![u8::try_from(sequences.len())?];
    for sequence in sequences {
        add_record(&mut bytes, *sequence);
    }
    let mut case = Case::new();
    let input = case.add_bytes_node("record_part", &bytes, Vec::new(), serde_json::json!({}))?;
    Ok((case, input))
}

#[test]
fn service_returns_typed_outcome() -> Result<(), Box<dyn Error>> {
    let (mut case, input) = make_input_case(&[0, 2, 4])?;
    let schema: RecordSchema = serde_json::from_slice(schema_bytes())?;
    let outcome = service::apply(
        &mut case,
        &RecordServiceInput {
            selected_node_ids: &[input],
            count_sources: None,
            schema: &schema,
            limits: RecordLimits {
                max_issue_examples: 1,
                ..RecordLimits::default()
            },
        },
    )?;

    assert!(!outcome.groups_complete);
    assert_eq!(outcome.group_node_ids.len(), 1);
    assert_eq!(outcome.issue_node_ids.len(), 1);
    assert_eq!(outcome.omissions.missing_sequences, 1);
    assert_eq!(
        find_node(&case, outcome.receipt_node_id)?.kind,
        "record_parse_receipt"
    );
    let receipt_node = find_node(&case, outcome.receipt_node_id)?;
    let receipt_blob_id = receipt_node
        .blob
        .as_deref()
        .ok_or("record receipt blob is missing")?;
    let receipt_bytes = case
        .blobs()
        .iter()
        .find(|blob| blob.id == receipt_blob_id)
        .map(|blob| blob.bytes.as_slice())
        .ok_or("record receipt bytes are missing")?;
    let receipt: Value = serde_json::from_slice(receipt_bytes)?;
    assert!(receipt.pointer("/parse").is_some());
    assert!(receipt.pointer("/inputs/0/parse").is_none());
    let group_node_id = outcome
        .group_node_ids
        .first()
        .copied()
        .ok_or("record group node is missing")?;
    let issue_node_id = outcome
        .issue_node_ids
        .first()
        .copied()
        .ok_or("record group issue node is missing")?;
    assert_eq!(find_node(&case, group_node_id)?.kind, "record_candidate");
    assert_eq!(find_node(&case, issue_node_id)?.kind, "record_group_issue");
    Ok(())
}

#[test]
fn service_failure_is_atomic() -> Result<(), Box<dyn Error>> {
    let input_bytes = [1, b'A', b'1', 0, 0, 0, 1, b'x'];
    let mut case = Case::with_blob_limit(input_bytes.len())?;
    let input = case.add_bytes_node(
        "record_part",
        &input_bytes,
        Vec::new(),
        serde_json::json!({}),
    )?;
    let original = case.clone();
    let mut schema_value: serde_json::Value = serde_json::from_slice(schema_bytes())?;
    schema_value
        .as_object_mut()
        .ok_or("schema fixture is not an object")?
        .insert("terminal_sequence".to_owned(), serde_json::json!(0));
    let schema: RecordSchema = serde_json::from_value(schema_value)?;

    assert!(
        service::apply(
            &mut case,
            &RecordServiceInput {
                selected_node_ids: &[input],
                count_sources: None,
                schema: &schema,
                limits: RecordLimits::default(),
            },
        )
        .is_err()
    );
    assert_eq!(case, original);
    Ok(())
}
