use super::{find_node, schema_bytes};
use crate::workbench::records::service::{self, RecordServiceInput};
use l2_workbench::{
    evidence::{
        Case, EvidenceStatus, PublishedEvidenceLimits, decode_published_evidence,
        write_published_case,
    },
    protocol::{RecordLimits, RecordSchema},
};
use serde_json::{Value, json};
use std::{error::Error, io::Cursor};

type TestResult<T> = Result<T, Box<dyn Error>>;

fn append_record(bytes: &mut Vec<u8>, identifier: [u8; 2], sequence: u16, payload: u8) {
    bytes.extend_from_slice(&identifier);
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.push(payload);
}

fn fixture() -> TestResult<(Case, [u64; 3], RecordSchema)> {
    let mut first = vec![2];
    append_record(&mut first, *b"A1", 0, b'a');
    append_record(&mut first, *b"B1", 4, b'b');
    let mut second = vec![2];
    append_record(&mut second, *b"A1", 2, b'c');
    append_record(&mut second, *b"A1", 2, b'd');
    let truncated = [1, b'A', b'1', 0, 0, 0, 3, b'x'];

    let mut case = Case::new();
    let inputs = [
        case.add_bytes_node("record_part", &first, Vec::new(), json!({}))?,
        case.add_bytes_node("record_part", &second, Vec::new(), json!({}))?,
        case.add_bytes_node("record_part", &truncated, Vec::new(), json!({}))?,
    ];
    Ok((case, inputs, serde_json::from_slice(schema_bytes())?))
}

fn receipt(case: &Case, node_id: u64) -> TestResult<Value> {
    let blob_id = find_node(case, node_id)?
        .blob
        .as_deref()
        .ok_or("record receipt has no blob")?;
    let blob = case.blob(blob_id).ok_or("record receipt blob is missing")?;
    Ok(serde_json::from_slice(&blob.bytes)?)
}

#[test]
fn discovered_groups_keep_exact_contradictions_and_inputs_in_one_receipt() -> TestResult<()> {
    let (mut case, inputs, schema) = fixture()?;
    let [first_input, second_input, rejected_input] = inputs;
    let prepared = service::prepare_recovery(
        &case,
        &RecordServiceInput {
            selected_node_ids: &inputs,
            count_sources: None,
            schema: &schema,
            limits: RecordLimits::default(),
        },
    )?;
    let outcome =
        service::commit_recovery(&mut case, prepared, service::RecordGroupIssues::Receipt)?;
    let receipt_node = find_node(&case, outcome.outcome.receipt_node_id)?;
    assert_eq!(
        receipt_node.details.get("group_issue_representation"),
        Some(&json!("parse_receipt"))
    );
    assert_eq!(
        receipt_node.details.get("incomplete_group_count"),
        Some(&json!(2))
    );
    assert!(outcome.outcome.issue_node_ids.is_empty());
    assert_eq!(outcome.rejected_inputs.len(), 1);
    assert_eq!(
        outcome
            .rejected_inputs
            .first()
            .map(|item| item.input_node_id),
        Some(rejected_input)
    );
    assert_eq!(outcome.outcome.group_node_ids.len(), 2);
    assert!(!outcome.outcome.groups_complete);

    let parsed = receipt(&case, receipt_node.id)?;
    assert_diagnostics(&parsed, inputs);
    let candidate_id = *outcome
        .outcome
        .group_node_ids
        .first()
        .ok_or("candidate group is missing")?;
    assert_candidate(&case, candidate_id, [first_input, second_input])?;
    assert_published_receipt(&case, receipt_node.id, &parsed)?;
    Ok(())
}

fn assert_diagnostics(parsed: &Value, inputs: [u64; 3]) {
    let [first_input, second_input, rejected_input] = inputs;
    assert_eq!(parsed.get("assembly_input_indexes"), Some(&json!([0, 1])));
    assert_eq!(
        parsed.pointer("/inputs/0/input_node"),
        Some(&json!(first_input))
    );
    assert_eq!(
        parsed.pointer("/inputs/1/input_node"),
        Some(&json!(second_input))
    );
    assert_eq!(
        parsed.pointer("/inputs/2/input_node"),
        Some(&json!(rejected_input))
    );
    assert!(
        parsed
            .pointer("/inputs/2/parse_error")
            .and_then(Value::as_str)
            .is_some()
    );
    assert_eq!(
        parsed.pointer("/assembly/terminal_sequence"),
        Some(&json!(4))
    );
    assert_eq!(
        parsed.pointer("/assembly/groups/0/identifier"),
        Some(&json!([65, 49]))
    );
    assert_eq!(
        parsed.pointer("/assembly/groups/0/missing_sequences"),
        Some(&json!([1, 3, 4]))
    );
    assert_eq!(
        parsed.pointer("/assembly/groups/0/missing_sequence_count"),
        Some(&json!(3))
    );
    assert_eq!(
        parsed.pointer("/assembly/groups/0/duplicate_sequences"),
        Some(&json!([2]))
    );
    assert_eq!(
        parsed.pointer("/assembly/groups/0/parts/0/input_index"),
        Some(&json!(0))
    );
    assert_eq!(
        parsed.pointer("/assembly/groups/0/parts/1/input_index"),
        Some(&json!(1))
    );
    assert_eq!(
        parsed.pointer("/assembly/groups/1/identifier"),
        Some(&json!([66, 49]))
    );
    assert_eq!(
        parsed.pointer("/assembly/groups/1/missing_sequences"),
        Some(&json!([0, 1, 2, 3]))
    );
}

fn assert_candidate(case: &Case, candidate_id: u64, inputs: [u64; 2]) -> TestResult<()> {
    // Candidate payloads and their exact source links remain available to later tasks
    let candidate = find_node(case, candidate_id)?;
    assert_eq!(candidate.kind, "record_candidate");
    let candidate_blob = case
        .blob(
            candidate
                .blob
                .as_deref()
                .ok_or("candidate blob is missing")?,
        )
        .ok_or("candidate bytes are missing")?;
    assert_eq!(candidate_blob.bytes, b"acd");
    for input in inputs {
        assert!(case.edges().iter().any(|edge| {
            edge.from == input
                && edge.to == candidate.id
                && edge.relation == "candidate_from"
                && edge.status == EvidenceStatus::Observed
        }));
    }
    assert!(
        !case
            .nodes()
            .iter()
            .any(|node| node.kind == "record_group_issue")
    );
    Ok(())
}

fn assert_published_receipt(case: &Case, node_id: u64, parsed: &Value) -> TestResult<()> {
    // The published reader must recover the complete diagnostic payload
    let mut encoded = Vec::new();
    write_published_case(case, &json!({"kind":"test"}), 1, &mut encoded, None)?;
    let mut decoded = Vec::new();
    decode_published_evidence(
        l2_workbench::evidence::PUBLISHED_EVIDENCE_ENCODING_VERSION,
        Cursor::new(&encoded),
        &mut decoded,
        PublishedEvidenceLimits::new(1_000_000, 100_000),
    )?;
    let published: Value = serde_json::from_slice(&decoded)?;
    let receipt_blob_id = find_node(case, node_id)?
        .blob
        .as_deref()
        .ok_or("record receipt has no blob")?;
    let published_blob = published
        .get("blobs")
        .and_then(Value::as_array)
        .and_then(|blobs| {
            blobs
                .iter()
                .find(|blob| blob.get("id").and_then(Value::as_str) == Some(receipt_blob_id))
        })
        .ok_or("published receipt blob is missing")?;
    assert_eq!(published_blob.get("inline_payload"), Some(parsed));
    assert!(
        decode_published_evidence(
            l2_workbench::evidence::PUBLISHED_EVIDENCE_ENCODING_VERSION,
            Cursor::new(&encoded),
            Vec::new(),
            PublishedEvidenceLimits::new(1_000_000, 32),
        )
        .is_err()
    );
    let mut corrupted = encoded.clone();
    let marker = b"\"parse_receipt\"";
    let marker_start = corrupted
        .windows(marker.len())
        .position(|window| window == marker)
        .ok_or("receipt representation marker is missing")?;
    *corrupted
        .get_mut(marker_start + 1)
        .ok_or("receipt representation marker is truncated")? = b'P';
    assert!(
        decode_published_evidence(
            l2_workbench::evidence::PUBLISHED_EVIDENCE_ENCODING_VERSION,
            Cursor::new(&corrupted),
            Vec::new(),
            PublishedEvidenceLimits::new(1_000_000, 100_000),
        )
        .is_err(),
        "a changed receipt representation must fail the Case identity check"
    );
    Ok(())
}

#[test]
fn discovered_complete_objects_keep_their_exact_bytes_and_group_links() -> TestResult<()> {
    let mut bytes = vec![6];
    for sequence in 0_u16..=4 {
        append_record(&mut bytes, *b"A1", sequence, b'a' + u8::try_from(sequence)?);
    }
    append_record(&mut bytes, *b"B1", 4, b'z');
    let mut case = Case::new();
    let source = case.add_bytes_node("record_part", &bytes, Vec::new(), json!({}))?;
    let schema: RecordSchema = serde_json::from_slice(schema_bytes())?;
    let prepared = service::prepare_recovery(
        &case,
        &RecordServiceInput {
            selected_node_ids: &[source],
            count_sources: None,
            schema: &schema,
            limits: RecordLimits::default(),
        },
    )?;
    let outcome =
        service::commit_recovery(&mut case, prepared, service::RecordGroupIssues::Receipt)?;
    let receipt_node = find_node(&case, outcome.outcome.receipt_node_id)?;
    assert_eq!(
        receipt_node.details.get("incomplete_group_count"),
        Some(&json!(1))
    );
    assert_eq!(outcome.outcome.group_node_ids.len(), 2);
    assert!(outcome.outcome.issue_node_ids.is_empty());
    let object = outcome
        .outcome
        .group_node_ids
        .iter()
        .find_map(|id| case.node(*id).filter(|node| node.kind == "record_object"))
        .ok_or("complete record object is missing")?;
    let object_bytes = case
        .blob(object.blob.as_deref().ok_or("record object has no blob")?)
        .ok_or("record object bytes are missing")?;
    assert_eq!(object_bytes.bytes, b"abcde");
    assert!(case.edges().iter().any(|edge| {
        edge.from == source && edge.to == object.id && edge.relation == "assembled_from"
    }));
    assert!(case.edges().iter().any(|edge| {
        edge.from == receipt_node.id && edge.to == object.id && edge.relation == "produced"
    }));
    let parsed = receipt(&case, receipt_node.id)?;
    assert_eq!(
        parsed.pointer("/assembly/groups/0/complete"),
        Some(&json!(true))
    );
    assert_eq!(
        parsed.pointer("/assembly/groups/1/complete"),
        Some(&json!(false))
    );
    Ok(())
}

#[test]
fn caller_supplied_record_schemas_keep_individual_issue_nodes() -> TestResult<()> {
    let (mut case, inputs, schema) = fixture()?;
    let prepared = service::prepare_recovery(
        &case,
        &RecordServiceInput {
            selected_node_ids: &inputs,
            count_sources: None,
            schema: &schema,
            limits: RecordLimits::default(),
        },
    )?;
    let outcome =
        service::commit_recovery(&mut case, prepared, service::RecordGroupIssues::Individual)?;
    assert_eq!(outcome.outcome.issue_node_ids.len(), 2);
    assert!(
        find_node(&case, outcome.outcome.receipt_node_id)?
            .details
            .get("group_issue_representation")
            .is_none()
    );
    assert!(outcome.outcome.issue_node_ids.iter().all(|id| {
        case.node(*id)
            .is_some_and(|node| node.kind == "record_group_issue")
    }));
    Ok(())
}
