use super::support::{path_arg, run, save_case};
use l2_workbench::evidence::{Case, Node};
use serde_json::Value;
use std::{error::Error, fs};

fn push_record(bytes: &mut Vec<u8>, identifier: &[u8], sequence: u16, payload: &[u8]) {
    bytes.extend_from_slice(identifier);
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(
        &u16::try_from(payload.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    bytes.extend_from_slice(payload);
}

const fn schema_json() -> &'static [u8] {
    br#"{
        "records_offset":1,
        "count":{"kind":"field","field":{"offset":0,"width":1,"byte_order":"big_endian"}},
        "identifier":{"offset":0,"width":2},
        "sequence":{"offset":2,"width":2,"byte_order":"big_endian"},
        "length":{"offset":4,"width":2,"byte_order":"big_endian"},
        "data_offset":6,
        "length_meaning":"payload_bytes",
        "sequence_base":0,
        "terminal_sequence":1
    }"#
}

const fn external_count_schema_json() -> &'static [u8] {
    br#"{
        "records_offset":0,
        "count":{"kind":"until_end"},
        "identifier":{"offset":0,"width":2},
        "sequence":{"offset":2,"width":2,"byte_order":"big_endian"},
        "length":{"offset":4,"width":2,"byte_order":"big_endian"},
        "data_offset":6,
        "length_meaning":"payload_bytes",
        "sequence_base":0,
        "terminal_sequence":1
    }"#
}

fn find_node<'a>(case: &'a Case, kind: &str) -> Result<&'a Node, Box<dyn Error>> {
    case.nodes()
        .iter()
        .find(|node| node.kind == kind)
        .ok_or_else(|| format!("missing {kind} node").into())
}

fn node_bytes<'a>(case: &'a Case, node: &Node) -> Result<&'a [u8], Box<dyn Error>> {
    case.blobs()
        .iter()
        .find(|blob| Some(&blob.id) == node.blob.as_ref())
        .map(|blob| blob.bytes.as_slice())
        .ok_or_else(|| format!("missing bytes for {} node", node.kind).into())
}

fn record_receipt(case: &Case) -> Result<(u64, Value), Box<dyn Error>> {
    let receipt = find_node(case, "record_parse_receipt")?;
    Ok((
        receipt.id,
        serde_json::from_slice(node_bytes(case, receipt)?)?,
    ))
}

#[test]
fn record_receipt_input_digest_matches_the_canonical_blob_digest() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let schema = directory.path().join("schema.json");
    fs::write(&schema, schema_json())?;
    let mut bytes = vec![1];
    push_record(&mut bytes, b"D1", 0, b"payload");
    let mut case = Case::new();
    let input = case.add_bytes_node(
        "candidate_stream",
        &bytes,
        Vec::new(),
        serde_json::json!({}),
    )?;
    let expected_digest = case
        .blobs()
        .first()
        .and_then(|blob| blob.id.strip_prefix("sha256:"))
        .ok_or("input blob does not have its canonical SHA-256 identity")?
        .to_owned();

    let output = run(
        &[
            "records",
            "-",
            "--node",
            &input.to_string(),
            "--schema",
            path_arg(&schema)?,
        ],
        &case.to_json()?,
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = Case::from_json(&output.stdout)?;
    let (_, receipt) = record_receipt(&result)?;
    assert_eq!(
        receipt.pointer("/inputs/0/input_sha256"),
        Some(&Value::from(expected_digest.clone()))
    );
    assert_eq!(
        receipt.pointer("/input_sha256"),
        Some(&Value::from(expected_digest))
    );
    assert_eq!(
        receipt.pointer("/inputs/0/input_length"),
        Some(&Value::from(bytes.len()))
    );
    Ok(())
}

#[test]
fn command_complete_objects_explains_incomplete() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let schema = directory.path().join("schema.json");
    fs::write(&schema, schema_json())?;
    let mut bytes = vec![3];
    push_record(&mut bytes, b"P1", 0, b"alpha");
    push_record(&mut bytes, b"Q2", 1, b"orphan");
    push_record(&mut bytes, b"P1", 1, b"beta");
    let mut case = Case::new();
    let input = case.add_bytes_node(
        "candidate_stream",
        &bytes,
        Vec::new(),
        serde_json::json!({}),
    )?;

    let output = run(
        &[
            "records",
            "-",
            "--node",
            &input.to_string(),
            "--schema",
            path_arg(&schema)?,
        ],
        &case.to_json()?,
    )?;

    assert!(output.status.success());
    let result = Case::from_json(&output.stdout)?;
    let object = result
        .nodes()
        .iter()
        .find(|node| node.kind == "record_object")
        .ok_or("missing assembled record object")?;
    let object_bytes = result
        .blobs()
        .iter()
        .find(|blob| Some(&blob.id) == object.blob.as_ref())
        .ok_or("missing assembled record bytes")?;
    assert_eq!(object_bytes.bytes, b"alphabeta");
    assert_eq!(
        object.details.get("input_node"),
        Some(&serde_json::json!(input))
    );
    let receipt_node = result
        .nodes()
        .iter()
        .find(|node| node.kind == "record_parse_receipt")
        .ok_or("missing record parse receipt")?;
    let receipt_blob = result
        .blobs()
        .iter()
        .find(|blob| Some(&blob.id) == receipt_node.blob.as_ref())
        .ok_or("missing record receipt bytes")?;
    let receipt: Value = serde_json::from_slice(&receipt_blob.bytes)?;
    assert_eq!(
        receipt.pointer("/assembly/groups/0/parts/0/input/start"),
        Some(&serde_json::json!(7))
    );
    assert_eq!(
        receipt.pointer("/assembly/groups/0/parts/1/output/start"),
        Some(&serde_json::json!(5))
    );
    assert_eq!(
        receipt.pointer("/assembly/terminal_sequence"),
        Some(&serde_json::json!(1))
    );
    assert!(result.nodes().iter().any(|node| {
        node.kind == "record_group_issue"
            && node
                .details
                .get("missing_sequence_count")
                .and_then(Value::as_u64)
                == Some(1)
    }));
    assert!(result.edges().iter().any(|edge| {
        edge.from == input && edge.to == object.id && edge.relation == "assembled_from"
    }));
    assert!(result.limitations().iter().any(|value| {
        value.contains("Record field meanings and sequence bases are operator supplied")
    }));
    Ok(())
}

#[test]
fn command_prefix_without_complete_objects() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut schema_value: Value = serde_json::from_slice(schema_json())?;
    schema_value
        .as_object_mut()
        .ok_or("schema fixture is not an object")?
        .remove("terminal_sequence");
    let schema = directory.path().join("schema.json");
    fs::write(&schema, serde_json::to_vec(&schema_value)?)?;
    let mut bytes = vec![2];
    push_record(&mut bytes, b"P1", 0, b"alpha");
    push_record(&mut bytes, b"P1", 1, b"beta");
    let mut case = Case::new();
    let input = case.add_bytes_node(
        "candidate_stream",
        &bytes,
        Vec::new(),
        serde_json::json!({}),
    )?;

    let output = run(
        &[
            "records",
            "-",
            "--node",
            &input.to_string(),
            "--schema",
            path_arg(&schema)?,
        ],
        &case.to_json()?,
    )?;

    assert!(output.status.success());
    let result = Case::from_json(&output.stdout)?;
    assert!(
        !result
            .nodes()
            .iter()
            .any(|node| node.kind == "record_object")
    );
    let candidate = find_node(&result, "record_candidate")?;
    assert_eq!(node_bytes(&result, candidate)?, b"alphabeta");
    assert_eq!(
        candidate.details.get("completion_basis"),
        Some(&serde_json::json!("observed_prefix_only"))
    );
    let issue = find_node(&result, "record_group_issue")?;
    assert_eq!(
        issue.details.get("completion_basis"),
        Some(&serde_json::json!("observed_prefix_only"))
    );
    for field in [
        "missing_sequence_count",
        "duplicate_sequence_count",
        "sequences_before_base_count",
        "sequences_after_terminal_count",
    ] {
        assert_eq!(issue.details.get(field), Some(&serde_json::json!(0)));
    }
    let (_, receipt) = record_receipt(&result)?;
    assert_eq!(
        receipt.pointer("/assembly/terminal_sequence"),
        Some(&Value::Null)
    );
    assert_eq!(
        receipt.pointer("/assembly/groups/0/complete"),
        Some(&serde_json::json!(false))
    );
    assert!(result.edges().iter().any(|edge| {
        edge.to == issue.id
            && edge
                .reason
                .contains("No operator-supplied terminal sequence establishes an end")
    }));
    assert!(result.edges().iter().any(|edge| {
        edge.from == input && edge.to == candidate.id && edge.relation == "candidate_from"
    }));
    Ok(())
}

#[test]
fn command_deduplicates_input_provenance_stable() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let schema = directory.path().join("schema.json");
    fs::write(&schema, schema_json())?;
    let mut bytes = vec![1];
    push_record(&mut bytes, b"D1", 0, b"payload");
    let mut case = Case::new();
    let input = case.add_bytes_node(
        "candidate_stream",
        &bytes,
        Vec::new(),
        serde_json::json!({}),
    )?;

    let output = run(
        &[
            "records",
            "-",
            "--node",
            &input.to_string(),
            "--node",
            &input.to_string(),
            "--schema",
            path_arg(&schema)?,
        ],
        &case.to_json()?,
    )?;

    assert!(output.status.success());
    let result = Case::from_json(&output.stdout)?;
    let issue = result
        .nodes()
        .iter()
        .find(|node| node.kind == "record_group_issue")
        .ok_or("missing duplicate sequence issue")?;
    assert_eq!(
        issue.details.get("input_node"),
        Some(&serde_json::json!(input))
    );
    assert_eq!(
        issue.details.get("input_count"),
        Some(&serde_json::json!(1))
    );
    assert_eq!(
        issue.details.get("completion_basis"),
        Some(&serde_json::json!("operator_terminal_sequence"))
    );
    Ok(())
}

#[test]
fn command_summarizes_without_copying_examples() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut schema_value: Value = serde_json::from_slice(schema_json())?;
    let schema_object = schema_value
        .as_object_mut()
        .ok_or("schema fixture is not an object")?;
    schema_object.insert("sequence_base".to_owned(), serde_json::json!(2));
    schema_object.insert("terminal_sequence".to_owned(), serde_json::json!(3));
    let schema = directory.path().join("schema.json");
    fs::write(&schema, serde_json::to_vec(&schema_value)?)?;
    let sequences = [0, 1, 2, 2, 2, 3, 3, 4, 5];
    let mut bytes = vec![u8::try_from(sequences.len())?];
    for sequence in sequences {
        push_record(&mut bytes, b"D1", sequence, b"x");
    }
    let mut case = Case::new();
    let input = case.add_bytes_node(
        "candidate_stream",
        &bytes,
        Vec::new(),
        serde_json::json!({}),
    )?;
    let output = run(
        &[
            "records",
            "-",
            "--node",
            &input.to_string(),
            "--schema",
            path_arg(&schema)?,
            "--max-issue-examples",
            "1",
        ],
        &case.to_json()?,
    )?;

    assert!(output.status.success());
    let result = Case::from_json(&output.stdout)?;
    let issue = find_node(&result, "record_group_issue")?;
    for (field, expected) in [
        ("missing_sequence_count", 0),
        ("duplicate_sequence_count", 2),
        ("sequences_before_base_count", 2),
        ("sequences_after_terminal_count", 2),
    ] {
        assert_eq!(issue.details.get(field), Some(&serde_json::json!(expected)));
    }
    for field in [
        "missing_sequences",
        "duplicate_sequences",
        "sequences_before_base",
        "sequences_after_terminal",
    ] {
        assert!(issue.details.get(field).is_none());
    }
    let (_, receipt) = record_receipt(&result)?;
    for field in [
        "duplicate_sequences",
        "sequences_before_base",
        "sequences_after_terminal",
    ] {
        assert_eq!(
            receipt
                .pointer(&format!("/assembly/groups/0/{field}"))
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(1)
        );
    }
    Ok(())
}

#[test]
fn command_large_selection_receipt_blob() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let schema = directory.path().join("schema.json");
    fs::write(&schema, schema_json())?;
    let mut bytes = vec![1];
    push_record(&mut bytes, b"R1", 0, b"x");
    let mut case = Case::new();
    let input = case.add_bytes_node(
        "candidate_stream",
        &bytes,
        Vec::new(),
        serde_json::json!({}),
    )?;
    let mut owned_args = vec!["records".to_owned(), "-".to_owned()];
    for _ in 0..2_048 {
        owned_args.push("--node".to_owned());
        owned_args.push(input.to_string());
    }
    owned_args.push("--schema".to_owned());
    owned_args.push(path_arg(&schema)?.to_owned());
    let args = owned_args.iter().map(String::as_str).collect::<Vec<_>>();

    let output = run(&args, &case.to_json()?)?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = Case::from_json(&output.stdout)?;
    let receipt_node = find_node(&result, "record_parse_receipt")?;
    assert_eq!(
        receipt_node.details.get("input_count"),
        Some(&serde_json::json!(2_048))
    );
    assert!(receipt_node.details.get("input_nodes").is_none());
    let (_, receipt) = record_receipt(&result)?;
    assert_eq!(
        receipt
            .get("inputs")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(2_048)
    );
    Ok(())
}

#[test]
fn command_large_examples_receipt_blob() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut schema_value: Value = serde_json::from_slice(schema_json())?;
    schema_value
        .as_object_mut()
        .ok_or("schema fixture is not an object")?
        .insert("terminal_sequence".to_owned(), serde_json::json!(2_048));
    let schema = directory.path().join("schema.json");
    fs::write(&schema, serde_json::to_vec(&schema_value)?)?;
    let mut bytes = vec![1];
    push_record(&mut bytes, b"R2", 0, b"x");
    let mut case = Case::new();
    let input = case.add_bytes_node(
        "candidate_stream",
        &bytes,
        Vec::new(),
        serde_json::json!({}),
    )?;

    let output = run(
        &[
            "records",
            "-",
            "--node",
            &input.to_string(),
            "--schema",
            path_arg(&schema)?,
            "--max-issue-examples",
            "2048",
        ],
        &case.to_json()?,
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = Case::from_json(&output.stdout)?;
    let issue = find_node(&result, "record_group_issue")?;
    assert_eq!(
        issue.details.get("missing_sequence_count"),
        Some(&serde_json::json!(2_048))
    );
    assert!(issue.details.get("missing_sequences").is_none());
    let (_, receipt) = record_receipt(&result)?;
    assert_eq!(
        receipt
            .pointer("/assembly/groups/0/missing_sequences")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(2_048)
    );
    Ok(())
}

#[test]
fn command_assembles_nodes_source_mapping() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let schema = directory.path().join("schema.json");
    fs::write(&schema, schema_json())?;
    let mut first_bytes = vec![1];
    push_record(&mut first_bytes, b"S1", 1, b"second");
    let mut second_bytes = vec![2];
    push_record(&mut second_bytes, b"S1", 0, b"first");
    push_record(&mut second_bytes, b"T2", 1, b"incomplete");
    let mut case = Case::new();
    let first = case.add_bytes_node(
        "candidate_stream",
        &first_bytes,
        Vec::new(),
        serde_json::json!({}),
    )?;
    let second = case.add_bytes_node(
        "candidate_stream",
        &second_bytes,
        Vec::new(),
        serde_json::json!({}),
    )?;

    let output = run(
        &[
            "records",
            "-",
            "--node",
            &first.to_string(),
            "--node",
            &second.to_string(),
            "--schema",
            path_arg(&schema)?,
        ],
        &case.to_json()?,
    )?;

    // Incomplete groups are evidence findings, not command execution failures
    assert!(output.status.success());
    let result = Case::from_json(&output.stdout)?;
    let object = find_node(&result, "record_object")?;
    assert_eq!(node_bytes(&result, object)?, b"firstsecond");
    assert_eq!(
        object.details.get("input_count"),
        Some(&serde_json::json!(2))
    );

    let (_, receipt) = record_receipt(&result)?;
    assert_eq!(
        receipt.pointer("/inputs/0/input_node"),
        Some(&serde_json::json!(first))
    );
    assert_eq!(
        receipt.pointer("/inputs/1/input_node"),
        Some(&serde_json::json!(second))
    );
    assert_eq!(
        receipt.pointer("/assembly/groups/0/parts/0/input_index"),
        Some(&serde_json::json!(1))
    );
    assert_eq!(
        receipt.pointer("/assembly/groups/0/parts/1/input_index"),
        Some(&serde_json::json!(0))
    );
    for input in [first, second] {
        assert!(result.edges().iter().any(|edge| {
            edge.from == input && edge.to == object.id && edge.relation == "assembled_from"
        }));
    }
    assert!(
        result
            .nodes()
            .iter()
            .any(|node| node.kind == "record_group_issue")
    );
    Ok(())
}

#[test]
fn command_uses_sources_per_part() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let schema = directory.path().join("schema.json");
    fs::write(&schema, external_count_schema_json())?;
    let mut first_bytes = Vec::new();
    push_record(&mut first_bytes, b"U3", 0, b"left");
    let mut second_bytes = Vec::new();
    push_record(&mut second_bytes, b"U3", 1, b"right");
    let mut case = Case::new();
    let first = case.add_bytes_node("part", &first_bytes, Vec::new(), serde_json::json!({}))?;
    let second = case.add_bytes_node("part", &second_bytes, Vec::new(), serde_json::json!({}))?;
    let first_count = case.add_bytes_node(
        "count_field",
        &[0xaa, 1, 0xbb],
        Vec::new(),
        serde_json::json!({}),
    )?;
    let second_count = case.add_bytes_node(
        "count_field",
        &[0xcc, 1, 0, 0xdd],
        Vec::new(),
        serde_json::json!({}),
    )?;
    let first_source = format!("node={first_count},offset=1,width=1,byte_order=big_endian");
    let second_source = format!("node={second_count},offset=1,width=2,byte_order=little_endian");

    let output = run(
        &[
            "records",
            "-",
            "--node",
            &first.to_string(),
            "--node",
            &second.to_string(),
            "--count-source",
            &first_source,
            "--count-source",
            &second_source,
            "--schema",
            path_arg(&schema)?,
        ],
        &case.to_json()?,
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = Case::from_json(&output.stdout)?;
    let object = find_node(&result, "record_object")?;
    assert_eq!(node_bytes(&result, object)?, b"leftright");
    let (receipt_node, receipt) = record_receipt(&result)?;
    assert_eq!(
        receipt.pointer("/inputs/0/count_source/value"),
        Some(&serde_json::json!(1))
    );
    assert_eq!(
        receipt.pointer("/inputs/0/count_source/range_sha256"),
        Some(&serde_json::json!(l2_workbench::sha256(&[1])))
    );
    assert_eq!(
        receipt.pointer("/inputs/1/count_source/range/end"),
        Some(&serde_json::json!(3))
    );
    assert_eq!(
        receipt.pointer("/inputs/1/count_source/byte_order"),
        Some(&serde_json::json!("little_endian"))
    );
    assert_eq!(
        receipt.pointer("/inputs/1/count_source/range_sha256"),
        Some(&serde_json::json!(l2_workbench::sha256(&[1, 0])))
    );
    for source in [first_count, second_count] {
        assert!(result.edges().iter().any(|edge| {
            edge.from == source
                && edge.to == receipt_node
                && edge.relation == "supplied_record_count"
        }));
    }
    Ok(())
}

#[test]
fn command_receipt_exceeds_aggregate_budget() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let schema = directory.path().join("schema.json");
    fs::write(&schema, schema_json())?;
    let mut bytes = vec![40];
    for sequence in 0..40 {
        push_record(&mut bytes, b"R3", sequence, b"x");
    }
    let mut case = Case::new();
    let input = case.add_bytes_node(
        "candidate_stream",
        &bytes,
        Vec::new(),
        serde_json::json!({}),
    )?;

    let output = run(
        &[
            "records",
            "-",
            "--node",
            &input.to_string(),
            "--schema",
            path_arg(&schema)?,
            "--max-report-bytes",
            "8192",
        ],
        &case.to_json()?,
    )?;

    assert!(!output.status.success());
    assert_eq!(output.stdout.len(), 0);
    assert!(String::from_utf8_lossy(&output.stderr).contains("record metadata needs"));
    Ok(())
}

#[test]
fn command_preflights_exhausted_aggregate_budget() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let schema = directory.path().join("schema.json");
    fs::write(&schema, schema_json())?;
    let mut valid_bytes = vec![1];
    push_record(&mut valid_bytes, b"R3", 0, b"valid");
    let malformed_next_part = [1, b'R'];
    let mut case = Case::new();
    let first = case.add_bytes_node(
        "candidate_stream",
        &valid_bytes,
        Vec::new(),
        serde_json::json!({}),
    )?;
    let second = case.add_bytes_node(
        "candidate_stream",
        &malformed_next_part,
        Vec::new(),
        serde_json::json!({}),
    )?;

    let output = run(
        &[
            "records",
            "-",
            "--node",
            &first.to_string(),
            "--node",
            &second.to_string(),
            "--schema",
            path_arg(&schema)?,
            "--max-records",
            "1",
        ],
        &case.to_json()?,
    )?;

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("record count 2 exceeds 1"));
    assert!(!stderr.contains("truncated record"));
    assert_eq!(output.stdout.len(), 0);
    Ok(())
}

#[test]
fn command_partial_external_count_source() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let schema = directory.path().join("schema.json");
    fs::write(&schema, schema_json())?;
    let mut bytes = vec![1];
    push_record(&mut bytes, b"V4", 0, b"payload");
    let mut case = Case::new();
    let first = case.add_bytes_node("part", &bytes, Vec::new(), serde_json::json!({}))?;
    let second = case.add_bytes_node("part", &bytes, Vec::new(), serde_json::json!({}))?;
    let count = case.add_bytes_node("count", &[1], Vec::new(), serde_json::json!({}))?;
    let source = format!("node={count},offset=0,width=1,byte_order=big_endian");

    let output = run(
        &[
            "records",
            "-",
            "--node",
            &first.to_string(),
            "--node",
            &second.to_string(),
            "--count-source",
            &source,
            "--schema",
            path_arg(&schema)?,
        ],
        &case.to_json()?,
    )?;

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("count source count must be zero or match the 2 selected input nodes")
    );
    Ok(())
}

#[test]
fn command_unconsumed_bytes_independent_part() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let schema = directory.path().join("schema.json");
    fs::write(&schema, schema_json())?;
    let mut first_bytes = vec![1];
    push_record(&mut first_bytes, b"W5", 0, b"valid");
    let mut second_bytes = vec![1];
    push_record(&mut second_bytes, b"W5", 1, b"valid");
    second_bytes.push(0xff);
    let mut case = Case::new();
    let first = case.add_bytes_node("part", &first_bytes, Vec::new(), serde_json::json!({}))?;
    let second = case.add_bytes_node("part", &second_bytes, Vec::new(), serde_json::json!({}))?;

    let output = run(
        &[
            "records",
            "-",
            "--node",
            &first.to_string(),
            "--node",
            &second.to_string(),
            "--schema",
            path_arg(&schema)?,
        ],
        &case.to_json()?,
    )?;

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unconsumed bytes"));
    assert_eq!(output.stdout.len(), 0);
    Ok(())
}

#[test]
fn command_external_outside_retained_bytes() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let schema = directory.path().join("schema.json");
    fs::write(&schema, schema_json())?;
    let mut bytes = vec![1];
    push_record(&mut bytes, b"X6", 0, b"valid");
    let mut case = Case::new();
    let part = case.add_bytes_node("part", &bytes, Vec::new(), serde_json::json!({}))?;
    let count = case.add_bytes_node("count", &[1], Vec::new(), serde_json::json!({}))?;
    let source = format!("node={count},offset=1,width=1,byte_order=big_endian");

    let output = run(
        &[
            "records",
            "-",
            "--node",
            &part.to_string(),
            "--count-source",
            &source,
            "--schema",
            path_arg(&schema)?,
        ],
        &case.to_json()?,
    )?;

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("range 1..2 exceeds its 1 retained bytes")
    );
    assert_eq!(output.stdout.len(), 0);
    Ok(())
}

#[test]
fn command_interleaves_records() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let schema = directory.path().join("schema.json");
    fs::write(&schema, schema_json())?;
    let mut first_bytes = vec![2];
    push_record(&mut first_bytes, b"A1", 0, b"a0");
    push_record(&mut first_bytes, b"B2", 1, b"b1");
    let mut second_bytes = vec![2];
    push_record(&mut second_bytes, b"B2", 0, b"b0");
    push_record(&mut second_bytes, b"A1", 1, b"a1");
    let mut case = Case::new();
    let first = case.add_bytes_node("part", &first_bytes, Vec::new(), serde_json::json!({}))?;
    let second = case.add_bytes_node("part", &second_bytes, Vec::new(), serde_json::json!({}))?;

    let output = run(
        &[
            "records",
            "-",
            "--node",
            &first.to_string(),
            "--node",
            &second.to_string(),
            "--schema",
            path_arg(&schema)?,
        ],
        &case.to_json()?,
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = Case::from_json(&output.stdout)?;
    let objects = result
        .nodes()
        .iter()
        .filter(|node| node.kind == "record_object")
        .collect::<Vec<_>>();
    assert_eq!(objects.len(), 2);
    let first_group = objects
        .iter()
        .find(|node| node.details.get("identifier_preview") == Some(&serde_json::json!([65, 49])))
        .ok_or("missing first interleaved group")?;
    let second_group = objects
        .iter()
        .find(|node| node.details.get("identifier_preview") == Some(&serde_json::json!([66, 50])))
        .ok_or("missing second interleaved group")?;
    assert_eq!(node_bytes(&result, first_group)?, b"a0a1");
    assert_eq!(node_bytes(&result, second_group)?, b"b0b1");
    assert!(
        !result
            .nodes()
            .iter()
            .any(|node| node.kind == "record_group_issue")
    );
    Ok(())
}

#[test]
fn candidate_artifact_stays_incomplete() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut schema_value: Value = serde_json::from_slice(schema_json())?;
    schema_value
        .as_object_mut()
        .ok_or("schema fixture is not an object")?
        .remove("terminal_sequence");
    let schema = directory.path().join("schema.json");
    fs::write(&schema, serde_json::to_vec(&schema_value)?)?;
    let mut payload = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut payload, 1, 1);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header()?;
        writer.write_image_data(&[1, 2, 3])?;
    }
    let mut bytes = vec![1];
    push_record(&mut bytes, b"P1", 0, &payload);
    let mut case = Case::new();
    let input = case.add_bytes_node(
        "candidate_stream",
        &bytes,
        Vec::new(),
        serde_json::json!({}),
    )?;

    let records = run(
        &[
            "records",
            "-",
            "--node",
            &input.to_string(),
            "--schema",
            path_arg(&schema)?,
        ],
        &case.to_json()?,
    )?;

    assert!(records.status.success());
    let records_case = Case::from_json(&records.stdout)?;
    let candidate = find_node(&records_case, "record_candidate")?;
    assert_eq!(node_bytes(&records_case, candidate)?, payload);
    assert_eq!(
        candidate.details.get("completion_basis"),
        Some(&serde_json::json!("observed_prefix_only"))
    );
    assert!(
        !records_case
            .nodes()
            .iter()
            .any(|node| node.kind == "record_object")
    );

    let expanded = run(
        &["expand", "-", "--node", &candidate.id.to_string()],
        &records_case.to_json()?,
    )?;

    assert!(
        expanded.status.success(),
        "{}",
        String::from_utf8_lossy(&expanded.stderr)
    );
    let expanded_case = Case::from_json(&expanded.stdout)?;
    let structure = find_node(&expanded_case, "png_structure")?;
    assert!(expanded_case.edges().iter().any(|edge| {
        edge.from == candidate.id && edge.to == structure.id && edge.relation == "parsed_as"
    }));
    assert!(
        !expanded_case
            .nodes()
            .iter()
            .any(|node| node.kind == "record_object")
    );
    Ok(())
}

#[test]
fn command_limits_unknown_schema_fields() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let schema = directory.path().join("schema.json");
    fs::write(&schema, schema_json())?;
    let mut bytes = vec![2];
    push_record(&mut bytes, b"R3", 0, b"one");
    push_record(&mut bytes, b"R3", 1, b"two");
    let mut case = Case::new();
    let input = case.add_bytes_node(
        "candidate_stream",
        &bytes,
        Vec::new(),
        serde_json::json!({}),
    )?;
    let case_path = save_case(directory.path(), "case.json", &case)?;

    let limited = run(
        &[
            "records",
            path_arg(&case_path)?,
            "--node",
            &input.to_string(),
            "--schema",
            path_arg(&schema)?,
            "--max-records",
            "1",
        ],
        &[],
    )?;
    assert!(!limited.status.success());
    assert!(String::from_utf8_lossy(&limited.stderr).contains("record count 2 exceeds 1"));

    let invalid_schema = directory.path().join("invalid-schema.json");
    let mut value: Value = serde_json::from_slice(schema_json())?;
    value
        .as_object_mut()
        .ok_or("schema fixture is not an object")?
        .insert("guessed_cipher".to_owned(), serde_json::json!(true));
    fs::write(&invalid_schema, serde_json::to_vec(&value)?)?;
    let rejected = run(
        &[
            "records",
            path_arg(&case_path)?,
            "--node",
            &input.to_string(),
            "--schema",
            path_arg(&invalid_schema)?,
        ],
        &[],
    )?;
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("unknown field"));
    Ok(())
}
