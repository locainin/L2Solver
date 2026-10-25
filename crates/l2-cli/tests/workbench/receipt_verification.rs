use super::support::{path_arg, run, save_case};
use l2_workbench::{evidence::Case, sha256};
use serde_json::{Value, json};
use std::{error::Error, fs};

const SOURCE: &[u8] = b"indexed source";

fn receipt_case() -> Result<Case, Box<dyn Error>> {
    let mut case = Case::new();
    let source_id = case.add_source(
        "capture.pcap",
        "capture",
        u64::try_from(SOURCE.len())?,
        &sha256(SOURCE),
        None,
    )?;
    case.add_bytes_node(
        "index_flow_selection",
        br#"{"requested_flow_ids":[8,5,8],"flow_contributions":[{"flow_id":8,"packet_records":2},{"flow_id":5,"packet_records":1}]}"#,
        Vec::new(),
        json!({
            "representation": "json_blob",
            "receipt_schema_version": 1,
            "flow_count": 2,
            "requested_flow_count": 3,
            "duplicate_flow_selections_removed": 1,
            "selected_records": 3,
            "retained_input_records": 2,
            "omitted_records": 1,
            "source_id": source_id,
            "predicate": "source_interface_vlan_bidirectional_unfragmented_transport_tuple",
        }),
    )?;
    Ok(case)
}

#[test]
fn verify_receipt_scoped_machine_readable() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let case_path = save_case(directory.path(), "case.json", &receipt_case()?)?;

    let output = run(
        &["verify-receipt", path_arg(&case_path)?, "--node", "1"],
        &[],
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report.get("verified"), Some(&json!(true)));
    assert_eq!(report.get("node"), Some(&json!(1)));
    assert_eq!(report.get("requested_flow_count"), Some(&json!(3)));
    assert_eq!(report.get("flow_count"), Some(&json!(2)));
    assert_eq!(report.get("selected_records"), Some(&json!(3)));
    assert_eq!(report.get("retained_input_records"), Some(&json!(2)));
    assert_eq!(report.get("omitted_records"), Some(&json!(1)));
    assert_eq!(report.get("case_collection_complete"), Some(&json!(true)));
    assert_eq!(
        report.get("verification_scope").and_then(Value::as_str),
        Some("receipt_internal_consistency_and_source_reference")
    );
    Ok(())
}

#[test]
fn verify_receipt_selected_input_budget() -> Result<(), Box<dyn Error>> {
    let encoded = receipt_case()?.to_json()?;
    let length = encoded.len().to_string();

    let output = run(
        &[
            "verify-receipt",
            "-",
            "--node",
            "1",
            "--max-input-bytes",
            &length,
        ],
        &encoded,
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report.get("verified"), Some(&json!(true)));
    Ok(())
}

#[test]
fn verify_receipt_without_weakening_success() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = receipt_case()?;
    case.mark_incomplete("A separate collection stage was incomplete")?;
    let case_path = save_case(directory.path(), "partial.json", &case)?;

    let output = run(
        &["verify-receipt", path_arg(&case_path)?, "--node", "1"],
        &[],
    )?;

    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report.get("verified"), Some(&json!(true)));
    assert_eq!(report.get("case_collection_complete"), Some(&json!(false)));
    Ok(())
}

#[test]
fn verify_receipt_never_replaces_output() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    case.add_bytes_node("custom_receipt", b"{}", Vec::new(), json!({}))?;
    let case_path = save_case(directory.path(), "unsupported.json", &case)?;
    let absent = directory.path().join("absent.json");

    let rejected = run(
        &[
            "verify-receipt",
            path_arg(&case_path)?,
            "--node",
            "1",
            "--output",
            path_arg(&absent)?,
        ],
        &[],
    )?;
    assert_eq!(rejected.status.code(), Some(1));
    assert!(!absent.exists());

    let existing = directory.path().join("existing.json");
    fs::write(&existing, b"preserve")?;
    let rejected = run(
        &[
            "verify-receipt",
            path_arg(&case_path)?,
            "--node",
            "1",
            "--output",
            path_arg(&existing)?,
        ],
        &[],
    )?;
    assert_eq!(rejected.status.code(), Some(1));
    assert_eq!(fs::read(existing)?, b"preserve");
    Ok(())
}

#[test]
fn verify_receipt_selected_budgets() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let case = receipt_case()?;
    let case_path = save_case(directory.path(), "case.json", &case)?;
    let receipt_length = case
        .nodes()
        .first()
        .and_then(|node| node.blob.as_deref())
        .and_then(|id| case.blobs().iter().find(|blob| blob.id == id))
        .map(|blob| blob.bytes.len())
        .ok_or("missing receipt blob")?;
    let exact_length = receipt_length.to_string();

    let accepted = run(
        &[
            "verify-receipt",
            path_arg(&case_path)?,
            "--node",
            "1",
            "--max-receipt-bytes",
            &exact_length,
            "--max-list-entries",
            "5",
        ],
        &[],
    )?;
    assert!(accepted.status.success());

    let below_length = (receipt_length - 1).to_string();
    let byte_limited = run(
        &[
            "verify-receipt",
            path_arg(&case_path)?,
            "--node",
            "1",
            "--max-receipt-bytes",
            &below_length,
        ],
        &[],
    )?;
    assert_eq!(byte_limited.status.code(), Some(1));

    let list_limited = run(
        &[
            "verify-receipt",
            path_arg(&case_path)?,
            "--node",
            "1",
            "--max-list-entries",
            "4",
        ],
        &[],
    )?;
    assert_eq!(list_limited.status.code(), Some(1));
    Ok(())
}
