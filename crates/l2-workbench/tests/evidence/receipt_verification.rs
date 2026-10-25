use l2_workbench::{
    evidence::{
        Case, ReceiptVerificationError, ReceiptVerificationLimits, verify_index_flow_selection,
    },
    sha256,
};
use serde_json::{Value, json};
use std::error::Error;

const SOURCE_BYTES: &[u8] = b"indexed source";
const PREDICATE: &str = "source_interface_vlan_bidirectional_unfragmented_transport_tuple";

fn valid_receipt() -> Vec<u8> {
    br#"{"requested_flow_ids":[9,3,9],"flow_contributions":[{"flow_id":9,"packet_records":2},{"flow_id":3,"packet_records":1}]}"#.to_vec()
}

fn valid_details() -> Value {
    json!({
        "representation": "json_blob",
        "receipt_schema_version": 1,
        "flow_count": 2,
        "requested_flow_count": 3,
        "duplicate_flow_selections_removed": 1,
        "selected_records": 3,
        "retained_input_records": 3,
        "omitted_records": 0,
        "source_id": format!("sha256:{}", sha256(SOURCE_BYTES)),
        "predicate": PREDICATE,
    })
}

fn case_with_receipt(receipt: &[u8], details: Value) -> Result<Case, Box<dyn Error>> {
    let mut case = Case::new();
    case.add_source(
        "capture.pcap",
        "capture",
        u64::try_from(SOURCE_BYTES.len())?,
        &sha256(SOURCE_BYTES),
        None,
    )?;
    case.add_bytes_node("index_flow_selection", receipt, Vec::new(), details)?;

    // The semantic verifier must operate on a normal validated case, including after persistence
    let encoded = case.to_json()?;
    Ok(Case::from_json(&encoded)?)
}

#[test]
fn valid_flow_verified_internal_consistency() -> Result<(), Box<dyn Error>> {
    let case = case_with_receipt(&valid_receipt(), valid_details())?;

    let report = verify_index_flow_selection(&case, 1, ReceiptVerificationLimits::default())?;

    assert!(report.verified);
    assert_eq!(report.node, 1);
    assert_eq!(report.requested_flow_count, 3);
    assert_eq!(report.flow_count, 2);
    assert_eq!(report.duplicate_flow_selections_removed, 1);
    assert_eq!(report.selected_records, 3);
    assert_eq!(report.retained_input_records, 3);
    assert_eq!(report.omitted_records, 0);
    assert_eq!(
        report.verification_scope,
        "receipt_internal_consistency_and_source_reference"
    );
    Ok(())
}

#[test]
fn retention_receipt_v2_round_trips_complete_and_truncated_prefixes() -> Result<(), Box<dyn Error>>
{
    let mut complete_details = valid_details();
    complete_details
        .as_object_mut()
        .ok_or("receipt details are not an object")?
        .extend([
            ("receipt_schema_version".to_owned(), json!(2)),
            ("retention_status".to_owned(), json!("complete")),
            ("retention_limits".to_owned(), json!([])),
        ]);
    let complete = case_with_receipt(&valid_receipt(), complete_details)?;
    let complete_report =
        verify_index_flow_selection(&complete, 1, ReceiptVerificationLimits::default())?;
    assert_eq!(complete_report.receipt_schema_version, 2);
    assert_eq!(complete_report.omitted_records, 0);

    let mut truncated_details = valid_details();
    truncated_details
        .as_object_mut()
        .ok_or("receipt details are not an object")?
        .extend([
            ("receipt_schema_version".to_owned(), json!(2)),
            ("retained_input_records".to_owned(), json!(1)),
            ("omitted_records".to_owned(), json!(2)),
            (
                "retention_status".to_owned(),
                json!("resource_truncated_prefix"),
            ),
            ("retention_limits".to_owned(), json!(["frames", "units"])),
        ]);
    let truncated = case_with_receipt(&valid_receipt(), truncated_details)?;
    let truncated_report =
        verify_index_flow_selection(&truncated, 1, ReceiptVerificationLimits::default())?;
    assert_eq!(truncated_report.receipt_schema_version, 2);
    assert_eq!(truncated_report.selected_records, 3);
    assert_eq!(truncated_report.retained_input_records, 1);
    assert_eq!(truncated_report.omitted_records, 2);
    Ok(())
}

#[test]
fn retention_receipt_v2_rejects_status_and_limit_contradictions() -> Result<(), Box<dyn Error>> {
    let mut complete_with_omissions = valid_details();
    complete_with_omissions
        .as_object_mut()
        .ok_or("receipt details are not an object")?
        .extend([
            ("receipt_schema_version".to_owned(), json!(2)),
            ("retained_input_records".to_owned(), json!(1)),
            ("omitted_records".to_owned(), json!(2)),
            ("retention_status".to_owned(), json!("complete")),
            ("retention_limits".to_owned(), json!([])),
        ]);
    let contradictory = case_with_receipt(&valid_receipt(), complete_with_omissions)?;
    assert!(matches!(
        verify_index_flow_selection(&contradictory, 1, ReceiptVerificationLimits::default()),
        Err(ReceiptVerificationError::Contradiction {
            invariant: "details.retention_status"
        })
    ));

    let mut missing_limit_reason = valid_details();
    missing_limit_reason
        .as_object_mut()
        .ok_or("receipt details are not an object")?
        .extend([
            ("receipt_schema_version".to_owned(), json!(2)),
            ("retained_input_records".to_owned(), json!(1)),
            ("omitted_records".to_owned(), json!(2)),
            (
                "retention_status".to_owned(),
                json!("resource_truncated_prefix"),
            ),
            ("retention_limits".to_owned(), json!([])),
        ]);
    let missing_reason = case_with_receipt(&valid_receipt(), missing_limit_reason)?;
    assert!(matches!(
        verify_index_flow_selection(&missing_reason, 1, ReceiptVerificationLimits::default()),
        Err(ReceiptVerificationError::Contradiction {
            invariant: "details.retention_limits"
        })
    ));
    Ok(())
}

#[test]
fn receipt_parser_malformed_duplicate_fields() -> Result<(), Box<dyn Error>> {
    let malformed = case_with_receipt(b"{", valid_details())?;
    assert!(matches!(
        verify_index_flow_selection(&malformed, 1, ReceiptVerificationLimits::default()),
        Err(ReceiptVerificationError::ReceiptJson)
    ));

    let duplicate_root = case_with_receipt(
        br#"{"requested_flow_ids":[9,3,9],"requested_flow_ids":[9,3,9],"flow_contributions":[{"flow_id":9,"packet_records":2},{"flow_id":3,"packet_records":1}]}"#,
        valid_details(),
    )?;
    assert!(matches!(
        verify_index_flow_selection(&duplicate_root, 1, ReceiptVerificationLimits::default()),
        Err(ReceiptVerificationError::ReceiptJson)
    ));

    let duplicate_contribution = case_with_receipt(
        br#"{"requested_flow_ids":[9,3,9],"flow_contributions":[{"flow_id":9,"flow_id":9,"packet_records":2},{"flow_id":3,"packet_records":1}]}"#,
        valid_details(),
    )?;
    assert!(matches!(
        verify_index_flow_selection(
            &duplicate_contribution,
            1,
            ReceiptVerificationLimits::default()
        ),
        Err(ReceiptVerificationError::ReceiptJson)
    ));

    let unknown_root = case_with_receipt(
        br#"{"requested_flow_ids":[9,3,9],"flow_contributions":[{"flow_id":9,"packet_records":2},{"flow_id":3,"packet_records":1}],"future":true}"#,
        valid_details(),
    )?;
    assert!(matches!(
        verify_index_flow_selection(&unknown_root, 1, ReceiptVerificationLimits::default()),
        Err(ReceiptVerificationError::ReceiptJson)
    ));

    let unknown_contribution = case_with_receipt(
        br#"{"requested_flow_ids":[9,3,9],"flow_contributions":[{"flow_id":9,"packet_records":2,"future":true},{"flow_id":3,"packet_records":1}]}"#,
        valid_details(),
    )?;
    assert!(matches!(
        verify_index_flow_selection(
            &unknown_contribution,
            1,
            ReceiptVerificationLimits::default()
        ),
        Err(ReceiptVerificationError::ReceiptJson)
    ));
    Ok(())
}

#[test]
fn loader_duplicate_builtin_receipt_details() -> Result<(), Box<dyn Error>> {
    let case = case_with_receipt(&valid_receipt(), valid_details())?;
    let encoded = String::from_utf8(case.to_json()?)?;
    let duplicate = encoded.replace(
        "\"selected_records\":3",
        "\"selected_records\":3,\"selected_records\":4",
    );
    assert!(matches!(
        Case::from_json(duplicate.as_bytes()),
        Err(l2_workbench::evidence::EvidenceError::InvalidJson)
    ));

    let unknown = encoded.replace(
        "\"selected_records\":3",
        "\"selected_records\":3,\"future_field\":true",
    );
    assert!(matches!(
        Case::from_json(unknown.as_bytes()),
        Err(l2_workbench::evidence::EvidenceError::InvalidJson)
    ));
    Ok(())
}

#[test]
fn verifier_contribution_detail_count_contradictions() -> Result<(), Box<dyn Error>> {
    let reordered = case_with_receipt(
        br#"{"requested_flow_ids":[9,3,9],"flow_contributions":[{"flow_id":3,"packet_records":1},{"flow_id":9,"packet_records":2}]}"#,
        valid_details(),
    )?;
    assert!(matches!(
        verify_index_flow_selection(&reordered, 1, ReceiptVerificationLimits::default()),
        Err(ReceiptVerificationError::Contradiction {
            invariant: "flow_contributions.first_seen_order"
        })
    ));

    let mut details = valid_details();
    *details
        .get_mut("selected_records")
        .ok_or("selected record count is missing")? = json!(4);
    let wrong_count = case_with_receipt(&valid_receipt(), details)?;
    assert!(matches!(
        verify_index_flow_selection(&wrong_count, 1, ReceiptVerificationLimits::default()),
        Err(ReceiptVerificationError::Contradiction {
            invariant: "details.selected_records"
        })
    ));
    Ok(())
}

#[test]
fn verifier_unsupported_versions_missing_sources() -> Result<(), Box<dyn Error>> {
    let mut version_details = valid_details();
    *version_details
        .get_mut("receipt_schema_version")
        .ok_or("receipt schema version is missing")? = json!(3);
    let unsupported = case_with_receipt(&valid_receipt(), version_details)?;
    assert!(matches!(
        verify_index_flow_selection(&unsupported, 1, ReceiptVerificationLimits::default()),
        Err(ReceiptVerificationError::UnsupportedFormat { version: Some(3) })
    ));

    let mut source_details = valid_details();
    *source_details
        .get_mut("source_id")
        .ok_or("source reference is missing")? = json!(format!("sha256:{}", "0".repeat(64)));
    let missing_source = case_with_receipt(&valid_receipt(), source_details)?;
    assert!(matches!(
        verify_index_flow_selection(&missing_source, 1, ReceiptVerificationLimits::default()),
        Err(ReceiptVerificationError::Contradiction {
            invariant: "details.source_id"
        })
    ));
    Ok(())
}

#[test]
fn verifier_exact_aggregate_entry_limits() -> Result<(), Box<dyn Error>> {
    let receipt = valid_receipt();
    let case = case_with_receipt(&receipt, valid_details())?;

    verify_index_flow_selection(
        &case,
        1,
        ReceiptVerificationLimits {
            max_receipt_bytes: Some(receipt.len()),
            max_list_entries: Some(5),
        },
    )?;

    assert!(matches!(
        verify_index_flow_selection(
            &case,
            1,
            ReceiptVerificationLimits {
                max_receipt_bytes: Some(receipt.len() - 1),
                max_list_entries: None,
            }
        ),
        Err(ReceiptVerificationError::LimitExceeded {
            resource: "receipt bytes",
            ..
        })
    ));
    assert!(matches!(
        verify_index_flow_selection(
            &case,
            1,
            ReceiptVerificationLimits {
                max_receipt_bytes: None,
                max_list_entries: Some(4),
            }
        ),
        Err(ReceiptVerificationError::LimitExceeded {
            resource: "receipt list entries",
            ..
        })
    ));
    Ok(())
}

#[test]
fn repeated_single_not_request_detail() -> Result<(), Box<dyn Error>> {
    let receipt =
        br#"{"requested_flow_ids":[7,7],"flow_contributions":[{"flow_id":7,"packet_records":1}]}"#;
    let mut details = valid_details();
    details
        .as_object_mut()
        .ok_or("receipt details are not an object")?
        .extend([
            ("flow_count".to_owned(), json!(1)),
            ("requested_flow_count".to_owned(), json!(2)),
            ("duplicate_flow_selections_removed".to_owned(), json!(1)),
            ("selected_records".to_owned(), json!(1)),
            ("retained_input_records".to_owned(), json!(1)),
            ("flow_id".to_owned(), json!(7)),
        ]);
    let case = case_with_receipt(receipt, details)?;

    assert!(matches!(
        verify_index_flow_selection(&case, 1, ReceiptVerificationLimits::default()),
        Err(ReceiptVerificationError::Contradiction {
            invariant: "details.flow_id"
        })
    ));
    Ok(())
}
