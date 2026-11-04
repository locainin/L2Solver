use super::*;
use l2_workbench::{carrier::discovery::DiscoveryMapping, evidence::SourceRange};

fn mapping(
    packet: Option<u64>,
    offset: usize,
    source_offset: u64,
    length: u64,
) -> DiscoveryMapping {
    DiscoveryMapping {
        offset,
        range: SourceRange {
            source: "capture".to_owned(),
            packet,
            offset: source_offset,
            length,
        },
    }
}

#[test]
fn packet_projections_group_contiguous_slices_and_keep_retransmission_witnesses()
-> Result<(), Box<dyn std::error::Error>> {
    let mappings = [
        mapping(Some(12), 2, 502, 2),
        mapping(Some(11), 0, 100, 4),
        mapping(Some(12), 0, 500, 2),
        mapping(Some(13), 4, 900, 2),
    ];
    let (projections, omitted) = packet_projections(&mappings, 6);
    assert_eq!(omitted, 0);
    let [first, second, third] = projections.as_slice() else {
        return Err("expected three packet projections".into());
    };
    assert_eq!((first.start, first.end), (0, 4));
    assert_eq!((second.start, second.end), (0, 4));
    assert_eq!(
        second.ranges.first().and_then(|range| range.packet),
        Some(12)
    );
    assert_eq!((third.start, third.end), (4, 6));
    Ok(())
}

#[test]
fn packet_projections_omit_gaps_misaligned_sources_and_missing_packet_ids() {
    let mappings = [
        mapping(Some(1), 0, 100, 2),
        mapping(Some(1), 3, 103, 2),
        mapping(Some(2), 0, 200, 2),
        mapping(Some(2), 2, 300, 2),
        mapping(None, 0, 400, 2),
        mapping(Some(3), 5, 500, 2),
    ];
    let (projections, omitted) = packet_projections(&mappings, 6);
    assert!(projections.is_empty());
    assert_eq!(omitted, 4);
}

#[test]
fn bounded_xor_search_and_publication_omissions_mark_their_own_coverage() {
    let search = RecoveryOmission::XorSearchLimit {
        input_node_id: 1,
        omitted_candidates: 0,
        search_truncated: true,
        sample_truncated: false,
    };
    assert!(!super::super::search_exhaustive_within_plan(&[search]));
    let publication = RecoveryOmission::XorMessageOmission {
        input_node_id: 1,
        omitted: 2,
        reason: "xor_mapping_limit".into(),
    };
    assert!(!super::super::discovery_input_coverage_complete(
        std::slice::from_ref(&publication)
    ));
    assert!(!super::super::report_details_complete(&[publication]));
}

#[test]
fn message_receipt_keeps_binary_bytes_and_obeys_memory_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let budget = MemoryBudget::new(4096);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 0)?;
    let receipt = serialize_message_bytes(&[0, 34, 255], &[13, 10, 128], &mut lease)?;
    let value: serde_json::Value = serde_json::from_slice(&receipt)?;
    assert_eq!(
        value.get("raw_bytes"),
        Some(&serde_json::json!([0, 34, 255]))
    );
    assert_eq!(
        value.get("normalized_bytes"),
        Some(&serde_json::json!([13, 10, 128]))
    );
    assert!(lease.bytes() >= u64::try_from(receipt.capacity())?);
    let tiny = MemoryBudget::new(1);
    let mut tiny_lease = tiny.try_reserve(MemoryClass::Executor, 0)?;
    assert!(serialize_message_bytes(&[1], &[2], &mut tiny_lease).is_err());
    assert_eq!(tiny_lease.bytes(), 0);
    Ok(())
}

#[test]
fn xor_report_accounts_for_retained_capacity_and_releases_it_on_failure()
-> Result<(), Box<dyn std::error::Error>> {
    use l2_workbench::{
        derivation::{Operation, Recipe},
        recovery::xor::{XOR_MAX_CANDIDATES, XorEvidence, XorProposal, XorProposalReport},
    };
    let evidence = XorEvidence {
        sample_bytes: 192,
        printable_bytes: 192,
        alphabetic_bytes: 120,
        complete_lines: 4,
        distinct_line_lengths: 3,
        text_score: 640,
    };
    let report = XorProposalReport {
        proposals: (0..XOR_MAX_CANDIDATES)
            .map(|_| XorProposal {
                recipe: Recipe {
                    steps: vec![Operation::XorRepeat {
                        key: vec![0x35],
                        offset: 0,
                    }],
                    constraints: Vec::new(),
                },
                evidence: evidence.clone(),
            })
            .collect(),
        omitted_candidates: 0,
        search_truncated: true,
        sample_truncated: false,
    };
    let budget = MemoryBudget::new(64 * 1024);
    let encoded = serialized_report(&report, &budget, 64 * 1024)?;
    assert!(budget.snapshot()?.used_bytes >= u64::try_from(encoded.bytes.capacity())?);
    let value: serde_json::Value = serde_json::from_slice(&encoded.bytes)?;
    assert_eq!(value.get("version"), Some(&serde_json::json!(1)));
    assert_eq!(
        value.get("search_truncated"),
        Some(&serde_json::json!(true))
    );
    assert_eq!(
        value.get("sample_truncated"),
        Some(&serde_json::json!(false))
    );
    assert_eq!(value.get("omitted_candidates"), Some(&serde_json::json!(0)));
    let expected_evidence = serde_json::to_value(&evidence)?;
    let proposals = value
        .get("proposals")
        .and_then(serde_json::Value::as_array)
        .ok_or("proposals missing")?;
    assert_eq!(proposals.len(), XOR_MAX_CANDIDATES);
    assert!(proposals.iter().all(
        |proposal| proposal.get("evidence") == Some(&expected_evidence)
            && proposal.get("key").is_none()
            && proposal.get("key_sha256").is_none()
            && proposal.get("period").is_none()
            && proposal.get("offset").is_none()
            && proposal.get("recipe").is_none()
    ));
    drop(encoded);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    let tiny = MemoryBudget::new(1);
    assert!(serialized_report(&report, &tiny, 64 * 1024).is_err());
    assert_eq!(tiny.snapshot()?.used_bytes, 0);
    assert!(serialized_report(&report, &budget, 1).is_err());
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn evidence_memory_exhaustion_is_partial_but_cancellation_stays_fatal() {
    let limit = RecoveryExecutionError::Evidence(l2_workbench::evidence::EvidenceError::Memory(
        MemoryError::Limit {
            limit: 10,
            used: 9,
            requested: 2,
        },
    ));
    let cancellation = RecoveryExecutionError::Evidence(
        l2_workbench::evidence::EvidenceError::Memory(MemoryError::Cancelled),
    );
    assert!(is_memory_limit(&limit));
    assert!(!is_memory_limit(&cancellation));
}
