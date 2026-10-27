use super::{FramingOutcome, apply, apply_with_basis};
use crate::workbench::framing_materialize::FramingSelectionBasis;
use l2_workbench::{
    evidence::{ByteMapping, Case, Edge, EvidenceStatus, MAX_EDGES, SourceRange},
    protocol::{BoundaryStatus, FramingKind},
};
use serde_json::json;
use std::error::Error;

#[test]
fn returns_created_frames() -> Result<(), Box<dyn Error>> {
    let (mut case, input) = tcp_run(b"aabb")?;

    let outcome = apply(&mut case, input, &FramingKind::FixedSize { bytes: 2 })?;

    assert_eq!(
        outcome,
        FramingOutcome {
            receipt_node: outcome.receipt_node,
            frame_nodes: outcome.frame_nodes.clone(),
            tail_node: None,
            status: BoundaryStatus::Complete,
        }
    );
    assert_eq!(outcome.frame_nodes.len(), 2);
    assert!(case.nodes().iter().any(|node| {
        node.id == outcome.receipt_node && node.kind == "custom_protocol_framing_receipt"
    }));
    let receipt = case
        .nodes()
        .iter()
        .find(|node| node.id == outcome.receipt_node)
        .ok_or("framing receipt is missing")?;
    let caller_basis = json!({"kind":"caller_supplied"});
    assert_eq!(receipt.details.get("selection_basis"), Some(&caller_basis));
    assert!(receipt.details.get("interpretation").is_none());
    let receipt_blob = case
        .blob(receipt.blob.as_deref().ok_or("receipt blob is missing")?)
        .ok_or("receipt blob is not retained")?;
    let receipt_json: serde_json::Value = serde_json::from_slice(&receipt_blob.bytes)?;
    assert_eq!(receipt_json.get("selection_basis"), Some(&caller_basis));
    assert!(receipt_json.get("interpretation").is_none());
    for (index, frame_id) in outcome.frame_nodes.iter().enumerate() {
        let frame = case
            .nodes()
            .iter()
            .find(|node| node.id == *frame_id)
            .ok_or("materialized frame is missing")?;
        assert_eq!(frame.details.get("framing_schema_version"), Some(&json!(2)));
        assert_eq!(frame.details.get("stream_start"), Some(&json!(index * 2)));
        assert_eq!(
            frame.details.get("stream_end"),
            Some(&json!((index + 1) * 2))
        );
        assert!(frame.details.get("framing_rule").is_none());
        assert!(frame.details.get("selection_basis").is_none());
        assert!(case.edges().iter().any(|edge| {
            edge.from == outcome.receipt_node
                && edge.to == *frame_id
                && edge.relation == "materialized"
                && edge.status == EvidenceStatus::Observed
        }));
        assert!(frame.details.get("interpretation").is_none());
    }
    Ok(())
}

#[test]
fn failure_is_atomic() -> Result<(), Box<dyn Error>> {
    let (mut case, _) = tcp_run(b"message")?;
    let before = case.try_clone()?;

    assert!(apply(&mut case, u64::MAX, &FramingKind::Delimiter { byte: b'\n' },).is_err());
    assert_eq!(case, before);
    Ok(())
}

#[test]
fn selection_basis_has_stable_typed_json() -> Result<(), Box<dyn Error>> {
    let caller_basis = FramingSelectionBasis::CallerSupplied {};
    let discovered_basis = FramingSelectionBasis::Discovered { report_node: 17 };
    let combined_basis = FramingSelectionBasis::CallerAndDiscovered { report_node: 18 };
    assert_eq!(
        serde_json::to_value(caller_basis)?,
        json!({"kind":"caller_supplied"})
    );
    assert_eq!(
        serde_json::to_value(discovered_basis)?,
        json!({"kind":"discovered","report_node":17})
    );
    assert_eq!(
        serde_json::to_value(combined_basis)?,
        json!({"kind":"caller_and_discovered","report_node":18})
    );
    assert_eq!(
        serde_json::from_value::<FramingSelectionBasis>(json!({"kind":"caller_supplied"}))?,
        caller_basis
    );
    assert_eq!(
        serde_json::from_value::<FramingSelectionBasis>(
            json!({"kind":"discovered","report_node":17})
        )?,
        discovered_basis
    );
    assert_eq!(
        serde_json::from_value::<FramingSelectionBasis>(
            json!({"kind":"caller_and_discovered","report_node":18})
        )?,
        combined_basis
    );
    assert!(
        serde_json::from_value::<FramingSelectionBasis>(
            json!({"kind":"caller_supplied","unexpected":true})
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<FramingSelectionBasis>(
            json!({"kind":"caller_and_discovered","report_node":18,"unexpected":true})
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn discovered_selection_is_related_to_report_without_making_it_a_byte_parent()
-> Result<(), Box<dyn Error>> {
    let (mut case, input) = tcp_run(b"aabb")?;
    let rule = FramingKind::FixedSize { bytes: 2 };
    let report = add_discovery_report(&mut case, &rule)?;

    let outcome = apply_with_basis(
        &mut case,
        input,
        &rule,
        FramingSelectionBasis::Discovered {
            report_node: report,
        },
    )?;

    let basis = json!({"kind":"discovered","report_node":report});
    let receipt = case
        .nodes()
        .iter()
        .find(|node| node.id == outcome.receipt_node)
        .ok_or("framing receipt is missing")?;
    assert_eq!(receipt.details.get("selection_basis"), Some(&basis));
    let receipt_blob = case
        .blob(receipt.blob.as_deref().ok_or("receipt blob is missing")?)
        .ok_or("receipt blob is not retained")?;
    let receipt_json: serde_json::Value = serde_json::from_slice(&receipt_blob.bytes)?;
    assert_eq!(receipt_json.get("selection_basis"), Some(&basis));
    assert!(case.edges().iter().any(|edge| {
        edge.from == report
            && edge.to == outcome.receipt_node
            && edge.relation == "framing_rule_selected_from"
            && edge.status == l2_workbench::evidence::EvidenceStatus::Observed
    }));
    for frame_id in &outcome.frame_nodes {
        let frame = case
            .nodes()
            .iter()
            .find(|node| node.id == *frame_id)
            .ok_or("materialized frame is missing")?;
        assert!(frame.details.get("selection_basis").is_none());
        assert!(frame.details.get("framing_rule").is_none());
        assert!(case.edges().iter().any(|edge| {
            edge.from == outcome.receipt_node
                && edge.to == *frame_id
                && edge.relation == "materialized"
        }));
        assert_eq!(frame.details.get("input_node"), Some(&json!(input)));
        assert!(
            !case
                .edges()
                .iter()
                .any(|edge| { edge.from == report && edge.to == *frame_id })
        );
    }
    Ok(())
}

#[test]
fn discovered_basis_accepts_compact_reports_without_hypothesis_details()
-> Result<(), Box<dyn Error>> {
    let (mut case, input) = tcp_run(b"aabb")?;
    let report = add_compact_discovery_report(&mut case)?;

    let outcome = apply_with_basis(
        &mut case,
        input,
        &FramingKind::FixedSize { bytes: 2 },
        FramingSelectionBasis::Discovered {
            report_node: report,
        },
    )?;

    assert_eq!(outcome.frame_nodes.len(), 2);
    Ok(())
}

#[test]
fn caller_and_discovered_basis_keeps_report_as_selection_provenance_only()
-> Result<(), Box<dyn Error>> {
    let (mut case, input) = tcp_run(b"aabb")?;
    let rule = FramingKind::FixedSize { bytes: 2 };
    let report = add_discovery_report(&mut case, &rule)?;
    let basis = FramingSelectionBasis::CallerAndDiscovered {
        report_node: report,
    };

    let outcome = apply_with_basis(&mut case, input, &rule, basis)?;

    let encoded_basis = json!({"kind":"caller_and_discovered","report_node":report});
    let receipt = case
        .nodes()
        .iter()
        .find(|node| node.id == outcome.receipt_node)
        .ok_or("framing receipt is missing")?;
    assert_eq!(receipt.details.get("selection_basis"), Some(&encoded_basis));
    let receipt_blob = case
        .blob(receipt.blob.as_deref().ok_or("receipt blob is missing")?)
        .ok_or("receipt blob is not retained")?;
    let receipt_json: serde_json::Value = serde_json::from_slice(&receipt_blob.bytes)?;
    assert_eq!(receipt_json.get("selection_basis"), Some(&encoded_basis));
    assert!(case.edges().iter().any(|edge| {
        edge.from == report
            && edge.to == receipt.id
            && edge.relation == "framing_rule_selected_from"
    }));
    for frame_id in outcome.frame_nodes {
        let frame = case
            .nodes()
            .iter()
            .find(|node| node.id == frame_id)
            .ok_or("materialized frame is missing")?;
        assert!(frame.details.get("selection_basis").is_none());
        assert!(frame.details.get("framing_rule").is_none());
        assert!(case.edges().iter().any(|edge| {
            edge.from == outcome.receipt_node
                && edge.to == frame_id
                && edge.relation == "materialized"
        }));
        assert_eq!(frame.details.get("input_node"), Some(&json!(input)));
        assert!(
            case.edges()
                .iter()
                .all(|edge| edge.from != report || edge.to != frame_id)
        );
    }
    Ok(())
}

#[test]
fn invalid_discovery_report_identity_fails_atomically() -> Result<(), Box<dyn Error>> {
    let (mut case, input) = tcp_run(b"aabb")?;
    let before = case.try_clone()?;

    assert!(
        apply_with_basis(
            &mut case,
            input,
            &FramingKind::FixedSize { bytes: 2 },
            FramingSelectionBasis::Discovered { report_node: input },
        )
        .is_err()
    );
    assert_eq!(case, before);
    Ok(())
}

#[test]
fn discovered_materialization_is_atomic_when_selection_edge_exceeds_quota()
-> Result<(), Box<dyn Error>> {
    let (mut case, input) = tcp_run(b"aabb")?;
    let rule = FramingKind::FixedSize { bytes: 2 };
    let report = add_discovery_report(&mut case, &rule)?;
    fill_edges_to(&mut case, input, MAX_EDGES - 5)?;
    let before = case.try_clone()?;

    assert!(
        apply_with_basis(
            &mut case,
            input,
            &rule,
            FramingSelectionBasis::Discovered {
                report_node: report
            },
        )
        .is_err()
    );
    assert_eq!(case, before);
    Ok(())
}

fn add_discovery_report(case: &mut Case, rule: &FramingKind) -> Result<u64, Box<dyn Error>> {
    let report = json!({
        "version":1,
        "case_scope":"current_case",
        "source_id":"fixture-source",
        "cohort":{"scope":"fixture"},
        "bootstrap":{"hypotheses":[rule]}
    });
    let report_bytes = serde_json::to_vec(&report)?;
    Ok(case.add_bytes_node(
        "recovery_framing_discovery_report",
        &report_bytes,
        Vec::new(),
        json!({"report_schema_version":1}),
    )?)
}

fn add_compact_discovery_report(case: &mut Case) -> Result<u64, Box<dyn Error>> {
    let report = json!({
        "version":1,
        "case_scope":"current_case",
        "source_id":"fixture-source",
        "cohort":{"scope":"fixture"},
        "bootstrap_summary":{"hypothesis_count":1,"hypotheses_omitted":1},
        "report_truncated":true
    });
    let report_bytes = serde_json::to_vec(&report)?;
    Ok(case.add_bytes_node(
        "recovery_framing_discovery_report",
        &report_bytes,
        Vec::new(),
        json!({"report_schema_version":1}),
    )?)
}

fn fill_edges_to(case: &mut Case, from: u64, edge_count: usize) -> Result<(), Box<dyn Error>> {
    let target = case.add_node("quota_target", None, Vec::new(), json!({}))?;
    while case.edges().len() < edge_count {
        let index = case.edges().len();
        case.add_edge(Edge {
            from,
            to: target,
            relation: format!("quota_filler_{index}"),
            status: EvidenceStatus::Observed,
            reason: "Synthetic relationship occupies one evidence slot".to_owned(),
        })?;
    }
    Ok(())
}

fn tcp_run(bytes: &[u8]) -> Result<(Case, u64), Box<dyn Error>> {
    let mut case = Case::new();
    let source = case.add_source(
        "capture.pcap",
        "capture",
        u64::try_from(bytes.len())?,
        &l2_workbench::sha256(b"framing service fixture"),
        None,
    )?;
    let mapping = ByteMapping {
        offset: 0,
        range: SourceRange {
            source,
            packet: Some(1),
            offset: 0,
            length: u64::try_from(bytes.len())?,
        },
    };
    let node = case.add_mapped_bytes_node("tcp_byte_run", bytes, &[mapping], json!({}))?;
    Ok((case, node))
}
