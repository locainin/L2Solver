use super::*;
use crate::workbench::recovery_executor::lookup_fixture as fixture;
use std::error::Error;

type TestResult<T> = Result<T, Box<dyn Error>>;

struct FrameGraph {
    case: Case,
    input: u64,
    receipt: u64,
    frame: u64,
    report: u64,
}

fn frame_graph() -> TestResult<FrameGraph> {
    let mut case = Case::new();
    let input = case.add_node("tcp_byte_run", None, Vec::new(), json!({}))?;
    let receipt = case.add_node("framing_receipt", None, Vec::new(), json!({}))?;
    let frame = case.add_node("custom_protocol_frame", None, Vec::new(), json!({}))?;
    let report = case.add_node("framing_report", None, Vec::new(), json!({}))?;
    fixture::link(
        &mut case,
        receipt,
        frame,
        "materialized",
        EvidenceStatus::Observed,
    )?;
    fixture::link(
        &mut case,
        report,
        receipt,
        "framing_rule_selected_from",
        EvidenceStatus::Observed,
    )?;
    fixture::link(
        &mut case,
        input,
        receipt,
        "framing_tested_by",
        EvidenceStatus::Observed,
    )?;
    Ok(FrameGraph {
        case,
        input,
        receipt,
        frame,
        report,
    })
}

fn index(case: &Case) -> TestResult<(EdgeIndex, usize)> {
    Ok(index_edges(case, &index_nodes(case)?)?)
}

#[test]
fn unrelated_edges_do_not_allocate_record_link_tables_but_still_count_as_scan_work()
-> TestResult<()> {
    let mut case = Case::new();
    fixture::unrelated_edges(&mut case, "supports", 4_096)?;
    let (indexed, work) = index(&case)?;
    assert_eq!(indexed.receipt_parents_by_frame.capacity(), 0);
    assert_eq!(indexed.selection_report_parents_by_receipt.capacity(), 0);
    assert_eq!(indexed.framing_input_link_counts.capacity(), 0);
    assert!(work > case.edges().len());
    Ok(())
}

#[test]
fn record_link_capacity_tracks_relevant_keys_and_preserves_duplicate_observations() -> TestResult<()>
{
    let mut graph = frame_graph()?;
    let (baseline, _) = index(&graph.case)?;
    fixture::unrelated_edges(&mut graph.case, "supports", 4_096)?;
    fixture::link(
        &mut graph.case,
        graph.receipt,
        graph.frame,
        "materialized",
        EvidenceStatus::Hypothesis,
    )?;
    fixture::link(
        &mut graph.case,
        graph.input,
        graph.receipt,
        "framing_tested_by",
        EvidenceStatus::Observed,
    )?;
    fixture::link(
        &mut graph.case,
        graph.input,
        graph.receipt,
        "framing_tested_by",
        EvidenceStatus::Hypothesis,
    )?;
    let (indexed, _) = index(&graph.case)?;
    assert_eq!(
        indexed.receipt_parents_by_frame.capacity(),
        baseline.receipt_parents_by_frame.capacity()
    );
    assert_eq!(
        indexed.selection_report_parents_by_receipt.capacity(),
        baseline.selection_report_parents_by_receipt.capacity()
    );
    assert_eq!(
        indexed.framing_input_link_counts.capacity(),
        baseline.framing_input_link_counts.capacity()
    );
    assert_eq!(
        indexed
            .receipt_parents_by_frame
            .get(&graph.frame)
            .map(Vec::as_slice),
        Some(
            [
                (graph.receipt, EvidenceStatus::Observed),
                (graph.receipt, EvidenceStatus::Hypothesis)
            ]
            .as_slice()
        )
    );
    assert_eq!(
        indexed
            .selection_report_parents_by_receipt
            .get(&graph.receipt)
            .map(Vec::as_slice),
        Some([(graph.report, EvidenceStatus::Observed)].as_slice())
    );
    assert_eq!(
        indexed
            .framing_input_link_counts
            .get(&(graph.input, graph.receipt)),
        Some(&2)
    );
    Ok(())
}
