use l2_workbench::{
    evidence::{Case, CaseSnapshotLimits, Edge, EvidenceError, EvidenceStatus},
    job::{MemoryBudget, MemoryClass, MemoryError},
};
use serde_json::json;
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

fn edge(from: u64, to: u64, status: EvidenceStatus, reason: &str) -> Edge {
    Edge {
        from,
        to,
        relation: "supports".to_owned(),
        status,
        reason: reason.to_owned(),
    }
}

fn contains(case: &Case, edge: &Edge) -> bool {
    case.contains_exact_edge(
        edge.from,
        edge.to,
        &edge.relation,
        edge.status,
        &edge.reason,
    )
}

#[test]
fn exact_edge_index_distinguishes_status_reason_and_endpoints() -> TestResult {
    let mut case = Case::new();
    let first = case.add_node("first", None, Vec::new(), json!({}))?;
    let second = case.add_node("second", None, Vec::new(), json!({}))?;
    let observed = edge(first, second, EvidenceStatus::Observed, "first reason");
    let alternate = edge(first, second, EvidenceStatus::Observed, "second reason");
    let hypothesis = edge(first, second, EvidenceStatus::Hypothesis, "first reason");
    case.add_edge(observed.clone())?;
    case.add_edge(observed.clone())?;
    case.add_edge(alternate.clone())?;
    case.add_edge(hypothesis.clone())?;

    assert!(contains(&case, &observed));
    assert!(contains(&case, &alternate));
    assert!(contains(&case, &hypothesis));
    assert!(!contains(
        &case,
        &edge(first, second, EvidenceStatus::Observed, "unknown")
    ));
    assert!(!contains(
        &case,
        &edge(second, first, EvidenceStatus::Observed, "first reason")
    ));
    let mut wrong_relation = observed;
    wrong_relation.relation = "contradicts".to_owned();
    assert!(!contains(&case, &wrong_relation));
    assert_eq!(case.edges().len(), 4);
    Ok(())
}

#[test]
fn exact_edge_index_restores_duplicates_and_reasons_after_nested_rollback() -> TestResult {
    let mut case = Case::new();
    let first = case.add_node("first", None, Vec::new(), json!({}))?;
    let second = case.add_node("second", None, Vec::new(), json!({}))?;
    let original = edge(first, second, EvidenceStatus::Observed, "original");
    let temporary = edge(first, second, EvidenceStatus::Observed, "temporary");
    let nested = edge(first, second, EvidenceStatus::Hypothesis, "nested");
    case.add_edge(original.clone())?;
    let result = case.transaction(|case| {
        case.add_edge(original.clone())?;
        case.add_edge(temporary.clone())?;
        let inner = case.transaction(|case| {
            case.add_edge(nested.clone())?;
            assert!(contains(case, &nested));
            Err::<(), _>(EvidenceError::InvalidJson)
        });
        assert_eq!(inner, Err(EvidenceError::InvalidJson));
        assert!(!contains(case, &nested));
        assert!(contains(case, &temporary));
        Err::<(), _>(EvidenceError::InvalidJson)
    });
    assert_eq!(result, Err(EvidenceError::InvalidJson));
    assert!(contains(&case, &original));
    assert!(!contains(&case, &temporary));
    assert!(!contains(&case, &nested));
    assert_eq!(case.edges().len(), 1);
    Ok(())
}

#[test]
fn exact_edge_index_rebuilds_after_json_and_budgeted_snapshot_restore() -> TestResult {
    let budget = MemoryBudget::new(1_000_000);
    let mut case = Case::with_memory_budget(&budget)?;
    let first = case.add_node("first", None, Vec::new(), json!({}))?;
    let second = case.add_node("second", None, Vec::new(), json!({}))?;
    let retained = edge(first, second, EvidenceStatus::Observed, "retained");
    case.add_edge(retained.clone())?;
    case.add_edge(edge(first, second, EvidenceStatus::Observed, "alternate"))?;

    let copied = case.try_clone()?;
    assert!(contains(&copied, &retained));
    assert_eq!(copied, case);
    drop(copied);

    let decoded = Case::from_json(&case.to_json()?)?;
    assert!(contains(&decoded, &retained));
    assert_eq!(decoded, case);
    let limits = CaseSnapshotLimits::new(1_000_000, 1_000_000);
    let mut graph = Vec::new();
    let mut blobs = Vec::new();
    case.write_snapshot(&mut graph, &mut blobs, limits)?;
    let (restored, _) =
        Case::from_snapshot_with_memory(graph.as_slice(), blobs.as_slice(), limits, &budget)?;
    assert!(contains(&restored, &retained));
    assert_eq!(restored, case);
    drop(restored);
    drop(case);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn exact_edge_index_remains_unchanged_when_shared_growth_is_denied() -> TestResult {
    let budget = MemoryBudget::new(100_000);
    let mut case = Case::with_memory_budget(&budget)?;
    let first = case.add_node("first", None, Vec::new(), json!({}))?;
    let second = case.add_node("second", None, Vec::new(), json!({}))?;
    let retained = edge(first, second, EvidenceStatus::Observed, "retained");
    case.add_edge(retained.clone())?;
    let used = budget.snapshot()?.used_bytes;
    let blocker = budget.try_reserve(MemoryClass::Executor, 100_000 - used)?;
    let before = case.to_json()?;
    let denied = edge(first, second, EvidenceStatus::Observed, "new reason");
    assert!(matches!(
        case.add_edge(denied.clone()),
        Err(EvidenceError::Memory(MemoryError::Limit { .. }))
    ));
    assert!(contains(&case, &retained));
    assert!(!contains(&case, &denied));
    assert_eq!(case.to_json()?, before);
    drop(blocker);
    drop(case);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}
