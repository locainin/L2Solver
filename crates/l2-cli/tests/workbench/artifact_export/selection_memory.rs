use std::error::Error;

use l2_workbench::{
    evidence::Case,
    job::{MemoryBudget, MemoryClass, MemoryError},
};
use serde_json::json;

type TestResult = Result<(), Box<dyn Error>>;

fn case_with_shared_records(budget: &MemoryBudget) -> Result<Case, Box<dyn Error>> {
    let mut case = Case::with_memory_budget(budget)?;
    let first = case.add_bytes_node("record_object", b"recoverable text", Vec::new(), json!({}))?;
    let blob = case
        .node(first)
        .and_then(|node| node.blob.clone())
        .ok_or("shared blob is missing")?;
    for _ in 1..32 {
        case.add_node("record_object", Some(&blob), Vec::new(), json!({}))?;
    }
    Ok(case)
}

#[test]
fn selected_provenance_stays_charged_until_selection_drops() -> TestResult {
    let budget = MemoryBudget::new(1024 * 1024);
    let case = case_with_shared_records(&budget)?;
    let baseline = budget.snapshot()?.used_bytes;
    let selected = super::super::select_artifacts(&case, Some(&budget))?;
    let artifact = selected.first().ok_or("selected artifact is missing")?;

    assert_eq!(selected.len(), 1);
    assert_eq!(artifact.bytes(), b"recoverable text");
    assert_eq!(artifact.provenance().len(), 32);
    assert!(
        budget.snapshot()?.used(MemoryClass::Publication) > 0,
        "selected provenance was not charged"
    );
    drop(selected);
    assert_eq!(budget.snapshot()?.used_bytes, baseline);
    drop(case);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn selection_rejects_a_full_shared_budget_without_leaking_charges() -> TestResult {
    let budget = MemoryBudget::new(1024 * 1024);
    let case = case_with_shared_records(&budget)?;
    let baseline = budget.snapshot()?.used_bytes;
    let blocker = budget.try_reserve(
        MemoryClass::Cache,
        budget.snapshot()?.limit_bytes - baseline,
    )?;
    let error = super::super::select_artifacts(&case, Some(&budget))
        .err()
        .ok_or("selection ignored the shared memory limit")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::Limit { .. })
    ));
    drop(blocker);
    assert_eq!(budget.snapshot()?.used_bytes, baseline);
    drop(case);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn selection_releases_partial_provenance_after_memory_refusal() -> TestResult {
    let budget = MemoryBudget::new(1024 * 1024);
    let case = case_with_shared_records(&budget)?;
    let baseline = budget.snapshot()?.used_bytes;
    let blocker = budget.try_reserve(
        MemoryClass::Cache,
        budget.snapshot()?.limit_bytes - baseline - 1024,
    )?;
    let before = budget.snapshot()?.used_bytes;
    let error = super::super::select_artifacts(&case, Some(&budget))
        .err()
        .ok_or("selection ignored pressure while retaining provenance")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::Limit { .. })
    ));
    assert!(budget.snapshot()?.peak_bytes > before);
    drop(blocker);
    assert_eq!(budget.snapshot()?.used_bytes, baseline);
    drop(case);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}
