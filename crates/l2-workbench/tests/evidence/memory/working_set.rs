use l2_workbench::{
    evidence::Case,
    job::{MemoryBudget, MemoryError},
};
use serde_json::json;
use std::error::Error;

#[test]
fn existing_case_moves_into_a_working_set_without_a_second_global_charge()
-> Result<(), Box<dyn Error>> {
    let root = MemoryBudget::new(4 * 1024 * 1024);
    let mut case = Case::with_memory_budget(&root)?;
    case.add_bytes_node("original", b"retained bytes", Vec::new(), json!({}))?;
    let original = case.to_json()?;
    let work = root.try_working_set(1024 * 1024)?;
    let before = root.snapshot()?;
    case.use_working_set(&work)?;
    assert_eq!(root.snapshot()?, before);
    assert_eq!(case.to_json()?, original);
    drop(work);
    assert_eq!(root.snapshot()?.working_sets.reserved_bytes, 0);
    assert!(root.snapshot()?.used_bytes > 0);
    drop(case);
    assert_eq!(root.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn uncharged_case_is_admitted_before_entering_a_working_set() -> Result<(), Box<dyn Error>> {
    let root = MemoryBudget::new(4 * 1024 * 1024);
    let mut case = Case::new();
    case.add_bytes_node("original", b"retained bytes", Vec::new(), json!({}))?;
    let original = case.to_json()?;
    let work = root.try_working_set(1024 * 1024)?;
    let before = root.snapshot()?;
    case.use_working_set(&work)?;
    let after = root.snapshot()?;
    assert_eq!(
        after.used_bytes - before.used_bytes,
        case.charged_memory_bytes()
            .ok_or("Case memory was not attached")?
    );
    assert_eq!(
        after.working_sets.reserved_bytes,
        before.working_sets.reserved_bytes
    );
    assert_eq!(case.to_json()?, original);
    drop(case);
    drop(work);
    assert_eq!(root.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn unrelated_budget_cannot_take_case_memory_ownership() -> Result<(), Box<dyn Error>> {
    let original_budget = MemoryBudget::new(4 * 1024 * 1024);
    let other_budget = MemoryBudget::new(4 * 1024 * 1024);
    let mut case = Case::with_memory_budget(&original_budget)?;
    case.add_bytes_node("original", b"retained bytes", Vec::new(), json!({}))?;
    let work = other_budget.try_working_set(1024 * 1024)?;
    let before = original_budget.snapshot()?;
    let error = case
        .use_working_set(&work)
        .err()
        .ok_or("unrelated budget was accepted")?;
    assert!(matches!(
        error,
        l2_workbench::evidence::EvidenceError::Memory(MemoryError::IncompatibleWorkingSet)
    ));
    assert_eq!(original_budget.snapshot()?, before);
    drop(case);
    drop(work);
    assert_eq!(original_budget.snapshot()?.used_bytes, 0);
    assert_eq!(other_budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn case_admission_accounts_existing_data_and_rejects_another_ledger() -> Result<(), Box<dyn Error>>
{
    let root = MemoryBudget::new(4 * 1024 * 1024);
    let foreign = MemoryBudget::new(4 * 1024 * 1024);
    let mut case = Case::new();
    case.add_bytes_node("original", b"retained bytes", Vec::new(), json!({}))?;
    let expected = case.to_json()?;

    case.admit_memory_budget(&root)?;
    let charge = case.charged_memory_bytes().ok_or("Case was not charged")?;
    assert!(charge > 0);
    assert_eq!(root.snapshot()?.used_bytes, charge);
    // A worker on the same ledger may read the native Case without charging it twice
    let worker = root.try_working_set(1024)?;
    case.admit_memory_budget(worker.budget())?;
    assert!(matches!(
        case.admit_memory_budget(&foreign),
        Err(l2_workbench::evidence::EvidenceError::Memory(
            MemoryError::IncompatibleWorkingSet
        ))
    ));
    assert_eq!(case.to_json()?, expected);
    assert_eq!(foreign.snapshot()?.used_bytes, 0);
    drop(worker);
    drop(case);
    assert_eq!(root.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn failed_case_admission_keeps_the_original_case_uncharged() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    case.add_bytes_node("original", b"retained bytes", Vec::new(), json!({}))?;
    let original = case.to_json()?;
    let budget = MemoryBudget::new(1);
    assert!(matches!(
        case.admit_memory_budget(&budget),
        Err(l2_workbench::evidence::EvidenceError::Memory(
            MemoryError::Limit { .. }
        ))
    ));
    assert_eq!(case.to_json()?, original);
    assert_eq!(case.charged_memory_bytes(), None);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}
