use super::{ProposalMemoryError, TransformProposalBudget, propose_transforms_with_memory};
use crate::job::{MemoryBudget, MemoryClass, MemoryError};
use std::error::Error;

#[test]
fn proposal_without_retained_results_needs_no_heap_workspace() -> Result<(), Box<dyn Error>> {
    let budget = MemoryBudget::new(1);
    let blocker = budget.try_reserve(MemoryClass::Cache, 1)?;
    let mut retained = budget.try_reserve(MemoryClass::Executor, 0)?;
    let report = propose_transforms_with_memory(
        b"not encoded!",
        TransformProposalBudget {
            max_candidates: 0,
            max_reports: 0,
        },
        &mut retained,
    )?;
    assert_eq!(report.proposals.len(), 0);
    assert_eq!(report.assessments.len(), 0);
    assert_eq!(retained.bytes(), 0);
    drop(report);
    drop(retained);
    drop(blocker);
    Ok(())
}

#[test]
fn proposal_denies_memory_before_retaining_results_and_rolls_back() -> Result<(), Box<dyn Error>> {
    let budget = MemoryBudget::new(128);
    let blocker = budget.try_reserve(MemoryClass::Cache, 128)?;
    let mut retained = budget.try_reserve(MemoryClass::Executor, 0)?;
    let result = propose_transforms_with_memory(
        b"4142",
        TransformProposalBudget {
            max_candidates: 7,
            max_reports: 7,
        },
        &mut retained,
    );
    assert!(matches!(
        result,
        Err(ProposalMemoryError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(retained.bytes(), 0);
    drop(retained);
    drop(blocker);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn proposal_retains_only_the_memory_of_its_live_results() -> Result<(), Box<dyn Error>> {
    let budget = MemoryBudget::new(64 * 1024);
    let mut retained = budget.try_reserve(MemoryClass::Executor, 0)?;
    let report = propose_transforms_with_memory(
        b"4142",
        TransformProposalBudget {
            max_candidates: 7,
            max_reports: 7,
        },
        &mut retained,
    )?;
    assert_ne!(report.proposals.len(), 0);
    assert_eq!(report.assessments.len(), 7);
    assert!(retained.bytes() > 0);
    drop(report);
    drop(retained);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}
