use super::{RegionMemoryError, TransformRegionLimits, propose_region_transforms_with_memory};
use crate::{
    derivation::Operation,
    job::{MemoryBudget, MemoryClass, MemoryError},
    recovery::proposals::TransformProposalBudget,
};
use std::error::Error;

fn proposals() -> TransformProposalBudget {
    TransformProposalBudget {
        max_candidates: 7,
        max_reports: 7,
    }
}

#[test]
fn region_scan_without_candidates_requires_no_heap_reservation() -> Result<(), Box<dyn Error>> {
    let input = [0x91, 0x92];
    let budget = MemoryBudget::new(1);
    let blocker = budget.try_reserve(MemoryClass::Cache, 1)?;
    let mut retained = budget.try_reserve(MemoryClass::Executor, 0)?;
    let report = propose_region_transforms_with_memory(
        &input,
        &[],
        TransformRegionLimits::for_input(input.len()),
        proposals(),
        &mut retained,
    )?;
    assert_eq!(report.regions.len(), 0);
    assert_eq!(retained.bytes(), 0);
    drop(report);
    drop(retained);
    drop(blocker);
    Ok(())
}

#[test]
fn region_candidate_memory_is_admitted_before_allocation() -> Result<(), Box<dyn Error>> {
    let input = b":4142:";
    let budget = MemoryBudget::new(1);
    let blocker = budget.try_reserve(MemoryClass::Cache, 1)?;
    let mut retained = budget.try_reserve(MemoryClass::Executor, 0)?;
    let result = propose_region_transforms_with_memory(
        input,
        &[],
        TransformRegionLimits::for_input(input.len()),
        proposals(),
        &mut retained,
    );
    assert!(matches!(
        result,
        Err(RegionMemoryError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(retained.bytes(), 0);
    drop(retained);
    drop(blocker);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn region_report_keeps_admitted_origins_and_recipes_live() -> Result<(), Box<dyn Error>> {
    let input = b":4142:";
    let budget = MemoryBudget::new(64 * 1024);
    let mut retained = budget.try_reserve(MemoryClass::Executor, 0)?;
    let report = propose_region_transforms_with_memory(
        input,
        &[],
        TransformRegionLimits::for_input(input.len()),
        proposals(),
        &mut retained,
    )?;
    let region = report.regions.first().ok_or("region missing")?;
    assert_eq!(region.cue_origins.len(), 2);
    assert!(region.proposal_report.proposals.iter().any(|proposal| {
        matches!(
            proposal.recipe.steps.as_slice(),
            [Operation::Slice { .. }, Operation::HexDecode {}]
        )
    }));
    assert!(retained.bytes() > 0);
    drop(report);
    drop(retained);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}
