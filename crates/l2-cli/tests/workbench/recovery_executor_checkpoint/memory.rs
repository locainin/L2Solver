use super::*;
use l2_workbench::job::{MemoryBudget, MemoryError};

#[test]
fn restored_checkpoint_metadata_keeps_its_charge_until_the_executor_is_dropped()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let plan = RecoveryPlan::default();
    let policy = normal_policy(&case)?;
    let executor = test_support::build_executor(&mut case, &plan, &policy)?;
    let mut bytes = Vec::new();
    checkpoint::write(
        &executor,
        &SchedulerCursor::default(),
        &mut bytes,
        1024 * 1024,
    )?;
    drop(executor);
    let budget = MemoryBudget::new(4 * 1024 * 1024);
    let (restored, _) = checkpoint::read(
        &mut case,
        &plan,
        &policy,
        &bytes,
        1024 * 1024,
        Some(&budget),
    )?;
    assert!(budget.snapshot()?.used_bytes > 0);
    drop(restored);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn checkpoint_reader_admits_owned_metadata_before_rebuilding_executor_state()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let plan = RecoveryPlan::default();
    let policy = normal_policy(&case)?;
    let executor = test_support::build_executor(&mut case, &plan, &policy)?;
    let mut output = Vec::new();
    checkpoint::write(
        &executor,
        &SchedulerCursor::default(),
        &mut output,
        1024 * 1024,
    )?;
    drop(executor);
    let original = case.to_json()?;
    let budget = MemoryBudget::new(0);
    let error = checkpoint::read(
        &mut case,
        &plan,
        &policy,
        &output,
        1024 * 1024,
        Some(&budget),
    )
    .err()
    .ok_or("checkpoint reader ignored the shared memory budget")?;
    assert!(matches!(
        crate::memory_error::find(&error),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(case.to_json()?, original);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn checkpoint_writer_charges_its_retained_coordinator_buffer_and_releases_it()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let plan = RecoveryPlan::default();
    let policy = normal_policy(&case)?;
    let budget = MemoryBudget::new(1024 * 1024);
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    executor.memory = Some(budget.clone());
    let mut output = Vec::new();
    checkpoint::write(
        &executor,
        &SchedulerCursor::default(),
        &mut output,
        1024 * 1024,
    )?;
    let usage = budget.snapshot()?;
    assert!(usage.peak_bytes > 0);
    assert_eq!(usage.used_bytes, 0);
    assert!(!output.is_empty());
    Ok(())
}

#[test]
fn checkpoint_writer_rejects_a_zero_budget_before_forwarding_any_output()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let plan = RecoveryPlan::default();
    let policy = normal_policy(&case)?;
    let budget = MemoryBudget::new(0);
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    executor.memory = Some(budget.clone());
    let mut output = b"original".to_vec();
    let error = checkpoint::write(
        &executor,
        &SchedulerCursor::default(),
        &mut output,
        1024 * 1024,
    )
    .err()
    .ok_or("checkpoint ignored the shared memory budget")?;
    assert!(matches!(
        crate::memory_error::find(&error),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(output, b"original");
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}
