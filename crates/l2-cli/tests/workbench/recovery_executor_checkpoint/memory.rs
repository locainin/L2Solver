use super::*;
use l2_workbench::job::{MemoryBudget, MemoryError};

#[test]
fn restored_case_index_admits_derived_entries_and_releases_the_charge() -> Result<(), Box<dyn Error>>
{
    use l2_workbench::job::MemoryClass;
    use serde_json::json;

    let mut case = Case::new();
    for input in 1..=64 {
        case.add_bytes_node(
            "decoding_output",
            b"shared decoded bytes",
            Vec::new(),
            json!({"shared_transform_receipt": 1, "source_input_node": input}),
        )?;
    }
    let source = CaseIndex::new(&case)?;
    let cursor = source.checkpoint_cursor();
    let denied = MemoryBudget::new(0);
    let error = CaseIndex::restore_from_checkpoint(&case, cursor, Some(&denied))
        .err()
        .ok_or("the Case index ignored its memory budget")?;
    assert!(matches!(
        crate::memory_error::find(&error),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(denied.snapshot()?.used_bytes, 0);

    let budget = MemoryBudget::new(1024 * 1024);
    let restored = CaseIndex::restore_from_checkpoint(&case, cursor, Some(&budget))?;
    assert_eq!(restored.contextual_decoding_views.len(), 64);
    assert!(budget.snapshot()?.used(MemoryClass::Executor) > 0);
    drop(restored);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn loaded_work_metadata_stays_admitted_while_the_resume_session_is_live()
-> Result<(), Box<dyn Error>> {
    use crate::arguments::RecoveryOptions;
    use crate::workbench::recovery_executor::{JobProgress, resume::RecoveryResume};
    use l2_workbench::job::{
        Counter, Job, MemoryClass,
        cache::{Cache, SourceIdentity, StageKey},
    };
    use serde_json::json;

    let temporary = tempfile::tempdir()?;
    let options = RecoveryOptions {
        memory_limit: 64 * 1024 * 1024,
        cache_max_bytes: 128 * 1024 * 1024,
        ..RecoveryOptions::default()
    };
    let memory = MemoryBudget::new(options.memory_limit);
    let cache = Cache::open_at_with_memory_budget(
        temporary.path().join("cache"),
        temporary.path().join("state"),
        options.cache_max_bytes,
        memory.clone(),
    )?;
    let key = StageKey::new(
        "loaded_work_memory",
        1,
        "loaded_work_memory",
        &json!({}),
        &SourceIdentity::from_sha256("d".repeat(64))?,
        &[],
    )?;
    let job = Job::with_memory_budget("loaded work memory", &memory);
    let scope = job.work_scope(key.as_str())?;
    scope.increment(Counter::CandidatesExamined, 7)?;
    let mut case = Case::with_memory_budget(&memory)?;
    let plan = RecoveryPlan::default();
    let policy = normal_policy(&case)?;
    let mut lease = cache.lease(&key)?;
    let mut resume = RecoveryResume::new(&mut lease, &options, Some(&memory));
    resume.prepare(&mut case)?;
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    executor.job = Some(JobProgress::new(scope));
    executor.memory = Some(memory.clone());
    resume.save(&executor, &SchedulerCursor::default())?;
    drop(executor);
    let loaded = resume.load()?.ok_or("checkpoint missing")?;
    assert_eq!(
        loaded
            .work
            .as_ref()
            .ok_or("work metadata missing")?
            .counter(Counter::CandidatesExamined),
        7
    );
    assert!(memory.snapshot()?.used(MemoryClass::Executor) > loaded.state_memory.bytes());
    drop(loaded);
    assert!(memory.snapshot()?.used(MemoryClass::Executor) > 0);
    drop(resume);
    assert_eq!(memory.snapshot()?.used(MemoryClass::Executor), 0);
    Ok(())
}

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
    assert_ne!(output.len(), 0);
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
