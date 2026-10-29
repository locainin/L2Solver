use super::*;
use crate::arguments::RecoveryOptions;
use crate::workbench::recovery_executor::{
    RecoveryOmission, execution_state::SchedulerPhase, recover_case_with_job,
    resume::RecoveryResume,
};
use l2_workbench::job::{
    MemoryBudget,
    cache::{Cache, SourceIdentity, StageKey},
};
use serde_json::json;

fn omission() -> RecoveryOmission {
    RecoveryOmission::RelationalIncrementalMetadata {
        limit: 4_096,
        reason: "retained checkpoint detail ".repeat(128).into(),
    }
}

#[test]
fn restored_outcome_keeps_its_memory_charge_until_it_is_dropped() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let plan = RecoveryPlan::default();
    let policy = normal_policy(&case)?;
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    executor.omissions.push(omission());
    let mut bytes = Vec::new();
    checkpoint::write(
        &executor,
        &SchedulerCursor::default(),
        &mut bytes,
        1024 * 1024,
    )?;
    drop(executor);

    let budget = MemoryBudget::new(16 * 1024 * 1024);
    let (restored, _) = checkpoint::read(
        &mut case,
        &plan,
        &policy,
        &bytes,
        1024 * 1024,
        Some(&budget),
    )?;
    assert!(budget.snapshot()?.used_bytes > 0);
    let outcome = finish_executor(restored)?;
    assert_eq!(outcome.omissions.len(), 1);
    assert!(
        budget.snapshot()?.used_bytes > 0,
        "the restored omission still owns checkpoint memory"
    );
    drop(outcome);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn restored_cursor_keeps_its_memory_charge_after_the_executor_is_dropped()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let root = case.add_bytes_node("http_body", b"4142", Vec::new(), json!({}))?;
    let plan = RecoveryPlan::default();
    let policy = normal_policy(&case)?;
    let executor = test_support::build_executor(&mut case, &plan, &policy)?;
    let mut cursor = SchedulerCursor::default();
    cursor.phase = SchedulerPhase::Seeding {
        roots: vec![(root, "http_body".to_owned())],
        next: 0,
    };
    let mut bytes = Vec::new();
    checkpoint::write(&executor, &cursor, &mut bytes, 1024 * 1024)?;
    drop(executor);

    let budget = MemoryBudget::new(16 * 1024 * 1024);
    let (restored, cursor) = checkpoint::read(
        &mut case,
        &plan,
        &policy,
        &bytes,
        1024 * 1024,
        Some(&budget),
    )?;
    drop(restored);
    assert!(
        budget.snapshot()?.used_bytes > 0,
        "the restored cursor still owns checkpoint data"
    );
    assert!(matches!(&cursor.phase, SchedulerPhase::Seeding { .. }));
    drop(cursor);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn restored_summary_keeps_its_memory_charge_through_coverage() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let options = RecoveryOptions {
        memory_limit: 64 * 1024 * 1024,
        cache_max_bytes: 128 * 1024 * 1024,
        strict_cache: true,
        ..RecoveryOptions::default()
    };
    let key = StageKey::new(
        "summary_checkpoint_memory",
        1,
        "summary_checkpoint_memory",
        &json!({}),
        &SourceIdentity::from_sha256("d".repeat(64))?,
        &[],
    )?;
    let cache = Cache::open_at(
        temporary.path().join("cache"),
        temporary.path().join("state"),
        options.cache_max_bytes,
    )?;
    let mut original = Case::new();
    let plan = RecoveryPlan {
        discover_transforms: true,
        discover_framing: true,
        discover_records: true,
        ..RecoveryPlan::default()
    };
    let policy =
        super::super::policy::policy_for_profile(&original, options.profile, options.memory_limit)?;
    {
        let mut lease = cache.lease(&key)?;
        let mut resume = RecoveryResume::new(&mut lease, &options, None);
        resume.prepare(&original)?;
        let mut executor = test_support::build_executor(&mut original, &plan, &policy)?;
        executor.omissions.push(omission());
        let mut cursor = SchedulerCursor::default();
        cursor.phase = SchedulerPhase::Finished;
        resume.save(&executor, &cursor)?;
    }

    let budget = MemoryBudget::new(64 * 1024 * 1024);
    let mut native = Case::new();
    let mut lease = cache.lease(&key)?;
    let mut resume = RecoveryResume::new(&mut lease, &options, Some(&budget));
    let summary = recover_case_with_job(
        &mut native,
        options.profile,
        options.memory_limit,
        None,
        Some(&budget),
        Some(&mut resume),
    )?;
    assert_eq!(summary.omissions().len(), 1);
    let while_summary_is_live = budget.snapshot()?.used_bytes;
    drop(summary);
    let after_summary_is_dropped = budget.snapshot()?.used_bytes;
    assert!(
        while_summary_is_live > after_summary_is_dropped,
        "restored omissions must stay admitted through summary consumption"
    );
    eprintln!(
        "checkpoint bytes retained by the recovery summary: {}",
        while_summary_is_live - after_summary_is_dropped
    );
    Ok(())
}

#[test]
fn invalid_checkpoint_releases_admission_and_preserves_the_case() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let plan = RecoveryPlan::default();
    let policy = normal_policy(&case)?;
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    executor.omissions.push(omission());
    let mut bytes = Vec::new();
    checkpoint::write(
        &executor,
        &SchedulerCursor::default(),
        &mut bytes,
        1024 * 1024,
    )?;
    drop(executor);
    let original = case.to_json()?;
    let mut invalid: serde_json::Value = serde_json::from_slice(&bytes)?;
    *invalid
        .get_mut("version")
        .ok_or("checkpoint version is missing")? = json!(99);
    let bytes = serde_json::to_vec(&invalid)?;
    let budget = MemoryBudget::new(16 * 1024 * 1024);
    assert!(
        checkpoint::read(
            &mut case,
            &plan,
            &policy,
            &bytes,
            1024 * 1024,
            Some(&budget),
        )
        .is_err()
    );
    assert_eq!(case.to_json()?, original);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn invalid_restored_cursor_releases_admission_and_preserves_the_case() -> Result<(), Box<dyn Error>>
{
    let mut case = Case::new();
    let plan = RecoveryPlan::default();
    let policy = normal_policy(&case)?;
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    executor.omissions.push(omission());
    let mut cursor = SchedulerCursor::default();
    cursor.phase = SchedulerPhase::Seeding {
        roots: Vec::new(),
        next: 1,
    };
    let mut bytes = Vec::new();
    checkpoint::write(&executor, &cursor, &mut bytes, 1024 * 1024)?;
    drop(executor);

    let original = case.to_json()?;
    let budget = MemoryBudget::new(16 * 1024 * 1024);
    assert!(
        checkpoint::read(
            &mut case,
            &plan,
            &policy,
            &bytes,
            1024 * 1024,
            Some(&budget),
        )
        .is_err()
    );
    assert_eq!(case.to_json()?, original);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}
