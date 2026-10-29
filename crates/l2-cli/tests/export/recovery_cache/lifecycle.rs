use super::{
    RecoveryCaseKind, RecoveryContext, RecoveryOptions, case_and_scope, open_cache, recover,
    recovery_key,
};
use l2_workbench::job::{
    Counter, Job,
    cache::{CacheReadPolicy, CheckpointStatus, StageStatus},
};
use serde_json::json;
use std::{error::Error, fs};

#[test]
fn terminal_recovery_with_incomplete_input_retires_its_checkpoint() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = open_cache(temporary.path())?;
    let options = RecoveryOptions::default();
    let (mut case, scope) = case_and_scope(b"4142", 117)?;
    case.mark_incomplete("the capture ended before this input was complete")?;
    let job = Job::new("terminal recovery with incomplete input");
    let result = recover(
        &mut case,
        RecoveryCaseKind::Flow,
        &scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: Some(&job),
            options: &options,
        },
    )?;
    assert!(!result.coverage.is_complete());
    assert_eq!(
        result
            .coverage
            .flow_cases_with_incomplete_case_evidence_collection,
        1
    );
    let key = recovery_key(RecoveryCaseKind::Flow, &scope, &options)?;
    assert_eq!(
        cache
            .read_checkpoint(&key)?
            .ok_or("missing checkpoint")?
            .status,
        CheckpointStatus::Complete,
        "finished policy work must release its resumable checkpoint"
    );
    {
        let entry = cache
            .lookup(&key, CacheReadPolicy::CompleteOnly)?
            .ok_or("the terminal search was not stored as a reusable result")?;
        assert_eq!(entry.status(), StageStatus::Complete);
    }
    let cleared = cache.clear()?;
    assert_eq!(cleared.removed_entries, 1);
    assert_eq!(cleared.skipped_checkpoints, 0);
    assert_eq!(cache.stats()?.entry_bytes, 0);
    Ok(())
}

#[test]
fn an_unfinished_stage_is_not_replayed_as_a_terminal_partial_result() -> Result<(), Box<dyn Error>>
{
    let temporary = tempfile::tempdir()?;
    let cache = open_cache(temporary.path())?;
    let options = RecoveryOptions::default();
    let (mut case, scope) = case_and_scope(b"4142", 119)?;
    case.mark_incomplete("the capture ended before this input was complete")?;
    let result = recover(
        &mut case,
        RecoveryCaseKind::Flow,
        &scope,
        &RecoveryContext {
            memory: None,
            cache: None,
            job: None,
            options: &options,
        },
    )?;
    assert!(!result.coverage.is_complete());
    let key = recovery_key(RecoveryCaseKind::Flow, &scope, &options)?;
    let lease = cache.lease(&key)?;
    fs::write(lease.directory().join("case.json"), case.to_json()?)?;
    drop(lease.commit(
        StageStatus::Partial,
        json!({"coverage":result.coverage,"omissions":result.omissions}),
    )?);

    let (mut fresh, _) = case_and_scope(b"4142", 119)?;
    fresh.mark_incomplete("the capture ended before this input was complete")?;
    let job = Job::new("unfinished recovery result must not be a cache hit");
    let result = recover(
        &mut fresh,
        RecoveryCaseKind::Flow,
        &scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: Some(&job),
            options: &options,
        },
    )?;
    assert!(!result.coverage.is_complete());
    let counters = job.snapshot()?.counters;
    assert_eq!(counters.get(&Counter::CacheHits), Some(&0));
    assert_eq!(counters.get(&Counter::CacheMisses), Some(&1));
    Ok(())
}
