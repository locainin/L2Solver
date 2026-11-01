use super::{
    CacheReadPolicy, Counter, Job, RecoveryCaseKind, RecoveryContext, RecoveryOptions,
    case_and_scope, open_cache, previous_recovery_key, recover, recovery_key,
};
use crate::workbench::{RecoveryResume, recover_case_with_job};
use l2_workbench::{
    evidence::Case,
    job::cache::{Cache, CheckpointStatus, SourceIdentity, StageKey},
};
use serde_json::json;
use std::error::Error;

#[test]
fn compact_record_evidence_does_not_replay_version_27_recovery_results()
-> Result<(), Box<dyn Error>> {
    assert_older_recovery_is_not_replayed(27)
}

#[test]
fn family_observation_policy_does_not_replay_version_28_recovery_results()
-> Result<(), Box<dyn Error>> {
    assert_older_recovery_is_not_replayed(28)
}

#[test]
fn execution_lifecycle_policy_does_not_replay_version_29_recovery_results()
-> Result<(), Box<dyn Error>> {
    assert_older_recovery_is_not_replayed(29)
}

#[test]
fn version_30_active_recovery_checkpoint_is_not_resumed_by_the_current_algorithm()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = open_cache(temporary.path())?;
    let options = RecoveryOptions::default();
    let (initial, scope) = case_and_scope(b"4142", 37)?;
    let old_key = previous_recovery_key(&scope, &options, 30)?;

    // Save a real scheduler generation under the old key without publishing a result
    checkpointed_recovery(&cache, &old_key, &options, initial.try_clone()?)?;
    assert_eq!(
        cache
            .read_checkpoint(&old_key)?
            .ok_or("missing old checkpoint")?
            .status,
        CheckpointStatus::Active
    );
    assert!(
        cache
            .lookup(&old_key, CacheReadPolicy::CompleteOnly)?
            .is_none()
    );

    // A same-key control proves that the stored generation is actually resumable
    let (control, control_job) =
        checkpointed_recovery(&cache, &old_key, &options, initial.try_clone()?)?;
    assert_eq!(
        control_job.snapshot()?.counters.get(&Counter::CacheHits),
        Some(&1)
    );

    let mut expected = initial.try_clone()?;
    let expected_job = Job::new("uncached recovery");
    recover(
        &mut expected,
        RecoveryCaseKind::Flow,
        &scope,
        &RecoveryContext {
            memory: None,
            cache: None,
            job: Some(&expected_job),
            options: &options,
        },
    )?;
    assert_eq!(control.to_json()?, expected.to_json()?);

    let mut current = initial;
    let job = Job::new("current recovery after old active checkpoint");
    recover(
        &mut current,
        RecoveryCaseKind::Flow,
        &scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: Some(&job),
            options: &options,
        },
    )?;
    let counters = job.snapshot()?.counters;
    assert_eq!(counters.get(&Counter::CacheHits), Some(&0));
    assert_eq!(counters.get(&Counter::CacheMisses), Some(&1));
    assert_eq!(
        counters.get(&Counter::CandidatesExamined),
        expected_job
            .snapshot()?
            .counters
            .get(&Counter::CandidatesExamined),
        "recomputation must use the same candidate work as an uncached run"
    );
    assert_eq!(current.to_json()?, expected.to_json()?);
    assert_eq!(
        cache
            .read_checkpoint(&old_key)?
            .ok_or("old checkpoint was removed")?
            .status,
        CheckpointStatus::Active
    );
    Ok(())
}

fn checkpointed_recovery(
    cache: &Cache,
    key: &StageKey,
    options: &RecoveryOptions,
    mut case: Case,
) -> Result<(Case, Job), Box<dyn Error>> {
    let job = Job::new("checkpointed recovery");
    let scope = job.work_scope(key.as_str())?;
    let mut lease = cache.lease(key)?;
    let mut resume = RecoveryResume::new(&mut lease, options, None);
    recover_case_with_job(
        &mut case,
        options.profile,
        options.memory_limit,
        Some(&scope),
        None,
        Some(&mut resume),
    )?;
    Ok((case, job))
}

fn assert_older_recovery_is_not_replayed(version: u32) -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = open_cache(temporary.path())?;
    let options = RecoveryOptions::default();
    let (mut old_case, scope) = case_and_scope(b"4142", 19)?;
    let source = super::super::source_id(&scope)?;
    let identity = SourceIdentity::from_sha256(
        source
            .strip_prefix("sha256:")
            .ok_or("missing source digest")?,
    )?;
    // This fixture keeps upstream versions compatible and changes only the recovery algorithm
    let old_policy = json!({
        "native_case_version": crate::workbench::full_source::NATIVE_CASE_VERSION,
        "transform_proposal_version": l2_workbench::recovery::proposals::TRANSFORM_PROPOSAL_FORMAT_VERSION,
        "kind": "flow",
        "profile": "normal",
        "memory_limit_bytes": options.memory_limit,
        "scope": scope,
    });
    let old_key = StageKey::new(
        "default_case_recovery",
        version,
        "l2-default-case-recovery",
        &old_policy,
        &identity,
        &[],
    )?;
    let result = recover(
        &mut old_case,
        RecoveryCaseKind::Flow,
        &scope,
        &RecoveryContext {
            memory: None,
            cache: None,
            job: None,
            options: &options,
        },
    )?;
    super::super::store_result(cache.lease(&old_key)?, &old_case, &result, &options, None)?;

    let job = Job::new("changed recovery algorithm");
    let (mut current_case, _) = case_and_scope(b"4142", 19)?;
    recover(
        &mut current_case,
        RecoveryCaseKind::Flow,
        &scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: Some(&job),
            options: &options,
        },
    )?;
    let counters = job.snapshot()?.counters;
    assert_eq!(counters.get(&Counter::CacheHits).copied().unwrap_or(0), 0);
    assert_eq!(counters.get(&Counter::CacheMisses), Some(&1));
    assert_eq!(current_case.to_json()?, old_case.to_json()?);
    assert!(
        cache
            .lookup(&old_key, CacheReadPolicy::AllowPartial)?
            .is_some()
    );
    let current_key = recovery_key(RecoveryCaseKind::Flow, &scope, &options)?;
    assert_ne!(current_key, old_key);
    assert!(
        cache
            .lookup(&current_key, CacheReadPolicy::AllowPartial)?
            .is_some()
    );
    Ok(())
}
