use super::{
    CacheReadPolicy, Counter, Job, RecoveryCaseKind, RecoveryContext, RecoveryOptions,
    case_and_scope, open_cache, recover, recovery_key,
};
use l2_workbench::job::cache::{SourceIdentity, StageKey};
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
