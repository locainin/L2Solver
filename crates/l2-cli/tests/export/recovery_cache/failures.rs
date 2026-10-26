use super::*;

#[test]
fn held_write_lease_recomputes_without_cache_and_strict_mode_fails() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = open_cache(temporary.path())?;
    let options = RecoveryOptions {
        refresh: true,
        ..RecoveryOptions::default()
    };
    let (_, scope) = case_and_scope(b"4142", 53)?;
    let key = recovery_key(RecoveryCaseKind::Flow, &scope, &options)?;
    let held_lease = cache.lease(&key)?;

    let (mut uncached_case, uncached_scope) = case_and_scope(b"4142", 53)?;
    let uncached = recover(
        &mut uncached_case,
        RecoveryCaseKind::Flow,
        &uncached_scope,
        &RecoveryContext {
            cache: None,
            job: None,
            options: &options,
        },
    )?;

    let job = Job::new("held recovery cache lease");
    let (mut recovered_case, recovered_scope) = case_and_scope(b"4142", 53)?;
    let recovered = recover(
        &mut recovered_case,
        RecoveryCaseKind::Flow,
        &recovered_scope,
        &RecoveryContext {
            cache: Some(&cache),
            job: Some(&job),
            options: &options,
        },
    )?;
    assert_eq!(recovered_case.to_json()?, uncached_case.to_json()?);
    assert_eq!(
        serde_json::to_value(recovered.coverage)?,
        serde_json::to_value(uncached.coverage)?
    );
    assert_eq!(recovered.omissions, uncached.omissions);
    assert_cache_fallback(&job.snapshot()?, CacheFallbackKind::LeaseUnavailable, 1)?;

    let strict = RecoveryOptions {
        strict_cache: true,
        ..options
    };
    let strict_job = Job::new("strict held recovery cache lease");
    let (mut strict_case, strict_scope) = case_and_scope(b"4142", 53)?;
    let error = recover(
        &mut strict_case,
        RecoveryCaseKind::Flow,
        &strict_scope,
        &RecoveryContext {
            cache: Some(&cache),
            job: Some(&strict_job),
            options: &strict,
        },
    )
    .err()
    .ok_or("strict cache mode accepted an unavailable write lease")?;
    assert!(
        error
            .to_string()
            .contains("cache entry is currently in use")
    );
    assert!(strict_job.snapshot()?.cache_fallbacks.records().is_empty());

    drop(held_lease);
    Ok(())
}

#[test]
fn cache_quota_commit_failure_preserves_recovery_and_is_fatal_in_strict_mode()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = Cache::open_at(
        temporary.path().join("quota-cache"),
        temporary.path().join("quota-state"),
        1,
    )?;
    let options = RecoveryOptions {
        refresh: true,
        ..RecoveryOptions::default()
    };

    let (mut uncached_case, uncached_scope) = case_and_scope(b"4142", 59)?;
    let uncached = recover(
        &mut uncached_case,
        RecoveryCaseKind::Flow,
        &uncached_scope,
        &RecoveryContext {
            cache: None,
            job: None,
            options: &options,
        },
    )?;

    let job = Job::new("recovery cache quota fallback");
    let (mut recovered_case, recovered_scope) = case_and_scope(b"4142", 59)?;
    let recovered = recover(
        &mut recovered_case,
        RecoveryCaseKind::Flow,
        &recovered_scope,
        &RecoveryContext {
            cache: Some(&cache),
            job: Some(&job),
            options: &options,
        },
    )?;
    assert_eq!(recovered_case.to_json()?, uncached_case.to_json()?);
    assert_eq!(
        serde_json::to_value(recovered.coverage)?,
        serde_json::to_value(uncached.coverage)?
    );
    assert_eq!(recovered.omissions, uncached.omissions);
    assert_cache_fallback(&job.snapshot()?, CacheFallbackKind::CommitFailed, 1)?;
    assert_eq!(cache.stats()?.entries, 0);

    let strict = RecoveryOptions {
        strict_cache: true,
        ..options
    };
    let strict_job = Job::new("strict recovery cache quota");
    let (mut strict_case, strict_scope) = case_and_scope(b"4142", 59)?;
    let error = recover(
        &mut strict_case,
        RecoveryCaseKind::Flow,
        &strict_scope,
        &RecoveryContext {
            cache: Some(&cache),
            job: Some(&strict_job),
            options: &strict,
        },
    )
    .err()
    .ok_or("strict cache mode accepted a quota-rejected commit")?;
    assert!(error.to_string().contains("cache stage needs at least"));
    assert!(strict_job.snapshot()?.cache_fallbacks.records().is_empty());
    assert_eq!(cache.stats()?.entries, 0);
    Ok(())
}

fn assert_cache_fallback(
    snapshot: &l2_workbench::job::JobSnapshot,
    kind: CacheFallbackKind,
    count: u64,
) -> Result<(), Box<dyn Error>> {
    let fallback = snapshot
        .cache_fallbacks
        .records()
        .iter()
        .find(|record| record.stage() == CacheStage::CaseRecovery && record.kind() == kind)
        .ok_or("expected cache fallback was not recorded")?;
    assert_eq!(fallback.count(), count);
    Ok(())
}
