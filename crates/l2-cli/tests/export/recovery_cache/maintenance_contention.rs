//! Keep native recovery independent of an unavailable cache maintenance gate

use super::*;
use l2_workbench::job::cache::CacheError;
use std::fs::File;

#[test]
fn optional_cache_maintenance_contention_preserves_native_evidence() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = open_cache(temporary.path())?;
    let options = RecoveryOptions::default();
    let (mut expected_case, scope) = case_and_scope(b"4142", 113)?;
    let expected = recover(
        &mut expected_case,
        RecoveryCaseKind::Flow,
        &scope,
        &RecoveryContext {
            memory: None,
            cache: None,
            job: None,
            options: &options,
        },
    )?;
    let _gate = lock_quota(temporary.path())?;
    let job = Job::new("optional cache maintenance contention");
    let (mut actual_case, actual_scope) = case_and_scope(b"4142", 113)?;
    let actual = recover(
        &mut actual_case,
        RecoveryCaseKind::Flow,
        &actual_scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: Some(&job),
            options: &options,
        },
    )?;
    // The bounded gate refusal must not replace native bytes or their provenance
    assert_cases_equal(&actual_case, &expected_case);
    assert_eq!(
        serde_json::to_value(actual.coverage)?,
        serde_json::to_value(expected.coverage)?
    );
    assert_eq!(actual.omissions, expected.omissions);
    let snapshot = job.snapshot()?;
    assert_eq!(snapshot.counters.get(&Counter::CacheMisses), Some(&1));
    assert_eq!(snapshot.cache_fallbacks.records().len(), 2);
    for kind in [
        CacheFallbackKind::LookupFailed,
        CacheFallbackKind::LeaseUnavailable,
    ] {
        assert!(snapshot.cache_fallbacks.records().iter().any(|record| {
            record.stage() == CacheStage::CaseRecovery
                && record.kind() == kind
                && record.count() == 1
        }));
    }
    Ok(())
}

#[test]
fn strict_cache_maintenance_contention_reports_the_typed_refusal() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = open_cache(temporary.path())?;
    let _gate = lock_quota(temporary.path())?;
    let options = RecoveryOptions {
        strict_cache: true,
        ..RecoveryOptions::default()
    };
    let job = Job::new("strict cache maintenance contention");
    let (mut case, scope) = case_and_scope(b"4142", 127)?;
    let initial = case.to_json()?;
    let error = recover(
        &mut case,
        RecoveryCaseKind::Flow,
        &scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: Some(&job),
            options: &options,
        },
    )
    .err()
    .ok_or("strict cache accepted the held maintenance gate")?;
    assert!(matches!(
        error.downcast_ref::<CacheError>(),
        Some(CacheError::CacheBusy)
    ));
    assert_eq!(case.to_json()?, initial);
    assert_eq!(job.snapshot()?.cache_fallbacks.records().len(), 0);
    Ok(())
}

fn lock_quota(root: &std::path::Path) -> Result<File, Box<dyn Error>> {
    // A separate open file description conflicts with the cache's real OS lock
    let gate = File::open(root.join("state/locks/quota.lock"))?;
    rustix::fs::flock(&gate, rustix::fs::FlockOperation::LockExclusive)?;
    Ok(gate)
}
