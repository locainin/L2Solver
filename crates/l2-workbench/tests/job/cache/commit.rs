use super::{cache_at, stage_key};
use l2_workbench::job::cache::{CacheError, CacheReadPolicy, CommitOutcome, StageStatus};
use serde_json::json;
use std::{error::Error, fs};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn quota_denial_retains_usable_private_work_until_its_owner_drops() -> TestResult {
    let directory = tempfile::tempdir()?;
    let cache = cache_at(directory.path(), 0)?;
    let key = stage_key("retained-quota")?;
    let lease = cache.lease(&key)?;
    let path = lease.directory().to_path_buf();
    fs::write(path.join("result.bin"), b"prepared")?;
    let outcome = lease.commit_or_retain(StageStatus::Complete, json!({"items": 1}))?;
    let CommitOutcome::QuotaExceeded(lease) = outcome else {
        return Err("over-quota work was unexpectedly published".into());
    };
    assert_eq!(fs::read(lease.directory().join("result.bin"))?, b"prepared");
    assert_eq!(cache.stats()?.entries, 0);
    drop(lease);
    assert!(!path.exists(), "private work outlived its owner");
    Ok(())
}

#[test]
fn retained_commit_publishes_files_and_metadata_when_the_quota_allows() -> TestResult {
    let directory = tempfile::tempdir()?;
    let cache = cache_at(directory.path(), 1024)?;
    let key = stage_key("committed-quota")?;
    let lease = cache.lease(&key)?;
    fs::write(lease.directory().join("result.bin"), b"prepared")?;
    let CommitOutcome::Committed(entry) =
        lease.commit_or_retain(StageStatus::Complete, json!({"items": 1}))?
    else {
        return Err("small stage was unexpectedly denied".into());
    };
    assert_eq!(entry.metadata(), &json!({"items": 1}));
    assert_eq!(fs::read(entry.directory().join("result.bin"))?, b"prepared");
    assert_eq!(cache.stats()?.entries, 1);
    Ok(())
}

#[test]
fn denied_replacement_keeps_the_previous_committed_entry_unchanged() -> TestResult {
    let directory = tempfile::tempdir()?;
    let cache = cache_at(directory.path(), 3)?;
    let key = stage_key("retained-replacement")?;
    let original = cache.lease(&key)?;
    fs::write(original.directory().join("result.bin"), b"old")?;
    drop(original.commit(StageStatus::Complete, json!({"generation": 1}))?);
    let replacement = cache.lease(&key)?;
    fs::write(replacement.directory().join("result.bin"), b"larger")?;
    let CommitOutcome::QuotaExceeded(lease) =
        replacement.commit_or_retain(StageStatus::Complete, json!({"generation": 2}))?
    else {
        return Err("oversized replacement was unexpectedly committed".into());
    };
    drop(lease);
    let entry = cache
        .lookup(&key, CacheReadPolicy::CompleteOnly)?
        .ok_or("old entry disappeared")?;
    assert_eq!(entry.metadata(), &json!({"generation": 1}));
    assert_eq!(fs::read(entry.directory().join("result.bin"))?, b"old");
    Ok(())
}

#[cfg(unix)]
#[test]
fn non_quota_commit_failure_remains_an_error_and_does_not_follow_a_symlink() -> TestResult {
    let directory = tempfile::tempdir()?;
    let cache = cache_at(directory.path(), 1024)?;
    let key = stage_key("unsafe-commit")?;
    let outside = directory.path().join("outside.bin");
    fs::write(&outside, b"unchanged")?;
    let lease = cache.lease(&key)?;
    std::os::unix::fs::symlink(&outside, lease.directory().join("unsafe.bin"))?;
    assert!(matches!(
        lease.commit_or_retain(StageStatus::Complete, json!({})),
        Err(CacheError::UnsafePath(_))
    ));
    assert_eq!(fs::read(outside)?, b"unchanged");
    assert_eq!(cache.stats()?.entries, 0);
    Ok(())
}
