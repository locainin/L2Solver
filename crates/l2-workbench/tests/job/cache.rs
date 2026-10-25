use std::{
    error::Error,
    fs, io,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use l2_workbench::job::{
    Job,
    cache::{
        Cache, CacheError, CacheReadPolicy, CheckpointStatus, SourceFingerprint, SourceIdentity,
        StageKey, StageStatus,
    },
};
use serde_json::{Value, json};

fn cache_at(directory: &Path, max_bytes: u64) -> Result<Cache, CacheError> {
    Cache::open_at(directory.join("cache"), directory.join("state"), max_bytes)
}

fn source_identity() -> Result<SourceIdentity, CacheError> {
    SourceIdentity::from_sha256(&"a".repeat(64))
}

fn stage_key(stage: &str) -> Result<StageKey, CacheError> {
    StageKey::new(
        stage,
        1,
        "test-algorithm-v1",
        &json!({"candidate_limit": 32, "strict": true}),
        &source_identity()?,
        &[],
    )
}

fn missing(message: &'static str) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::NotFound, message).into()
}

fn write_entry(cache: &Cache, key: &StageKey, body: &[u8]) -> Result<PathBuf, CacheError> {
    let lease = cache.lease(key)?;
    fs::write(lease.directory().join("result.bin"), body)?;
    let entry = lease.commit(StageStatus::Complete, json!({"items": 1}))?;
    Ok(entry.directory().to_path_buf())
}

#[test]
fn fast_source_fingerprint_detects_same_length_content_changes() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let source = temporary.path().join("source.bin");
    fs::write(&source, b"first-content")?;
    let before = SourceFingerprint::fast(&source)?;
    let strong_before = SourceIdentity::sha256_file(&source)?;

    // Equal lengths keep the size field constant, so the sampled bytes must distinguish the versions
    fs::write(&source, b"other-content")?;
    let after = SourceFingerprint::fast(&source)?;
    let strong_after = SourceIdentity::sha256_file(&source)?;

    assert_ne!(before, after);
    assert_ne!(strong_before, strong_after);
    Ok(())
}

#[test]
fn sample_hint_matches_a_copied_source_but_stays_fast() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let original = temporary.path().join("original.bin");
    let copy = temporary.path().join("copy.bin");
    fs::write(&original, b"same-content")?;
    fs::copy(&original, &copy)?;

    let original_fingerprint = SourceFingerprint::fast(&original)?;
    let copy_fingerprint = SourceFingerprint::fast(&copy)?;
    let hint = original_fingerprint.sample_hint();

    assert_ne!(original_fingerprint, copy_fingerprint);
    assert_eq!(hint, copy_fingerprint.sample_hint());
    assert_eq!(hint.device_id, None);
    assert_eq!(hint.file_id, None);
    assert_eq!(hint.modified, None);
    assert_eq!(hint.changed, None);
    Ok(())
}

#[test]
fn stage_keys_include_algorithm_policy_and_dependencies() -> Result<(), Box<dyn Error>> {
    let source = source_identity()?;
    let dependency = stage_key("source-ingestion")?;
    let first = StageKey::new(
        "flow-analysis",
        1,
        "algorithm-a",
        &json!({"strict": true}),
        &source,
        std::slice::from_ref(&dependency),
    )?;
    let algorithm_change = StageKey::new(
        "flow-analysis",
        1,
        "algorithm-b",
        &json!({"strict": true}),
        &source,
        std::slice::from_ref(&dependency),
    )?;
    let policy_change = StageKey::new(
        "flow-analysis",
        1,
        "algorithm-a",
        &json!({"strict": false}),
        &source,
        std::slice::from_ref(&dependency),
    )?;
    let dependency_change = StageKey::new(
        "flow-analysis",
        1,
        "algorithm-a",
        &json!({"strict": true}),
        &source,
        &[stage_key("different-source-ingestion")?],
    )?;

    assert_ne!(first, algorithm_change);
    assert_ne!(first, policy_change);
    assert_ne!(first, dependency_change);
    Ok(())
}

#[test]
fn stage_keys_reject_malformed_source_digests() -> Result<(), Box<dyn Error>> {
    let source = SourceIdentity::Sha256("not-a-digest".to_owned());

    assert!(matches!(
        StageKey::new("stage", 1, "algorithm", &json!({}), &source, &[]),
        Err(CacheError::InvalidInput(_))
    ));
    Ok(())
}

#[test]
fn partial_entries_are_not_reused_as_complete_results() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 1024)?;
    let key = stage_key("candidate-search")?;
    let lease = cache.lease(&key)?;
    fs::write(lease.directory().join("partial.json"), b"[]")?;
    let entry = lease.commit(StageStatus::Partial, json!({"found": 0}))?;
    drop(entry);

    assert!(cache.lookup(&key, CacheReadPolicy::CompleteOnly)?.is_none());
    let partial = cache
        .lookup(&key, CacheReadPolicy::AllowPartial)?
        .ok_or_else(|| missing("partial entry should remain available for resume"))?;
    assert_eq!(partial.status(), StageStatus::Partial);
    Ok(())
}

#[test]
fn completed_entries_round_trip_metadata_and_relative_files() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 1024)?;
    let key = stage_key("validated-result")?;
    let directory = write_entry(&cache, &key, b"stable-result")?;

    let entry = cache
        .lookup(&key, CacheReadPolicy::CompleteOnly)?
        .ok_or_else(|| missing("complete entry should be reusable"))?;
    assert_eq!(entry.status(), StageStatus::Complete);
    assert_eq!(entry.metadata().get("items"), Some(&Value::from(1)));
    assert_eq!(fs::read(directory.join("result.bin"))?, b"stable-result");
    let stats = cache.stats()?;
    assert_eq!(stats.entries, 1);
    assert_eq!(stats.entry_bytes, u64::try_from(b"stable-result".len())?);
    Ok(())
}

#[test]
fn complete_empty_results_remain_terminal_cache_hits() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 1024)?;
    let key = stage_key("empty-result")?;
    let lease = cache.lease(&key)?;
    let entry = lease.commit(StageStatus::Complete, json!({"matches": 0}))?;
    drop(entry);

    let cached = cache
        .lookup(&key, CacheReadPolicy::CompleteOnly)?
        .ok_or_else(|| missing("complete empty result should be a cache hit"))?;
    assert_eq!(cached.status(), StageStatus::Complete);
    assert_eq!(cached.metadata().get("matches"), Some(&Value::from(0)));
    Ok(())
}

#[test]
fn missing_or_changed_entry_files_are_reported_as_corruption() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 1024)?;
    let key = stage_key("validated-result")?;
    let directory = write_entry(&cache, &key, b"original")?;
    fs::write(directory.join("result.bin"), b"short")?;

    assert!(matches!(
        cache.lookup(&key, CacheReadPolicy::CompleteOnly),
        Err(CacheError::CorruptEntry(_))
    ));
    Ok(())
}

#[test]
fn cache_schema_rejects_an_incompatible_database_version() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache_root = temporary.path().join("cache");
    let state_root = temporary.path().join("state");
    drop(Cache::open_at(&cache_root, &state_root, 1024)?);
    let database = rusqlite::Connection::open(state_root.join("cache.sqlite3"))?;
    database.pragma_update(None, "user_version", 999_i64)?;
    drop(database);

    assert!(matches!(
        Cache::open_at(cache_root, state_root, 1024),
        Err(CacheError::IncompatibleSchema(999))
    ));
    Ok(())
}

#[test]
fn leases_exclude_writers_while_shared_entry_readers_can_coexist() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 1024)?;
    let second_cache = cache_at(temporary.path(), 1024)?;
    let key = stage_key("concurrent-stage")?;

    let lease = cache.lease(&key)?;
    assert!(matches!(
        second_cache.lease(&key),
        Err(CacheError::LockBusy)
    ));
    drop(lease);

    let directory = write_entry(&cache, &key, b"complete")?;
    let first_reader = cache
        .lookup(&key, CacheReadPolicy::CompleteOnly)?
        .ok_or_else(|| missing("first reader should see the complete entry"))?;
    let second_reader = second_cache
        .lookup(&key, CacheReadPolicy::CompleteOnly)?
        .ok_or_else(|| missing("second reader should share the complete entry"))?;
    assert!(matches!(cache.lease(&key), Err(CacheError::LockBusy)));
    let report = second_cache.clear()?;
    assert_eq!(report.skipped_locked, 1);
    assert!(directory.is_dir());

    drop((first_reader, second_reader));
    let lease = second_cache.lease(&key)?;
    assert!(directory.is_dir());
    drop(lease);
    Ok(())
}

#[test]
fn pruning_skips_live_reader_pins_then_evicts_oldest_unpinned_entries() -> Result<(), Box<dyn Error>>
{
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 0)?;
    let oldest_key = stage_key("oldest-stage")?;
    let newest_key = stage_key("newest-stage")?;
    let oldest_directory = write_entry(&cache, &oldest_key, b"old")?;
    thread::sleep(Duration::from_millis(2));
    let newest_directory = write_entry(&cache, &newest_key, b"new")?;
    drop(cache.lookup(&newest_key, CacheReadPolicy::CompleteOnly)?);
    let oldest_pin = cache
        .lookup(&oldest_key, CacheReadPolicy::CompleteOnly)?
        .ok_or_else(|| missing("old entry should be pinned"))?;

    let report = cache.prune()?;
    assert_eq!(report.removed_entries, 1);
    assert!(oldest_directory.is_dir());
    assert!(!newest_directory.exists());

    drop(oldest_pin);
    let report = cache.prune()?;
    assert_eq!(report.removed_entries, 1);
    assert!(!oldest_directory.exists());
    Ok(())
}

#[test]
fn lru_pruning_evicts_the_least_recently_used_unpinned_entry() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 3)?;
    let oldest_key = stage_key("least-recent-stage")?;
    let newest_key = stage_key("most-recent-stage")?;
    let oldest_directory = write_entry(&cache, &oldest_key, b"old")?;
    thread::sleep(Duration::from_millis(2));
    let newest_directory = write_entry(&cache, &newest_key, b"new")?;
    drop(cache.lookup(&oldest_key, CacheReadPolicy::CompleteOnly)?);

    let report = cache.prune()?;
    assert_eq!(report.removed_entries, 1);
    assert!(oldest_directory.is_dir());
    assert!(!newest_directory.exists());
    Ok(())
}

#[test]
fn active_checkpoints_pin_entries_and_preserve_the_job_snapshot() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 0)?;
    let key = stage_key("resumable-stage")?;
    let directory = write_entry(&cache, &key, b"stage-output")?;
    let snapshot = Job::new("durable recovery").snapshot()?;

    cache.write_checkpoint(&key, &snapshot, CheckpointStatus::Active)?;
    let checkpoint = cache
        .read_checkpoint(&key)?
        .ok_or_else(|| missing("durable checkpoint should be available"))?;
    assert_eq!(checkpoint.key, key);
    assert_eq!(checkpoint.status, CheckpointStatus::Active);
    assert_eq!(
        checkpoint.snapshot_version,
        l2_workbench::job::cache::JOB_SNAPSHOT_VERSION
    );
    assert_eq!(checkpoint.snapshot, snapshot);
    let report = cache.clear()?;
    assert_eq!(report.removed_entries, 0);
    assert!(directory.is_dir());

    cache.write_checkpoint(&key, &snapshot, CheckpointStatus::Complete)?;
    assert_eq!(cache.clear()?.removed_entries, 1);
    assert!(!directory.exists());
    Ok(())
}

#[test]
fn preserved_work_reopens_under_an_active_checkpoint() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 1024)?;
    let key = stage_key("resumable-work")?;
    let snapshot = Job::new("recover interrupted stage").snapshot()?;
    let lease = cache.lease(&key)?;
    fs::write(lease.directory().join("cursor.json"), b"resume-at-12")?;
    let work_directory = lease.directory().to_path_buf();

    lease.preserve(&snapshot)?;
    assert!(work_directory.is_dir());
    let resumed = cache.lease(&key)?;
    assert_eq!(
        fs::read(resumed.directory().join("cursor.json"))?,
        b"resume-at-12"
    );
    let partial = resumed.commit(StageStatus::Partial, json!({"next": 12}))?;
    assert_eq!(partial.status(), StageStatus::Partial);
    Ok(())
}

#[test]
fn checkpoint_snapshot_versions_are_validated_before_restore() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 1024)?;
    let key = stage_key("versioned-checkpoint")?;
    let snapshot = Job::new("versioned checkpoint").snapshot()?;
    cache.write_checkpoint(&key, &snapshot, CheckpointStatus::Active)?;

    let database =
        rusqlite::Connection::open(temporary.path().join("state").join("cache.sqlite3"))?;
    database.execute(
        "UPDATE checkpoints SET snapshot_version = 999 WHERE key = ?1",
        [key.as_str()],
    )?;
    drop(database);

    assert!(matches!(
        cache.read_checkpoint(&key),
        Err(CacheError::CorruptCheckpoint)
    ));
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlinked_roots_and_replaced_roots_are_rejected() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir()?;
    let actual_cache = temporary.path().join("actual-cache");
    let actual_state = temporary.path().join("actual-state");
    fs::create_dir(&actual_cache)?;
    fs::create_dir(&actual_state)?;
    let cache_link = temporary.path().join("cache-link");
    symlink(&actual_cache, &cache_link)?;
    assert!(matches!(
        Cache::open_at(cache_link, actual_state.clone(), 1024),
        Err(CacheError::UnsafePath(_))
    ));

    let cache_root = temporary.path().join("cache-root");
    let state_root = temporary.path().join("state-root");
    let cache = Cache::open_at(&cache_root, &state_root, 1024)?;
    let key = stage_key("path-replacement")?;
    let moved_cache = temporary.path().join("moved-cache");
    fs::rename(&cache_root, &moved_cache)?;
    symlink(&actual_cache, &cache_root)?;

    assert!(matches!(cache.lease(&key), Err(CacheError::UnsafePath(_))));
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlinked_key_lock_is_rejected_without_opening_its_target() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 1024)?;
    let key = stage_key("symlinked-lock")?;
    let outside = temporary.path().join("outside.lock");
    fs::write(&outside, b"outside-data")?;
    symlink(
        &outside,
        temporary
            .path()
            .join("state")
            .join("locks")
            .join(format!("{}.lock", key.as_str())),
    )?;

    assert!(matches!(cache.lease(&key), Err(CacheError::UnsafePath(_))));
    assert_eq!(fs::read(outside)?, b"outside-data");
    Ok(())
}
