use std::{
    error::Error,
    fs, io,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use l2_workbench::job::{
    CacheFallbackKind, CacheStage, Counter, Job, RecoveryCandidateSample, RecoveryTransition,
    RecoveryTransitionOutcome, RecoveryTransitionSample, RecoveryTransitionStage,
    cache::{
        Cache, CacheError, CacheReadPolicy, CheckpointStatus, SourceFingerprint, SourceIdentity,
        StageKey, StageStatus,
    },
};
use serde_json::{Value, json};

#[path = "cache/fingerprint.rs"]
mod fingerprint;

#[path = "cache/execution.rs"]
mod execution;

#[path = "cache/memory.rs"]
mod memory;

#[path = "cache/commit.rs"]
mod commit;

#[path = "cache/scoped_memory.rs"]
mod scoped_memory;

#[path = "cache/maintenance.rs"]
mod maintenance;
#[cfg(target_os = "linux")]
#[path = "cache/terminal_fsync.rs"]
mod terminal_fsync;

#[cfg(target_os = "linux")]
#[path = "cache/terminal_retirement.rs"]
mod terminal_retirement;

#[cfg(target_os = "linux")]
#[path = "cache/manifest_io.rs"]
mod manifest_io;

fn cache_at(directory: &Path, max_bytes: u64) -> Result<Cache, CacheError> {
    Cache::open_at(directory.join("cache"), directory.join("state"), max_bytes)
}

fn source_identity() -> Result<SourceIdentity, CacheError> {
    SourceIdentity::from_sha256("a".repeat(64))
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
fn stage_keys_reject_malformed_source_digests() {
    let source = SourceIdentity::Sha256("not-a-digest".to_owned());

    assert!(matches!(
        StageKey::new("stage", 1, "algorithm", &json!({}), &source, &[]),
        Err(CacheError::InvalidInput(_))
    ));
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
fn committing_a_new_entry_evicts_the_oldest_unpinned_entry_automatically()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 3)?;
    let oldest_key = stage_key("automatic-lru-oldest")?;
    let newest_key = stage_key("automatic-lru-newest")?;
    let oldest_directory = write_entry(&cache, &oldest_key, b"old")?;
    thread::sleep(Duration::from_millis(2));

    let newest_directory = write_entry(&cache, &newest_key, b"new")?;

    assert!(!oldest_directory.exists());
    assert!(newest_directory.is_dir());
    let stats = cache.stats()?;
    assert_eq!(stats.entries, 1);
    assert_eq!(stats.entry_bytes, cache.max_bytes());
    assert_eq!(stats.over_limit_bytes, 0);
    Ok(())
}

#[test]
fn committing_an_oversized_stage_is_rejected_without_retaining_it() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 2)?;
    let key = stage_key("oversized-stage")?;
    let lease = cache.lease(&key)?;
    let staging_path = lease.directory().to_path_buf();
    fs::write(staging_path.join("result.bin"), b"three")?;

    assert!(matches!(
        lease.commit(StageStatus::Complete, json!({})),
        Err(CacheError::QuotaExceeded {
            limit_bytes: 2,
            required_bytes: 5,
        })
    ));
    assert!(!staging_path.exists());
    assert_eq!(cache.stats()?.entry_bytes, 0);
    Ok(())
}

#[test]
fn committing_rejects_growth_when_existing_entries_are_pinned() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 3)?;
    let pinned_key = stage_key("pinned-entry")?;
    let incoming_key = stage_key("quota-blocked-entry")?;
    let pinned_directory = {
        let lease = cache.lease(&pinned_key)?;
        fs::write(lease.directory().join("result.bin"), b"old")?;
        lease.commit(StageStatus::Complete, json!({}))?
    };
    let lease = cache.lease(&incoming_key)?;
    fs::write(lease.directory().join("result.bin"), b"new")?;

    assert!(matches!(
        lease.commit(StageStatus::Complete, json!({})),
        Err(CacheError::QuotaExceeded { .. })
    ));
    assert!(pinned_directory.directory().join("result.bin").is_file());
    assert_eq!(cache.stats()?.entry_bytes, 3);
    assert!(
        cache
            .lookup(&incoming_key, CacheReadPolicy::CompleteOnly)?
            .is_none()
    );
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
fn version_zero_database_with_existing_tables_is_rejected_without_rewriting_it()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache_root = temporary.path().join("cache");
    let state_root = temporary.path().join("state");
    fs::create_dir_all(&state_root)?;
    let database_path = state_root.join("cache.sqlite3");
    let database = rusqlite::Connection::open(&database_path)?;
    database.execute("CREATE TABLE unrecognized_data (value TEXT)", [])?;
    drop(database);

    let Err(error) = Cache::open_at(&cache_root, &state_root, 1024) else {
        return Err("unversioned user tables must not be treated as a new cache".into());
    };
    assert!(matches!(&error, CacheError::IncompatibleDatabase));
    assert!(error.to_string().contains("unrecognized or incomplete"));
    let database = rusqlite::Connection::open(&database_path)?;
    let table_count: i64 = database.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'unrecognized_data'",
        [],
        |row| row.get(0),
    )?;
    let version: i64 = database.pragma_query_value(None, "user_version", |row| row.get(0))?;
    assert_eq!(table_count, 1);
    assert_eq!(version, 0);
    Ok(())
}

#[cfg(unix)]
#[test]
fn concurrent_processes_can_initialize_the_same_cache() -> Result<(), Box<dyn Error>> {
    const PROCESS_COUNT: usize = 4;

    let temporary = tempfile::tempdir()?;
    let cache_root = temporary.path().join("cache");
    let state_root = temporary.path().join("state");
    let release = temporary.path().join("release-open");
    let mut children = Vec::with_capacity(PROCESS_COUNT);
    let executable = std::env::current_exe()?;

    for index in 0..PROCESS_COUNT {
        let ready = temporary.path().join(format!("ready-{index}"));
        let child = Command::new(&executable)
            .args([
                "--exact",
                "cache::concurrent_cache_open_child",
                "--nocapture",
            ])
            .env("L2_CACHE_OPEN_CACHE_ROOT", &cache_root)
            .env("L2_CACHE_OPEN_STATE_ROOT", &state_root)
            .env("L2_CACHE_OPEN_READY", &ready)
            .env("L2_CACHE_OPEN_RELEASE", &release)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        children.push((ready, child));
    }

    let deadline = Instant::now() + Duration::from_secs(10);
    while children.iter().any(|(ready, _)| !ready.exists()) {
        if Instant::now() >= deadline {
            fs::write(&release, b"open")?;
            for (_, child) in &mut children {
                let _ = child.kill();
            }
            return Err("cache-open children did not reach the start barrier".into());
        }
        thread::sleep(Duration::from_millis(5));
    }
    fs::write(&release, b"open")?;

    for (_, child) in children {
        let output = child.wait_with_output()?;
        assert!(
            output.status.success(),
            "cache-open child failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    let cache = Cache::open_at(cache_root, state_root, 1024)?;
    assert_eq!(cache.stats()?.entries, 0);
    Ok(())
}

#[cfg(unix)]
#[test]
fn concurrent_cache_open_child() -> Result<(), Box<dyn Error>> {
    let child_configuration = (
        std::env::var_os("L2_CACHE_OPEN_CACHE_ROOT"),
        std::env::var_os("L2_CACHE_OPEN_STATE_ROOT"),
        std::env::var_os("L2_CACHE_OPEN_READY"),
        std::env::var_os("L2_CACHE_OPEN_RELEASE"),
    );
    if child_configuration.0.is_none()
        && child_configuration.1.is_none()
        && child_configuration.2.is_none()
        && child_configuration.3.is_none()
    {
        return Ok(());
    }
    let (Some(cache_root), Some(state_root), Some(ready), Some(release)) = child_configuration
    else {
        return Err("cache-open child environment is incomplete".into());
    };
    let release = PathBuf::from(release);
    fs::write(ready, b"ready")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !release.exists() {
        if Instant::now() >= deadline {
            return Err("cache-open child timed out at the start barrier".into());
        }
        thread::sleep(Duration::from_millis(5));
    }

    let cache = Cache::open_at(cache_root, state_root, 1024)?;
    assert_eq!(cache.stats()?.entries, 0);
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
    let cache = cache_at(temporary.path(), 6)?;
    let oldest_key = stage_key("oldest-stage")?;
    let newest_key = stage_key("newest-stage")?;
    let oldest_directory = write_entry(&cache, &oldest_key, b"old")?;
    thread::sleep(Duration::from_millis(2));
    let newest_directory = write_entry(&cache, &newest_key, b"new")?;
    drop(cache.lookup(&newest_key, CacheReadPolicy::CompleteOnly)?);
    let oldest_pin = cache
        .lookup(&oldest_key, CacheReadPolicy::CompleteOnly)?
        .ok_or_else(|| missing("old entry should be pinned"))?;

    let tight_cache = cache_at(temporary.path(), 0)?;
    assert!(oldest_directory.is_dir());
    assert!(!newest_directory.exists());
    assert_eq!(tight_cache.stats()?.over_limit_bytes, 3);

    drop(oldest_pin);
    let report = tight_cache.prune()?;
    assert_eq!(report.removed_entries, 1);
    assert!(!oldest_directory.exists());
    Ok(())
}

#[test]
fn opening_cache_evicts_the_least_recently_used_unpinned_entry() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 6)?;
    let oldest_key = stage_key("least-recent-stage")?;
    let newest_key = stage_key("most-recent-stage")?;
    let oldest_directory = write_entry(&cache, &oldest_key, b"old")?;
    thread::sleep(Duration::from_millis(2));
    let newest_directory = write_entry(&cache, &newest_key, b"new")?;
    drop(cache.lookup(&oldest_key, CacheReadPolicy::CompleteOnly)?);

    let tight_cache = cache_at(temporary.path(), 3)?;
    assert!(oldest_directory.is_dir());
    assert!(!newest_directory.exists());
    assert_eq!(tight_cache.stats()?.over_limit_bytes, 0);
    Ok(())
}

#[test]
fn active_checkpoints_pin_entries_and_preserve_the_job_snapshot() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 1024)?;
    let key = stage_key("resumable-stage")?;
    let directory = write_entry(&cache, &key, b"stage-output")?;
    let snapshot = Job::new("durable recovery").snapshot()?;

    cache.write_checkpoint(&key, &snapshot, CheckpointStatus::Active)?;
    let tight_cache = cache_at(temporary.path(), 0)?;
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
    let report = tight_cache.clear()?;
    assert_eq!(report.removed_entries, 0);
    assert!(directory.is_dir());
    assert_eq!(
        tight_cache.stats()?.over_limit_bytes,
        b"stage-output".len() as u64
    );

    tight_cache.write_checkpoint(&key, &snapshot, CheckpointStatus::Complete)?;
    assert_eq!(tight_cache.clear()?.removed_entries, 1);
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

#[test]
fn checkpoint_version_four_round_trips_transitions_and_reads_legacy_versions()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 1024)?;
    let current_key = stage_key("version-four-transitions")?;
    let current_job = Job::new("version four checkpoint");
    current_job.record_cache_fallback(
        CacheStage::CaseRecovery,
        CacheFallbackKind::CommitCaseTooLarge,
        format_args!("Case JSON exceeds the recovery-cache limit"),
    )?;
    current_job.increment(Counter::RecordInputApplications, 3)?;
    current_job.record_recovery_transition(RecoveryTransition {
        stage: RecoveryTransitionStage::Schema,
        outcome: RecoveryTransitionOutcome::ReportRetained,
        sample: None,
    })?;
    let current_snapshot = current_job.snapshot()?;
    cache.write_checkpoint(&current_key, &current_snapshot, CheckpointStatus::Active)?;
    let current = cache
        .read_checkpoint(&current_key)?
        .ok_or_else(|| missing("version-four checkpoint should be available"))?;
    assert_eq!(current.snapshot_version, 4);
    assert_eq!(current.snapshot, current_snapshot);
    for version in [1, 2, 3] {
        assert_legacy_checkpoint(&cache, temporary.path(), version)?;
    }
    Ok(())
}

fn assert_legacy_checkpoint(
    cache: &Cache,
    directory: &Path,
    version: u32,
) -> Result<(), Box<dyn Error>> {
    let key = stage_key(&format!("compatible-version-{version}"))?;
    let legacy_job = Job::new("compatible legacy checkpoint");
    legacy_job.record_cache_fallback(
        CacheStage::CaseRecovery,
        CacheFallbackKind::InvalidEntry,
        format_args!("cached Case could not be restored"),
    )?;
    legacy_job.record_recovery_transition(RecoveryTransition {
        stage: RecoveryTransitionStage::Schema,
        outcome: RecoveryTransitionOutcome::Hypothesis,
        sample: Some(RecoveryTransitionSample::Candidate(
            RecoveryCandidateSample {
                candidate_index: 1,
                input_node_id: 2,
                input_blob_sha256: [3; 32],
                input_batch_sha256: [4; 32],
                task_sha256: [5; 32],
                source_range: None,
                input_count: 1,
                evidence_node_id: Some(6),
            },
        )),
    })?;
    let mut legacy_json = serde_json::to_value(legacy_job.snapshot()?)?;
    if version < 3 {
        legacy_json
            .as_object_mut()
            .ok_or_else(|| missing("snapshot must be an object"))?
            .remove("recovery_transitions");
        legacy_json
            .get_mut("counters")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| missing("snapshot counters must be an object"))?
            .remove("record_input_applications");
    } else {
        let sample = legacy_json
            .pointer_mut("/recovery_transitions/records/0/sample")
            .ok_or_else(|| missing("legacy candidate sample is missing"))?;
        *sample = sample
            .get("detail")
            .cloned()
            .ok_or_else(|| missing("candidate detail is missing"))?;
    }
    let expected: l2_workbench::job::JobSnapshot = serde_json::from_value(legacy_json.clone())?;
    cache.write_checkpoint(&key, &legacy_job.snapshot()?, CheckpointStatus::Active)?;
    let database = rusqlite::Connection::open(directory.join("state").join("cache.sqlite3"))?;
    database.execute(
        "UPDATE checkpoints SET snapshot_version = ?1, snapshot_json = ?2 WHERE key = ?3",
        rusqlite::params![version, serde_json::to_string(&legacy_json)?, key.as_str()],
    )?;
    drop(database);
    let legacy = cache
        .read_checkpoint(&key)?
        .ok_or_else(|| missing("legacy checkpoint should be available"))?;
    assert_eq!(legacy.snapshot_version, version);
    assert_eq!(legacy.snapshot, expected);
    let restored = Job::new("restored legacy checkpoint");
    restored.restore(legacy.snapshot)?;
    assert_eq!(
        restored
            .snapshot()?
            .counters
            .get(&Counter::RecordInputApplications),
        Some(&0)
    );
    Ok(())
}

#[test]
fn oversized_cache_metadata_has_a_typed_size_error() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 1024)?;
    let key = stage_key("oversized-metadata")?;
    let lease = cache.lease(&key)?;
    let metadata_limit = 4 * 1024 * 1024;
    let oversized_metadata = Value::String("x".repeat(metadata_limit - 1));

    assert!(matches!(
        lease.commit(StageStatus::Complete, oversized_metadata),
        Err(CacheError::MetadataTooLarge {
            limit_bytes: 4_194_304,
            actual_bytes: 4_194_305,
        })
    ));
    assert_eq!(cache.stats()?.entries, 0);
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
        Cache::open_at(cache_link, actual_state, 1024),
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

#[test]
fn checkpoint_read_rejects_invalid_job_phase_structure() -> Result<(), Box<dyn Error>> {
    for corruption in ["missing", "duplicate", "invalid progress"] {
        let temporary = tempfile::tempdir()?;
        let cache = cache_at(temporary.path(), 1024)?;
        let key = stage_key("malformed-phase-checkpoint")?;
        let snapshot = Job::new("checkpoint with invalid phases").snapshot()?;
        cache.write_checkpoint(&key, &snapshot, CheckpointStatus::Active)?;
        let mut value = serde_json::to_value(snapshot)?;
        let phases = value
            .get_mut("phases")
            .and_then(serde_json::Value::as_array_mut)
            .ok_or("checkpoint phase list is missing")?;
        match corruption {
            "missing" => phases.clear(),
            "duplicate" => {
                let first = phases.first().cloned().ok_or("first phase is missing")?;
                *phases.get_mut(1).ok_or("second phase is missing")? = first;
            }
            _ => {
                let first = phases.first_mut().ok_or("first phase is missing")?;
                *first
                    .get_mut("progress_percent")
                    .ok_or("progress is missing")? = serde_json::json!(101);
            }
        }
        let connection =
            rusqlite::Connection::open(temporary.path().join("state").join("cache.sqlite3"))?;
        connection.execute(
            "UPDATE checkpoints SET snapshot_json = ?1 WHERE key = ?2",
            rusqlite::params![value.to_string(), key.as_str()],
        )?;
        drop(connection);
        assert!(
            matches!(
                cache.read_checkpoint(&key),
                Err(CacheError::CorruptCheckpoint)
            ),
            "malformed phases must be rejected ({corruption})"
        );
    }
    Ok(())
}
