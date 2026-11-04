use std::{error::Error, fs};

use l2_workbench::job::{
    MemoryBudget, MemoryClass, MemoryError,
    cache::{Cache, CacheError, CacheReadPolicy, StageKey, StageStatus},
};
use serde_json::json;

use super::{cache_at, stage_key};

#[cfg(target_os = "linux")]
const LARGE_METADATA_BYTES: usize = 1024 * 1024;

#[cfg(target_os = "linux")]
fn thread_read_bytes() -> Result<u64, Box<dyn Error>> {
    let contents = fs::read_to_string("/proc/thread-self/io")?;
    let value = contents
        .lines()
        .find_map(|line| line.strip_prefix("rchar: "))
        .ok_or("rchar is missing")?;
    Ok(value.trim().parse()?)
}

fn save_fixture(cache: &Cache, key: &StageKey, size: usize) -> Result<(), Box<dyn Error>> {
    let lease = cache.lease(key)?;
    fs::write(lease.directory().join("result"), b"result")?;
    drop(lease.commit(StageStatus::Complete, json!({"payload": "x".repeat(size)}))?);
    Ok(())
}

#[test]
fn lookup_retains_a_shared_cache_charge_until_the_entry_is_dropped() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let key = stage_key("memory-live-entry")?;
    let producer = cache_at(temporary.path(), 64 * 1024)?;
    save_fixture(&producer, &key, 4_096)?;
    drop(producer);
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let budget = MemoryBudget::new(8 * 1024 * 1024);
    cache.attach_memory_budget(budget.clone())?;
    let entry = cache
        .lookup(&key, CacheReadPolicy::CompleteOnly)?
        .ok_or("entry is missing")?;
    let while_live = budget.snapshot()?;
    assert!(while_live.used(MemoryClass::Cache) > 0);
    assert!(while_live.peak_bytes > while_live.used_bytes);
    assert_eq!(
        entry.metadata()["payload"].as_str().map(str::len),
        Some(4_096)
    );
    drop(entry);
    assert_eq!(budget.snapshot()?.used(MemoryClass::Cache), 0);
    Ok(())
}

#[test]
fn pressure_is_typed_and_does_not_decode_or_replay_the_entry() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let key = stage_key("memory-denied-entry")?;
    let producer = cache_at(temporary.path(), 64 * 1024)?;
    save_fixture(&producer, &key, 4_096)?;
    drop(producer);
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let budget = MemoryBudget::new(1);
    cache.attach_memory_budget(budget.clone())?;
    assert!(matches!(
        cache.lookup(&key, CacheReadPolicy::CompleteOnly),
        Err(CacheError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    assert_eq!(cache.stats()?.entries, 1);
    drop(cache);
    let unbudgeted = cache_at(temporary.path(), 64 * 1024)?;
    assert_eq!(
        unbudgeted
            .lookup(&key, CacheReadPolicy::CompleteOnly)?
            .ok_or("entry was removed")?
            .metadata()["payload"]
            .as_str()
            .map(str::len),
        Some(4_096)
    );
    Ok(())
}

#[test]
fn cache_clones_share_one_budget_and_cannot_rebind_it() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let key = stage_key("memory-shared-clones")?;
    let producer = cache_at(temporary.path(), 64 * 1024)?;
    save_fixture(&producer, &key, 5_000)?;
    drop(producer);
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let other = cache.clone();
    let budget = MemoryBudget::new(1_000_000);
    other.attach_memory_budget(budget.clone())?;
    assert!(cache.attach_memory_budget(budget.clone()).is_err());
    let entry = cache
        .lookup(&key, CacheReadPolicy::CompleteOnly)?
        .ok_or("entry is missing")?;
    let live = budget.snapshot()?.used(MemoryClass::Cache);
    assert!(live > 0);
    assert!(matches!(
        other.lookup(&key, CacheReadPolicy::CompleteOnly),
        Err(CacheError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(budget.snapshot()?.used(MemoryClass::Cache), live);
    drop(entry);
    assert_eq!(budget.snapshot()?.used(MemoryClass::Cache), 0);
    Ok(())
}

#[test]
fn first_unbudgeted_lookup_prevents_a_late_budget_attachment() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let key = stage_key("memory-late-attachment")?;
    let producer = cache_at(temporary.path(), 64 * 1024)?;
    save_fixture(&producer, &key, 10)?;
    drop(producer);
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let entry = cache
        .lookup(&key, CacheReadPolicy::CompleteOnly)?
        .ok_or("entry is missing")?;
    assert!(
        cache
            .attach_memory_budget(MemoryBudget::new(1_000_000))
            .is_err()
    );
    assert_eq!(entry.metadata()["payload"].as_str(), Some("xxxxxxxxxx"));
    Ok(())
}

#[test]
fn committed_entry_holds_and_releases_its_metadata_charge() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let key = stage_key("memory-committed-entry")?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let budget = MemoryBudget::new(4 * 1024 * 1024);
    cache.attach_memory_budget(budget.clone())?;
    let lease = cache.lease(&key)?;
    fs::write(lease.directory().join("result"), b"result")?;
    let entry = lease.commit(StageStatus::Complete, json!({"payload": "x".repeat(1_024)}))?;
    assert!(budget.snapshot()?.used(MemoryClass::Cache) > 0);
    drop(entry);
    assert_eq!(budget.snapshot()?.used(MemoryClass::Cache), 0);
    Ok(())
}

#[test]
fn adopted_metadata_charge_stays_live_after_the_worker_finishes() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let key = stage_key("memory-adopted-metadata")?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let budget = MemoryBudget::new(4 * 1024 * 1024);
    cache.attach_memory_budget(budget.clone())?;
    let worker = budget.try_working_set(64 * 1024)?;
    let reservation = worker.budget().try_reserve(MemoryClass::Cache, 8 * 1024)?;
    let lease = cache.lease(&key)?;
    fs::write(lease.directory().join("result"), b"result")?;
    let entry = lease.commit_with_reserved_metadata(
        StageStatus::Complete,
        json!({"payload": "x".repeat(1024)}),
        reservation,
    )?;
    drop(worker);
    assert!(
        budget.snapshot()?.used(MemoryClass::Cache) >= 8 * 1024,
        "the entry must own the adopted charge"
    );
    assert_eq!(
        entry
            .metadata()
            .get("payload")
            .and_then(|v| v.as_str())
            .map(str::len),
        Some(1024)
    );
    drop(entry);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn adopted_metadata_uses_remaining_worker_credit_for_its_transient_buffer()
-> Result<(), Box<dyn Error>> {
    commit_adopted_metadata_with_headroom(70 * 1024)
}

#[test]
fn adopted_metadata_uses_worker_credit_for_manifest_and_quota_checks() -> Result<(), Box<dyn Error>>
{
    commit_adopted_metadata_with_headroom(16 * 1024)
}

fn commit_adopted_metadata_with_headroom(headroom: u64) -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let key = stage_key("memory-adopted-transient-credit")?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let budget = MemoryBudget::new(4 * 1024 * 1024);
    cache.attach_memory_budget(budget.clone())?;
    let lease = cache.lease(&key)?;
    fs::write(lease.directory().join("result"), b"result")?;
    let worker = budget.try_working_set(4 * 1024 * 1024 - headroom)?;
    let reservation = worker.budget().try_reserve(MemoryClass::Cache, 1024)?;
    let entry = lease.commit_with_reserved_metadata(
        StageStatus::Complete,
        json!({"payload": "x".repeat(4096)}),
        reservation,
    )?;
    drop(worker);
    assert!(budget.snapshot()?.used(MemoryClass::Cache) > 0);
    drop(entry);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn metadata_adoption_rejects_other_ledgers_and_non_cache_charges() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let key = stage_key("memory-invalid-adoption")?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let budget = MemoryBudget::new(4 * 1024 * 1024);
    let other = MemoryBudget::new(4 * 1024 * 1024);
    cache.attach_memory_budget(budget.clone())?;
    for reservation in [
        other.try_reserve(MemoryClass::Cache, 1024)?,
        budget.try_reserve(MemoryClass::Executor, 1024)?,
    ] {
        let lease = cache.lease(&key)?;
        fs::write(lease.directory().join("result"), b"result")?;
        assert!(matches!(
            lease.commit_with_reserved_metadata(
                StageStatus::Complete,
                json!({"payload": "value"}),
                reservation,
            ),
            Err(CacheError::InvalidInput(_))
        ));
    }
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    assert_eq!(other.snapshot()?.used_bytes, 0);
    assert!(cache.lookup(&key, CacheReadPolicy::CompleteOnly)?.is_none());
    Ok(())
}

#[test]
fn cache_without_attached_budget_can_adopt_the_callers_cache_charge() -> Result<(), Box<dyn Error>>
{
    let temporary = tempfile::tempdir()?;
    let key = stage_key("memory-adopted-unattached")?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let budget = MemoryBudget::new(4 * 1024 * 1024);
    let reservation = budget.try_reserve(MemoryClass::Cache, 1024)?;
    let lease = cache.lease(&key)?;
    fs::write(lease.directory().join("result"), b"result")?;
    let entry = lease.commit_with_reserved_metadata(
        StageStatus::Complete,
        json!({"payload": "value"}),
        reservation,
    )?;
    assert!(budget.snapshot()?.used(MemoryClass::Cache) >= 1024);
    drop(entry);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn rejected_metadata_charge_growth_preserves_the_previous_entry() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let key = stage_key("memory-adoption-denied")?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    save_fixture(&cache, &key, 10)?;
    let budget = MemoryBudget::new(64 * 1024);
    let reservation = budget.try_reserve(MemoryClass::Cache, 1024)?;
    let lease = cache.lease(&key)?;
    fs::write(lease.directory().join("result"), b"replacement")?;
    assert!(matches!(
        lease.commit_with_reserved_metadata(
            StageStatus::Complete,
            json!({"payload": "x".repeat(4096)}),
            reservation,
        ),
        Err(CacheError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    let entry = cache
        .lookup(&key, CacheReadPolicy::CompleteOnly)?
        .ok_or("the previous cache entry was lost")?;
    assert_eq!(
        entry.metadata().get("payload").and_then(|v| v.as_str()),
        Some("xxxxxxxxxx")
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn denied_lookup_does_not_read_the_large_metadata_column() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let key = stage_key("memory-denied-io")?;
    let producer = cache_at(temporary.path(), 64 * 1024)?;
    save_fixture(&producer, &key, LARGE_METADATA_BYTES)?;
    drop(producer);
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    cache.attach_memory_budget(MemoryBudget::new(1))?;
    let before = thread_read_bytes()?;
    assert!(matches!(
        cache.lookup(&key, CacheReadPolicy::CompleteOnly),
        Err(CacheError::Memory(MemoryError::Limit { .. }))
    ));
    let delta = thread_read_bytes()?
        .checked_sub(before)
        .ok_or("thread I/O counter moved backwards")?;
    assert!(
        delta < u64::try_from(LARGE_METADATA_BYTES / 4)?,
        "denied lookup read {delta} bytes"
    );
    Ok(())
}

#[test]
fn checkpoint_read_admission_fails_before_snapshot_decoding() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let key = stage_key("memory-checkpoint-read")?;
    let producer = cache_at(temporary.path(), 64 * 1024)?;
    let snapshot = l2_workbench::job::Job::new("snapshot").snapshot()?;
    producer.write_checkpoint(
        &key,
        &snapshot,
        l2_workbench::job::cache::CheckpointStatus::Active,
    )?;
    drop(producer);
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let budget = MemoryBudget::new(1);
    cache.attach_memory_budget(budget.clone())?;
    assert!(matches!(
        cache.read_checkpoint(&key),
        Err(CacheError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn checkpoint_write_admission_precedes_serialization_and_database_changes()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let key = stage_key("memory-checkpoint-write")?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let budget = MemoryBudget::new(1);
    cache.attach_memory_budget(budget.clone())?;
    let snapshot = l2_workbench::job::Job::new("snapshot").snapshot()?;
    assert!(matches!(
        cache.write_checkpoint(
            &key,
            &snapshot,
            l2_workbench::job::cache::CheckpointStatus::Active
        ),
        Err(CacheError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    assert_eq!(cache.stats()?.checkpoints, 0);
    Ok(())
}

#[test]
fn partial_entry_is_filtered_before_memory_admission() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let key = stage_key("memory-partial-filter")?;
    let producer = cache_at(temporary.path(), 64 * 1024)?;
    let lease = producer.lease(&key)?;
    fs::write(lease.directory().join("result"), b"partial")?;
    drop(lease.commit(StageStatus::Partial, json!({"payload": "x".repeat(5_000)}))?);
    drop(producer);
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let budget = MemoryBudget::new(1);
    cache.attach_memory_budget(budget.clone())?;
    assert!(cache.lookup(&key, CacheReadPolicy::CompleteOnly)?.is_none());
    assert_eq!(budget.snapshot()?.rejected, 0);
    assert!(matches!(
        cache.lookup(&key, CacheReadPolicy::AllowPartial),
        Err(CacheError::Memory(MemoryError::Limit { .. }))
    ));
    Ok(())
}

#[test]
fn denied_commit_does_not_publish_metadata_or_a_stage_result() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let key = stage_key("memory-denied-commit")?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let lease = cache.lease(&key)?;
    let budget = MemoryBudget::new(1);
    cache.attach_memory_budget(budget.clone())?;
    fs::write(lease.directory().join("result"), b"result")?;
    assert!(matches!(
        lease.commit(StageStatus::Complete, json!({"data": "new"})),
        Err(CacheError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(cache.stats()?.entries, 0);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn unexpected_tree_growth_is_rejected_and_releases_its_memory_charge() -> Result<(), Box<dyn Error>>
{
    let temporary = tempfile::tempdir()?;
    let key = stage_key("memory-tree-growth")?;
    let producer = cache_at(temporary.path(), 64 * 1024)?;
    save_fixture(&producer, &key, 32)?;
    let entry = producer
        .lookup(&key, CacheReadPolicy::CompleteOnly)?
        .ok_or("entry is missing")?;
    fs::write(entry.directory().join("extra"), b"new")?;
    drop(entry);
    drop(producer);
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let budget = MemoryBudget::new(2 * 1024 * 1024);
    cache.attach_memory_budget(budget.clone())?;
    assert!(matches!(
        cache.lookup(&key, CacheReadPolicy::CompleteOnly),
        Err(CacheError::CorruptEntry(_))
    ));
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn denied_checkpoint_read_after_a_large_write_avoids_scanning_the_wal() -> Result<(), Box<dyn Error>>
{
    assert_large_checkpoint_denial_is_bounded(false)
}

#[cfg(target_os = "linux")]
#[test]
fn denied_checkpoint_read_after_a_large_write_with_an_idle_connection_is_bounded()
-> Result<(), Box<dyn Error>> {
    assert_large_checkpoint_denial_is_bounded(true)
}

#[cfg(target_os = "linux")]
fn assert_large_checkpoint_denial_is_bounded(hold_idle: bool) -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let key = stage_key("memory-large-write-small-wal")?;
    let producer = cache_at(temporary.path(), 64 * 1024)?;
    let consumer = cache_at(temporary.path(), 64 * 1024)?;
    consumer.attach_memory_budget(MemoryBudget::new(1))?;

    // Start the large write with no existing WAL or live database connection
    let path = temporary.path().join("state/cache.sqlite3");
    let database = rusqlite::Connection::open(&path)?;
    database.query_row("SELECT count(*) FROM checkpoints", [], |row| {
        row.get::<_, i64>(0)
    })?;
    drop(database);
    assert!(!temporary.path().join("state/cache.sqlite3-wal").exists());
    let idle = if hold_idle {
        let database = rusqlite::Connection::open(&path)?;
        database.set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
            true,
        )?;
        database.query_row("SELECT count(*) FROM checkpoints", [], |row| {
            row.get::<_, i64>(0)
        })?;
        Some(database)
    } else {
        None
    };
    let snapshot = l2_workbench::job::Job::new("x".repeat(LARGE_METADATA_BYTES)).snapshot()?;
    producer.write_checkpoint(
        &key,
        &snapshot,
        l2_workbench::job::cache::CheckpointStatus::Active,
    )?;
    drop(idle);

    // The denied read must not first rebuild an oversized retained WAL
    let before = thread_read_bytes()?;
    assert!(matches!(
        consumer.read_checkpoint(&key),
        Err(CacheError::Memory(MemoryError::Limit { .. }))
    ));
    let delta = thread_read_bytes()?
        .checked_sub(before)
        .ok_or("thread I/O counter moved backwards")?;
    assert!(
        delta < u64::try_from(LARGE_METADATA_BYTES / 4)?,
        "denied read after a large write read {delta} bytes"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn denied_checkpoint_read_does_not_read_the_large_snapshot_column() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let key = stage_key("memory-denied-checkpoint-io")?;
    let producer = cache_at(temporary.path(), 64 * 1024)?;
    let snapshot = l2_workbench::job::Job::new("x".repeat(LARGE_METADATA_BYTES)).snapshot()?;
    producer.write_checkpoint(
        &key,
        &snapshot,
        l2_workbench::job::cache::CheckpointStatus::Active,
    )?;
    drop(producer);
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    cache.attach_memory_budget(MemoryBudget::new(1))?;
    let before = thread_read_bytes()?;
    assert!(matches!(
        cache.read_checkpoint(&key),
        Err(CacheError::Memory(MemoryError::Limit { .. }))
    ));
    let delta = thread_read_bytes()?
        .checked_sub(before)
        .ok_or("thread I/O counter moved backwards")?;
    assert!(
        delta < u64::try_from(LARGE_METADATA_BYTES / 4)?,
        "denied checkpoint read {delta} bytes"
    );
    Ok(())
}

#[test]
fn commit_admits_manifest_growth_before_recording_a_large_stage_tree() -> Result<(), Box<dyn Error>>
{
    let temporary = tempfile::tempdir()?;
    let key = stage_key("memory-manifest-growth")?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let budget = MemoryBudget::new(160 * 1024);
    cache.attach_memory_budget(budget.clone())?;
    let lease = cache.lease(&key)?;
    for index in 0..256 {
        fs::write(lease.directory().join(format!("item-{index:04}")), b"x")?;
    }
    assert!(matches!(
        lease.commit(StageStatus::Complete, json!({})),
        Err(CacheError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(cache.stats()?.entries, 0);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

const fn execution_limits() -> l2_workbench::job::cache::ExecutionCheckpointLimits {
    l2_workbench::job::cache::ExecutionCheckpointLimits {
        max_encoded_bytes: 4_096,
        max_executor_bytes: 4_096,
        max_metadata_bytes: 8_192,
    }
}

#[test]
fn active_writer_buffers_are_charged_and_released_after_publication() -> Result<(), Box<dyn Error>>
{
    let temporary = tempfile::tempdir()?;
    let key = stage_key("memory-active-writer")?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let budget = MemoryBudget::new(8 * 1024 * 1024);
    cache.attach_memory_budget(budget.clone())?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(
        &l2_workbench::job::Job::new("writer").snapshot()?,
        execution_limits(),
        |writer| {
            assert!(budget.snapshot()?.used(MemoryClass::Cache) >= 3 * 8 * 1024);
            writer.streams().2.write_all(b"cursor")?;
            Ok(json!({}))
        },
    )?;
    assert_eq!(budget.snapshot()?.used(MemoryClass::Cache), 0);
    Ok(())
}

#[test]
fn active_generation_keeps_its_envelope_charge_until_reader_drop() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let key = stage_key("memory-active-reader")?;
    let producer = cache_at(temporary.path(), 64 * 1024)?;
    let mut writer = producer.lease(&key)?;
    writer.save_active(
        &l2_workbench::job::Job::new("reader").snapshot()?,
        execution_limits(),
        |writer| {
            writer.streams().2.write_all(b"cursor")?;
            Ok(json!({"payload": "x".repeat(1_024)}))
        },
    )?;
    drop(writer);
    drop(producer);
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let budget = MemoryBudget::new(8 * 1024 * 1024);
    cache.attach_memory_budget(budget.clone())?;
    let lease = cache.lease(&key)?;
    let active = lease
        .load_active(execution_limits())?
        .ok_or("active generation is missing")?;
    let current = budget.snapshot()?;
    assert!(current.used(MemoryClass::Cache) > 0);
    assert!(current.peak_bytes > current.used_bytes);
    assert_eq!(
        active.metadata()["payload"].as_str().map(str::len),
        Some(1_024)
    );
    assert_eq!(active.executor_bytes(), 6);
    drop(active);
    assert_eq!(budget.snapshot()?.used(MemoryClass::Cache), 0);
    Ok(())
}

#[test]
fn active_save_memory_pressure_keeps_the_previous_generation() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let key = stage_key("memory-active-save-pressure")?;
    let producer = cache_at(temporary.path(), 64 * 1024)?;
    let snapshot = l2_workbench::job::Job::new("active pressure").snapshot()?;
    let mut writer = producer.lease(&key)?;
    writer.save_active(&snapshot, execution_limits(), |_| {
        Ok(json!({"generation": 1}))
    })?;
    drop(writer);
    drop(producer);
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let mut lease = cache.lease(&key)?;
    let budget = MemoryBudget::new(100 * 1024);
    cache.attach_memory_budget(budget.clone())?;
    let result = lease.save_active(&snapshot, execution_limits(), |_| {
        Ok(json!({"generation": 2}))
    });
    assert!(matches!(
        result,
        Err(CacheError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    drop(lease);
    drop(cache);
    let unbudgeted = cache_at(temporary.path(), 64 * 1024)?;
    assert_eq!(
        unbudgeted
            .lease(&key)?
            .load_active(execution_limits())?
            .ok_or("prior generation was lost")?
            .metadata(),
        &json!({"generation": 1})
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn denied_active_load_does_not_read_the_large_envelope_column() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let key = stage_key("memory-active-envelope-io")?;
    let producer = cache_at(temporary.path(), 4 * 1024 * 1024)?;
    let mut lease = producer.lease(&key)?;
    let caps = l2_workbench::job::cache::ExecutionCheckpointLimits {
        max_metadata_bytes: 2 * 1024 * 1024,
        ..execution_limits()
    };
    lease.save_active(
        &l2_workbench::job::Job::new("large envelope").snapshot()?,
        caps,
        |_| Ok(json!({"payload": "x".repeat(LARGE_METADATA_BYTES)})),
    )?;
    drop(lease);
    drop(producer);
    let cache = cache_at(temporary.path(), 4 * 1024 * 1024)?;
    let lease = cache.lease(&key)?;
    cache.attach_memory_budget(MemoryBudget::new(1))?;
    let before = thread_read_bytes()?;
    assert!(matches!(
        lease.load_active(caps),
        Err(CacheError::Memory(MemoryError::Limit { .. }))
    ));
    let delta = thread_read_bytes()?
        .checked_sub(before)
        .ok_or("thread I/O counter moved backwards")?;
    assert!(
        delta < u64::try_from(LARGE_METADATA_BYTES / 4)?,
        "denied active load read {delta} bytes"
    );
    Ok(())
}

#[test]
fn denied_active_writer_admission_does_not_invoke_the_callback_or_create_a_generation()
-> Result<(), Box<dyn Error>> {
    use std::cell::Cell;
    let temporary = tempfile::tempdir()?;
    let key = stage_key("memory-denied-active-writer")?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let mut lease = cache.lease(&key)?;
    cache.attach_memory_budget(MemoryBudget::new(1))?;
    let called = Cell::new(false);
    let result = lease.save_active(
        &l2_workbench::job::Job::new("denied writer").snapshot()?,
        execution_limits(),
        |_| {
            called.set(true);
            Ok(json!({}))
        },
    );
    assert!(matches!(
        result,
        Err(CacheError::Memory(MemoryError::Limit { .. }))
    ));
    assert!(!called.get());
    let database = rusqlite::Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    let count: i64 = database.query_row("SELECT count(*) FROM executions", [], |row| row.get(0))?;
    assert_eq!(count, 0);
    Ok(())
}
