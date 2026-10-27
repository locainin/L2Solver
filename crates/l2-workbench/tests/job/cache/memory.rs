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
    let budget = MemoryBudget::new(1);
    cache.attach_memory_budget(budget.clone())?;
    let lease = cache.lease(&key)?;
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
