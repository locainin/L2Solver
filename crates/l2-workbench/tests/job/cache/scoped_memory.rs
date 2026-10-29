use super::{execution::limits, stage_key, write_entry};
use l2_workbench::job::{
    Job, MemoryBudget, MemoryClass, MemoryError,
    cache::{Cache, CacheError, CacheReadPolicy, CheckpointStatus, StageStatus},
};
use serde_json::json;
use std::{error::Error, fs, path::Path};

const LIMIT: u64 = 4 * 1024 * 1024;
const HEADROOM: u64 = 16 * 1024;

fn cache_with_budget(path: &Path, budget: &MemoryBudget) -> Result<Cache, CacheError> {
    Cache::open_at_with_memory_budget(
        path.join("cache"),
        path.join("state"),
        64 * 1024,
        budget.clone(),
    )
}

#[test]
fn scoped_lookup_and_commit_spend_worker_credit_without_rebinding_the_root()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let budget = MemoryBudget::new(LIMIT);
    let cache = cache_with_budget(directory.path(), &budget)?;
    let cached_key = stage_key("scoped-cached")?;
    let new_key = stage_key("scoped-new")?;
    write_entry(&cache, &cached_key, b"cached data")?;
    let worker = budget.try_working_set(LIMIT - HEADROOM)?;
    let scoped = cache.with_memory_scope(worker.budget())?;

    // An unscoped clone cannot spend credit reserved by this worker
    assert!(matches!(
        cache.lookup(&cached_key, CacheReadPolicy::CompleteOnly),
        Err(CacheError::Memory(MemoryError::Limit { .. }))
    ));
    assert!(matches!(
        cache.lease(&new_key),
        Err(CacheError::Memory(MemoryError::Limit { .. }))
    ));
    let cached = scoped
        .lookup(&cached_key, CacheReadPolicy::CompleteOnly)?
        .ok_or("the scoped lookup lost the existing entry")?;
    assert_eq!(cached.metadata(), &json!({"items": 1}));
    drop(cached);

    let lease = scoped.lease(&new_key)?;
    fs::write(lease.directory().join("result"), b"worker data")?;
    let saved = lease.commit(StageStatus::Complete, json!({"scope": "worker"}))?;
    drop(scoped);
    drop(worker);
    assert!(budget.snapshot()?.used(MemoryClass::Cache) > 0);
    drop(saved);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    let saved = cache
        .lookup(&new_key, CacheReadPolicy::CompleteOnly)?
        .ok_or("the committed entry is missing")?;
    assert_eq!(saved.metadata(), &json!({"scope": "worker"}));
    Ok(())
}

#[test]
fn one_scoped_handle_cannot_spend_another_workers_credit() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let budget = MemoryBudget::new(LIMIT);
    let cache = cache_with_budget(directory.path(), &budget)?;
    let key = stage_key("scoped-separate-workers")?;
    write_entry(&cache, &key, b"shared entry")?;
    let small = budget.try_working_set(8 * 1024)?;
    let large = budget.try_working_set(LIMIT - 8 * 1024 - HEADROOM)?;
    let small_cache = cache.with_memory_scope(small.budget())?;
    let large_cache = cache.with_memory_scope(large.budget())?;

    assert!(matches!(
        small_cache.lookup(&key, CacheReadPolicy::CompleteOnly),
        Err(CacheError::Memory(MemoryError::Limit { .. }))
    ));
    let entry = large_cache
        .lookup(&key, CacheReadPolicy::CompleteOnly)?
        .ok_or("the larger worker could not find the entry")?;
    assert_eq!(entry.metadata(), &json!({"items": 1}));
    drop(entry);
    drop(small_cache);
    drop(large_cache);
    drop(small);
    drop(large);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn scoped_commit_rejects_metadata_charged_to_another_worker() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let budget = MemoryBudget::new(LIMIT);
    let cache = cache_with_budget(directory.path(), &budget)?;
    let key = stage_key("scoped-foreign-metadata")?;
    let worker = budget.try_working_set(512 * 1024)?;
    let other = budget.try_working_set(512 * 1024)?;
    let scoped = cache.with_memory_scope(worker.budget())?;
    let lease = scoped.lease(&key)?;
    fs::write(lease.directory().join("result"), b"unpublished")?;
    let foreign = other.budget().try_reserve(MemoryClass::Cache, 1024)?;
    assert!(matches!(
        lease.commit_with_reserved_metadata(StageStatus::Complete, json!({"items": 1}), foreign),
        Err(CacheError::InvalidInput(_))
    ));
    assert!(cache.lookup(&key, CacheReadPolicy::CompleteOnly)?.is_none());
    drop(scoped);
    drop(worker);
    drop(other);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn scoped_checkpoints_and_execution_use_the_worker_credit() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let budget = MemoryBudget::new(LIMIT);
    let cache = cache_with_budget(directory.path(), &budget)?;
    let checkpoint_key = stage_key("scoped-checkpoint")?;
    let execution_key = stage_key("scoped-execution")?;
    let snapshot = Job::new("scoped checkpoint").snapshot()?;
    let worker = budget.try_working_set(LIMIT - HEADROOM)?;
    let scoped = cache.with_memory_scope(worker.budget())?;

    scoped.write_checkpoint(&checkpoint_key, &snapshot, CheckpointStatus::Complete)?;
    assert_eq!(
        scoped
            .read_checkpoint(&checkpoint_key)?
            .ok_or("checkpoint was not saved")?
            .snapshot,
        snapshot
    );
    let mut lease = scoped.lease(&execution_key)?;
    lease.save_active(&snapshot, limits(), |writer| {
        let (graph, blobs, executor) = writer.streams();
        graph.write_all(b"graph")?;
        blobs.write_all(b"blobs")?;
        executor.write_all(b"cursor")?;
        Ok(json!({"cursor": 1}))
    })?;
    let mut active = lease
        .load_active(limits())?
        .ok_or("active execution is missing")?;
    assert_eq!(active.snapshot(), &snapshot);
    assert_eq!(active.metadata(), &json!({"cursor": 1}));
    let mut restored = Vec::new();
    active.streams().2.read_to_end(&mut restored)?;
    assert_eq!(restored, b"cursor");
    drop(active);
    drop(lease);
    drop(scoped);
    drop(worker);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn scoped_handle_rejects_unattached_or_different_ledgers() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let cache = super::cache_at(directory.path(), 64 * 1024)?;
    let budget = MemoryBudget::new(LIMIT);
    let foreign = MemoryBudget::new(LIMIT);
    let worker = budget.try_working_set(1024)?;
    assert!(matches!(
        cache.with_memory_scope(worker.budget()),
        Err(CacheError::InvalidInput(_))
    ));
    // Rejecting a scope does not consume the cache's one-time budget attachment
    cache.attach_memory_budget(budget.clone())?;
    assert!(matches!(
        cache.with_memory_scope(&foreign),
        Err(CacheError::InvalidInput(_))
    ));
    cache.with_memory_scope(worker.budget())?;
    drop(worker);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    assert_eq!(foreign.snapshot()?.used_bytes, 0);
    Ok(())
}
