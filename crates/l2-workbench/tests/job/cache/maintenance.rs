use std::{error::Error, fs, path::Path};

use l2_workbench::job::{
    MemoryBudget, MemoryClass, MemoryError,
    cache::{Cache, CacheError, StageStatus},
};
use serde_json::json;

use super::stage_key;

fn seed_index(root: &Path, count: usize, pinned: usize) -> Result<(), Box<dyn Error>> {
    let cache = Cache::open_at(root.join("cache"), root.join("state"), u64::MAX)?;
    drop(cache);
    let mut database = rusqlite::Connection::open(root.join("state/cache.sqlite3"))?;
    let transaction = database.transaction()?;
    for index in 0..count {
        let key = format!("{index:064x}");
        let relative = format!("{key}/lease-seeded");
        let directory = root.join("cache/entries").join(&relative);
        fs::create_dir_all(&directory)?;
        fs::write(directory.join("result"), b"x")?;
        transaction.execute(
            "INSERT INTO entries(key, stage, status, relative_path, metadata_json, manifest_json, bytes, created_ns, accessed_ns) VALUES (?1, 'bulk', 1, ?2, '{}', '{}', 1, 1, 1)",
            rusqlite::params![key, relative],
        )?;
        if index < pinned {
            transaction.execute("INSERT INTO checkpoints(key, status, snapshot_version, snapshot_json, updated_ns) VALUES (?1, 1, 2, '{}', 1)", [&key])?;
        }
        transaction.execute(
            "INSERT INTO execution_reservations(token, key, bytes) VALUES (?1, ?2, 0)",
            rusqlite::params![format!("{key}/active-debris"), key],
        )?;
        transaction.execute(
            "INSERT INTO retired_generations(key, relative_path, bytes) VALUES (?1, ?2, 0)",
            rusqlite::params![key, format!("{key}/active-retired")],
        )?;
    }
    transaction.commit()?;
    Ok(())
}

#[test]
fn budgeted_open_prunes_all_unpinned_rows_with_bounded_maintenance_memory()
-> Result<(), Box<dyn Error>> {
    const COUNT: usize = 257;
    const PINNED: usize = 33;
    let temporary = tempfile::tempdir()?;
    seed_index(temporary.path(), COUNT, PINNED)?;
    let budget = MemoryBudget::new(128 * 1024);
    let cache = Cache::open_at_with_memory_budget(
        temporary.path().join("cache"),
        temporary.path().join("state"),
        0,
        budget.clone(),
    )?;
    let stats = cache.stats()?;
    assert_eq!(stats.entries, u64::try_from(PINNED)?);
    assert_eq!(stats.entry_bytes, u64::try_from(PINNED)?);
    assert_eq!(stats.checkpoints, u64::try_from(PINNED)?);
    assert_eq!(budget.snapshot()?.used(MemoryClass::Cache), 0);
    assert!(budget.snapshot()?.peak_bytes <= 128 * 1024);
    let database = rusqlite::Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    let reservations: i64 =
        database.query_row("SELECT count(*) FROM execution_reservations", [], |row| {
            row.get(0)
        })?;
    let retired: i64 =
        database.query_row("SELECT count(*) FROM retired_generations", [], |row| {
            row.get(0)
        })?;
    assert_eq!((reservations, retired), (0, 0));
    assert!(cache.attach_memory_budget(budget).is_err());
    Ok(())
}

#[test]
fn capacity_admission_evicts_all_needed_pages_without_skipping_equal_lru_keys()
-> Result<(), Box<dyn Error>> {
    const COUNT: usize = 129;
    let temporary = tempfile::tempdir()?;
    seed_index(temporary.path(), COUNT, 0)?;
    let budget = MemoryBudget::new(256 * 1024);
    let cache = Cache::open_at_with_memory_budget(
        temporary.path().join("cache"),
        temporary.path().join("state"),
        u64::try_from(COUNT)?,
        budget.clone(),
    )?;
    let key = stage_key("paged-incoming")?;
    let lease = cache.lease(&key)?;
    fs::write(lease.directory().join("result"), vec![1; COUNT])?;
    drop(lease.commit(StageStatus::Complete, json!({}))?);
    let stats = cache.stats()?;
    assert_eq!(
        (stats.entries, stats.entry_bytes),
        (1, u64::try_from(COUNT)?)
    );
    assert_eq!(budget.snapshot()?.used(MemoryClass::Cache), 0);
    assert!(budget.snapshot()?.peak_bytes <= 256 * 1024);
    Ok(())
}

#[test]
fn impossible_admission_does_not_evict_any_candidate_across_pages() -> Result<(), Box<dyn Error>> {
    const COUNT: usize = 129;
    const PINNED: usize = 100;
    let temporary = tempfile::tempdir()?;
    seed_index(temporary.path(), COUNT, PINNED)?;
    let budget = MemoryBudget::new(256 * 1024);
    let cache = Cache::open_at_with_memory_budget(
        temporary.path().join("cache"),
        temporary.path().join("state"),
        u64::try_from(COUNT)?,
        budget,
    )?;
    let key = stage_key("paged-impossible")?;
    let lease = cache.lease(&key)?;
    fs::write(lease.directory().join("result"), vec![1; 30])?;
    assert!(matches!(
        lease.commit(StageStatus::Complete, json!({})),
        Err(CacheError::QuotaExceeded { .. })
    ));
    assert_eq!(cache.stats()?.entries, u64::try_from(COUNT)?);
    Ok(())
}

#[test]
fn startup_maintenance_uses_the_budget_before_allocating_a_page() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    seed_index(temporary.path(), 40, 0)?;
    let budget = MemoryBudget::new(1);
    let result = Cache::open_at_with_memory_budget(
        temporary.path().join("cache"),
        temporary.path().join("state"),
        0,
        budget.clone(),
    );
    assert!(matches!(
        result,
        Err(CacheError::Memory(MemoryError::Limit { .. }))
    ));
    let database = rusqlite::Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    let entries: i64 = database.query_row("SELECT count(*) FROM entries", [], |row| row.get(0))?;
    assert_eq!(entries, 40);
    assert!(budget.snapshot()?.rejected > 0);
    Ok(())
}

#[cfg(unix)]
#[test]
fn new_active_checkpoint_waits_until_quota_planning_releases_its_gate() -> Result<(), Box<dyn Error>>
{
    use std::{sync::mpsc, time::Duration};
    let temporary = tempfile::tempdir()?;
    let cache = Cache::open_at(
        temporary.path().join("cache"),
        temporary.path().join("state"),
        1_024,
    )?;
    let key = stage_key("quota-checkpoint-gate")?;
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(temporary.path().join("state/locks/quota.lock"))?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive)?;
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let worker_cache = cache;
    let worker = std::thread::spawn(move || {
        let snapshot = l2_workbench::job::Job::new("gated checkpoint").snapshot();
        let _ = started_tx.send(());
        let result = snapshot
            .map_err(|error| error.to_string())
            .and_then(|snapshot| {
                worker_cache
                    .write_checkpoint(
                        &key,
                        &snapshot,
                        l2_workbench::job::cache::CheckpointStatus::Active,
                    )
                    .map_err(|error| error.to_string())
            });
        let _ = done_tx.send(result);
    });
    started_rx.recv_timeout(Duration::from_secs(5))?;
    assert!(matches!(
        done_rx.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    drop(file);
    done_rx
        .recv_timeout(Duration::from_secs(5))?
        .map_err(std::io::Error::other)?;
    worker.join().map_err(|_| "checkpoint worker panicked")?;
    Ok(())
}

#[test]
fn lru_keyset_query_uses_the_existing_ordered_index() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    drop(Cache::open_at(
        temporary.path().join("cache"),
        temporary.path().join("state"),
        1_024,
    )?);
    let database = rusqlite::Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    let mut statement = database.prepare("EXPLAIN QUERY PLAN SELECT accessed_ns, created_ns, key, bytes FROM entries WHERE (accessed_ns, created_ns, key) > (?1, ?2, ?3) ORDER BY accessed_ns, created_ns, key LIMIT 1")?;
    let details = statement
        .query_map(rusqlite::params![1_i64, 1_i64, "0".repeat(64)], |row| {
            row.get::<_, String>(3)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    assert!(details.iter().any(|detail| detail.contains("entries_lru")));
    assert!(details.iter().all(|detail| !detail.contains("TEMP B-TREE")));
    Ok(())
}
