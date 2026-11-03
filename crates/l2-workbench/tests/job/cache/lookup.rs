use std::{
    error::Error,
    fs,
    time::{Duration, Instant},
};

use l2_workbench::job::{
    MemoryBudget, MemoryError,
    cache::{CacheError, CacheReadPolicy, StageKey, StageStatus},
};
use rusqlite::Connection;
use serde_json::json;

use super::{cache_at, stage_key, write_entry};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn wal_writer_does_not_block_a_valid_hit_and_later_reads_refresh_lru() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 6)?;
    let older = stage_key("contended-older")?;
    let newer = stage_key("contended-newer")?;
    let older_directory = write_entry(&cache, &older, b"old")?;
    let newer_directory = write_entry(&cache, &newer, b"new")?;
    let database = Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    let journal: String = database.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    assert_eq!(journal.to_ascii_lowercase(), "wal");
    let set_order = "UPDATE entries SET accessed_ns = CASE key WHEN ?1 THEN 1 ELSE 2 END";
    let read_recency = "SELECT accessed_ns FROM entries WHERE key = ?1";
    database.execute(set_order, [older.as_str()])?;

    // Hold the SQLite writer until the lookup has returned
    database.execute_batch("BEGIN IMMEDIATE")?;
    let started = Instant::now();
    let entry = cache
        .lookup(&older, CacheReadPolicy::CompleteOnly)?
        .ok_or("contended entry disappeared")?;
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "recency update waited for the writer"
    );
    assert_eq!(entry.status(), StageStatus::Complete);
    assert_eq!(entry.metadata(), &json!({"items": 1}));
    assert_eq!(fs::read(entry.directory().join("result.bin"))?, b"old");
    assert!(matches!(cache.lease(&older), Err(CacheError::LockBusy)));
    let unchanged: i64 = database.query_row(read_recency, [older.as_str()], |row| row.get(0))?;
    assert_eq!(unchanged, 1, "a blocked touch must not change recency");
    database.execute_batch("ROLLBACK")?;

    // Even stale recency cannot let maintenance remove a pinned entry
    let tight_cache = cache_at(temporary.path(), 3)?;
    assert!(older_directory.is_dir(), "maintenance removed a live pin");
    assert!(
        !newer_directory.exists(),
        "maintenance skipped an unpinned entry"
    );
    assert_eq!(tight_cache.stats()?.entry_bytes, 3);
    drop(tight_cache);
    drop(entry);

    // Restore the comparison entry and assign a known LRU order
    let newer_directory = write_entry(&cache, &newer, b"new")?;
    database.execute(set_order, [older.as_str()])?;
    // Once the writer is gone, a normal hit must refresh LRU again
    drop(cache.lookup(&older, CacheReadPolicy::CompleteOnly)?);
    let refreshed: i64 = database.query_row(read_recency, [older.as_str()], |row| row.get(0))?;
    assert!(refreshed > 2, "the later hit did not refresh LRU");
    let tight_cache = cache_at(temporary.path(), 3)?;
    assert!(older_directory.is_dir(), "the refreshed entry was evicted");
    assert!(
        !newer_directory.exists(),
        "the older LRU entry was retained"
    );
    assert_eq!(tight_cache.stats()?.entry_bytes, 3);
    Ok(())
}

#[test]
fn wal_writer_preserves_partial_and_missing_lookup_policies() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 1024)?;
    let key = stage_key("contended-partial")?;
    let lease = cache.lease(&key)?;
    fs::write(lease.directory().join("result.bin"), b"partial")?;
    drop(lease.commit(StageStatus::Partial, json!({"next": 7}))?);
    let missing = stage_key("contended-missing")?;
    let database = Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    database.execute_batch("BEGIN IMMEDIATE")?;

    // Missing and filtered results do not need a recency write
    assert!(cache.lookup(&key, CacheReadPolicy::CompleteOnly)?.is_none());
    assert!(
        cache
            .lookup(&missing, CacheReadPolicy::AllowPartial)?
            .is_none()
    );
    let partial = cache
        .lookup(&key, CacheReadPolicy::AllowPartial)?
        .ok_or("partial result disappeared")?;
    assert_eq!(partial.status(), StageStatus::Partial);
    assert_eq!(partial.metadata(), &json!({"next": 7}));
    assert_eq!(
        fs::read(partial.directory().join("result.bin"))?,
        b"partial"
    );
    database.execute_batch("ROLLBACK")?;
    Ok(())
}

#[test]
fn wal_writer_does_not_hide_invalid_entries_or_memory_denial() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 1024)?;
    let bad_metadata = stage_key("contended-metadata")?;
    let bad_stage = stage_key("contended-stage")?;
    let bad_path = stage_key("contended-path")?;
    let changed_file = stage_key("contended-file")?;
    let valid = stage_key("contended-memory")?;
    for key in [&bad_metadata, &bad_stage, &bad_path, &valid] {
        write_entry(&cache, key, b"valid")?;
    }
    let changed_directory = write_entry(&cache, &changed_file, b"valid")?;
    fs::write(changed_directory.join("result.bin"), b"changed length")?;
    let budgeted = cache_at(temporary.path(), 1024)?;
    budgeted.attach_memory_budget(MemoryBudget::new(1))?;
    let database = Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    // Commit each damaged row before taking the writer lock seen by the reader
    database.execute(
        "UPDATE entries SET metadata_json = '{' WHERE key = ?1",
        [bad_metadata.as_str()],
    )?;
    database.execute(
        "UPDATE entries SET stage = 'different' WHERE key = ?1",
        [bad_stage.as_str()],
    )?;
    database.execute(
        "UPDATE entries SET relative_path = '../outside' WHERE key = ?1",
        [bad_path.as_str()],
    )?;
    database.execute_batch("BEGIN IMMEDIATE")?;

    for key in [&bad_metadata, &bad_stage, &bad_path, &changed_file] {
        assert!(
            matches!(
                cache.lookup(key, CacheReadPolicy::CompleteOnly),
                Err(CacheError::CorruptEntry(_))
            ),
            "corruption was not reported for {}",
            key.stage()
        );
    }
    let bad_digest: StageKey =
        serde_json::from_value(json!({"digest": "invalid", "stage": "contended-digest"}))?;
    assert!(matches!(
        cache.lookup(&bad_digest, CacheReadPolicy::CompleteOnly),
        Err(CacheError::InvalidInput(_))
    ));
    assert!(matches!(
        budgeted.lookup(&valid, CacheReadPolicy::CompleteOnly),
        Err(CacheError::Memory(MemoryError::Limit { .. }))
    ));
    database.execute_batch("ROLLBACK")?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn wal_writer_does_not_hide_a_replaced_cache_root() -> TestResult {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 1024)?;
    let key = stage_key("contended-replaced-root")?;
    write_entry(&cache, &key, b"valid")?;
    let database = Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    database.execute_batch("BEGIN IMMEDIATE")?;
    let outside = temporary.path().join("outside");
    fs::create_dir(&outside)?;
    fs::write(outside.join("keep"), b"untouched")?;
    // The cache still holds the original directory after this path is replaced
    fs::rename(
        temporary.path().join("cache"),
        temporary.path().join("moved"),
    )?;
    symlink(&outside, temporary.path().join("cache"))?;

    assert!(matches!(
        cache.lookup(&key, CacheReadPolicy::CompleteOnly),
        Err(CacheError::UnsafePath(_))
    ));
    assert_eq!(fs::read(outside.join("keep"))?, b"untouched");
    database.execute_batch("ROLLBACK")?;
    Ok(())
}

#[test]
fn recency_update_reports_noncontention_database_errors() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 1024)?;
    let key = stage_key("rejected-touch")?;
    write_entry(&cache, &key, b"valid")?;
    let database = Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    // Fail only the recency write, after the entry itself has been validated
    database.execute_batch("CREATE TRIGGER reject_recency BEFORE UPDATE OF accessed_ns ON entries BEGIN SELECT RAISE(ABORT, 'recency rejected'); END")?;

    match cache.lookup(&key, CacheReadPolicy::CompleteOnly) {
        Err(CacheError::Database(error)) => {
            assert!(error.to_string().contains("recency rejected"));
        }
        result => return Err(format!("unexpected lookup result: {result:?}").into()),
    }
    database.execute_batch("DROP TRIGGER reject_recency")?;
    assert!(cache.lookup(&key, CacheReadPolicy::CompleteOnly)?.is_some());
    Ok(())
}
