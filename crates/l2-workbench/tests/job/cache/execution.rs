use super::{cache_at, stage_key};
use l2_workbench::job::{
    Counter, Job, Phase,
    cache::{CacheError, ExecutionCheckpointLimits, StageStatus},
};
use serde_json::json;
use std::{error::Error, io};

const fn limits() -> ExecutionCheckpointLimits {
    ExecutionCheckpointLimits {
        max_encoded_bytes: 4_096,
        max_executor_bytes: 1_024,
        max_metadata_bytes: 8_192,
    }
}

#[test]
fn active_generations_restore_one_committed_snapshot_and_all_components()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("active-search")?;
    let job = Job::new("active search");
    job.start(Phase::TransformDiscovery, None)?;
    job.increment(Counter::CandidatesExamined, 17)?;
    let expected = job.snapshot()?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&expected, limits(), |writer| {
        let (graph, blobs, executor) = writer.streams();
        graph.write_all(b"graph-one\n")?;
        blobs.write_all(b"exact-original-bytes")?;
        executor.write_all(br#"{"next_candidate":18,"work_charged":1234}"#)?;
        Ok(json!({"case_version":1,"work_charged":1234}))
    })?;
    drop(lease);

    let lease = cache.lease(&key)?;
    let mut saved = lease
        .load_active(limits())?
        .ok_or("active generation is missing")?;
    assert_eq!(saved.snapshot(), &expected);
    assert_eq!(
        saved.metadata(),
        &json!({"case_version":1,"work_charged":1234})
    );
    let (graph, blobs, executor) = saved.streams();
    let mut graph_bytes = Vec::new();
    graph.read_to_end(&mut graph_bytes)?;
    let mut blob_bytes = Vec::new();
    blobs.read_to_end(&mut blob_bytes)?;
    let mut executor_bytes = Vec::new();
    executor.read_to_end(&mut executor_bytes)?;
    assert_eq!(graph_bytes, b"graph-one\n");
    assert_eq!(blob_bytes, b"exact-original-bytes");
    assert_eq!(
        executor_bytes,
        br#"{"next_candidate":18,"work_charged":1234}"#
    );
    Ok(())
}

#[test]
fn failed_generation_write_keeps_the_previous_committed_cursor() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("active-search")?;
    let job = Job::new("active search");
    let snapshot = job.snapshot()?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&snapshot, limits(), |writer| {
        writer.streams().2.write_all(b"old-cursor")?;
        Ok(json!({"generation":1}))
    })?;

    let failed = lease.save_active(&snapshot, limits(), |writer| {
        writer.streams().2.write_all(b"uncommitted-cursor")?;
        Err(io::Error::other("injected interrupted write").into())
    });
    assert!(failed.is_err());
    let mut saved = lease
        .load_active(limits())?
        .ok_or("previous generation was lost")?;
    assert_eq!(saved.metadata(), &json!({"generation":1}));
    let mut state = Vec::new();
    saved.streams().2.read_to_end(&mut state)?;
    assert_eq!(state, b"old-cursor");
    Ok(())
}

#[test]
fn oversized_state_cannot_replace_a_valid_active_generation() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("active-search")?;
    let snapshot = Job::new("bounded search").snapshot()?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&snapshot, limits(), |writer| {
        writer.streams().2.write_all(b"old-cursor")?;
        Ok(json!({"generation":1}))
    })?;
    let error = lease.save_active(&snapshot, limits(), |writer| {
        // The writer must retain failure even if a caller ignores a short write error
        let _ = writer.streams().2.write_all(&vec![0; 1_025]);
        Ok(json!({"generation":2}))
    });
    assert!(matches!(error, Err(CacheError::QuotaExceeded { .. })));
    assert_eq!(
        lease
            .load_active(limits())?
            .ok_or("previous generation was lost")?
            .metadata(),
        &json!({"generation":1})
    );
    Ok(())
}

#[test]
fn terminal_stage_commit_retires_the_active_execution_atomically() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("active-search")?;
    let snapshot = Job::new("finished search").snapshot()?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&snapshot, limits(), |writer| {
        writer.streams().2.write_all(b"pending")?;
        Ok(json!({"generation":1}))
    })?;
    std::fs::write(lease.directory().join("result.bin"), b"finished")?;
    drop(lease.commit(StageStatus::Complete, json!({"complete":true}))?);
    let next = cache.lease(&key)?;
    assert!(next.load_active(limits())?.is_none());
    Ok(())
}

#[test]
fn active_execution_is_protected_from_cache_clear() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("active-search")?;
    let snapshot = Job::new("paused search").snapshot()?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&snapshot, limits(), |writer| {
        writer.streams().2.write_all(b"pending")?;
        Ok(json!({"generation":1}))
    })?;
    drop(lease);
    cache.clear()?;
    let next = cache.lease(&key)?;
    assert!(next.load_active(limits())?.is_some());
    Ok(())
}

#[test]
fn database_failure_does_not_replace_the_committed_generation_or_snapshot()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("database-rollback")?;
    let job = Job::new("rollback");
    let first = job.snapshot()?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&first, limits(), |writer| {
        writer.streams().2.write_all(b"first")?;
        Ok(json!({"generation": 1}))
    })?;
    job.increment(Counter::CandidatesExamined, 1)?;
    let later = job.snapshot()?;
    let database = rusqlite::Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    database.execute_batch("CREATE TRIGGER reject_execution_update BEFORE UPDATE ON executions BEGIN SELECT RAISE(ABORT, 'injected failure'); END;")?;
    let error = lease.save_active(&later, limits(), |writer| {
        writer.streams().2.write_all(b"second")?;
        Ok(json!({"generation": 2}))
    });
    assert!(error.is_err());
    let mut active = lease
        .load_active(limits())?
        .ok_or("committed generation disappeared")?;
    assert_eq!(active.snapshot(), &first);
    assert_eq!(active.metadata(), &json!({"generation": 1}));
    let mut bytes = Vec::new();
    active.streams().2.read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"first");
    assert_eq!(
        cache
            .read_checkpoint(&key)?
            .ok_or("checkpoint disappeared")?
            .snapshot,
        first
    );
    Ok(())
}

#[test]
fn same_length_component_corruption_is_rejected_before_a_reader_is_returned()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("component-corruption")?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&Job::new("corruption").snapshot()?, limits(), |writer| {
        writer.streams().2.write_all(b"original")?;
        Ok(json!({}))
    })?;
    let database = rusqlite::Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    let relative: String = database.query_row(
        "SELECT relative_path FROM executions WHERE key = ?1",
        [key.as_str()],
        |row| row.get(0),
    )?;
    std::fs::write(
        temporary
            .path()
            .join("cache/entries")
            .join(relative)
            .join("executor"),
        b"modified",
    )?;
    assert!(lease.load_active(limits()).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn hard_linked_checkpoint_component_is_rejected() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("linked-component")?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&Job::new("linked").snapshot()?, limits(), |writer| {
        writer.streams().2.write_all(b"linked")?;
        Ok(json!({}))
    })?;
    let database = rusqlite::Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    let relative: String = database.query_row(
        "SELECT relative_path FROM executions WHERE key = ?1",
        [key.as_str()],
        |row| row.get(0),
    )?;
    std::fs::hard_link(
        temporary
            .path()
            .join("cache/entries")
            .join(relative)
            .join("executor"),
        temporary.path().join("outside"),
    )?;
    assert!(lease.load_active(limits()).is_err());
    Ok(())
}

#[test]
fn active_bytes_are_reported_and_survive_prune_and_reopen() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("active-usage")?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&Job::new("usage").snapshot()?, limits(), |writer| {
        writer.streams().0.write_all(b"graph")?;
        Ok(json!({}))
    })?;
    assert!(cache.stats()?.entry_bytes >= 5);
    drop(lease);
    drop(cache);
    let reopened = cache_at(temporary.path(), 0)?;
    assert!(reopened.stats()?.over_limit_bytes > 0);
    reopened.prune()?;
    assert!(reopened.lease(&key)?.load_active(limits())?.is_some());
    Ok(())
}

#[test]
fn lower_read_limit_rejects_saved_metadata_before_decoding() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("metadata-read-limit")?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&Job::new("metadata").snapshot()?, limits(), |_| {
        Ok(json!({"value": "recorded"}))
    })?;
    let low = ExecutionCheckpointLimits {
        max_metadata_bytes: 32,
        ..limits()
    };
    assert!(lease.load_active(low).is_err());
    assert!(lease.load_active(limits())?.is_some());
    Ok(())
}

#[test]
fn pending_writes_share_the_global_quota() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 20_000)?;
    let first_key = stage_key("concurrent-reservation-first")?;
    let second_key = stage_key("concurrent-reservation-second")?;
    let (written_tx, written_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let first_cache = cache.clone();
    let writer = std::thread::spawn(move || -> Result<(), CacheError> {
        let mut lease = first_cache.lease(&first_key)?;
        let snapshot = Job::new("first")
            .snapshot()
            .map_err(|_| CacheError::InvalidInput("snapshot failed"))?;
        let caps = ExecutionCheckpointLimits {
            max_encoded_bytes: 16_000,
            max_executor_bytes: 1_024,
            max_metadata_bytes: 8_192,
        };
        lease.save_active(&snapshot, caps, |streams| {
            streams.streams().0.write_all(&vec![7; 12_000])?;
            written_tx
                .send(())
                .map_err(|_| CacheError::InvalidInput("coordination failed"))?;
            release_rx
                .recv()
                .map_err(|_| CacheError::InvalidInput("coordination failed"))?;
            Ok(json!({}))
        })
    });
    written_rx.recv()?;
    assert!(cache.stats()?.entry_bytes >= 12_000);
    let mut second = cache.lease(&second_key)?;
    let caps = ExecutionCheckpointLimits {
        max_encoded_bytes: 16_000,
        max_executor_bytes: 1_024,
        max_metadata_bytes: 8_192,
    };
    let result = second.save_active(&Job::new("second").snapshot()?, caps, |streams| {
        streams.streams().0.write_all(&vec![9; 12_000])?;
        Ok(json!({}))
    });
    release_tx.send(())?;
    writer.join().map_err(|_| "writer thread panicked")??;
    assert!(matches!(result, Err(CacheError::QuotaExceeded { .. })));
    Ok(())
}

#[test]
fn version_one_cache_migrates_without_losing_stage_or_checkpoint() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("migration")?;
    let snapshot = Job::new("migrated").snapshot()?;
    super::write_entry(&cache, &key, b"existing result")?;
    cache.write_checkpoint(
        &key,
        &snapshot,
        l2_workbench::job::cache::CheckpointStatus::Active,
    )?;
    drop(cache);
    let database = rusqlite::Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    database.execute_batch(
        "DROP TABLE execution_reservations; DROP TABLE executions; PRAGMA user_version = 1;",
    )?;
    drop(database);
    let migrated = cache_at(temporary.path(), 64 * 1024)?;
    assert_eq!(
        migrated
            .read_checkpoint(&key)?
            .ok_or("checkpoint was lost")?
            .snapshot,
        snapshot
    );
    assert!(
        migrated
            .lookup(
                &key,
                l2_workbench::job::cache::CacheReadPolicy::CompleteOnly
            )?
            .is_some()
    );
    let database = rusqlite::Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    let version: u32 = database.pragma_query_value(None, "user_version", |row| row.get(0))?;
    assert_eq!(version, 2);
    Ok(())
}

#[test]
fn failed_version_one_migration_leaves_schema_and_version_unchanged() -> Result<(), Box<dyn Error>>
{
    let temporary = tempfile::tempdir()?;
    drop(cache_at(temporary.path(), 64 * 1024)?);
    let database = rusqlite::Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    database.execute_batch("DROP TABLE execution_reservations; DROP TABLE executions; CREATE TABLE executions (key TEXT); PRAGMA user_version = 1;")?;
    drop(database);
    assert!(cache_at(temporary.path(), 64 * 1024).is_err());
    let database = rusqlite::Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    let version: u32 = database.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let reservations: i64 = database.query_row("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'execution_reservations'", [], |row| row.get(0))?;
    assert_eq!(version, 1);
    assert_eq!(reservations, 0);
    Ok(())
}

#[test]
fn stale_reservation_and_orphan_are_reclaimed_without_deleting_committed_data()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("stale-reservation")?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&Job::new("committed").snapshot()?, limits(), |writer| {
        writer.streams().2.write_all(b"current")?;
        Ok(json!({}))
    })?;
    drop(lease);
    let staged = temporary
        .path()
        .join("cache/staging")
        .join(key.as_str())
        .join("active-crashed");
    let orphan = temporary
        .path()
        .join("cache/entries")
        .join(key.as_str())
        .join("active-crashed");
    std::fs::create_dir_all(&staged)?;
    std::fs::create_dir_all(&orphan)?;
    std::fs::write(staged.join("part"), b"partial")?;
    std::fs::write(orphan.join("part"), b"orphan")?;
    let database = rusqlite::Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    database.execute(
        "INSERT INTO execution_reservations(token, key, bytes) VALUES (?1, ?2, 4096)",
        rusqlite::params![format!("{}/active-crashed", key.as_str()), key.as_str()],
    )?;
    let before = cache.stats()?.entry_bytes;
    cache.prune()?;
    assert!(!staged.exists());
    assert!(!orphan.exists());
    assert_eq!(cache.stats()?.entry_bytes + 4096, before);
    let lease = cache.lease(&key)?;
    let mut saved = lease
        .load_active(limits())?
        .ok_or("committed generation was lost")?;
    let mut data = Vec::new();
    saved.streams().2.read_to_end(&mut data)?;
    assert_eq!(data, b"current");
    Ok(())
}

#[test]
fn failed_terminal_transaction_keeps_the_active_generation() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("terminal-rollback")?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&Job::new("terminal").snapshot()?, limits(), |writer| {
        writer.streams().2.write_all(b"resume")?;
        Ok(json!({}))
    })?;
    let database = rusqlite::Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    database.execute_batch("CREATE TRIGGER reject_retirement BEFORE DELETE ON executions BEGIN SELECT RAISE(ABORT, 'injected failure'); END;")?;
    std::fs::write(lease.directory().join("result"), b"final")?;
    assert!(lease.commit(StageStatus::Complete, json!({})).is_err());
    drop(database);
    let lease = cache.lease(&key)?;
    let mut active = lease
        .load_active(limits())?
        .ok_or("active generation was lost")?;
    let mut data = Vec::new();
    active.streams().2.read_to_end(&mut data)?;
    assert_eq!(data, b"resume");
    Ok(())
}

#[test]
fn small_checkpoint_does_not_evict_results_for_unused_reservation_space()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 8_000)?;
    let existing = stage_key("reservation-existing")?;
    super::write_entry(&cache, &existing, &vec![1; 5_000])?;
    let key = stage_key("reservation-small")?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&Job::new("small").snapshot()?, limits(), |writer| {
        writer.streams().0.write_all(b"x")?;
        Ok(json!({}))
    })?;
    assert!(
        cache
            .lookup(
                &existing,
                l2_workbench::job::cache::CacheReadPolicy::CompleteOnly
            )?
            .is_some()
    );
    Ok(())
}
