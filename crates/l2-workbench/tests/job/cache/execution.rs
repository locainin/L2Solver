use super::{cache_at, stage_key};
use l2_workbench::job::{
    Counter, Job, Phase,
    cache::{CacheError, ExecutionCheckpointLimits, StageStatus},
};
use serde_json::json;
use std::{
    error::Error,
    io,
    path::{Path, PathBuf},
};

const fn limits() -> ExecutionCheckpointLimits {
    ExecutionCheckpointLimits {
        max_encoded_bytes: 4_096,
        max_executor_bytes: 1_024,
        max_metadata_bytes: 8_192,
    }
}

fn active_staging_directory(parent: &Path) -> io::Result<PathBuf> {
    let mut active = None;
    for item in std::fs::read_dir(parent)? {
        let item = item?;
        if item
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with("active-"))
            && active.replace(item.path()).is_some()
        {
            return Err(io::Error::other("multiple active staging directories"));
        }
    }
    active.ok_or_else(|| io::Error::other("active staging directory is missing"))
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

#[cfg(target_os = "linux")]
#[test]
fn real_full_filesystem_preserves_the_committed_execution_generation() -> Result<(), Box<dyn Error>>
{
    use std::{fs, io::Write};

    let Some(base) = std::env::var_os("L2_TEST_ENOSPC_ROOT") else {
        eprintln!("active-generation ENOSPC test needs an isolated small filesystem");
        return Ok(());
    };
    let temporary = tempfile::tempdir_in(base)?;
    let cache = cache_at(temporary.path(), 4 * 1024 * 1024)?;
    let key = stage_key("real-full-generation")?;
    let job = Job::new("active search");
    let first = job.snapshot()?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&first, limits(), |writer| {
        writer.streams().2.write_all(b"first-cursor")?;
        Ok(json!({"generation":1}))
    })?;

    // Fill only the isolated tmpfs while keeping its filler inode alive
    let filler_path = temporary.path().join("space-filler");
    let mut filler = fs::File::create(&filler_path)?;
    let block = [0_u8; 8 * 1024];
    let mut full = false;
    for _ in 0..512 {
        if let Err(error) = filler.write_all(&block) {
            assert_eq!(error.kind(), io::ErrorKind::StorageFull);
            full = true;
            break;
        }
    }
    assert!(full, "the isolated filesystem did not report ENOSPC");
    job.increment(Counter::CandidatesExamined, 1)?;
    let later = job.snapshot()?;
    let failure = lease.save_active(&later, limits(), |writer| {
        writer.streams().2.write_all(b"second-cursor")?;
        Ok(json!({"generation":2}))
    });
    let error = failure
        .err()
        .ok_or("generation was saved on a full filesystem")?;
    let storage_failure = match &error {
        CacheError::Io(error) => error.kind() == io::ErrorKind::StorageFull,
        CacheError::Database(error) => matches!(
            error.downcast_ref::<rusqlite::Error>(),
            Some(rusqlite::Error::SqliteFailure(code, _))
                if matches!(code.code, rusqlite::ErrorCode::DiskFull | rusqlite::ErrorCode::SystemIoFailure)
        ),
        _ => false,
    };
    eprintln!("full-filesystem generation result: {error:?}");
    assert!(
        storage_failure,
        "generation failed for a different reason: {error}"
    );
    drop(filler);
    fs::remove_file(filler_path)?;
    drop(lease);

    // Reopen the lease and read the previous generation after space is freed
    let reopened = cache.lease(&key)?;
    let mut active = reopened
        .load_active(limits())?
        .ok_or("committed generation disappeared")?;
    assert_eq!(active.snapshot(), &first);
    assert_eq!(active.metadata(), &json!({"generation":1}));
    let mut cursor = Vec::new();
    active.streams().2.read_to_end(&mut cursor)?;
    assert_eq!(cursor, b"first-cursor");
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
    drop(active);
    database.execute_batch("DROP TRIGGER reject_execution_update;")?;
    lease.save_active(&later, limits(), |writer| {
        writer.streams().2.write_all(b"second")?;
        Ok(json!({"generation": 2}))
    })?;
    assert_eq!(
        lease
            .load_active(limits())?
            .ok_or("retry did not commit")?
            .snapshot(),
        &later
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
    cache.prune()?;
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
        "DROP TABLE retired_generations; DROP TABLE execution_reservations; DROP TABLE executions; PRAGMA user_version = 1;",
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
    assert_eq!(version, 3);
    Ok(())
}

#[test]
fn failed_version_one_migration_leaves_schema_and_version_unchanged() -> Result<(), Box<dyn Error>>
{
    let temporary = tempfile::tempdir()?;
    drop(cache_at(temporary.path(), 64 * 1024)?);
    let database = rusqlite::Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    database.execute_batch("DROP TABLE retired_generations; DROP TABLE execution_reservations; DROP TABLE executions; CREATE TABLE executions (key TEXT); PRAGMA user_version = 1;")?;
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

#[test]
fn large_checkpoint_evicts_unpinned_results_when_its_actual_bytes_need_space()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 12_000)?;
    let existing = stage_key("large-reservation-existing")?;
    super::write_entry(&cache, &existing, &vec![1; 8_000])?;
    let key = stage_key("large-reservation-incoming")?;
    let mut lease = cache.lease(&key)?;
    let caps = ExecutionCheckpointLimits {
        max_encoded_bytes: 8_000,
        ..limits()
    };
    lease.save_active(&Job::new("large").snapshot()?, caps, |writer| {
        writer.streams().0.write_all(&vec![2; 5_000])?;
        Ok(json!({}))
    })?;
    assert!(
        cache
            .lookup(
                &existing,
                l2_workbench::job::cache::CacheReadPolicy::CompleteOnly
            )?
            .is_none()
    );
    assert!(lease.load_active(caps)?.is_some());
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlinked_checkpoint_component_is_rejected_without_touching_its_target()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("symlink-component")?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&Job::new("symlink").snapshot()?, limits(), |writer| {
        writer.streams().2.write_all(b"original")?;
        Ok(json!({}))
    })?;
    let database = rusqlite::Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    let relative: String = database.query_row(
        "SELECT relative_path FROM executions WHERE key = ?1",
        [key.as_str()],
        |row| row.get(0),
    )?;
    let component = temporary
        .path()
        .join("cache/entries")
        .join(relative)
        .join("executor");
    let target = temporary.path().join("outside");
    std::fs::write(&target, b"original")?;
    std::fs::remove_file(&component)?;
    std::os::unix::fs::symlink(&target, &component)?;
    assert!(lease.load_active(limits()).is_err());
    assert_eq!(std::fs::read(target)?, b"original");
    Ok(())
}

#[test]
fn oversized_metadata_does_not_replace_the_committed_generation() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("oversized-execution-metadata")?;
    let mut lease = cache.lease(&key)?;
    let snapshot = Job::new("bounded metadata").snapshot()?;
    lease.save_active(&snapshot, limits(), |_| Ok(json!({"generation": 1})))?;
    let result = lease.save_active(&snapshot, limits(), |_| {
        Ok(json!({"huge": "x".repeat(10_000)}))
    });
    assert!(matches!(result, Err(CacheError::MetadataTooLarge { .. })));
    assert_eq!(
        lease
            .load_active(limits())?
            .ok_or("generation was lost")?
            .metadata(),
        &json!({"generation": 1})
    );
    Ok(())
}

#[test]
fn active_execution_keeps_its_stage_pinned_even_if_the_legacy_checkpoint_is_completed()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("execution-pins-stage")?;
    super::write_entry(&cache, &key, b"prior stage")?;
    let snapshot = Job::new("pinned").snapshot()?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&snapshot, limits(), |_| Ok(json!({})))?;
    drop(lease);
    cache.write_checkpoint(
        &key,
        &snapshot,
        l2_workbench::job::cache::CheckpointStatus::Complete,
    )?;
    cache.clear()?;
    assert!(
        cache
            .lookup(
                &key,
                l2_workbench::job::cache::CacheReadPolicy::CompleteOnly
            )?
            .is_some()
    );
    assert!(cache.lease(&key)?.load_active(limits())?.is_some());
    Ok(())
}

#[test]
fn four_simultaneous_writers_cannot_reserve_more_than_the_global_quota()
-> Result<(), Box<dyn Error>> {
    use std::sync::{Arc, Condvar, Mutex, mpsc};
    use std::time::Duration;

    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 20_000)?;
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let (events_tx, events_rx) = mpsc::channel();
    let mut threads = Vec::new();
    for number in 0_u8..4 {
        let cache = cache.clone();
        let key = stage_key(&format!("four-writers-{number}"))?;
        let gate = Arc::clone(&gate);
        let events = events_tx.clone();
        threads.push(std::thread::spawn(move || -> Result<(), CacheError> {
            let mut lease = cache.lease(&key)?;
            let snapshot = Job::new("concurrent")
                .snapshot()
                .map_err(|_| CacheError::InvalidInput("snapshot failed"))?;
            let caps = ExecutionCheckpointLimits {
                max_encoded_bytes: 8_000,
                ..limits()
            };
            lease.save_active(&snapshot, caps, |writer| {
                let written = writer.streams().0.write_all(&vec![number; 6_000]);
                events
                    .send(written.is_ok())
                    .map_err(|_| CacheError::InvalidInput("coordination failed"))?;
                written?;
                let (lock, wake) = &*gate;
                let mut released = lock
                    .lock()
                    .map_err(|_| CacheError::InvalidInput("coordination failed"))?;
                while !*released {
                    released = wake
                        .wait(released)
                        .map_err(|_| CacheError::InvalidInput("coordination failed"))?;
                }
                drop(released);
                Ok(json!({}))
            })
        }));
    }
    drop(events_tx);
    let mut accepted = 0;
    let mut event_error = None;
    for _ in 0..4 {
        match events_rx.recv_timeout(Duration::from_secs(20)) {
            Ok(true) => accepted += 1,
            Ok(false) => {}
            Err(error) => {
                event_error = Some(error);
                break;
            }
        }
    }
    let reserved = cache.stats()?.entry_bytes;
    let (lock, wake) = &*gate;
    *lock.lock().map_err(|_| "coordination lock poisoned")? = true;
    wake.notify_all();
    for thread in threads {
        match thread.join().map_err(|_| "writer thread panicked")? {
            Ok(()) | Err(CacheError::QuotaExceeded { .. }) => {}
            Err(error) => return Err(error.into()),
        }
    }
    if let Some(error) = event_error {
        return Err(error.into());
    }
    assert_eq!(accepted, 3);
    assert_eq!(reserved, 18_000);
    assert!(cache.stats()?.entry_bytes <= 20_000);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn saving_a_large_component_does_not_read_back_its_contents() -> Result<(), Box<dyn Error>> {
    fn thread_bytes_read() -> Result<u64, Box<dyn Error>> {
        let io = std::fs::read_to_string("/proc/thread-self/io")?;
        let value = io
            .lines()
            .find_map(|line| line.strip_prefix("rchar: "))
            .ok_or("rchar is missing")?;
        Ok(value.trim().parse()?)
    }

    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 32 * 1024 * 1024)?;
    let key = stage_key("streaming-save-io")?;
    let mut lease = cache.lease(&key)?;
    let snapshot = Job::new("large streaming save").snapshot()?;
    let data = vec![0x5a; 8 * 1024 * 1024];
    let caps = ExecutionCheckpointLimits {
        max_encoded_bytes: 16 * 1024 * 1024,
        ..limits()
    };
    let before = thread_bytes_read()?;
    lease.save_active(&snapshot, caps, |writer| {
        writer.streams().0.write_all(&data)?;
        Ok(json!({}))
    })?;
    let read_bytes = thread_bytes_read()?
        .checked_sub(before)
        .ok_or("thread I/O counter moved backwards")?;
    assert!(
        read_bytes < u64::try_from(data.len() / 2)?,
        "saving read {read_bytes} bytes for an {}-byte component",
        data.len()
    );
    Ok(())
}

#[test]
fn failed_no_replace_rename_keeps_debris_reserved_until_exclusive_recovery()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("rename-collision")?;
    let snapshot = Job::new("rename collision").snapshot()?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&snapshot, limits(), |writer| {
        writer.streams().2.write_all(b"committed")?;
        Ok(json!({"generation": 1}))
    })?;
    let baseline = cache.stats()?.entry_bytes;
    let staging_key = lease
        .directory()
        .parent()
        .ok_or("staging parent is missing")?
        .to_path_buf();
    let entry_root = temporary.path().join("cache/entries").join(key.as_str());
    let failed = lease.save_active(&snapshot, limits(), |writer| {
        writer.streams().2.write_all(b"uncommitted")?;
        let active = active_staging_directory(&staging_key)?;
        let name = active
            .file_name()
            .ok_or(CacheError::InvalidInput("active name is missing"))?;
        std::fs::create_dir(entry_root.join(name))?;
        Ok(json!({"generation": 2}))
    });
    assert!(failed.is_err());
    let with_debris = cache.stats()?.entry_bytes;
    assert!(with_debris > baseline);
    cache.prune()?;
    assert_eq!(cache.stats()?.entry_bytes, with_debris);
    assert_eq!(
        lease
            .load_active(limits())?
            .ok_or("prior generation is missing")?
            .metadata(),
        &json!({"generation": 1})
    );
    drop(lease);
    let lease = cache.lease(&key)?;
    assert_eq!(cache.stats()?.entry_bytes, baseline);
    assert_eq!(
        lease
            .load_active(limits())?
            .ok_or("prior generation is missing after recovery")?
            .metadata(),
        &json!({"generation": 1})
    );
    Ok(())
}

#[test]
fn replacing_a_written_component_is_rejected_even_when_bytes_match() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("component-replacement")?;
    let snapshot = Job::new("replacement").snapshot()?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&snapshot, limits(), |_| Ok(json!({"generation": 1})))?;
    let staging_key = lease
        .directory()
        .parent()
        .ok_or("staging parent is missing")?
        .to_path_buf();
    let result = lease.save_active(&snapshot, limits(), |writer| {
        writer.streams().0.write_all(b"same")?;
        let active = active_staging_directory(&staging_key)?;
        let graph = active.join("graph");
        std::fs::remove_file(&graph)?;
        std::fs::write(graph, b"same")?;
        Ok(json!({"generation": 2}))
    });
    assert!(result.is_err());
    assert_eq!(
        lease
            .load_active(limits())?
            .ok_or("prior generation is missing")?
            .metadata(),
        &json!({"generation": 1})
    );
    Ok(())
}

#[test]
fn terminal_commit_accounts_for_retired_bytes_until_cleanup_finishes() -> Result<(), Box<dyn Error>>
{
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("terminal-retirement-usage")?;
    let snapshot = Job::new("terminal cleanup").snapshot()?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&snapshot, limits(), |writer| {
        writer.streams().2.write_all(b"pending state")?;
        Ok(json!({}))
    })?;
    let active_bytes = cache.stats()?.entry_bytes;
    let database = rusqlite::Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    database.execute_batch("CREATE TRIGGER reject_cleanup BEFORE DELETE ON retired_generations BEGIN SELECT RAISE(ABORT, 'injected failure'); END;")?;
    std::fs::write(lease.directory().join("result"), b"final")?;
    drop(lease.commit(StageStatus::Complete, json!({}))?);
    assert!(cache.stats()?.entry_bytes >= active_bytes + 5);
    let reopened = cache_at(temporary.path(), 64 * 1024)?;
    let result = reopened.lookup(
        &key,
        l2_workbench::job::cache::CacheReadPolicy::CompleteOnly,
    )?;
    assert!(result.is_some());
    drop(result);
    drop(reopened);
    database.execute_batch("DROP TRIGGER reject_cleanup;")?;
    cache.prune()?;
    assert_eq!(cache.stats()?.entry_bytes, 5);
    let lease = cache.lease(&key)?;
    assert!(lease.load_active(limits())?.is_none());
    Ok(())
}

#[test]
fn terminal_commit_removes_the_retired_generation_after_publication() -> Result<(), Box<dyn Error>>
{
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("terminal-retired-files")?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(
        &Job::new("terminal cleanup").snapshot()?,
        limits(),
        |writer| {
            writer.streams().2.write_all(b"pending")?;
            Ok(json!({}))
        },
    )?;
    let database = rusqlite::Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    let relative: String = database.query_row(
        "SELECT relative_path FROM executions WHERE key = ?1",
        [key.as_str()],
        |row| row.get(0),
    )?;
    let retired = temporary.path().join("cache/entries").join(relative);
    std::fs::write(lease.directory().join("result"), b"final")?;
    drop(lease.commit(StageStatus::Complete, json!({}))?);
    assert!(!retired.exists());
    assert_eq!(cache.stats()?.entry_bytes, 5);
    Ok(())
}

#[test]
fn superseded_active_bytes_remain_counted_when_retirement_cleanup_fails()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("active-retirement-usage")?;
    let snapshot = Job::new("active retirement").snapshot()?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&snapshot, limits(), |writer| {
        writer.streams().2.write_all(b"first")?;
        Ok(json!({"generation": 1}))
    })?;
    let prior_bytes = cache.stats()?.entry_bytes;
    let database = rusqlite::Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    database.execute_batch("CREATE TRIGGER reject_cleanup BEFORE DELETE ON retired_generations BEGIN SELECT RAISE(ABORT, 'injected failure'); END;")?;
    lease.save_active(&snapshot, limits(), |writer| {
        writer.streams().2.write_all(b"later")?;
        Ok(json!({"generation": 2}))
    })?;
    assert_eq!(cache.stats()?.entry_bytes, prior_bytes * 2);
    assert_eq!(
        lease
            .load_active(limits())?
            .ok_or("latest generation is missing")?
            .metadata(),
        &json!({"generation": 2})
    );
    drop(lease);
    database.execute_batch("DROP TRIGGER reject_cleanup;")?;
    cache.prune()?;
    assert_eq!(cache.stats()?.entry_bytes, prior_bytes);
    Ok(())
}

#[test]
fn superseded_stage_bytes_remain_counted_when_retirement_cleanup_fails()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("stage-retirement-usage")?;
    super::write_entry(&cache, &key, b"first")?;
    let database = rusqlite::Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    database.execute_batch("CREATE TRIGGER reject_cleanup BEFORE DELETE ON retired_generations BEGIN SELECT RAISE(ABORT, 'injected failure'); END;")?;
    super::write_entry(&cache, &key, b"latest")?;
    assert_eq!(cache.stats()?.entry_bytes, 11);
    database.execute_batch("DROP TRIGGER reject_cleanup;")?;
    cache.prune()?;
    assert_eq!(cache.stats()?.entry_bytes, 6);
    Ok(())
}

#[test]
fn version_two_cache_migrates_without_losing_active_generation() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("version-two-active-migration")?;
    let snapshot = Job::new("migrated active").snapshot()?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&snapshot, limits(), |writer| {
        writer.streams().2.write_all(b"cursor")?;
        Ok(json!({"version": 2}))
    })?;
    drop(lease);
    drop(cache);
    let database = rusqlite::Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    database.execute_batch("DROP TABLE retired_generations; PRAGMA user_version = 2;")?;
    drop(database);
    let migrated = cache_at(temporary.path(), 64 * 1024)?;
    let lease = migrated.lease(&key)?;
    let mut active = lease
        .load_active(limits())?
        .ok_or("active generation was lost")?;
    assert_eq!(active.snapshot(), &snapshot);
    assert_eq!(active.metadata(), &json!({"version": 2}));
    let mut bytes = Vec::new();
    active.streams().2.read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"cursor");
    Ok(())
}

#[test]
fn stage_replacement_must_fit_while_the_previous_stage_is_still_present()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 8)?;
    let key = stage_key("stage-replacement-peak-quota")?;
    super::write_entry(&cache, &key, b"first")?;
    let lease = cache.lease(&key)?;
    std::fs::write(lease.directory().join("result"), b"latest")?;
    assert!(matches!(
        lease.commit(StageStatus::Complete, json!({})),
        Err(CacheError::QuotaExceeded { .. })
    ));
    let prior = cache
        .lookup(
            &key,
            l2_workbench::job::cache::CacheReadPolicy::CompleteOnly,
        )?
        .ok_or("prior stage was lost")?;
    assert_eq!(
        std::fs::read(prior.directory().join("result.bin"))?,
        b"first"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn terminal_commit_rejects_hardlinked_stage_files_and_preserves_prior_results()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("terminal-hardlink")?;
    super::write_entry(&cache, &key, b"previous")?;
    let snapshot = Job::new("hardlinked output").snapshot()?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&snapshot, limits(), |writer| {
        writer.streams().2.write_all(b"cursor")?;
        Ok(json!({}))
    })?;
    let outside = temporary.path().join("outside");
    std::fs::write(&outside, b"new")?;
    std::fs::hard_link(&outside, lease.directory().join("result"))?;
    assert!(lease.commit(StageStatus::Complete, json!({})).is_err());
    assert_eq!(std::fs::read(outside)?, b"new");
    let prior = cache
        .lookup(
            &key,
            l2_workbench::job::cache::CacheReadPolicy::CompleteOnly,
        )?
        .ok_or("prior stage was lost")?;
    assert_eq!(
        std::fs::read(prior.directory().join("result.bin"))?,
        b"previous"
    );
    drop(prior);
    assert!(cache.lease(&key)?.load_active(limits())?.is_some());
    Ok(())
}

#[test]
fn terminal_commit_syncs_nested_stage_directories_without_changing_their_contents()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("nested-terminal")?;
    let lease = cache.lease(&key)?;
    let nested = lease.directory().join("nested/child");
    std::fs::create_dir_all(&nested)?;
    std::fs::write(nested.join("result"), b"nested result")?;
    let entry = lease.commit(StageStatus::Complete, json!({}))?;
    assert_eq!(
        std::fs::read(entry.directory().join("nested/child/result"))?,
        b"nested result"
    );
    Ok(())
}

#[test]
fn failed_terminal_publication_keeps_renamed_output_counted_until_recovery()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("terminal-ambiguous-publication")?;
    super::write_entry(&cache, &key, b"previous")?;
    let snapshot = Job::new("ambiguous publication").snapshot()?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&snapshot, limits(), |writer| {
        writer.streams().2.write_all(b"cursor")?;
        Ok(json!({}))
    })?;
    let baseline = cache.stats()?.entry_bytes;
    let generation = lease
        .directory()
        .file_name()
        .ok_or("stage generation is missing")?
        .to_owned();
    let destination = temporary
        .path()
        .join("cache/entries")
        .join(key.as_str())
        .join(generation);
    std::fs::write(lease.directory().join("result"), b"new")?;
    let database = rusqlite::Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    database.execute_batch("CREATE TRIGGER reject_result BEFORE INSERT ON entries BEGIN SELECT RAISE(ABORT, 'injected failure'); END;")?;
    assert!(lease.commit(StageStatus::Complete, json!({})).is_err());
    assert!(destination.exists());
    assert_eq!(cache.stats()?.entry_bytes, baseline + 3);
    database.execute_batch("DROP TRIGGER reject_result;")?;
    let lease = cache.lease(&key)?;
    assert!(!destination.exists());
    assert_eq!(cache.stats()?.entry_bytes, baseline);
    assert!(lease.load_active(limits())?.is_some());
    drop(lease);
    let prior = cache
        .lookup(
            &key,
            l2_workbench::job::cache::CacheReadPolicy::CompleteOnly,
        )?
        .ok_or("prior stage was lost")?;
    assert_eq!(
        std::fs::read(prior.directory().join("result.bin"))?,
        b"previous"
    );
    Ok(())
}
