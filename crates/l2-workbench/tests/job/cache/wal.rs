use std::{
    error::Error,
    fs,
    io::{Read, Seek},
    path::Path,
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use l2_workbench::job::{
    Job,
    cache::{CacheError, CacheReadPolicy, CheckpointStatus},
};
use rusqlite::{Connection, config::DbConfig};

use super::{cache_at, stage_key, write_entry};

type TestResult = Result<(), Box<dyn Error>>;

const CHILD_ROOT: &str = "L2_TEST_CACHE_WAL_ROOT";
const ROOT_MARKER: &str = "controlled-wal-test-root";
const ROOT_MARKER_CONTENT: &[u8] = b"controlled cache WAL test";
const REOPEN_TEST: &str = "cache::wal::committed_wal_survives_a_separate_process_reopen";
#[cfg(target_os = "linux")]
const CRASH_TEST: &str = "cache::wal::committed_wal_survives_a_killed_process";

fn check_child_root(root: &Path) -> TestResult {
    // A child must never open a directory without the test's marker
    if fs::read(root.join(ROOT_MARKER))? != ROOT_MARKER_CONTENT {
        return Err("controlled WAL test root marker does not match".into());
    }
    Ok(())
}

fn wal_path(root: &Path) -> std::path::PathBuf {
    root.join("state/cache.sqlite3-wal")
}

fn run_child(command: &mut Command) -> Result<(ExitStatus, String), Box<dyn Error>> {
    let mut log = tempfile::tempfile()?;
    let mut child = super::execution::OwnedCrashChild(
        command
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log.try_clone()?))
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait()? {
            log.rewind()?;
            let mut output = String::new();
            log.read_to_string(&mut output)?;
            return Ok((status, output));
        }
        if Instant::now() >= deadline {
            // The existing child guard kills and reaps a timed-out process
            return Err("WAL test child timed out".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn committed_wal_survives_a_separate_process_reopen() -> TestResult {
    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        let root = Path::new(&root);
        check_child_root(root)?;
        let cache = cache_at(root, 1024)?;
        let key = stage_key("wal-reopen")?;
        let entry = cache
            .lookup(&key, CacheReadPolicy::CompleteOnly)?
            .ok_or("committed entry disappeared")?;
        assert_eq!(
            fs::read(entry.directory().join("result.bin"))?,
            b"persisted"
        );
        let saved = cache
            .read_checkpoint(&key)?
            .ok_or("checkpoint disappeared")?;
        assert_eq!(saved.snapshot.label, "WAL persistence");
        assert_eq!(saved.status, CheckpointStatus::Active);
        return Ok(());
    }

    let temporary = tempfile::tempdir()?;
    fs::write(temporary.path().join(ROOT_MARKER), ROOT_MARKER_CONTENT)?;
    let cache = cache_at(temporary.path(), 1024)?;
    let key = stage_key("wal-reopen")?;
    write_entry(&cache, &key, b"persisted")?;
    let snapshot = Job::new("WAL persistence").snapshot()?;
    cache.write_checkpoint(&key, &snapshot, CheckpointStatus::Active)?;
    // Small committed logs remain present when the last connection closes
    assert!(fs::metadata(wal_path(temporary.path()))?.len() > 32);
    drop(cache);

    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["--exact", REOPEN_TEST, "--nocapture"])
        .env(CHILD_ROOT, temporary.path());
    let (status, output) = run_child(&mut command)?;
    assert!(
        status.success(),
        "separate process could not recover the cache: {output}"
    );
    let database = Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    let integrity: String =
        database.pragma_query_value(None, "integrity_check", |row| row.get(0))?;
    assert_eq!(integrity, "ok");
    Ok(())
}

#[test]
fn wal_reopen_child_rejects_an_unowned_root_without_changes() -> TestResult {
    let temporary = tempfile::tempdir()?;
    fs::write(temporary.path().join("unrelated"), b"unchanged")?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["--exact", REOPEN_TEST, "--nocapture"])
        .env(CHILD_ROOT, temporary.path());
    let (status, _) = run_child(&mut command)?;
    assert!(!status.success(), "unowned child root was accepted");
    assert_eq!(fs::read(temporary.path().join("unrelated"))?, b"unchanged");
    assert_eq!(fs::read_dir(temporary.path())?.count(), 1);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn committed_wal_survives_a_killed_process() -> TestResult {
    use std::os::unix::process::ExitStatusExt;

    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        let root = Path::new(&root);
        check_child_root(root)?;
        let cache = cache_at(root, 1024)?;
        let key = stage_key("wal-killed-process")?;
        write_entry(&cache, &key, b"durable")?;
        let snapshot = Job::new("saved before SIGKILL").snapshot()?;
        cache.write_checkpoint(&key, &snapshot, CheckpointStatus::Active)?;
        // Notify the parent only after the committed WAL has been synced
        fs::write(root.join("ready"), b"ready")?;
        loop {
            thread::sleep(Duration::from_secs(1));
        }
    }

    let temporary = tempfile::tempdir()?;
    fs::write(temporary.path().join(ROOT_MARKER), ROOT_MARKER_CONTENT)?;
    let mut child = super::execution::OwnedCrashChild(
        Command::new(std::env::current_exe()?)
            .args(["--exact", CRASH_TEST, "--nocapture"])
            .env(CHILD_ROOT, temporary.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while !temporary.path().join("ready").exists() && Instant::now() < deadline {
        if child.0.try_wait()?.is_some() {
            return Err("WAL writer exited before committing".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        temporary.path().join("ready").exists(),
        "WAL writer timed out"
    );
    assert!(fs::metadata(wal_path(temporary.path()))?.len() > 32);
    child.0.kill()?;
    let status = child.0.wait()?;
    assert!(status.signal().is_some(), "WAL writer was not killed");

    let cache = cache_at(temporary.path(), 1024)?;
    let key = stage_key("wal-killed-process")?;
    let entry = cache
        .lookup(&key, CacheReadPolicy::CompleteOnly)?
        .ok_or("committed entry disappeared after SIGKILL")?;
    assert_eq!(fs::read(entry.directory().join("result.bin"))?, b"durable");
    let checkpoint = cache
        .read_checkpoint(&key)?
        .ok_or("checkpoint disappeared")?;
    assert_eq!(checkpoint.snapshot.label, "saved before SIGKILL");
    Ok(())
}

#[test]
fn repeated_short_lived_writes_recycle_the_wal_and_keep_the_checkpoint() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 1024)?;
    let key = stage_key("wal-many-writes")?;
    let snapshot = Job::new("repeated WAL writes").snapshot()?;
    let mut largest = 0_u64;
    let mut previous = 0_u64;
    let mut recycled = false;

    for _ in 0..1_300 {
        cache.write_checkpoint(&key, &snapshot, CheckpointStatus::Active)?;
        let size = match fs::metadata(wal_path(temporary.path())) {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error.into()),
        };
        largest = largest.max(size);
        recycled |= previous > 32 * 1024 && size < previous;
        previous = size;
    }
    assert!(largest > 32 * 1024, "the WAL never accumulated writes");
    assert!(recycled, "the growing WAL was never recycled");
    assert!(largest < 256 * 1024, "the serial WAL grew excessively");

    drop(cache);
    let reopened = cache_at(temporary.path(), 1024)?;
    let saved = reopened
        .read_checkpoint(&key)?
        .ok_or("checkpoint disappeared")?;
    assert_eq!(saved.snapshot, snapshot);
    let database = Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    let integrity: String =
        database.pragma_query_value(None, "integrity_check", |row| row.get(0))?;
    assert_eq!(integrity, "ok");
    Ok(())
}

#[test]
fn explicit_wal_checkpoint_moves_committed_progress_to_the_database() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 1024)?;
    let key = stage_key("explicit-wal-checkpoint")?;
    let snapshot = Job::new("explicit WAL checkpoint").snapshot()?;
    cache.write_checkpoint(&key, &snapshot, CheckpointStatus::Active)?;
    cache.checkpoint_wal()?;

    // Read only the main database to verify SQLite copied the committed row
    let path = temporary.path().join("state/cache.sqlite3");
    let uri = format!("file:{}?immutable=1", path.display());
    let database = Connection::open_with_flags(
        uri,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )?;
    let saved: String = database.query_row(
        "SELECT snapshot_json FROM checkpoints WHERE key = ?1",
        [key.as_str()],
        |row| row.get(0),
    )?;
    let value = serde_json::from_str::<serde_json::Value>(&saved)?;
    assert_eq!(
        value.get("label").and_then(serde_json::Value::as_str),
        Some("explicit WAL checkpoint")
    );
    Ok(())
}

#[test]
fn foreign_database_is_rejected_without_changing_its_rows() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let state = temporary.path().join("state");
    fs::create_dir(&state)?;
    let path = state.join("cache.sqlite3");
    let database = Connection::open(&path)?;
    database.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
    database.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA application_id=1234; CREATE TABLE foreign_data(value TEXT); INSERT INTO foreign_data VALUES('unchanged');",
    )?;
    drop(database);
    assert!(matches!(
        cache_at(temporary.path(), 1024),
        Err(CacheError::IncompatibleDatabase)
    ));
    let database = Connection::open(path)?;
    assert_eq!(
        database.query_row("SELECT value FROM foreign_data", [], |row| row
            .get::<_, String>(0))?,
        "unchanged"
    );
    let application_id: i64 =
        database.pragma_query_value(None, "application_id", |row| row.get(0))?;
    assert_eq!(application_id, 1234);
    Ok(())
}

#[test]
fn missing_sidecars_are_recreated_without_touching_unrelated_files() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 1024)?;
    let unrelated = temporary.path().join("state/unrelated");
    fs::write(&unrelated, b"unchanged")?;

    // A normal SQLite close removes any existing WAL and shared-memory sidecars
    let database = Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    database.query_row("SELECT count(*) FROM checkpoints", [], |row| {
        row.get::<_, i64>(0)
    })?;
    drop(database);
    assert!(!wal_path(temporary.path()).exists());
    assert!(!temporary.path().join("state/cache.sqlite3-shm").exists());

    let key = stage_key("missing-sidecars")?;
    let snapshot = Job::new("recreated sidecars").snapshot()?;
    cache.write_checkpoint(&key, &snapshot, CheckpointStatus::Active)?;
    assert_eq!(
        cache
            .read_checkpoint(&key)?
            .ok_or("checkpoint disappeared")?
            .snapshot,
        snapshot
    );
    assert_eq!(fs::read(unrelated)?, b"unchanged");
    Ok(())
}

#[test]
fn large_wal_waits_for_a_reader_and_is_cleaned_after_the_reader_closes() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 1024)?;
    let database_path = temporary.path().join("state/cache.sqlite3");
    let unrelated = temporary.path().join("state/unrelated");
    fs::write(&unrelated, b"unchanged")?;
    let reader = Connection::open(&database_path)?;
    reader.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
    reader.execute_batch("BEGIN")?;
    let before: i64 = reader.query_row("SELECT count(*) FROM entries", [], |row| row.get(0))?;

    // Keep a real reader snapshot while another connection fills the WAL
    let writer = Connection::open(&database_path)?;
    writer.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
    writer.execute_batch(
        "CREATE TABLE wal_test_data(data BLOB NOT NULL); INSERT INTO wal_test_data VALUES(zeroblob(4500000));",
    )?;
    drop(writer);
    assert!(fs::metadata(wal_path(temporary.path()))?.len() > 4 * 1024 * 1024);
    let started = Instant::now();
    assert_eq!(cache.stats()?.entries, 0);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "reader blocked cache stats"
    );
    assert_eq!(
        reader.query_row("SELECT count(*) FROM entries", [], |row| row
            .get::<_, i64>(0))?,
        before
    );
    assert!(
        wal_path(temporary.path()).exists(),
        "live reader lost its WAL"
    );
    reader.execute_batch("ROLLBACK")?;
    drop(reader);

    // A later cache connection can use SQLite's ordinary last-close cleanup
    assert_eq!(cache.stats()?.entries, 0);
    assert!(
        !wal_path(temporary.path()).exists(),
        "large WAL was not cleaned"
    );
    assert_eq!(fs::read(unrelated)?, b"unchanged");
    let database = Connection::open(database_path)?;
    assert_eq!(
        database.query_row("SELECT length(data) FROM wal_test_data", [], |row| row
            .get::<_, i64>(0))?,
        4_500_000
    );
    let integrity: String =
        database.pragma_query_value(None, "integrity_check", |row| row.get(0))?;
    assert_eq!(integrity, "ok");
    Ok(())
}

#[test]
fn large_committed_write_does_not_wait_for_an_active_wal_reader() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 1024)?;
    let key = stage_key("wal-active-reader")?;
    let reader = Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    reader.execute_batch("BEGIN")?;
    let before: i64 = reader.query_row("SELECT count(*) FROM checkpoints", [], |row| row.get(0))?;

    // The large commit must not wait for a reader's older snapshot
    let snapshot = Job::new("x".repeat(128 * 1024)).snapshot()?;
    let started = Instant::now();
    cache.write_checkpoint(&key, &snapshot, CheckpointStatus::Active)?;
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "checkpoint cleanup waited for a reader"
    );
    assert!(fs::metadata(wal_path(temporary.path()))?.len() > 64 * 1024);
    assert_eq!(
        reader.query_row("SELECT count(*) FROM checkpoints", [], |row| row
            .get::<_, i64>(0))?,
        before
    );
    reader.execute_batch("ROLLBACK")?;
    drop(reader);

    let saved = cache
        .read_checkpoint(&key)?
        .ok_or("committed checkpoint disappeared")?;
    assert_eq!(saved.snapshot, snapshot);
    Ok(())
}

#[cfg(unix)]
#[test]
fn sqlite_sidecar_links_are_rejected_without_touching_the_target() -> TestResult {
    use std::os::unix::fs::symlink;

    for suffix in ["-wal", "-shm"] {
        let temporary = tempfile::tempdir()?;
        let cache = cache_at(temporary.path(), 1024)?;
        let outside = temporary.path().join("outside");
        fs::write(&outside, b"unchanged")?;
        let sidecar = temporary
            .path()
            .join("state")
            .join(format!("cache.sqlite3{suffix}"));
        if sidecar.exists() {
            fs::rename(&sidecar, sidecar.with_extension("saved"))?;
        }
        symlink(&outside, &sidecar)?;
        assert!(matches!(cache.stats(), Err(CacheError::UnsafePath(_))));
        assert_eq!(fs::read(outside)?, b"unchanged");
    }
    Ok(())
}

#[test]
fn sqlite_sidecar_directories_are_rejected_without_removing_them() -> TestResult {
    for suffix in ["-wal", "-shm"] {
        let temporary = tempfile::tempdir()?;
        let cache = cache_at(temporary.path(), 1024)?;
        let sidecar = temporary
            .path()
            .join("state")
            .join(format!("cache.sqlite3{suffix}"));
        if sidecar.exists() {
            fs::rename(&sidecar, sidecar.with_extension("saved"))?;
        }
        fs::create_dir(&sidecar)?;
        fs::write(sidecar.join("keep"), b"unchanged")?;
        assert!(matches!(cache.stats(), Err(CacheError::UnsafePath(_))));
        assert_eq!(fs::read(sidecar.join("keep"))?, b"unchanged");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn failed_lru_wal_sync_is_reported() -> TestResult {
    failed_sync_keeps_live_generation("lookup", "cache::wal::failed_lru_wal_sync_is_reported")
}

#[cfg(target_os = "linux")]
#[test]
fn failed_prune_wal_sync_keeps_the_live_generation() -> TestResult {
    failed_sync_keeps_live_generation(
        "prune",
        "cache::wal::failed_prune_wal_sync_keeps_the_live_generation",
    )
}

#[cfg(target_os = "linux")]
#[test]
fn failed_capacity_wal_sync_keeps_the_live_generation() -> TestResult {
    failed_sync_keeps_live_generation(
        "capacity",
        "cache::wal::failed_capacity_wal_sync_keeps_the_live_generation",
    )
}

#[cfg(target_os = "linux")]
#[test]
fn failed_drop_checkpoint_keeps_the_committed_wal_recoverable() -> TestResult {
    const TEST: &str = "cache::wal::failed_drop_checkpoint_keeps_the_committed_wal_recoverable";
    const LABEL_BYTES: usize = 128 * 1024;

    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        let root = Path::new(&root);
        check_child_root(root)?;
        let cache = cache_at(root, 1024)?;
        let snapshot = Job::new("x".repeat(LABEL_BYTES)).snapshot()?;
        cache.write_checkpoint(
            &stage_key("drop-checkpoint-fsync")?,
            &snapshot,
            CheckpointStatus::Active,
        )?;
        return Ok(());
    }

    let temporary = tempfile::tempdir()?;
    if !super::terminal_fsync::strace_available(temporary.path()) {
        return Err("the checkpoint sync test needs usable strace".into());
    }
    fs::write(temporary.path().join(ROOT_MARKER), ROOT_MARKER_CONTENT)?;
    drop(cache_at(temporary.path(), 1024)?);
    let database_path = temporary.path().join("state/cache.sqlite3");
    let database = Connection::open(&database_path)?;
    database.query_row("SELECT count(*) FROM checkpoints", [], |row| {
        row.get::<_, i64>(0)
    })?;
    drop(database);

    // Fail every main-database sync while leaving the committed WAL sync intact
    let trace_path = temporary.path().join("checkpoint-fsync.trace");
    let mut command = Command::new("strace");
    command
        .args(["-f", "-qq", "-yy", "--kill-on-exit", "-P"])
        .arg(&database_path)
        .args([
            "-e",
            "trace=fsync,fdatasync",
            "-e",
            "inject=fsync:error=EIO:when=1+1",
            "-e",
            "inject=fdatasync:error=EIO:when=1+1",
            "-o",
        ])
        .arg(&trace_path)
        .arg(std::env::current_exe()?)
        .args(["--exact", TEST, "--nocapture"])
        .env(CHILD_ROOT, temporary.path());
    let (status, output) = run_child(&mut command)?;
    let trace = fs::read_to_string(trace_path)?;
    assert!(
        status.success(),
        "checkpoint child failed: {output}\n{trace}"
    );
    let database_descriptor = format!("<{}>", database_path.display());
    assert!(
        trace.lines().any(|line| line.contains("EIO")
            && line.contains("INJECTED")
            && line.contains(&database_descriptor)),
        "main database sync was not faulted: {trace}"
    );

    let cache = cache_at(temporary.path(), 1024)?;
    let saved = cache
        .read_checkpoint(&stage_key("drop-checkpoint-fsync")?)?
        .ok_or("committed WAL was lost after the checkpoint failed")?;
    assert_eq!(saved.snapshot.label, "x".repeat(LABEL_BYTES));
    let database = Connection::open(database_path)?;
    let integrity: String =
        database.pragma_query_value(None, "integrity_check", |row| row.get(0))?;
    assert_eq!(integrity, "ok");
    Ok(())
}

#[cfg(target_os = "linux")]
fn failed_sync_keeps_live_generation(action: &str, test: &str) -> TestResult {
    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        return failed_sync_child(Path::new(&root), action);
    }

    let temporary = tempfile::tempdir()?;
    if !super::terminal_fsync::strace_available(temporary.path()) {
        return Err("the WAL sync test needs usable strace".into());
    }
    fs::write(temporary.path().join(ROOT_MARKER), ROOT_MARKER_CONTENT)?;
    let cache = cache_at(temporary.path(), 3)?;
    let key = stage_key("wal-sync-original")?;
    let original = write_entry(&cache, &key, b"old")?;
    let database = Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    database.pragma_update(None, "synchronous", "FULL")?;
    database.execute(
        "UPDATE entries SET accessed_ns = 1 WHERE key = ?1",
        [key.as_str()],
    )?;
    // Keep the WAL open so a NORMAL write cannot sync merely by creating its header
    let trace = temporary.path().join("wal-sync.trace");
    let wal = wal_path(temporary.path());
    let mut command = Command::new("strace");
    command
        .args(["-f", "-qq", "-yy", "--kill-on-exit", "-P"])
        .arg(&wal)
        .args([
            "-e",
            "trace=fsync,fdatasync",
            "-e",
            "inject=fsync:error=EIO:when=1",
            "-e",
            "inject=fdatasync:error=EIO:when=1",
            "-o",
        ])
        .arg(&trace)
        .arg(std::env::current_exe()?)
        .args(["--exact", test, "--nocapture"])
        .env(CHILD_ROOT, temporary.path());
    let (status, output) = run_child(&mut command)?;
    let trace = fs::read_to_string(trace)?;
    assert!(status.success(), "{action} child failed: {output}\n{trace}");
    assert!(
        trace.lines().any(|line| line.contains("EIO")
            && line.contains("INJECTED")
            && line.contains(wal.to_string_lossy().as_ref())),
        "{action} did not reach the WAL sync: {trace}"
    );
    assert_eq!(
        fs::read(original.join("result.bin"))?,
        b"old",
        "{action} removed live files before the WAL sync"
    );
    let count: i64 = database.query_row(
        "SELECT count(*) FROM entries WHERE key = ?1",
        [key.as_str()],
        |row| row.get(0),
    )?;
    assert_eq!(count, 1, "{action} lost the live entry after a failed sync");
    Ok(())
}

#[cfg(target_os = "linux")]
fn failed_sync_child(root: &Path, action: &str) -> TestResult {
    use serde_json::json;

    check_child_root(root)?;
    let key = stage_key("wal-sync-original")?;
    let result = match action {
        "lookup" => {
            let cache = cache_at(root, 3)?;
            cache
                .lookup(&key, CacheReadPolicy::CompleteOnly)
                .map(|_| ())
        }
        "prune" => cache_at(root, 0).map(|_| ()),
        "capacity" => {
            let cache = cache_at(root, 3)?;
            let lease = cache.lease(&stage_key("wal-sync-new")?)?;
            fs::write(lease.directory().join("result.bin"), b"new")?;
            lease
                .commit(l2_workbench::job::cache::StageStatus::Complete, json!({}))
                .map(|_| ())
        }
        _ => return Err("unknown child action".into()),
    };
    assert!(
        matches!(
            &result,
            Err(CacheError::Database(error)) if matches!(
                error.downcast_ref::<rusqlite::Error>(),
                Some(rusqlite::Error::SqliteFailure(code, _))
                    if code.code == rusqlite::ErrorCode::SystemIoFailure
                        && code.extended_code == rusqlite::ffi::SQLITE_IOERR_FSYNC
            )
        ),
        "WAL sync failure was not reported: {result:?}"
    );
    Ok(())
}
