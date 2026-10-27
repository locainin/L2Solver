//! Check accounting when a retired generation cannot be removed

use super::{cache_at, execution::limits, stage_key, terminal_fsync::strace_available};
use l2_workbench::job::{
    Job,
    cache::{CacheReadPolicy, StageStatus},
};
use serde_json::json;
use std::{error::Error, fs, path::Path, process::Command};

const NEW_RESULT: &[u8] = b"new-result";

#[test]
fn terminal_retirement_failure_child() -> Result<(), Box<dyn Error>> {
    let Some(base) = std::env::var_os("L2_TEST_TERMINAL_RETIRE_ROOT") else {
        return Ok(());
    };
    let cache = cache_at(Path::new(&base), 64 * 1024)?;
    let key = stage_key("terminal-retirement")?;
    let lease = cache.lease(&key)?;
    let entry = lease.commit(StageStatus::Complete, json!({"generation":2}))?;
    assert_eq!(fs::read(entry.directory().join("result.bin"))?, NEW_RESULT);
    Ok(())
}

#[test]
fn retirement_unlink_failure_retains_accounting_until_cleanup_succeeds()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    if !strace_available(temporary.path()) {
        eprintln!("retirement unlink fault test needs usable strace");
        return Ok(());
    }
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("terminal-retirement")?;
    let snapshot = Job::new("prior active generation").snapshot()?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&snapshot, limits(), |writer| {
        writer.streams().2.write_all(b"old-cursor")?;
        Ok(json!({"generation":1}))
    })?;
    fs::write(lease.directory().join("result.bin"), NEW_RESULT)?;
    lease.preserve(&snapshot)?;

    let database = rusqlite::Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    let (relative, old_bytes): (String, u64) = database.query_row(
        "SELECT relative_path, bytes FROM executions WHERE key = ?1",
        [key.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let retired = temporary.path().join("cache/entries").join(&relative);
    let trace_path = temporary.path().join("retirement.trace");
    let child = Command::new("strace")
        .args(["-f", "-qq", "-yy", "-P"])
        .arg(&retired)
        .args([
            "-e",
            "trace=unlinkat",
            "-e",
            "inject=unlinkat:error=EIO:when=1",
            "-o",
        ])
        .arg(&trace_path)
        .arg(std::env::current_exe()?)
        .args([
            "--exact",
            "cache::terminal_retirement::terminal_retirement_failure_child",
            "--nocapture",
        ])
        .env("L2_TEST_TERMINAL_RETIRE_ROOT", temporary.path())
        .output()?;
    assert!(
        child.status.success(),
        "terminal child failed: stdout={} stderr={}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    let trace = fs::read_to_string(trace_path)?;
    let injected = trace.lines().any(|line| {
        line.contains("EIO")
            && line.contains("INJECTED")
            && line.contains(retired.to_string_lossy().as_ref())
    });
    assert!(injected, "targeted unlink injection did not fire: {trace}");
    for line in trace.lines().filter(|line| line.contains("INJECTED")) {
        eprintln!("targeted retired-file unlink: {line}");
    }

    let retained_bytes: u64 = database.query_row(
        "SELECT bytes FROM retired_generations WHERE key = ?1 AND relative_path = ?2",
        rusqlite::params![key.as_str(), relative],
        |row| row.get(0),
    )?;
    assert_eq!(retained_bytes, old_bytes);
    let new_bytes = u64::try_from(NEW_RESULT.len())?;
    assert_eq!(cache.stats()?.entry_bytes, old_bytes + new_bytes);
    let entry = cache
        .lookup(&key, CacheReadPolicy::CompleteOnly)?
        .ok_or("new result disappeared")?;
    assert_eq!(fs::read(entry.directory().join("result.bin"))?, NEW_RESULT);
    drop(entry);
    drop(database);
    cache.prune()?;
    assert!(!retired.exists());
    assert_eq!(cache.stats()?.entry_bytes, new_bytes);
    Ok(())
}
