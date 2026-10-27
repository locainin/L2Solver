//! Verify terminal publication when the filesystem rejects a required sync

use super::{cache_at, execution::limits, stage_key, write_entry};
use l2_workbench::job::{
    Job,
    cache::{CacheReadPolicy, StageStatus},
};
use serde_json::json;
use std::{error::Error, fs, path::Path, process::Command};

#[test]
fn terminal_fsync_failure_child() -> Result<(), Box<dyn Error>> {
    let Some(base) = std::env::var_os("L2_TEST_TERMINAL_FSYNC_ROOT") else {
        return Ok(());
    };
    let cache = cache_at(Path::new(&base), 64 * 1024)?;
    let key = stage_key("terminal-fsync")?;
    let lease = cache.lease(&key)?;
    let result = lease.commit(StageStatus::Complete, json!({"generation":2}));
    if result.is_ok() {
        return Err("terminal publication succeeded after the staged file sync failed".into());
    }
    Ok(())
}

#[test]
fn terminal_fsync_failure_keeps_previous_entry_and_active_generation() -> Result<(), Box<dyn Error>>
{
    let temporary = tempfile::tempdir()?;
    let probe = Command::new("strace")
        .args(["-qq", "-o"])
        .arg(temporary.path().join("probe.trace"))
        .arg("true")
        .output();
    match probe {
        Ok(output) if output.status.success() => {}
        _ => {
            eprintln!("terminal fsync fault test needs usable strace");
            return Ok(());
        }
    }

    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("terminal-fsync")?;
    let old = write_entry(&cache, &key, b"old-result")?;
    let snapshot = Job::new("prior active generation").snapshot()?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&snapshot, limits(), |writer| {
        writer.streams().2.write_all(b"old-cursor")?;
        Ok(json!({"generation":1}))
    })?;
    let stage_file = lease.directory().join("result.bin");
    fs::write(&stage_file, b"new-result")?;
    lease.preserve(&snapshot)?;
    let trace_path = temporary.path().join("fault.trace");
    let child = Command::new("strace")
        .args(["-f", "-qq", "-P"])
        .arg(&stage_file)
        .args([
            "-e",
            "trace=fsync",
            "-e",
            "inject=fsync:error=EIO:when=1",
            "-o",
        ])
        .arg(&trace_path)
        .arg(std::env::current_exe()?)
        .args([
            "--exact",
            "cache::terminal_fsync::terminal_fsync_failure_child",
            "--nocapture",
        ])
        .env("L2_TEST_TERMINAL_FSYNC_ROOT", temporary.path())
        .output()?;
    assert!(
        child.status.success(),
        "terminal child failed: stdout={} stderr={}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    let trace = fs::read_to_string(trace_path)?;
    assert!(
        trace.contains("EIO") && trace.contains("INJECTED"),
        "sync injection did not fire: {trace}"
    );
    for line in trace.lines().filter(|line| line.contains("INJECTED")) {
        eprintln!("targeted staged-file fsync: {line}");
    }

    let entry = cache
        .lookup(&key, CacheReadPolicy::CompleteOnly)?
        .ok_or("previous entry disappeared")?;
    assert_eq!(entry.directory(), old);
    assert_eq!(
        fs::read(entry.directory().join("result.bin"))?,
        b"old-result"
    );
    drop(entry);
    let lease = cache.lease(&key)?;
    let mut active = lease
        .load_active(limits())?
        .ok_or("prior active generation disappeared")?;
    assert_eq!(active.snapshot(), &snapshot);
    assert_eq!(active.metadata(), &json!({"generation":1}));
    let mut cursor = Vec::new();
    active.streams().2.read_to_end(&mut cursor)?;
    assert_eq!(cursor, b"old-cursor");
    Ok(())
}
