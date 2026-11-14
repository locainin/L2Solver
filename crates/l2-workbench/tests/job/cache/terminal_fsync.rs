//! Verify terminal publication when the filesystem rejects a required sync

use super::{cache_at, execution::limits, stage_key, write_entry};
use l2_workbench::job::{
    Job, JobSnapshot,
    cache::{Cache, CacheReadPolicy, StageStatus},
};
use serde_json::json;
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

pub(super) fn strace_available(directory: &Path) -> bool {
    let probe = Command::new("strace")
        .args(["-qq", "-o"])
        .arg(directory.join("probe.trace"))
        .arg("true")
        .output();
    matches!(probe, Ok(output) if output.status.success())
}

#[test]
fn terminal_fsync_failure_child() -> Result<(), Box<dyn Error>> {
    let Some(base) = std::env::var_os("L2_TEST_TERMINAL_FSYNC_ROOT") else {
        return Ok(());
    };
    let cache = cache_at(Path::new(&base), 64 * 1024)?;
    let key = stage_key("terminal-fsync")?;
    let lease = cache.lease(&key)?;
    fs::write(lease.directory().join("result.bin"), b"new-result")?;
    let result = lease.commit(StageStatus::Complete, json!({"generation":2}));
    if std::env::var_os("L2_TEST_TERMINAL_FSYNC_PROBE").is_some() {
        result?;
        return Ok(());
    }
    if result.is_ok() {
        return Err("terminal publication succeeded after the staged file sync failed".into());
    }
    Ok(())
}

#[test]
fn terminal_fsync_failure_keeps_previous_entry_and_active_generation() -> Result<(), Box<dyn Error>>
{
    let temporary = tempfile::tempdir()?;
    if !strace_available(temporary.path()) {
        eprintln!("terminal fsync fault test needs usable strace");
        return Ok(());
    }

    let probe = tempfile::tempdir()?;
    let (_probe_cache, _, _) = prepare(probe.path())?;
    let probe_trace = probe.path().join("probe-fsync.trace");
    run_child(probe.path(), &probe_trace, None)?;
    let baseline = fs::read_to_string(probe_trace)?;
    // The stage name is private and random, so locate its sync in an identical clean run
    let call = baseline
        .lines()
        .filter(|line| line.contains("fsync("))
        .position(|line| line.contains("/result.bin>"))
        .ok_or("staged file was not synced in the baseline run")?
        + 1;

    let (cache, old, snapshot) = prepare(temporary.path())?;
    let key = stage_key("terminal-fsync")?;
    let trace_path = temporary.path().join("fault.trace");
    run_child(temporary.path(), &trace_path, Some(call))?;
    let trace = fs::read_to_string(trace_path)?;
    assert!(
        trace.lines().any(|line| line.contains("/result.bin>")
            && line.contains("EIO")
            && line.contains("INJECTED")),
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

fn prepare(root: &Path) -> Result<(Cache, PathBuf, JobSnapshot), Box<dyn Error>> {
    let cache = cache_at(root, 64 * 1024)?;
    let key = stage_key("terminal-fsync")?;
    let old = write_entry(&cache, &key, b"old-result")?;
    let snapshot = Job::new("prior active generation").snapshot()?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&snapshot, limits(), |writer| {
        writer.streams().2.write_all(b"old-cursor")?;
        Ok(json!({"generation":1}))
    })?;
    drop(lease);
    Ok((cache, old, snapshot))
}

fn run_child(root: &Path, trace: &Path, fault: Option<usize>) -> Result<(), Box<dyn Error>> {
    let mut command = Command::new("strace");
    command.args(["-f", "-qq", "-yy", "-e", "trace=fsync"]);
    if let Some(call) = fault {
        command
            .arg("-e")
            .arg(format!("inject=fsync:error=EIO:when={call}"));
    } else {
        command.env("L2_TEST_TERMINAL_FSYNC_PROBE", "1");
    }
    let child = command
        .arg("-o")
        .arg(trace)
        .arg(std::env::current_exe()?)
        .args([
            "--exact",
            "cache::terminal_fsync::terminal_fsync_failure_child",
            "--nocapture",
        ])
        .env("L2_TEST_TERMINAL_FSYNC_ROOT", root)
        .output()?;
    assert!(
        child.status.success(),
        "terminal child failed: stdout={} stderr={} trace={}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr),
        fs::read_to_string(trace)?
    );
    Ok(())
}
