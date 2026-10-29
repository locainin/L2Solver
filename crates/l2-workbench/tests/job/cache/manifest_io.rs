//! Check that real manifest-read failures keep their original error class

use super::{cache_at, stage_key, terminal_fsync::strace_available};
use l2_workbench::job::cache::{CacheError, CacheReadPolicy, StageStatus};
use rustix::io::Errno;
use serde_json::json;
use std::{error::Error, fs, path::Path, process::Command};

#[test]
fn manifest_lookup_with_injected_failure_child() -> Result<(), Box<dyn Error>> {
    let Some(base) = std::env::var_os("L2_TEST_MANIFEST_IO_ROOT") else {
        return Ok(());
    };
    let expected: i32 = std::env::var("L2_TEST_MANIFEST_IO_ERRNO")?.parse()?;
    let cache = cache_at(Path::new(&base), 64 * 1024)?;
    let key = stage_key("manifest-io")?;
    let error = cache
        .lookup(&key, CacheReadPolicy::CompleteOnly)
        .err()
        .ok_or("manifest lookup unexpectedly succeeded")?;
    assert!(
        matches!(&error, CacheError::Io(source) if source.raw_os_error() == Some(expected)),
        "manifest lookup lost the original filesystem error: {error}"
    );
    Ok(())
}

#[test]
fn manifest_read_resource_failures_remain_typed_io_errors() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    if !strace_available(temporary.path()) {
        eprintln!("manifest read fault test needs usable strace");
        return Ok(());
    }
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("manifest-io")?;
    let lease = cache.lease(&key)?;
    fs::create_dir(lease.directory().join("nested"))?;
    fs::write(lease.directory().join("nested/result"), b"result")?;
    let entry = lease.commit(StageStatus::Complete, json!({}))?;
    let nested = fs::canonicalize(entry.directory().join("nested"))?;
    drop(entry);

    let generation = nested.parent().ok_or("missing cache generation")?;
    for (name, errno, syscall, path) in [
        ("ENOMEM", Errno::NOMEM, "getdents64", nested.as_path()),
        ("EDQUOT", Errno::DQUOT, "getdents64", nested.as_path()),
        ("ENOMEM", Errno::NOMEM, "openat", generation),
        ("EDQUOT", Errno::DQUOT, "openat", generation),
    ] {
        let trace_path = temporary
            .path()
            .join(format!("manifest-{syscall}-{name}.trace"));
        let trace = format!("trace={syscall}");
        let injection = format!("inject={syscall}:error={name}:when=1");
        let child = Command::new("strace")
            .args(["-f", "-qq", "-yy", "-P"])
            .arg(path)
            .arg("-e")
            .arg(trace)
            .arg("-e")
            .arg(injection)
            .arg("-o")
            .arg(&trace_path)
            .arg(std::env::current_exe()?)
            .args([
                "--exact",
                "cache::manifest_io::manifest_lookup_with_injected_failure_child",
                "--nocapture",
            ])
            .env("L2_TEST_MANIFEST_IO_ROOT", temporary.path())
            .env(
                "L2_TEST_MANIFEST_IO_ERRNO",
                errno.raw_os_error().to_string(),
            )
            .output()?;
        let trace = fs::read_to_string(trace_path)?;
        assert!(
            trace.contains(name) && trace.contains("INJECTED"),
            "targeted manifest read injection did not fire: {trace}"
        );
        assert!(
            child.status.success(),
            "manifest lookup child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
    }
    Ok(())
}
