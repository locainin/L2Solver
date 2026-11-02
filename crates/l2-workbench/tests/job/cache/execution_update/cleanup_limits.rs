//! Reject oversized cleanup fields before consuming their full input

use super::*;
use std::{path::Path, process::Command};

const CHILD_ROOT: &str = "L2_TEST_CLEANUP_LIMIT_ROOT";
const CHILD_TEST: &str = "cache::execution_update::cleanup_limits::cleanup_rejects_oversized_directory_without_reading_it";
const CHILD_RECEIPT: &str = "bounded-cleanup-checked";
const OVERSIZED: usize = 2 * 1024 * 1024;
const MAX_READ_BYTES: u64 = 512 * 1024;

fn process_read_bytes() -> Result<u64, Box<dyn Error>> {
    let usage = fs::read_to_string("/proc/self/io")?;
    let value = usage
        .lines()
        .find_map(|line| line.strip_prefix("rchar: "))
        .ok_or("process read count is missing")?;
    Ok(value.trim().parse()?)
}

#[test]
fn cleanup_child_rejects_an_unowned_directory_without_writing() -> Result<(), Box<dyn Error>> {
    assert_child_rejects_unowned_root(CHILD_ROOT, CHILD_TEST)
}

fn bounded_cleanup_child() -> Result<(), Box<dyn Error>> {
    let root = std::env::var_os(CHILD_ROOT).ok_or("missing controlled child directory")?;
    check_child_root(Path::new(&root))?;
    let cache = cache_at(Path::new(&root), 8 * 1024 * 1024)?;
    let key = stage_key("executor-update")?;
    let before = process_read_bytes()?;
    assert!(
        cache.lease(&key).is_err(),
        "the malformed envelope was accepted"
    );
    let consumed = process_read_bytes()?.saturating_sub(before);
    assert!(
        consumed < MAX_READ_BYTES,
        "cleanup consumed {consumed} bytes while rejecting an oversized field"
    );
    // Signal only after the child has checked both rejection and the read bound
    fs::write(Path::new(&root).join(CHILD_RECEIPT), b"cleanup checked")?;
    Ok(())
}

#[derive(Clone, Copy)]
enum Corruption {
    Directory,
    FieldName,
    Nesting,
}

fn assert_bounded_cleanup(corruption: Corruption) -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(None)?;
    fixture.mark_child_root()?;
    let database =
        rusqlite::Connection::open(fixture.temporary.path().join("state/cache.sqlite3"))?;
    let encoded: String =
        database.query_row("SELECT envelope_json FROM executions", [], |row| row.get(0))?;
    let mut envelope: Value = serde_json::from_str(&encoded)?;
    let damaged = match corruption {
        Corruption::Nesting => {
            let marker = "\"metadata\":{\"cursor\":0}";
            assert!(encoded.contains(marker), "metadata marker is missing");
            let nested = format!(
                "\"metadata\":{}0{}",
                "[".repeat(OVERSIZED / 2),
                "]".repeat(OVERSIZED / 2)
            );
            encoded.replace(marker, &nested)
        }
        Corruption::Directory => {
            envelope
                .get_mut("components")
                .and_then(Value::as_array_mut)
                .and_then(|components| components.get_mut(2))
                .and_then(Value::as_object_mut)
                .ok_or("executor component is missing")?
                .insert("directory".to_owned(), Value::String("x".repeat(OVERSIZED)));
            serde_json::to_string(&envelope)?
        }
        Corruption::FieldName => {
            envelope
                .as_object_mut()
                .ok_or("envelope is not an object")?
                .insert("x".repeat(OVERSIZED), Value::Null);
            serde_json::to_string(&envelope)?
        }
    };
    database.execute("UPDATE executions SET envelope_json = ?1", [damaged])?;
    drop(database);
    let staging_key = fixture
        .lease
        .directory()
        .parent()
        .ok_or("staging key is missing")?
        .to_path_buf();
    drop(fixture.lease);
    // Keep startup maintenance from visiting the damaged row before the child measures it
    fs::remove_dir(staging_key)?;
    let child = Command::new(std::env::current_exe()?)
        .args(["--exact", CHILD_TEST, "--nocapture"])
        .env(CHILD_ROOT, fixture.temporary.path())
        .output()?;
    assert!(
        child.status.success(),
        "cleanup child failed: stdout={} stderr={}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    // A successful empty test filter must not count as a checked cleanup
    assert_eq!(
        fs::read(fixture.temporary.path().join(CHILD_RECEIPT))?,
        b"cleanup checked"
    );
    Ok(())
}

#[test]
fn cleanup_rejects_oversized_directory_without_reading_it() -> Result<(), Box<dyn Error>> {
    // The parent sets this root only for the isolated read-accounting child
    if std::env::var_os(CHILD_ROOT).is_some() {
        return bounded_cleanup_child();
    }
    assert_bounded_cleanup(Corruption::Directory)
}

#[test]
fn cleanup_rejects_oversized_field_name_without_reading_it() -> Result<(), Box<dyn Error>> {
    assert_bounded_cleanup(Corruption::FieldName)
}

#[test]
fn cleanup_rejects_excessive_ignored_nesting_without_reading_it() -> Result<(), Box<dyn Error>> {
    assert_bounded_cleanup(Corruption::Nesting)
}

#[test]
fn cleanup_accepts_large_valid_metadata_within_the_callers_limit() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 8 * 1024 * 1024)?;
    let key = stage_key("large-valid-cleanup-metadata")?;
    let mut lease = cache.lease(&key)?;
    let mut caps = limits();
    caps.max_metadata_bytes = 2 * 1024 * 1024;
    let mut nested = Value::Null;
    for _ in 0..96 {
        nested = Value::Array(vec![nested]);
    }
    let metadata = json!({"large": "x".repeat(512 * 1024), "nested": nested});
    lease.save_active_generation(&Job::new("large metadata").snapshot()?, caps, |writer| {
        writer.streams().2.write_all(b"cursor")?;
        Ok(&metadata)
    })?;
    drop(lease);
    let restored = cache.lease(&key)?;
    assert!(restored.load_active(caps)?.is_some());
    Ok(())
}
