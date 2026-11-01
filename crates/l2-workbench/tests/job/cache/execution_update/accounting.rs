//! Keep displaced cursor charges until retired files are durably removed

use super::*;
use l2_workbench::job::cache::StageStatus;
use std::{os::unix::fs::PermissionsExt, path::Path};

struct RestoreDirectoryMode(PathBuf);

impl Drop for RestoreDirectoryMode {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
    }
}

fn reservation_bytes(database: &rusqlite::Connection, key: &str) -> Result<u64, Box<dyn Error>> {
    Ok(database.query_row(
        "SELECT COALESCE(sum(bytes), 0) FROM execution_reservations WHERE key = ?1",
        [key],
        |row| row.get(0),
    )?)
}

fn restore_mode(directory: &Path) -> Result<(), Box<dyn Error>> {
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[test]
fn failed_retirement_keeps_displaced_cursor_bytes_charged_through_next_lease()
-> Result<(), Box<dyn Error>> {
    let mut fixture = Fixture::new(None)?;
    let directory = fixture.directory()?;
    let old = directory.join("executor");
    let link = fixture.temporary.path().join("held-cursor");
    fs::hard_link(&old, &link)?;
    fixture.lease.update_active_executor(
        &mut fixture.generation,
        &fixture.initial_snapshot,
        limits(),
        |writer| {
            writer.write_all(b"new cursor")?;
            Ok(json!({"cursor":1}))
        },
    )?;
    assert!(old.exists(), "the displaced cursor must remain on disk");
    fs::remove_file(link)?;

    let key = stage_key("executor-update")?;
    let database =
        rusqlite::Connection::open(fixture.temporary.path().join("state/cache.sqlite3"))?;
    assert_eq!(reservation_bytes(&database, key.as_str())?, 11);
    // Deny unlink in this generation while allowing terminal publication elsewhere
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o500))?;
    let mode_guard = RestoreDirectoryMode(directory.clone());
    fs::write(fixture.lease.directory().join("result"), b"final")?;
    drop(fixture.lease.commit(StageStatus::Complete, json!({}))?);
    assert!(
        old.exists(),
        "retired cleanup must fail before unlinking the old cursor"
    );
    let before = fixture.cache.stats()?.entry_bytes;

    let lease = fixture.cache.lease(&key)?;
    assert!(old.exists());
    assert_eq!(reservation_bytes(&database, key.as_str())?, 11);
    assert_eq!(fixture.cache.stats()?.entry_bytes, before);
    drop(lease);

    restore_mode(&directory)?;
    drop(mode_guard);
    fixture.cache.prune()?;
    assert!(!directory.exists());
    assert_eq!(reservation_bytes(&database, key.as_str())?, 0);
    assert_eq!(fixture.cache.stats()?.entry_bytes, 5);
    Ok(())
}

#[test]
fn retired_cleanup_does_not_release_a_similar_generation_name() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(None)?;
    let key = stage_key("executor-update")?;
    let database =
        rusqlite::Connection::open(fixture.temporary.path().join("state/cache.sqlite3"))?;
    let relative: String = database.query_row(
        "SELECT relative_path FROM executions WHERE key = ?1",
        [key.as_str()],
        |row| row.get(0),
    )?;
    let other = format!("{relative}other/executor");
    database.execute(
        "INSERT INTO execution_reservations(token, key, bytes) VALUES (?1, ?2, 13)",
        rusqlite::params![other, key.as_str()],
    )?;
    fs::write(fixture.lease.directory().join("result"), b"final")?;
    drop(fixture.lease.commit(StageStatus::Complete, json!({}))?);
    // A matching text prefix is not a child of the retired generation
    assert_eq!(reservation_bytes(&database, key.as_str())?, 13);
    Ok(())
}
