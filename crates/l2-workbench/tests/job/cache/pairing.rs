use super::*;

#[test]
fn mismatched_state_preserves_live_data() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache_root = temporary.path().join("cache");
    let first = Cache::open_at(&cache_root, temporary.path().join("state-one"), 1024)?;
    let entry_key = stage_key("pinned-entry")?;
    let writer_key = stage_key("active-writer")?;
    let lease = first.lease(&entry_key)?;
    fs::write(lease.directory().join("result"), b"committed")?;
    let pinned = lease.commit(StageStatus::Complete, json!({}))?;
    let writer = first.lease(&writer_key)?;
    fs::write(writer.directory().join("result"), b"in-progress")?;

    let second = Cache::open_at(&cache_root, temporary.path().join("state-two"), 1024);

    assert!(second.is_err());
    assert_eq!(fs::read(pinned.directory().join("result"))?, b"committed");
    assert_eq!(fs::read(writer.directory().join("result"))?, b"in-progress");
    Ok(())
}

#[test]
fn mismatched_cache_preserves_state() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let cache = cache_at(root, 1024)?;
    let key = stage_key("existing-entry")?;
    let directory = write_entry(&cache, &key, b"saved")?;

    assert!(Cache::open_at(root.join("other-cache"), root.join("state"), 1024).is_err());
    assert_eq!(fs::read(directory.join("result.bin"))?, b"saved");
    assert!(cache.lookup(&key, CacheReadPolicy::CompleteOnly)?.is_some());
    Ok(())
}

#[test]
fn mismatched_pair_does_not_migrate_state() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    drop(Cache::open_at(
        root.join("cache-one"),
        root.join("state-one"),
        1024,
    )?);
    drop(Cache::open_at(
        root.join("cache-two"),
        root.join("state-two"),
        1024,
    )?);
    let path = root.join("state-two/cache.sqlite3");
    let database = rusqlite::Connection::open(&path)?;
    database.pragma_update(None, "user_version", 1)?;
    drop(database);

    assert!(Cache::open_at(root.join("cache-one"), root.join("state-two"), 1024).is_err());
    let database = rusqlite::Connection::open(path)?;
    let version: u32 = database.pragma_query_value(None, "user_version", |row| row.get(0))?;
    assert_eq!(version, 1);
    Ok(())
}

#[test]
fn legacy_pair_migrates_without_removing_entries() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let cache = cache_at(root, 1024)?;
    let key = stage_key("legacy-entry")?;
    let directory = write_entry(&cache, &key, b"saved")?;
    drop(cache);
    fs::remove_file(root.join("cache/pairing"))?;
    fs::remove_file(root.join("state/pairing"))?;

    let reopened = cache_at(root, 1024)?;
    assert_eq!(fs::read(directory.join("result.bin"))?, b"saved");
    assert!(
        reopened
            .lookup(&key, CacheReadPolicy::CompleteOnly)?
            .is_some()
    );
    Ok(())
}

#[test]
fn legacy_unknown_generation_is_preserved() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let cache = cache_at(root, 1024)?;
    let key = stage_key("legacy-entry")?;
    let directory = write_entry(&cache, &key, b"saved")?;
    drop(cache);
    fs::remove_file(root.join("cache/pairing"))?;
    fs::remove_file(root.join("state/pairing"))?;
    let unknown = directory
        .parent()
        .ok_or("missing entry root")?
        .join("unknown");
    fs::create_dir(&unknown)?;
    fs::write(unknown.join("result"), b"unknown")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&unknown, fs::Permissions::from_mode(0o755))?;
    }

    assert!(cache_at(root, 1024).is_err());
    assert_eq!(fs::read(directory.join("result.bin"))?, b"saved");
    assert_eq!(fs::read(unknown.join("result"))?, b"unknown");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&unknown)?.permissions().mode() & 0o777, 0o755);
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn legacy_lock_inspection_preserves_permissions() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let cache = cache_at(root, 1024)?;
    drop(cache);
    fs::remove_file(root.join("cache/pairing"))?;
    fs::remove_file(root.join("state/pairing"))?;
    let path = root
        .join("state/locks")
        .join(format!("{}.lock", stage_key("legacy-lock")?.as_str()));
    fs::write(&path, b"unchanged")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;

    drop(cache_at(root, 1024)?);
    assert_eq!(fs::read(&path)?, b"unchanged");
    assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o644);
    Ok(())
}
