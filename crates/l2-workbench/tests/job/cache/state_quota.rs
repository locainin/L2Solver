use super::*;

#[test]
fn metadata_cannot_grow_state_without_limit() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 0)?;
    for index in 0..20 {
        let key = stage_key(&format!("metadata-{index}"))?;
        let lease = cache.lease(&key)?;
        drop(lease.commit(
            StageStatus::Complete,
            json!({"payload": "x".repeat(512 * 1024)}),
        )?);
    }

    assert!(
        cache.stats()?.entries < 20,
        "metadata must not bypass the state limit"
    );
    Ok(())
}

#[test]
fn state_pressure_keeps_active_entries() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 0)?;
    let pinned_key = stage_key("pinned-state")?;
    let pinned = cache.lease(&pinned_key)?.commit(
        StageStatus::Complete,
        json!({"payload": "p".repeat(512 * 1024)}),
    )?;
    cache.write_checkpoint(
        &pinned_key,
        &Job::new("active").snapshot()?,
        CheckpointStatus::Active,
    )?;

    for index in 0..12 {
        let key = stage_key(&format!("replaceable-{index}"))?;
        drop(cache.lease(&key)?.commit(
            StageStatus::Complete,
            json!({"payload": "x".repeat(512 * 1024)}),
        )?);
    }

    assert!(pinned.directory().is_dir());
    assert_eq!(
        cache
            .read_checkpoint(&pinned_key)?
            .ok_or("missing checkpoint")?
            .status,
        CheckpointStatus::Active
    );
    assert!(cache.stats()?.entries < 13);
    Ok(())
}

#[test]
fn state_limit_holds_with_wal_reader() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 0)?;
    let key = stage_key("wal-reader")?;
    drop(
        cache
            .lease(&key)?
            .commit(StageStatus::Complete, json!({"payload":"initial"}))?,
    );
    let reader = rusqlite::Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    reader.execute_batch("BEGIN; SELECT count(*) FROM entries;")?;

    let mut committed = 0;
    let mut blocked = false;
    for index in 0..30 {
        let lease = match cache.lease(&key) {
            Ok(lease) => lease,
            Err(CacheError::CacheBusy | CacheError::QuotaExceeded { .. }) => {
                blocked = true;
                break;
            }
            Err(error) => return Err(error.into()),
        };
        let byte = char::from(b'a' + u8::try_from(index % 26)?);
        match lease.commit(
            StageStatus::Complete,
            json!({"index":index,"payload":byte.to_string().repeat(512 * 1024)}),
        ) {
            Ok(entry) => {
                drop(entry);
                committed += 1;
            }
            Err(CacheError::CacheBusy | CacheError::QuotaExceeded { .. }) => {
                blocked = true;
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }

    let stats = cache.stats()?;
    assert!(committed > 0, "no updates reached the pinned WAL");
    assert!(blocked, "the pinned WAL did not stop further writes");
    assert!(
        stats.state_bytes <= stats.state_limit_bytes,
        "state {} exceeds limit {}",
        stats.state_bytes,
        stats.state_limit_bytes
    );
    reader.execute_batch("ROLLBACK")?;
    drop(reader);
    drop(
        cache
            .lease(&key)?
            .commit(StageStatus::Complete, json!({"payload":"recovered"}))?,
    );
    Ok(())
}

#[test]
fn completed_checkpoints_make_room() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 0)?;
    let active_key = stage_key("active-checkpoint")?;
    let snapshot = Job::new("x".repeat(512 * 1024)).snapshot()?;
    cache.write_checkpoint(&active_key, &snapshot, CheckpointStatus::Active)?;

    for index in 0..12 {
        let key = stage_key(&format!("completed-checkpoint-{index}"))?;
        cache.write_checkpoint(&key, &snapshot, CheckpointStatus::Complete)?;
    }

    assert_eq!(
        cache
            .read_checkpoint(&active_key)?
            .ok_or("missing active checkpoint")?
            .status,
        CheckpointStatus::Active
    );
    assert!(cache.stats()?.checkpoints < 13);
    Ok(())
}

#[test]
fn pinned_state_denies_growth() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 0)?;
    let key = stage_key("pinned-state")?;
    let pinned = cache.lease(&key)?.commit(
        StageStatus::Complete,
        json!({"payload": "p".repeat(2 * 1024 * 1024)}),
    )?;
    let incoming = stage_key("incoming-state")?;
    let result = cache.lease(&incoming)?.commit(
        StageStatus::Complete,
        json!({"payload": "x".repeat(3 * 1024 * 1024)}),
    );

    assert!(matches!(result, Err(CacheError::QuotaExceeded { .. })));
    assert_eq!(
        pinned
            .metadata()
            .get("payload")
            .and_then(Value::as_str)
            .map(str::len),
        Some(2 * 1024 * 1024)
    );
    assert_eq!(cache.stats()?.entries, 1);
    Ok(())
}

#[test]
fn denied_state_keeps_unpinned_entry() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 0)?;
    let pinned_key = stage_key("pinned-state-denial")?;
    let victim_key = stage_key("unrelated-state")?;
    let incoming_key = stage_key("incoming-state-denial")?;
    let completed_key = stage_key("unrelated-checkpoint")?;
    let pinned = cache.lease(&pinned_key)?.commit(
        StageStatus::Complete,
        json!({"payload": "p".repeat(2 * 1024 * 1024)}),
    )?;
    drop(cache.lease(&victim_key)?.commit(
        StageStatus::Complete,
        json!({"payload": "v".repeat(1024 * 1024)}),
    )?);
    cache.write_checkpoint(
        &completed_key,
        &Job::new("c".repeat(256 * 1024)).snapshot()?,
        CheckpointStatus::Complete,
    )?;

    let result = cache.lease(&incoming_key)?.commit(
        StageStatus::Complete,
        json!({"payload": "i".repeat(2 * 1024 * 1024)}),
    );

    assert!(matches!(result, Err(CacheError::QuotaExceeded { .. })));
    assert!(pinned.directory().is_dir());
    assert!(
        cache
            .lookup(&victim_key, CacheReadPolicy::CompleteOnly)?
            .is_some()
    );
    assert_eq!(
        cache
            .read_checkpoint(&completed_key)?
            .ok_or("missing checkpoint")?
            .status,
        CheckpointStatus::Complete
    );
    Ok(())
}
