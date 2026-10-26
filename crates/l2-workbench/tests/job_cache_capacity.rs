use std::{error::Error, fs, path::PathBuf};

use l2_workbench::job::cache::{Cache, CacheEntry, SourceIdentity, StageKey, StageStatus};
use serde_json::json;

fn stage_key(name: &str) -> Result<StageKey, Box<dyn Error>> {
    let source = SourceIdentity::from_sha256("a".repeat(64))?;
    Ok(StageKey::new(
        name,
        1,
        "capacity-test-v1",
        &json!({"stable": true}),
        &source,
        &[],
    )?)
}

fn commit_entry(cache: &Cache, key: &StageKey) -> Result<CacheEntry, Box<dyn Error>> {
    let lease = cache.lease(key)?;
    fs::write(lease.directory().join("result.bin"), b"same-size")?;
    Ok(lease.commit(StageStatus::Complete, json!({"complete": true}))?)
}

fn write_entry(cache: &Cache, key: &StageKey) -> Result<PathBuf, Box<dyn Error>> {
    let entry = commit_entry(cache, key)?;
    Ok(entry.directory().to_path_buf())
}

#[test]
fn exact_quota_fit_keeps_all_entries() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache_root = temporary.path().join("cache");
    let state_root = temporary.path().join("state");
    let initial_cache = Cache::open_at(&cache_root, &state_root, u64::MAX)?;
    let first_directory = write_entry(&initial_cache, &stage_key("first-stage")?)?;
    let entry_bytes = initial_cache.stats()?.entry_bytes;
    assert_eq!(entry_bytes, u64::try_from(b"same-size".len())?);
    drop(initial_cache);

    // The two identical entries exactly fill the configured quota
    let exact_limit = entry_bytes.checked_mul(2).ok_or("cache quota overflow")?;
    let cache = Cache::open_at(&cache_root, &state_root, exact_limit)?;
    let second_directory = write_entry(&cache, &stage_key("second-stage")?)?;

    assert!(first_directory.is_dir());
    assert!(second_directory.is_dir());
    let stats = cache.stats()?;
    assert_eq!(stats.entries, 2);
    assert_eq!(stats.entry_bytes, exact_limit);
    Ok(())
}

#[test]
fn eviction_accepts_an_underfilled_final_quota() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache_root = temporary.path().join("cache");
    let state_root = temporary.path().join("state");
    let initial_cache = Cache::open_at(&cache_root, &state_root, u64::MAX)?;
    let first_directory = write_entry(&initial_cache, &stage_key("old-stage")?)?;
    drop(initial_cache);

    let cache = Cache::open_at(&cache_root, &state_root, 10)?;
    let second_directory = write_entry(&cache, &stage_key("new-stage")?)?;

    assert!(!first_directory.exists());
    assert!(second_directory.is_dir());
    let stats = cache.stats()?;
    assert_eq!(stats.entries, 1);
    assert_eq!(stats.entry_bytes, u64::try_from(b"same-size".len())?);
    assert_eq!(stats.over_limit_bytes, 0);
    Ok(())
}

#[test]
fn eviction_plans_multiple_entries_after_reader_pins_are_released() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache_root = temporary.path().join("cache");
    let state_root = temporary.path().join("state");
    let initial_cache = Cache::open_at(&cache_root, &state_root, u64::MAX)?;
    let first = commit_entry(&initial_cache, &stage_key("first-stage")?)?;
    let second = commit_entry(&initial_cache, &stage_key("second-stage")?)?;
    let first_directory = first.directory().to_path_buf();
    let second_directory = second.directory().to_path_buf();
    let entry_bytes = initial_cache.stats()?.entry_bytes / 2;
    assert_eq!(entry_bytes, u64::try_from(b"same-size".len())?);
    drop(initial_cache);

    // Reader pins keep both entries present while a stricter quota is opened
    let cache = Cache::open_at(&cache_root, &state_root, entry_bytes)?;
    let pinned_stats = cache.stats()?;
    assert_eq!(pinned_stats.entries, 2);
    assert_eq!(pinned_stats.over_limit_bytes, entry_bytes);
    drop(first);
    drop(second);

    let newest = commit_entry(&cache, &stage_key("third-stage")?)?;

    assert!(!first_directory.exists());
    assert!(!second_directory.exists());
    assert!(newest.directory().is_dir());
    let stats = cache.stats()?;
    assert_eq!(stats.entries, 1);
    assert_eq!(stats.entry_bytes, entry_bytes);
    Ok(())
}
