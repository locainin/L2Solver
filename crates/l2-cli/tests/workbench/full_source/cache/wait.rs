use super::{source_index_key, wait_for_cache_key};
use l2_workbench::job::cache::{Cache, CacheError, CacheReadPolicy};
use std::{
    error::Error,
    time::{Duration, Instant},
};

#[test]
fn busy_key_is_not_ready_at_deadline() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let cache = Cache::open_at(
        root.path().join("cache"),
        root.path().join("state"),
        1_000_000,
    )?;
    let key = source_index_key(&format!("sha256:{}", "00".repeat(32)))?;
    let _lease = cache.lease(&key)?;
    assert!(matches!(
        cache.lookup(&key, CacheReadPolicy::CompleteOnly),
        Err(CacheError::LockBusy)
    ));

    // Check both an expired deadline and a short wait with the lease still held
    for timeout in [Duration::ZERO, Duration::from_millis(30)] {
        assert!(
            !wait_for_cache_key(&cache, &key, None, Instant::now() + timeout, true)?,
            "a busy cache key must remain unavailable through its deadline"
        );
    }
    Ok(())
}
