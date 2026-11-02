use super::{AcquisitionOptions, LLDP_CAPTURE, acquire_indexed_source, source_alias_key};
use l2_workbench::job::{
    CacheFallbackKind, CacheStage, Counter, Job, Phase, PhaseState,
    cache::{Cache, CacheError, CacheReadPolicy, SourceFingerprint},
};
use std::{error::Error, fs};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn optional_capture_quota_keeps_the_prepared_index_without_reingestion() -> TestResult {
    let directory = tempfile::tempdir()?;
    let capture = directory.path().join("capture.pcap");
    fs::write(&capture, LLDP_CAPTURE)?;
    let cache = Cache::open_at(
        directory.path().join("cache"),
        directory.path().join("state"),
        0,
    )?;
    let job = Job::new("capture cache quota fallback");
    let indexed = acquire_indexed_source(
        &capture,
        directory.path(),
        &AcquisitionOptions {
            cache: Some(&cache),
            job: Some(&job),
            ..AcquisitionOptions::default()
        },
    )?;

    // A denied cache write must keep the one completed source read usable
    assert_eq!(indexed.receipt.packets, 1);
    assert!(
        indexed
            .store
            .packet(&indexed.receipt.source_id, 1)?
            .flow
            .is_none()
    );
    let snapshot = job.snapshot()?;
    assert_eq!(snapshot.counters.get(&Counter::Packets), Some(&1));
    assert_eq!(snapshot.counters.get(&Counter::CacheMisses), Some(&1));
    assert_eq!(
        snapshot.phase(Phase::Ingestion).map(|phase| phase.state),
        Some(PhaseState::Completed)
    );
    assert!(snapshot.cache_fallbacks.records().iter().any(|record| {
        record.stage() == CacheStage::CaptureIndex
            && record.kind() == CacheFallbackKind::CommitQuotaExceeded
    }));
    assert_eq!(cache.stats()?.entries, 0);
    Ok(())
}

#[test]
fn strict_capture_quota_returns_the_typed_error_without_a_fallback() -> TestResult {
    let directory = tempfile::tempdir()?;
    let capture = directory.path().join("capture.pcap");
    fs::write(&capture, LLDP_CAPTURE)?;
    let cache = Cache::open_at(
        directory.path().join("cache"),
        directory.path().join("state"),
        0,
    )?;
    let job = Job::new("strict capture cache quota");
    let result = acquire_indexed_source(
        &capture,
        directory.path(),
        &AcquisitionOptions {
            cache: Some(&cache),
            job: Some(&job),
            strict_cache: true,
            ..AcquisitionOptions::default()
        },
    );
    let error = result
        .err()
        .ok_or("strict cache quota unexpectedly succeeded")?;
    assert!(matches!(
        error.downcast_ref::<CacheError>(),
        Some(CacheError::QuotaExceeded { limit_bytes: 0, .. })
    ));
    assert_eq!(job.snapshot()?.cache_fallbacks.records().len(), 0);
    assert_eq!(job.snapshot()?.counters.get(&Counter::Packets), Some(&1));
    Ok(())
}

#[test]
fn reused_content_index_does_not_store_another_index_in_its_alias() -> TestResult {
    let directory = tempfile::tempdir()?;
    let original = directory.path().join("original.pcap");
    let moved = directory.path().join("moved.pcap");
    fs::write(&original, LLDP_CAPTURE)?;
    fs::copy(&original, &moved)?;
    let cache_root = directory.path().join("cache");
    let state_root = directory.path().join("state");
    let initial_cache = Cache::open_at(&cache_root, &state_root, 16 * 1024 * 1024)?;
    let original_index = acquire_indexed_source(
        &original,
        directory.path(),
        &AcquisitionOptions {
            cache: Some(&initial_cache),
            ..AcquisitionOptions::default()
        },
    )?;
    // Keep the content index pinned while removing its unpinned source alias
    initial_cache.clear()?;
    let retained_bytes = initial_cache.stats()?.entry_bytes;
    let cache = Cache::open_at(&cache_root, &state_root, retained_bytes)?;
    let job = Job::new("content index winner alias");
    let indexed = acquire_indexed_source(
        &moved,
        directory.path(),
        &AcquisitionOptions {
            cache: Some(&cache),
            job: Some(&job),
            ..AcquisitionOptions::default()
        },
    )?;
    assert_eq!(indexed.receipt.source_id, original_index.receipt.source_id);
    let key = source_alias_key(&SourceFingerprint::fast(&moved)?)?;
    let alias = cache
        .lookup(&key, CacheReadPolicy::CompleteOnly)?
        .ok_or("source alias was not stored")?;
    assert_eq!(fs::read_dir(alias.directory())?.count(), 0);
    assert_eq!(cache.stats()?.entry_bytes, retained_bytes);
    assert_eq!(job.snapshot()?.cache_fallbacks.records().len(), 0);
    Ok(())
}

#[test]
fn optional_alias_quota_keeps_the_pinned_content_index_usable() -> TestResult {
    let directory = tempfile::tempdir()?;
    let capture = directory.path().join("capture.pcap");
    fs::write(&capture, LLDP_CAPTURE)?;
    let cache_root = directory.path().join("cache");
    let state_root = directory.path().join("state");
    let initial_cache = Cache::open_at(&cache_root, &state_root, 16 * 1024 * 1024)?;
    let original_index = acquire_indexed_source(
        &capture,
        directory.path(),
        &AcquisitionOptions {
            cache: Some(&initial_cache),
            ..AcquisitionOptions::default()
        },
    )?;
    initial_cache.clear()?;
    // A smaller quota cannot evict this live index or justify discarding its result
    let cache = Cache::open_at(&cache_root, &state_root, 0)?;
    let job = Job::new("optional source alias quota");
    let indexed = acquire_indexed_source(
        &capture,
        directory.path(),
        &AcquisitionOptions {
            cache: Some(&cache),
            job: Some(&job),
            ..AcquisitionOptions::default()
        },
    )?;
    assert_eq!(indexed.receipt.source_id, original_index.receipt.source_id);
    assert_eq!(indexed.receipt.packets, 1);
    assert_eq!(job.snapshot()?.counters.get(&Counter::CacheHits), Some(&1));
    assert!(
        job.snapshot()?
            .cache_fallbacks
            .records()
            .iter()
            .any(|record| {
                record.stage() == CacheStage::CaptureIndex
                    && record.kind() == CacheFallbackKind::CommitQuotaExceeded
            })
    );
    Ok(())
}
