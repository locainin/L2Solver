use super::{AcquisitionOptions, LLDP_CAPTURE, acquire_indexed_source, open_test_cache};
use l2_workbench::job::{
    CacheFallbackKind, CacheStage, Counter, Job, MemoryBudget, MemoryClass, Phase, PhaseState,
    cache::{Cache, CacheError},
};
use rusqlite::{Connection, params};
use serde_json::Value;
use std::{error::Error, fs, path::Path};

type TestResult = Result<(), Box<dyn Error>>;

fn seeded(directory: &Path) -> Result<(Cache, std::path::PathBuf, String), Box<dyn Error>> {
    let capture = directory.join("capture.pcap");
    fs::write(&capture, LLDP_CAPTURE)?;
    let cache = open_test_cache(directory)?;
    let indexed = acquire_indexed_source(
        &capture,
        directory,
        &AcquisitionOptions {
            cache: Some(&cache),
            ..AcquisitionOptions::default()
        },
    )?;
    let identity = indexed.receipt.source_id.clone();
    drop(indexed);
    Ok((cache, capture, identity))
}

fn change_json(
    directory: &Path,
    stage: &str,
    column: &str,
    change: impl FnOnce(&mut Value) -> TestResult,
) -> Result<String, Box<dyn Error>> {
    let connection = Connection::open(directory.join("state/cache.sqlite3"))?;
    let query = match column {
        "manifest_json" => "SELECT manifest_json FROM entries WHERE stage = ?1",
        "metadata_json" => "SELECT metadata_json FROM entries WHERE stage = ?1",
        _ => return Err("unsupported cache fixture column".into()),
    };
    let original: String = connection.query_row(query, [stage], |row| row.get(0))?;
    let mut value: Value = serde_json::from_str(&original)?;
    change(&mut value)?;
    let changed = serde_json::to_string(&value)?;
    let update = match column {
        "manifest_json" => "UPDATE entries SET manifest_json = ?1 WHERE stage = ?2",
        "metadata_json" => "UPDATE entries SET metadata_json = ?1 WHERE stage = ?2",
        _ => return Err("unsupported cache fixture column".into()),
    };
    assert_eq!(connection.execute(update, params![changed, stage])?, 1);
    Ok(changed)
}

fn cached_column(directory: &Path, stage: &str, column: &str) -> Result<String, Box<dyn Error>> {
    let connection = Connection::open(directory.join("state/cache.sqlite3"))?;
    let query = match column {
        "manifest_json" => "SELECT manifest_json FROM entries WHERE stage = ?1",
        "metadata_json" => "SELECT metadata_json FROM entries WHERE stage = ?1",
        "relative_path" => "SELECT relative_path FROM entries WHERE stage = ?1",
        _ => return Err("unsupported cache fixture column".into()),
    };
    Ok(connection.query_row(query, [stage], |row| row.get(0))?)
}

fn assert_uncached_recovery(
    directory: &Path,
    cache: &Cache,
    capture: &Path,
    identity: &str,
) -> TestResult {
    let job = Job::new("corrupt capture index fallback");
    let indexed = acquire_indexed_source(
        capture,
        directory,
        &AcquisitionOptions {
            cache: Some(cache),
            job: Some(&job),
            ..AcquisitionOptions::default()
        },
    )?;
    assert_eq!(indexed.receipt.source_id, identity);
    assert_eq!(indexed.receipt.packets, 1);
    let snapshot = job.snapshot()?;
    assert_eq!(
        snapshot.phase(Phase::Ingestion).map(|phase| phase.state),
        Some(PhaseState::Completed)
    );
    assert_eq!(
        snapshot
            .phase(Phase::Ingestion)
            .map(|phase| phase.completed),
        Some(u64::try_from(LLDP_CAPTURE.len())?)
    );
    assert_eq!(snapshot.counters.get(&Counter::Packets), Some(&1));
    assert_eq!(snapshot.counters.get(&Counter::CacheMisses), Some(&1));
    assert!(snapshot.cache_fallbacks.records().iter().any(|record| {
        record.stage() == CacheStage::CaptureIndex
            && record.kind() == CacheFallbackKind::InvalidEntry
    }));
    assert!(!snapshot.cache_fallbacks.records().iter().any(|record| {
        record.stage() == CacheStage::CaptureIndex
            && record.kind() == CacheFallbackKind::ContentionFallback
    }));
    drop(indexed);
    Ok(())
}

fn assert_strict_rejects(directory: &Path, cache: &Cache, capture: &Path) -> TestResult {
    let job = Job::new("strict corrupt capture index");
    let result = acquire_indexed_source(
        capture,
        directory,
        &AcquisitionOptions {
            cache: Some(cache),
            job: Some(&job),
            strict_cache: true,
            ..AcquisitionOptions::default()
        },
    );
    assert!(result.is_err());
    assert!(job.snapshot()?.cache_fallbacks.records().is_empty());
    Ok(())
}

#[cfg(unix)]
#[test]
fn changed_manifest_device_recomputes_in_default_mode_and_strict_mode_rejects() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (cache, capture, identity) = seeded(directory.path())?;
    let relative = cached_column(directory.path(), "capture_index", "relative_path")?;
    let index = directory
        .path()
        .join("cache/entries")
        .join(relative)
        .join("index/index.sqlite");
    let index_bytes = fs::read(&index)?;
    let saved = change_json(
        directory.path(),
        "capture_index",
        "manifest_json",
        |manifest| {
            let device = manifest
                .pointer_mut("/items/0/device_id")
                .ok_or("fixture lacks a Unix device ID")?;
            *device = Value::from(device.as_u64().ok_or("device ID is not numeric")? ^ 1);
            Ok(())
        },
    )?;
    assert_strict_rejects(directory.path(), &cache, &capture)?;
    assert_uncached_recovery(directory.path(), &cache, &capture, &identity)?;
    assert_eq!(
        cached_column(directory.path(), "capture_index", "manifest_json")?,
        saved
    );
    assert_eq!(fs::read(index)?, index_bytes);
    assert_eq!(cache.stats()?.entries, 2);
    Ok(())
}

#[test]
fn corrupt_alias_recomputes_in_default_mode_and_preserves_the_entry() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (cache, capture, identity) = seeded(directory.path())?;
    let saved = change_json(
        directory.path(),
        "capture_source",
        "manifest_json",
        |manifest| {
            *manifest.get_mut("items").ok_or("manifest items missing")? = serde_json::json!([{}]);
            Ok(())
        },
    )?;
    assert_strict_rejects(directory.path(), &cache, &capture)?;
    assert_uncached_recovery(directory.path(), &cache, &capture, &identity)?;
    assert_eq!(
        cached_column(directory.path(), "capture_source", "manifest_json")?,
        saved
    );
    assert_eq!(cache.stats()?.entries, 2);
    Ok(())
}

#[test]
fn missing_index_generation_recomputes_without_removing_the_saved_entry() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (cache, capture, identity) = seeded(directory.path())?;
    let relative = cached_column(directory.path(), "capture_index", "relative_path")?;
    let generation = directory.path().join("cache/entries").join(relative);
    let saved = directory.path().join("saved-generation");
    fs::rename(generation, &saved)?;
    assert_strict_rejects(directory.path(), &cache, &capture)?;
    assert_uncached_recovery(directory.path(), &cache, &capture, &identity)?;
    assert!(saved.join("index/index.sqlite").is_file());
    assert_eq!(cache.stats()?.entries, 2);
    Ok(())
}

#[test]
fn invalid_cached_index_receipt_recomputes_after_lookup_without_replacing_it() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (cache, capture, identity) = seeded(directory.path())?;
    let saved = change_json(
        directory.path(),
        "capture_index",
        "metadata_json",
        |metadata| {
            *metadata
                .pointer_mut("/receipt/packets")
                .ok_or("packet count missing")? = Value::from(999_u64);
            Ok(())
        },
    )?;
    assert_strict_rejects(directory.path(), &cache, &capture)?;
    assert_uncached_recovery(directory.path(), &cache, &capture, &identity)?;
    assert_eq!(
        cached_column(directory.path(), "capture_index", "metadata_json")?,
        saved
    );
    assert_eq!(cache.stats()?.entries, 2);
    Ok(())
}

#[test]
fn corrupt_index_found_after_ingestion_reuses_the_staged_index_without_rereading() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (cache, capture, identity) = seeded(directory.path())?;
    let alias = change_json(
        directory.path(),
        "capture_source",
        "metadata_json",
        |metadata| {
            *metadata
                .get_mut("fingerprint")
                .ok_or("fingerprint missing")? = Value::Null;
            Ok(())
        },
    )?;
    let index = change_json(
        directory.path(),
        "capture_index",
        "manifest_json",
        |manifest| {
            *manifest
                .pointer_mut("/items/0")
                .ok_or("manifest item missing")? = serde_json::json!({});
            Ok(())
        },
    )?;
    assert_uncached_recovery(directory.path(), &cache, &capture, &identity)?;
    assert_eq!(
        cached_column(directory.path(), "capture_source", "metadata_json")?,
        alias
    );
    assert_eq!(
        cached_column(directory.path(), "capture_index", "manifest_json")?,
        index
    );
    assert_eq!(cache.stats()?.entries, 2);
    Ok(())
}

#[test]
fn invalid_index_receipt_found_after_ingestion_keeps_the_staged_index() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (cache, capture, identity) = seeded(directory.path())?;
    let alias = change_json(
        directory.path(),
        "capture_source",
        "metadata_json",
        |metadata| {
            *metadata
                .get_mut("fingerprint")
                .ok_or("fingerprint missing")? = Value::Null;
            Ok(())
        },
    )?;
    let index = change_json(
        directory.path(),
        "capture_index",
        "metadata_json",
        |metadata| {
            *metadata
                .pointer_mut("/receipt/packets")
                .ok_or("packet count missing")? = Value::from(999_u64);
            Ok(())
        },
    )?;
    assert_uncached_recovery(directory.path(), &cache, &capture, &identity)?;
    assert_eq!(
        cached_column(directory.path(), "capture_source", "metadata_json")?,
        alias
    );
    assert_eq!(
        cached_column(directory.path(), "capture_index", "metadata_json")?,
        index
    );
    assert_eq!(cache.stats()?.entries, 2);
    Ok(())
}

#[test]
fn source_change_is_not_treated_as_an_optional_cache_failure() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (cache, capture, _) = seeded(directory.path())?;
    let fingerprint = Cache::fingerprint_source(&capture)?;
    fs::write(&capture, super::STP_CAPTURE)?;
    let result = acquire_indexed_source(
        &capture,
        directory.path(),
        &AcquisitionOptions {
            cache: Some(&cache),
            fingerprint: Some(fingerprint),
            ..AcquisitionOptions::default()
        },
    );
    let error = result.err().ok_or("changed source was accepted")?;
    assert!(matches!(
        error.downcast_ref::<CacheError>(),
        Some(CacheError::SourceChanged)
    ));
    Ok(())
}

#[test]
fn memory_denial_does_not_start_an_uncached_fallback() -> TestResult {
    let directory = tempfile::tempdir()?;
    let capture = directory.path().join("capture.pcap");
    fs::write(&capture, LLDP_CAPTURE)?;
    let memory = MemoryBudget::new(16 * 1024 * 1024);
    let cache = Cache::open_at_with_memory_budget(
        directory.path().join("cache"),
        directory.path().join("state"),
        256 * 1024 * 1024,
        memory.clone(),
    )?;
    let indexed = acquire_indexed_source(
        &capture,
        directory.path(),
        &AcquisitionOptions {
            cache: Some(&cache),
            ..AcquisitionOptions::default()
        },
    )?;
    drop(indexed);
    let _all_memory = memory.try_reserve(MemoryClass::Executor, 16 * 1024 * 1024)?;
    let job = Job::new("denied capture cache lookup");
    let result = acquire_indexed_source(
        &capture,
        directory.path(),
        &AcquisitionOptions {
            cache: Some(&cache),
            job: Some(&job),
            ..AcquisitionOptions::default()
        },
    );
    let error = result.err().ok_or("memory denial was ignored")?;
    assert!(crate::memory_error::find(error.as_ref()).is_some());
    assert!(job.snapshot()?.cache_fallbacks.records().is_empty());
    assert!(memory.snapshot()?.rejected > 0);
    Ok(())
}

#[test]
fn cancellation_during_corrupt_cache_lookup_does_not_start_fallback() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (cache, capture, _) = seeded(directory.path())?;
    change_json(
        directory.path(),
        "capture_source",
        "manifest_json",
        |manifest| {
            *manifest.get_mut("items").ok_or("manifest items missing")? = serde_json::json!([{}]);
            Ok(())
        },
    )?;
    let job = Job::new("cancelled corrupt capture cache");
    job.request_cancel();
    let result = acquire_indexed_source(
        &capture,
        directory.path(),
        &AcquisitionOptions {
            cache: Some(&cache),
            job: Some(&job),
            ..AcquisitionOptions::default()
        },
    );
    assert!(result.is_err());
    assert!(job.snapshot()?.cache_fallbacks.records().is_empty());
    Ok(())
}
