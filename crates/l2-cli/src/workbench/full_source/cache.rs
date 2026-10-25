//! Content-addressed capture indexes and native analysis cases

mod cases;

pub(super) use cases::investigate_flow;

use super::{IngestReceipt, input, invalid, label, validate_indexed_receipt};
use l2_workbench::{
    job::{
        Counter, Job, Phase, PhaseOutcome,
        cache::{
            Cache, CacheEntry, CacheError, CacheReadPolicy, SourceFingerprint, SourceIdentity,
            StageKey, StageStatus, Value,
        },
    },
    store::{Options, SCHEMA_VERSION, Store},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    error::Error,
    fs,
    io::{self, Read},
    path::Path,
};

const SOURCE_ALIAS_STAGE: &str = "capture_source";
const SOURCE_ALIAS_ALGORITHM: &str = "pcap-source-alias-v1";
const SOURCE_INDEX_STAGE: &str = "capture_index";
const SOURCE_INDEX_ALGORITHM: &str = "pcap-index-v1";
const INDEX_DIRECTORY: &str = "index";

pub const NATIVE_CASE_VERSION: u32 = 1;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// Optional shared services used while acquiring an indexed capture
#[derive(Clone, Default)]
pub struct AcquisitionOptions<'a> {
    /// Persistent cache used for reusable capture indexes
    pub cache: Option<&'a Cache>,
    /// Progress and cooperative cancellation state for capture ingestion
    pub job: Option<&'a Job>,
    /// Fingerprint sampled by a caller before acquisition began
    pub fingerprint: Option<SourceFingerprint>,
    /// Require a whole-file digest before trusting a cached source alias
    pub strict_cache: bool,
}

/// A disk index and the receipt that identifies its source
///
/// The backing directory is held after the store so the read-only store closes before its
/// temporary directory or cache pin is released
pub struct IndexedSource {
    /// Read-only disk index for the capture source
    pub store: Store,
    /// Source identity and collection totals recorded during ingestion
    pub receipt: IngestReceipt,
    _storage: IndexedSourceStorage,
}

enum IndexedSourceStorage {
    Temporary { _directory: tempfile::TempDir },
    Cached { _entry: CacheEntry },
}

/// Optional cache and progress services used for indexed flow analysis
#[derive(Clone, Copy, Default)]
pub struct IndexedAnalysisContext<'a> {
    /// Persistent cache used for native evidence cases
    pub cache: Option<&'a Cache>,
    /// Cumulative progress and cache counters
    pub job: Option<&'a Job>,
}

/// Index a capture or reopen its complete content-addressed disk index
///
/// Cached indexes are keyed by the source SHA-256 digest. A fast metadata and sample alias avoids
/// rereading unchanged sources, while moved or strict-checked sources use a full digest before
/// reuse. New index contents are built inside a cache lease and committed only after ingestion
/// has finished and the open store has been closed
///
/// # Errors
/// Returns capture, filesystem, cache, source-change, or progress errors
pub fn acquire_indexed_source(
    path: &Path,
    temporary_parent: &Path,
    options: &AcquisitionOptions<'_>,
) -> Result<IndexedSource> {
    let fingerprint = current_fingerprint(path, options)?;
    if options.cache.is_none() {
        return acquire_temporary_index(path, temporary_parent, fingerprint.as_ref(), options.job);
    }

    let fingerprint = fingerprint
        .ok_or_else(|| invalid("standard input cannot use the persistent capture index cache"))?;
    acquire_cached_index(path, &fingerprint, options)
}

fn current_fingerprint(
    path: &Path,
    options: &AcquisitionOptions<'_>,
) -> Result<Option<SourceFingerprint>> {
    if path == Path::new("-") {
        if options.fingerprint.is_some() {
            return Err(invalid("standard input cannot use a file fingerprint"));
        }
        return Ok(None);
    }

    let actual = SourceFingerprint::fast(path)?;
    // A caller-provided preflight must still describe the file before cache selection begins
    if options
        .fingerprint
        .as_ref()
        .is_some_and(|expected| expected != &actual)
    {
        return Err(CacheError::SourceChanged.into());
    }
    Ok(Some(actual))
}

fn check_fingerprint_unchanged(path: &Path, expected: Option<&SourceFingerprint>) -> Result<()> {
    if let Some(expected) = expected {
        let actual = SourceFingerprint::fast(path)?;
        if &actual != expected {
            return Err(CacheError::SourceChanged.into());
        }
    }
    Ok(())
}

fn acquire_temporary_index(
    path: &Path,
    temporary_parent: &Path,
    fingerprint: Option<&SourceFingerprint>,
    job: Option<&Job>,
) -> Result<IndexedSource> {
    let temporary = tempfile::tempdir_in(temporary_parent)?;
    let (store, receipt) = ingest_capture(path, temporary.path(), fingerprint, job)?;
    drop(store);
    let store = Store::open(temporary.path(), Options::default())?;
    validate_indexed_receipt(&store, &receipt)?;
    check_fingerprint_unchanged(path, fingerprint)?;
    Ok(IndexedSource {
        store,
        receipt,
        _storage: IndexedSourceStorage::Temporary {
            _directory: temporary,
        },
    })
}

fn acquire_cached_index(
    path: &Path,
    fingerprint: &SourceFingerprint,
    options: &AcquisitionOptions<'_>,
) -> Result<IndexedSource> {
    let cache = options
        .cache
        .ok_or_else(|| invalid("capture cache is missing"))?;
    let alias_key = source_alias_key(fingerprint)?;
    let alias_entry = cache.lookup(&alias_key, CacheReadPolicy::CompleteOnly)?;
    let alias_metadata = alias_entry
        .as_ref()
        .and_then(|entry| decode_alias_metadata(entry.metadata()).ok());
    let alias_is_current = alias_metadata
        .as_ref()
        .is_some_and(|metadata| metadata.fingerprint == *fingerprint);

    // An exact fingerprint allows reuse of the saved digest without reading the full source
    let known_source_id = if options.strict_cache || (alias_metadata.is_some() && !alias_is_current)
    {
        let identity = SourceIdentity::sha256_file(path)?;
        check_fingerprint_unchanged(path, Some(fingerprint))?;
        Some(source_id_from_identity(&identity)?)
    } else if alias_is_current {
        alias_metadata
            .as_ref()
            .map(|metadata| metadata.receipt.source_id.clone())
    } else {
        None
    };

    if let Some(source_id) = &known_source_id {
        let key = source_index_key(source_id)?;
        if let Some(entry) = cached_index(cache, &key, source_id)? {
            drop(alias_entry);
            let indexed = indexed_from_cache(entry.0, entry.1)?;
            check_fingerprint_unchanged(path, Some(fingerprint))?;
            ensure_source_alias(cache, &alias_key, fingerprint, &indexed.receipt)?;
            count_cache_hit(options.job)?;
            skip_ingestion(options.job)?;
            return Ok(indexed);
        }
        count_cache_miss(options.job)?;
    }

    // Hold the fast alias lease while ingesting so temporary index data stays on the cache
    // filesystem and competing processes cannot publish a stale alias for this sample
    drop(alias_entry);
    let alias_lease = cache.lease(&alias_key)?;
    let index_directory = alias_lease.directory().join(INDEX_DIRECTORY);
    fs::create_dir(&index_directory)?;
    let (store, receipt) = ingest_capture(path, &index_directory, Some(fingerprint), options.job)?;
    check_fingerprint_unchanged(path, Some(fingerprint))?;
    // Closing SQLite releases all handles before the index directory moves to its content key
    drop(store);

    if known_source_id
        .as_ref()
        .is_some_and(|source_id| source_id != &receipt.source_id)
    {
        return Err(CacheError::SourceChanged.into());
    }

    let source_key = source_index_key(&receipt.source_id)?;
    let cached_entry = cached_index(cache, &source_key, &receipt.source_id)?;
    if let Some((entry, cached_receipt)) = cached_entry {
        count_cache_hit(options.job)?;
        drop(alias_lease);
        let indexed = indexed_from_cache(entry, cached_receipt)?;
        check_fingerprint_unchanged(path, Some(fingerprint))?;
        ensure_source_alias(cache, &alias_key, fingerprint, &indexed.receipt)?;
        return Ok(indexed);
    }
    if known_source_id.is_none() {
        count_cache_miss(options.job)?;
    }

    let store_lease = cache.lease(&source_key)?;
    let destination = store_lease.directory().join(INDEX_DIRECTORY);
    fs::rename(&index_directory, &destination)?;
    let entry = store_lease.commit(StageStatus::Complete, json!({"receipt": receipt}))?;
    let alias_entry = alias_lease.commit(
        StageStatus::Complete,
        alias_metadata_value(fingerprint, &receipt)?,
    )?;
    drop(alias_entry);
    let receipt = receipt_from_index_entry(&entry, &receipt.source_id)?;
    let indexed = indexed_from_cache(entry, receipt)?;
    check_fingerprint_unchanged(path, Some(fingerprint))?;
    Ok(indexed)
}

fn ingest_capture(
    path: &Path,
    directory: &Path,
    fingerprint: Option<&SourceFingerprint>,
    job: Option<&Job>,
) -> Result<(Store, IngestReceipt)> {
    if let Some(job) = job {
        job.start(Phase::Ingestion, fingerprint.map(|value| value.size_bytes))?;
    }

    let ingestion = (|| {
        let mut store = Store::create(directory, Options::default())?;
        let input = input::capture(path)?;
        let reader = IngestionReader { input, job };
        let receipt = store
            .ingest(label(path, "capture"), reader)
            .map_err(|error| input::boxed_capture_error(path, error))?;
        if let Some(job) = job {
            job.check_cancelled()?;
        }
        Ok((store, receipt))
    })();

    if let Some(job) = job {
        let outcome = match &ingestion {
            Ok(_) => PhaseOutcome::Completed,
            Err(_) if job.is_cancelled() => PhaseOutcome::Cancelled,
            Err(_) => PhaseOutcome::Failed,
        };
        job.finish(Phase::Ingestion, outcome)?;
    }
    ingestion
}

struct IngestionReader<'a, R> {
    input: R,
    job: Option<&'a Job>,
}

impl<R: Read> Read for IngestionReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        // Check cancellation before the capture reader consumes the next buffer
        if let Some(job) = self.job {
            job.check_cancelled().map_err(io::Error::other)?;
        }
        let count = self.input.read(buffer)?;
        // Keep the byte counter aligned with the source bytes read by Store::ingest
        if count != 0
            && let Some(job) = self.job
        {
            job.advance(
                Phase::Ingestion,
                u64::try_from(count).map_err(io::Error::other)?,
            )
            .map_err(io::Error::other)?;
        }
        Ok(count)
    }
}

fn source_alias_key(fingerprint: &SourceFingerprint) -> Result<StageKey> {
    // The sample hint locates candidates while the receipt retains the full fingerprint
    StageKey::new(
        SOURCE_ALIAS_STAGE,
        SCHEMA_VERSION,
        SOURCE_ALIAS_ALGORITHM,
        &json!({}),
        &SourceIdentity::Fast(fingerprint.sample_hint()),
        &[],
    )
    .map_err(Into::into)
}

fn source_index_key(source_id: &str) -> Result<StageKey> {
    let source = source_identity(source_id)?;
    StageKey::new(
        SOURCE_INDEX_STAGE,
        SCHEMA_VERSION,
        SOURCE_INDEX_ALGORITHM,
        &json!({}),
        &source,
        &[],
    )
    .map_err(Into::into)
}

pub(super) fn source_identity(source_id: &str) -> Result<SourceIdentity> {
    let digest = source_id
        .strip_prefix("sha256:")
        .ok_or_else(|| invalid("capture source identity has no SHA-256 prefix"))?;
    SourceIdentity::from_sha256(digest.to_owned()).map_err(Into::into)
}

fn source_id_from_identity(identity: &SourceIdentity) -> Result<String> {
    match identity {
        SourceIdentity::Sha256(digest) => Ok(format!("sha256:{digest}")),
        SourceIdentity::Fast(_) => Err(invalid("capture cache requires a strong source identity")),
        _ => Err(invalid(
            "capture cache source identity has an unsupported variant",
        )),
    }
}

#[derive(Deserialize, Serialize)]
struct SourceAliasMetadata {
    fingerprint: SourceFingerprint,
    receipt: IngestReceipt,
}

fn decode_alias_metadata(value: &Value) -> Result<SourceAliasMetadata> {
    serde_json::from_value(value.clone()).map_err(Into::into)
}

fn alias_metadata_value(fingerprint: &SourceFingerprint, receipt: &IngestReceipt) -> Result<Value> {
    serde_json::to_value(SourceAliasMetadata {
        fingerprint: fingerprint.clone(),
        receipt: receipt.clone(),
    })
    .map_err(Into::into)
}

fn cached_index(
    cache: &Cache,
    key: &StageKey,
    expected_source_id: &str,
) -> Result<Option<(CacheEntry, IngestReceipt)>> {
    let Some(entry) = cache.lookup(key, CacheReadPolicy::CompleteOnly)? else {
        return Ok(None);
    };
    let receipt = receipt_from_index_entry(&entry, expected_source_id)?;
    Ok(Some((entry, receipt)))
}

fn receipt_from_index_entry(entry: &CacheEntry, expected_source_id: &str) -> Result<IngestReceipt> {
    let receipt = entry
        .metadata()
        .get("receipt")
        .cloned()
        .ok_or_else(|| invalid("cached capture index is missing its receipt"))?;
    let receipt: IngestReceipt = serde_json::from_value(receipt)?;
    if receipt.source_id != expected_source_id {
        return Err(invalid(
            "cached capture index receipt has the wrong source identity",
        ));
    }
    Ok(receipt)
}

fn indexed_from_cache(entry: CacheEntry, receipt: IngestReceipt) -> Result<IndexedSource> {
    let directory = entry.directory().join(INDEX_DIRECTORY);
    let store = Store::open(&directory, Options::default())?;
    validate_indexed_receipt(&store, &receipt)?;
    Ok(IndexedSource {
        store,
        receipt,
        _storage: IndexedSourceStorage::Cached { _entry: entry },
    })
}

fn ensure_source_alias(
    cache: &Cache,
    alias_key: &StageKey,
    fingerprint: &SourceFingerprint,
    receipt: &IngestReceipt,
) -> Result<()> {
    let value = alias_metadata_value(fingerprint, receipt)?;
    if cache
        .lookup(alias_key, CacheReadPolicy::CompleteOnly)?
        .is_some_and(|entry| entry.metadata() == &value)
    {
        return Ok(());
    }

    let lease = cache.lease(alias_key)?;
    drop(lease.commit(StageStatus::Complete, value)?);
    Ok(())
}

pub(super) fn count_cache_hit(job: Option<&Job>) -> Result<()> {
    if let Some(job) = job {
        job.increment(Counter::CacheHits, 1)?;
    }
    Ok(())
}

pub(super) fn count_cache_miss(job: Option<&Job>) -> Result<()> {
    if let Some(job) = job {
        job.increment(Counter::CacheMisses, 1)?;
    }
    Ok(())
}

fn skip_ingestion(job: Option<&Job>) -> Result<()> {
    if let Some(job) = job {
        job.finish(Phase::Ingestion, PhaseOutcome::Skipped)?;
    }
    Ok(())
}
