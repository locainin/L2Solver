//! Content-addressed capture indexes and native analysis cases

mod cases;

pub(super) use cases::investigate_flow;

use super::{IngestReceipt, input, invalid, label, validate_indexed_receipt};
use l2_workbench::{
    job::{
        CacheFallbackKind, CacheStage, Counter, Job, Phase, PhaseOutcome,
        cache::{
            Cache, CacheEntry, CacheError, CacheReadPolicy, Lease, SourceFingerprint,
            SourceIdentity, StageKey, StageStatus, Value,
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
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

const SOURCE_ALIAS_STAGE: &str = "capture_source";
const SOURCE_ALIAS_ALGORITHM: &str = "pcap-source-alias-v1";
const SOURCE_INDEX_STAGE: &str = "capture_index";
const SOURCE_INDEX_ALGORITHM: &str = "pcap-index-v1";
const INDEX_DIRECTORY: &str = "index";
const CACHE_CONTENTION_WAIT: Duration = Duration::from_secs(5);
const CACHE_CONTENTION_POLL: Duration = Duration::from_millis(20);
const CACHE_BUSY_FALLBACK_MESSAGE: &str = "Cache is busy; building a temporary index";

pub const NATIVE_CASE_VERSION: u32 = 2;

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
    Uncached { _lease: Lease },
}

/// Optional cache and progress services used for indexed flow analysis
#[derive(Clone, Copy, Default)]
pub struct IndexedAnalysisContext<'a> {
    /// Persistent cache used for native evidence cases
    pub cache: Option<&'a Cache>,
    /// Cumulative progress and cache counters
    pub job: Option<&'a Job>,
}

struct CachedIndexWork<'a> {
    cache: &'a Cache,
    path: &'a Path,
    fingerprint: SourceFingerprint,
    job: Option<&'a Job>,
    deadline: Instant,
    alias_lease: Lease,
    index_directory: PathBuf,
    expected_source_id: Option<String>,
    cache_miss_counted: bool,
}

enum WaitedCacheLookup<T> {
    Ready(T),
    Busy,
}

enum AliasDecision {
    Reused(Box<IndexedSource>),
    Build {
        entry: Option<CacheEntry>,
        source_id: Option<String>,
        cache_miss_counted: bool,
    },
    Busy,
}

enum ContentIndexLookup {
    Cached(Box<CacheEntry>, IngestReceipt),
    Missing,
    Busy,
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
        return acquire_temporary_index(
            path,
            temporary_parent,
            fingerprint.as_ref(),
            options.job,
            None,
        );
    }

    let fingerprint = fingerprint
        .ok_or_else(|| invalid("standard input cannot use the persistent capture index cache"))?;
    acquire_cached_index(path, temporary_parent, &fingerprint, options)
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
    progress_message: Option<&str>,
) -> Result<IndexedSource> {
    let temporary = tempfile::tempdir_in(temporary_parent)?;
    let temporary_path = temporary.path().to_path_buf();
    let indexed_path = temporary_path.clone();
    ingest_capture_then(
        path,
        &temporary_path,
        fingerprint,
        job,
        progress_message,
        move |store, receipt| {
            drop(store);
            let store = Store::open(&indexed_path, Options::default())?;
            validate_indexed_receipt(&store, &receipt)?;
            check_fingerprint_unchanged(path, fingerprint)?;
            Ok(IndexedSource {
                store,
                receipt,
                _storage: IndexedSourceStorage::Temporary {
                    _directory: temporary,
                },
            })
        },
    )
}

fn acquire_cached_index(
    path: &Path,
    temporary_parent: &Path,
    fingerprint: &SourceFingerprint,
    options: &AcquisitionOptions<'_>,
) -> Result<IndexedSource> {
    let cache = options
        .cache
        .ok_or_else(|| invalid("capture cache is missing"))?;
    let alias_key = source_alias_key(fingerprint)?;
    let deadline = Instant::now() + CACHE_CONTENTION_WAIT;
    loop {
        let (entry, source_id, cache_miss_counted) = match inspect_cached_alias(
            path,
            fingerprint,
            options.strict_cache,
            cache,
            &alias_key,
            options.job,
            deadline,
        )? {
            AliasDecision::Reused(indexed) => return Ok(*indexed),
            AliasDecision::Busy => {
                return temporary_cache_fallback(path, temporary_parent, fingerprint, options.job);
            }
            AliasDecision::Build {
                entry,
                source_id,
                cache_miss_counted,
            } => (entry, source_id, cache_miss_counted),
        };

        // Hold the alias lease so another process cannot publish a stale sample mapping
        drop(entry);
        let alias_lease = match cache.lease(&alias_key) {
            Ok(lease) => lease,
            Err(CacheError::LockBusy) => {
                if wait_for_cache_key(cache, &alias_key, options.job, deadline, true)? {
                    continue;
                }
                if !cache_miss_counted {
                    return temporary_cache_fallback(
                        path,
                        temporary_parent,
                        fingerprint,
                        options.job,
                    );
                }
                record_capture_contention_fallback(options.job)?;
                return acquire_temporary_index(
                    path,
                    temporary_parent,
                    Some(fingerprint),
                    options.job,
                    Some(CACHE_BUSY_FALLBACK_MESSAGE),
                );
            }
            Err(error) => return Err(error.into()),
        };
        let index_directory = alias_lease.directory().join(INDEX_DIRECTORY);
        fs::create_dir(&index_directory)?;
        let work = CachedIndexWork {
            cache,
            path,
            fingerprint: fingerprint.clone(),
            job: options.job,
            deadline,
            alias_lease,
            index_directory: index_directory.clone(),
            expected_source_id: source_id,
            cache_miss_counted,
        };

        return ingest_capture_then(
            path,
            &index_directory,
            Some(fingerprint),
            options.job,
            None,
            move |store, receipt| publish_ingested_index(store, receipt, work),
        );
    }
}

fn inspect_cached_alias(
    path: &Path,
    fingerprint: &SourceFingerprint,
    strict_cache: bool,
    cache: &Cache,
    alias_key: &StageKey,
    job: Option<&Job>,
    deadline: Instant,
) -> Result<AliasDecision> {
    let entry = match lookup_alias_after_wait(cache, alias_key, job, deadline)? {
        WaitedCacheLookup::Ready(entry) => entry,
        WaitedCacheLookup::Busy => return Ok(AliasDecision::Busy),
    };
    let source_id = trusted_source_id(path, fingerprint, strict_cache, entry.as_ref(), job)?;
    let Some(source_id) = source_id else {
        return Ok(AliasDecision::Build {
            entry,
            source_id: None,
            cache_miss_counted: false,
        });
    };

    let key = source_index_key(&source_id)?;
    match lookup_index_after_wait(cache, &key, &source_id, job, deadline)? {
        WaitedCacheLookup::Ready(Some((cached_entry, receipt))) => {
            drop(entry);
            let indexed = indexed_from_cache(cached_entry, receipt)?;
            check_fingerprint_unchanged(path, Some(fingerprint))?;
            ensure_source_alias(
                cache,
                alias_key,
                fingerprint,
                &indexed.receipt,
                job,
                deadline,
            )?;
            count_cache_hit(job)?;
            skip_ingestion(job)?;
            Ok(AliasDecision::Reused(Box::new(indexed)))
        }
        WaitedCacheLookup::Ready(None) => {
            count_cache_miss(job)?;
            Ok(AliasDecision::Build {
                entry,
                source_id: Some(source_id),
                cache_miss_counted: true,
            })
        }
        WaitedCacheLookup::Busy => {
            drop(entry);
            Ok(AliasDecision::Busy)
        }
    }
}

fn temporary_cache_fallback(
    path: &Path,
    temporary_parent: &Path,
    fingerprint: &SourceFingerprint,
    job: Option<&Job>,
) -> Result<IndexedSource> {
    record_capture_contention_fallback(job)?;
    count_cache_miss(job)?;
    acquire_temporary_index(
        path,
        temporary_parent,
        Some(fingerprint),
        job,
        Some(CACHE_BUSY_FALLBACK_MESSAGE),
    )
}

fn record_capture_contention_fallback(job: Option<&Job>) -> Result<()> {
    if let Some(job) = job {
        job.record_cache_fallback(
            CacheStage::CaptureIndex,
            CacheFallbackKind::ContentionFallback,
            format_args!("{CACHE_BUSY_FALLBACK_MESSAGE}"),
        )?;
    }
    Ok(())
}

fn ingest_capture_then<T>(
    path: &Path,
    directory: &Path,
    fingerprint: Option<&SourceFingerprint>,
    job: Option<&Job>,
    progress_message: Option<&str>,
    complete: impl FnOnce(Store, IngestReceipt) -> Result<T>,
) -> Result<T> {
    if let Some(job) = job {
        job.start(Phase::Ingestion, fingerprint.map(|value| value.size_bytes))?;
        if let Some(message) = progress_message {
            job.set_current(Phase::Ingestion, message)?;
        }
    }

    let ingestion = (|| {
        let mut store = Store::create(directory, Options::default())?;
        let input = input::capture(path)?;
        let reader = IngestionReader { input, job };
        let receipt = store
            .ingest(label(path, "capture"), reader)
            .map_err(|error| input::boxed_capture_error(path, error))?;
        if let Some(job) = job {
            job.increment(Counter::Packets, receipt.packets)?;
            job.check_cancelled()?;
        }
        complete(store, receipt)
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

fn publish_ingested_index(
    store: Store,
    receipt: IngestReceipt,
    work: CachedIndexWork<'_>,
) -> Result<IndexedSource> {
    check_fingerprint_unchanged(work.path, Some(&work.fingerprint))?;
    // Closing SQLite releases all handles before the index directory moves to its content key
    drop(store);

    if work
        .expected_source_id
        .as_ref()
        .is_some_and(|source_id| source_id != &receipt.source_id)
    {
        return Err(CacheError::SourceChanged.into());
    }

    let source_key = source_index_key(&receipt.source_id)?;
    loop {
        match lookup_content_index(
            work.cache,
            &source_key,
            &receipt.source_id,
            work.job,
            work.deadline,
        )? {
            ContentIndexLookup::Cached(entry, cached_receipt) => {
                count_cache_hit(work.job)?;
                return open_cached_winner(*entry, cached_receipt, work);
            }
            ContentIndexLookup::Missing => {}
            ContentIndexLookup::Busy => return use_uncached_index(receipt, work),
        }

        match work.cache.lease(&source_key) {
            Ok(store_lease) => return commit_content_index(store_lease, &receipt, work),
            Err(CacheError::LockBusy) => {
                if wait_for_cache_key(work.cache, &source_key, work.job, work.deadline, false)? {
                    continue;
                }
                return use_uncached_index(receipt, work);
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn lookup_content_index(
    cache: &Cache,
    key: &StageKey,
    source_id: &str,
    job: Option<&Job>,
    deadline: Instant,
) -> Result<ContentIndexLookup> {
    loop {
        match cached_index(cache, key, source_id) {
            Ok(Some((entry, receipt))) => {
                return Ok(ContentIndexLookup::Cached(Box::new(entry), receipt));
            }
            Ok(None) => return Ok(ContentIndexLookup::Missing),
            Err(error) if is_cache_lock_busy(error.as_ref()) => {
                if wait_for_cache_key(cache, key, job, deadline, false)? {
                    continue;
                }
                return Ok(ContentIndexLookup::Busy);
            }
            Err(error) => return Err(error),
        }
    }
}

fn open_cached_winner(
    entry: CacheEntry,
    receipt: IngestReceipt,
    work: CachedIndexWork<'_>,
) -> Result<IndexedSource> {
    let alias_entry = work.alias_lease.commit(
        StageStatus::Complete,
        alias_metadata_value(&work.fingerprint, &receipt)?,
    )?;
    drop(alias_entry);
    let indexed = indexed_from_cache(entry, receipt)?;
    check_fingerprint_unchanged(work.path, Some(&work.fingerprint))?;
    Ok(indexed)
}

fn commit_content_index(
    lease: Lease,
    receipt: &IngestReceipt,
    work: CachedIndexWork<'_>,
) -> Result<IndexedSource> {
    if !work.cache_miss_counted {
        count_cache_miss(work.job)?;
    }
    let destination = lease.directory().join(INDEX_DIRECTORY);
    fs::rename(&work.index_directory, &destination)?;
    let entry = lease.commit(StageStatus::Complete, json!({"receipt": receipt}))?;
    let alias_entry = work.alias_lease.commit(
        StageStatus::Complete,
        alias_metadata_value(&work.fingerprint, receipt)?,
    )?;
    drop(alias_entry);
    let receipt = receipt_from_index_entry(&entry, &receipt.source_id)?;
    let indexed = indexed_from_cache(entry, receipt)?;
    check_fingerprint_unchanged(work.path, Some(&work.fingerprint))?;
    Ok(indexed)
}

fn use_uncached_index(receipt: IngestReceipt, work: CachedIndexWork<'_>) -> Result<IndexedSource> {
    if !work.cache_miss_counted {
        count_cache_miss(work.job)?;
    }
    indexed_from_uncached_lease(
        &work.index_directory,
        receipt,
        work.alias_lease,
        work.path,
        &work.fingerprint,
        work.job,
    )
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

fn lookup_alias_after_wait(
    cache: &Cache,
    key: &StageKey,
    job: Option<&Job>,
    deadline: Instant,
) -> Result<WaitedCacheLookup<Option<CacheEntry>>> {
    loop {
        match cache.lookup(key, CacheReadPolicy::CompleteOnly) {
            Ok(entry) => return Ok(WaitedCacheLookup::Ready(entry)),
            Err(CacheError::LockBusy) => {
                if wait_for_cache_key(cache, key, job, deadline, true)? {
                    continue;
                }
                return Ok(WaitedCacheLookup::Busy);
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn lookup_index_after_wait(
    cache: &Cache,
    key: &StageKey,
    source_id: &str,
    job: Option<&Job>,
    deadline: Instant,
) -> Result<WaitedCacheLookup<Option<(CacheEntry, IngestReceipt)>>> {
    loop {
        match cached_index(cache, key, source_id) {
            Ok(index) => return Ok(WaitedCacheLookup::Ready(index)),
            Err(error) if is_cache_lock_busy(error.as_ref()) => {
                if wait_for_cache_key(cache, key, job, deadline, true)? {
                    continue;
                }
                return Ok(WaitedCacheLookup::Busy);
            }
            Err(error) => return Err(error),
        }
    }
}

fn trusted_source_id(
    path: &Path,
    fingerprint: &SourceFingerprint,
    strict_cache: bool,
    alias_entry: Option<&CacheEntry>,
    job: Option<&Job>,
) -> Result<Option<String>> {
    let alias_metadata = match alias_entry {
        Some(entry) => {
            if let Ok(metadata) = decode_alias_metadata(entry.metadata()) {
                Some(metadata)
            } else {
                if let Some(job) = job {
                    job.record_cache_fallback(
                        CacheStage::CaptureIndex,
                        CacheFallbackKind::InvalidEntry,
                        format_args!("capture source alias metadata was rejected"),
                    )?;
                }
                None
            }
        }
        None => None,
    };
    let alias_is_current = alias_metadata
        .as_ref()
        .is_some_and(|metadata| metadata.fingerprint == *fingerprint);

    // Exact metadata can reuse the digest unless the caller requested strict verification
    if strict_cache || (alias_metadata.is_some() && !alias_is_current) {
        let identity = SourceIdentity::sha256_file(path)?;
        check_fingerprint_unchanged(path, Some(fingerprint))?;
        return Ok(Some(source_id_from_identity(&identity)?));
    }
    Ok(alias_metadata
        .filter(|_| alias_is_current)
        .map(|metadata| metadata.receipt.source_id))
}

fn is_cache_lock_busy(error: &(dyn Error + 'static)) -> bool {
    error
        .downcast_ref::<CacheError>()
        .is_some_and(|cache_error| matches!(cache_error, CacheError::LockBusy))
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

fn indexed_from_uncached_lease(
    index_directory: &Path,
    receipt: IngestReceipt,
    lease: Lease,
    path: &Path,
    fingerprint: &SourceFingerprint,
    job: Option<&Job>,
) -> Result<IndexedSource> {
    if let Some(job) = job {
        record_capture_contention_fallback(Some(job))?;
        job.set_current(Phase::Ingestion, CACHE_BUSY_FALLBACK_MESSAGE)?;
    }
    let store = Store::open(index_directory, Options::default())?;
    validate_indexed_receipt(&store, &receipt)?;
    check_fingerprint_unchanged(path, Some(fingerprint))?;
    Ok(IndexedSource {
        store,
        receipt,
        _storage: IndexedSourceStorage::Uncached { _lease: lease },
    })
}

fn wait_for_cache_key(
    cache: &Cache,
    key: &StageKey,
    job: Option<&Job>,
    deadline: Instant,
    ingestion_pending: bool,
) -> Result<bool> {
    loop {
        if let Some(job) = job
            && job.is_cancelled()
        {
            if ingestion_pending {
                job.start(Phase::Ingestion, None)?;
                job.finish(Phase::Ingestion, PhaseOutcome::Cancelled)?;
            }
            return Err(l2_workbench::job::JobError::Cancelled.into());
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        thread::sleep(remaining.min(CACHE_CONTENTION_POLL));
        match cache.lookup(key, CacheReadPolicy::CompleteOnly) {
            Ok(entry) => {
                drop(entry);
                return Ok(true);
            }
            Err(CacheError::LockBusy) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn ensure_source_alias(
    cache: &Cache,
    alias_key: &StageKey,
    fingerprint: &SourceFingerprint,
    receipt: &IngestReceipt,
    job: Option<&Job>,
    deadline: Instant,
) -> Result<()> {
    let value = alias_metadata_value(fingerprint, receipt)?;
    loop {
        match cache.lookup(alias_key, CacheReadPolicy::CompleteOnly) {
            Ok(Some(entry)) if entry.metadata() == &value => return Ok(()),
            Ok(entry) => drop(entry),
            Err(CacheError::LockBusy) => {
                if !wait_for_cache_key(cache, alias_key, job, deadline, true)? {
                    return Ok(());
                }
                continue;
            }
            Err(error) => return Err(error.into()),
        }

        match cache.lease(alias_key) {
            Ok(lease) => {
                drop(lease.commit(StageStatus::Complete, value)?);
                return Ok(());
            }
            Err(CacheError::LockBusy) => {
                if !wait_for_cache_key(cache, alias_key, job, deadline, true)? {
                    return Ok(());
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
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
