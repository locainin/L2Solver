//! Cache exact per-scope default recovery results

use super::coverage::{RecoveryCaseKind, RecoveryCoverage};
use crate::{
    arguments::{RecoveryOptions, RecoveryProfile},
    input, workbench,
};
use l2_workbench::{
    evidence::{Case, CaseSnapshotLimits, CaseSnapshotUsage, EvidenceError, MAX_CASE_JSON_BYTES},
    job::{
        CacheFallbackKind, CacheStage, Counter, Job, PhaseState,
        cache::{
            Cache, CacheEntry, CacheError, CacheReadPolicy, Lease, SourceIdentity, StageKey,
            StageStatus,
        },
    },
    recovery::proposals::TRANSFORM_PROPOSAL_FORMAT_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    error::Error,
    fmt,
    fs::OpenOptions,
    io::{self, BufWriter, Read, Write},
};

// Advance when recovery eligibility, generation, cohorting, or parser constraints change
// Application semantics also belong to this stage's identity
// Capture indexing and native reconstruction keep their separate upstream versions
pub(super) const RECOVERY_STAGE_VERSION: u32 = 22;
const RECOVERY_STAGE: &str = "default_case_recovery";
const RECOVERY_ALGORITHM: &str = "l2-default-case-recovery";
const CASE_FILE: &str = "case.json";
const CASE_GRAPH_FILE: &str = "case.graph.gz";
const CASE_BLOB_PACK_FILE: &str = "case.blobs";
const CASE_SNAPSHOT_FORMAT: u32 = 1;

#[cfg(test)]
#[path = "../../tests/export/recovery_cache.rs"]
mod tests;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// Shared inputs for one per-Case recovery stage
pub(super) struct RecoveryContext<'a> {
    pub(super) cache: Option<&'a Cache>,
    pub(super) job: Option<&'a Job>,
    pub(super) options: &'a RecoveryOptions,
}

/// Cached or freshly computed coverage and user-visible recovery omissions
pub(super) struct CachedRecovery {
    pub(super) coverage: RecoveryCoverage,
    pub(super) omissions: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryMetadata {
    coverage: RecoveryCoverage,
    omissions: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_metadata_field")]
    case_storage_format: MetadataField<u32>,
    #[serde(default, deserialize_with = "deserialize_metadata_field")]
    case_snapshot_usage: MetadataField<CaseSnapshotUsage>,
}

#[derive(Default)]
enum MetadataField<T> {
    // Only absent fields identify the older JSON format; explicit null is invalid
    #[default]
    Missing,
    Null,
    Value(T),
}

fn deserialize_metadata_field<'de, D, T>(
    deserializer: D,
) -> std::result::Result<MetadataField<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
        .map(|value| value.map_or_else(|| MetadataField::Null, MetadataField::Value))
}

#[derive(Serialize)]
struct RecoveryMetadataRef<'a> {
    coverage: &'a RecoveryCoverage,
    omissions: &'a [String],
    case_storage_format: u32,
    case_snapshot_usage: &'a CaseSnapshotUsage,
}

/// Recover one flow or cohort Case, reusing only an exact matching stage result
pub(super) fn recover(
    case: &mut Case,
    kind: RecoveryCaseKind,
    scope: &Value,
    context: &RecoveryContext<'_>,
) -> Result<CachedRecovery> {
    let source_id = source_id(scope)?;
    require_case_source(case, &source_id)?;
    let key = recovery_key(kind, scope, context.options)?;
    let cache = context.cache.filter(|_| !context.options.no_cache);

    if let Some(cache) = cache {
        if !context.options.refresh {
            // Profile and memory limits are in the key, keeping partial reuse policy exact
            match cache.lookup(&key, CacheReadPolicy::AllowPartial) {
                Ok(Some(entry)) => match cached_result(&entry, &source_id, kind, context.options) {
                    Ok((cached_case, result)) => {
                        count_cache_hit(context.job)?;
                        *case = cached_case;
                        return Ok(result);
                    }
                    Err(error) if context.options.strict_cache => return Err(error),
                    Err(_) => note_cache_fallback(
                        context.job,
                        CacheFallbackKind::InvalidEntry,
                        format_args!("cached Case could not be restored"),
                    )?,
                },
                Err(error) if context.options.strict_cache => return Err(error.into()),
                Err(_) => note_cache_fallback(
                    context.job,
                    CacheFallbackKind::LookupFailed,
                    format_args!("recovery cache lookup failed"),
                )?,
                Ok(None) => {}
            }
        }
        count_cache_miss(context.job, kind)?;
    }

    let lease = match cache {
        Some(cache) => match cache.lease(&key) {
            Ok(lease) => Some(lease),
            Err(error) if context.options.strict_cache => return Err(error.into()),
            Err(_) => {
                note_cache_fallback(
                    context.job,
                    CacheFallbackKind::LeaseUnavailable,
                    format_args!("recovery cache write lease unavailable"),
                )?;
                None
            }
        },
        None => None,
    };
    let summary = workbench::recover_case_with_job(
        case,
        context.options.profile,
        context.options.memory_limit,
        context.job,
    )?;
    let mut coverage = RecoveryCoverage::default();
    coverage.record(&summary, kind)?;
    let omissions = summary
        .omissions
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let result = CachedRecovery {
        coverage,
        omissions,
    };

    if let Some(lease) = lease {
        match store_result(lease, case, &result, context.options) {
            Err(error) if context.options.strict_cache => return Err(error),
            Ok(()) => {}
            Err(error) => {
                let kind = cache_commit_fallback_kind(error.as_ref());
                note_cache_fallback(
                    context.job,
                    kind,
                    format_args!("{}", cache_commit_fallback_detail(kind)),
                )?;
            }
        }
    }
    Ok(result)
}

fn note_cache_fallback(
    job: Option<&Job>,
    kind: CacheFallbackKind,
    detail: fmt::Arguments<'_>,
) -> Result<()> {
    if let Some(job) = job {
        job.record_cache_fallback(CacheStage::CaseRecovery, kind, detail)?;
    }
    Ok(())
}

fn cache_commit_fallback_kind(error: &(dyn Error + 'static)) -> CacheFallbackKind {
    if matches!(
        error.downcast_ref::<EvidenceError>(),
        Some(EvidenceError::CaseTooLarge { .. })
    ) {
        return CacheFallbackKind::CommitCaseTooLarge;
    }
    if let Some(cache_error) = error.downcast_ref::<CacheError>() {
        return match cache_error {
            CacheError::MetadataTooLarge { .. } => CacheFallbackKind::CommitMetadataTooLarge,
            CacheError::QuotaExceeded { .. } => CacheFallbackKind::CommitQuotaExceeded,
            CacheError::Io(_) => CacheFallbackKind::CommitStorageIo,
            _ => CacheFallbackKind::CommitFailed,
        };
    }
    if error.downcast_ref::<io::Error>().is_some()
        || matches!(
            error.downcast_ref::<EvidenceError>(),
            Some(EvidenceError::WriteFailed)
        )
    {
        return CacheFallbackKind::CommitStorageIo;
    }
    CacheFallbackKind::CommitFailed
}

const fn cache_commit_fallback_detail(kind: CacheFallbackKind) -> &'static str {
    match kind {
        CacheFallbackKind::CommitCaseTooLarge => {
            "recovery Case snapshot exceeds its storage or memory limit"
        }
        CacheFallbackKind::CommitMetadataTooLarge => "recovery cache metadata exceeds its limit",
        CacheFallbackKind::CommitQuotaExceeded => "recovery cache quota exceeded",
        CacheFallbackKind::CommitStorageIo => "recovery cache storage I/O failed",
        _ => "recovery cache write failed",
    }
}

fn recovery_key(
    kind: RecoveryCaseKind,
    scope: &Value,
    options: &RecoveryOptions,
) -> Result<StageKey> {
    let source = SourceIdentity::from_sha256(
        source_id(scope)?
            .strip_prefix("sha256:")
            .ok_or("recovery scope source identity is not SHA-256")?,
    )?;
    let policy = json!({
        "native_case_version": workbench::full_source::NATIVE_CASE_VERSION,
        "transform_proposal_version": TRANSFORM_PROPOSAL_FORMAT_VERSION,
        "kind": kind_name(kind),
        "profile": profile_name(options.profile),
        "memory_limit_bytes": options.memory_limit,
        "scope": scope,
    });
    Ok(StageKey::new(
        RECOVERY_STAGE,
        RECOVERY_STAGE_VERSION,
        RECOVERY_ALGORITHM,
        &policy,
        &source,
        &[],
    )?)
}

fn cached_result(
    entry: &CacheEntry,
    expected_source_id: &str,
    kind: RecoveryCaseKind,
    options: &RecoveryOptions,
) -> Result<(Case, CachedRecovery)> {
    let metadata: RecoveryMetadata = serde_json::from_value(entry.metadata().clone())?;
    let case_storage_format = metadata.case_storage_format;
    let case_snapshot_usage = metadata.case_snapshot_usage;
    let result = CachedRecovery {
        coverage: metadata.coverage,
        omissions: metadata.omissions,
    };
    validate_cached_coverage(&result, entry.status(), kind)?;
    let case = read_cached_case(
        entry,
        case_storage_format,
        case_snapshot_usage,
        snapshot_limits(options),
    )?;
    require_case_source(&case, expected_source_id)?;
    let incomplete_case_count = match kind {
        RecoveryCaseKind::Flow => {
            result
                .coverage
                .flow_cases_with_incomplete_case_evidence_collection
        }
        RecoveryCaseKind::Cohort => {
            result
                .coverage
                .cohort_cases_with_incomplete_case_evidence_collection
        }
    };
    if incomplete_case_count != u64::from(!case.collection_complete()) {
        return Err(invalid_cache(
            "cached recovery coverage disagrees with the Case collection flag",
        ));
    }
    Ok((case, result))
}

fn validate_cached_coverage(
    result: &CachedRecovery,
    status: StageStatus,
    kind: RecoveryCaseKind,
) -> Result<()> {
    let coverage = &result.coverage;
    let (flow_cases, cohort_cases) = match kind {
        RecoveryCaseKind::Flow => (1, 0),
        RecoveryCaseKind::Cohort => (0, 1),
    };
    if coverage.flow_cases != flow_cases
        || coverage.cohort_cases != cohort_cases
        || coverage.resources.recovery_cases != 1
        || !coverage.resources.has_single_case_ranges()
        || u64::try_from(result.omissions.len())? != coverage.omissions
    {
        return Err(invalid_cache(
            "recovery coverage does not describe one matching Case",
        ));
    }
    match (status, coverage.is_complete()) {
        (StageStatus::Complete, true) | (StageStatus::Partial, false) => Ok(()),
        _ => Err(invalid_cache(
            "cached recovery status disagrees with its coverage",
        )),
    }
}

fn read_cached_case(
    entry: &CacheEntry,
    storage_format: MetadataField<u32>,
    usage: MetadataField<CaseSnapshotUsage>,
    limits: CaseSnapshotLimits,
) -> Result<Case> {
    match (storage_format, usage) {
        (MetadataField::Missing, MetadataField::Missing) => read_legacy_case(entry, limits),
        (MetadataField::Value(CASE_SNAPSHOT_FORMAT), MetadataField::Value(usage)) => {
            read_snapshot_case(entry, usage, limits)
        }
        _ => Err(invalid_cache("recovery Case storage metadata is invalid")),
    }
}

fn read_snapshot_case(
    entry: &CacheEntry,
    usage: CaseSnapshotUsage,
    limits: CaseSnapshotLimits,
) -> Result<Case> {
    let declared_decoded_bytes = usage
        .graph_decoded_bytes
        .checked_add(usage.blob_pack_bytes)
        .ok_or("snapshot decoded size overflow")?;
    if declared_decoded_bytes > limits.maximum_decoded_bytes() {
        return Err(invalid_cache(
            "cached recovery snapshot exceeds its decoded size limit",
        ));
    }
    let graph = input::regular_no_follow(&entry.directory().join(CASE_GRAPH_FILE))?;
    let blob_pack = input::regular_no_follow(&entry.directory().join(CASE_BLOB_PACK_FILE))?;
    let graph_bytes = graph.metadata()?.len();
    let blob_pack_bytes = blob_pack.metadata()?.len();
    let total_storage_bytes = graph_bytes
        .checked_add(blob_pack_bytes)
        .ok_or("snapshot package size overflow")?;
    if total_storage_bytes > limits.maximum_storage_bytes() {
        return Err(invalid_cache(
            "cached recovery snapshot exceeds its storage limit",
        ));
    }
    let (case, actual_usage) = Case::from_snapshot(graph, blob_pack, limits)?;
    if actual_usage != usage {
        return Err(invalid_cache(
            "snapshot usage metadata does not match stored files",
        ));
    }
    Ok(case)
}

fn read_legacy_case(entry: &CacheEntry, limits: CaseSnapshotLimits) -> Result<Case> {
    let path = entry.directory().join(CASE_FILE);
    let file = input::regular_no_follow(&path)?;
    let maximum = u64::try_from(MAX_CASE_JSON_BYTES)?
        .min(limits.maximum_decoded_bytes())
        .min(limits.maximum_storage_bytes());
    let file_bytes = file.metadata()?.len();
    if file_bytes > maximum {
        return Err(invalid_cache(
            "cached legacy recovery Case exceeds its size limit",
        ));
    }
    let probe = maximum
        .checked_add(1)
        .ok_or("Case JSON size limit overflow")?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(usize::try_from(file_bytes)?)?;
    file.take(probe).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len())? > maximum {
        return Err(invalid_cache(
            "cached legacy recovery Case exceeds its size limit",
        ));
    }
    Ok(Case::from_json(&bytes)?)
}

fn store_result(
    lease: Lease,
    case: &Case,
    result: &CachedRecovery,
    options: &RecoveryOptions,
) -> Result<()> {
    let usage = write_case(&lease, case, options)?;
    let metadata = serde_json::to_value(RecoveryMetadataRef {
        coverage: &result.coverage,
        omissions: &result.omissions,
        case_storage_format: CASE_SNAPSHOT_FORMAT,
        case_snapshot_usage: &usage,
    })?;
    let status = if result.coverage.is_complete() {
        StageStatus::Complete
    } else {
        StageStatus::Partial
    };
    drop(lease.commit(status, metadata)?);
    Ok(())
}

fn write_case(lease: &Lease, case: &Case, options: &RecoveryOptions) -> Result<CaseSnapshotUsage> {
    let graph_file = create_case_snapshot_file(lease, CASE_GRAPH_FILE)?;
    let blob_pack_file = create_case_snapshot_file(lease, CASE_BLOB_PACK_FILE)?;
    let mut graph = BufWriter::new(graph_file);
    let mut blob_pack = BufWriter::new(blob_pack_file);
    let usage = case.write_snapshot(&mut graph, &mut blob_pack, snapshot_limits(options))?;
    sync_snapshot_file(graph)?;
    sync_snapshot_file(blob_pack)?;
    Ok(usage)
}

fn create_case_snapshot_file(lease: &Lease, filename: &str) -> Result<std::fs::File> {
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(lease.directory().join(filename))?)
}

fn sync_snapshot_file(mut writer: BufWriter<std::fs::File>) -> Result<()> {
    writer.flush()?;
    writer
        .into_inner()
        .map_err(io::IntoInnerError::into_error)?
        .sync_all()?;
    Ok(())
}

const fn snapshot_limits(options: &RecoveryOptions) -> CaseSnapshotLimits {
    CaseSnapshotLimits::new(options.cache_max_bytes, options.memory_limit)
}

fn count_cache_hit(job: Option<&Job>) -> Result<()> {
    let Some(job) = job else {
        return Ok(());
    };
    job.increment(Counter::CacheHits, 1)?;
    set_current_for(job, "reused cached Case recovery")?;
    Ok(())
}

fn count_cache_miss(job: Option<&Job>, kind: RecoveryCaseKind) -> Result<()> {
    if let Some(job) = job {
        job.increment(Counter::CacheMisses, 1)?;
        set_current_for(job, &format!("recovering {} Case", kind_name(kind)))?;
    }
    Ok(())
}

fn set_current_for(job: &Job, message: &str) -> Result<()> {
    let snapshot = job.snapshot()?;
    let Some(phase) = snapshot.current_phase else {
        return Ok(());
    };
    if snapshot
        .phase(phase)
        .is_some_and(|progress| progress.state == PhaseState::InProgress)
    {
        job.set_current(phase, message)?;
    }
    Ok(())
}

fn source_id(scope: &Value) -> Result<String> {
    scope
        .get("source_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "recovery scope is missing its strong source_id".into())
}

fn require_case_source(case: &Case, expected_source_id: &str) -> Result<()> {
    if case
        .sources()
        .iter()
        .any(|source| source.id == expected_source_id)
    {
        return Ok(());
    }
    Err(invalid_cache(
        "recovery Case does not contain the scoped strong source identity",
    ))
}

const fn profile_name(profile: RecoveryProfile) -> &'static str {
    match profile {
        RecoveryProfile::Fast => "fast",
        RecoveryProfile::Normal => "normal",
        RecoveryProfile::Deep => "deep",
    }
}

const fn kind_name(kind: RecoveryCaseKind) -> &'static str {
    match kind {
        RecoveryCaseKind::Flow => "flow",
        RecoveryCaseKind::Cohort => "cohort",
    }
}

fn invalid_cache(message: &'static str) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidData, message).into()
}
