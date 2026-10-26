//! Cache exact per-scope default recovery results

use super::coverage::{RecoveryCaseKind, RecoveryCoverage};
use crate::{
    arguments::{RecoveryOptions, RecoveryProfile},
    input, workbench,
};
use l2_workbench::{
    evidence::{Case, MAX_CASE_JSON_BYTES},
    job::{
        CacheFallbackKind, CacheStage, Counter, Job, PhaseState,
        cache::{Cache, CacheEntry, CacheReadPolicy, Lease, SourceIdentity, StageKey, StageStatus},
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
pub(super) const RECOVERY_STAGE_VERSION: u32 = 17;
const RECOVERY_STAGE: &str = "default_case_recovery";
const RECOVERY_ALGORITHM: &str = "l2-default-case-recovery";
const CASE_FILE: &str = "case.json";

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
}

#[derive(Serialize)]
struct RecoveryMetadataRef<'a> {
    coverage: &'a RecoveryCoverage,
    omissions: &'a [String],
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
                Ok(Some(entry)) => match cached_result(&entry, &source_id, kind) {
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
        match store_result(lease, case, &result) {
            Err(error) if context.options.strict_cache => return Err(error),
            Ok(()) => {}
            Err(_) => note_cache_fallback(
                context.job,
                CacheFallbackKind::CommitFailed,
                format_args!("recovery cache write failed"),
            )?,
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
) -> Result<(Case, CachedRecovery)> {
    let metadata: RecoveryMetadata = serde_json::from_value(entry.metadata().clone())?;
    let result = CachedRecovery {
        coverage: metadata.coverage,
        omissions: metadata.omissions,
    };
    validate_cached_coverage(&result, entry.status(), kind)?;
    let case = read_cached_case(entry)?;
    require_case_source(&case, expected_source_id)?;
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

fn read_cached_case(entry: &CacheEntry) -> Result<Case> {
    let path = entry.directory().join(CASE_FILE);
    let file = input::regular_no_follow(&path)?;
    let maximum = u64::try_from(MAX_CASE_JSON_BYTES)?;
    if file.metadata()?.len() > maximum {
        return Err(invalid_cache(
            "cached recovery Case exceeds the evidence size limit",
        ));
    }
    let probe = maximum
        .checked_add(1)
        .ok_or("Case JSON size limit overflow")?;
    let mut bytes = Vec::new();
    file.take(probe).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_CASE_JSON_BYTES {
        return Err(invalid_cache(
            "cached recovery Case exceeds the evidence size limit",
        ));
    }
    Ok(Case::from_json(&bytes)?)
}

fn store_result(lease: Lease, case: &Case, result: &CachedRecovery) -> Result<()> {
    write_case(&lease, case)?;
    let metadata = serde_json::to_value(RecoveryMetadataRef {
        coverage: &result.coverage,
        omissions: &result.omissions,
    })?;
    let status = if result.coverage.is_complete() {
        StageStatus::Complete
    } else {
        StageStatus::Partial
    };
    drop(lease.commit(status, metadata)?);
    Ok(())
}

fn write_case(lease: &Lease, case: &Case) -> Result<()> {
    let path = lease.directory().join(CASE_FILE);
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    // Stream through a size limit instead of allocating a second full Case representation
    let mut writer = LimitedWriter {
        inner: BufWriter::new(file),
        remaining: MAX_CASE_JSON_BYTES,
    };
    case.write_json(&mut writer)?;
    writer.flush()?;
    writer
        .inner
        .into_inner()
        .map_err(io::IntoInnerError::into_error)?
        .sync_all()?;
    Ok(())
}

struct LimitedWriter<W> {
    inner: W,
    remaining: usize,
}

impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "case JSON exceeds the evidence size limit",
            ));
        }
        let length = bytes.len().min(self.remaining);
        let written = self.inner.write(bytes.split_at(length).0)?;
        self.remaining -= written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
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
