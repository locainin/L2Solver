//! Complete native evidence cases cached by source, flow, and reconstruction limits

use super::super::invalid;
use super::{
    IndexedAnalysisContext, NATIVE_CASE_VERSION, Result, count_cache_hit, count_cache_miss,
    source_identity,
};
use l2_workbench::{
    evidence::{CaseSnapshotLimits, CaseSnapshotUsage, MAX_CASE_JSON_BYTES},
    investigation::BuildResult,
    job::{
        CacheFallbackKind, CacheStage, MemoryBudget,
        cache::{Cache, CacheEntry, CacheReadPolicy, StageKey, StageStatus},
    },
    reconstruction::Limits,
    store::Store,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

const NATIVE_CASE_STAGE: &str = "native_case";
const NATIVE_CASE_ALGORITHM: &str = "l2-native-case-v3";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeCaseMetadata {
    complete: bool,
    case_storage_format: u32,
    case_snapshot_usage: CaseSnapshotUsage,
}

/// Analyze a flow while reusing its complete native evidence case when available
pub fn investigate_flow(
    store: &Store,
    source_id: &str,
    flow_id: i64,
    limits: Limits,
    context: IndexedAnalysisContext<'_>,
) -> Result<BuildResult> {
    if let Some(job) = context.job {
        job.check_cancelled()?;
    }
    let Some(cache) = context.cache else {
        let result = store.investigate_flows(&[flow_id], limits)?;
        if let Some(job) = context.job {
            job.check_cancelled()?;
        }
        return Ok(result);
    };

    // Source digest, flow identity, limits, and algorithm version define a reusable case
    let source = source_identity(source_id)?;
    let policy = json!({
        "flow_ids": [flow_id],
        "limits": limits,
    });
    let key = StageKey::new(
        NATIVE_CASE_STAGE,
        NATIVE_CASE_VERSION,
        NATIVE_CASE_ALGORITHM,
        &policy,
        &source,
        &[],
    )?;
    match cache.lookup(&key, CacheReadPolicy::CompleteOnly) {
        Ok(Some(entry)) => {
            match load_cached_case(&entry, source_id, store.memory_budget(), cache.max_bytes()) {
                Ok(result) => {
                    if let Some(job) = context.job {
                        job.check_cancelled()?;
                    }
                    count_cache_hit(context.job)?;
                    return Ok(result);
                }
                Err(error) => cache_failure(context, CacheFallbackKind::InvalidEntry, error)?,
            }
        }
        Ok(None) => {}
        Err(error) => cache_failure(context, CacheFallbackKind::LookupFailed, error.into())?,
    }

    count_cache_miss(context.job)?;
    let result = store.investigate_flows(&[flow_id], limits)?;
    if let Some(job) = context.job {
        job.check_cancelled()?;
    }
    if let Err(error) = store_cached_case(cache, &key, &result, store.memory_budget()) {
        cache_failure(context, CacheFallbackKind::CommitFailed, error)?;
    }
    Ok(result)
}

fn load_cached_case(
    entry: &CacheEntry,
    source_id: &str,
    memory: Option<&MemoryBudget>,
    maximum_storage_bytes: u64,
) -> Result<BuildResult> {
    let metadata = NativeCaseMetadata::deserialize(entry.metadata())?;
    if metadata.case_storage_format != crate::case_snapshot::STORAGE_FORMAT {
        return Err(invalid("cached native Case snapshot format is unsupported"));
    }
    let case = crate::case_snapshot::read(
        entry,
        metadata.case_snapshot_usage,
        snapshot_limits(maximum_storage_bytes)?,
        memory,
    )?;
    if !matches!(case.sources(), [source] if source.id == source_id) {
        return Err(invalid("cached native Case belongs to a different source"));
    }
    Ok(BuildResult {
        case,
        complete: metadata.complete,
    })
}

fn store_cached_case(
    cache: &Cache,
    key: &StageKey,
    result: &BuildResult,
    memory: Option<&MemoryBudget>,
) -> Result<()> {
    let lease = cache.lease(key)?;
    let usage = crate::case_snapshot::write(
        &lease,
        &result.case,
        snapshot_limits(cache.max_bytes())?,
        memory,
    )?;
    let metadata = NativeCaseMetadata {
        complete: result.complete,
        case_storage_format: crate::case_snapshot::STORAGE_FORMAT,
        case_snapshot_usage: usage,
    };
    drop(lease.commit(StageStatus::Complete, serde_json::to_value(metadata)?)?);
    Ok(())
}

fn cache_failure(
    context: IndexedAnalysisContext<'_>,
    kind: CacheFallbackKind,
    error: Box<dyn std::error::Error>,
) -> Result<()> {
    if let Some(job) = context.job {
        job.check_cancelled()?;
    }
    // Shared pressure must stop admission instead of starting uncharged replacement work
    if context.strict_cache || crate::memory_error::find(error.as_ref()).is_some() {
        return Err(error);
    }
    if let Some(job) = context.job {
        job.record_cache_fallback(
            CacheStage::CaseRecovery,
            kind,
            format_args!(
                "native Case cache {}; continuing from the capture index",
                kind.label()
            ),
        )?;
    }
    Ok(())
}

fn snapshot_limits(maximum_storage_bytes: u64) -> Result<CaseSnapshotLimits> {
    Ok(CaseSnapshotLimits::new(
        maximum_storage_bytes,
        u64::try_from(MAX_CASE_JSON_BYTES)?,
    ))
}
