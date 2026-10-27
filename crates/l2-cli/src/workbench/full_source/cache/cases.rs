//! Complete native evidence cases cached by source, flow, and reconstruction limits

use super::super::invalid;
use super::{
    IndexedAnalysisContext, NATIVE_CASE_VERSION, Result, count_cache_hit, count_cache_miss,
    source_identity,
};
use l2_workbench::{
    evidence::{CaseSnapshotLimits, CaseSnapshotUsage, MAX_CASE_JSON_BYTES},
    investigation::BuildResult,
    job::cache::{CacheReadPolicy, StageKey, StageStatus},
    reconstruction::Limits,
    store::Store,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

const NATIVE_CASE_STAGE: &str = "native_case";
const NATIVE_CASE_ALGORITHM: &str = "l2-native-case-v2";

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
    if let Some(entry) = cache.lookup(&key, CacheReadPolicy::CompleteOnly)? {
        if let Some(job) = context.job {
            job.check_cancelled()?;
        }
        let metadata = NativeCaseMetadata::deserialize(entry.metadata())?;
        if metadata.case_storage_format != crate::case_snapshot::STORAGE_FORMAT {
            return Err(invalid("cached native Case snapshot format is unsupported"));
        }
        let case = crate::case_snapshot::read(
            &entry,
            metadata.case_snapshot_usage,
            snapshot_limits(cache.max_bytes())?,
            store.memory_budget(),
        )?;
        if !matches!(case.sources(), [source] if source.id == source_id) {
            return Err(invalid("cached native Case belongs to a different source"));
        }
        count_cache_hit(context.job)?;
        return Ok(BuildResult {
            case,
            complete: metadata.complete,
        });
    }

    count_cache_miss(context.job)?;
    let result = store.investigate_flows(&[flow_id], limits)?;
    if let Some(job) = context.job {
        job.check_cancelled()?;
    }
    let lease = cache.lease(&key)?;
    let usage = crate::case_snapshot::write(
        &lease,
        &result.case,
        snapshot_limits(cache.max_bytes())?,
        store.memory_budget(),
    )?;
    let metadata = NativeCaseMetadata {
        complete: result.complete,
        case_storage_format: crate::case_snapshot::STORAGE_FORMAT,
        case_snapshot_usage: usage,
    };
    drop(lease.commit(StageStatus::Complete, serde_json::to_value(metadata)?)?);
    Ok(result)
}

fn snapshot_limits(maximum_storage_bytes: u64) -> Result<CaseSnapshotLimits> {
    Ok(CaseSnapshotLimits::new(
        maximum_storage_bytes,
        u64::try_from(MAX_CASE_JSON_BYTES)?,
    ))
}
