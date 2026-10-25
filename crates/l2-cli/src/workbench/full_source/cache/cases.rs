//! Complete native evidence cases cached by source, flow, and reconstruction limits

use super::super::{input, invalid};
use super::{
    IndexedAnalysisContext, NATIVE_CASE_VERSION, Result, count_cache_hit, count_cache_miss,
    source_identity,
};
use l2_workbench::{
    evidence::{Case, MAX_CASE_JSON_BYTES},
    investigation::BuildResult,
    job::cache::{CacheEntry, CacheReadPolicy, StageKey, StageStatus, Value},
    reconstruction::Limits,
    store::Store,
};
use serde_json::json;
use std::{
    fs::OpenOptions,
    io::{BufWriter, Read, Write},
};

const NATIVE_CASE_STAGE: &str = "native_case";
const NATIVE_CASE_ALGORITHM: &str = "l2-native-case-v1";
const CASE_FILE: &str = "case.json";

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
        let complete = entry
            .metadata()
            .get("complete")
            .and_then(Value::as_bool)
            .ok_or_else(|| invalid("cached native case is missing its completeness value"))?;
        let case = read_cached_case(&entry)?;
        count_cache_hit(context.job)?;
        return Ok(BuildResult { case, complete });
    }

    count_cache_miss(context.job)?;
    let result = store.investigate_flows(&[flow_id], limits)?;
    if let Some(job) = context.job {
        job.check_cancelled()?;
    }
    let lease = cache.lease(&key)?;
    write_cached_case(&lease, &result.case)?;
    drop(lease.commit(StageStatus::Complete, json!({"complete": result.complete}))?);
    Ok(result)
}

fn read_cached_case(entry: &CacheEntry) -> Result<Case> {
    let path = entry.directory().join(CASE_FILE);
    let file = input::regular_no_follow(&path)?;
    let maximum = u64::try_from(MAX_CASE_JSON_BYTES)?;
    if file.metadata()?.len() > maximum {
        return Err(invalid(
            "cached native case exceeds the evidence size limit",
        ));
    }
    // Limit the read again in case the file grows after its metadata check
    let mut bytes = Vec::new();
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_CASE_JSON_BYTES {
        return Err(invalid(
            "cached native case exceeds the evidence size limit",
        ));
    }
    Ok(Case::from_json(&bytes)?)
}

fn write_cached_case(lease: &l2_workbench::job::cache::Lease, case: &Case) -> Result<()> {
    let path = lease.directory().join(CASE_FILE);
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let mut writer = BufWriter::new(file);
    case.write_json(&mut writer)?;
    writer.flush()?;
    writer
        .into_inner()
        .map_err(std::io::IntoInnerError::into_error)?
        .sync_all()?;
    Ok(())
}
