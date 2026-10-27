use super::{
    AcquisitionOptions, IndexedAnalysisContext, IndexedAnalysisOptions, Limits,
    acquire_indexed_source, analyze_indexed_source_with_context, open_test_cache,
    single_flow_capture,
};
use crate::workbench::full_source::FullSourceItem;
use l2_workbench::{
    evidence::{Case, CaseSnapshotLimits},
    job::{
        Counter, Job, MemoryBudget, MemoryClass,
        cache::{Cache, SourceIdentity, StageKey, StageStatus},
    },
    store::{IngestReceipt, Store},
};
use serde_json::json;
use std::{error::Error, fs, path::Path};

type TestResult = Result<(), Box<dyn Error>>;

fn analyze_flow(
    store: &Store,
    receipt: &IngestReceipt,
    cache: Option<&Cache>,
    job: Option<&Job>,
) -> Result<Case, Box<dyn Error>> {
    let mut retained = None;
    analyze_indexed_source_with_context(
        store,
        receipt,
        IndexedAnalysisOptions {
            include_cohorts: false,
            ..IndexedAnalysisOptions::default()
        },
        IndexedAnalysisContext { cache, job },
        |item| {
            if let FullSourceItem::Flow(flow) = item {
                retained = Some(flow.result.case);
            }
            Ok(())
        },
    )?;
    retained.ok_or_else(|| "expected one flow Case".into())
}

fn prepare_capture(directory: &Path) -> Result<(std::path::PathBuf, Cache), Box<dyn Error>> {
    let capture_path = directory.join("flow.pcap");
    fs::write(&capture_path, single_flow_capture())?;
    Ok((capture_path, open_test_cache(directory)?))
}

fn native_key(
    receipt: &IngestReceipt,
    flow_id: i64,
    version: u32,
    algorithm: &str,
) -> Result<StageKey, Box<dyn Error>> {
    let digest = receipt
        .source_id
        .strip_prefix("sha256:")
        .ok_or("expected SHA-256 source")?;
    let source = SourceIdentity::from_sha256(digest)?;
    Ok(StageKey::new(
        "native_case",
        version,
        algorithm,
        &json!({"flow_ids": [flow_id], "limits": Limits::default()}),
        &source,
        &[],
    )?)
}

fn seed_snapshot(
    cache: &Cache,
    key: &StageKey,
    case: &Case,
    complete: bool,
    mismatched_usage: bool,
) -> TestResult {
    let lease = cache.lease(key)?;
    let mut graph = fs::File::create(lease.directory().join("case.graph.gz"))?;
    let mut blobs = fs::File::create(lease.directory().join("case.blobs"))?;
    let mut usage = case.write_snapshot(
        &mut graph,
        &mut blobs,
        CaseSnapshotLimits::new(cache.max_bytes(), 64 * 1024 * 1024),
    )?;
    usage.graph_decoded_bytes += u64::from(mismatched_usage);
    drop(lease.commit(
        StageStatus::Complete,
        json!({
            "complete": complete,
            "case_storage_format": 1,
            "case_snapshot_usage": usage,
        }),
    )?);
    Ok(())
}

#[test]
fn warm_native_case_restores_exact_evidence_with_live_shared_charge() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (capture, cache) = prepare_capture(directory.path())?;
    let acquisition = AcquisitionOptions {
        cache: Some(&cache),
        ..AcquisitionOptions::default()
    };
    let mut indexed = acquire_indexed_source(&capture, directory.path(), &acquisition)?;
    let expected = analyze_flow(&indexed.store, &indexed.receipt, None, None)?;
    let written = analyze_flow(&indexed.store, &indexed.receipt, Some(&cache), None)?;
    assert_eq!(written, expected);
    drop(written);

    let budget = MemoryBudget::new(32 * 1024 * 1024);
    indexed.store.set_memory_budget(budget.clone())?;
    let job = Job::new("warm native Case");
    let restored = analyze_flow(&indexed.store, &indexed.receipt, Some(&cache), Some(&job))?;
    assert_eq!(restored, expected);
    assert_eq!(job.snapshot()?.counters.get(&Counter::CacheHits), Some(&1));
    assert!(budget.snapshot()?.used(MemoryClass::Case) > 0);
    assert_eq!(budget.snapshot()?.used(MemoryClass::Cache), 0);
    drop(restored);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn warm_native_case_rejects_small_budget_without_damaging_the_cache() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (capture, cache) = prepare_capture(directory.path())?;
    let acquisition = AcquisitionOptions {
        cache: Some(&cache),
        ..AcquisitionOptions::default()
    };
    let mut indexed = acquire_indexed_source(&capture, directory.path(), &acquisition)?;
    let expected = analyze_flow(&indexed.store, &indexed.receipt, Some(&cache), None)?;
    drop(expected);
    let budget = MemoryBudget::new(1024 * 1024);
    indexed.store.set_memory_budget(budget.clone())?;
    let uncached = analyze_flow(&indexed.store, &indexed.receipt, None, None)?;
    assert!(budget.snapshot()?.used(MemoryClass::Case) > 0);
    drop(uncached);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    assert!(analyze_flow(&indexed.store, &indexed.receipt, Some(&cache), None).is_err());
    assert!(budget.snapshot()?.rejected > 0);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    drop(indexed);

    let mut indexed = acquire_indexed_source(&capture, directory.path(), &acquisition)?;
    let budget = MemoryBudget::new(32 * 1024 * 1024);
    indexed.store.set_memory_budget(budget.clone())?;
    let job = Job::new("retry native Case");
    let restored = analyze_flow(&indexed.store, &indexed.receipt, Some(&cache), Some(&job))?;
    assert_eq!(job.snapshot()?.counters.get(&Counter::CacheHits), Some(&1));
    assert!(budget.snapshot()?.used(MemoryClass::Case) > 0);
    drop(restored);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn charged_native_analysis_misses_legacy_json_but_reuses_the_capture_index() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (capture, cache) = prepare_capture(directory.path())?;
    let acquisition = AcquisitionOptions {
        cache: Some(&cache),
        ..AcquisitionOptions::default()
    };
    let indexed = acquire_indexed_source(&capture, directory.path(), &acquisition)?;
    let flow_id = indexed
        .store
        .packet(&indexed.receipt.source_id, 1)?
        .flow
        .ok_or("expected one indexed flow")?;
    let legacy = indexed
        .store
        .investigate_flows(&[flow_id], Limits::default())?;
    let key = native_key(&indexed.receipt, flow_id, 1, "l2-native-case-v1")?;
    let lease = cache.lease(&key)?;
    legacy
        .case
        .write_json(&mut fs::File::create(lease.directory().join("case.json"))?)?;
    drop(lease.commit(StageStatus::Complete, json!({"complete": legacy.complete}))?);
    drop(indexed);

    let acquisition_job = Job::new("reuse capture index");
    let mut indexed = acquire_indexed_source(
        &capture,
        directory.path(),
        &AcquisitionOptions {
            cache: Some(&cache),
            job: Some(&acquisition_job),
            ..AcquisitionOptions::default()
        },
    )?;
    assert_eq!(
        acquisition_job
            .snapshot()?
            .counters
            .get(&Counter::CacheHits),
        Some(&1)
    );
    let budget = MemoryBudget::new(32 * 1024 * 1024);
    indexed.store.set_memory_budget(budget.clone())?;
    let job = Job::new("recompute legacy native Case");
    let actual = analyze_flow(&indexed.store, &indexed.receipt, Some(&cache), Some(&job))?;
    assert_eq!(actual, legacy.case);
    assert_eq!(
        job.snapshot()?.counters.get(&Counter::CacheMisses),
        Some(&1)
    );
    assert_eq!(job.snapshot()?.counters.get(&Counter::CacheHits), Some(&0));
    assert!(budget.snapshot()?.used(MemoryClass::Case) > 0);
    drop(actual);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn mismatched_native_snapshot_usage_fails_without_retaining_shared_memory() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (capture, cache) = prepare_capture(directory.path())?;
    let acquisition = AcquisitionOptions {
        cache: Some(&cache),
        ..AcquisitionOptions::default()
    };
    let mut indexed = acquire_indexed_source(&capture, directory.path(), &acquisition)?;
    let flow_id = indexed
        .store
        .packet(&indexed.receipt.source_id, 1)?
        .flow
        .ok_or("expected one indexed flow")?;
    let result = indexed
        .store
        .investigate_flows(&[flow_id], Limits::default())?;
    let key = native_key(&indexed.receipt, flow_id, 2, "l2-native-case-v2")?;
    seed_snapshot(&cache, &key, &result.case, result.complete, true)?;

    let budget = MemoryBudget::new(32 * 1024 * 1024);
    indexed.store.set_memory_budget(budget.clone())?;
    assert!(analyze_flow(&indexed.store, &indexed.receipt, Some(&cache), None).is_err());
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn native_snapshot_for_a_different_source_is_rejected_without_leaking_memory() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (capture, cache) = prepare_capture(directory.path())?;
    let acquisition = AcquisitionOptions {
        cache: Some(&cache),
        ..AcquisitionOptions::default()
    };
    let mut indexed = acquire_indexed_source(&capture, directory.path(), &acquisition)?;
    let flow_id = indexed
        .store
        .packet(&indexed.receipt.source_id, 1)?
        .flow
        .ok_or("expected one indexed flow")?;

    let other_capture = directory.path().join("other.pcap");
    let mut other_bytes = single_flow_capture();
    *other_bytes.get_mut(24).ok_or("capture has no timestamp")? = 2;
    fs::write(&other_capture, other_bytes)?;
    let other = acquire_indexed_source(&other_capture, directory.path(), &acquisition)?;
    let other_flow = other
        .store
        .packet(&other.receipt.source_id, 1)?
        .flow
        .ok_or("expected one indexed flow")?;
    let wrong = other
        .store
        .investigate_flows(&[other_flow], Limits::default())?;
    assert_ne!(indexed.receipt.source_id, other.receipt.source_id);
    let key = native_key(&indexed.receipt, flow_id, 2, "l2-native-case-v2")?;
    seed_snapshot(&cache, &key, &wrong.case, wrong.complete, false)?;

    let budget = MemoryBudget::new(32 * 1024 * 1024);
    indexed.store.set_memory_budget(budget.clone())?;
    assert!(analyze_flow(&indexed.store, &indexed.receipt, Some(&cache), None).is_err());
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}
