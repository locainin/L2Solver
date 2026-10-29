use super::{
    Counter, Job, Limits, MemoryBudget, MemoryClass, PendingCase, RecoveryContext, RecoveryOptions,
    RecoveryProfile, process_case_batch, two_udp_flows,
};
use crate::workbench::full_source::{
    AcquisitionOptions, FullSourceItem, IndexedAnalysisContext, IndexedAnalysisOptions,
    acquire_indexed_source, analyze_indexed_source_with_context,
};
use l2_workbench::{job::cache::Cache, protocol::ProtocolLimits};
use std::{error::Error, fs};

#[test]
fn cached_collection_uses_each_workers_reserved_credit() -> Result<(), Box<dyn Error>> {
    const LIMIT: u64 = 64 * 1024 * 1024;
    const HEADROOM: u64 = 16 * 1024;
    let directory = tempfile::tempdir()?;
    let capture = directory.path().join("flows.pcap");
    fs::write(&capture, two_udp_flows()?)?;
    let budget = MemoryBudget::new(LIMIT);
    let cache = Cache::open_at_with_memory_budget(
        directory.path().join("cache"),
        directory.path().join("state"),
        64 * 1024 * 1024,
        budget.clone(),
    )?;
    let options = RecoveryOptions {
        profile: RecoveryProfile::Fast,
        memory_limit: LIMIT,
        strict_cache: true,
        ..RecoveryOptions::default()
    };
    let mut indexed =
        acquire_indexed_source(&capture, directory.path(), &AcquisitionOptions::default())?;
    indexed.store.set_memory_budget(budget.clone())?;
    let pool = rayon::ThreadPoolBuilder::new().num_threads(1).build()?;
    let job = Job::new("scoped cached collection");
    let mut expected = Vec::new();
    let mut restored = Vec::new();

    for warm in [false, true] {
        let context = RecoveryContext {
            cache: Some(&cache),
            job: warm.then_some(&job),
            memory: Some(&budget),
            options: &options,
        };
        analyze_indexed_source_with_context(
            &indexed.store,
            &indexed.receipt,
            IndexedAnalysisOptions {
                limits: Limits::default(),
                include_cohorts: false,
            },
            IndexedAnalysisContext::default(),
            |item| {
                let native = match &item {
                    FullSourceItem::Flow(flow) => &flow.result.case,
                    FullSourceItem::FlowPage(page) => &page.result.case,
                    FullSourceItem::Cohort(cohort) => &cohort.result.case,
                };
                let usage = native.resource_usage();
                let retained = native.charged_memory_bytes().unwrap_or(
                    u64::try_from(usage.blob_bytes)? + u64::try_from(usage.details_bytes)?,
                );
                let reports = u64::try_from(ProtocolLimits::default().max_report_bytes)? * 2;
                let snapshot = budget.snapshot()?;
                let remaining = snapshot.limit_bytes - snapshot.used_bytes;
                // Leave room for exactly one worker and only a small unreserved root balance
                let held = if warm {
                    Some(
                        budget.try_reserve(
                            MemoryClass::Base,
                            remaining
                                .checked_sub(retained + reports + HEADROOM)
                                .ok_or("fixture exceeded the budget")?,
                        )?,
                    )
                } else {
                    None
                };
                let mut batch = vec![PendingCase::new(item)?];
                process_case_batch(&mut batch, &pool, directory.path(), &context, |recovered| {
                    let mut bytes = Vec::new();
                    match &recovered.item {
                        FullSourceItem::Flow(flow) => flow.result.case.write_json(&mut bytes)?,
                        FullSourceItem::FlowPage(page) => {
                            page.result.case.write_json(&mut bytes)?
                        }
                        FullSourceItem::Cohort(cohort) => {
                            cohort.result.case.write_json(&mut bytes)?
                        }
                    }
                    if warm {
                        restored.push(bytes);
                    } else {
                        expected.push(bytes);
                    }
                    Ok(())
                })?;
                drop(held);
                Ok(())
            },
        )?;
    }
    assert!(!expected.is_empty());
    assert_eq!(restored, expected);
    assert_eq!(
        job.snapshot()?.counters.get(&Counter::CacheHits).copied(),
        Some(u64::try_from(expected.len())?)
    );
    Ok(())
}
