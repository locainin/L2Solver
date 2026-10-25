use super::super::{correlation, input, read_bounded};
use crate::arguments::ReviewArgs;
use l2_workbench::{
    carrier::discovery::{
        DiscoveryCandidate, DiscoveryResultStore, ResultReadOptions, StoredDiscoverySummary,
    },
    identity::{CorrelationPlan, CorrelationReport},
    journal::{Entry, Journal, JournalOptions, Overview, ToolReceiptSummary},
};
use serde::Serialize;
use std::{error::Error, path::PathBuf};

#[derive(Serialize)]
pub(super) struct CarrierOverview {
    pub directory: PathBuf,
    pub summary: StoredDiscoverySummary,
    pub candidates: Vec<DiscoveryCandidate>,
    pub omitted_candidates: usize,
    pub next_after: Option<usize>,
}
#[derive(Serialize)]
pub(super) struct ReviewReport {
    pub journal: Overview,
    pub hypotheses: Vec<Entry>,
    pub omitted_hypotheses: u64,
    pub tools: Vec<ToolReceiptSummary>,
    pub omitted_tools: u64,
    pub carrier_results: Vec<CarrierOverview>,
    pub correlation: CorrelationReport,
    pub complete: bool,
}

pub(super) fn collect(args: &ReviewArgs) -> Result<ReviewReport, Box<dyn Error>> {
    let plan = if let Some(path) = &args.correlation_plan {
        serde_json::from_slice(&read_bounded(
            input::regular_no_follow(path)?,
            args.resources.max_plan_bytes.get(),
        )?)?
    } else {
        CorrelationPlan::default()
    };
    let journal = Journal::open_readonly(
        &args.directory,
        JournalOptions {
            cache_mib: args.resources.cache_mib.get(),
            max_entry_bytes: args.resources.max_entry_bytes.get(),
            max_tool_report_bytes: args.resources.max_tool_report_bytes.get(),
        },
    )?;
    journal.read_snapshot(|journal| {
        let overview = journal.overview()?;
        let mut hypotheses = Vec::new();
        journal.visit_review(Some(u64::try_from(args.limit.get())?), |entry| {
            hypotheses.push(entry);
            Ok(())
        })?;
        let mut tools = Vec::new();
        journal.visit_tool_receipts(None, Some(u64::try_from(args.limit.get())?), |receipt| {
            tools.push(receipt);
            Ok(())
        })?;
        let correlation = correlation::collect_in_snapshot(journal, &plan, &args.resources)?;
        let mut carrier_results = Vec::new();
        for directory in &args.carrier_results {
            let store = DiscoveryResultStore::open_with_options(
                directory,
                ResultReadOptions {
                    max_disk_bytes: args.max_result_disk_bytes.get(),
                    max_record_bytes: args.max_result_record_bytes.get(),
                    max_page_bytes: args.max_result_page_bytes.get(),
                },
            )?;
            let page = store.list_candidates(None, args.limit.get())?;
            carrier_results.push(CarrierOverview {
                directory: directory.clone(),
                summary: store.summary().clone(),
                omitted_candidates: store.summary().candidate_count - page.rows.len(),
                candidates: page.rows,
                next_after: page.next_after,
            });
        }
        let omitted_hypotheses = overview.hypotheses - u64::try_from(hypotheses.len())?;
        let omitted_tools = overview.tool_receipts - u64::try_from(tools.len())?;
        let complete = omitted_hypotheses == 0
            && omitted_tools == 0
            && correlation.complete
            && carrier_results
                .iter()
                .all(|store| store.omitted_candidates == 0 && store.summary.enumeration_complete);
        Ok(ReviewReport {
            journal: overview,
            hypotheses,
            omitted_hypotheses,
            tools,
            omitted_tools,
            carrier_results,
            correlation,
            complete,
        })
    })
}
