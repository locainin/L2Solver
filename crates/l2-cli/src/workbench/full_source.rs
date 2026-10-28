//! Full-source disk acquisition followed by bounded per-flow analysis

mod cache;

pub use cache::NATIVE_CASE_VERSION;
pub use cache::{
    AcquisitionOptions, IndexedAnalysisContext, IndexedSource, acquire_indexed_source,
};

use super::{input, label};
use l2_workbench::{
    investigation::BuildResult,
    reconstruction::{Limits, Reconstructor, RecordRetentionLimit},
    store::{Flow, FlowCohortCoverage, IngestReceipt, Store},
};
use serde::Serialize;
use std::{error::Error, io, path::Path};

#[cfg(test)]
use l2_workbench::store::Options;

const FLOW_PAGE_SIZE: usize = 256;

/// Return the bounded basename associated with the current capture request
pub fn source_label(path: &Path) -> &str {
    label(path, "capture")
}

/// Counters from a successful source read through clean EOF, separate from flow analysis
/// coverage
#[derive(Clone, Debug, Serialize)]
pub struct SourceCoverage {
    pub source_id: String,
    pub bytes: u64,
    pub packet_records: u64,
    pub supported_transport_records: u64,
    /// Includes records without a supported tuple, such as non-transport frames
    pub packets_without_supported_transport: u64,
    #[serde(serialize_with = "l2_workbench::capture_collection::serialize")]
    pub collection_summary: l2_pcap::CollectionSummary,
}

/// Aggregate selected, retained, and omitted records across each indexed flow
///
/// Incomplete flows include reconstruction and downstream evidence or parser omissions
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct FlowAnalysisCoverage {
    pub flows: u64,
    pub complete_flows: u64,
    pub incomplete_flows: u64,
    /// Flows whose selected records were truncated at a retention ceiling
    pub selection_truncated_flows: u64,
    /// Flows whose first omitted record reached the frame ceiling
    pub frame_limited_flows: u64,
    /// Flows whose first omitted record exceeded remaining byte capacity
    pub byte_limited_flows: u64,
    /// Flows whose first omitted record reached the retained unit ceiling
    pub unit_limited_flows: u64,
    /// Flows with one or more reconstruction range omissions
    pub range_omission_flows: u64,
    /// Flows with any reconstruction omission from the capture summary
    pub reconstruction_omission_flows: u64,
    pub omitted_tcp_records: u64,
    pub omitted_fragments: u64,
    /// TCP and fragment range omissions reported by the capture summary
    pub omitted_sequence_ranges: u64,
    /// Byte positions affected by omitted observations or rejected range reservations
    pub omitted_tcp_bytes: u64,
    pub omitted_tcp_observations: u64,
    /// Byte positions affected by omitted observations or rejected range reservations
    pub omitted_fragment_bytes: u64,
    pub omitted_fragment_observations: u64,
    /// Ranges rejected before observation coverage could be built
    pub unmeasured_omitted_ranges: u64,
    pub omitted_state_observations: u64,
    pub selected_flow_records: u64,
    pub retained_flow_records: u64,
    pub omitted_flow_records: u64,
    /// Independent later-page analyses, with non-overlapping selected packet records
    pub supplementary_pages: SupplementaryPageCoverage,
}

/// Coverage for independent Cases built after each flow's retained prefix
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct SupplementaryPageCoverage {
    pub flows: u64,
    pub pages: u64,
    pub selected_records: u64,
    pub retained_records: u64,
    pub omitted_records: u64,
    /// Capture-summary reconstruction omissions from independent page Cases
    pub reconstruction_omissions: ReconstructionOmissionCoverage,
}

/// Full-source acquisition counters and downstream flow-analysis coverage
#[derive(Clone, Debug, Serialize)]
pub struct FullSourceCoverage {
    pub source: SourceCoverage,
    pub analysis: FlowAnalysisCoverage,
    /// Exact reconstruction omissions from cohort capture summaries
    pub cohort_reconstruction: ReconstructionOmissionCoverage,
    /// `None` means the caller deliberately did not request cross-flow analysis
    pub cohort_analysis: Option<FlowCohortCoverage>,
}

/// Controls bounded analysis of one source already present in a disk index
#[derive(Clone, Copy, Debug)]
pub struct IndexedAnalysisOptions {
    /// Retention budgets applied to each flow and cohort analysis
    pub limits: Limits,
    /// Whether cross-flow IP-pair cohorts are analyzed after individual flows
    pub include_cohorts: bool,
}

impl Default for IndexedAnalysisOptions {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            include_cohorts: true,
        }
    }
}

/// Capture-summary omission totals for one set of analyzed Cases
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ReconstructionOmissionCoverage {
    pub cases: u64,
    pub cases_with_omissions: u64,
    pub omitted_tcp_records: u64,
    pub omitted_fragments: u64,
    pub omitted_sequence_ranges: u64,
    /// Byte positions affected by omitted observations or rejected range reservations
    pub omitted_tcp_bytes: u64,
    pub omitted_tcp_observations: u64,
    /// Byte positions affected by omitted observations or rejected range reservations
    pub omitted_fragment_bytes: u64,
    pub omitted_fragment_observations: u64,
    /// Ranges rejected before observation coverage could be built
    pub unmeasured_omitted_ranges: u64,
    pub omitted_state_observations: u64,
}

impl ReconstructionOmissionCoverage {
    fn record(&mut self, next: ReconstructionCaseOmissions) -> Result<(), Box<dyn Error>> {
        self.cases = add_counter(self.cases, 1)?;
        if next.has_omissions() {
            self.cases_with_omissions = add_counter(self.cases_with_omissions, 1)?;
        }
        self.omitted_tcp_records = add_counter(self.omitted_tcp_records, next.omitted_tcp_records)?;
        self.omitted_fragments = add_counter(self.omitted_fragments, next.omitted_fragments)?;
        self.omitted_sequence_ranges =
            add_counter(self.omitted_sequence_ranges, next.omitted_sequence_ranges)?;
        self.omitted_tcp_bytes = add_counter(self.omitted_tcp_bytes, next.omitted_tcp_bytes)?;
        self.omitted_tcp_observations =
            add_counter(self.omitted_tcp_observations, next.omitted_tcp_observations)?;
        self.omitted_fragment_bytes =
            add_counter(self.omitted_fragment_bytes, next.omitted_fragment_bytes)?;
        self.omitted_fragment_observations = add_counter(
            self.omitted_fragment_observations,
            next.omitted_fragment_observations,
        )?;
        self.unmeasured_omitted_ranges = add_counter(
            self.unmeasured_omitted_ranges,
            next.unmeasured_omitted_ranges,
        )?;
        self.omitted_state_observations = add_counter(
            self.omitted_state_observations,
            next.omitted_state_observations,
        )?;
        Ok(())
    }
}

/// Reconstruction omissions reported by one capture summary
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReconstructionCaseOmissions {
    pub omitted_tcp_records: u64,
    pub omitted_fragments: u64,
    pub omitted_sequence_ranges: u64,
    pub omitted_tcp_bytes: u64,
    pub omitted_tcp_observations: u64,
    pub omitted_fragment_bytes: u64,
    pub omitted_fragment_observations: u64,
    pub unmeasured_omitted_ranges: u64,
    pub omitted_state_observations: u64,
}

impl ReconstructionCaseOmissions {
    pub const fn has_omissions(self) -> bool {
        self.omitted_tcp_records != 0
            || self.omitted_fragments != 0
            || self.omitted_sequence_ranges != 0
            || self.omitted_tcp_bytes != 0
            || self.omitted_tcp_observations != 0
            || self.omitted_fragment_bytes != 0
            || self.omitted_fragment_observations != 0
            || self.unmeasured_omitted_ranges != 0
            || self.omitted_state_observations != 0
    }
}

/// One analyzed flow delivered to a caller without retaining earlier results
pub struct FlowAnalysis<R = BuildResult> {
    pub flow: Flow,
    pub result: R,
    pub coverage: PerFlowCoverage,
}

/// One bounded cross-flow analysis delivered without retaining earlier results
pub struct CohortAnalysis<R = BuildResult> {
    pub member_flows: Vec<Flow>,
    pub packet_flow_ids: Vec<(u32, i64)>,
    pub result: R,
    pub split: bool,
}

/// One event from a capture analysis pass
pub enum FullSourceItem<R = BuildResult> {
    Flow(Box<FlowAnalysis<R>>),
    FlowPage(Box<SupplementaryFlowPage<R>>),
    Cohort(Box<CohortAnalysis<R>>),
}

impl<R> FullSourceItem<R> {
    /// Move analysis metadata unchanged while replacing its Case storage
    ///
    /// # Errors
    /// Propagates the storage conversion error and drops the consumed input on failure
    pub(crate) fn try_map_result<S, E>(
        self,
        map: impl FnOnce(R) -> Result<S, E>,
    ) -> Result<FullSourceItem<S>, E> {
        Ok(match self {
            Self::Flow(analysis) => {
                let FlowAnalysis {
                    flow,
                    result,
                    coverage,
                } = *analysis;
                FullSourceItem::Flow(Box::new(FlowAnalysis {
                    flow,
                    result: map(result)?,
                    coverage,
                }))
            }
            Self::FlowPage(page) => {
                let SupplementaryFlowPage {
                    flow,
                    page_index,
                    first_packet,
                    last_packet,
                    selected_records,
                    retained_records,
                    omitted_records,
                    result,
                } = *page;
                FullSourceItem::FlowPage(Box::new(SupplementaryFlowPage {
                    flow,
                    page_index,
                    first_packet,
                    last_packet,
                    selected_records,
                    retained_records,
                    omitted_records,
                    result: map(result)?,
                }))
            }
            Self::Cohort(cohort) => {
                let CohortAnalysis {
                    member_flows,
                    packet_flow_ids,
                    result,
                    split,
                } = *cohort;
                FullSourceItem::Cohort(Box::new(CohortAnalysis {
                    member_flows,
                    packet_flow_ids,
                    result: map(result)?,
                    split,
                }))
            }
        })
    }
}

/// One independent bounded analysis page for an indexed flow
pub struct SupplementaryFlowPage<R = BuildResult> {
    pub flow: Flow,
    pub page_index: u64,
    pub first_packet: u32,
    pub last_packet: u32,
    pub selected_records: u64,
    pub retained_records: u64,
    pub omitted_records: u64,
    pub result: R,
}

/// Per-flow retention and analysis status
pub struct PerFlowCoverage {
    /// Source records indexed for this flow
    pub selected_records: u64,
    /// Source records retained for flow analysis
    pub retained_records: u64,
    /// Selected source records omitted after a retention ceiling was reached
    pub omitted_records: u64,
    /// Retention ceilings reached at the first omitted source record
    pub retention_limits: Vec<RecordRetentionLimit>,
    /// Reconstruction omissions reported by the capture summary
    pub reconstruction_omissions: ReconstructionCaseOmissions,
    /// Completeness of the full retained flow analysis
    pub complete: bool,
}

/// Index a full capture on disk and visit every indexed flow as a bounded analysis result
///
/// Flow ID pages bound working memory but do not limit the number of analyzed flows
///
/// # Errors
/// Returns source parsing, disk-indexing, analysis, visitor, or counter failures
#[cfg(test)]
fn acquire_full_source(
    path: &Path,
    limits: Limits,
    visitor: impl FnMut(FlowAnalysis) -> Result<(), Box<dyn Error>>,
) -> Result<FullSourceCoverage, Box<dyn Error>> {
    let temporary_parent = std::env::temp_dir();
    let mut flow_visitor = visitor;
    acquire_full_source_inner(
        path,
        &temporary_parent,
        IndexedAnalysisOptions {
            limits,
            include_cohorts: false,
        },
        |item| match item {
            FullSourceItem::Flow(analysis) => flow_visitor(*analysis),
            FullSourceItem::FlowPage(_) => Ok(()),
            FullSourceItem::Cohort(_) => Err(invalid("flow-only acquisition emitted a cohort")),
        },
    )
}

/// Index a full capture in a caller-selected directory and visit every indexed flow
///
/// # Errors
/// Returns source parsing, disk-indexing, analysis, visitor, or counter failures
#[cfg(test)]
pub fn acquire_full_source_in(
    path: &Path,
    temporary_parent: &Path,
    limits: Limits,
    visitor: impl FnMut(FlowAnalysis) -> Result<(), Box<dyn Error>>,
) -> Result<FullSourceCoverage, Box<dyn Error>> {
    let mut flow_visitor = visitor;
    acquire_full_source_inner(
        path,
        temporary_parent,
        IndexedAnalysisOptions {
            limits,
            include_cohorts: false,
        },
        |item| match item {
            FullSourceItem::Flow(analysis) => flow_visitor(*analysis),
            FullSourceItem::FlowPage(_) => Ok(()),
            FullSourceItem::Cohort(_) => Err(invalid("flow-only acquisition emitted a cohort")),
        },
    )
}

/// Index a full capture, then analyze bounded flows and IP-pair cohorts
///
/// # Errors
/// Returns source parsing, disk-indexing, analysis, visitor, or counter failures
#[cfg(test)]
pub fn acquire_full_source_with_cohorts_in(
    path: &Path,
    temporary_parent: &Path,
    limits: Limits,
    visitor: impl FnMut(FullSourceItem) -> Result<(), Box<dyn Error>>,
) -> Result<FullSourceCoverage, Box<dyn Error>> {
    acquire_full_source_inner(
        path,
        temporary_parent,
        IndexedAnalysisOptions {
            limits,
            include_cohorts: true,
        },
        visitor,
    )
}

#[cfg(test)]
fn acquire_full_source_inner(
    path: &Path,
    temporary_parent: &Path,
    options: IndexedAnalysisOptions,
    visitor: impl FnMut(FullSourceItem) -> Result<(), Box<dyn Error>>,
) -> Result<FullSourceCoverage, Box<dyn Error>> {
    // Reject invalid budgets before reading a capture into the temporary index
    Reconstructor::with_limits(options.limits)?;

    // Keep the full source and SQLite index on the caller-selected filesystem
    let temporary_directory = tempfile::tempdir_in(temporary_parent)?;
    let mut store = Store::create(temporary_directory.path(), Options::default())?;
    let receipt = store
        .ingest(label(path, "capture"), input::capture(path)?)
        .map_err(|error| input::boxed_capture_error(path, error))?;
    analyze_indexed_source(&store, &receipt, options, visitor)
}

/// Analyze one validated source from an existing disk index with bounded working memory
///
/// The receipt must identify exactly one indexed source with matching byte and packet counts,
/// including when the source has no supported flows.
///
/// # Errors
/// Returns invalid receipt, source/indexing, analysis, visitor, or coverage counter failures
#[cfg(test)]
pub fn analyze_indexed_source(
    store: &Store,
    receipt: &IngestReceipt,
    options: IndexedAnalysisOptions,
    visitor: impl FnMut(FullSourceItem) -> Result<(), Box<dyn Error>>,
) -> Result<FullSourceCoverage, Box<dyn Error>> {
    analyze_indexed_source_with_context(
        store,
        receipt,
        options,
        IndexedAnalysisContext::default(),
        visitor,
    )
}

/// Analyze one validated indexed source with optional persistent case caching
pub fn analyze_indexed_source_with_context(
    store: &Store,
    receipt: &IngestReceipt,
    options: IndexedAnalysisOptions,
    context: IndexedAnalysisContext<'_>,
    visitor: impl FnMut(FullSourceItem) -> Result<(), Box<dyn Error>>,
) -> Result<FullSourceCoverage, Box<dyn Error>> {
    // Validate before visiting flows so empty sources receive the same budget checks
    Reconstructor::with_limits(options.limits)?;
    let source = validate_indexed_receipt(store, receipt)?;
    analyze_indexed_source_flows(store, receipt, source, options, context, visitor)
}

fn validate_indexed_receipt(
    store: &Store,
    receipt: &IngestReceipt,
) -> Result<SourceCoverage, Box<dyn Error>> {
    let mut matching_source_found = false;
    store.visit_sources(|source| {
        if source.source_id == receipt.source_id {
            if matching_source_found {
                return Err(invalid("ingest receipt matches multiple indexed sources"));
            }
            matching_source_found = true;
            if source.bytes != receipt.bytes || source.packets != receipt.packets {
                return Err(invalid(
                    "ingest receipt does not match indexed source metadata",
                ));
            }
        }
        Ok(())
    })?;
    if !matching_source_found {
        return Err(invalid(
            "ingest receipt must identify exactly one indexed source",
        ));
    }

    Ok(source_coverage(receipt))
}

fn analyze_indexed_source_flows(
    store: &Store,
    receipt: &IngestReceipt,
    source: SourceCoverage,
    options: IndexedAnalysisOptions,
    context: IndexedAnalysisContext<'_>,
    mut visitor: impl FnMut(FullSourceItem) -> Result<(), Box<dyn Error>>,
) -> Result<FullSourceCoverage, Box<dyn Error>> {
    let mut analysis = FlowAnalysisCoverage::default();
    analyze_indexed_flows(
        store,
        receipt,
        options,
        context,
        &mut analysis,
        &mut visitor,
    )?;

    let mut cohort_reconstruction = ReconstructionOmissionCoverage::default();
    let cohort_analysis = if options.include_cohorts {
        Some(
            store.visit_ip_pair_cohort_analyses(options.limits, |analysis| {
                cohort_reconstruction
                    .record(reconstruction_case_omissions(&analysis.result.case)?)?;
                visitor(FullSourceItem::Cohort(Box::new(CohortAnalysis {
                    member_flows: analysis.member_flows,
                    packet_flow_ids: analysis.packet_flow_ids,
                    result: analysis.result,
                    split: analysis.split,
                })))
            })?,
        )
    } else {
        None
    };
    Ok(FullSourceCoverage {
        source,
        analysis,
        cohort_reconstruction,
        cohort_analysis,
    })
}

fn analyze_indexed_flows(
    store: &Store,
    receipt: &IngestReceipt,
    options: IndexedAnalysisOptions,
    context: IndexedAnalysisContext<'_>,
    analysis: &mut FlowAnalysisCoverage,
    visitor: &mut impl FnMut(FullSourceItem) -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    let mut after = 0_i64;

    loop {
        // Close the SQLite row cursor before investigating flows on the same connection
        let mut page = Vec::with_capacity(FLOW_PAGE_SIZE);
        let mut page_end = after;
        store.visit_flows(after, Some(u64::try_from(FLOW_PAGE_SIZE)?), |flow| {
            page_end = flow.id;
            page.push(flow);
            Ok(())
        })?;
        if page.is_empty() {
            break;
        }

        for flow in page {
            if flow.source_id != receipt.source_id {
                return Err(invalid("indexed flow belongs to a different source"));
            }
            let result = cache::investigate_flow(
                store,
                &receipt.source_id,
                flow.id,
                options.limits,
                context,
            )?;
            let flow_coverage = per_flow_coverage(&flow, &result)?;
            add_flow_coverage(analysis, &flow_coverage)?;
            let flow_id = flow.id;
            let retained_prefix_records = flow_coverage.retained_records;
            let page_flow = flow.clone();
            visitor(FullSourceItem::Flow(Box::new(FlowAnalysis {
                flow,
                result,
                coverage: flow_coverage,
            })))?;
            let page_reconstruction = &mut analysis.supplementary_pages.reconstruction_omissions;
            let page_coverage = store.visit_flow_pages_after_prefix(
                flow_id,
                retained_prefix_records,
                options.limits,
                |page| {
                    page_reconstruction
                        .record(reconstruction_case_omissions(&page.result.case)?)?;
                    visitor(FullSourceItem::FlowPage(Box::new(SupplementaryFlowPage {
                        flow: page_flow.clone(),
                        page_index: page.page_index,
                        first_packet: page.first_packet,
                        last_packet: page.last_packet,
                        selected_records: page.selected_records,
                        retained_records: page.retained_records,
                        omitted_records: page.omitted_records,
                        result: page.result,
                    })))
                },
            )?;
            add_supplementary_page_coverage(&mut analysis.supplementary_pages, page_coverage)?;
        }
        after = page_end;
    }

    Ok(())
}

fn source_coverage(receipt: &IngestReceipt) -> SourceCoverage {
    SourceCoverage {
        source_id: receipt.source_id.clone(),
        bytes: receipt.bytes,
        packet_records: receipt.packets,
        supported_transport_records: receipt.transport_packets,
        packets_without_supported_transport: receipt.unsupported_transport_packets,
        collection_summary: receipt.collection_summary,
    }
}

fn per_flow_coverage(flow: &Flow, result: &BuildResult) -> Result<PerFlowCoverage, Box<dyn Error>> {
    let capture_summary = capture_summary(&result.case)?;
    let reconstruction_retained_records = capture_summary
        .details
        .get("retained_frames")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| invalid("flow analysis is missing its retained record count"))?;
    let selection = result
        .case
        .nodes()
        .iter()
        .find(|node| node.kind == "index_flow_selection")
        .ok_or_else(|| invalid("flow analysis is missing its selection receipt"))?;
    let retained_records = selection
        .details
        .get("retained_input_records")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| invalid("flow selection receipt is missing its retained prefix count"))?;
    if retained_records != reconstruction_retained_records {
        return Err(invalid(
            "flow input retention and reconstruction prefix counts disagree",
        ));
    }
    let omitted_records = flow
        .packets
        .checked_sub(retained_records)
        .ok_or_else(|| invalid("flow analysis retained more records than were selected"))?;
    let retention_limits: Vec<RecordRetentionLimit> = serde_json::from_value(
        selection
            .details
            .get("retention_limits")
            .cloned()
            .ok_or_else(|| invalid("flow selection receipt is missing retention limits"))?,
    )?;
    let retention_status = selection
        .details
        .get("retention_status")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid("flow selection receipt is missing its retention status"))?;
    let expected_status = if omitted_records == 0 {
        "complete"
    } else {
        "resource_truncated_prefix"
    };
    if retention_status != expected_status || (omitted_records == 0) != retention_limits.is_empty()
    {
        return Err(invalid("flow selection retention coverage is inconsistent"));
    }
    let reconstruction_omissions = capture_summary_omissions(capture_summary)?;
    Ok(PerFlowCoverage {
        selected_records: flow.packets,
        retained_records,
        omitted_records,
        retention_limits,
        reconstruction_omissions,
        complete: result.complete,
    })
}

fn reconstruction_case_omissions(
    case: &l2_workbench::evidence::Case,
) -> Result<ReconstructionCaseOmissions, Box<dyn Error>> {
    capture_summary_omissions(capture_summary(case)?)
}

fn capture_summary(
    case: &l2_workbench::evidence::Case,
) -> Result<&l2_workbench::evidence::Node, Box<dyn Error>> {
    case.nodes()
        .iter()
        .find(|node| node.kind == "capture_summary")
        .ok_or_else(|| invalid("flow analysis is missing its capture summary"))
}

fn capture_summary_omissions(
    summary: &l2_workbench::evidence::Node,
) -> Result<ReconstructionCaseOmissions, Box<dyn Error>> {
    let read_count = |name, message| {
        summary
            .details
            .get(name)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| invalid(message))
    };
    Ok(ReconstructionCaseOmissions {
        omitted_tcp_records: read_count(
            "omitted_tcp_records",
            "capture summary is missing its omitted TCP record count",
        )?,
        omitted_fragments: read_count(
            "omitted_fragments",
            "capture summary is missing its omitted fragment count",
        )?,
        omitted_sequence_ranges: read_count(
            "omitted_sequence_ranges",
            "capture summary is missing its omitted sequence range count",
        )?,
        omitted_tcp_bytes: read_count(
            "omitted_tcp_bytes",
            "capture summary is missing its omitted TCP byte count",
        )?,
        omitted_tcp_observations: read_count(
            "omitted_tcp_observations",
            "capture summary is missing its omitted TCP observation count",
        )?,
        omitted_fragment_bytes: read_count(
            "omitted_fragment_bytes",
            "capture summary is missing its omitted fragment byte count",
        )?,
        omitted_fragment_observations: read_count(
            "omitted_fragment_observations",
            "capture summary is missing its omitted fragment observation count",
        )?,
        unmeasured_omitted_ranges: read_count(
            "unmeasured_omitted_ranges",
            "capture summary is missing its unmeasured range count",
        )?,
        omitted_state_observations: read_count(
            "omitted_state_observations",
            "capture summary is missing its omitted state observation count",
        )?,
    })
}

fn add_flow_coverage(
    total: &mut FlowAnalysisCoverage,
    next: &PerFlowCoverage,
) -> Result<(), Box<dyn Error>> {
    total.flows = add_counter(total.flows, 1)?;
    if next.complete {
        total.complete_flows = add_counter(total.complete_flows, 1)?;
    } else {
        total.incomplete_flows = add_counter(total.incomplete_flows, 1)?;
    }
    total.selected_flow_records = add_counter(total.selected_flow_records, next.selected_records)?;
    total.retained_flow_records = add_counter(total.retained_flow_records, next.retained_records)?;
    total.omitted_flow_records = add_counter(total.omitted_flow_records, next.omitted_records)?;
    if next.omitted_records != 0 {
        total.selection_truncated_flows = add_counter(total.selection_truncated_flows, 1)?;
    }
    if next.reconstruction_omissions.has_omissions() {
        total.reconstruction_omission_flows = add_counter(total.reconstruction_omission_flows, 1)?;
    }
    total.omitted_tcp_records = add_counter(
        total.omitted_tcp_records,
        next.reconstruction_omissions.omitted_tcp_records,
    )?;
    total.omitted_fragments = add_counter(
        total.omitted_fragments,
        next.reconstruction_omissions.omitted_fragments,
    )?;
    total.omitted_sequence_ranges = add_counter(
        total.omitted_sequence_ranges,
        next.reconstruction_omissions.omitted_sequence_ranges,
    )?;
    total.omitted_tcp_bytes = add_counter(
        total.omitted_tcp_bytes,
        next.reconstruction_omissions.omitted_tcp_bytes,
    )?;
    total.omitted_tcp_observations = add_counter(
        total.omitted_tcp_observations,
        next.reconstruction_omissions.omitted_tcp_observations,
    )?;
    total.omitted_fragment_bytes = add_counter(
        total.omitted_fragment_bytes,
        next.reconstruction_omissions.omitted_fragment_bytes,
    )?;
    total.omitted_fragment_observations = add_counter(
        total.omitted_fragment_observations,
        next.reconstruction_omissions.omitted_fragment_observations,
    )?;
    total.unmeasured_omitted_ranges = add_counter(
        total.unmeasured_omitted_ranges,
        next.reconstruction_omissions.unmeasured_omitted_ranges,
    )?;
    total.omitted_state_observations = add_counter(
        total.omitted_state_observations,
        next.reconstruction_omissions.omitted_state_observations,
    )?;
    for limit in &next.retention_limits {
        let count = match limit {
            RecordRetentionLimit::Frames => &mut total.frame_limited_flows,
            RecordRetentionLimit::Bytes => &mut total.byte_limited_flows,
            RecordRetentionLimit::Units => &mut total.unit_limited_flows,
        };
        *count = add_counter(*count, 1)?;
    }
    if next.reconstruction_omissions.omitted_sequence_ranges != 0 {
        total.range_omission_flows = add_counter(total.range_omission_flows, 1)?;
    }
    Ok(())
}

fn add_supplementary_page_coverage(
    total: &mut SupplementaryPageCoverage,
    next: l2_workbench::store::FlowPageCoverage,
) -> Result<(), Box<dyn Error>> {
    let total_pages = add_counter(total.pages, next.pages)?;
    let accounted_records = next
        .retained_records
        .checked_add(next.omitted_records)
        .ok_or("supplementary flow page record total overflow")?;
    if accounted_records != next.selected_records {
        return Err(invalid("supplementary page record counts are inconsistent"));
    }
    if (next.pages == 0) != (next.selected_records == 0) {
        return Err(invalid(
            "supplementary page count disagrees with selected records",
        ));
    }
    if total.reconstruction_omissions.cases != total_pages {
        return Err(invalid(
            "supplementary page reconstruction Case count disagrees with page count",
        ));
    }
    if next.pages != 0 {
        total.flows = add_counter(total.flows, 1)?;
    }
    total.pages = total_pages;
    total.selected_records = add_counter(total.selected_records, next.selected_records)?;
    total.retained_records = add_counter(total.retained_records, next.retained_records)?;
    total.omitted_records = add_counter(total.omitted_records, next.omitted_records)?;
    Ok(())
}

fn add_counter(total: u64, next: u64) -> Result<u64, Box<dyn Error>> {
    total
        .checked_add(next)
        .ok_or_else(|| invalid("full-source coverage count overflow"))
}

fn invalid(message: &'static str) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidData, message).into()
}

#[cfg(test)]
#[path = "../../tests/workbench/full_source.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/workbench/full_source_index.rs"]
mod index_tests;
