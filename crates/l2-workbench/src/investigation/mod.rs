//! Case construction joins literal packet facts, candidate bytes, and reproducible analysis

mod applications;
mod artifacts;
mod carriers;
mod ftp;
mod graph;
mod network;
mod scope;
mod timestamps;

pub use scope::RecordWindow;
use scope::Scope;

use crate::{
    evidence::{Case, EvidenceError},
    job::MemoryBudget,
    reconstruction::{InputSelection, Limits, ReconstructionReport, Reconstructor},
};
use l2_capture::CapturedFrame;
use std::{collections::BTreeMap, error::Error};

pub struct Record {
    pub number: u32,
    pub frame: CapturedFrame,
}

/// Source hashing and clean EOF are the responsibility of the capture reader
#[derive(Clone, Copy)]
pub struct BuildInput<'a> {
    pub label: &'a str,
    pub length: u64,
    pub sha256_hex: &'a str,
    pub records: &'a [Record],
    pub frames_seen: u64,
}

pub struct BuildResult {
    pub case: Case,
    pub complete: bool,
}

/// Build a bounded evidence case from retained records of one fully read source
///
/// # Errors
/// Rejects inconsistent record order, source locations, and unsupported case metadata
pub fn build(input: BuildInput<'_>) -> Result<BuildResult, Box<dyn Error>> {
    build_with_limits(input, Limits::default())
}

/// Build a capture-prefix case using explicit record and reconstruction budgets
///
/// Independent evidence and application limits can still omit analysis results
///
/// # Errors
/// Rejects inconsistent records, unsupported case metadata, and zero budgets
pub fn build_with_limits(
    input: BuildInput<'_>,
    limits: Limits,
) -> Result<BuildResult, Box<dyn Error>> {
    build_scoped(input, Scope::capture(input.frames_seen), limits, None)
}

/// Analyze a complete selected record window while preserving original record numbers
///
/// # Errors
/// Rejects a missing, misnumbered, or out-of-source window
pub fn build_window(
    input: BuildInput<'_>,
    window: RecordWindow,
) -> Result<BuildResult, Box<dyn Error>> {
    build_scoped(
        input,
        Scope::window(input, window)?,
        Limits::default(),
        None,
    )
}

/// Analyze explicitly selected records while keeping their original packet numbers
///
/// `selected_frames` includes any selected records omitted by the caller's memory budget
///
/// # Errors
/// Rejects invalid record order, source bounds, or inconsistent selection counts
pub fn build_selected(
    input: BuildInput<'_>,
    selected_frames: u64,
) -> Result<BuildResult, Box<dyn Error>> {
    build_selected_with_limits(input, selected_frames, Limits::default())
}

/// Analyze explicitly selected records using caller supplied reconstruction budgets
///
/// `selected_frames` includes selected records omitted by the caller's memory budget
///
/// # Errors
/// Rejects invalid record order, source bounds, inconsistent counts, and zero budgets
pub fn build_selected_with_limits(
    input: BuildInput<'_>,
    selected_frames: u64,
    limits: Limits,
) -> Result<BuildResult, Box<dyn Error>> {
    build_scoped(
        input,
        Scope::selection(input, selected_frames)?,
        limits,
        None,
    )
}

/// Analyze selected records with a shared budget for the retained evidence Case
///
/// Reconstruction inputs, reports, and parser scratch require their own charges
///
/// # Errors
/// Returns an admission error or any selected-record and reconstruction error
pub fn build_selected_with_limits_and_memory(
    input: BuildInput<'_>,
    selected_frames: u64,
    limits: Limits,
    budget: &MemoryBudget,
) -> Result<BuildResult, Box<dyn Error>> {
    build_scoped(
        input,
        Scope::selection(input, selected_frames)?,
        limits,
        Some(budget),
    )
}

fn build_scoped(
    input: BuildInput<'_>,
    scope: Scope,
    limits: Limits,
    budget: Option<&MemoryBudget>,
) -> Result<BuildResult, Box<dyn Error>> {
    let mut case = if let Some(budget) = budget {
        Case::with_memory_budget(budget)?
    } else {
        Case::new()
    };
    let source = case.add_source(input.label, "capture", input.length, input.sha256_hex, None)?;
    let mut reconstruction = Reconstructor::with_limits_at(limits, scope.first)?;
    let mut records = BTreeMap::new();
    for record in input.records {
        let accepted = match scope.mode {
            InputSelection::ConsecutiveRecords => {
                reconstruction.observe(record.number, &record.frame)?
            }
            InputSelection::SelectedRecords => {
                reconstruction.observe_selected(record.number, &record.frame)?
            }
        };
        if !accepted {
            break;
        }
        records.insert(record.number, &record.frame);
    }
    if input.frames_seen < u64::try_from(input.records.len())? {
        return Err("capture count is smaller than retained record count".into());
    }
    let report = reconstruction.finish()?;
    let omitted = scope.selected - u64::try_from(records.len())?;
    let mut complete = report.complete && omitted == 0;
    if omitted != 0 {
        case.add_limitation(&format!("{omitted} capture records were omitted after the retention budget; later absence and event chains are unresolved"))?;
    }
    if scope.window.is_some() {
        case.add_limitation("This selected record window preserves original source positions; absence, protocol state, and event chains outside the window remain unresolved")?;
    }
    if scope.mode == InputSelection::SelectedRecords {
        case.add_limitation("This case contains explicitly selected original records; absence and event chains outside that selection remain unresolved")?;
    }
    for limitation in [
        "Capture order and header addresses do not establish ownership, delivery, causality, or malicious intent",
        "Checksums, peer processing, decryption authenticity, and external credential acceptance are not validated",
        "Fragment IDs and TCP tuples can be reused; reconstructed bytes are candidates and endpoint overlap policy is unresolved",
        "Length fields, bit planes, capitalization, and timing are measurements; matching hypotheses are not protocol or covert-channel proof",
    ] {
        case.add_limitation(limitation)?;
    }
    let mut context = graph::Context {
        case: &mut case,
        source: &source,
        records: &records,
        packet_nodes: BTreeMap::new(),
        incomplete: false,
    };
    let retained = populate(&mut context, input.frames_seen, omitted, scope, &report);
    if let Err(error) = retained {
        if quota_error(error.as_ref()) {
            complete = false;
            context.case.add_limitation(&format!("Case analysis stopped after an evidence resource budget ({error}); remaining results were omitted"))?;
        } else {
            return Err(error);
        }
    }
    complete &= !context.incomplete;
    if !complete {
        case.mark_incomplete("Some capture evidence or analysis is incomplete; case limitations identify omitted or unsupported inputs")?;
    }
    case.validate()?;
    Ok(BuildResult { case, complete })
}

fn populate(
    context: &mut graph::Context<'_>,
    frames_seen: u64,
    omitted: u64,
    scope: Scope,
    report: &ReconstructionReport,
) -> Result<(), Box<dyn Error>> {
    context.case.add_node("capture_summary", None, Vec::new(), serde_json::json!({
        "frames_seen": frames_seen, "retained_frames": context.records.len(), "omitted_frames": omitted,
        "record_window": scope.window, "outside_scope_frames": frames_seen - scope.selected,
        "input_selection":scope.mode,
        "reconstruction_limits": report.limits,
        "reconstruction_complete": report.complete, "unsupported_transport_frames": report.unsupported_frames,
        "omitted_fragments": report.omitted_fragments, "omitted_tcp_records": report.omitted_tcp_records,
        "omitted_sequence_ranges": report.omitted_ranges,
        "unmeasured_omitted_ranges": report.unmeasured_omitted_ranges,
        "omitted_tcp_bytes": report.omitted_tcp_bytes,
        "omitted_tcp_observations": report.omitted_tcp_observations,
        "omitted_fragment_bytes": report.omitted_fragment_bytes,
        "omitted_fragment_observations": report.omitted_fragment_observations,
        "omitted_state_observations": report.omitted_state_observations,
    }))?;
    network::packets(context)?;
    network::forensics(context)?;
    let sessions = network::reconstruction(context, report)?;
    ftp::add(context, report, &sessions)?;
    carriers::add(context)?;
    Ok(())
}

fn quota_error(error: &(dyn Error + 'static)) -> bool {
    error.downcast_ref::<EvidenceError>().is_some_and(|error| {
        matches!(
            error,
            EvidenceError::QuotaExceeded { .. }
                | EvidenceError::NodeDetailsTooLarge { .. }
                | EvidenceError::TotalDetailsTooLarge { .. }
        )
    })
}
