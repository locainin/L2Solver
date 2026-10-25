//! Deterministic candidate enumeration and report assembly

mod competitors;
mod execution;
mod printable;
mod receipts;

use self::{
    competitors::{apply_competitor_counts, competing_outputs},
    execution::{CandidateCoordinates, evaluate_parameter},
    printable::PrintableRunBudget,
    receipts::{retained_source_receipts, sample_receipt},
};
use super::{
    model::{DiscoveryError, DiscoveryLimit, DiscoveryPlan, DiscoveryReport, DiscoverySample},
    plan::{partition_samples, validate_plan, validate_samples},
};

pub(super) trait DiscoveryResultSink {
    fn records_receipts(&self) -> bool {
        true
    }

    fn begin(
        &mut self,
        plan: &DiscoveryPlan,
        identity: &super::model::DiscoveryIdentity,
        omitted: &[u64],
        input_bytes: usize,
        parameter_space_size: usize,
    ) -> Result<(), DiscoveryError>;
    fn sample_receipt(
        &mut self,
        receipt: &super::model::DiscoverySampleReceipt,
    ) -> Result<(), DiscoveryError>;
    fn output(
        &mut self,
        candidate_id: usize,
        partition: super::model::Partition,
        unit_index: usize,
        bytes: &[u8],
    ) -> Result<(), DiscoveryError>;
    fn printable_run(&mut self, run: &super::model::PrintableRun) -> Result<(), DiscoveryError>;
    fn candidate(
        &mut self,
        candidate: &super::model::DiscoveryCandidate,
    ) -> Result<(), DiscoveryError>;
}

/// Enumerate selected bit planes, byte offsets, reset behavior, and sample orders
///
/// Sample mappings must cover every byte exactly once; mixed identities and ambiguous input
/// fail before any candidate is attempted. The later control partition is transformed
/// independently, so checks describe consistency with that partition rather than acceptance
///
/// # Errors
/// Rejects invalid plans, ambiguous or unmapped samples, mixed evidence identities, or invalid checks
pub fn discover(
    samples: &[DiscoverySample<'_>],
    requested_plan: &DiscoveryPlan,
) -> Result<DiscoveryReport, DiscoveryError> {
    discover_with_identity(samples, requested_plan, None, Vec::new(), None)
}

pub(super) fn discover_to_sink(
    samples: &[DiscoverySample<'_>],
    requested_plan: &DiscoveryPlan,
    sink: &mut dyn DiscoveryResultSink,
) -> Result<DiscoveryReport, DiscoveryError> {
    discover_with_identity(samples, requested_plan, None, Vec::new(), Some(sink))
}

pub(super) fn discover_case_to_sink(
    samples: &[DiscoverySample<'_>],
    requested_plan: &DiscoveryPlan,
    direction: String,
    local_identity: String,
    omitted_empty_sample_ids: Vec<u64>,
    sink: &mut dyn DiscoveryResultSink,
) -> Result<DiscoveryReport, DiscoveryError> {
    let source_scope = samples
        .first()
        .map(|sample| sample.source_scope.clone())
        .ok_or(DiscoveryError::InvalidSelection)?;
    let identity = super::model::DiscoveryIdentity {
        source_scope,
        direction,
        local_identity,
    };
    discover_with_identity(
        samples,
        requested_plan,
        Some(&identity),
        omitted_empty_sample_ids,
        Some(sink),
    )
}

pub(super) fn discover_for_cohort(
    samples: &[DiscoverySample<'_>],
    requested_plan: &DiscoveryPlan,
    direction: String,
    local_identity: String,
    omitted_empty_sample_ids: Vec<u64>,
) -> Result<DiscoveryReport, DiscoveryError> {
    let source_scope = samples
        .first()
        .map(|sample| sample.source_scope.clone())
        .ok_or(DiscoveryError::InvalidSelection)?;
    let identity = super::model::DiscoveryIdentity {
        source_scope,
        direction,
        local_identity,
    };
    discover_with_identity(
        samples,
        requested_plan,
        Some(&identity),
        omitted_empty_sample_ids,
        None,
    )
}

pub(super) fn discover_with_identity(
    samples: &[DiscoverySample<'_>],
    requested_plan: &DiscoveryPlan,
    cohort_identity: Option<&super::model::DiscoveryIdentity>,
    omitted_empty_sample_ids: Vec<u64>,
    mut sink: Option<&mut dyn DiscoveryResultSink>,
) -> Result<DiscoveryReport, DiscoveryError> {
    let plan = validate_plan(requested_plan)?;
    let (identity, input_bytes) = validate_samples(samples, plan.max_input_bytes, cohort_identity)?;
    let partitions = partition_samples(samples);
    let (sample_receipts, retained_bytes) = if sink.is_some() {
        (Vec::new(), 0)
    } else {
        retained_source_receipts(
            samples,
            &partitions,
            &omitted_empty_sample_ids,
            plan.max_report_bytes,
        )?
    };
    let mut report = initial_report(
        identity,
        omitted_empty_sample_ids,
        sample_receipts,
        input_bytes,
        &plan,
    );
    let mut run_budget = PrintableRunBudget {
        maximum: if sink.is_some() {
            usize::MAX
        } else {
            plan.max_report_bytes
        },
        used: retained_bytes,
        next_id: 0,
        attempted: 0,
        complete: true,
        retain_runs: sink.is_none(),
    };

    if let Some(observer) = sink.as_mut() {
        emit_source_receipts(
            &mut **observer,
            requested_plan,
            &report,
            samples,
            &partitions,
            input_bytes,
            plan.parameter_space_size,
        )?;
    }

    'candidates: for width in &plan.widths {
        for phase in &plan.phases {
            for start_offset in &plan.start_offsets {
                for reset_mode in &plan.reset_modes {
                    for sample_order in &plan.sample_orders {
                        let coordinates = CandidateCoordinates {
                            width: *width,
                            phase: *phase,
                            start_offset: *start_offset,
                            reset_mode: *reset_mode,
                            sample_order: *sample_order,
                        };
                        if !evaluate_parameter(
                            samples,
                            &partitions,
                            &plan,
                            coordinates,
                            &mut report,
                            &mut run_budget,
                            &mut sink,
                        )? {
                            break 'candidates;
                        }
                    }
                }
            }
        }
    }
    finish_report(&mut report, &run_budget, sink.is_none());
    Ok(report)
}

fn finish_report(
    report: &mut DiscoveryReport,
    run_budget: &PrintableRunBudget,
    include_competing_outputs: bool,
) {
    report.report_bytes = run_budget.used;
    report.attempted_printable_runs = run_budget.attempted;
    report.printable_runs_complete = run_budget.complete;
    if !run_budget.complete {
        report.limits.push(DiscoveryLimit::PrintableRunReportBytes);
    }
    if include_competing_outputs {
        report.competing_outputs = competing_outputs(&report.candidates);
        apply_competitor_counts(&mut report.candidates);
    }
}

fn initial_report(
    identity: super::model::DiscoveryIdentity,
    omitted_empty_sample_ids: Vec<u64>,
    sample_receipts: Vec<super::model::DiscoverySampleReceipt>,
    input_bytes: usize,
    plan: &super::plan::ValidatedPlan,
) -> DiscoveryReport {
    DiscoveryReport {
        identity,
        sample_receipts,
        omitted_empty_sample_ids,
        parameter_space_size: plan.parameter_space_size,
        input_bytes,
        input_budget_bytes: plan.max_input_bytes,
        attempted_parameters: 0,
        attempted_transforms: 0,
        work_bytes: 0,
        work_budget_bytes: plan.max_work_bytes,
        candidate_budget: plan.max_candidates,
        report_bytes: 0,
        report_budget_bytes: plan.max_report_bytes,
        printable_runs_complete: true,
        attempted_printable_runs: 0,
        enumeration_complete: true,
        limits: Vec::new(),
        candidates: Vec::new(),
        competing_outputs: Vec::new(),
        limitations: vec![
            "Every mapping receipt identifies source bytes; bit positions follow the recorded selection parameters",
            "Length and ASCII values are measurements, and supplied constraints test only their stated predicates",
            "Discovery and control outputs do not establish covert communication, protocol validity, peer acceptance, or credential acceptance",
            "The parameter space is limited to the listed widths, phases, byte offsets, reset modes, sample orders, and checks",
        ],
    }
}

fn emit_source_receipts(
    sink: &mut dyn DiscoveryResultSink,
    requested_plan: &DiscoveryPlan,
    report: &DiscoveryReport,
    samples: &[DiscoverySample<'_>],
    partitions: &super::plan::Partitions,
    input_bytes: usize,
    parameter_space_size: usize,
) -> Result<(), DiscoveryError> {
    sink.begin(
        requested_plan,
        &report.identity,
        &report.omitted_empty_sample_ids,
        input_bytes,
        parameter_space_size,
    )?;
    if !sink.records_receipts() {
        return Ok(());
    }
    let mut control_indexes = std::collections::HashSet::new();
    control_indexes
        .try_reserve(partitions.control.len())
        .map_err(|_| DiscoveryError::AllocationFailed)?;
    control_indexes.extend(partitions.control.iter().copied());
    for (index, sample) in samples.iter().enumerate() {
        let partition = if control_indexes.contains(&index) {
            super::model::Partition::Control
        } else {
            super::model::Partition::Discovery
        };
        sink.sample_receipt(&sample_receipt(sample, partition)?)?;
    }
    Ok(())
}
