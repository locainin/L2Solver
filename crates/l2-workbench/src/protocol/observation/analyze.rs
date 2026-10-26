use super::budget::{add_saturating, can_retain_report, consume_work, omit_sample, reserve_work};
use super::error::ObservationError;
use super::length::{
    length_field_ranges, length_hypotheses, make_constraint, retain_integer_interpretations,
};
use super::limits::validate_limits;
use super::model::{
    ByteObservation, ObservationCoverage, ObservationInput, ObservationLimits, ObservationPlan,
    ObservationReport, PartialConstraint,
};
use super::provenance::{
    byte_observation_cost, byte_origins, copy_bytes, origin_check_count, validate_input,
};
use super::regions::{build_regions, collect_region_records};
use super::validation::{
    account_unadmitted_region_ranges, normalized_region_ranges, sample_ranges,
    validate_unique_sample_ids,
};
use crate::measurement::ByteOrder;
use crate::protocol::ByteRange;
use std::mem::size_of;

#[derive(Default)]
struct SampleIndexes {
    facts: Vec<(ByteRange, usize)>,
    interpretations: Vec<(ByteRange, ByteOrder, usize)>,
}

/// Collect bounded raw byte facts, numeric readings, and per-sample constraints
///
/// Byte equality is retained as a fact. Length relationships remain hypotheses,
/// and each sample receives an independent supported, contradicted, or untestable result
///
/// # Errors
/// Returns an error for duplicate admitted sample identifiers, invalid ranges or
/// provenance, limits above hard ceilings, or failed bounded allocations
pub fn observe(
    inputs: &[ObservationInput<'_>],
    plan: &ObservationPlan,
) -> Result<ObservationReport, ObservationError> {
    validate_limits(plan.limits)?;
    let mut report = new_report();
    let accepted = admit_inputs(inputs, plan.limits, &mut report.coverage)?;
    let hypotheses = length_hypotheses(plan.limits, &mut report.coverage)?;
    let field_ranges = length_field_ranges(&hypotheses)?;
    let region_ranges = normalized_region_ranges(plan, &mut report.coverage)?;
    let mut region_records = Vec::new();
    region_records
        .try_reserve(region_ranges.len())
        .map_err(|_| ObservationError::AllocationFailed {
            field: "region coverage records",
        })?;

    for input in &accepted {
        let sample_indexes = observe_sample_bytes(
            input,
            &field_ranges,
            &region_ranges,
            plan.limits,
            &mut report,
        )?;
        collect_region_records(
            input,
            &region_ranges,
            &sample_indexes.facts,
            plan.limits,
            &mut report.coverage,
            &mut region_records,
        )?;
        observe_sample_constraints(
            input,
            &hypotheses,
            &sample_indexes.interpretations,
            plan.limits,
            &mut report,
        )?;
    }

    account_unadmitted_region_ranges(&accepted, &region_ranges, &mut report.coverage)?;
    build_regions(
        region_records,
        &report.byte_observations,
        plan.limits,
        &mut report.coverage,
        &mut report.regions,
    )?;
    Ok(report)
}

fn new_report() -> ObservationReport {
    ObservationReport {
        byte_observations: Vec::new(),
        integer_interpretations: Vec::new(),
        partial_constraints: Vec::new(),
        regions: Vec::new(),
        coverage: ObservationCoverage {
            complete: true,
            ..ObservationCoverage::default()
        },
    }
}

fn admit_inputs<'input, 'data>(
    inputs: &'input [ObservationInput<'data>],
    limits: ObservationLimits,
    coverage: &mut ObservationCoverage,
) -> Result<Vec<&'input ObservationInput<'data>>, ObservationError> {
    coverage.samples_seen = inputs.len();
    let sample_count = inputs.len().min(limits.max_samples);
    // Bytes after this bounded sample window stay explicitly unmeasured
    validate_unique_sample_ids(
        inputs
            .iter()
            .take(sample_count)
            .map(|input| input.message.sample),
    )?;
    coverage.input_bytes_unmeasured_samples = inputs.len().saturating_sub(sample_count);
    if coverage.input_bytes_unmeasured_samples > 0 {
        coverage.omitted_samples = coverage.input_bytes_unmeasured_samples;
        coverage.complete = false;
    }

    let mut accepted = Vec::new();
    accepted
        .try_reserve(sample_count)
        .map_err(|_| ObservationError::AllocationFailed {
            field: "admitted observation samples",
        })?;
    let mut admitted_bytes = 0_usize;
    for input in inputs.iter().take(sample_count) {
        let message_length = input.message.bytes.len();
        add_saturating(
            &mut coverage.input_bytes_seen,
            message_length,
            &mut coverage.complete,
        );
        if message_length > limits.max_message_bytes {
            omit_sample(coverage, message_length);
            continue;
        }
        let Some(next_total) = admitted_bytes.checked_add(message_length) else {
            omit_sample(coverage, message_length);
            continue;
        };
        if next_total > limits.max_total_bytes {
            omit_sample(coverage, message_length);
            continue;
        }
        validate_input(input, limits)?;
        if let Some(context) = input.message.context.as_ref()
            && (context.source.len() > limits.max_identity_bytes
                || context.scope.len() > limits.max_identity_bytes)
        {
            coverage.omitted_contexts = coverage.omitted_contexts.saturating_add(1);
            coverage.omitted_context_bytes = coverage
                .omitted_context_bytes
                .saturating_add(context.source.len().saturating_add(context.scope.len()));
            coverage.complete = false;
        }
        admitted_bytes = next_total;
        coverage.samples_retained = coverage.samples_retained.saturating_add(1);
        accepted.push(input);
    }
    coverage.input_bytes_retained = admitted_bytes;
    Ok(accepted)
}

fn observe_sample_bytes(
    input: &ObservationInput<'_>,
    field_ranges: &[ByteRange],
    region_ranges: &[super::model::SampleRange],
    limits: ObservationLimits,
    report: &mut ObservationReport,
) -> Result<SampleIndexes, ObservationError> {
    let ranges = sample_ranges(input, field_ranges, region_ranges, limits)?;
    let mut indexes = SampleIndexes::default();
    indexes
        .facts
        .try_reserve(ranges.len().min(limits.max_byte_observations))
        .map_err(|_| ObservationError::AllocationFailed {
            field: "sample byte observation indices",
        })?;
    indexes
        .interpretations
        .try_reserve(
            field_ranges
                .len()
                .min(limits.max_byte_observations)
                .saturating_mul(2),
        )
        .map_err(|_| ObservationError::AllocationFailed {
            field: "sample integer interpretation indices",
        })?;
    for range in ranges {
        retain_byte_observation(input, range, field_ranges, limits, report, &mut indexes)?;
    }
    Ok(indexes)
}

fn retain_byte_observation(
    input: &ObservationInput<'_>,
    range: ByteRange,
    field_ranges: &[ByteRange],
    limits: ObservationLimits,
    report: &mut ObservationReport,
    indexes: &mut SampleIndexes,
) -> Result<(), ObservationError> {
    let copied_bytes = range.end.saturating_sub(range.start).max(1);
    if !reserve_work(&mut report.coverage, copied_bytes, limits.max_work_units) {
        report.coverage.omitted_byte_observations =
            report.coverage.omitted_byte_observations.saturating_add(1);
        report.coverage.omitted_origin_checks = report
            .coverage
            .omitted_origin_checks
            .saturating_add(origin_check_count(input));
        return Ok(());
    }
    let bytes = input
        .message
        .bytes
        .get(range.start..range.end)
        .ok_or(ObservationError::InvalidRange { range })?;
    let (origins, origin_complete, omitted_origins, omitted_origin_checks) =
        byte_origins(input, range, limits, &mut report.coverage)?;
    report.coverage.omitted_origins = report
        .coverage
        .omitted_origins
        .saturating_add(omitted_origins);
    report.coverage.omitted_origin_checks = report
        .coverage
        .omitted_origin_checks
        .saturating_add(omitted_origin_checks);
    if omitted_origins > 0 || omitted_origin_checks > 0 {
        report.coverage.complete = false;
    }
    let context = input
        .message
        .context
        .as_ref()
        .filter(|context| {
            context.source.len() <= limits.max_identity_bytes
                && context.scope.len() <= limits.max_identity_bytes
        })
        .cloned();
    let observation = ByteObservation {
        sample: input.message.sample,
        role: input.message.role,
        context,
        range,
        bytes: copy_bytes(bytes, "byte observation bytes")?,
        origins,
        origin_complete,
    };
    store_byte_fact(observation, field_ranges, limits, report, indexes)
}

fn store_byte_fact(
    observation: ByteObservation,
    field_ranges: &[ByteRange],
    limits: ObservationLimits,
    report: &mut ObservationReport,
    indexes: &mut SampleIndexes,
) -> Result<(), ObservationError> {
    let observation_cost = byte_observation_cost(&observation);
    if report.coverage.byte_observations_retained >= limits.max_byte_observations
        || !can_retain_report(&report.coverage, observation_cost, limits)
    {
        report.coverage.omitted_byte_observations =
            report.coverage.omitted_byte_observations.saturating_add(1);
        report.coverage.omitted_origins = report
            .coverage
            .omitted_origins
            .saturating_add(observation.origins.len());
        report.coverage.complete = false;
        return Ok(());
    }
    report
        .byte_observations
        .try_reserve(1)
        .map_err(|_| ObservationError::AllocationFailed {
            field: "byte observations",
        })?;
    let observation_index = report.byte_observations.len();
    if field_ranges.contains(&observation.range) {
        retain_integer_interpretations(
            observation.range,
            observation_index,
            &observation.bytes,
            limits,
            report,
            &mut indexes.interpretations,
        )?;
    }
    indexes.facts.push((observation.range, observation_index));
    report.coverage.report_bytes_retained = report
        .coverage
        .report_bytes_retained
        .saturating_add(observation_cost);
    report.coverage.byte_observations_retained =
        report.coverage.byte_observations_retained.saturating_add(1);
    report.coverage.origins_retained = report
        .coverage
        .origins_retained
        .saturating_add(observation.origins.len());
    report.byte_observations.push(observation);
    Ok(())
}

fn observe_sample_constraints(
    input: &ObservationInput<'_>,
    hypotheses: &[crate::protocol::FramingKind],
    interpretation_indices: &[(ByteRange, ByteOrder, usize)],
    limits: ObservationLimits,
    report: &mut ObservationReport,
) -> Result<(), ObservationError> {
    for (candidate_index, hypothesis) in hypotheses.iter().enumerate() {
        if !consume_work(&mut report.coverage, limits.max_work_units) {
            let skipped = hypotheses.len().saturating_sub(candidate_index);
            report.coverage.omitted_constraints =
                report.coverage.omitted_constraints.saturating_add(skipped);
            report.coverage.omitted_work_units = report
                .coverage
                .omitted_work_units
                .saturating_add(skipped.saturating_sub(1));
            report.coverage.complete = false;
            break;
        }
        let constraint = make_constraint(
            input,
            hypothesis,
            interpretation_indices,
            &report.integer_interpretations,
        );
        let cost = size_of::<PartialConstraint>();
        if report.coverage.constraints_retained >= limits.max_constraints
            || !can_retain_report(&report.coverage, cost, limits)
        {
            report.coverage.omitted_constraints =
                report.coverage.omitted_constraints.saturating_add(1);
            report.coverage.complete = false;
            continue;
        }
        report.partial_constraints.try_reserve(1).map_err(|_| {
            ObservationError::AllocationFailed {
                field: "partial constraints",
            }
        })?;
        report.coverage.report_bytes_retained =
            report.coverage.report_bytes_retained.saturating_add(cost);
        report.coverage.constraints_retained =
            report.coverage.constraints_retained.saturating_add(1);
        report.partial_constraints.push(constraint);
    }
    Ok(())
}
