//! Candidate execution and partition summaries

use super::DiscoveryResultSink;
use super::{
    super::{
        model::{
            BitMappingReceipt, CaseHypothesis, ConstraintKind, ConstraintSummary,
            DiscoveryCandidate, DiscoveryError, DiscoveryLimit, DiscoveryReport, DiscoverySample,
            LengthHypothesis, Partition, PartitionSummary, ResetMode, SampleOrder,
        },
        plan::{Partitions, ValidatedPlan, WorkUnit, make_units, units_work},
    },
    printable::{PrintableRunBudget, PrintableRunContext, append_printable_runs},
};
use crate::derivation::{self, BitRemainder, Constraint, ConstraintStatus};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Clone, Copy)]
pub(super) struct CandidateCoordinates {
    pub(super) width: u8,
    pub(super) phase: u8,
    pub(super) start_offset: usize,
    pub(super) reset_mode: ResetMode,
    pub(super) sample_order: SampleOrder,
}
#[derive(Clone, Copy)]
pub(super) struct SummarySpec<'a> {
    pub(super) width: u8,
    pub(super) phase: u8,
    pub(super) start_offset: usize,
    pub(super) remainder: BitRemainder,
    pub(super) constraints: &'a [Constraint],
    pub(super) minimum_run_bytes: usize,
    pub(super) partition: Partition,
    pub(super) candidate_id: usize,
}

pub(super) fn evaluate_parameter(
    samples: &[DiscoverySample<'_>],
    partitions: &Partitions,
    plan: &ValidatedPlan,
    coordinates: CandidateCoordinates,
    report: &mut DiscoveryReport,
    budget: &mut PrintableRunBudget,
    sink: &mut Option<&mut dyn DiscoveryResultSink>,
) -> Result<bool, DiscoveryError> {
    if report.attempted_parameters >= plan.max_candidates {
        report.enumeration_complete = false;
        report.limits.push(DiscoveryLimit::CandidateCount);
        return Ok(false);
    }
    let CandidateCoordinates {
        width,
        phase,
        start_offset,
        reset_mode,
        sample_order,
    } = coordinates;
    let discovery_units = make_units(samples, &partitions.discovery, reset_mode, sample_order)?;
    let control_units = make_units(samples, &partitions.control, reset_mode, sample_order)?;
    let estimated_work = candidate_work(&discovery_units, &control_units, coordinates, plan)?;
    let Some(next_work_bytes) = report
        .work_bytes
        .checked_add(estimated_work)
        .filter(|next| *next <= plan.max_work_bytes)
    else {
        report.enumeration_complete = false;
        report.limits.push(DiscoveryLimit::WorkBytes);
        return Ok(false);
    };
    let id = report.attempted_parameters;
    report.attempted_parameters += 1;
    report.work_bytes = next_work_bytes;
    let spec = SummarySpec {
        width,
        phase,
        start_offset,
        remainder: plan.remainder,
        constraints: &plan.constraints,
        minimum_run_bytes: plan.minimum_printable_run_bytes,
        partition: Partition::Discovery,
        candidate_id: id,
    };
    let discovery = summarize_partition(
        samples,
        &discovery_units,
        spec,
        &mut report.attempted_transforms,
        budget,
        &mut *sink,
    )?;
    let control = if control_units.is_empty() {
        None
    } else {
        Some(summarize_partition(
            samples,
            &control_units,
            SummarySpec {
                partition: Partition::Control,
                ..spec
            },
            &mut report.attempted_transforms,
            budget,
            &mut *sink,
        )?)
    };
    let candidate = make_candidate(id, coordinates, plan, discovery, control, estimated_work)?;
    if let Some(observer) = sink.as_mut() {
        observer.candidate(&candidate)?;
    } else {
        report.candidates.push(candidate);
    }
    Ok(true)
}

fn make_candidate(
    id: usize,
    coordinates: CandidateCoordinates,
    plan: &ValidatedPlan,
    discovery: PartitionSummary,
    control: Option<PartitionSummary>,
    work_bytes: usize,
) -> Result<DiscoveryCandidate, DiscoveryError> {
    let CandidateCoordinates {
        width,
        phase,
        start_offset,
        reset_mode,
        sample_order,
    } = coordinates;
    Ok(DiscoveryCandidate {
        id,
        width,
        phase,
        source_byte_offset: start_offset,
        reset_mode,
        sample_order,
        bit_mapping: BitMappingReceipt {
            start_bit: start_offset
                .checked_mul(8)
                .ok_or(DiscoveryError::InvalidPlan("source byte offset overflowed"))?,
            stride_bits: 8,
            phase,
            bits_per_byte: width,
            remainder: plan.remainder,
        },
        discovery: Some(discovery),
        control,
        competitor_count: 0,
        work_bytes,
    })
}

fn candidate_work(
    discovery_units: &[WorkUnit],
    control_units: &[WorkUnit],
    coordinates: CandidateCoordinates,
    plan: &ValidatedPlan,
) -> Result<usize, DiscoveryError> {
    let CandidateCoordinates {
        width,
        start_offset,
        ..
    } = coordinates;
    units_work(
        discovery_units,
        width,
        start_offset,
        plan.remainder,
        plan.constraints.len(),
    )?
    .checked_add(units_work(
        control_units,
        width,
        start_offset,
        plan.remainder,
        plan.constraints.len(),
    )?)
    .ok_or(DiscoveryError::InvalidPlan("work estimate overflowed"))
}

fn summarize_partition(
    samples: &[DiscoverySample<'_>],
    units: &[WorkUnit],
    spec: SummarySpec<'_>,
    attempted_transforms: &mut usize,
    run_budget: &mut PrintableRunBudget,
    sink: &mut Option<&mut dyn DiscoveryResultSink>,
) -> Result<PartitionSummary, DiscoveryError> {
    let SummarySpec {
        width,
        phase,
        start_offset,
        remainder,
        constraints,
        ..
    } = spec;
    let mut output_hasher = Sha256::new();
    let mut successful_lengths = BTreeSet::new();
    let mut input_lengths = Vec::new();
    input_lengths
        .try_reserve_exact(units.len())
        .map_err(|_| DiscoveryError::AllocationFailed)?;
    let mut equal_length_units = 0;
    let mut failed_units = 0;
    let mut output_length = 0_usize;
    let mut case = CaseHypothesis::default();
    let mut printable_runs = Vec::new();
    let mut printable_runs_omitted = 0_usize;
    let mut constraint_counts = constraint_summaries(constraints);

    for (unit_index, unit) in units.iter().enumerate() {
        *attempted_transforms = attempted_transforms
            .checked_add(1)
            .ok_or(DiscoveryError::InvalidPlan("transform count overflowed"))?;
        input_lengths.push(unit.input_length);
        let Some(output) = transform_unit(samples, unit, width, phase, start_offset, remainder)?
        else {
            mark_failed_unit(&mut failed_units, &mut constraint_counts);
            continue;
        };
        successful_lengths.insert(output.len());
        output_length = output_length
            .checked_add(output.len())
            .ok_or(DiscoveryError::InvalidPlan("output length overflowed"))?;
        if unit.input_length == output.len() {
            equal_length_units += 1;
        }
        append_case_counts(&mut case, &output);
        output_hasher.update(&output);
        if let Some(observer) = sink.as_mut() {
            observer.output(spec.candidate_id, spec.partition, unit_index, &output)?;
        }
        let checks = derivation::check_constraints(&output, constraints)?;
        update_constraint_counts(&mut constraint_counts, &checks);
        append_printable_runs(
            &PrintableRunContext {
                samples,
                unit_index,
                unit,
                output: &output,
                spec,
            },
            run_budget,
            &mut printable_runs,
            &mut printable_runs_omitted,
            &mut *sink,
        )?;
    }
    Ok(PartitionSummary {
        unit_count: units.len(),
        failed_units,
        output_length,
        output_sha256: (failed_units == 0 && !units.is_empty())
            .then(|| format!("{:x}", output_hasher.finalize())),
        lengths: length_hypothesis(&input_lengths, &successful_lengths, equal_length_units),
        case,
        constraints: constraint_counts,
        printable_runs,
        printable_runs_omitted,
    })
}

fn length_hypothesis(
    input_lengths: &[usize],
    successful_lengths: &BTreeSet<usize>,
    equal_length_units: usize,
) -> LengthHypothesis {
    LengthHypothesis {
        input_minimum: input_lengths.iter().copied().min(),
        input_maximum: input_lengths.iter().copied().max(),
        output_minimum: successful_lengths.first().copied(),
        output_maximum: successful_lengths.last().copied(),
        distinct_output_lengths: successful_lengths.len(),
        equal_length_units,
    }
}

fn mark_failed_unit(failed_units: &mut usize, constraint_counts: &mut [ConstraintSummary]) {
    *failed_units += 1;
    for constraint in constraint_counts {
        constraint.not_evaluated += 1;
    }
}

fn update_constraint_counts(
    counts: &mut [ConstraintSummary],
    checks: &[crate::derivation::ConstraintReport],
) {
    for (summary, result) in counts.iter_mut().zip(checks) {
        match result.status {
            ConstraintStatus::Satisfied => summary.satisfied += 1,
            ConstraintStatus::Violated { .. } => summary.violated += 1,
            ConstraintStatus::Invalid { .. } => summary.invalid += 1,
            ConstraintStatus::NotEvaluated { .. } => summary.not_evaluated += 1,
        }
    }
}

fn constraint_summaries(constraints: &[Constraint]) -> Vec<ConstraintSummary> {
    constraints
        .iter()
        .enumerate()
        .map(|(index, constraint)| ConstraintSummary {
            constraint_index: index,
            kind: constraint_kind(constraint),
            satisfied: 0,
            violated: 0,
            invalid: 0,
            not_evaluated: 0,
        })
        .collect()
}

fn transform_unit(
    samples: &[DiscoverySample<'_>],
    unit: &WorkUnit,
    width: u8,
    phase: u8,
    start_offset: usize,
    remainder: BitRemainder,
) -> Result<Option<Vec<u8>>, DiscoveryError> {
    let mut slices = Vec::new();
    slices
        .try_reserve_exact(unit.sample_indexes.len())
        .map_err(|_| DiscoveryError::AllocationFailed)?;
    let mut skipped = start_offset;
    for sample_index in &unit.sample_indexes {
        let sample = samples
            .get(*sample_index)
            .ok_or(DiscoveryError::InvalidSelection)?;
        if skipped >= sample.bytes.len() {
            skipped -= sample.bytes.len();
            continue;
        }
        slices.push(
            sample
                .bytes
                .get(skipped..)
                .ok_or(DiscoveryError::InvalidSelection)?,
        );
        skipped = 0;
    }
    let selected_length = unit.input_length.saturating_sub(start_offset);
    let output_length = selected_output_length(selected_length, width, remainder)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(output_length)
        .map_err(|_| DiscoveryError::AllocationFailed)?;
    let group_width = usize::from(width);
    let maximum_chunk = derivation::MAX_INPUT_BYTES
        .checked_div(group_width)
        .and_then(|groups| groups.checked_mul(group_width))
        .filter(|length| *length > 0)
        .ok_or(DiscoveryError::InvalidPlan(
            "bit width produced an invalid chunk size",
        ))?;
    let mut source = SliceCursor::new(&slices);
    let mut remaining = selected_length;

    while remaining > 0 {
        let chunk_length = remaining.min(maximum_chunk);
        let final_chunk = chunk_length == remaining;
        let chunk_slices = source.take(chunk_length)?;
        let chunk_remainder = if final_chunk {
            remainder
        } else {
            BitRemainder::Reject
        };
        let Ok(transformed) = derivation::select_bit_plane_chunks(
            chunk_slices,
            phase,
            width,
            chunk_remainder,
            derivation::MAX_OUTPUT_BYTES,
        ) else {
            return Ok(None);
        };
        output.extend_from_slice(&transformed);
        remaining -= chunk_length;
    }
    Ok(Some(output))
}

struct SliceCursor<'a> {
    slices: &'a [&'a [u8]],
    index: usize,
    offset: usize,
}

impl<'a> SliceCursor<'a> {
    const fn new(slices: &'a [&'a [u8]]) -> Self {
        Self {
            slices,
            index: 0,
            offset: 0,
        }
    }

    fn take(&mut self, mut length: usize) -> Result<Vec<&'a [u8]>, DiscoveryError> {
        let mut result = Vec::new();
        result
            .try_reserve_exact(self.slices.len())
            .map_err(|_| DiscoveryError::AllocationFailed)?;
        while length > 0 {
            let slice = self
                .slices
                .get(self.index)
                .ok_or(DiscoveryError::InvalidSelection)?;
            let available = slice
                .len()
                .checked_sub(self.offset)
                .ok_or(DiscoveryError::InvalidSelection)?;
            if available == 0 {
                self.index += 1;
                self.offset = 0;
                continue;
            }
            let take = available.min(length);
            result.push(
                slice
                    .get(self.offset..self.offset + take)
                    .ok_or(DiscoveryError::InvalidSelection)?,
            );
            self.offset += take;
            length -= take;
            if self.offset == slice.len() {
                self.index += 1;
                self.offset = 0;
            }
        }
        Ok(result)
    }
}

fn selected_output_length(
    selected_bytes: usize,
    width: u8,
    remainder: BitRemainder,
) -> Result<usize, DiscoveryError> {
    let width = usize::from(width);
    let complete = selected_bytes / width;
    let partial = !selected_bytes.is_multiple_of(width);
    if partial && matches!(remainder, BitRemainder::ZeroFill | BitRemainder::OneFill) {
        complete
            .checked_add(1)
            .ok_or(DiscoveryError::InvalidPlan("output length overflowed"))
    } else {
        Ok(complete)
    }
}

fn append_case_counts(summary: &mut CaseHypothesis, bytes: &[u8]) {
    for byte in bytes {
        if byte.is_ascii_uppercase() {
            summary.ascii_letters += 1;
            summary.uppercase_letters += 1;
        } else if byte.is_ascii_lowercase() {
            summary.ascii_letters += 1;
            summary.lowercase_letters += 1;
        } else if byte.is_ascii() {
            summary.other_ascii_bytes += 1;
        } else {
            summary.non_ascii_bytes += 1;
        }
    }
}

const fn constraint_kind(constraint: &Constraint) -> ConstraintKind {
    match constraint {
        Constraint::Length { .. } => ConstraintKind::Length,
        Constraint::Prefix { .. } => ConstraintKind::Prefix,
        Constraint::Sha256 { .. } => ConstraintKind::Sha256,
        Constraint::Utf8 {} => ConstraintKind::Utf8,
        Constraint::Json {} => ConstraintKind::Json,
        Constraint::Crc32 { .. } => ConstraintKind::Crc32,
        Constraint::AesGcm { .. } => ConstraintKind::AesGcm,
    }
}
