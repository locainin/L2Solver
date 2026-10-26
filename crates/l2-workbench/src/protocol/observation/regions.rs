use super::budget::{can_retain_report, consume_work, reserve_work};
use super::error::ObservationError;
use super::model::{
    ByteObservation, ObservationCohort, ObservationCoverage, ObservationInput, ObservationLimits,
    RegionCoverage, RegionObservation, RegionValue, SampleRange,
};
use super::validation::region_ranges_for_sample;
use crate::protocol::ByteRange;
use std::cmp::Ordering;
use std::mem::size_of;
#[derive(Clone, Debug)]
pub(super) struct RegionRequestRecord {
    cohort: ObservationCohort,
    range: ByteRange,
    sample: u64,
    outcome: RegionRequestOutcome,
}

#[derive(Clone, Copy, Debug)]
enum RegionRequestOutcome {
    Observed { observation_index: usize },
    Untestable,
    Omitted,
}

pub(super) fn collect_region_records(
    input: &ObservationInput<'_>,
    region_ranges: &[SampleRange],
    fact_indices: &[(ByteRange, usize)],
    limits: ObservationLimits,
    coverage: &mut ObservationCoverage,
    records: &mut Vec<RegionRequestRecord>,
) -> Result<(), ObservationError> {
    for sample_range in region_ranges_for_sample(region_ranges, input.message.sample)? {
        if let Some(record) =
            collect_region_record(input, sample_range, fact_indices, limits, coverage)?
        {
            push_region_record(records, record)?;
        }
    }
    Ok(())
}

fn collect_region_record(
    input: &ObservationInput<'_>,
    sample_range: &SampleRange,
    fact_indices: &[(ByteRange, usize)],
    limits: ObservationLimits,
    coverage: &mut ObservationCoverage,
) -> Result<Option<RegionRequestRecord>, ObservationError> {
    if !consume_work(coverage, limits.max_work_units) {
        coverage.omitted_region_occurrences = coverage.omitted_region_occurrences.saturating_add(1);
        return Ok(None);
    }
    let Some(context) = input.message.context.as_ref() else {
        omit_unscoped_region(coverage);
        return Ok(None);
    };
    if context.source.is_empty()
        || context.scope.is_empty()
        || context.source.len() > limits.max_identity_bytes
        || context.scope.len() > limits.max_identity_bytes
    {
        omit_unscoped_region(coverage);
        return Ok(None);
    }
    // Session stays on the byte fact while source, scope, and direction form the comparison key
    let cohort = ObservationCohort::from(context);
    let width = sample_range
        .range
        .end
        .checked_sub(sample_range.range.start)
        .ok_or(ObservationError::InvalidRange {
            range: sample_range.range,
        })?;
    let outcome = if width > limits.max_region_width {
        RegionRequestOutcome::Omitted
    } else if sample_range.range.end > input.message.bytes.len() {
        coverage.untestable_region_occurrences =
            coverage.untestable_region_occurrences.saturating_add(1);
        RegionRequestOutcome::Untestable
    } else if let Some((_, observation_index)) = fact_indices
        .iter()
        .find(|(range, _)| *range == sample_range.range)
    {
        RegionRequestOutcome::Observed {
            observation_index: *observation_index,
        }
    } else {
        RegionRequestOutcome::Omitted
    };
    Ok(Some(RegionRequestRecord {
        cohort,
        range: sample_range.range,
        sample: sample_range.sample,
        outcome,
    }))
}

const fn omit_unscoped_region(coverage: &mut ObservationCoverage) {
    coverage.unscoped_region_occurrences = coverage.unscoped_region_occurrences.saturating_add(1);
    coverage.omitted_region_occurrences = coverage.omitted_region_occurrences.saturating_add(1);
    coverage.complete = false;
}
fn push_region_record(
    records: &mut Vec<RegionRequestRecord>,
    record: RegionRequestRecord,
) -> Result<(), ObservationError> {
    records
        .try_reserve(1)
        .map_err(|_| ObservationError::AllocationFailed {
            field: "region request records",
        })?;
    records.push(record);
    Ok(())
}
pub(super) fn build_regions(
    mut records: Vec<RegionRequestRecord>,
    observations: &[ByteObservation],
    limits: ObservationLimits,
    coverage: &mut ObservationCoverage,
    output: &mut Vec<RegionObservation>,
) -> Result<(), ObservationError> {
    let Some(sort_work) = estimate_sort_work(records.len(), 1) else {
        omit_region_records(records, coverage);
        return Ok(());
    };
    if !reserve_work(coverage, sort_work, limits.max_work_units) {
        omit_region_records(records, coverage);
        return Ok(());
    }
    records.sort_by(|left, right| {
        left.cohort
            .cmp(&right.cohort)
            .then_with(|| left.range.cmp(&right.range))
            .then_with(|| left.sample.cmp(&right.sample))
    });
    let mut records = records.into_iter().peekable();
    while let Some(first) = records.next() {
        let cohort = first.cohort.clone();
        let range = first.range;
        let mut records_in_group = Vec::new();
        records_in_group
            .try_reserve(1)
            .map_err(|_| ObservationError::AllocationFailed {
                field: "region group records",
            })?;
        records_in_group.push(first);
        while records
            .peek()
            .is_some_and(|next| next.cohort == cohort && next.range == range)
        {
            if let Some(record) = records.next() {
                records_in_group.try_reserve(1).map_err(|_| {
                    ObservationError::AllocationFailed {
                        field: "region group records",
                    }
                })?;
                records_in_group.push(record);
            }
        }
        let Some(region) = build_region(
            cohort,
            range,
            records_in_group,
            observations,
            limits,
            coverage,
        )?
        else {
            continue;
        };
        output
            .try_reserve(1)
            .map_err(|_| ObservationError::AllocationFailed {
                field: "region observations",
            })?;
        output.push(region);
    }
    Ok(())
}

fn build_region(
    cohort: ObservationCohort,
    range: ByteRange,
    mut records: Vec<RegionRequestRecord>,
    observations: &[ByteObservation],
    limits: ObservationLimits,
    coverage: &mut ObservationCoverage,
) -> Result<Option<RegionObservation>, ObservationError> {
    let cost = size_of::<RegionObservation>()
        .saturating_add(cohort.source.len())
        .saturating_add(cohort.scope.len());
    if !can_retain_report(coverage, cost, limits) {
        coverage.complete = false;
        for record in records {
            if matches!(record.outcome, RegionRequestOutcome::Untestable) {
                continue;
            }
            increment_omitted_region(coverage);
        }
        return Ok(None);
    }
    coverage.report_bytes_retained = coverage.report_bytes_retained.saturating_add(cost);
    let mut region = RegionObservation {
        cohort,
        range,
        values: Vec::new(),
        coverage: RegionCoverage::default(),
    };
    let Some(sort_work) = estimate_sort_work(records.len(), range.end - range.start) else {
        omit_group_records(records, &mut region, coverage);
        return Ok(Some(region));
    };
    if !reserve_work(coverage, sort_work, limits.max_work_units) {
        omit_group_records(records, &mut region, coverage);
        return Ok(Some(region));
    }
    records.sort_by(|left, right| {
        compare_region_values(left, right, observations)
            .then_with(|| left.sample.cmp(&right.sample))
    });
    let mut last_value_index = None;
    let mut last_value_retained = false;
    for record in records {
        region.coverage.requested_occurrences =
            region.coverage.requested_occurrences.saturating_add(1);
        match record.outcome {
            RegionRequestOutcome::Untestable => {
                region.coverage.untestable_occurrences =
                    region.coverage.untestable_occurrences.saturating_add(1);
            }
            RegionRequestOutcome::Omitted => {
                region.coverage.omitted_occurrences =
                    region.coverage.omitted_occurrences.saturating_add(1);
                increment_omitted_region(coverage);
            }
            RegionRequestOutcome::Observed { observation_index } => {
                retain_region_occurrence(
                    observation_index,
                    observations,
                    limits,
                    &mut region,
                    &mut last_value_index,
                    &mut last_value_retained,
                    coverage,
                )?;
            }
        }
    }
    Ok(Some(region))
}

fn estimate_sort_work(items: usize, value_width: usize) -> Option<usize> {
    if items < 2 {
        return Some(0);
    }
    let levels = usize::BITS - (items - 1).leading_zeros();
    items
        .checked_mul(usize::try_from(levels).ok()?)?
        .checked_mul(value_width)
}

fn omit_region_records(records: Vec<RegionRequestRecord>, coverage: &mut ObservationCoverage) {
    for record in records {
        if !matches!(record.outcome, RegionRequestOutcome::Untestable) {
            increment_omitted_region(coverage);
        }
    }
}

fn omit_group_records(
    records: Vec<RegionRequestRecord>,
    region: &mut RegionObservation,
    coverage: &mut ObservationCoverage,
) {
    for record in records {
        region.coverage.requested_occurrences =
            region.coverage.requested_occurrences.saturating_add(1);
        if matches!(record.outcome, RegionRequestOutcome::Untestable) {
            region.coverage.untestable_occurrences =
                region.coverage.untestable_occurrences.saturating_add(1);
        } else {
            omit_region_occurrence(region, coverage);
        }
    }
}

fn retain_region_occurrence(
    observation_index: usize,
    observations: &[ByteObservation],
    limits: ObservationLimits,
    region: &mut RegionObservation,
    last_value_index: &mut Option<usize>,
    last_value_retained: &mut bool,
    coverage: &mut ObservationCoverage,
) -> Result<(), ObservationError> {
    let Some(observation) = observations.get(observation_index) else {
        omit_region_occurrence(region, coverage);
        return Ok(());
    };
    if coverage.region_occurrences_retained >= limits.max_region_occurrences {
        omit_region_occurrence(region, coverage);
        return Ok(());
    }
    let Some(same_value) = compare_region_value(
        *last_value_index,
        observation,
        observations,
        limits,
        coverage,
    ) else {
        omit_region_occurrence(region, coverage);
        return Ok(());
    };
    // Singleton groups remain in the report so consumers can apply their own support rules
    if !same_value {
        *last_value_index = Some(observation_index);
        *last_value_retained = retain_region_value(observation, limits, region, coverage)?;
    }
    if !*last_value_retained {
        omit_region_occurrence(region, coverage);
        return Ok(());
    }
    retain_occurrence_index(observation_index, same_value, limits, region, coverage)
}

fn compare_region_value(
    previous_index: Option<usize>,
    observation: &ByteObservation,
    observations: &[ByteObservation],
    limits: ObservationLimits,
    coverage: &mut ObservationCoverage,
) -> Option<bool> {
    let Some(previous) = previous_index.and_then(|index| observations.get(index)) else {
        return Some(false);
    };
    if previous.bytes.len() != observation.bytes.len() {
        return Some(false);
    }
    reserve_work(coverage, observation.bytes.len(), limits.max_work_units)
        .then(|| previous.bytes == observation.bytes)
}

fn retain_region_value(
    observation: &ByteObservation,
    limits: ObservationLimits,
    region: &mut RegionObservation,
    coverage: &mut ObservationCoverage,
) -> Result<bool, ObservationError> {
    let value_cost = size_of::<RegionValue>().saturating_add(observation.bytes.len());
    let first_occurrence_cost = size_of::<usize>();
    let fits = region.values.len() < limits.max_region_values
        && can_retain_report(
            coverage,
            value_cost.saturating_add(first_occurrence_cost),
            limits,
        )
        && reserve_work(
            coverage,
            observation.bytes.len().saturating_add(1),
            limits.max_work_units,
        );
    if !fits {
        coverage.omitted_region_values = coverage.omitted_region_values.saturating_add(1);
        coverage.complete = false;
        return Ok(false);
    }
    region
        .values
        .try_reserve(1)
        .map_err(|_| ObservationError::AllocationFailed {
            field: "region value groups",
        })?;
    coverage.report_bytes_retained = coverage
        .report_bytes_retained
        .saturating_add(value_cost)
        .saturating_add(first_occurrence_cost);
    coverage.region_values_retained = coverage.region_values_retained.saturating_add(1);
    region.values.push(RegionValue {
        bytes: observation.bytes.clone(),
        observation_indices: Vec::new(),
    });
    Ok(true)
}

fn retain_occurrence_index(
    observation_index: usize,
    same_value: bool,
    limits: ObservationLimits,
    region: &mut RegionObservation,
    coverage: &mut ObservationCoverage,
) -> Result<(), ObservationError> {
    let occurrence_cost = size_of::<usize>();
    if coverage.region_occurrences_retained >= limits.max_region_occurrences
        || !can_retain_report(coverage, occurrence_cost, limits)
        || (same_value && !reserve_work(coverage, 1, limits.max_work_units))
    {
        omit_region_occurrence(region, coverage);
        return Ok(());
    }
    let Some(value) = region.values.last_mut() else {
        omit_region_occurrence(region, coverage);
        return Ok(());
    };
    value
        .observation_indices
        .try_reserve(1)
        .map_err(|_| ObservationError::AllocationFailed {
            field: "region occurrence indices",
        })?;
    value.observation_indices.push(observation_index);
    region.coverage.observed_occurrences = region.coverage.observed_occurrences.saturating_add(1);
    coverage.region_occurrences_retained = coverage.region_occurrences_retained.saturating_add(1);
    coverage.report_bytes_retained = coverage
        .report_bytes_retained
        .saturating_add(occurrence_cost);
    Ok(())
}

const fn omit_region_occurrence(
    region: &mut RegionObservation,
    coverage: &mut ObservationCoverage,
) {
    region.coverage.omitted_occurrences = region.coverage.omitted_occurrences.saturating_add(1);
    increment_omitted_region(coverage);
}

const fn increment_omitted_region(coverage: &mut ObservationCoverage) {
    coverage.omitted_region_occurrences = coverage.omitted_region_occurrences.saturating_add(1);
    coverage.complete = false;
}

fn compare_region_values(
    left: &RegionRequestRecord,
    right: &RegionRequestRecord,
    observations: &[ByteObservation],
) -> Ordering {
    match (left.outcome, right.outcome) {
        (
            RegionRequestOutcome::Observed {
                observation_index: left_index,
            },
            RegionRequestOutcome::Observed {
                observation_index: right_index,
            },
        ) => {
            let left_bytes = observations
                .get(left_index)
                .map(|observation| observation.bytes.as_slice())
                .unwrap_or_default();
            let right_bytes = observations
                .get(right_index)
                .map(|observation| observation.bytes.as_slice())
                .unwrap_or_default();
            left_bytes.cmp(right_bytes)
        }
        _ => region_outcome_order(left.outcome).cmp(&region_outcome_order(right.outcome)),
    }
}

const fn region_outcome_order(outcome: RegionRequestOutcome) -> u8 {
    match outcome {
        RegionRequestOutcome::Observed { .. } => 0,
        RegionRequestOutcome::Untestable => 1,
        RegionRequestOutcome::Omitted => 2,
    }
}
