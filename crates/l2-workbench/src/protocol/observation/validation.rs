use super::error::ObservationError;
use super::limits::MAX_REGION_RANGES;
use super::model::{
    ObservationCoverage, ObservationInput, ObservationLimits, ObservationPlan, SampleRange,
    validate_range,
};
use crate::protocol::ByteRange;
pub(super) fn validate_unique_sample_ids(
    sample_ids: impl IntoIterator<Item = u64>,
) -> Result<(), ObservationError> {
    let mut samples = Vec::new();
    for sample in sample_ids {
        samples
            .try_reserve(1)
            .map_err(|_| ObservationError::AllocationFailed {
                field: "unique observation sample identifiers",
            })?;
        samples.push(sample);
    }
    samples.sort_unstable();
    if let Some(pair) = samples.windows(2).find(|pair| pair.first() == pair.get(1))
        && let Some(sample) = pair.first()
    {
        return Err(ObservationError::DuplicateSample { sample: *sample });
    }
    Ok(())
}
pub(super) fn normalized_region_ranges(
    plan: &ObservationPlan,
    coverage: &mut ObservationCoverage,
) -> Result<Vec<SampleRange>, ObservationError> {
    if plan.region_ranges.len() > MAX_REGION_RANGES {
        coverage.omitted_region_ranges = plan.region_ranges.len();
        coverage.complete = false;
        return Ok(Vec::new());
    }
    let mut ranges = Vec::new();
    ranges.try_reserve(plan.region_ranges.len()).map_err(|_| {
        ObservationError::AllocationFailed {
            field: "requested region ranges",
        }
    })?;
    for sample_range in &plan.region_ranges {
        validate_range(sample_range.range)?;
        ranges.push(*sample_range);
    }
    ranges.sort_unstable();
    ranges.dedup();
    let unique_count = ranges.len();
    if unique_count > plan.limits.max_region_ranges {
        let omitted = unique_count - plan.limits.max_region_ranges;
        coverage.omitted_region_ranges = omitted;
        coverage.complete = false;
        ranges.truncate(plan.limits.max_region_ranges);
    }
    coverage.region_ranges_retained = ranges.len();
    Ok(ranges)
}
pub(super) fn sample_ranges(
    input: &ObservationInput<'_>,
    field_ranges: &[ByteRange],
    region_ranges: &[SampleRange],
    limits: ObservationLimits,
) -> Result<Vec<ByteRange>, ObservationError> {
    let sample_region_ranges = region_ranges_for_sample(region_ranges, input.message.sample)?;
    let mut ranges = Vec::new();
    ranges
        .try_reserve(
            field_ranges
                .len()
                .saturating_add(sample_region_ranges.len()),
        )
        .map_err(|_| ObservationError::AllocationFailed {
            field: "sample byte ranges",
        })?;
    for range in field_ranges {
        if range.end <= input.message.bytes.len() {
            ranges.push(*range);
        }
    }
    for sample_range in sample_region_ranges {
        if sample_range.range.end <= input.message.bytes.len()
            && sample_range.range.end - sample_range.range.start <= limits.max_region_width
        {
            ranges.push(sample_range.range);
        }
    }
    ranges.sort_unstable();
    ranges.dedup();
    Ok(ranges)
}

pub(super) fn region_ranges_for_sample(
    region_ranges: &[SampleRange],
    sample: u64,
) -> Result<&[SampleRange], ObservationError> {
    let start = region_ranges.partition_point(|range| range.sample < sample);
    let end = region_ranges.partition_point(|range| range.sample <= sample);
    region_ranges
        .get(start..end)
        .ok_or(ObservationError::InvalidPlan)
}

pub(super) fn account_unadmitted_region_ranges(
    accepted: &[&ObservationInput<'_>],
    ranges: &[SampleRange],
    coverage: &mut ObservationCoverage,
) -> Result<(), ObservationError> {
    let mut admitted_samples = Vec::new();
    admitted_samples.try_reserve(accepted.len()).map_err(|_| {
        ObservationError::AllocationFailed {
            field: "admitted sample identifiers for region coverage",
        }
    })?;
    admitted_samples.extend(accepted.iter().map(|input| input.message.sample));
    admitted_samples.sort_unstable();
    for sample_range in ranges {
        if admitted_samples
            .binary_search(&sample_range.sample)
            .is_err()
        {
            coverage.omitted_region_occurrences =
                coverage.omitted_region_occurrences.saturating_add(1);
            coverage.complete = false;
        }
    }
    Ok(())
}
