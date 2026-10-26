use super::budget::reserve_work;
use super::error::ObservationError;
use super::model::{
    ByteObservation, ObservationCoverage, ObservationInput, ObservationLimits, ObservationOrigin,
    validate_range,
};
use crate::evidence::clip_byte_mappings;
use crate::protocol::ByteRange;
use std::mem::size_of;
use std::ops::Range;
pub(super) fn validate_input(
    input: &ObservationInput<'_>,
    limits: ObservationLimits,
) -> Result<(), ObservationError> {
    let sample = input.message.sample;
    match &input.provenance {
        super::model::ObservationProvenance::Literal { mappings } => {
            // Too many mappings are skipped later as omitted provenance checks
            if mappings.len() > limits.max_mappings_per_input {
                return Ok(());
            }
            for mapping in *mappings {
                let Ok(length) = usize::try_from(mapping.range.length) else {
                    return Err(ObservationError::InvalidProvenance { sample });
                };
                let Some(end) = mapping.offset.checked_add(length) else {
                    return Err(ObservationError::InvalidProvenance { sample });
                };
                if end > input.message.bytes.len()
                    || mapping
                        .range
                        .offset
                        .checked_add(mapping.range.length)
                        .is_none()
                {
                    return Err(ObservationError::InvalidProvenance { sample });
                }
            }
        }
        super::model::ObservationProvenance::Derived { identity, range } => {
            validate_range(*range)?;
            let Some(length) = range.end.checked_sub(range.start) else {
                return Err(ObservationError::InvalidProvenance { sample });
            };
            if length != input.message.bytes.len() || identity.is_empty() {
                return Err(ObservationError::InvalidProvenance { sample });
            }
        }
    }
    Ok(())
}
pub(super) fn byte_origins(
    input: &ObservationInput<'_>,
    range: ByteRange,
    limits: ObservationLimits,
    coverage: &mut ObservationCoverage,
) -> Result<(Vec<ObservationOrigin>, bool, usize, usize), ObservationError> {
    match &input.provenance {
        super::model::ObservationProvenance::Literal { mappings } => {
            literal_byte_origins(mappings, range, limits, input.message.sample, coverage)
        }
        super::model::ObservationProvenance::Derived {
            identity,
            range: base,
        } => {
            // A derived input keeps its own coordinates instead of borrowing source ranges
            derived_byte_origin(
                input.message.sample,
                range,
                base,
                identity,
                limits,
                coverage,
            )
        }
    }
}

fn literal_byte_origins(
    mappings: &[crate::evidence::ByteMapping],
    range: ByteRange,
    limits: ObservationLimits,
    sample: u64,
    coverage: &mut ObservationCoverage,
) -> Result<(Vec<ObservationOrigin>, bool, usize, usize), ObservationError> {
    if mappings.len() > limits.max_mappings_per_input {
        return Ok((Vec::new(), false, 0, mappings.len()));
    }
    if !reserve_work(coverage, mappings.len(), limits.max_work_units) {
        return Ok((Vec::new(), false, 0, mappings.len()));
    }
    let mut origins = Vec::new();
    origins
        .try_reserve_exact(limits.max_origin_ranges_per_observation.min(mappings.len()))
        .map_err(|_| ObservationError::AllocationFailed {
            field: "literal observation origins",
        })?;
    let mut intervals = Vec::new();
    intervals
        .try_reserve(mappings.len())
        .map_err(|_| ObservationError::AllocationFailed {
            field: "literal origin coverage intervals",
        })?;
    let mut omitted = 0_usize;
    for mapping in mappings {
        let length = usize::try_from(mapping.range.length)
            .map_err(|_| ObservationError::InvalidProvenance { sample })?;
        let end = mapping
            .offset
            .checked_add(length)
            .ok_or(ObservationError::InvalidProvenance { sample })?;
        let first = mapping.offset.max(range.start);
        let last = end.min(range.end);
        if first >= last {
            continue;
        }
        intervals.push((first - range.start, last - range.start));
        if mapping.range.source.len() > limits.max_identity_bytes
            || origins.len() >= limits.max_origin_ranges_per_observation
        {
            omitted = omitted.saturating_add(1);
            continue;
        }
        let copy_cost = mapping
            .range
            .source
            .len()
            .saturating_add(size_of::<ObservationOrigin>());
        if !reserve_work(coverage, copy_cost, limits.max_work_units) {
            omitted = omitted.saturating_add(1);
            continue;
        }
        let clipped = clip_byte_mappings(
            std::slice::from_ref(mapping),
            Range {
                start: range.start,
                end: range.end,
            },
        )
        .map_err(|_| ObservationError::InvalidProvenance { sample })?;
        let clipped_mapping = clipped
            .into_iter()
            .next()
            .ok_or(ObservationError::InvalidProvenance { sample })?;
        origins.push(ObservationOrigin::Literal(clipped_mapping.range));
    }
    let intervals_checked = reserve_work(coverage, intervals.len(), limits.max_work_units);
    if intervals_checked {
        intervals.sort_unstable();
    }
    // Gaps or overlaps leave the origin incomplete even when the bytes are present
    let local_range = ByteRange {
        start: 0,
        end: range.end - range.start,
    };
    let origin_complete =
        intervals_checked && intervals_cover(local_range, &intervals) && omitted == 0;
    Ok((origins, origin_complete, omitted, 0))
}

fn derived_byte_origin(
    sample: u64,
    range: ByteRange,
    base: &ByteRange,
    identity: &str,
    limits: ObservationLimits,
    coverage: &mut ObservationCoverage,
) -> Result<(Vec<ObservationOrigin>, bool, usize, usize), ObservationError> {
    if identity.is_empty() || identity.len() > limits.max_identity_bytes {
        return Ok((Vec::new(), false, 1, 0));
    }
    if !reserve_work(coverage, 1, limits.max_work_units) {
        return Ok((Vec::new(), false, 0, 1));
    }
    if limits.max_origin_ranges_per_observation == 0 {
        return Ok((Vec::new(), false, 1, 0));
    }
    let Some(start) = base.start.checked_add(range.start) else {
        return Err(ObservationError::InvalidProvenance { sample });
    };
    let Some(end) = start.checked_add(range.end - range.start) else {
        return Err(ObservationError::InvalidProvenance { sample });
    };
    let mut origins = Vec::new();
    origins
        .try_reserve_exact(1)
        .map_err(|_| ObservationError::AllocationFailed {
            field: "derived observation origin",
        })?;
    origins.push(ObservationOrigin::Derived {
        identity: identity.to_owned(),
        range: ByteRange { start, end },
    });
    Ok((origins, true, 0, 0))
}
pub(super) const fn origin_check_count(input: &ObservationInput<'_>) -> usize {
    match &input.provenance {
        super::model::ObservationProvenance::Literal { mappings } => mappings.len(),
        super::model::ObservationProvenance::Derived { .. } => 1,
    }
}
fn intervals_cover(range: ByteRange, intervals: &[(usize, usize)]) -> bool {
    let mut cursor = range.start;
    for (start, end) in intervals {
        if *start != cursor || end < start {
            return false;
        }
        cursor = *end;
    }
    cursor == range.end
}
pub(super) fn byte_observation_cost(observation: &ByteObservation) -> usize {
    let context_bytes = observation.context.as_ref().map_or(0, |context| {
        context.source.len().saturating_add(context.scope.len())
    });
    let origin_bytes = observation.origins.iter().fold(0_usize, |total, origin| {
        total.saturating_add(match origin {
            ObservationOrigin::Literal(range) => range.source.len(),
            ObservationOrigin::Derived { identity, .. } => identity.len(),
        })
    });
    size_of::<ByteObservation>()
        .saturating_add(observation.bytes.len())
        .saturating_add(context_bytes)
        .saturating_add(origin_bytes)
        .saturating_add(
            observation
                .origins
                .len()
                .saturating_mul(size_of::<ObservationOrigin>()),
        )
}
pub(super) fn copy_bytes(bytes: &[u8], field: &'static str) -> Result<Vec<u8>, ObservationError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())
        .map_err(|_| ObservationError::AllocationFailed { field })?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}
