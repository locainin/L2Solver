use l2_workbench::protocol::{
    RelationalByteRangeLocator, RelationalCoordinateBasis, RelationalRecordSample,
    RelationalTransformRule,
};
use std::ops::Range;

pub fn candidate_ranges_are_valid(
    samples: &[RelationalRecordSample<'_>],
    rule: &RelationalTransformRule,
) -> bool {
    if rule.seed_locator.coordinate_basis != RelationalCoordinateBasis::MessageStartV1 {
        return false;
    }

    for sample in samples {
        let seed_matches = locator_matches(sample, &rule.seed_locator, 0);
        let seed_range = if seed_matches {
            let Some(range) = value_range(sample, &rule.seed_locator, 0) else {
                return false;
            };
            Some(range)
        } else {
            None
        };
        let payload_seed_end = match rule.payload_locator.coordinate_basis {
            RelationalCoordinateBasis::MessageStartV1 => 0,
            RelationalCoordinateBasis::SeedRangeEndV1 => {
                let Some(seed_range) = seed_range.as_ref() else {
                    continue;
                };
                seed_range.end
            }
        };
        let payload_matches = locator_matches(sample, &rule.payload_locator, payload_seed_end);
        let payload_range = if payload_matches {
            let Some(range) = value_range(sample, &rule.payload_locator, payload_seed_end) else {
                return false;
            };
            Some(range)
        } else {
            None
        };
        if let (Some(seed), Some(payload)) = (seed_range, payload_range)
            && ranges_overlap(&seed, &payload)
        {
            return false;
        }
    }
    true
}

pub fn locator_matches(
    sample: &RelationalRecordSample<'_>,
    locator: &RelationalByteRangeLocator,
    seed_end: usize,
) -> bool {
    if locator.marker.is_empty() || sample.context.direction != locator.direction {
        return false;
    }
    let Some(marker_start) = locator_offset(locator, locator.marker_offset, seed_end) else {
        return false;
    };
    sample
        .bytes
        .get(marker_start..)
        .and_then(|tail| tail.get(..locator.marker.len()))
        == Some(locator.marker.as_slice())
}

pub fn value_range(
    sample: &RelationalRecordSample<'_>,
    locator: &RelationalByteRangeLocator,
    seed_end: usize,
) -> Option<Range<usize>> {
    let start = locator_offset(locator, locator.value_offset, seed_end)?;
    let end = match locator.value_length {
        Some(length) => start.checked_add(length)?,
        None => sample.bytes.len(),
    };
    let range = start..end;
    let bytes = sample.bytes.get(range.clone())?;
    if bytes.is_empty() {
        return None;
    }
    Some(range)
}

const fn locator_offset(
    locator: &RelationalByteRangeLocator,
    offset: usize,
    seed_end: usize,
) -> Option<usize> {
    match locator.coordinate_basis {
        RelationalCoordinateBasis::MessageStartV1 => Some(offset),
        RelationalCoordinateBasis::SeedRangeEndV1 => seed_end.checked_add(offset),
    }
}

const fn ranges_overlap(left: &Range<usize>, right: &Range<usize>) -> bool {
    left.start < right.end && right.start < left.end
}
