use super::{
    super::model::{
        RelationalByteRangeLocator, RelationalRecordSample, RelationalTransformError,
        RelationalTransformLimits, Selector,
    },
    input::{SelectorIndex, SessionGroup},
};

#[derive(Clone)]
pub(super) struct LocatorCandidate {
    pub(super) selector: Selector,
    varying_bytes: usize,
    ends_at_message_boundary: bool,
    pub(super) locator: RelationalByteRangeLocator,
}

pub(super) const fn locator_start_rank(candidate: &LocatorCandidate) -> (u8, usize) {
    let marker_end = candidate
        .selector
        .marker_offset
        .saturating_add(candidate.selector.marker.len());
    if candidate.locator.value_offset >= marker_end {
        (0, candidate.locator.value_offset - marker_end)
    } else {
        (1, marker_end - candidate.locator.value_offset)
    }
}

fn varying_range_bytes(
    samples: &[RelationalRecordSample<'_>],
    indexes: &[SelectorIndex],
    selector: &Selector,
    value_offset: usize,
    value_length: usize,
) -> usize {
    let Some(first_sample_index) = indexes
        .first()
        .and_then(|index| index.get(selector))
        .and_then(|indices| indices.first())
    else {
        return 0;
    };
    let Some(first_range) = samples.get(*first_sample_index).and_then(|sample| {
        sample
            .bytes
            .get(value_offset..value_offset.saturating_add(value_length))
    }) else {
        return 0;
    };
    (0..value_length)
        .filter(|offset| {
            let Some(first_byte) = first_range.get(*offset) else {
                return false;
            };
            indexes.iter().skip(1).any(|index| {
                index
                    .get(selector)
                    .and_then(|indices| indices.first())
                    .and_then(|sample_index| samples.get(*sample_index))
                    .and_then(|sample| {
                        value_offset
                            .checked_add(*offset)
                            .and_then(|position| sample.bytes.get(position))
                    })
                    .is_some_and(|byte| byte != first_byte)
            })
        })
        .count()
}

fn range_ends_message_boundary(
    samples: &[RelationalRecordSample<'_>],
    indexes: &[SelectorIndex],
    selector: &Selector,
    value_offset: usize,
    value_length: usize,
) -> bool {
    let Some(range_end) = value_offset.checked_add(value_length) else {
        return false;
    };
    indexes.iter().all(|index| {
        index.get(selector).is_some_and(|indices| {
            !indices.is_empty()
                && indices.iter().all(|sample_index| {
                    samples
                        .get(*sample_index)
                        .is_some_and(|sample| sample.bytes.len() == range_end)
                })
        })
    })
}

pub(super) fn seed_locators(
    samples: &[RelationalRecordSample<'_>],
    groups: &[SessionGroup],
    indexes: &[SelectorIndex],
    selectors: &[Selector],
    limits: RelationalTransformLimits,
) -> Result<(Vec<LocatorCandidate>, bool), RelationalTransformError> {
    let mut candidates = Vec::new();
    for selector in selectors {
        for value_offset in 0..=limits.max_locator_offset {
            for value_length in 1..=limits.max_seed_bytes {
                let locator = RelationalByteRangeLocator {
                    direction: selector.direction,
                    marker_offset: selector.marker_offset,
                    marker: selector.marker.clone(),
                    value_offset,
                    value_length: Some(value_length),
                };
                if groups.iter().enumerate().all(|(group_index, _group)| {
                    let Some(index) = indexes.get(group_index) else {
                        return false;
                    };
                    let Some(indices) = index.get(selector) else {
                        return false;
                    };
                    indices.len() == 1
                        && indices.first().is_some_and(|sample_index| {
                            samples.get(*sample_index).is_some_and(|sample| {
                                value_offset
                                    .checked_add(value_length)
                                    .is_some_and(|end| end <= sample.bytes.len())
                            })
                        })
                }) {
                    if candidates.len() == limits.max_locator_candidates {
                        return Ok((candidates, false));
                    }
                    candidates
                        .try_reserve(1)
                        .map_err(|_| RelationalTransformError::AllocationFailed)?;
                    candidates.push(LocatorCandidate {
                        selector: selector.clone(),
                        varying_bytes: varying_range_bytes(
                            samples,
                            indexes,
                            selector,
                            value_offset,
                            value_length,
                        ),
                        ends_at_message_boundary: range_ends_message_boundary(
                            samples,
                            indexes,
                            selector,
                            value_offset,
                            value_length,
                        ),
                        locator,
                    });
                }
            }
        }
    }
    candidates.sort_by(|left, right| {
        right
            .ends_at_message_boundary
            .cmp(&left.ends_at_message_boundary)
            .then_with(|| {
                let left_length = left.locator.value_length.unwrap_or_default() as u128;
                let right_length = right.locator.value_length.unwrap_or_default() as u128;
                (right.varying_bytes as u128 * left_length)
                    .cmp(&(left.varying_bytes as u128 * right_length))
            })
            .then_with(|| right.varying_bytes.cmp(&left.varying_bytes))
            .then_with(|| locator_start_rank(left).cmp(&locator_start_rank(right)))
            .then_with(|| {
                right
                    .selector
                    .marker_offset
                    .cmp(&left.selector.marker_offset)
            })
            .then_with(|| right.selector.marker.len().cmp(&left.selector.marker.len()))
            .then_with(|| right.locator.value_length.cmp(&left.locator.value_length))
            .then_with(|| left.selector.marker.cmp(&right.selector.marker))
    });
    Ok((candidates, true))
}

pub(super) fn payload_locators(
    samples: &[RelationalRecordSample<'_>],
    groups: &[SessionGroup],
    indexes: &[SelectorIndex],
    selectors: &[Selector],
    limits: RelationalTransformLimits,
) -> Result<(Vec<LocatorCandidate>, bool), RelationalTransformError> {
    let mut candidates = Vec::new();
    for selector in selectors {
        for value_offset in 0..=limits.max_locator_offset {
            let locator = RelationalByteRangeLocator {
                direction: selector.direction,
                marker_offset: selector.marker_offset,
                marker: selector.marker.clone(),
                value_offset,
                value_length: None,
            };
            let supported = groups.iter().enumerate().all(|(group_index, _group)| {
                let Some(index) = indexes.get(group_index) else {
                    return false;
                };
                let Some(indices) = index.get(selector) else {
                    return false;
                };
                !indices.is_empty()
                    && indices.iter().all(|sample_index| {
                        samples.get(*sample_index).is_some_and(|sample| {
                            sample
                                .bytes
                                .get(value_offset..)
                                .is_some_and(|range| !range.is_empty())
                        })
                    })
            });
            if supported {
                if candidates.len() == limits.max_locator_candidates {
                    return Ok((candidates, false));
                }
                candidates
                    .try_reserve(1)
                    .map_err(|_| RelationalTransformError::AllocationFailed)?;
                candidates.push(LocatorCandidate {
                    selector: selector.clone(),
                    varying_bytes: 0,
                    ends_at_message_boundary: false,
                    locator,
                });
            }
        }
    }
    candidates.sort_by(|left, right| {
        locator_start_rank(left)
            .cmp(&locator_start_rank(right))
            .then_with(|| {
                right
                    .selector
                    .marker_offset
                    .cmp(&left.selector.marker_offset)
            })
            .then_with(|| right.selector.marker.len().cmp(&left.selector.marker.len()))
            .then_with(|| left.selector.marker.cmp(&right.selector.marker))
    });
    Ok((candidates, true))
}

pub(super) fn locator_ranges_overlap(
    samples: &[RelationalRecordSample<'_>],
    indexes: &[SelectorIndex],
    seed_selector: &Selector,
    payload_selector: &Selector,
    seed: &RelationalByteRangeLocator,
    payload: &RelationalByteRangeLocator,
) -> bool {
    indexes.iter().any(|index| {
        let (Some(seed_samples), Some(payload_samples)) =
            (index.get(seed_selector), index.get(payload_selector))
        else {
            return false;
        };
        let (smaller, larger) = if seed_samples.len() <= payload_samples.len() {
            (seed_samples, payload_samples)
        } else {
            (payload_samples, seed_samples)
        };
        smaller.iter().any(|sample_index| {
            larger.contains(sample_index)
                && sample_value_ranges_overlap(samples, *sample_index, seed, payload)
        })
    })
}

fn sample_value_ranges_overlap(
    samples: &[RelationalRecordSample<'_>],
    sample_index: usize,
    seed: &RelationalByteRangeLocator,
    payload: &RelationalByteRangeLocator,
) -> bool {
    let Some(sample) = samples.get(sample_index) else {
        return true;
    };
    let Some(seed_length) = seed.value_length else {
        return true;
    };
    let Some(seed_end) = seed.value_offset.checked_add(seed_length) else {
        return true;
    };
    let payload_end = match payload.value_length {
        Some(length) => {
            let Some(end) = payload.value_offset.checked_add(length) else {
                return true;
            };
            end
        }
        None => sample.bytes.len(),
    };
    if sample.bytes.get(seed.value_offset..seed_end).is_none()
        || sample
            .bytes
            .get(payload.value_offset..payload_end)
            .is_none()
    {
        return true;
    }
    seed.value_offset < payload_end && payload.value_offset < seed_end
}
