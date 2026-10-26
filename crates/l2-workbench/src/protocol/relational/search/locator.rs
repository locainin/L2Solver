use super::{
    super::model::{
        RelationalByteRangeLocator, RelationalCoordinateBasis, RelationalLengthField,
        RelationalRecordSample, RelationalTransformError, RelationalTransformLimits, Selector,
    },
    input::{SelectorIndex, SessionGroup},
};
use crate::{derivation::CounterWidth, integer::decode_unsigned, protocol::ByteOrder};
use std::{cmp::Ordering, collections::BinaryHeap};

#[derive(Clone)]
pub(super) struct LocatorCandidate {
    pub(super) selector: Selector,
    varying_bytes: usize,
    ends_at_message_boundary: bool,
    pub(super) locator: RelationalByteRangeLocator,
    pub(super) anchor_seed_index: Option<usize>,
}

impl LocatorCandidate {
    pub(super) const fn anchored_payload(
        seed_index: usize,
        selector: Selector,
        locator: RelationalByteRangeLocator,
    ) -> Self {
        Self {
            selector,
            varying_bytes: 0,
            ends_at_message_boundary: false,
            locator,
            anchor_seed_index: Some(seed_index),
        }
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum LocatorRanking {
    Seed,
    Payload,
}

struct RankedLocatorCandidate {
    ranking: LocatorRanking,
    candidate: LocatorCandidate,
}

impl PartialEq for RankedLocatorCandidate {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for RankedLocatorCandidate {}

impl PartialOrd for RankedLocatorCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RankedLocatorCandidate {
    fn cmp(&self, other: &Self) -> Ordering {
        self.ranking.cmp(&other.ranking).then_with(|| {
            compare_locator_candidates(self.ranking, &self.candidate, &other.candidate)
        })
    }
}

struct BoundedLocatorCandidates {
    ranking: LocatorRanking,
    maximum: usize,
    retained: BinaryHeap<RankedLocatorCandidate>,
    omitted: bool,
}

impl BoundedLocatorCandidates {
    const fn new(ranking: LocatorRanking, maximum: usize) -> Self {
        Self {
            ranking,
            maximum,
            retained: BinaryHeap::new(),
            omitted: false,
        }
    }

    fn retain(&mut self, candidate: LocatorCandidate) -> Result<(), RelationalTransformError> {
        let candidate = RankedLocatorCandidate {
            ranking: self.ranking,
            candidate,
        };
        if self.retained.len() < self.maximum {
            self.retained
                .try_reserve(1)
                .map_err(|_| RelationalTransformError::AllocationFailed)?;
            self.retained.push(candidate);
            return Ok(());
        }

        self.omitted = true;
        if self
            .retained
            .peek()
            .is_some_and(|worst| candidate.cmp(worst).is_lt())
        {
            self.retained.pop();
            self.retained.push(candidate);
        }
        Ok(())
    }

    fn finish(self) -> (Vec<LocatorCandidate>, bool) {
        let candidates = self
            .retained
            .into_sorted_vec()
            .into_iter()
            .map(|ranked| ranked.candidate)
            .collect();
        (candidates, !self.omitted)
    }
}

fn compare_locator_candidates(
    ranking: LocatorRanking,
    left: &LocatorCandidate,
    right: &LocatorCandidate,
) -> Ordering {
    let ranking = match ranking {
        LocatorRanking::Seed => compare_seed_locators(left, right),
        LocatorRanking::Payload => compare_payload_locators(left, right),
    };
    ranking
        .then_with(|| left.locator.cmp(&right.locator))
        .then_with(|| left.selector.cmp(&right.selector))
        .then_with(|| left.anchor_seed_index.cmp(&right.anchor_seed_index))
}

fn compare_seed_locators(left: &LocatorCandidate, right: &LocatorCandidate) -> Ordering {
    declared_length_rank(left)
        .cmp(&declared_length_rank(right))
        .then_with(|| {
            right
                .ends_at_message_boundary
                .cmp(&left.ends_at_message_boundary)
        })
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
}

fn compare_payload_locators(left: &LocatorCandidate, right: &LocatorCandidate) -> Ordering {
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

fn matching_preceding_lengths(
    samples: &[RelationalRecordSample<'_>],
    indexes: &[SelectorIndex],
    selector: &Selector,
    value_offset: usize,
    value_length: usize,
) -> Result<Vec<RelationalLengthField>, RelationalTransformError> {
    let mut fields = Vec::new();
    let Ok(expected) = u64::try_from(value_length) else {
        return Ok(fields);
    };
    for width in [
        CounterWidth::OneByte,
        CounterWidth::TwoBytes,
        CounterWidth::FourBytes,
        CounterWidth::EightBytes,
    ] {
        let width_bytes = width.byte_length();
        let Some(offset) = value_offset.checked_sub(width_bytes) else {
            continue;
        };
        for byte_order in [ByteOrder::BigEndian, ByteOrder::LittleEndian] {
            if width == CounterWidth::OneByte && byte_order == ByteOrder::LittleEndian {
                continue;
            }
            let matches_every_session = indexes.iter().all(|index| {
                index.get(selector).is_some_and(|selected| {
                    selected.len() == 1
                        && selected.first().is_some_and(|sample_index| {
                            samples.get(*sample_index).is_some_and(|sample| {
                                offset
                                    .checked_add(width_bytes)
                                    .and_then(|end| sample.bytes.get(offset..end))
                                    .and_then(|bytes| {
                                        decode_unsigned(
                                            bytes,
                                            byte_order == ByteOrder::LittleEndian,
                                        )
                                    })
                                    == Some(expected)
                            })
                        })
                })
            });
            if matches_every_session {
                fields
                    .try_reserve(1)
                    .map_err(|_| RelationalTransformError::AllocationFailed)?;
                fields.push(RelationalLengthField {
                    offset,
                    width,
                    byte_order,
                });
            }
        }
    }
    Ok(fields)
}

pub(super) fn seed_locators(
    samples: &[RelationalRecordSample<'_>],
    groups: &[SessionGroup],
    indexes: &[SelectorIndex],
    selectors: &[Selector],
    limits: RelationalTransformLimits,
) -> Result<(Vec<LocatorCandidate>, bool), RelationalTransformError> {
    let mut candidates =
        BoundedLocatorCandidates::new(LocatorRanking::Seed, limits.max_locator_candidates);
    for selector in selectors {
        let Some(minimum_length) =
            minimum_selected_message_length(samples, indexes, selector, groups.len(), true)
        else {
            continue;
        };
        let last_seed_offset = minimum_length
            .saturating_sub(1)
            .min(limits.max_locator_offset);
        for value_offset in 0..=last_seed_offset {
            let maximum_seed_length = limits
                .max_seed_bytes
                .min(minimum_length.saturating_sub(value_offset));
            for value_length in 1..=maximum_seed_length {
                add_seed_locator_candidates(
                    samples,
                    groups,
                    indexes,
                    selector,
                    (value_offset, value_length),
                    &mut candidates,
                )?;
            }
        }
    }
    Ok(candidates.finish())
}

fn add_seed_locator_candidates(
    samples: &[RelationalRecordSample<'_>],
    groups: &[SessionGroup],
    indexes: &[SelectorIndex],
    selector: &Selector,
    value_range: (usize, usize),
    candidates: &mut BoundedLocatorCandidates,
) -> Result<(), RelationalTransformError> {
    let (value_offset, value_length) = value_range;
    if !seed_locator_supported(
        samples,
        groups,
        indexes,
        selector,
        value_offset,
        value_length,
    ) {
        return Ok(());
    }
    let locator = RelationalByteRangeLocator {
        coordinate_basis: RelationalCoordinateBasis::MessageStartV1,
        direction: selector.direction,
        marker_offset: selector.marker_offset,
        marker: selector.marker.clone(),
        value_offset,
        value_length: Some(value_length),
        declared_length: None,
    };
    let varying_bytes = varying_range_bytes(samples, indexes, selector, value_offset, value_length);
    let ends_at_message_boundary =
        range_ends_message_boundary(samples, indexes, selector, value_offset, value_length);
    let matching_lengths =
        matching_preceding_lengths(samples, indexes, selector, value_offset, value_length)?;
    push_seed_locator_candidate(
        candidates,
        selector,
        &locator,
        varying_bytes,
        ends_at_message_boundary,
    )?;
    for field in matching_lengths {
        let mut constrained_locator = locator.clone();
        constrained_locator.declared_length = Some(field);
        push_seed_locator_candidate(
            candidates,
            selector,
            &constrained_locator,
            varying_bytes,
            ends_at_message_boundary,
        )?;
    }
    Ok(())
}

fn seed_locator_supported(
    samples: &[RelationalRecordSample<'_>],
    groups: &[SessionGroup],
    indexes: &[SelectorIndex],
    selector: &Selector,
    value_offset: usize,
    value_length: usize,
) -> bool {
    groups.iter().enumerate().all(|(group_index, _group)| {
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
    })
}

fn push_seed_locator_candidate(
    candidates: &mut BoundedLocatorCandidates,
    selector: &Selector,
    locator: &RelationalByteRangeLocator,
    varying_bytes: usize,
    ends_at_message_boundary: bool,
) -> Result<(), RelationalTransformError> {
    candidates.retain(LocatorCandidate {
        selector: selector.clone(),
        varying_bytes,
        ends_at_message_boundary,
        locator: locator.clone(),
        anchor_seed_index: None,
    })
}

pub(super) fn payload_locators(
    samples: &[RelationalRecordSample<'_>],
    groups: &[SessionGroup],
    indexes: &[SelectorIndex],
    selectors: &[Selector],
    limits: RelationalTransformLimits,
    maximum_candidates: usize,
) -> Result<(Vec<LocatorCandidate>, bool), RelationalTransformError> {
    let mut candidates = BoundedLocatorCandidates::new(LocatorRanking::Payload, maximum_candidates);
    for selector in selectors {
        let Some(minimum_length) =
            minimum_selected_message_length(samples, indexes, selector, groups.len(), false)
        else {
            continue;
        };
        let last_payload_offset = minimum_length
            .saturating_sub(1)
            .min(limits.max_locator_offset);
        for value_offset in 0..=last_payload_offset {
            let locator = RelationalByteRangeLocator {
                coordinate_basis: RelationalCoordinateBasis::MessageStartV1,
                direction: selector.direction,
                marker_offset: selector.marker_offset,
                marker: selector.marker.clone(),
                value_offset,
                value_length: None,
                declared_length: None,
            };
            let supported = groups.iter().enumerate().all(|(group_index, _group)| {
                indexes
                    .get(group_index)
                    .and_then(|index| index.get(selector))
                    .is_some_and(|selected| {
                        !selected.is_empty()
                            && selected.iter().all(|sample_index| {
                                samples.get(*sample_index).is_some_and(|sample| {
                                    sample
                                        .bytes
                                        .get(value_offset..)
                                        .is_some_and(|range| !range.is_empty())
                                })
                            })
                    })
            });
            if supported {
                candidates.retain(LocatorCandidate {
                    selector: selector.clone(),
                    varying_bytes: 0,
                    ends_at_message_boundary: false,
                    locator,
                    anchor_seed_index: None,
                })?;
            }
        }
    }
    Ok(candidates.finish())
}

fn minimum_selected_message_length(
    samples: &[RelationalRecordSample<'_>],
    indexes: &[SelectorIndex],
    selector: &Selector,
    expected_groups: usize,
    require_single_per_group: bool,
) -> Option<usize> {
    if indexes.len() != expected_groups {
        return None;
    }
    let mut minimum_length = usize::MAX;
    for index in indexes {
        let selected = index.get(selector)?;
        if selected.is_empty() || (require_single_per_group && selected.len() != 1) {
            return None;
        }
        for sample_index in selected {
            let sample = samples.get(*sample_index)?;
            minimum_length = minimum_length.min(sample.bytes.len());
        }
    }
    (minimum_length != usize::MAX && minimum_length > 0).then_some(minimum_length)
}

fn declared_length_rank(candidate: &LocatorCandidate) -> (u8, usize, usize, u8) {
    // Wider matching fields preserve more of the frozen equality check
    candidate
        .locator
        .declared_length
        .map_or((1, usize::MAX, usize::MAX, u8::MAX), |field| {
            (
                0,
                usize::MAX - field.width.byte_length(),
                field.offset,
                match field.byte_order {
                    ByteOrder::BigEndian => 0,
                    ByteOrder::LittleEndian => 1,
                },
            )
        })
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
