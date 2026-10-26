//! Shared bounded ordering for length fields and payload boundaries

use super::super::super::RecordLengthMeaning;
use super::super::super::{IntegerField, RecordDiscoveryError};
use super::super::model::LENGTH_MEANINGS;
use super::allocation_error;
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::ops::ControlFlow;

/// Order fallback checks without changing the layouts included in the full domain
#[derive(Clone, Copy)]
pub(super) enum LengthLayoutOrder {
    GapFirst,
    CompactPrefix,
}

/// Visit each bounded field, payload boundary, and length interpretation at most once
///
/// Source-supported boundaries run first. Fallback order only chooses which checks fit under
/// the cap; total and omitted counts still describe the complete domain
pub(super) fn visit_length_layouts(
    fields: &[IntegerField],
    maximum_data_offset: usize,
    maximum_checks: usize,
    prioritized_offsets: &[usize],
    order: LengthLayoutOrder,
    visitor: &mut impl FnMut(
        IntegerField,
        usize,
        RecordLengthMeaning,
    ) -> Result<ControlFlow<()>, RecordDiscoveryError>,
) -> Result<(usize, usize, bool), RecordDiscoveryError> {
    let total_checks = length_domain_stats(fields, maximum_data_offset)?;
    let mut checks = 0_usize;

    if !prioritized_offsets.is_empty() {
        let stopped = visit_prioritized_length_layouts(
            fields,
            prioritized_offsets,
            maximum_checks,
            &mut checks,
            visitor,
        )?;
        if stopped {
            return Ok((checks, total_checks, true));
        }
    }

    if checks < maximum_checks {
        let stopped = visit_fallback_length_layouts(
            fields,
            maximum_data_offset,
            maximum_checks,
            prioritized_offsets,
            order,
            &mut checks,
            visitor,
        )?;
        if stopped {
            return Ok((checks, total_checks, true));
        }
    }

    Ok((checks, total_checks, false))
}

fn visit_prioritized_length_layouts(
    fields: &[IntegerField],
    prioritized_offsets: &[usize],
    maximum_checks: usize,
    checks: &mut usize,
    visitor: &mut impl FnMut(
        IntegerField,
        usize,
        RecordLengthMeaning,
    ) -> Result<ControlFlow<()>, RecordDiscoveryError>,
) -> Result<bool, RecordDiscoveryError> {
    let mut priority_fields = Vec::new();
    priority_fields
        .try_reserve_exact(fields.len())
        .map_err(|_| allocation_error())?;
    priority_fields.extend(0..fields.len());
    priority_fields.sort_unstable_by_key(|index| {
        let field_end = fields
            .get(*index)
            .map_or(0, |field| field.offset.saturating_add(field.width));
        (Reverse(field_end), *index)
    });

    // Framing boundaries narrow the payload start, so check their length meanings first
    'prioritized: for data_offset in prioritized_offsets {
        for field_index in &priority_fields {
            let field = fields
                .get(*field_index)
                .ok_or(RecordDiscoveryError::InvalidLimits)?;
            let field_end = field
                .offset
                .checked_add(field.width)
                .ok_or(RecordDiscoveryError::InvalidLimits)?;
            if field_end > *data_offset {
                continue;
            }
            for meaning in LENGTH_MEANINGS {
                if *checks == maximum_checks {
                    break 'prioritized;
                }
                if matches!(
                    visitor(*field, *data_offset, meaning)?,
                    ControlFlow::Break(())
                ) {
                    return Ok(true);
                }
                *checks = (*checks)
                    .checked_add(1)
                    .ok_or(RecordDiscoveryError::InvalidLimits)?;
            }
        }
    }
    Ok(false)
}

fn visit_fallback_length_layouts(
    fields: &[IntegerField],
    maximum_data_offset: usize,
    maximum_checks: usize,
    prioritized_offsets: &[usize],
    order: LengthLayoutOrder,
    checks: &mut usize,
    visitor: &mut impl FnMut(
        IntegerField,
        usize,
        RecordLengthMeaning,
    ) -> Result<ControlFlow<()>, RecordDiscoveryError>,
) -> Result<bool, RecordDiscoveryError> {
    let mut pending = BinaryHeap::new();
    pending
        .try_reserve(fields.len())
        .map_err(|_| allocation_error())?;
    for (field_index, field) in fields.iter().enumerate() {
        let field_end = field
            .offset
            .checked_add(field.width)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        if field_end > maximum_data_offset {
            continue;
        }
        let Some(gap) =
            next_unprioritized_gap(field_end, maximum_data_offset, 0, prioritized_offsets)?
        else {
            continue;
        };
        let priority = length_layout_priority(order, field_end, gap, maximum_data_offset)?;
        pending.push(Reverse((priority, field_index, gap)));
    }

    while let Some(Reverse((_, field_index, gap))) = pending.pop() {
        let field = fields
            .get(field_index)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        let field_end = field
            .offset
            .checked_add(field.width)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        let data_offset = field_end
            .checked_add(gap)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        for meaning in LENGTH_MEANINGS {
            if *checks == maximum_checks {
                return Ok(false);
            }
            if matches!(
                visitor(*field, data_offset, meaning)?,
                ControlFlow::Break(())
            ) {
                return Ok(true);
            }
            *checks = (*checks)
                .checked_add(1)
                .ok_or(RecordDiscoveryError::InvalidLimits)?;
        }

        let Some(next_gap) = gap.checked_add(1) else {
            return Err(RecordDiscoveryError::InvalidLimits);
        };
        let Some(next_gap) = next_unprioritized_gap(
            field_end,
            maximum_data_offset,
            next_gap,
            prioritized_offsets,
        )?
        else {
            continue;
        };
        let priority = length_layout_priority(order, field_end, next_gap, maximum_data_offset)?;
        pending.push(Reverse((priority, field_index, next_gap)));
    }
    Ok(false)
}

fn next_unprioritized_gap(
    field_end: usize,
    maximum_data_offset: usize,
    mut gap: usize,
    prioritized_offsets: &[usize],
) -> Result<Option<usize>, RecordDiscoveryError> {
    loop {
        let Some(data_offset) = field_end.checked_add(gap) else {
            return Err(RecordDiscoveryError::InvalidLimits);
        };
        if data_offset > maximum_data_offset {
            return Ok(None);
        }
        if prioritized_offsets.binary_search(&data_offset).is_err() {
            return Ok(Some(gap));
        }
        gap = gap
            .checked_add(1)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
    }
}

fn length_layout_priority(
    order: LengthLayoutOrder,
    field_end: usize,
    gap: usize,
    maximum_data_offset: usize,
) -> Result<usize, RecordDiscoveryError> {
    match order {
        LengthLayoutOrder::GapFirst => Ok(gap),
        LengthLayoutOrder::CompactPrefix => {
            // A half-prefix penalty interleaves compact padded layouts with wider packed headers
            let gap_weight = (maximum_data_offset / 2).max(1);
            field_end
                .checked_add(
                    gap.checked_mul(gap_weight)
                        .ok_or(RecordDiscoveryError::InvalidLimits)?,
                )
                .ok_or(RecordDiscoveryError::InvalidLimits)
        }
    }
}

pub(super) fn length_domain_stats(
    fields: &[IntegerField],
    maximum_data_offset: usize,
) -> Result<usize, RecordDiscoveryError> {
    let mut total_checks = 0_usize;
    for field in fields {
        let field_end = field
            .offset
            .checked_add(field.width)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        let Some(gap) = maximum_data_offset.checked_sub(field_end) else {
            continue;
        };
        let boundary_count = gap
            .checked_add(1)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        let field_checks = boundary_count
            .checked_mul(LENGTH_MEANINGS.len())
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
        total_checks = total_checks
            .checked_add(field_checks)
            .ok_or(RecordDiscoveryError::InvalidLimits)?;
    }
    Ok(total_checks)
}
