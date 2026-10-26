use super::budget::can_retain_report;
use super::error::ObservationError;
use super::model::{
    ConstraintOutcome, IntegerInterpretation, ObservationCoverage, ObservationInput,
    ObservationLimits, ObservationReport, PartialConstraint,
};
use crate::evidence::EvidenceStatus;
use crate::measurement::{ByteOrder, LengthMeaning};
use crate::protocol::{ByteRange, FramingKind};
use std::mem::size_of;
pub(super) fn length_hypotheses(
    limits: ObservationLimits,
    coverage: &mut ObservationCoverage,
) -> Result<Vec<FramingKind>, ObservationError> {
    let offset_count = limits
        .max_prefix_offset
        .checked_add(1)
        .ok_or(ObservationError::InvalidLimits)?;
    let possible = offset_count
        .checked_mul(14)
        .ok_or(ObservationError::InvalidLimits)?;
    let retained = possible.min(limits.max_hypotheses);
    let mut candidates = Vec::new();
    candidates
        .try_reserve_exact(retained)
        .map_err(|_| ObservationError::AllocationFailed {
            field: "length hypotheses",
        })?;
    'offsets: for offset in 0..offset_count {
        for width in [1_usize, 2, 4, 8] {
            let byte_orders: &[ByteOrder] = if width == 1 {
                &[ByteOrder::BigEndian]
            } else {
                &[ByteOrder::BigEndian, ByteOrder::LittleEndian]
            };
            for byte_order in byte_orders {
                for meaning in [LengthMeaning::WholeMessage, LengthMeaning::BytesAfterField] {
                    if candidates.len() >= retained {
                        break 'offsets;
                    }
                    candidates.push(FramingKind::LengthPrefix {
                        offset,
                        width,
                        byte_order: *byte_order,
                        meaning,
                    });
                }
            }
        }
    }
    coverage.hypotheses_retained = candidates.len();
    coverage.omitted_hypotheses = possible.saturating_sub(candidates.len());
    if coverage.omitted_hypotheses > 0 {
        coverage.complete = false;
    }
    Ok(candidates)
}
pub(super) fn length_field_ranges(
    candidates: &[FramingKind],
) -> Result<Vec<ByteRange>, ObservationError> {
    let mut ranges = Vec::new();
    ranges
        .try_reserve(candidates.len())
        .map_err(|_| ObservationError::AllocationFailed {
            field: "length field byte ranges",
        })?;
    for candidate in candidates {
        if let FramingKind::LengthPrefix { offset, width, .. } = candidate {
            let end = offset
                .checked_add(*width)
                .ok_or(ObservationError::InvalidLimits)?;
            ranges.push(ByteRange {
                start: *offset,
                end,
            });
        }
    }
    ranges.sort_unstable();
    ranges.dedup();
    Ok(ranges)
}
pub(super) fn retain_integer_interpretations(
    range: ByteRange,
    observation_index: usize,
    bytes: &[u8],
    limits: ObservationLimits,
    report: &mut ObservationReport,
    local_indices: &mut Vec<(ByteRange, ByteOrder, usize)>,
) -> Result<(), ObservationError> {
    let orders: &[ByteOrder] = if bytes.len() == 1 {
        &[ByteOrder::BigEndian]
    } else {
        &[ByteOrder::BigEndian, ByteOrder::LittleEndian]
    };
    for byte_order in orders {
        let Some(value) =
            crate::integer::decode_unsigned(bytes, *byte_order == ByteOrder::LittleEndian)
        else {
            continue;
        };
        let interpretation = IntegerInterpretation {
            byte_observation: observation_index,
            byte_order: *byte_order,
            value,
        };
        let cost = size_of::<IntegerInterpretation>();
        if report.coverage.integer_interpretations_retained
            >= limits.max_byte_observations.saturating_mul(2)
            || !can_retain_report(&report.coverage, cost, limits)
        {
            report.coverage.omitted_integer_interpretations = report
                .coverage
                .omitted_integer_interpretations
                .saturating_add(1);
            report.coverage.complete = false;
            continue;
        }
        report.integer_interpretations.try_reserve(1).map_err(|_| {
            ObservationError::AllocationFailed {
                field: "integer interpretations",
            }
        })?;
        local_indices
            .try_reserve(1)
            .map_err(|_| ObservationError::AllocationFailed {
                field: "sample integer interpretation indices",
            })?;
        let index = report.integer_interpretations.len();
        report.coverage.report_bytes_retained =
            report.coverage.report_bytes_retained.saturating_add(cost);
        report.coverage.integer_interpretations_retained = report
            .coverage
            .integer_interpretations_retained
            .saturating_add(1);
        report.integer_interpretations.push(interpretation);
        local_indices.push((range, *byte_order, index));
    }
    Ok(())
}
pub(super) fn make_constraint(
    input: &ObservationInput<'_>,
    hypothesis: &FramingKind,
    interpretation_indices: &[(ByteRange, ByteOrder, usize)],
    interpretations: &[IntegerInterpretation],
) -> PartialConstraint {
    let FramingKind::LengthPrefix {
        offset,
        width,
        byte_order,
        meaning,
    } = hypothesis
    else {
        return PartialConstraint {
            sample: input.message.sample,
            hypothesis: hypothesis.clone(),
            expected: None,
            observed: None,
            outcome: ConstraintOutcome::Untestable,
            semantic_status: EvidenceStatus::Hypothesis,
            integer_interpretation: None,
        };
    };
    let Some(field_end) = offset.checked_add(*width) else {
        return untestable_constraint(input.message.sample, hypothesis);
    };
    let Some(field) = input.message.bytes.get(*offset..field_end) else {
        return untestable_constraint(input.message.sample, hypothesis);
    };
    let expected_length = match meaning {
        LengthMeaning::WholeMessage => input.message.bytes.len(),
        LengthMeaning::BytesAfterField => {
            let Some(length) = input.message.bytes.len().checked_sub(field_end) else {
                return untestable_constraint(input.message.sample, hypothesis);
            };
            length
        }
    };
    let expected = u64::try_from(expected_length).ok();
    let observed = crate::integer::decode_unsigned(field, *byte_order == ByteOrder::LittleEndian);
    let range = ByteRange {
        start: *offset,
        end: field_end,
    };
    let integer_interpretation = interpretation_indices
        .iter()
        .find(|(candidate_range, candidate_order, _)| {
            *candidate_range == range && *candidate_order == *byte_order
        })
        .map(|(_, _, index)| *index)
        .filter(|index| interpretations.get(*index).is_some());
    let outcome = match (expected, observed) {
        (Some(expected), Some(observed)) if expected == observed => ConstraintOutcome::Supported,
        (Some(_), Some(_)) => ConstraintOutcome::Contradicted,
        _ => ConstraintOutcome::Untestable,
    };
    // A per-sample match supports the candidate without proving a protocol grammar
    PartialConstraint {
        sample: input.message.sample,
        hypothesis: hypothesis.clone(),
        expected,
        observed,
        outcome,
        semantic_status: EvidenceStatus::Hypothesis,
        integer_interpretation,
    }
}
fn untestable_constraint(sample: u64, hypothesis: &FramingKind) -> PartialConstraint {
    PartialConstraint {
        sample,
        hypothesis: hypothesis.clone(),
        expected: None,
        observed: None,
        outcome: ConstraintOutcome::Untestable,
        semantic_status: EvidenceStatus::Hypothesis,
        integer_interpretation: None,
    }
}
