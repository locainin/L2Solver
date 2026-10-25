use super::{
    builder::{Builder, ObservationDraft},
    model::{Ambiguity, CarrierError, OmissionReason, Rule, Sample, TimingStatus, Value},
    resolve::{ResolvedSample, sample_ranges},
};
use crate::{
    evidence::SourceRange,
    measurement::{IntervalStatus, TimedSample, measure_timing},
};
use std::collections::BTreeMap;

pub(super) fn extract_timing(
    builder: &mut Builder,
    samples: &[Sample<'_>],
    resolved: &[ResolvedSample],
) -> Result<(), CarrierError> {
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (index, sample) in samples.iter().enumerate() {
        let Some(event_id) = sample.event_id else {
            builder.omit(
                Some(sample.id),
                &Rule::Timing,
                OmissionReason::MissingEventIdentity,
            );
            continue;
        };
        groups.entry(event_id.to_owned()).or_default().push(index);
    }
    for (event_id, indexes) in groups {
        if indexes.len() < 2 {
            let sample_id = indexes
                .first()
                .and_then(|index| samples.get(*index))
                .map(|sample| sample.id);
            builder.omit(
                sample_id,
                &Rule::Timing,
                OmissionReason::InsufficientTimingSamples,
            );
            continue;
        }
        // Keep caller sample order and let the shared measurement reject non-increasing values
        for pair in indexes.windows(2) {
            let Some((&left_index, &right_index)) = pair.first().zip(pair.get(1)) else {
                continue;
            };
            let left = samples
                .get(left_index)
                .ok_or(CarrierError::InvalidSampleId)?;
            let right = samples
                .get(right_index)
                .ok_or(CarrierError::InvalidSampleId)?;
            let left_data = resolved
                .get(left_index)
                .ok_or(CarrierError::InvalidSampleId)?;
            let right_data = resolved
                .get(right_index)
                .ok_or(CarrierError::InvalidSampleId)?;
            let (value, reason) = timing_value(left, right);
            let mut ranges = sample_ranges(left, 0, left.length)?;
            extend_unique_ranges(&mut ranges, sample_ranges(right, 0, right.length)?);
            builder.observe(ObservationDraft {
                sample_ids: vec![left.id, right.id],
                event_id: Some(event_id.clone()),
                rule: Rule::Timing,
                component_index: None,
                value,
                ranges,
                ambiguity: more_ambiguous(left_data.ambiguity, right_data.ambiguity),
            });
            if let Some(reason) = reason {
                builder.omit(Some(left.id), &Rule::Timing, reason);
            }
        }
    }
    Ok(())
}

fn timing_value(left: &Sample<'_>, right: &Sample<'_>) -> (Value, Option<OmissionReason>) {
    let (Some(left_sequence), Some(right_sequence)) = (left.sequence, right.sequence) else {
        return (
            timing_projection(left, right, None, TimingStatus::OrderUnresolved),
            Some(OmissionReason::TimingUnresolved),
        );
    };
    if left_sequence == 0 || right_sequence <= left_sequence {
        return (
            timing_projection(left, right, None, TimingStatus::OrderUnresolved),
            Some(OmissionReason::TimingUnresolved),
        );
    }
    let (Some(left_time), Some(right_time)) = (&left.time, &right.time) else {
        return (
            timing_projection(left, right, None, TimingStatus::MissingTimestamp),
            Some(OmissionReason::TimingUnresolved),
        );
    };
    let intervals = [
        TimedSample {
            packet: left_sequence,
            clock: left_time.clock.clone(),
            ticks: left_time.ticks,
        },
        TimedSample {
            packet: right_sequence,
            clock: right_time.clock.clone(),
            ticks: right_time.ticks,
        },
    ];
    let Ok(report) = measure_timing(&intervals) else {
        return (
            timing_projection(left, right, None, TimingStatus::Unsupported),
            Some(OmissionReason::TimingUnresolved),
        );
    };
    let Some(interval) = report.intervals.first() else {
        return (
            timing_projection(left, right, None, TimingStatus::Unsupported),
            Some(OmissionReason::TimingUnresolved),
        );
    };
    let status = match interval.status {
        IntervalStatus::Measured => TimingStatus::Measured,
        IntervalStatus::MissingTimestamp => TimingStatus::MissingTimestamp,
        IntervalStatus::Backwards => TimingStatus::Backwards,
        IntervalStatus::ScopeMismatch => TimingStatus::ScopeMismatch,
        IntervalStatus::ClockMismatch => TimingStatus::ClockMismatch,
    };
    let reason = (status != TimingStatus::Measured).then_some(OmissionReason::TimingUnresolved);
    (
        timing_projection(left, right, interval.delta_ticks, status),
        reason,
    )
}

fn timing_projection(
    left: &Sample<'_>,
    right: &Sample<'_>,
    delta_ticks: Option<u64>,
    status: TimingStatus,
) -> Value {
    // Keep exact timing inputs beside the result so the interval can be checked again later
    Value::Timing {
        from_sequence: left.sequence,
        to_sequence: right.sequence,
        from_ticks: left.time.as_ref().and_then(|time| time.ticks),
        to_ticks: right.time.as_ref().and_then(|time| time.ticks),
        delta_ticks,
        status,
        left_clock: left.time.as_ref().map(|time| time.clock.clone()),
        right_clock: right.time.as_ref().map(|time| time.clock.clone()),
    }
}

fn extend_unique_ranges(target: &mut Vec<SourceRange>, ranges: Vec<SourceRange>) {
    for range in ranges {
        if !target.contains(&range) {
            target.push(range);
        }
    }
}

const fn more_ambiguous(left: Ambiguity, right: Ambiguity) -> Ambiguity {
    if matches!(left, Ambiguity::MultipleCandidates)
        || matches!(right, Ambiguity::MultipleCandidates)
    {
        Ambiguity::MultipleCandidates
    } else {
        Ambiguity::None
    }
}
