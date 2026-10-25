use super::{Observation, RangeReport, Span, SpanStatus};

#[derive(Clone, Copy, Default)]
struct Position {
    value: Option<u8>,
    conflict: bool,
}

impl Position {
    const fn status(self) -> SpanStatus {
        if self.conflict {
            SpanStatus::Conflict
        } else if self.value.is_some() {
            SpanStatus::Observed
        } else {
            SpanStatus::Gap
        }
    }
}

pub(super) fn finish(
    start_sequence: u32,
    length: usize,
    observations: Vec<Observation>,
    omitted_observations: u64,
    omitted_coverage: &[bool],
) -> RangeReport {
    let mut positions = vec![Position::default(); length];
    for observation in &observations {
        for (position, byte) in positions
            .iter_mut()
            .skip(observation.range_offset)
            .zip(&observation.bytes)
        {
            // A conflict stays a conflict even when later packets repeat the first value
            position.conflict |= position.value.is_some_and(|previous| previous != *byte);
            position.value.get_or_insert(*byte);
        }
    }
    let mut report = RangeReport {
        start_sequence,
        length,
        observed_bytes: 0,
        missing_bytes: 0,
        conflicting_bytes: 0,
        omitted_bytes: 0,
        omitted_observations,
        observations,
        spans: Vec::new(),
    };
    for (offset, (position, omitted)) in positions.into_iter().zip(omitted_coverage).enumerate() {
        let status = position.status();
        match status {
            SpanStatus::Observed => report.observed_bytes += 1,
            SpanStatus::Gap => report.missing_bytes += 1,
            SpanStatus::Conflict => report.conflicting_bytes += 1,
        }
        report.omitted_bytes += usize::from(*omitted);
        append_span(&mut report.spans, offset, status, *omitted, position.value);
    }
    report
}

fn append_span(
    spans: &mut Vec<Span>,
    offset: usize,
    status: SpanStatus,
    omitted: bool,
    value: Option<u8>,
) {
    if let Some(previous) = spans.last_mut()
        && previous.status == status
        && previous.omitted_observation == omitted
    {
        previous.length += 1;
        if let (Some(bytes), Some(value)) = (&mut previous.bytes, value) {
            bytes.push(value);
        }
        return;
    }
    spans.push(Span {
        offset,
        length: 1,
        status,
        omitted_observation: omitted,
        bytes: if status == SpanStatus::Observed {
            value.map(|byte| vec![byte])
        } else {
            None
        },
    });
}
