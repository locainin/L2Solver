#![no_main]

use l2_workbench::tcp_range::{
    MAX_OBSERVATIONS, MAX_RANGE_BYTES, Observation, Segment, SpanStatus, TcpRange,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_SEGMENTS: usize = MAX_OBSERVATIONS + 2;

struct InputSegment<'a> {
    packet_index: u32,
    payload_frame_offset: usize,
    sequence: u32,
    flags: u8,
    payload: &'a [u8],
}

impl InputSegment<'_> {
    const fn borrowed(&self) -> Segment<'_> {
        Segment {
            packet_index: self.packet_index,
            payload_frame_offset: self.payload_frame_offset,
            sequence: self.sequence,
            flags: self.flags,
            payload: self.payload,
        }
    }
}

#[derive(Clone, Copy, Default)]
struct ExpectedPosition {
    // Keep the first source value and mark disagreement without selecting a winner
    value: Option<u8>,
    conflict: bool,
    omitted: bool,
}

fn range_intersection(
    start_sequence: u32,
    range_length: usize,
    segment: &InputSegment<'_>,
) -> (usize, usize, usize) {
    // Use a signed modular distance as an independent overlap calculation
    let data_sequence = segment
        .sequence
        // SYN consumes one sequence position before payload bytes
        .wrapping_add(u32::from(segment.flags & 0x02 != 0));
    let difference = i32::from_be_bytes(data_sequence.wrapping_sub(start_sequence).to_be_bytes());
    if difference >= 0 {
        let Ok(offset) = usize::try_from(difference) else {
            return (0, 0, 0);
        };
        if offset < range_length {
            return (offset, 0, segment.payload.len().min(range_length - offset));
        }
    } else {
        let Ok(skip) = usize::try_from(difference.unsigned_abs()) else {
            return (0, 0, 0);
        };
        if skip < segment.payload.len() {
            return (0, skip, range_length.min(segment.payload.len() - skip));
        }
    }
    (0, 0, 0)
}

fn verify_range(
    start_sequence: u32,
    range_length: usize,
    inputs: &[InputSegment<'_>],
) -> l2_workbench::tcp_range::RangeReport {
    let Ok(mut range) = TcpRange::new(start_sequence, range_length) else {
        unreachable!("generated range length is within the public ceiling");
    };
    let mut retained = Vec::with_capacity(inputs.len());
    for input in inputs {
        let Ok(result) = range.observe(input.borrowed()) else {
            unreachable!("generated source locations and payloads are bounded");
        };
        retained.push(result);
    }
    let report = range.finish();
    check_report(start_sequence, range_length, inputs, &retained, &report);
    report
}

fn check_report(
    start_sequence: u32,
    range_length: usize,
    inputs: &[InputSegment],
    retained: &[bool],
    report: &l2_workbench::tcp_range::RangeReport,
) {
    assert_eq!(report.start_sequence, start_sequence);
    assert_eq!(report.length, range_length);
    assert_eq!(inputs.len(), retained.len());

    let mut expected = vec![ExpectedPosition::default(); range_length];
    let mut retained_index = 0;
    let mut omitted_observations = 0_u64;
    let mut omitted_started = false;
    for (input, retained) in inputs.iter().zip(retained) {
        let (range_offset, skip, length) = range_intersection(start_sequence, range_length, input);
        let eligible = length > 0 || input.flags & 0x07 != 0;
        if !eligible {
            assert!(!retained);
            continue;
        }
        if !retained {
            // Omitted positions stay visible even though their source bytes are absent
            omitted_started = true;
            omitted_observations += 1;
            for position in expected.iter_mut().skip(range_offset).take(length) {
                position.omitted = true;
            }
            continue;
        }

        assert!(!omitted_started);
        let Some(observation) = report.observations.get(retained_index) else {
            unreachable!("each retained input produces one observation");
        };
        retained_index += 1;
        check_observation(input, observation, range_offset, skip, length);
        for (position, byte) in expected
            .iter_mut()
            .skip(range_offset)
            .zip(input.payload.iter().skip(skip).take(length))
        {
            position.conflict |= position.value.is_some_and(|previous| previous != *byte);
            position.value.get_or_insert(*byte);
        }
    }

    assert_eq!(retained_index, report.observations.len());
    check_totals(&expected, omitted_observations, report);
    check_spans(range_length, &expected, report);
}

fn check_totals(
    expected: &[ExpectedPosition],
    omitted_observations: u64,
    report: &l2_workbench::tcp_range::RangeReport,
) {
    assert_eq!(report.omitted_observations, omitted_observations);
    let mut observed_bytes = 0;
    let mut missing_bytes = 0;
    let mut conflicting_bytes = 0;
    let mut omitted_bytes = 0;
    for position in expected {
        match expected_status(*position) {
            SpanStatus::Observed => observed_bytes += 1,
            SpanStatus::Gap => missing_bytes += 1,
            SpanStatus::Conflict => conflicting_bytes += 1,
        }
        omitted_bytes += usize::from(position.omitted);
    }
    assert_eq!(
        (
            report.observed_bytes,
            report.missing_bytes,
            report.conflicting_bytes,
            report.omitted_bytes,
        ),
        (
            observed_bytes,
            missing_bytes,
            conflicting_bytes,
            omitted_bytes,
        )
    );
    assert_eq!(
        report.has_unique_coverage(),
        missing_bytes == 0 && conflicting_bytes == 0 && omitted_observations == 0
    );
}

fn check_spans(
    range_length: usize,
    expected: &[ExpectedPosition],
    report: &l2_workbench::tcp_range::RangeReport,
) {
    // Consecutive spans must form one exact partition of the selected range
    let mut offset = 0;
    for span in &report.spans {
        assert_eq!(span.offset, offset);
        assert!(span.length > 0);
        let end = offset + span.length;
        assert!(end <= range_length);
        let Some(positions) = expected.get(offset..end) else {
            unreachable!("span partitions stay inside the selected range");
        };
        for position in positions {
            assert_eq!(span.status, expected_status(*position));
            assert_eq!(span.omitted_observation, position.omitted);
        }
        match span.status {
            SpanStatus::Observed => {
                let Some(bytes) = span.bytes.as_ref() else {
                    unreachable!("observed spans carry their unambiguous values");
                };
                let mut expected_bytes = Vec::with_capacity(span.length);
                for position in positions {
                    let Some(value) = position.value else {
                        unreachable!("observed positions have a retained value");
                    };
                    expected_bytes.push(value);
                }
                assert_eq!(bytes, &expected_bytes);
            }
            SpanStatus::Conflict | SpanStatus::Gap => assert!(span.bytes.is_none()),
        }
        offset = end;
    }
    assert_eq!(offset, range_length);
}

fn check_observation(
    input: &InputSegment<'_>,
    observation: &Observation,
    range_offset: usize,
    skip: usize,
    length: usize,
) {
    assert_eq!(observation.packet_index, input.packet_index);
    assert_eq!(observation.sequence, input.sequence);
    assert_eq!(observation.flags, input.flags);
    assert_eq!(observation.range_offset, range_offset);
    assert_eq!(
        observation.payload_frame_offset,
        input.payload_frame_offset + skip
    );
    let Some(bytes) = input.payload.get(skip..skip + length) else {
        unreachable!("expected clipping stays inside the source payload");
    };
    assert_eq!(observation.bytes, bytes);
}

const fn expected_status(position: ExpectedPosition) -> SpanStatus {
    if position.conflict {
        SpanStatus::Conflict
    } else if position.value.is_some() {
        SpanStatus::Observed
    } else {
        SpanStatus::Gap
    }
}

fn decode_input(data: &[u8]) -> Option<(u32, usize, Vec<InputSegment<'_>>)> {
    let header = data.get(..6)?;
    let start_sequence = u32::from_be_bytes(header.get(..4)?.try_into().ok()?);
    let encoded_length = u16::from_be_bytes(header.get(4..6)?.try_into().ok()?);
    let range_length = usize::from(encoded_length) % MAX_RANGE_BYTES + 1;
    let mut inputs = Vec::new();
    let mut cursor = 6_usize;
    while inputs.len() < MAX_INPUT_SEGMENTS {
        let Some(header_end) = cursor.checked_add(9) else {
            break;
        };
        let Some(segment_header) = data.get(cursor..header_end) else {
            break;
        };
        let delta = u32::from_be_bytes(segment_header.get(..4)?.try_into().ok()?);
        let flags = *segment_header.get(4)?;
        let frame_offset = usize::from(u16::from_be_bytes(
            segment_header.get(5..7)?.try_into().ok()?,
        ));
        let encoded_payload_length = usize::from(u16::from_be_bytes(
            segment_header.get(7..9)?.try_into().ok()?,
        ));
        let payload_start = header_end;
        let available = data.get(payload_start..)?;
        let payload_length = encoded_payload_length
            .min(available.len())
            .min(MAX_RANGE_BYTES);
        let payload = available.get(..payload_length)?;
        let Ok(packet_index) = u32::try_from(inputs.len() + 1) else {
            break;
        };
        let data_sequence = start_sequence.wrapping_add(delta);
        inputs.push(InputSegment {
            packet_index,
            payload_frame_offset: frame_offset,
            sequence: data_sequence.wrapping_sub(u32::from(flags & 0x02 != 0)),
            flags,
            payload,
        });
        cursor = payload_start.checked_add(payload_length)?;
        if payload_length < encoded_payload_length {
            break;
        }
    }
    Some((start_sequence, range_length, inputs))
}

fn check_quota_path(data: &[u8]) {
    let Some(&first_byte) = data.first() else {
        return;
    };
    if first_byte & 0x80 == 0 {
        return;
    }
    let Some(prefix) = data.get(..4) else {
        return;
    };
    let Ok(prefix) = <[u8; 4]>::try_from(prefix) else {
        return;
    };
    let start_sequence = u32::from_be_bytes(prefix);
    let range_length = usize::from(first_byte & 0x0f) + 1;
    // Keep every generated byte in range while exceeding the observation cap
    let mut inputs = Vec::with_capacity(MAX_INPUT_SEGMENTS);
    for index in 0..MAX_INPUT_SEGMENTS {
        let source_index = index % data.len();
        let Some(payload) = data.get(source_index..source_index + 1) else {
            return;
        };
        let Some(&source_byte) = payload.first() else {
            unreachable!("generated quota payloads contain one source byte");
        };
        let data_offset = index % range_length;
        let flags = 0x10 | (source_byte & 0x07);
        let Ok(packet_index) = u32::try_from(index + 1) else {
            return;
        };
        let Ok(data_offset) = u32::try_from(data_offset) else {
            return;
        };
        let data_sequence = start_sequence.wrapping_add(data_offset);
        inputs.push(InputSegment {
            packet_index,
            payload_frame_offset: index,
            sequence: data_sequence.wrapping_sub(u32::from(flags & 0x02 != 0)),
            flags,
            payload,
        });
    }
    let report = verify_range(start_sequence, range_length, &inputs);
    assert!(report.omitted_observations > 0);
}

fuzz_target!(|data: &[u8]| {
    if let Some((start_sequence, range_length, inputs)) = decode_input(data) {
        verify_range(start_sequence, range_length, &inputs);
    }
    check_quota_path(data);
});
