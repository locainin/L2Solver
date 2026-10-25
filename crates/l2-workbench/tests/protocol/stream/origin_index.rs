use super::common::context;
use l2_workbench::protocol::{
    FramingKind, MessageOrigin, ProtocolLimits, StreamExtractionReport, StreamMessageParser,
    StreamTransitionState,
};
use l2_workbench::reconstruction::Origin;
use std::{collections::BTreeSet, error::Error};

const fn origin(packet: u32, frame_offset: usize, offset: usize, length: usize) -> Origin {
    Origin {
        packet,
        frame_offset,
        offset,
        length,
    }
}

fn overlapping_origins() -> Vec<Origin> {
    let duplicate = origin(5, 40, 0, 3);
    vec![
        origin(8, 200, 2, 4),
        origin(3, 91, 1, 4),
        origin(6, 16, 0, 3),
        origin(7, 20, 0, 2),
        duplicate.clone(),
        origin(2, 150, 4, 2),
        origin(9, 300, 2, 1),
        duplicate,
    ]
}

fn parser_with_overlapping_origins() -> Result<StreamMessageParser, Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        ProtocolLimits::default(),
    )?;
    let origins = overlapping_origins();
    for (offset, bytes) in [(0, &b"a\n"[..]), (2, &b"b\n"[..]), (4, &b"c\n"[..])] {
        // The same full source map appears with each byte chunk, as it does for reconstructed runs
        parser.push_chunk(offset, bytes, &origins)?;
    }
    Ok(parser)
}

fn report_for_range(
    start: usize,
    end: usize,
    stream_length: usize,
    origins: &[Origin],
) -> Result<StreamExtractionReport, Box<dyn Error>> {
    let mut bytes = vec![b'x'; stream_length];
    let terminal = end.checked_sub(1).ok_or("range must be nonempty")?;
    *bytes
        .get_mut(terminal)
        .ok_or("range end must fit generated input")? = b'\n';
    if let Some(previous) = start.checked_sub(1) {
        *bytes
            .get_mut(previous)
            .ok_or("range start must fit generated input")? = b'\n';
    }

    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        ProtocolLimits::default(),
    )?;
    parser.push_chunk(0, &bytes, origins)?;
    Ok(parser.into_report()?)
}

fn linear_reference(
    start: usize,
    end: usize,
    input_origins: &[Origin],
) -> Result<Vec<MessageOrigin>, Box<dyn Error>> {
    let unique_origins = input_origins.iter().cloned().collect::<BTreeSet<_>>();
    let mut mapped = Vec::new();
    for origin in &unique_origins {
        let origin_end = origin
            .offset
            .checked_add(origin.length)
            .ok_or("test origin endpoint overflow")?;
        let overlap_start = start.max(origin.offset);
        let overlap_end = end.min(origin_end);
        if overlap_start < overlap_end {
            mapped.push(MessageOrigin {
                packet: origin.packet,
                frame_offset: origin
                    .frame_offset
                    .checked_add(overlap_start - origin.offset)
                    .ok_or("test frame offset overflow")?,
                message_offset: overlap_start - start,
                length: overlap_end - overlap_start,
            });
        }
    }
    mapped.sort_by_key(|mapped| (mapped.message_offset, mapped.packet, mapped.frame_offset));
    Ok(mapped)
}

#[test]
fn overlapping_origins_deduplicated_across_chunks() -> Result<(), Box<dyn Error>> {
    let origins = overlapping_origins();
    let report = parser_with_overlapping_origins()?.into_report()?;

    assert_eq!(report.messages.len(), 3);
    for (message, (start, end)) in report.messages.iter().zip([(0, 2), (2, 4), (4, 6)]) {
        assert_eq!(message.stream_range.start, start);
        assert_eq!(message.stream_range.end, end);
        assert_eq!(message.origins, linear_reference(start, end, &origins)?);
        assert!(
            message
                .origins
                .iter()
                .zip(message.origins.iter().skip(1))
                .all(|(left, right)| {
                    (left.message_offset, left.packet, left.frame_offset)
                        <= (right.message_offset, right.packet, right.frame_offset)
                })
        );
    }
    Ok(())
}

#[test]
fn byte_end_half_mapping_boundaries() -> Result<(), Box<dyn Error>> {
    let origins = overlapping_origins();
    let report = parser_with_overlapping_origins()?.into_report()?;
    let first_message = report
        .messages
        .first()
        .ok_or("first message was not retained")?;
    let second_message = report
        .messages
        .get(1)
        .ok_or("second message was not retained")?;

    assert!(
        first_message.origins.iter().any(|origin| {
            origin.packet == 7 && origin.frame_offset == 20 && origin.length == 2
        })
    );
    assert!(
        !first_message
            .origins
            .iter()
            .any(|origin| origin.packet == 9)
    );
    assert!(
        !second_message
            .origins
            .iter()
            .any(|origin| origin.packet == 7)
    );
    assert!(second_message.origins.iter().any(|origin| {
        origin.packet == 9 && origin.frame_offset == 300 && origin.message_offset == 0
    }));
    assert_eq!(first_message.origins, linear_reference(0, 2, &origins)?);
    assert_eq!(second_message.origins, linear_reference(2, 4, &origins)?);
    Ok(())
}

#[test]
fn checkpoint_source_sorted_array_resume() -> Result<(), Box<dyn Error>> {
    let origins = overlapping_origins();
    let expected_legacy_array = origins
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()?;
    let checkpoint = serde_json::to_value(parser_with_overlapping_origins()?)?;
    let stored_origins = checkpoint
        .get("source_origins")
        .and_then(serde_json::Value::as_array)
        .ok_or("checkpoint source_origins was not an array")?;

    assert_eq!(stored_origins, &expected_legacy_array);
    let mut duplicated_checkpoint = checkpoint.clone();
    duplicated_checkpoint
        .get_mut("source_origins")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("checkpoint source_origins was not an array")?
        .push(
            expected_legacy_array
                .first()
                .ok_or("legacy source map was empty")?
                .clone(),
        );
    let normalized_checkpoint = serde_json::to_value(
        serde_json::from_value::<StreamMessageParser>(duplicated_checkpoint)?,
    )?;
    assert_eq!(
        normalized_checkpoint
            .get("source_origins")
            .and_then(serde_json::Value::as_array)
            .ok_or("normalized source_origins was not an array")?,
        &expected_legacy_array
    );

    let resumed: StreamMessageParser = serde_json::from_value(checkpoint)?;
    let report = resumed.into_report()?;
    for (message, (start, end)) in report.messages.iter().zip([(0, 2), (2, 4), (4, 6)]) {
        assert_eq!(message.origins, linear_reference(start, end, &origins)?);
    }
    Ok(())
}

#[test]
fn checkpoint_invalid_overflowing_source_origins() -> Result<(), Box<dyn Error>> {
    let checkpoint = serde_json::to_value(parser_with_overlapping_origins()?)?;
    let invalid_origins = [
        origin(1, 0, usize::MAX, 1),
        origin(1, usize::MAX, 0, 1),
        origin(1, 0, 0, 0),
        origin(0, 0, 0, 1),
    ];

    for invalid_origin in invalid_origins {
        let mut malformed = checkpoint.clone();
        let source_origins = malformed
            .get_mut("source_origins")
            .and_then(serde_json::Value::as_array_mut)
            .ok_or("checkpoint source_origins was not an array")?;
        source_origins.clear();
        source_origins.push(serde_json::to_value(invalid_origin)?);
        assert!(serde_json::from_value::<StreamMessageParser>(malformed).is_err());
    }
    Ok(())
}

#[test]
fn sorted_origin_single_byte_mapping() -> Result<(), Box<dyn Error>> {
    const ORIGIN_COUNT: usize = 65_536;
    let limits = ProtocolLimits::default();
    let mut bytes = vec![b'x'; ORIGIN_COUNT];
    bytes.push(b'\n');
    let origins = (0..bytes.len())
        .map(|index| {
            Ok(origin(
                u32::try_from(index + 1)?,
                index.checked_mul(7).ok_or("test frame offset overflow")?,
                index,
                1,
            ))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        limits,
    )?;

    parser.push_chunk(0, &bytes, &origins)?;
    let report = parser.into_report()?;
    assert_eq!(report.messages.len(), 1);
    let message = report.messages.first().ok_or("message was not retained")?;
    assert_eq!(message.origins.len(), ORIGIN_COUNT + 1);
    for (index, source) in message.origins.iter().enumerate() {
        assert_eq!(source.packet, u32::try_from(index + 1)?);
        assert_eq!(source.frame_offset, index * 7);
        assert_eq!(source.message_offset, index);
        assert_eq!(source.length, 1);
    }
    Ok(())
}

#[test]
fn generated_half_linear_overlap_reference() -> Result<(), Box<dyn Error>> {
    const STREAM_LENGTH: usize = 12;
    let mut origins = Vec::new();
    let mut packet = 1_u32;
    for start in 0..STREAM_LENGTH {
        for end in start + 1..=STREAM_LENGTH {
            let frame_offset = usize::try_from(packet)?
                .checked_mul(31)
                .ok_or("test frame offset overflow")?;
            origins.push(origin(packet, frame_offset, start, end - start));
            packet += 1;
        }
    }

    // Same byte interval with different packet and frame tie-breakers
    origins.extend([
        origin(1_000, 50_000, 0, STREAM_LENGTH),
        origin(1_000, 50_001, 0, STREAM_LENGTH),
        origin(1_001, 50_000, 0, STREAM_LENGTH),
    ]);
    origins.push(
        origins
            .first()
            .ok_or("generated source map was empty")?
            .clone(),
    );

    for start in 0..STREAM_LENGTH {
        for end in start + 1..=STREAM_LENGTH {
            let report = report_for_range(start, end, STREAM_LENGTH, &origins)?;
            let message = report
                .messages
                .iter()
                .find(|message| {
                    message.stream_range.start == start && message.stream_range.end == end
                })
                .ok_or("selected test range was not emitted")?;
            assert_eq!(message.origins, linear_reference(start, end, &origins)?);
        }
    }
    Ok(())
}

#[test]
fn source_query_ends_usize_max() -> Result<(), Box<dyn Error>> {
    let start = usize::MAX - 3;
    let source = origin(1, start, start, 3);
    let limits = ProtocolLimits {
        max_total_bytes: 3,
        max_run_bytes: 3,
        ..ProtocolLimits::default()
    };
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        limits,
    )?;
    parser.push_chunk(start, b"ab\n", std::slice::from_ref(&source))?;
    let report = parser.into_report()?;
    let unresolved_tail = report
        .transitions
        .iter()
        .find(|transition| {
            transition.state == StreamTransitionState::UnresolvedTail
                && transition.stream_range.start == start
                && transition.stream_range.end == usize::MAX
        })
        .ok_or("high-offset unresolved tail was not retained")?;

    assert_eq!(
        unresolved_tail.origins,
        linear_reference(start, usize::MAX, &[source])?
    );
    Ok(())
}
