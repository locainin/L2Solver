use super::common::{context, set_checkpoint_field, transition_metadata_bytes};
use l2_workbench::protocol::{
    FramingKind, ProtocolLimits, StreamMessageParser, StreamTransitionState,
};
use l2_workbench::reconstruction::Origin;
use std::error::Error;

fn multi_gap_report(
    segmented: bool,
) -> Result<l2_workbench::protocol::StreamExtractionReport, Box<dyn Error>> {
    if !segmented {
        return Ok(multi_gap_parser()?.into_report()?);
    }
    let (prefix_origin, middle_origin, last_origin) = multi_gap_origins();
    let mut segmented_parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        ProtocolLimits::default(),
    )?;
    segmented_parser.push_chunk(0, b"old", &prefix_origin)?;
    segmented_parser.push_chunk(6, b"ab", &middle_origin)?;
    let checkpoint = serde_json::to_vec(&segmented_parser)?;
    let mut resumed: StreamMessageParser = serde_json::from_slice(&checkpoint)?;
    resumed.push_chunk(8, b"cd", &middle_origin)?;
    resumed.push_chunk(13, b"xyz", &last_origin)?;
    Ok(resumed.into_report()?)
}

const fn multi_gap_origins() -> ([Origin; 1], [Origin; 1], [Origin; 1]) {
    (
        [Origin {
            packet: 1,
            frame_offset: 40,
            offset: 0,
            length: 3,
        }],
        [Origin {
            packet: 2,
            frame_offset: 50,
            offset: 6,
            length: 4,
        }],
        [Origin {
            packet: 3,
            frame_offset: 70,
            offset: 13,
            length: 3,
        }],
    )
}

fn multi_gap_parser() -> Result<StreamMessageParser, Box<dyn Error>> {
    let (prefix_origin, middle_origin, last_origin) = multi_gap_origins();
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        ProtocolLimits::default(),
    )?;
    parser.push_chunk(0, b"old", &prefix_origin)?;
    parser.push_chunk(6, b"abcd", &middle_origin)?;
    parser.push_chunk(13, b"xyz", &last_origin)?;
    Ok(parser)
}

#[test]
fn sequence_gaps_without_inventing_frames() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        ProtocolLimits::default(),
    )?;
    parser.push_chunk(
        0,
        b"partial",
        &[Origin {
            packet: 1,
            frame_offset: 40,
            offset: 0,
            length: 7,
        }],
    )?;
    parser.push_chunk(
        12,
        b"later\n",
        &[Origin {
            packet: 3,
            frame_offset: 40,
            offset: 12,
            length: 6,
        }],
    )?;
    parser.finalize()?;
    let report = parser.into_report()?;

    assert_eq!(report.messages.len(), 0);
    assert!(report.transitions.iter().any(|transition| {
        transition.state == StreamTransitionState::SequenceGap
            && !transition.sequence_ambiguous
            && transition.stream_range.start == 7
            && transition.stream_range.end == 12
            && transition.evidence_sha256.is_none()
            && transition.origins.is_empty()
    }));
    let observed_tail = report
        .transitions
        .iter()
        .find(|transition| {
            transition.state == StreamTransitionState::UnresolvedTail
                && transition.stream_range.start == 12
                && transition.stream_range.end == 18
        })
        .ok_or("post-gap bytes were not retained as an unresolved tail")?;
    assert_eq!(
        observed_tail.evidence_sha256.as_deref(),
        Some(l2_workbench::sha256(b"later\n").as_str())
    );
    assert_eq!(observed_tail.origins.len(), 1);
    let origin = observed_tail
        .origins
        .first()
        .ok_or("tail origin is missing")?;
    assert_eq!(origin.packet, 3);
    assert_eq!(origin.frame_offset, 40);
    assert_eq!(origin.message_offset, 0);
    assert_eq!(origin.length, 6);
    Ok(())
}

#[test]
fn multiple_gaps_independent_observed_tails() -> Result<(), Box<dyn Error>> {
    let coalesced = multi_gap_report(false)?;
    let segmented = multi_gap_report(true)?;

    assert_eq!(segmented.messages, coalesced.messages);
    assert_eq!(segmented.transitions, coalesced.transitions);
    assert_eq!(segmented.input_bytes, coalesced.input_bytes);
    assert_eq!(segmented.input_bytes, 10);
    let gaps = segmented
        .transitions
        .iter()
        .filter(|transition| transition.state == StreamTransitionState::SequenceGap)
        .collect::<Vec<_>>();
    assert_eq!(gaps.len(), 2);
    assert_eq!(
        gaps.iter()
            .map(|transition| transition.stream_range)
            .collect::<Vec<_>>(),
        [
            l2_workbench::protocol::ByteRange { start: 3, end: 6 },
            l2_workbench::protocol::ByteRange { start: 10, end: 13 },
        ]
    );
    let tails = segmented
        .transitions
        .iter()
        .filter(|transition| transition.state == StreamTransitionState::UnresolvedTail)
        .collect::<Vec<_>>();
    assert_eq!(tails.len(), 3);
    assert_eq!(
        tails
            .iter()
            .map(|transition| transition.stream_range)
            .collect::<Vec<_>>(),
        [
            l2_workbench::protocol::ByteRange { start: 0, end: 3 },
            l2_workbench::protocol::ByteRange { start: 6, end: 10 },
            l2_workbench::protocol::ByteRange { start: 13, end: 16 },
        ]
    );
    assert_eq!(
        tails
            .get(1)
            .and_then(|transition| transition.evidence_sha256.as_deref()),
        Some(l2_workbench::sha256(b"abcd").as_str())
    );
    assert_eq!(
        tails
            .get(2)
            .and_then(|transition| transition.evidence_sha256.as_deref()),
        Some(l2_workbench::sha256(b"xyz").as_str())
    );
    Ok(())
}

#[test]
fn checkpoint_missing_tail_consistent_budget() -> Result<(), Box<dyn Error>> {
    let mut parser = multi_gap_parser()?;
    parser.finalize()?;
    let mut checkpoint = serde_json::to_value(parser)?;
    let transitions = checkpoint
        .get_mut("transitions")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("checkpoint has no transitions")?;
    let index = transitions
        .iter()
        .position(|transition| {
            transition.get("state") == Some(&serde_json::json!("unresolved_tail"))
                && transition
                    .get("stream_range")
                    .and_then(|range| range.get("start"))
                    == Some(&serde_json::json!(6))
                && transition
                    .get("stream_range")
                    .and_then(|range| range.get("end"))
                    == Some(&serde_json::json!(10))
        })
        .ok_or("checkpoint has no middle post-gap tail")?;
    let removed = transitions.remove(index);
    let origins = removed
        .get("origins")
        .and_then(serde_json::Value::as_array)
        .ok_or("post-gap tail has no origins")?
        .len();
    let digest_bytes = removed
        .get("evidence_sha256")
        .and_then(serde_json::Value::as_str)
        .ok_or("post-gap tail has no evidence digest")?
        .len();
    let removed_metadata = transition_metadata_bytes(&context(), origins, digest_bytes);
    let retained = checkpoint
        .get("retained_bytes")
        .and_then(serde_json::Value::as_u64)
        .ok_or("checkpoint has no retained byte count")?;
    let retained = usize::try_from(retained)?;
    set_checkpoint_field(
        &mut checkpoint,
        "retained_bytes",
        serde_json::json!(
            retained
                .checked_sub(removed_metadata)
                .ok_or("retained bytes are below removed tail metadata")?
        ),
    )?;
    let mut resumed: StreamMessageParser = serde_json::from_value(checkpoint)?;

    assert!(matches!(
        resumed.finalize(),
        Err(l2_workbench::protocol::ProtocolError::InvalidParserState)
    ));
    Ok(())
}

#[test]
fn legacy_checkpoint_gap_rejected_unaccounted() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        ProtocolLimits::default(),
    )?;
    parser.push_chunk(
        0,
        b"old",
        &[Origin {
            packet: 1,
            frame_offset: 40,
            offset: 0,
            length: 3,
        }],
    )?;
    parser.push_chunk(
        6,
        b"new",
        &[Origin {
            packet: 2,
            frame_offset: 60,
            offset: 6,
            length: 3,
        }],
    )?;
    let mut checkpoint = serde_json::to_value(parser)?;
    if let Some(object) = checkpoint.as_object_mut() {
        object.remove("checkpoint_version");
        object.remove("pending_unparsed");
    }
    let mut resumed: StreamMessageParser = serde_json::from_value(checkpoint)?;

    assert!(matches!(
        resumed.finalize(),
        Err(l2_workbench::protocol::ProtocolError::InvalidParserState)
    ));
    Ok(())
}

#[test]
fn gappy_checkpoint_pending_observed_bytes() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        ProtocolLimits::default(),
    )?;
    parser.push_chunk(
        0,
        b"old",
        &[Origin {
            packet: 1,
            frame_offset: 40,
            offset: 0,
            length: 3,
        }],
    )?;
    parser.push_chunk(
        6,
        b"new",
        &[Origin {
            packet: 2,
            frame_offset: 60,
            offset: 6,
            length: 3,
        }],
    )?;
    let mut checkpoint = serde_json::to_value(parser)?;
    checkpoint
        .as_object_mut()
        .ok_or("checkpoint is not an object")?
        .remove("pending_unparsed");
    let mut resumed: StreamMessageParser = serde_json::from_value(checkpoint)?;

    assert!(matches!(
        resumed.finalize(),
        Err(l2_workbench::protocol::ProtocolError::InvalidParserState)
    ));
    Ok(())
}

#[test]
fn finalized_gappy_resumes_mapped_tail() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        ProtocolLimits::default(),
    )?;
    parser.push_chunk(
        4,
        b"tail",
        &[Origin {
            packet: 2,
            frame_offset: 60,
            offset: 4,
            length: 4,
        }],
    )?;
    parser.finalize()?;
    let checkpoint = serde_json::to_vec(&parser)?;
    let resumed: StreamMessageParser = serde_json::from_slice(&checkpoint)?;
    let report = resumed.into_report()?;

    let tail = report
        .transitions
        .iter()
        .find(|transition| {
            transition.state == StreamTransitionState::UnresolvedTail
                && transition.stream_range.start == 4
                && transition.stream_range.end == 8
        })
        .ok_or("finalized checkpoint lost its observed tail")?;
    assert_eq!(
        tail.evidence_sha256.as_deref(),
        Some(l2_workbench::sha256(b"tail").as_str())
    );
    assert_eq!(tail.origins.len(), 1);
    Ok(())
}

#[test]
fn competing_framings_same_observed_bytes() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![
            FramingKind::Delimiter { byte: b'\n' },
            FramingKind::FixedSize { bytes: 2 },
        ],
        ProtocolLimits::default(),
    )?;
    parser.push_chunk(
        0,
        b"old",
        &[Origin {
            packet: 1,
            frame_offset: 40,
            offset: 0,
            length: 3,
        }],
    )?;
    parser.push_chunk(
        5,
        b"abcd",
        &[Origin {
            packet: 2,
            frame_offset: 60,
            offset: 5,
            length: 4,
        }],
    )?;
    let report = parser.into_report()?;

    let gaps = report
        .transitions
        .iter()
        .filter(|transition| transition.state == StreamTransitionState::SequenceGap)
        .collect::<Vec<_>>();
    assert_eq!(gaps.len(), 2);
    assert!(
        gaps.iter()
            .all(|transition| transition.stream_range.start == 3)
    );
    assert!(
        gaps.iter()
            .all(|transition| transition.stream_range.end == 5)
    );
    let post_gap_tails = report
        .transitions
        .iter()
        .filter(|transition| {
            transition.state == StreamTransitionState::UnresolvedTail
                && transition.stream_range.start == 5
                && transition.stream_range.end == 9
        })
        .collect::<Vec<_>>();
    assert_eq!(post_gap_tails.len(), 2);
    assert!(post_gap_tails.iter().all(|tail| {
        tail.evidence_sha256.as_deref() == Some(l2_workbench::sha256(b"abcd").as_str())
    }));
    Ok(())
}
