use super::common::context;
use l2_workbench::protocol::{FramingKind, MessageRole, ProtocolLimits, StreamMessageParser};
use l2_workbench::reconstruction::Origin;
use std::error::Error;

fn delimiter_and_fixed_size() -> Vec<FramingKind> {
    vec![
        FramingKind::Delimiter { byte: b'\n' },
        FramingKind::FixedSize { bytes: 3 },
    ]
}

#[test]
fn stream_parser_maps_messages_packets() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        delimiter_and_fixed_size(),
        ProtocolLimits::default(),
    )?;
    let first = [Origin {
        packet: 4,
        frame_offset: 54,
        offset: 0,
        length: 2,
    }];
    let second = [Origin {
        packet: 7,
        frame_offset: 62,
        offset: 2,
        length: 4,
    }];

    parser.push_chunk(0, b"ab", &first)?;
    parser.push_chunk(2, b"\ncd\n", &second)?;
    parser.finalize()?;
    let report = parser.into_report()?;

    let delimiter = report
        .messages
        .iter()
        .filter(|message| message.framing == FramingKind::Delimiter { byte: b'\n' })
        .collect::<Vec<_>>();
    let fixed = report
        .messages
        .iter()
        .filter(|message| message.framing == FramingKind::FixedSize { bytes: 3 })
        .collect::<Vec<_>>();
    assert_eq!(delimiter.len(), 2);
    let first_delimited = delimiter.first().ok_or("missing first delimiter frame")?;
    assert_eq!(first_delimited.bytes, b"ab\n");
    assert_eq!(first_delimited.stream_range.start, 0);
    assert_eq!(first_delimited.stream_range.end, 3);
    assert_eq!(first_delimited.origins.len(), 2);
    assert_eq!(
        first_delimited.origins.first().map(|origin| origin.packet),
        Some(4)
    );
    assert_eq!(
        first_delimited.origins.get(1).map(|origin| origin.packet),
        Some(7)
    );
    assert_eq!(fixed.len(), 2);
    assert_eq!(
        fixed.first().map(|message| message.bytes.as_slice()),
        Some(&b"ab\n"[..])
    );
    assert!(report.messages.iter().all(|message| {
        message.role.is_none()
            && !message.generation_ambiguous
            && message.assumption == "candidate_framing"
    }));
    assert!(report.transitions.iter().all(|transition| {
        transition.role.is_none()
            && transition.context.source == "sha256:source"
            && transition.assumption == "candidate_framing"
    }));
    Ok(())
}

#[test]
fn chunk_segmentation_candidate_boundaries_origins() -> Result<(), Box<dyn Error>> {
    let bytes = b"a\nb\nc\n";
    let origin = [Origin {
        packet: 6,
        frame_offset: 42,
        offset: 0,
        length: bytes.len(),
    }];
    let framings = vec![FramingKind::Delimiter { byte: b'\n' }];
    let mut coalesced = StreamMessageParser::new(
        context(),
        false,
        false,
        framings.clone(),
        ProtocolLimits::default(),
    )?;
    coalesced.push_chunk(0, bytes, &origin)?;
    let coalesced = coalesced.into_report()?;

    let mut segmented =
        StreamMessageParser::new(context(), false, false, framings, ProtocolLimits::default())?;
    segmented.push_chunk(0, b"a", &origin)?;
    segmented.push_chunk(1, b"\nb\n", &origin)?;
    segmented.push_chunk(4, b"c\n", &origin)?;
    let segmented = segmented.into_report()?;

    assert_eq!(segmented.messages, coalesced.messages);
    assert_eq!(segmented.transitions, coalesced.transitions);
    assert_eq!(segmented.input_bytes, coalesced.input_bytes);
    Ok(())
}

#[test]
fn parser_roles_until_evidence_supplied() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        ProtocolLimits::default(),
    )?;
    parser.push_chunk(
        0,
        b"data\n",
        &[Origin {
            packet: 4,
            frame_offset: 54,
            offset: 0,
            length: 5,
        }],
    )?;

    let report = parser.into_report()?;
    let message = report.messages.first().ok_or("missing extracted message")?;
    assert!(message.role.is_none());
    assert_ne!(Some(MessageRole::Request), message.role);
    Ok(())
}
