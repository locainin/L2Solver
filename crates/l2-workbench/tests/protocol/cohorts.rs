use l2_workbench::protocol::{
    self, CorrelationStatus, Direction, MessageContext, MessageRole, MessageSample, ProtocolLimits,
};
use std::error::Error;

#[test]
fn equal_fields_without_cross_matching() -> Result<(), Box<dyn Error>> {
    let messages = [
        (
            1,
            MessageRole::Request,
            b"\x11q".as_slice(),
            context(1, Direction::FirstToSecond),
        ),
        (
            2,
            MessageRole::Response,
            b"r\x11".as_slice(),
            context(1, Direction::SecondToFirst),
        ),
        (
            3,
            MessageRole::Request,
            b"\x12s".as_slice(),
            context(2, Direction::FirstToSecond),
        ),
        (
            4,
            MessageRole::Response,
            b"t\x12".as_slice(),
            context(2, Direction::SecondToFirst),
        ),
        (
            5,
            MessageRole::Request,
            b"\x2aQ".as_slice(),
            context(3, Direction::FirstToSecond),
        ),
        (
            6,
            MessageRole::Request,
            b"\x2aS".as_slice(),
            context(4, Direction::FirstToSecond),
        ),
        (
            7,
            MessageRole::Response,
            b"R\x2a".as_slice(),
            context(4, Direction::SecondToFirst),
        ),
        (
            8,
            MessageRole::Response,
            b"T\x2a".as_slice(),
            context(4, Direction::SecondToFirst),
        ),
    ];
    let samples = samples(&messages);

    let report = protocol::correlate_fields(&samples, 0, 1, 1)?;
    let [first, second] = report.holdout.transitions.as_slice() else {
        return Err("expected two holdout response transitions".into());
    };

    assert_eq!(first.status, CorrelationStatus::Unique);
    assert_eq!(first.request_sample, Some(6));
    assert_eq!(first.equal_outside_context_count, 1);
    assert_eq!(first.cross_session_equal_count, 1);
    assert_eq!(first.equal_outside_context_requests, [5]);
    assert_eq!(second.status, CorrelationStatus::CrossSessionEqual);
    assert_eq!(second.candidate_count, 0);
    assert_eq!(second.cross_session_equal_count, 1);
    assert_eq!(second.equal_outside_context_requests, [5]);
    Ok(())
}

#[test]
fn equal_fields_direction_context_mismatches() -> Result<(), Box<dyn Error>> {
    let messages = [
        (
            1,
            MessageRole::Request,
            b"\x2aQ".as_slice(),
            context(1, Direction::FirstToSecond),
        ),
        (
            2,
            MessageRole::Response,
            b"R\x2a".as_slice(),
            context(1, Direction::FirstToSecond),
        ),
        (
            3,
            MessageRole::Request,
            b"\x10S".as_slice(),
            context(2, Direction::FirstToSecond),
        ),
        (
            4,
            MessageRole::Response,
            b"T\x10".as_slice(),
            context(2, Direction::SecondToFirst),
        ),
    ];
    let samples = samples(&messages);

    let report = protocol::correlate_fields(&samples, 0, 1, 1)?;
    let [discovery] = report.discovery.transitions.as_slice() else {
        return Err("expected one discovery transition".into());
    };

    assert_eq!(discovery.status, CorrelationStatus::ContextMismatch);
    assert_eq!(discovery.equal_outside_context_count, 1);
    assert_eq!(discovery.cross_session_equal_count, 0);
    assert_eq!(discovery.equal_outside_context_requests, [1]);
    Ok(())
}

#[test]
fn equal_fields_source_context_mismatches() -> Result<(), Box<dyn Error>> {
    let mut other_source_request = context(3, Direction::FirstToSecond);
    other_source_request.source = "source-b".to_owned();
    let messages = [
        (
            1,
            MessageRole::Request,
            b"\x10q".as_slice(),
            context(1, Direction::FirstToSecond),
        ),
        (
            2,
            MessageRole::Response,
            b"r\x10".as_slice(),
            context(1, Direction::SecondToFirst),
        ),
        (
            3,
            MessageRole::Request,
            b"\x20s".as_slice(),
            context(2, Direction::FirstToSecond),
        ),
        (
            4,
            MessageRole::Response,
            b"t\x20".as_slice(),
            context(2, Direction::SecondToFirst),
        ),
        (
            5,
            MessageRole::Request,
            b"\x2aQ".as_slice(),
            other_source_request,
        ),
        (
            6,
            MessageRole::Response,
            b"R\x2a".as_slice(),
            context(4, Direction::SecondToFirst),
        ),
    ];
    let samples = samples(&messages);

    let report = protocol::correlate_fields(&samples, 0, 1, 1)?;
    let [transition] = report.holdout.transitions.as_slice() else {
        return Err("expected one holdout response transition".into());
    };

    assert_eq!(transition.status, CorrelationStatus::ContextMismatch);
    assert_eq!(transition.equal_outside_context_count, 1);
    assert_eq!(transition.cross_session_equal_count, 0);
    assert_eq!(transition.equal_outside_context_requests, [5]);
    Ok(())
}

#[test]
fn holdout_complete_sessions_together() -> Result<(), Box<dyn Error>> {
    let messages = [
        (
            1,
            MessageRole::Request,
            b"\x11q".as_slice(),
            context(1, Direction::FirstToSecond),
        ),
        (
            2,
            MessageRole::Response,
            b"r\x11".as_slice(),
            context(1, Direction::SecondToFirst),
        ),
        (
            3,
            MessageRole::Request,
            b"\x22s".as_slice(),
            context(2, Direction::FirstToSecond),
        ),
        (
            4,
            MessageRole::Response,
            b"t\x22".as_slice(),
            context(2, Direction::SecondToFirst),
        ),
        (
            5,
            MessageRole::Request,
            b"\x33u".as_slice(),
            context(3, Direction::FirstToSecond),
        ),
        (
            6,
            MessageRole::Response,
            b"v\x33".as_slice(),
            context(3, Direction::SecondToFirst),
        ),
        (
            7,
            MessageRole::Request,
            b"\x44w".as_slice(),
            context(4, Direction::FirstToSecond),
        ),
        (
            8,
            MessageRole::Response,
            b"x\x44".as_slice(),
            context(4, Direction::SecondToFirst),
        ),
    ];
    let samples = samples(&messages);

    let report = protocol::infer_framing(&samples)?;
    let discovery_sessions = session_ids(&report.discovery_samples, &samples);
    let holdout_sessions = session_ids(&report.holdout_samples, &samples);

    assert_eq!(discovery_sessions, [1, 1, 2, 2]);
    assert_eq!(holdout_sessions, [3, 3, 4, 4]);
    assert!(
        discovery_sessions
            .iter()
            .all(|id| !holdout_sessions.contains(id))
    );
    Ok(())
}

#[test]
fn partial_context_using_message_half() {
    let samples = [
        MessageSample {
            sample: 1,
            role: MessageRole::Unclassified,
            bytes: b"a",
            context: Some(context(1, Direction::FirstToSecond)),
        },
        MessageSample {
            sample: 2,
            role: MessageRole::Unclassified,
            bytes: b"b",
            context: None,
        },
        MessageSample {
            sample: 3,
            role: MessageRole::Unclassified,
            bytes: b"c",
            context: Some(context(2, Direction::FirstToSecond)),
        },
        MessageSample {
            sample: 4,
            role: MessageRole::Unclassified,
            bytes: b"d",
            context: Some(context(2, Direction::FirstToSecond)),
        },
    ];

    assert!(matches!(
        protocol::infer_framing(&samples),
        Err(protocol::ProtocolError::IncompleteContext { sample: 2 })
    ));
}

#[test]
fn field_candidate_aliases_holdout_counterexamples() -> Result<(), Box<dyn Error>> {
    let messages = [
        (
            1,
            MessageRole::Request,
            b"\x01\x01q".as_slice(),
            context(1, Direction::FirstToSecond),
        ),
        (
            2,
            MessageRole::Response,
            b"r\x01\x01".as_slice(),
            context(1, Direction::SecondToFirst),
        ),
        (
            3,
            MessageRole::Request,
            b"\x02\x02s".as_slice(),
            context(2, Direction::FirstToSecond),
        ),
        (
            4,
            MessageRole::Response,
            b"t\x02\x02".as_slice(),
            context(2, Direction::SecondToFirst),
        ),
        (
            5,
            MessageRole::Request,
            b"\x03\x04u".as_slice(),
            context(3, Direction::FirstToSecond),
        ),
        (
            6,
            MessageRole::Response,
            b"v\x05\x06".as_slice(),
            context(3, Direction::SecondToFirst),
        ),
        (
            7,
            MessageRole::Request,
            b"\x04\x06w".as_slice(),
            context(4, Direction::FirstToSecond),
        ),
        (
            8,
            MessageRole::Response,
            b"x\x07\x08".as_slice(),
            context(4, Direction::SecondToFirst),
        ),
    ];
    let samples = samples(&messages);

    let report = protocol::infer_correlation_candidates(&samples, ProtocolLimits::default())?;
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| {
            candidate.request_offset == 0 && candidate.response_offset == 1 && candidate.width == 1
        })
        .ok_or("expected first matching field candidate")?;
    let alias = candidate
        .aliases
        .iter()
        .find(|alias| alias.request_offset == 1 && alias.response_offset == 2 && alias.width == 1)
        .ok_or("same-observation alias should be retained")?;

    assert_eq!(candidate.discovery.supported_sessions, 2);
    assert_eq!(candidate.holdout.counterexample_count, 2);
    assert_eq!(candidate.holdout.counterexamples.len(), 2);
    assert_eq!(alias.discovery_supported_sessions, 2);
    assert!(!report.next_observation.is_empty());
    Ok(())
}

#[test]
fn protocol_limits_messages_configured_ceiling() -> Result<(), Box<dyn Error>> {
    let message_length = 66_000_usize;
    let mut messages = Vec::new();
    for length_delta in 0_u32..4 {
        let length = message_length + usize::try_from(length_delta)?;
        let mut message = vec![0x5a; length];
        let encoded = u32::try_from(length)?.to_be_bytes();
        message
            .get_mut(..4)
            .ok_or("missing length field")?
            .copy_from_slice(&encoded);
        messages.push(message);
    }
    let refs = messages.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let samples = unclassified_samples(&refs)?;
    let limits = ProtocolLimits {
        max_message_bytes: 70_000,
        max_total_bytes: 280_006,
        ..ProtocolLimits::default()
    };

    let report = protocol::infer_framing_with_limits(&samples, limits)?;
    assert!(report.candidates.iter().any(|candidate| {
        candidate.kind
            == protocol::FramingKind::LengthPrefix {
                offset: 0,
                width: 4,
                byte_order: protocol::ByteOrder::BigEndian,
                meaning: protocol::LengthMeaning::WholeMessage,
            }
            && candidate.discovery.supported == 2
            && candidate.holdout.supported == 2
    }));
    Ok(())
}

#[test]
fn candidate_counterexample_preview_omitted_sessions() -> Result<(), Box<dyn Error>> {
    let mut messages = Vec::new();
    for session in 1_u64..=40 {
        let value = u8::try_from(session)?;
        let response_value = if session <= 20 {
            value
        } else {
            value.wrapping_add(100)
        };
        messages.push((
            session * 2 - 1,
            MessageRole::Request,
            vec![value, 0xee],
            context(session, Direction::FirstToSecond),
        ));
        messages.push((
            session * 2,
            MessageRole::Response,
            vec![response_value, 0xff],
            context(session, Direction::SecondToFirst),
        ));
    }
    let samples = messages
        .iter()
        .map(|(sample, role, bytes, context)| MessageSample {
            sample: *sample,
            role: *role,
            bytes,
            context: Some(context.clone()),
        })
        .collect::<Vec<_>>();

    let report = protocol::infer_correlation_candidates(&samples, ProtocolLimits::default())?;
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| {
            candidate.request_offset == 0 && candidate.response_offset == 0 && candidate.width == 1
        })
        .ok_or("expected a first-byte equality candidate")?;

    assert_eq!(candidate.holdout.counterexample_count, 20);
    assert_eq!(candidate.holdout.counterexamples.len(), 16);
    assert_eq!(candidate.holdout.omitted_counterexamples, 4);
    Ok(())
}

fn context(session: u64, direction: Direction) -> MessageContext {
    MessageContext {
        source: "source-a".to_owned(),
        scope: "scope-a".to_owned(),
        session,
        direction,
    }
}

fn samples<'a>(
    messages: &[(u64, MessageRole, &'a [u8], MessageContext)],
) -> Vec<MessageSample<'a>> {
    messages
        .iter()
        .map(|(sample, role, bytes, context)| MessageSample {
            sample: *sample,
            role: *role,
            bytes,
            context: Some(context.clone()),
        })
        .collect()
}

fn unclassified_samples<'a>(
    messages: &[&'a [u8]],
) -> Result<Vec<MessageSample<'a>>, std::num::TryFromIntError> {
    messages
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            Ok(MessageSample {
                sample: u64::try_from(index + 1)?,
                role: MessageRole::Unclassified,
                bytes,
                context: None,
            })
        })
        .collect()
}

fn session_ids(ids: &[u64], samples: &[MessageSample<'_>]) -> Vec<u64> {
    ids.iter()
        .filter_map(|sample_id| {
            samples
                .iter()
                .find(|sample| sample.sample == *sample_id)
                .and_then(|sample| sample.context.as_ref())
                .map(|context| context.session)
        })
        .collect()
}
