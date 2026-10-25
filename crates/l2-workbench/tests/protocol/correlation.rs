use l2_workbench::protocol::{
    self, CorrelationStatus, Direction, MessageContext, MessageRole, MessageSample,
};
use std::error::Error;

#[test]
fn request_response_fields_only() -> Result<(), Box<dyn Error>> {
    let messages: [(&[u8], MessageRole); 5] = [
        (b"\x07a", MessageRole::Request),
        (b"b\x07", MessageRole::Response),
        (b"\x09c", MessageRole::Request),
        (b"d\x09", MessageRole::Response),
        (b"e\x0b", MessageRole::Response),
    ];
    let samples = message_samples(&messages)?;
    let report = protocol::correlate_fields(&samples, 0, 1, 1)?;

    assert_eq!(report.discovery.transitions.len(), 1);
    let [discovery] = report.discovery.transitions.as_slice() else {
        return Err("expected one discovery transition".into());
    };
    assert_eq!(discovery.status, CorrelationStatus::Unique);
    assert_eq!(discovery.request_sample, Some(1));
    assert_eq!(report.holdout.transitions.len(), 2);
    let [holdout_unique, holdout_unmatched] = report.holdout.transitions.as_slice() else {
        return Err("expected two holdout transitions".into());
    };
    assert_eq!(holdout_unique.status, CorrelationStatus::Unique);
    assert_eq!(holdout_unique.request_sample, Some(3));
    assert_eq!(holdout_unmatched.status, CorrelationStatus::Unmatched);
    Ok(())
}

#[test]
fn competing_requests_pending_ambiguous_response() -> Result<(), Box<dyn Error>> {
    let messages: [(&[u8], MessageRole); 8] = [
        (b"\x08a", MessageRole::Request),
        (b"\x08b", MessageRole::Request),
        (b"c\x08", MessageRole::Response),
        (b"d\x08", MessageRole::Response),
        (b"\x0ac", MessageRole::Request),
        (b"d\x0a", MessageRole::Response),
        (b"e\x0a", MessageRole::Response),
        (b"f\x0b", MessageRole::Response),
    ];
    let samples = message_samples(&messages)?;
    let report = protocol::correlate_fields(&samples, 0, 1, 1)?;

    let [discovery_ambiguous, discovery_still_ambiguous] = report.discovery.transitions.as_slice()
    else {
        return Err("expected two ambiguous discovery transitions".into());
    };
    assert_eq!(discovery_ambiguous.status, CorrelationStatus::Ambiguous);
    assert_eq!(discovery_ambiguous.candidate_count, 2);
    assert_eq!(
        discovery_still_ambiguous.status,
        CorrelationStatus::Ambiguous
    );
    assert_eq!(report.discovery.pending_requests, 2);
    let [holdout_unique, holdout_unmatched, holdout_unmatched_again] =
        report.holdout.transitions.as_slice()
    else {
        return Err("expected three holdout transitions".into());
    };
    assert_eq!(holdout_unique.status, CorrelationStatus::Unique);
    assert_eq!(holdout_unique.request_sample, Some(5));
    assert_eq!(holdout_unmatched.status, CorrelationStatus::Unmatched);
    assert_eq!(holdout_unmatched_again.status, CorrelationStatus::Unmatched);
    Ok(())
}

#[test]
fn malformed_field_rejected_reported_untestable() -> Result<(), Box<dyn Error>> {
    let messages: [(&[u8], MessageRole); 4] = [
        (b"\x01", MessageRole::Request),
        (b"\x01", MessageRole::Response),
        (b"\x02", MessageRole::Request),
        (b"\x02", MessageRole::Response),
    ];
    let samples = message_samples(&messages)?;

    assert!(matches!(
        protocol::correlate_fields(&samples, 0, 0, 0),
        Err(protocol::ProtocolError::InvalidFieldWidth { .. })
    ));
    let report = protocol::correlate_fields(&samples, 1, 1, 1)?;
    assert_eq!(report.discovery.untestable_requests, 1);
    let [discovery] = report.discovery.transitions.as_slice() else {
        return Err("expected one untestable discovery transition".into());
    };
    assert_eq!(discovery.status, CorrelationStatus::Untestable);
    assert_eq!(report.holdout.untestable_requests, 1);
    let [holdout] = report.holdout.transitions.as_slice() else {
        return Err("expected one untestable holdout transition".into());
    };
    assert_eq!(holdout.status, CorrelationStatus::Untestable);
    assert!(matches!(
        protocol::correlate_fields(&samples, protocol::MAX_MESSAGE_BYTES, 0, 1),
        Err(protocol::ProtocolError::InvalidFieldRange { .. })
    ));
    Ok(())
}

#[test]
fn selected_field_sixteen_bytes_messages() -> Result<(), Box<dyn Error>> {
    let field = vec![0x5a; 24];
    let messages = [
        (field.as_slice(), MessageRole::Request),
        (field.as_slice(), MessageRole::Response),
        (field.as_slice(), MessageRole::Request),
        (field.as_slice(), MessageRole::Response),
    ];
    let samples = message_samples(&messages)?;

    let report = protocol::correlate_fields(&samples, 0, 0, 24)?;

    assert!(
        report
            .discovery
            .transitions
            .iter()
            .chain(&report.holdout.transitions)
            .all(|transition| transition.status == CorrelationStatus::Unique)
    );
    Ok(())
}

#[test]
fn bounded_previews_omitted_counts_counts() -> Result<(), Box<dyn Error>> {
    let mut messages = (1..=44)
        .map(|_| (b"\xaaQ".as_slice(), MessageRole::Request))
        .collect::<Vec<_>>();
    messages.extend((0..4).map(|_| (b"R\xaa".as_slice(), MessageRole::Response)));
    let samples = message_samples(&messages)?;

    let report = protocol::correlate_fields(&samples, 0, 1, 1)?;

    let transition = report
        .holdout
        .transitions
        .first()
        .ok_or("expected an ambiguous holdout response")?;
    assert_eq!(transition.status, CorrelationStatus::Ambiguous);
    assert_eq!(transition.candidate_count, 20);
    assert_eq!(transition.candidate_requests.len(), 16);
    assert_eq!(transition.omitted_candidate_requests, 4);
    Ok(())
}

#[test]
fn cross_session_omitted_request_ids() -> Result<(), Box<dyn Error>> {
    let mut samples = Vec::new();
    for session in 1..=41 {
        samples.push(MessageSample {
            sample: session,
            role: MessageRole::Request,
            bytes: b"\xaaQ",
            context: Some(MessageContext {
                source: "capture".to_owned(),
                scope: "scope".to_owned(),
                session,
                direction: Direction::FirstToSecond,
            }),
        });
    }
    samples.push(MessageSample {
        sample: 42,
        role: MessageRole::Response,
        bytes: b"R\xaa",
        context: Some(MessageContext {
            source: "capture".to_owned(),
            scope: "scope".to_owned(),
            session: 42,
            direction: Direction::SecondToFirst,
        }),
    });

    let report = protocol::correlate_fields(&samples, 0, 1, 1)?;

    let transition = report
        .holdout
        .transitions
        .first()
        .ok_or("expected a cross-session holdout response")?;
    assert_eq!(transition.status, CorrelationStatus::CrossSessionEqual);
    assert_eq!(transition.cross_session_equal_count, 20);
    assert_eq!(transition.equal_outside_context_requests.len(), 16);
    assert_eq!(transition.omitted_equal_outside_context_requests, 4);
    Ok(())
}

fn message_samples<'a>(
    messages: &[(&'a [u8], MessageRole)],
) -> Result<Vec<MessageSample<'a>>, Box<dyn Error>> {
    let mut samples = Vec::with_capacity(messages.len());
    for (index, (bytes, role)) in messages.iter().enumerate() {
        let number = index
            .checked_add(1)
            .ok_or("fixture sample number overflow")?;
        samples.push(MessageSample {
            sample: u64::try_from(number)?,
            role: *role,
            bytes,
            context: None,
        });
    }
    Ok(samples)
}
