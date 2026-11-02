use l2_workbench::protocol::{self, FramingKind, MessageRole, MessageSample, ProtocolLimits};
use std::error::Error;

#[test]
fn length_prefix_candidates_holdout_counterexamples() -> Result<(), Box<dyn Error>> {
    let messages: [&[u8]; 5] = [
        &[4, 0x10, 0x11, 0x12],
        &[5, 0x20, 0x21, 0x22, 0x23],
        &[6, 0x30, 0x31, 0x32, 0x33, 0x34],
        &[7, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45],
        &[8, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56],
    ];
    let samples = samples(&messages)?;
    let report = protocol::infer_framing(&samples)?;
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| {
            candidate.kind
                == (FramingKind::LengthPrefix {
                    offset: 0,
                    width: 1,
                    byte_order: protocol::ByteOrder::BigEndian,
                    meaning: protocol::LengthMeaning::WholeMessage,
                })
        })
        .ok_or("one-byte whole-message candidate is missing")?;

    assert_eq!(candidate.discovery.supported, 2);
    assert_eq!(candidate.holdout.supported, 3);
    assert_eq!(candidate.holdout.counterexample_count, 0);
    assert_eq!(report.discovery_samples, [1, 2]);
    assert_eq!(report.holdout_samples, [3, 4, 5]);
    assert_ne!(report.limitations.len(), 0);
    Ok(())
}

#[test]
fn length_prefix_endian_trailing_bytes() -> Result<(), Box<dyn Error>> {
    let mut messages = Vec::new();
    for message_length in [8_usize, 9, 10, 11] {
        let trailing_length = message_length
            .checked_sub(6)
            .ok_or("fixture field exceeds message length")?;
        let encoded = u32::try_from(trailing_length)?.to_le_bytes();
        let mut message = vec![0xa5; message_length];
        let field = message
            .get_mut(2..6)
            .ok_or("fixture field range is invalid")?;
        field.copy_from_slice(&encoded);
        messages.push(message);
    }
    let message_refs = messages.iter().map(Vec::as_slice).collect::<Vec<&[u8]>>();
    let samples = samples(&message_refs)?;
    let report = protocol::infer_framing(&samples)?;
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| {
            candidate.kind
                == (FramingKind::LengthPrefix {
                    offset: 2,
                    width: 4,
                    byte_order: protocol::ByteOrder::LittleEndian,
                    meaning: protocol::LengthMeaning::BytesAfterField,
                })
        })
        .ok_or("nonzero-offset little-endian candidate is missing")?;

    assert_eq!(candidate.discovery.supported, 2);
    assert_eq!(candidate.holdout.supported, 2);
    assert_eq!(candidate.discovery.counterexample_count, 0);
    assert_eq!(candidate.holdout.counterexample_count, 0);
    Ok(())
}

#[test]
fn absent_length_fields_counted_untestable() -> Result<(), Box<dyn Error>> {
    let messages: [&[u8]; 4] = [b"a", b"bc", b"def", b"ghij"];
    let samples = samples(&messages)?;
    let report = protocol::infer_framing(&samples)?;
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| {
            candidate.kind
                == (FramingKind::LengthPrefix {
                    offset: 2,
                    width: 4,
                    byte_order: protocol::ByteOrder::BigEndian,
                    meaning: protocol::LengthMeaning::WholeMessage,
                })
        })
        .ok_or("absent-field candidate is missing")?;

    assert_eq!(candidate.discovery.compared, 0);
    assert_eq!(candidate.discovery.untestable_samples, 2);
    assert_eq!(candidate.holdout.compared, 0);
    assert_eq!(candidate.holdout.untestable_samples, 2);
    Ok(())
}

#[test]
fn delimiter_candidates_report_holdout_mismatches() -> Result<(), Box<dyn Error>> {
    let messages: [&[u8]; 4] = [b"A\n", b"BC\n", b"D\n", b"EF!"];
    let samples = samples(&messages)?;
    let report = protocol::infer_framing(&samples)?;
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.kind == FramingKind::Delimiter { byte: b'\n' })
        .ok_or("discovery terminator candidate is missing")?;
    let counterexample = candidate
        .holdout
        .counterexamples
        .first()
        .ok_or("holdout counterexample is missing")?;

    assert_eq!(candidate.discovery.supported, 2);
    assert_eq!(candidate.holdout.supported, 1);
    assert_eq!(candidate.holdout.counterexample_count, 1);
    assert_eq!(counterexample.sample, 4);
    Ok(())
}

#[test]
fn fixed_size_candidate_retained_competing() -> Result<(), Box<dyn Error>> {
    let messages: [&[u8]; 4] = [b"abcd", b"efgh", b"ijkl", b"mnop"];
    let samples = samples(&messages)?;
    let report = protocol::infer_framing(&samples)?;
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.kind == FramingKind::FixedSize { bytes: 4 })
        .ok_or("fixed-size candidate is missing")?;

    assert_eq!(candidate.discovery.supported, 2);
    assert_eq!(candidate.holdout.supported, 2);
    Ok(())
}

#[test]
fn candidate_budget_output_omitted_hypotheses() -> Result<(), Box<dyn Error>> {
    let messages: [&[u8]; 4] = [b"A\n", b"B\n", b"C\n", b"D\n"];
    let samples = samples(&messages)?;
    let limits = ProtocolLimits {
        max_candidates: 1,
        ..ProtocolLimits::default()
    };

    let report = protocol::infer_framing_with_limits(&samples, limits)?;

    assert_eq!(report.candidates.len(), 1);
    assert!(report.omitted_candidates > 0);
    Ok(())
}

#[test]
fn configured_prefix_beyond_default_domain() -> Result<(), Box<dyn Error>> {
    let mut messages = Vec::new();
    for length in 32_usize..36 {
        let mut message = vec![0xa5; length];
        let encoded = u8::try_from(length)?;
        *message
            .get_mut(20)
            .ok_or("missing configured prefix byte")? = encoded;
        messages.push(message);
    }
    let refs = messages.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let samples = samples(&refs)?;
    let limits = ProtocolLimits {
        max_prefix_offset: 20,
        ..ProtocolLimits::default()
    };

    let report = protocol::infer_framing_with_limits(&samples, limits)?;

    assert!(report.candidates.iter().any(|candidate| {
        candidate.kind
            == FramingKind::LengthPrefix {
                offset: 20,
                width: 1,
                byte_order: protocol::ByteOrder::BigEndian,
                meaning: protocol::LengthMeaning::WholeMessage,
            }
            && candidate.discovery.supported == 2
            && candidate.holdout.supported == 2
    }));
    Ok(())
}

#[test]
fn counterexample_preview_omissions_not_counts() -> Result<(), Box<dyn Error>> {
    let messages = (0..20)
        .map(|_| b"frame\n".as_slice())
        .chain((0..20).map(|_| b"tail!".as_slice()))
        .collect::<Vec<_>>();
    let samples = samples(&messages)?;

    let report = protocol::infer_framing(&samples)?;
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| candidate.kind == FramingKind::Delimiter { byte: b'\n' })
        .ok_or("discovery delimiter candidate is missing")?;

    assert_eq!(candidate.holdout.counterexample_count, 20);
    assert_eq!(candidate.holdout.counterexamples.len(), 16);
    assert_eq!(candidate.holdout.omitted_counterexamples, 4);
    Ok(())
}

#[test]
fn framing_requires_samples_bounded_input() {
    let repeated = [MessageSample {
        sample: 1,
        role: MessageRole::Unclassified,
        bytes: b"same",
        context: None,
    }];
    assert!(matches!(
        protocol::infer_framing(&repeated),
        Err(protocol::ProtocolError::InsufficientSamples { .. })
    ));

    let large = vec![0_u8; protocol::MAX_MESSAGE_BYTES + 1];
    let samples = [
        MessageSample {
            sample: 1,
            role: MessageRole::Unclassified,
            bytes: &large,
            context: None,
        },
        MessageSample {
            sample: 2,
            role: MessageRole::Unclassified,
            bytes: b"a",
            context: None,
        },
        MessageSample {
            sample: 3,
            role: MessageRole::Unclassified,
            bytes: b"b",
            context: None,
        },
        MessageSample {
            sample: 4,
            role: MessageRole::Unclassified,
            bytes: b"c",
            context: None,
        },
    ];
    assert!(matches!(
        protocol::infer_framing(&samples),
        Err(protocol::ProtocolError::MessageTooLarge { .. })
    ));
}

#[test]
fn protocol_errors_standard_error_reporting() -> Result<(), Box<dyn Error>> {
    let error = protocol::infer_framing(&[])
        .err()
        .ok_or("an empty sample set should be rejected")?;
    let standard_error: &dyn Error = &error;

    assert_ne!(error.to_string().len(), 0);
    assert!(standard_error.source().is_none());
    Ok(())
}

fn samples<'a>(messages: &[&'a [u8]]) -> Result<Vec<MessageSample<'a>>, Box<dyn Error>> {
    let mut samples = Vec::with_capacity(messages.len());
    for (index, bytes) in messages.iter().enumerate() {
        let number = index
            .checked_add(1)
            .ok_or("fixture sample number overflow")?;
        samples.push(MessageSample {
            sample: u64::try_from(number)?,
            role: MessageRole::Unclassified,
            bytes,
            context: None,
        });
    }
    Ok(samples)
}
