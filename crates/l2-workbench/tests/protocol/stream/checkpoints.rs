use super::common::{context, set_checkpoint_field};
use l2_workbench::protocol::{
    FramingKind, MessageRole, ProtocolLimits, StreamMessageParser, StreamTransitionState,
};
use l2_workbench::reconstruction::Origin;
use std::error::Error;

fn checkpoint_record<'a>(
    checkpoint: &'a serde_json::Value,
    records: &str,
    index: usize,
) -> Result<&'a serde_json::Value, Box<dyn Error>> {
    checkpoint
        .get(records)
        .and_then(serde_json::Value::as_array)
        .and_then(|records| records.get(index))
        .ok_or_else(|| format!("missing {records} record {index}").into())
}

fn checkpoint_record_mut<'a>(
    checkpoint: &'a mut serde_json::Value,
    records: &str,
    index: usize,
) -> Result<&'a mut serde_json::Value, Box<dyn Error>> {
    checkpoint
        .get_mut(records)
        .and_then(serde_json::Value::as_array_mut)
        .and_then(|records| records.get_mut(index))
        .ok_or_else(|| format!("missing {records} record {index}").into())
}

fn set_checkpoint_record_field(
    checkpoint: &mut serde_json::Value,
    records: &str,
    index: usize,
    field: &str,
    value: serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    checkpoint_record_mut(checkpoint, records, index)?
        .as_object_mut()
        .ok_or("checkpoint record is missing")?
        .insert(field.to_owned(), value);
    Ok(())
}

fn assert_checkpoint_change_rejected(
    mut checkpoint: serde_json::Value,
    record_array: &str,
    field: &str,
    value: serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    checkpoint
        .get_mut(record_array)
        .and_then(serde_json::Value::as_array_mut)
        .and_then(|records| records.first_mut())
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("missing checkpoint message or transition")?
        .insert(field.to_owned(), value);
    let mut resumed: StreamMessageParser = serde_json::from_value(checkpoint)?;
    let result = resumed.push_chunk(
        2,
        b"cd",
        &[Origin {
            packet: 2,
            frame_offset: 40,
            offset: 2,
            length: 2,
        }],
    );
    assert!(matches!(
        result,
        Err(l2_workbench::protocol::ProtocolError::InvalidParserState)
    ));
    Ok(())
}

#[test]
fn parser_state_resumes_across_pages() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        true,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        ProtocolLimits::default(),
    )?;
    parser.push_chunk(
        0,
        b"first",
        &[Origin {
            packet: 1,
            frame_offset: 40,
            offset: 0,
            length: 5,
        }],
    )?;

    let encoded = serde_json::to_vec(&parser)?;
    let mut resumed: StreamMessageParser = serde_json::from_slice(&encoded)?;
    resumed.push_chunk(
        5,
        b"\nsecond\n",
        &[Origin {
            packet: 2,
            frame_offset: 54,
            offset: 5,
            length: 8,
        }],
    )?;
    resumed.finalize()?;
    let report = resumed.into_report()?;

    assert_eq!(report.messages.len(), 2);
    assert_eq!(
        report
            .messages
            .first()
            .map(|message| message.bytes.as_slice()),
        Some(&b"first\n"[..])
    );
    assert_eq!(
        report
            .messages
            .get(1)
            .map(|message| message.bytes.as_slice()),
        Some(&b"second\n"[..])
    );
    assert!(
        report
            .messages
            .iter()
            .all(|message| message.generation_ambiguous)
    );
    assert!(
        report
            .messages
            .iter()
            .all(|message| !message.sequence_ambiguous)
    );
    assert!(
        report
            .transitions
            .iter()
            .any(|transition| { transition.state == StreamTransitionState::MessageBoundary })
    );
    Ok(())
}

#[test]
fn delimiter_parser_cursor_across_boundary() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        ProtocolLimits::default(),
    )?;
    parser.push_chunk(
        0,
        b"first",
        &[Origin {
            packet: 1,
            frame_offset: 40,
            offset: 0,
            length: 5,
        }],
    )?;
    let checkpoint = serde_json::to_value(parser)?;
    assert_eq!(
        checkpoint_record(&checkpoint, "candidates", 0)?.get("delimiter_scanned_to"),
        Some(&serde_json::json!(5)),
    );
    let mut resumed: StreamMessageParser = serde_json::from_value(checkpoint)?;
    resumed.push_chunk(
        5,
        b"\nsecond\n",
        &[Origin {
            packet: 2,
            frame_offset: 60,
            offset: 5,
            length: 8,
        }],
    )?;
    let report = resumed.into_report()?;

    assert_eq!(
        report
            .messages
            .iter()
            .map(|message| message.bytes.as_slice())
            .collect::<Vec<_>>(),
        [b"first\n".as_slice(), b"second\n".as_slice()]
    );
    Ok(())
}

#[test]
fn legacy_delimiter_checkpoint_unscanned_tail() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        ProtocolLimits::default(),
    )?;
    parser.push_chunk(
        0,
        b"first",
        &[Origin {
            packet: 1,
            frame_offset: 40,
            offset: 0,
            length: 5,
        }],
    )?;
    let mut checkpoint = serde_json::to_value(parser)?;
    if let Some(object) = checkpoint.as_object_mut() {
        object.remove("checkpoint_version");
        object.remove("pending_unparsed");
    }
    set_checkpoint_field(&mut checkpoint, "retained_bytes", serde_json::json!(5))?;
    checkpoint_record_mut(&mut checkpoint, "candidates", 0)?
        .as_object_mut()
        .ok_or("candidate is missing")?
        .remove("delimiter_scanned_to");
    let mut resumed: StreamMessageParser = serde_json::from_value(checkpoint)?;
    resumed.push_chunk(
        5,
        b"\n",
        &[Origin {
            packet: 2,
            frame_offset: 60,
            offset: 5,
            length: 1,
        }],
    )?;
    let report = resumed.into_report()?;

    assert_eq!(report.messages.len(), 1);
    assert_eq!(
        report
            .messages
            .first()
            .map(|message| message.bytes.as_slice()),
        Some(&b"first\n"[..])
    );
    Ok(())
}

#[test]
fn delimiter_checkpoint_cannot_already_scanned() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        ProtocolLimits::default(),
    )?;
    parser.push_chunk(
        0,
        b"first",
        &[Origin {
            packet: 1,
            frame_offset: 40,
            offset: 0,
            length: 5,
        }],
    )?;
    let mut checkpoint = serde_json::to_value(parser)?;
    set_checkpoint_record_field(
        &mut checkpoint,
        "candidates",
        0,
        "buffer",
        serde_json::json!([102, 105, 114, 115, 116, 10]),
    )?;
    set_checkpoint_record_field(
        &mut checkpoint,
        "candidates",
        0,
        "delimiter_scanned_to",
        serde_json::json!(6),
    )?;
    set_checkpoint_field(&mut checkpoint, "next_offset", serde_json::json!(6))?;
    set_checkpoint_field(&mut checkpoint, "total_input_bytes", serde_json::json!(6))?;
    set_checkpoint_field(&mut checkpoint, "retained_bytes", serde_json::json!(6))?;
    set_checkpoint_record_field(
        &mut checkpoint,
        "source_origins",
        0,
        "length",
        serde_json::json!(6),
    )?;
    let mut resumed: StreamMessageParser = serde_json::from_value(checkpoint)?;

    let result = resumed.push_chunk(
        6,
        b"next",
        &[Origin {
            packet: 2,
            frame_offset: 60,
            offset: 6,
            length: 4,
        }],
    );

    assert!(matches!(
        result,
        Err(l2_workbench::protocol::ProtocolError::InvalidParserState)
    ));
    Ok(())
}

#[test]
fn resumed_parser_outside_observed_stream() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::FixedSize { bytes: 3 }],
        ProtocolLimits::default(),
    )?;
    parser.push_chunk(
        0,
        b"ab",
        &[Origin {
            packet: 1,
            frame_offset: 40,
            offset: 0,
            length: 2,
        }],
    )?;
    let mut checkpoint = serde_json::to_value(parser)?;
    checkpoint
        .get_mut("candidates")
        .and_then(serde_json::Value::as_array_mut)
        .and_then(|candidates| candidates.first_mut())
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("missing checkpoint candidate")?
        .insert("buffer_start".to_owned(), usize::MAX.into());
    let mut forged = checkpoint.clone();
    forged
        .as_object_mut()
        .ok_or("checkpoint is not an object")?
        .insert("needs_validation".to_owned(), false.into());
    assert!(serde_json::from_value::<StreamMessageParser>(forged).is_err());
    let mut resumed: StreamMessageParser = serde_json::from_value(checkpoint)?;

    let result = resumed.push_chunk(
        2,
        b"c",
        &[Origin {
            packet: 2,
            frame_offset: 40,
            offset: 2,
            length: 1,
        }],
    );

    assert!(matches!(
        result,
        Err(l2_workbench::protocol::ProtocolError::InvalidParserState)
    ));
    Ok(())
}

#[test]
fn rejects_tampered_metadata() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::FixedSize { bytes: 2 }],
        ProtocolLimits::default(),
    )?;
    parser.push_chunk(
        0,
        b"ab",
        &[Origin {
            packet: 1,
            frame_offset: 40,
            offset: 0,
            length: 2,
        }],
    )?;
    let checkpoint = serde_json::to_value(parser)?;
    let changed_values = [
        ("role", serde_json::to_value(MessageRole::Request)?),
        ("assumption", serde_json::json!("observed_protocol")),
        ("generation_ambiguous", serde_json::json!(true)),
        ("sequence_ambiguous", serde_json::json!(true)),
    ];

    for record_array in ["messages", "transitions"] {
        for (field, value) in &changed_values {
            assert_checkpoint_change_rejected(
                checkpoint.clone(),
                record_array,
                field,
                value.clone(),
            )?;
        }
    }
    Ok(())
}

#[test]
fn resumed_parser_duplicate_message_intervals() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::FixedSize { bytes: 2 }],
        ProtocolLimits::default(),
    )?;
    parser.push_chunk(
        0,
        b"ab",
        &[Origin {
            packet: 1,
            frame_offset: 40,
            offset: 0,
            length: 2,
        }],
    )?;
    let mut checkpoint = serde_json::to_value(parser)?;
    let message = checkpoint_record(&checkpoint, "messages", 0)?.clone();
    let transition = checkpoint_record(&checkpoint, "transitions", 0)?.clone();
    checkpoint
        .get_mut("messages")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("messages are missing")?
        .push(message);
    checkpoint
        .get_mut("transitions")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("transitions are missing")?
        .push(transition);
    let retained = checkpoint
        .get("retained_bytes")
        .and_then(serde_json::Value::as_u64)
        .ok_or("retained bytes are missing")?;
    set_checkpoint_field(
        &mut checkpoint,
        "retained_bytes",
        serde_json::Value::from(retained + 2),
    )?;
    let mut resumed: StreamMessageParser = serde_json::from_value(checkpoint)?;

    let result = resumed.push_chunk(
        2,
        b"cd",
        &[Origin {
            packet: 2,
            frame_offset: 40,
            offset: 2,
            length: 2,
        }],
    );

    assert!(matches!(
        result,
        Err(l2_workbench::protocol::ProtocolError::InvalidParserState)
    ));
    Ok(())
}

#[test]
fn resumed_parser_message_boundary_transitions() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::FixedSize { bytes: 2 }],
        ProtocolLimits::default(),
    )?;
    parser.push_chunk(
        0,
        b"ab",
        &[Origin {
            packet: 1,
            frame_offset: 40,
            offset: 0,
            length: 2,
        }],
    )?;
    let mut checkpoint = serde_json::to_value(parser)?;
    let transition = checkpoint_record(&checkpoint, "transitions", 0)?.clone();
    checkpoint
        .get_mut("transitions")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("transitions are missing")?
        .push(transition);
    let mut resumed: StreamMessageParser = serde_json::from_value(checkpoint)?;

    let result = resumed.push_chunk(
        2,
        b"cd",
        &[Origin {
            packet: 2,
            frame_offset: 40,
            offset: 2,
            length: 2,
        }],
    );

    assert!(matches!(
        result,
        Err(l2_workbench::protocol::ProtocolError::InvalidParserState)
    ));
    Ok(())
}

#[test]
fn legacy_no_counter_canonical_accounting() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        ProtocolLimits::default(),
    )?;
    parser.push_chunk(
        0,
        b"head",
        &[Origin {
            packet: 1,
            frame_offset: 40,
            offset: 0,
            length: 4,
        }],
    )?;
    let mut checkpoint = serde_json::to_value(parser)?;
    if let Some(object) = checkpoint.as_object_mut() {
        object.remove("checkpoint_version");
        object.remove("pending_unparsed");
    }
    set_checkpoint_field(&mut checkpoint, "retained_bytes", serde_json::json!(4))?;
    let mut resumed: StreamMessageParser = serde_json::from_value(checkpoint)?;
    resumed.push_chunk(
        4,
        b"\n",
        &[Origin {
            packet: 2,
            frame_offset: 50,
            offset: 4,
            length: 1,
        }],
    )?;
    let migrated = serde_json::to_value(resumed)?;

    assert_eq!(
        migrated.get("checkpoint_version"),
        Some(&serde_json::json!(1))
    );
    assert!(
        migrated
            .get("retained_bytes")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|bytes| bytes > 5)
    );
    Ok(())
}

#[test]
fn parser_rejects_unknown_checkpoint_versions() -> Result<(), Box<dyn Error>> {
    let parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        ProtocolLimits::default(),
    )?;
    let mut checkpoint = serde_json::to_value(parser)?;
    set_checkpoint_field(&mut checkpoint, "checkpoint_version", serde_json::json!(3))?;
    let mut resumed: StreamMessageParser = serde_json::from_value(checkpoint)?;

    assert!(matches!(
        resumed.finalize(),
        Err(l2_workbench::protocol::ProtocolError::InvalidParserState)
    ));
    Ok(())
}
