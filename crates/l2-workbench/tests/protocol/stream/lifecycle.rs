use super::common::{context, set_checkpoint_field, transition_metadata_bytes};
use l2_workbench::protocol::{
    ByteOrder, FramingKind, LengthMeaning, ProtocolLimits, StreamMessageParser,
};
use l2_workbench::reconstruction::Origin;
use std::error::Error;

const fn source_origin(packet: u32, offset: usize, length: usize) -> Origin {
    Origin {
        packet,
        frame_offset: 40,
        offset,
        length,
    }
}

fn set_candidate_field(
    checkpoint: &mut serde_json::Value,
    field: &str,
    value: serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    checkpoint
        .get_mut("candidates")
        .and_then(serde_json::Value::as_array_mut)
        .and_then(|candidates| candidates.first_mut())
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("checkpoint has no first candidate")?
        .insert(field.to_owned(), value);
    Ok(())
}

fn set_first_record_field(
    checkpoint: &mut serde_json::Value,
    records: &str,
    field: &str,
    value: serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    checkpoint
        .get_mut(records)
        .and_then(serde_json::Value::as_array_mut)
        .and_then(|items| items.first_mut())
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| format!("checkpoint has no first {records} record"))?
        .insert(field.to_owned(), value);
    Ok(())
}

fn set_gap_start(checkpoint: &mut serde_json::Value, start: usize) -> Result<(), Box<dyn Error>> {
    let transitions = checkpoint
        .get_mut("transitions")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("checkpoint has no transition list")?;
    let gap = transitions
        .iter_mut()
        .find(|transition| transition.get("state") == Some(&serde_json::json!("sequence_gap")))
        .ok_or("checkpoint has no sequence gap transition")?;
    gap.get_mut("stream_range")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("gap transition has no stream range")?
        .insert("start".to_owned(), serde_json::json!(start));
    Ok(())
}

fn remove_pre_gap_tail(checkpoint: &mut serde_json::Value) -> Result<(), Box<dyn Error>> {
    let transitions = checkpoint
        .get_mut("transitions")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("checkpoint has no transition list")?;
    let removed = transitions
        .iter()
        .position(|transition| {
            transition.get("state") == Some(&serde_json::json!("unresolved_tail"))
                && transition
                    .get("stream_range")
                    .and_then(|range| range.get("start"))
                    == Some(&serde_json::json!(0))
                && transition
                    .get("stream_range")
                    .and_then(|range| range.get("end"))
                    == Some(&serde_json::json!(3))
        })
        .ok_or("checkpoint has no pre-gap tail")?;
    transitions.remove(removed);

    // Keep retained metadata accounting consistent so lifecycle validation is exercised
    let retained = checkpoint
        .get("retained_bytes")
        .and_then(serde_json::Value::as_u64)
        .ok_or("checkpoint retained byte count is missing")?;
    let retained = usize::try_from(retained)?;
    let removed_bytes = transition_metadata_bytes(&context(), 1, 64);
    set_checkpoint_field(
        checkpoint,
        "retained_bytes",
        serde_json::json!(
            retained
                .checked_sub(removed_bytes)
                .ok_or("retained byte count is smaller than removed transition")?
        ),
    )
}

#[test]
fn no_gap_observed_input_count() -> Result<(), Box<dyn Error>> {
    let limits = ProtocolLimits {
        max_run_bytes: 1,
        max_total_bytes: 1,
        ..ProtocolLimits::default()
    };
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        limits,
    )?;
    parser.push_chunk(0, b"a", &[source_origin(1, 0, 1)])?;

    let mut checkpoint = serde_json::to_value(parser)?;
    set_checkpoint_field(&mut checkpoint, "total_input_bytes", serde_json::json!(0))?;
    let mut resumed: StreamMessageParser = serde_json::from_value(checkpoint)?;

    assert!(matches!(
        resumed.push_chunk(1, b"b", &[source_origin(2, 1, 1)]),
        Err(l2_workbench::protocol::ProtocolError::InvalidParserState)
    ));
    Ok(())
}

#[test]
fn gappy_checkpoint_without_missing_ranges() -> Result<(), Box<dyn Error>> {
    let limits = ProtocolLimits {
        max_run_bytes: 2,
        max_total_bytes: 2,
        ..ProtocolLimits::default()
    };
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        limits,
    )?;
    parser.push_chunk(0, b"a", &[source_origin(1, 0, 1)])?;
    parser.push_chunk(3, b"b", &[source_origin(2, 3, 1)])?;

    let mut checkpoint = serde_json::to_value(parser)?;
    set_checkpoint_field(&mut checkpoint, "total_input_bytes", serde_json::json!(0))?;
    let mut resumed: StreamMessageParser = serde_json::from_value(checkpoint)?;

    assert!(matches!(
        resumed.push_chunk(4, b"c", &[source_origin(3, 4, 1)]),
        Err(l2_workbench::protocol::ProtocolError::InvalidParserState)
    ));
    Ok(())
}

#[test]
fn checkpoint_cannot_active_candidate_suffix() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        ProtocolLimits::default(),
    )?;
    parser.push_chunk(0, b"abc", &[source_origin(1, 0, 3)])?;

    let mut checkpoint = serde_json::to_value(parser)?;
    set_candidate_field(&mut checkpoint, "buffer", serde_json::json!([]))?;
    set_candidate_field(
        &mut checkpoint,
        "delimiter_scanned_to",
        serde_json::json!(0),
    )?;
    let retained = checkpoint
        .get("retained_bytes")
        .and_then(serde_json::Value::as_u64)
        .ok_or("checkpoint retained byte count is missing")?;
    set_checkpoint_field(
        &mut checkpoint,
        "retained_bytes",
        serde_json::json!(
            usize::try_from(retained)?
                .checked_sub(3)
                .ok_or("retained byte count is smaller than buffer")?
        ),
    )?;
    let resumed: StreamMessageParser = serde_json::from_value(checkpoint)?;

    assert!(matches!(
        resumed.into_report(),
        Err(l2_workbench::protocol::ProtocolError::InvalidParserState)
    ));
    Ok(())
}

#[test]
fn checkpoint_cannot_reactivate_terminal_candidate() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::LengthPrefix {
            offset: 0,
            width: 1,
            byte_order: ByteOrder::BigEndian,
            meaning: LengthMeaning::WholeMessage,
        }],
        ProtocolLimits::default(),
    )?;
    parser.push_chunk(0, b"\0", &[source_origin(1, 0, 1)])?;

    let mut checkpoint = serde_json::to_value(parser)?;
    set_candidate_field(&mut checkpoint, "active", serde_json::json!(true))?;
    let mut resumed: StreamMessageParser = serde_json::from_value(checkpoint)?;

    assert!(matches!(
        resumed.push_chunk(1, &[2, b'x'], &[source_origin(2, 1, 2)]),
        Err(l2_workbench::protocol::ProtocolError::InvalidParserState)
    ));
    Ok(())
}

#[test]
fn checkpoint_omitted_candidate_count_resource() -> Result<(), Box<dyn Error>> {
    let limits = ProtocolLimits {
        max_samples: 1,
        ..ProtocolLimits::default()
    };
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        limits,
    )?;
    parser
        .push_chunk(0, b"a\nb\n", &[source_origin(1, 0, 4)])
        .map_err(|error| format!("resource-omission setup: {error:?}"))?;

    let mut checkpoint = serde_json::to_value(parser)?;
    set_checkpoint_field(&mut checkpoint, "omitted_candidates", serde_json::json!(0))?;
    let resumed: StreamMessageParser = serde_json::from_value(checkpoint)?;

    assert!(matches!(
        resumed.into_report(),
        Err(l2_workbench::protocol::ProtocolError::InvalidParserState)
    ));
    Ok(())
}

#[test]
fn live_configured_limit_omitted_suffix() -> Result<(), Box<dyn Error>> {
    let limits = ProtocolLimits {
        max_samples: 1,
        ..ProtocolLimits::default()
    };
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::FixedSize { bytes: 2 }],
        limits,
    )?;
    parser.push_chunk(0, b"abcd", &[source_origin(1, 0, 4)])?;

    let report = parser.into_report()?;
    assert_eq!(report.messages.len(), 1);
    let message = report
        .messages
        .first()
        .ok_or("sample-limited report has no retained message")?;
    assert_eq!(message.stream_range.start, 0);
    assert_eq!(message.stream_range.end, 2);
    assert!(report.partial);
    assert!(report.transitions.iter().any(|transition| {
        transition.state == l2_workbench::protocol::StreamTransitionState::ResourceOmitted
            && transition.stream_range.start == 2
            && transition.stream_range.end == 4
    }));
    Ok(())
}

#[test]
fn checkpoint_message_retained_framing_boundary() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        ProtocolLimits::default(),
    )?;
    parser.push_chunk(0, b"a\n", &[source_origin(1, 0, 2)])?;

    let mut checkpoint = serde_json::to_value(parser)?;
    let inconsistent_framing = serde_json::to_value(FramingKind::FixedSize { bytes: 1 })?;
    set_candidate_field(&mut checkpoint, "framing", inconsistent_framing.clone())?;
    set_candidate_field(
        &mut checkpoint,
        "delimiter_scanned_to",
        serde_json::Value::Null,
    )?;
    set_first_record_field(
        &mut checkpoint,
        "messages",
        "framing",
        inconsistent_framing.clone(),
    )?;
    set_first_record_field(
        &mut checkpoint,
        "transitions",
        "framing",
        inconsistent_framing,
    )?;
    let resumed: StreamMessageParser = serde_json::from_value(checkpoint)?;

    assert!(matches!(
        resumed.into_report(),
        Err(l2_workbench::protocol::ProtocolError::InvalidParserState)
    ));
    Ok(())
}

#[test]
fn checkpoint_noncanonical_transition_digest_shape() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        ProtocolLimits::default(),
    )?;
    parser.push_chunk(0, b"partial", &[source_origin(1, 0, 7)])?;
    parser.finalize()?;

    let mut checkpoint = serde_json::to_value(parser)?;
    set_first_record_field(
        &mut checkpoint,
        "transitions",
        "evidence_sha256",
        serde_json::json!("z".repeat(64)),
    )?;
    let resumed: StreamMessageParser = serde_json::from_value(checkpoint)?;

    assert!(matches!(
        resumed.into_report(),
        Err(l2_workbench::protocol::ProtocolError::InvalidParserState)
    ));
    Ok(())
}

#[test]
fn finalized_tail_retained_active_buffer() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        ProtocolLimits::default(),
    )?;
    parser.push_chunk(0, b"partial", &[source_origin(1, 0, 7)])?;
    parser.finalize()?;

    let mut checkpoint = serde_json::to_value(parser)?;
    set_first_record_field(
        &mut checkpoint,
        "transitions",
        "evidence_sha256",
        serde_json::json!(l2_workbench::sha256(b"different retained bytes")),
    )?;
    let resumed: StreamMessageParser = serde_json::from_value(checkpoint)?;

    assert!(matches!(
        resumed.into_report(),
        Err(l2_workbench::protocol::ProtocolError::InvalidParserState)
    ));
    Ok(())
}

#[test]
fn checkpoint_cannot_first_sequence_gap() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        ProtocolLimits::default(),
    )?;
    parser
        .push_chunk(0, b"a\n", &[source_origin(1, 0, 2)])
        .map_err(|error| format!("message setup: {error:?}"))?;
    parser
        .push_chunk(4, b"x", &[source_origin(2, 4, 1)])
        .map_err(|error| format!("gap setup: {error:?}"))?;

    let mut checkpoint = serde_json::to_value(parser)?;
    set_gap_start(&mut checkpoint, 1)?;
    set_checkpoint_field(&mut checkpoint, "total_input_bytes", serde_json::json!(2))?;
    let mut resumed: StreamMessageParser = serde_json::from_value(checkpoint)?;

    assert!(matches!(
        resumed.finalize(),
        Err(l2_workbench::protocol::ProtocolError::InvalidParserState)
    ));
    Ok(())
}

#[test]
fn gappy_checkpoint_cannot_gap_tail() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        ProtocolLimits::default(),
    )?;
    parser.push_chunk(0, b"old", &[source_origin(1, 0, 3)])?;
    parser.push_chunk(6, b"new", &[source_origin(2, 6, 3)])?;

    let mut checkpoint = serde_json::to_value(parser)?;
    remove_pre_gap_tail(&mut checkpoint)?;
    let mut resumed: StreamMessageParser = serde_json::from_value(checkpoint)?;

    assert!(matches!(
        resumed.finalize(),
        Err(l2_workbench::protocol::ProtocolError::InvalidParserState)
    ));
    Ok(())
}

#[test]
fn gappy_checkpoint_last_gap_end() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        ProtocolLimits::default(),
    )?;
    parser.push_chunk(0, b"old", &[source_origin(1, 0, 3)])?;
    parser.push_chunk(6, b"new", &[source_origin(2, 6, 3)])?;

    let mut checkpoint = serde_json::to_value(parser)?;
    let pending = checkpoint
        .get_mut("pending_unparsed")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("checkpoint has no pending unparsed tail")?;
    pending.insert("start".to_owned(), serde_json::json!(7));
    pending.insert("bytes".to_owned(), serde_json::json!([b'n', b'e']));
    let retained = checkpoint
        .get("retained_bytes")
        .and_then(serde_json::Value::as_u64)
        .ok_or("checkpoint has no retained byte count")?;
    set_checkpoint_field(
        &mut checkpoint,
        "retained_bytes",
        serde_json::json!(
            usize::try_from(retained)?
                .checked_sub(1)
                .ok_or("retained byte count is smaller than removed byte")?
        ),
    )?;
    let mut resumed: StreamMessageParser = serde_json::from_value(checkpoint)?;

    assert!(matches!(
        resumed.finalize(),
        Err(l2_workbench::protocol::ProtocolError::InvalidParserState)
    ));
    Ok(())
}
