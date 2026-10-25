use l2_helper_protocol::{
    HEADER_LENGTH, MAX_MESSAGE_LENGTH, Message, MessageKind, ProtocolError, SessionId, decode,
    encode,
};

fn session() -> Result<SessionId, ProtocolError> {
    SessionId::new([0x11; 16])
}

#[test]
fn golden_cancel_trips_exact_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let message = Message::new(MessageKind::Cancel, session()?, 7, &[])?;
    let mut encoded = vec![0; HEADER_LENGTH];
    let written = encode(&message, &mut encoded)?;
    let mut expected = Vec::new();
    expected.extend_from_slice(b"L2HP");
    expected.extend_from_slice(&1_u16.to_be_bytes());
    expected.extend_from_slice(&4_u16.to_be_bytes());
    expected.extend_from_slice(&0_u32.to_be_bytes());
    expected.extend_from_slice(&[0x11; 16]);
    expected.extend_from_slice(&7_u64.to_be_bytes());

    assert_eq!(written, HEADER_LENGTH);
    assert_eq!(encoded, expected);
    assert_eq!(decode(&encoded)?, message);
    Ok(())
}

#[test]
fn rejects_truncated_messages() -> Result<(), Box<dyn std::error::Error>> {
    let payload = [0x22; 24];
    let message = Message::new(MessageKind::OpenReceive, session()?, 1, &payload)?;
    let mut encoded = vec![0; HEADER_LENGTH + payload.len()];
    encode(&message, &mut encoded)?;

    for length in 0..encoded.len() {
        assert!(decode(encoded.get(..length).ok_or("prefix")?).is_err());
    }
    assert_eq!(decode(&encoded)?, message);
    Ok(())
}

#[test]
fn invalid_header_fields_trailing_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let message = Message::new(MessageKind::Cancel, session()?, 7, &[])?;
    let mut encoded = vec![0; HEADER_LENGTH];
    encode(&message, &mut encoded)?;

    for (offset, replacement, expected) in [
        (0, 0_u8, ProtocolError::BadMagic),
        (5, 2_u8, ProtocolError::UnsupportedVersion(2)),
        (7, 0xff_u8, ProtocolError::UnknownMessageKind(255)),
        (35, 0_u8, ProtocolError::ZeroSequence),
    ] {
        let mut changed = encoded.clone();
        let byte = changed.get_mut(offset).ok_or("mutation offset")?;
        *byte = replacement;
        assert_eq!(decode(&changed), Err(expected));
    }

    let mut zero_session = encoded.clone();
    zero_session.get_mut(12..28).ok_or("session field")?.fill(0);
    assert_eq!(decode(&zero_session), Err(ProtocolError::ZeroSession));

    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(decode(&trailing), Err(ProtocolError::TrailingBytes));
    Ok(())
}

#[test]
fn enforces_payload_and_output_limits() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        Message::new(MessageKind::Cancel, session()?, 1, &[1]),
        Err(ProtocolError::InvalidPayloadLength {
            kind: MessageKind::Cancel,
            length: 1,
        })
    );
    assert_eq!(
        Message::new(MessageKind::OpenReceive, session()?, 1, &[0; 23]),
        Err(ProtocolError::InvalidPayloadLength {
            kind: MessageKind::OpenReceive,
            length: 23,
        })
    );

    let message = Message::new(MessageKind::Cancel, session()?, 1, &[])?;
    let mut destination = vec![0xa5; HEADER_LENGTH - 1];
    assert!(matches!(
        encode(&message, &mut destination),
        Err(ProtocolError::OutputTooShort { .. })
    ));
    assert!(destination.iter().all(|byte| *byte == 0xa5));
    Ok(())
}

#[test]
fn bounds_advertised_payload() -> Result<(), Box<dyn std::error::Error>> {
    let message = Message::new(MessageKind::Cancel, session()?, 1, &[])?;
    let mut encoded = vec![0; HEADER_LENGTH];
    encode(&message, &mut encoded)?;
    encoded
        .get_mut(8..12)
        .ok_or("payload length")?
        .copy_from_slice(&u32::MAX.to_be_bytes());

    assert_eq!(
        decode(&encoded),
        Err(ProtocolError::InvalidPayloadLength {
            kind: MessageKind::Cancel,
            length: usize::try_from(u32::MAX)?,
        })
    );
    assert_eq!(MAX_MESSAGE_LENGTH, HEADER_LENGTH + 24);
    Ok(())
}
