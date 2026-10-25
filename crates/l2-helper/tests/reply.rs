use l2_helper::{
    HelperReply, HelperReplyKind, MAX_FRAME_BYTES, MAX_IPC_BYTES, ReplyError, ReplyErrorCode,
    SessionId, decode_reply, encode_reply,
};

fn session() -> Result<SessionId, Box<dyn std::error::Error>> {
    Ok(SessionId::new([0x42; 16])?)
}

#[test]
fn frame_reply_preserves_record_boundary() -> Result<(), Box<dyn std::error::Error>> {
    let frame = [0xaa, 0xbb, 0xcc];
    let reply = HelperReply::frame(session()?, 9, &frame)?;
    let mut encoded = vec![0_u8; MAX_IPC_BYTES];
    let length = encode_reply(&reply, &mut encoded)?;
    assert_eq!(length, 36 + frame.len());
    let decoded = decode_reply(encoded.get(..length).ok_or("reply boundary")?)?;
    assert_eq!(decoded.kind(), HelperReplyKind::Frame);
    assert_eq!(decoded.session(), session()?);
    assert_eq!(decoded.sequence(), 9);
    assert_eq!(decoded.payload(), frame);
    Ok(())
}

#[test]
fn error_reply_known_fixed_code() -> Result<(), Box<dyn std::error::Error>> {
    let reply = HelperReply::error(session()?, 2, ReplyErrorCode::BindingMismatch)?;
    let mut encoded = vec![0_u8; 36 + 2];
    let length = encode_reply(&reply, &mut encoded)?;
    let decoded = decode_reply(encoded.get(..length).ok_or("reply boundary")?)?;
    assert_eq!(decoded.kind(), HelperReplyKind::Error);
    assert_eq!(decoded.payload(), [0, 3]);
    Ok(())
}

#[test]
fn reply_codec_oversized_trailing() -> Result<(), Box<dyn std::error::Error>> {
    let oversized = vec![0x7f; MAX_FRAME_BYTES + 1];
    assert!(matches!(
        HelperReply::frame(session()?, 1, &oversized),
        Err(ReplyError::MessageTooLarge { .. })
    ));

    let reply = HelperReply::empty(HelperReplyKind::Ready, session()?, 1)?;
    let mut encoded = vec![0_u8; MAX_IPC_BYTES];
    let length = encode_reply(&reply, &mut encoded)?;
    let trailing = encoded.get(..length + 1).ok_or("reply boundary")?;
    assert!(matches!(
        decode_reply(trailing),
        Err(ReplyError::TrailingBytes)
    ));
    Ok(())
}
