use wifi_core::{
    ControlSubtype, DataSubtype, DecodeError, FrameKind, FrameType, MacAddress, ManagementSubtype,
    decode,
};

const RECEIVER: [u8; 6] = [0, 1, 2, 3, 4, 5];
const TRANSMITTER: [u8; 6] = [6, 7, 8, 9, 10, 11];
const BSSID: [u8; 6] = [12, 13, 14, 15, 16, 17];
const ADDRESS4: [u8; 6] = [18, 19, 20, 21, 22, 23];

fn header(frame_control: u16) -> Vec<u8> {
    let mut bytes = Vec::from(frame_control.to_le_bytes());
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(&RECEIVER);
    bytes.extend_from_slice(&TRANSMITTER);
    bytes.extend_from_slice(&BSSID);
    bytes.extend_from_slice(&0x1234_u16.to_le_bytes());
    bytes
}

#[test]
fn beacon_preserves_management_addresses() -> Result<(), DecodeError> {
    let mut bytes = header(0x0080);
    bytes.extend_from_slice(&[1, 2, 3]);

    let frame = decode(&bytes)?;

    assert_eq!(
        frame.kind(),
        FrameKind::Management(ManagementSubtype::Beacon)
    );
    assert_eq!(frame.receiver(), Some(MacAddress::new(RECEIVER)));
    assert_eq!(frame.transmitter(), Some(MacAddress::new(TRANSMITTER)));
    assert_eq!(frame.address3(), Some(MacAddress::new(BSSID)));
    assert_eq!(frame.sequence_control(), Some(0x1234));
    assert_eq!(frame.body(), &[1, 2, 3]);
    assert_eq!(frame.bytes(), bytes.as_slice());
    assert_eq!(frame.control().raw(), 0x0080);
    assert_eq!(frame.control().frame_type(), FrameType::Management);
    assert!(!frame.control().to_ds());
    assert!(!frame.control().from_ds());
    assert!(!frame.control().retry());
    assert!(!frame.control().protected());
    assert!(!frame.control().order());
    assert_eq!(MacAddress::new(RECEIVER).octets(), RECEIVER);
    Ok(())
}

#[test]
fn qos_four_frame_exact_body() -> Result<(), DecodeError> {
    // Data, QoS subtype, ToDS, FromDS, and Order select every optional header field
    let mut bytes = header(0xcb88);
    bytes.extend_from_slice(&ADDRESS4);
    bytes.extend_from_slice(&0x4567_u16.to_le_bytes());
    bytes.extend_from_slice(&0x89ab_cdef_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xde, 0xad]);

    let frame = decode(&bytes)?;

    assert_eq!(
        frame.kind(),
        FrameKind::Data(DataSubtype::from_wire_nibble(8))
    );
    assert_eq!(frame.control().raw(), 0xcb88);
    assert_eq!(frame.control().frame_type(), FrameType::Data);
    assert!(frame.control().to_ds());
    assert!(frame.control().from_ds());
    assert!(frame.control().retry());
    assert!(frame.control().protected());
    assert!(frame.control().order());
    assert_eq!(frame.address4(), Some(MacAddress::new(ADDRESS4)));
    assert_eq!(frame.qos_control(), Some(0x4567));
    assert_eq!(frame.ht_control(), Some(0x89ab_cdef));
    assert_eq!(frame.body(), &[0xde, 0xad]);
    Ok(())
}

#[test]
fn ordered_management() -> Result<(), DecodeError> {
    let mut bytes = header(0x8080);
    bytes.extend_from_slice(&0x0102_0304_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xaa, 0xbb]);

    let frame = decode(&bytes)?;

    assert_eq!(frame.ht_control(), Some(0x0102_0304));
    assert_eq!(frame.body(), &[0xaa, 0xbb]);
    assert!(frame.control().order());
    Ok(())
}

#[test]
fn control_addresses() -> Result<(), DecodeError> {
    let rts = [0xb4, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    let rts_frame = decode(&rts)?;
    assert_eq!(rts_frame.receiver(), Some(MacAddress::new(RECEIVER)));
    assert_eq!(rts_frame.transmitter(), Some(MacAddress::new(TRANSMITTER)));

    let cts = [0xc4, 0, 0, 0, 0, 1, 2, 3, 4, 5];
    let cts_frame = decode(&cts)?;
    assert_eq!(cts_frame.receiver(), Some(MacAddress::new(RECEIVER)));
    assert_eq!(cts_frame.transmitter(), None);
    Ok(())
}

#[test]
fn qos_one_direction() -> Result<(), DecodeError> {
    let mut bytes = header(0x0188);
    bytes.extend_from_slice(&0x4567_u16.to_le_bytes());
    bytes.extend_from_slice(&0x89ab_cdef_u32.to_le_bytes());
    bytes.extend_from_slice(&[0xde, 0xad]);

    let frame = decode(&bytes)?;

    assert!(frame.control().to_ds());
    assert!(!frame.control().from_ds());
    assert!(!frame.control().order());
    assert_eq!(frame.address4(), None);
    assert_eq!(frame.qos_control(), Some(0x4567));
    assert_eq!(frame.ht_control(), None);
    assert_eq!(frame.body(), &[0xef, 0xcd, 0xab, 0x89, 0xde, 0xad]);
    Ok(())
}

#[test]
fn control_frames_use_subtype_widths() -> Result<(), DecodeError> {
    let cases = [
        (0x00b4_u16, 16_usize, ControlSubtype::Rts),
        (0x00c4, 10, ControlSubtype::Cts),
        (0x00d4, 10, ControlSubtype::Ack),
        (0x0084, 20, ControlSubtype::BlockAckRequest),
        (0x0094, 28, ControlSubtype::BlockAck),
    ];

    for (frame_control, length, expected) in cases {
        let mut bytes = vec![0_u8; length];
        bytes
            .get_mut(..2)
            .ok_or(DecodeError::InvalidLayout("control fixture"))?
            .copy_from_slice(&frame_control.to_le_bytes());
        assert_eq!(decode(&bytes)?.kind(), FrameKind::Control(expected));
    }
    Ok(())
}

#[test]
fn control_length() {
    let bytes = [0xb4, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    assert_eq!(
        decode(&bytes),
        Err(DecodeError::Truncated {
            context: "control header",
            needed: 16,
            available: 10,
        })
    );
}

#[test]
fn subtype_bits() {
    let qos = DataSubtype::from_wire_nibble(0xf8);
    assert_eq!(qos.value(), 8);
    assert!(qos.has_qos());

    let non_qos = DataSubtype::from_wire_nibble(0x07);
    assert_eq!(non_qos.value(), 7);
    assert!(!non_qos.has_qos());
}

#[test]
fn error_text() {
    assert_eq!(
        DecodeError::Truncated {
            context: "frame control",
            needed: 2,
            available: 1,
        }
        .to_string(),
        "truncated 802.11 frame control: need 2 bytes, have 1"
    );
    assert_eq!(
        DecodeError::UnsupportedVersion(3).to_string(),
        "unsupported 802.11 protocol version 3"
    );
    assert_eq!(
        DecodeError::InvalidLayout("test field").to_string(),
        "invalid 802.11 test field"
    );
}

#[test]
fn unsupported_protocol_version_is_distinct() {
    let bytes = [1_u8, 0, 0, 0];

    assert_eq!(decode(&bytes), Err(DecodeError::UnsupportedVersion(1)));
}

#[test]
fn every_beacon_truncation_is_rejected() {
    let bytes = header(0x0080);

    for length in 0..bytes.len() {
        let Some(prefix) = bytes.get(..length) else {
            continue;
        };
        assert!(matches!(decode(prefix), Err(DecodeError::Truncated { .. })));
    }
}

#[test]
fn arbitrary_short_inputs_never_panic() {
    for length in 0..=64 {
        let bytes = vec![0xff; length];
        let _ = decode(&bytes);
    }
}
