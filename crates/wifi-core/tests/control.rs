use wifi_core::{ControlSubtype, DecodeError, FrameKind, MacAddress, decode};

const RECEIVER: [u8; 6] = [0, 1, 2, 3, 4, 5];
const TRANSMITTER: [u8; 6] = [6, 7, 8, 9, 10, 11];

fn control_frame(frame_control: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::from(frame_control.to_le_bytes());
    bytes.extend_from_slice(&[0xaa, 0xbb]);
    bytes.extend_from_slice(&RECEIVER);
    bytes.extend_from_slice(&TRANSMITTER);
    bytes.extend_from_slice(body);
    bytes
}

#[test]
fn sixteen_byte_control_keeps_addresses() -> Result<(), DecodeError> {
    let cases = [
        (0x00a4_u16, ControlSubtype::PsPoll),
        (0x00e4, ControlSubtype::CfEnd),
        (0x00f4, ControlSubtype::CfEndCfAck),
    ];

    for (frame_control, subtype) in cases {
        let bytes = control_frame(frame_control, &[0xde, 0xad]);
        let frame = decode(&bytes)?;

        assert_eq!(frame.kind(), FrameKind::Control(subtype));
        assert_eq!(frame.receiver(), Some(MacAddress::new(RECEIVER)));
        assert_eq!(frame.transmitter(), Some(MacAddress::new(TRANSMITTER)));
        assert_eq!(frame.address3(), None);
        assert_eq!(frame.body(), &[0xde, 0xad]);
    }
    Ok(())
}

#[test]
fn sixteen_byte_control_ten_byte() {
    let cases = [0x00a4_u16, 0x00e4, 0x00f4];

    for frame_control in cases {
        let mut bytes = control_frame(frame_control, &[]);
        bytes.truncate(10);

        assert_eq!(
            decode(&bytes),
            Err(DecodeError::Truncated {
                context: "control header",
                needed: 16,
                available: 10,
            })
        );
    }
}

#[test]
fn unknown_control_ten_byte_layout() -> Result<(), DecodeError> {
    let bytes = control_frame(0x0004, &[0xca, 0xfe]);
    let frame = decode(&bytes)?;

    assert_eq!(frame.kind(), FrameKind::Control(ControlSubtype::Other(0)));
    assert_eq!(frame.receiver(), Some(MacAddress::new(RECEIVER)));
    assert_eq!(frame.transmitter(), None);
    assert_eq!(frame.body(), &[6, 7, 8, 9, 10, 11, 0xca, 0xfe]);
    Ok(())
}
