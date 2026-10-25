use std::panic::{AssertUnwindSafe, catch_unwind};

use l2_core::{DecodeContext, DecodeError, FrameField, MAX_FRAME_LEN, VlanTag, decode};
use proptest::prelude::*;

const DESTINATION: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x00];
const SOURCE: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

fn header(field: u16) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14);
    frame.extend_from_slice(&DESTINATION);
    frame.extend_from_slice(&SOURCE);
    frame.extend_from_slice(&field.to_be_bytes());
    frame
}

fn vlan_frame(tags: &[(u16, u16)], field: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = header(field);
    if !tags.is_empty() {
        frame.truncate(12);
        for &(tpid, tci) in tags {
            frame.extend_from_slice(&tpid.to_be_bytes());
            frame.extend_from_slice(&tci.to_be_bytes());
        }
        frame.extend_from_slice(&field.to_be_bytes());
    }
    frame.extend_from_slice(payload);
    frame
}

#[test]
fn decodes_basic_ethernet_ii_frame() {
    let frame = vlan_frame(&[], 0x0800, &[0xde, 0xad, 0xbe, 0xef]);

    let result = decode(&frame);
    assert!(result.is_ok());
    let Ok(decoded) = result else { return };

    assert_eq!(decoded.destination, DESTINATION);
    assert_eq!(decoded.source, SOURCE);
    assert!(decoded.vlan_tags.is_empty());
    assert_eq!(decoded.field, FrameField::EtherType(0x0800));
    assert_eq!(decoded.payload, &[0xde, 0xad, 0xbe, 0xef]);
    assert!(decoded.padding.is_empty());
}

#[test]
fn rejects_a_truncated_fixed_header() {
    let mut frame = header(0x0800);
    frame.truncate(13);

    assert_eq!(
        decode(&frame),
        Err(DecodeError::Truncated {
            context: DecodeContext::EthernetHeader,
            needed: 14,
            available: 13,
        })
    );
}

#[test]
fn unknown_ether_type_wire_value() {
    let frame = vlan_frame(&[], 0xffff, &[0x01, 0x02]);

    let result = decode(&frame);
    assert!(result.is_ok());
    let Ok(decoded) = result else { return };

    assert_eq!(decoded.field, FrameField::EtherType(0xffff));
    assert_eq!(decoded.payload, &[0x01, 0x02]);
}

#[test]
fn ieee_length_trailing_padding() {
    let mut frame = header(3);
    frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0x00, 0x00]);

    let result = decode(&frame);
    assert!(result.is_ok());
    let Ok(decoded) = result else { return };

    assert_eq!(decoded.field, FrameField::Length(3));
    assert_eq!(decoded.payload, &[0xaa, 0xbb, 0xcc]);
    assert_eq!(decoded.padding, &[0x00, 0x00]);
}

#[test]
fn accepts_zero_maximum_ieee_lengths() {
    let empty_payload = header(0);
    let empty_result = decode(&empty_payload);
    assert!(empty_result.is_ok());
    if let Ok(decoded_empty) = empty_result {
        assert_eq!(decoded_empty.field, FrameField::Length(0));
        assert!(decoded_empty.payload.is_empty());
        assert!(decoded_empty.padding.is_empty());
    }

    let mut maximum_payload = header(1500);
    maximum_payload.extend(std::iter::repeat_n(0xa5, 1500));
    let maximum_result = decode(&maximum_payload);
    assert!(maximum_result.is_ok());
    if let Ok(decoded_maximum) = maximum_result {
        assert_eq!(decoded_maximum.field, FrameField::Length(1500));
        assert_eq!(decoded_maximum.payload.len(), 1500);
        assert!(decoded_maximum.padding.is_empty());
    }
}

#[test]
fn accepts_single_vlan_tags_wire() {
    let frame = vlan_frame(
        &[(0x8100, 0x0064), (0x88a8, 0xa123), (0x8100, 0x0fff)],
        0x86dd,
        &[0x10, 0x20],
    );

    let result = decode(&frame);
    assert!(result.is_ok());
    let Ok(decoded) = result else { return };

    assert_eq!(
        decoded.vlan_tags,
        vec![
            VlanTag {
                tpid: 0x8100,
                tci: 0x0064,
            },
            VlanTag {
                tpid: 0x88a8,
                tci: 0xa123,
            },
            VlanTag {
                tpid: 0x8100,
                tci: 0x0fff,
            },
        ]
    );
    assert_eq!(decoded.field, FrameField::EtherType(0x86dd));
    assert_eq!(decoded.payload, &[0x10, 0x20]);
}

#[test]
fn vlan_tag_depth_boundary() {
    let four_tags = vlan_frame(
        &[(0x8100, 1), (0x88a8, 2), (0x8100, 3), (0x88a8, 4)],
        0x0800,
        &[0x42],
    );
    let four_result = decode(&four_tags);
    assert!(four_result.is_ok());
    if let Ok(decoded) = four_result {
        assert_eq!(decoded.vlan_tags.len(), 4);
    }

    let five_tags = vlan_frame(
        &[
            (0x8100, 1),
            (0x88a8, 2),
            (0x8100, 3),
            (0x88a8, 4),
            (0x8100, 5),
        ],
        0x0800,
        &[0x42],
    );
    assert_eq!(
        decode(&five_tags),
        Err(DecodeError::TooManyVlanTags { max: 4 })
    );
}

#[test]
fn treats_unrecognized_tpid_frame_field() {
    let frame = vlan_frame(&[], 0x9100, &[0x81, 0x00, 0x00, 0x01]);

    let result = decode(&frame);
    assert!(result.is_ok());
    if let Ok(decoded) = result {
        assert_eq!(decoded.vlan_tags.len(), 0);
        assert_eq!(decoded.field, FrameField::EtherType(0x9100));
        assert_eq!(decoded.payload, &[0x81, 0x00, 0x00, 0x01]);
    }
}

#[test]
fn rejects_reserved_type_length_values() {
    for value in [1501, 1510, 1535] {
        assert_eq!(
            decode(&header(value)),
            Err(DecodeError::ReservedField { value })
        );
    }
}

#[test]
fn classifies_ether_type_lower_boundary() {
    let frame = header(1536);
    let decoded = decode(&frame);
    assert!(decoded.is_ok());
    if let Ok(decoded) = decoded {
        assert_eq!(decoded.field, FrameField::EtherType(1536));
    }
}

#[test]
fn rejects_length_exceeds_available_payload() {
    let mut frame = header(4);
    frame.extend_from_slice(&[0xaa, 0xbb]);

    assert_eq!(
        decode(&frame),
        Err(DecodeError::PayloadTruncated {
            declared: 4,
            available: 2,
        })
    );
}

#[test]
fn frames_larger_bounded_input_limit() {
    let mut frame = header(0x0800);
    frame.resize(MAX_FRAME_LEN, 0);
    assert!(decode(&frame).is_ok());

    frame.push(0);
    assert_eq!(
        decode(&frame),
        Err(DecodeError::FrameTooLong {
            length: MAX_FRAME_LEN + 1,
            max: MAX_FRAME_LEN,
        })
    );
}

#[test]
fn reports_truncation_at_each_boundary() {
    let frame = vlan_frame(&[(0x8100, 7), (0x88a8, 8)], 3, &[0xaa, 0xbb, 0xcc, 0]);

    for end in 0..=frame.len() {
        if let Some(truncated) = frame.get(..end) {
            let result = catch_unwind(AssertUnwindSafe(|| decode(truncated)));
            assert!(result.is_ok(), "decoder panicked for {end}-byte input");
        }
    }
}

#[test]
fn truncated_vlan_tag_truncated_field() {
    let mut truncated_tag = header(0x8100);
    truncated_tag.push(0);
    assert_eq!(
        decode(&truncated_tag),
        Err(DecodeError::Truncated {
            context: DecodeContext::VlanTag,
            needed: 4,
            available: 3,
        })
    );

    let truncated_field = header(0x8100);
    assert_eq!(
        decode(&truncated_field),
        Err(DecodeError::Truncated {
            context: DecodeContext::VlanTag,
            needed: 4,
            available: 2,
        })
    );
}

#[test]
fn rejects_missing_type_length_vlan() {
    let mut frame = vlan_frame(&[(0x8100, 7)], 0x0800, &[]);
    frame.truncate(frame.len() - 2);

    assert_eq!(
        decode(&frame),
        Err(DecodeError::Truncated {
            context: DecodeContext::TypeLengthField,
            needed: 2,
            available: 0,
        })
    );
}

#[test]
fn formats_decode_errors_for_diagnostics() {
    assert_eq!(DecodeContext::EthernetHeader.to_string(), "Ethernet header");
    assert_eq!(DecodeContext::VlanTag.to_string(), "VLAN tag");
    assert_eq!(
        DecodeContext::TypeLengthField.to_string(),
        "type/length field"
    );
    assert_eq!(
        DecodeError::FrameTooLong {
            length: 65_536,
            max: MAX_FRAME_LEN,
        }
        .to_string(),
        "frame length 65536 exceeds maximum 65535"
    );
    assert_eq!(
        DecodeError::Truncated {
            context: DecodeContext::VlanTag,
            needed: 4,
            available: 2,
        }
        .to_string(),
        "truncated VLAN tag: need 4 bytes, have 2"
    );
    assert_eq!(
        DecodeError::ReservedField { value: 1_501 }.to_string(),
        "reserved EtherType/length value 0x05dd"
    );
    assert_eq!(
        DecodeError::PayloadTruncated {
            declared: 4,
            available: 2,
        }
        .to_string(),
        "802.3 payload declares 4 bytes, only 2 available"
    );
    assert_eq!(
        DecodeError::TooManyVlanTags { max: 4 }.to_string(),
        "frame contains more than 4 VLAN tags"
    );
}

proptest! {
    #[test]
    fn arbitrary_bytes_stay_within_input(
        input in prop::collection::vec(any::<u8>(), 0..=MAX_FRAME_LEN + 1)
    ) {
        let result = catch_unwind(AssertUnwindSafe(|| decode(&input)));
        prop_assert!(result.is_ok());

        if let Ok(Ok(frame)) = result {
            prop_assert!(frame.payload.len() <= input.len());
            prop_assert!(frame.padding.len() <= input.len());
            prop_assert!(frame.payload.len() + frame.padding.len() <= input.len());
        }
    }
}
