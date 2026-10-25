use l2_core::{EncodeError, EthernetFrame, FrameField, VlanTag, decode, encode, encoded_len};
use proptest::prelude::*;

const DESTINATION: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x00];
const SOURCE: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

const fn ethernet_frame<'a>(
    vlan_tags: Vec<VlanTag>,
    field: FrameField,
    payload: &'a [u8],
    padding: &'a [u8],
) -> EthernetFrame<'a> {
    EthernetFrame {
        destination: DESTINATION,
        source: SOURCE,
        vlan_tags,
        payload,
        padding,
        field,
    }
}

#[test]
fn encodes_golden_tagged_frame_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let frame = ethernet_frame(
        vec![
            VlanTag {
                tpid: 0x88a8,
                tci: 0x0123,
            },
            VlanTag {
                tpid: 0x8100,
                tci: 0x0abc,
            },
        ],
        FrameField::EtherType(0x88cc),
        &[0xde, 0xad, 0xbe, 0xef],
        &[],
    );
    let expected = [
        0x01, 0x80, 0xc2, 0x00, 0x00, 0x00, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x88, 0xa8, 0x01,
        0x23, 0x81, 0x00, 0x0a, 0xbc, 0x88, 0xcc, 0xde, 0xad, 0xbe, 0xef,
    ];

    assert_eq!(encoded_len(&frame)?, expected.len());
    let mut actual = [0xa5; 26];
    assert_eq!(encode(&frame, &mut actual)?, expected.len());
    assert_eq!(actual.get(..expected.len()), Some(expected.as_slice()));
    assert!(
        actual
            .get(expected.len()..)
            .is_some_and(|tail| tail.iter().all(|byte| *byte == 0xa5))
    );
    Ok(())
}

#[test]
fn accepts_output_type_length_boundaries() -> Result<(), Box<dyn std::error::Error>> {
    let four_tags = ethernet_frame(
        vec![
            VlanTag {
                tpid: 0x8100,
                tci: 1,
            };
            4
        ],
        FrameField::EtherType(1_536),
        &[],
        &[],
    );
    let needed = encoded_len(&four_tags)?;
    let mut output = vec![0xa5; needed + 1];
    assert_eq!(encode(&four_tags, &mut output)?, needed);
    assert_eq!(output.get(needed), Some(&0xa5));

    let payload = [0; 1_500];
    let maximum_length_frame = ethernet_frame(Vec::new(), FrameField::Length(1_500), &payload, &[]);
    assert_eq!(encoded_len(&maximum_length_frame)?, 14 + 1_500);

    let maximum_payload = vec![0; l2_core::MAX_FRAME_LEN - 14];
    let maximum_frame = ethernet_frame(
        Vec::new(),
        FrameField::EtherType(0x0800),
        &maximum_payload,
        &[],
    );
    assert_eq!(encoded_len(&maximum_frame)?, l2_core::MAX_FRAME_LEN);
    Ok(())
}

#[test]
fn round_trip_preserves_untagged_payload() -> Result<(), Box<dyn std::error::Error>> {
    let frame = ethernet_frame(
        Vec::new(),
        FrameField::Length(3),
        &[0xaa, 0xbb, 0xcc],
        &[0x00, 0x00, 0x00, 0x00],
    );
    let mut encoded = vec![0; encoded_len(&frame)?];
    assert_eq!(encode(&frame, &mut encoded)?, encoded.len());

    let decoded = decode(&encoded)?;
    assert_eq!(decoded, frame);
    Ok(())
}

#[test]
fn short_output_buffer_left_unchanged() -> Result<(), Box<dyn std::error::Error>> {
    let frame = ethernet_frame(Vec::new(), FrameField::EtherType(0x0800), &[1, 2, 3], &[]);
    let needed = encoded_len(&frame)?;
    let mut output = vec![0xa5; needed - 1];
    let before = output.clone();

    assert_eq!(
        encode(&frame, &mut output),
        Err(EncodeError::BufferTooShort {
            needed,
            available: needed - 1,
        })
    );
    assert_eq!(output, before);
    Ok(())
}

#[test]
fn rejects_invalid_frame_fields_writing() {
    let cases = [
        (
            ethernet_frame(
                vec![VlanTag {
                    tpid: 0x9100,
                    tci: 0,
                }],
                FrameField::EtherType(0x0800),
                &[],
                &[],
            ),
            EncodeError::UnsupportedVlanTpid {
                index: 0,
                tpid: 0x9100,
            },
        ),
        (
            ethernet_frame(
                vec![
                    VlanTag {
                        tpid: 0x8100,
                        tci: 0,
                    };
                    5
                ],
                FrameField::EtherType(0x0800),
                &[],
                &[],
            ),
            EncodeError::TooManyVlanTags { max: 4 },
        ),
        (
            ethernet_frame(Vec::new(), FrameField::EtherType(1501), &[], &[]),
            EncodeError::ReservedField { value: 1501 },
        ),
        (
            ethernet_frame(Vec::new(), FrameField::Length(3), &[1, 2], &[]),
            EncodeError::LengthMismatch {
                declared: 3,
                payload: 2,
            },
        ),
        (
            ethernet_frame(Vec::new(), FrameField::EtherType(0x8100), &[], &[]),
            EncodeError::VlanTpidAsFinalType { value: 0x8100 },
        ),
        (
            ethernet_frame(
                vec![VlanTag {
                    tpid: 0x8100,
                    tci: 10,
                }],
                FrameField::EtherType(0x88a8),
                &[],
                &[],
            ),
            EncodeError::VlanTpidAsFinalType { value: 0x88a8 },
        ),
    ];

    for (frame, expected) in cases {
        let mut output = vec![0xa5; 128];
        let before = output.clone();
        assert_eq!(encode(&frame, &mut output), Err(expected));
        assert_eq!(output, before);
    }

    let oversized_payload = vec![0; l2_core::MAX_FRAME_LEN];
    let oversized = ethernet_frame(
        Vec::new(),
        FrameField::EtherType(0x0800),
        &oversized_payload,
        &[],
    );
    let mut output = [0xa5; 128];
    assert_eq!(
        encode(&oversized, &mut output),
        Err(EncodeError::FrameTooLong {
            length: 14 + l2_core::MAX_FRAME_LEN,
            max: l2_core::MAX_FRAME_LEN,
        })
    );
}

#[test]
fn every_encode_error_diagnostic_text() {
    let errors = [
        EncodeError::FrameTooLong { length: 2, max: 1 },
        EncodeError::BufferTooShort {
            needed: 2,
            available: 1,
        },
        EncodeError::TooManyVlanTags { max: 4 },
        EncodeError::UnsupportedVlanTpid {
            index: 0,
            tpid: 0x9100,
        },
        EncodeError::ReservedField { value: 1_501 },
        EncodeError::LengthMismatch {
            declared: 2,
            payload: 1,
        },
        EncodeError::VlanTpidAsFinalType { value: 0x8100 },
        EncodeError::LengthOverflow,
    ];

    for error in errors {
        assert!(!error.to_string().is_empty());
    }
}

proptest! {
    #[test]
    fn successful_canonical_encoding_always_decodes(
        destination in prop::array::uniform6(any::<u8>()),
        source in prop::array::uniform6(any::<u8>()),
        tags in prop::collection::vec((any::<bool>(), any::<u16>()), 0..=4),
        payload in prop::collection::vec(any::<u8>(), 0..=128),
        padding in prop::collection::vec(any::<u8>(), 0..=128),
    ) {
        let vlan_tags = tags
            .into_iter()
            .map(|(service, tci)| VlanTag {
                tpid: if service { 0x88a8 } else { 0x8100 },
                tci,
            })
            .collect();
        let frame = EthernetFrame {
            destination,
            source,
            vlan_tags,
            field: FrameField::Length(u16::try_from(payload.len()).unwrap_or_default()),
            payload: &payload,
            padding: &padding,
        };
        let length = encoded_len(&frame).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let mut encoded = vec![0; length];
        encode(&frame, &mut encoded).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let decoded = decode(&encoded).map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(decoded, frame);
    }
}
