use l2_codecs::{
    EncodeError, LldpFrame, MAX_FRAME_LEN, MAX_TLVS, Tlv, Validity, decode_lldp, encode_lldp,
    lldp_encoded_len,
};

fn tlv(kind: u8, value: &[u8]) -> Vec<u8> {
    let Ok(length) = u16::try_from(value.len()) else {
        return Vec::new();
    };
    let header = (u16::from(kind) << 9) | length;
    let mut bytes = header.to_be_bytes().to_vec();
    bytes.extend_from_slice(value);
    bytes
}

fn valid_lldp() -> Vec<u8> {
    let chassis = [4, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let mut port = vec![5];
    port.extend_from_slice(b"Gi1/0/1");

    let mut bytes = tlv(1, &chassis);
    bytes.extend(tlv(2, &port));
    bytes.extend(tlv(3, &120_u16.to_be_bytes()));
    bytes.extend(tlv(127, &[0xde, 0xad]));
    bytes.extend([0, 0]);
    bytes.extend([0xaa, 0xbb, 0xcc]);
    bytes
}

#[test]
fn encodes_decoded_golden_lldp() -> Result<(), Box<dyn std::error::Error>> {
    let input = valid_lldp();
    let frame = decode_lldp(&input)?;
    let mut output = vec![0xa5; lldp_encoded_len(&frame)?];

    assert_eq!(encode_lldp(&frame, &mut output)?, input.len());
    assert_eq!(output, input);
    Ok(())
}

#[test]
fn unknown_optional_tlvs_wire() -> Result<(), Box<dyn std::error::Error>> {
    let input = valid_lldp();
    let frame = decode_lldp(&input)?;
    let unknown = frame
        .tlvs
        .iter()
        .find(|tlv| tlv.kind == 127)
        .ok_or_else(|| std::io::Error::other("unknown LLDP TLV was not retained"))?;
    assert_eq!(unknown.value, &[0xde, 0xad]);

    let mut output = vec![0; lldp_encoded_len(&frame)?];
    encode_lldp(&frame, &mut output)?;
    assert_eq!(output, input);
    Ok(())
}

#[test]
fn short_output_buffer_left_unchanged() -> Result<(), Box<dyn std::error::Error>> {
    let input = valid_lldp();
    let frame = decode_lldp(&input)?;
    let needed = lldp_encoded_len(&frame)?;
    let mut output = vec![0xa5; needed - 1];
    let before = output.clone();

    assert_eq!(
        encode_lldp(&frame, &mut output),
        Err(EncodeError::BufferTooShort {
            needed,
            available: needed - 1,
        })
    );
    assert_eq!(output, before);
    Ok(())
}

#[test]
fn preserves_output_tail_at_capacity() -> Result<(), Box<dyn std::error::Error>> {
    let input = valid_lldp();
    let frame = decode_lldp(&input)?;
    let needed = lldp_encoded_len(&frame)?;
    let mut output = vec![0xa5; needed + 1];

    assert_eq!(encode_lldp(&frame, &mut output)?, needed);
    assert_eq!(output.get(..needed), Some(input.as_slice()));
    assert_eq!(output.get(needed), Some(&0xa5));
    Ok(())
}

#[test]
fn accepts_exact_value_count_limits() {
    let chassis = [4, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let port = [5, b'G'];
    let ttl = 120_u16.to_be_bytes();
    let exact_value = [0xde; 511];
    let exact_value_frame = LldpFrame {
        tlvs: vec![
            Tlv {
                kind: 1,
                value: &chassis,
                offset: 0,
            },
            Tlv {
                kind: 2,
                value: &port,
                offset: 0,
            },
            Tlv {
                kind: 3,
                value: &ttl,
                offset: 0,
            },
            Tlv {
                kind: 127,
                value: &exact_value,
                offset: 0,
            },
        ],
        padding: &[],
        validity: Validity::Valid,
    };
    assert!(lldp_encoded_len(&exact_value_frame).is_ok());

    let mut tlvs = Vec::with_capacity(MAX_TLVS);
    tlvs.extend([
        Tlv {
            kind: 1,
            value: &chassis,
            offset: 0,
        },
        Tlv {
            kind: 2,
            value: &port,
            offset: 0,
        },
        Tlv {
            kind: 3,
            value: &ttl,
            offset: 0,
        },
    ]);
    tlvs.extend((3..MAX_TLVS).map(|_| Tlv {
        kind: 127,
        value: &[],
        offset: 0,
    }));
    let exact_count_frame = LldpFrame {
        tlvs,
        padding: &[],
        validity: Validity::Valid,
    };
    assert_eq!(exact_count_frame.tlvs.len(), MAX_TLVS);
    assert!(lldp_encoded_len(&exact_count_frame).is_ok());
}

#[test]
fn rejects_frames_larger_encoder_budget() -> Result<(), Box<dyn std::error::Error>> {
    let input = valid_lldp();
    let mut frame = decode_lldp(&input)?;
    frame.padding = &[];
    let base_len = lldp_encoded_len(&frame)?;
    let exact_padding = vec![0; MAX_FRAME_LEN - base_len];
    frame.padding = &exact_padding;
    assert_eq!(lldp_encoded_len(&frame)?, MAX_FRAME_LEN);

    let oversized_padding = vec![0; MAX_FRAME_LEN - base_len + 1];
    frame.padding = &oversized_padding;
    assert_eq!(
        lldp_encoded_len(&frame),
        Err(EncodeError::FrameTooLong {
            length: MAX_FRAME_LEN + 1,
            max: MAX_FRAME_LEN,
        })
    );
    Ok(())
}

#[test]
fn rejects_invalid_lldp_semantics() {
    let invalid = LldpFrame {
        tlvs: Vec::new(),
        padding: &[],
        validity: Validity::Invalid,
    };
    assert_eq!(
        lldp_encoded_len(&invalid),
        Err(EncodeError::InvalidSemantic)
    );

    let oversized_value = [0; 512];
    let invalid_tlv = LldpFrame {
        tlvs: vec![Tlv {
            kind: 127,
            value: &oversized_value,
            offset: 0,
        }],
        padding: &[],
        validity: Validity::Valid,
    };
    assert_eq!(
        lldp_encoded_len(&invalid_tlv),
        Err(EncodeError::TlvValueTooLong {
            kind: 127,
            length: 512,
            max: 511,
        })
    );

    let invalid_kind = LldpFrame {
        tlvs: vec![Tlv {
            kind: 128,
            value: &[],
            offset: 0,
        }],
        padding: &[],
        validity: Validity::Valid,
    };
    assert_eq!(
        lldp_encoded_len(&invalid_kind),
        Err(EncodeError::InvalidTlvKind { kind: 128 })
    );

    let values = [0_u8; MAX_TLVS + 1];
    let tlvs = values
        .iter()
        .map(|value| Tlv {
            kind: 127,
            value: std::slice::from_ref(value),
            offset: 0,
        })
        .collect();
    let too_many = LldpFrame {
        tlvs,
        padding: &[],
        validity: Validity::Valid,
    };
    assert_eq!(
        lldp_encoded_len(&too_many),
        Err(EncodeError::TooManyTlvs { max: MAX_TLVS })
    );
}

#[test]
fn canonical_encoding_rechecks_semantic_marker() -> Result<(), Box<dyn std::error::Error>> {
    let input = valid_lldp();
    let mut forged_invalid = decode_lldp(&input)?;
    forged_invalid.validity = Validity::Invalid;
    assert_eq!(
        lldp_encoded_len(&forged_invalid),
        Err(EncodeError::InvalidSemantic)
    );

    let mut forged_valid = decode_lldp(&input)?;
    forged_valid.tlvs.swap(0, 1);
    forged_valid.validity = Validity::Valid;
    assert_eq!(
        lldp_encoded_len(&forged_valid),
        Err(EncodeError::InvalidSemantic)
    );
    Ok(())
}

#[test]
fn lldp_encode_error_diagnostic_text() {
    let errors = [
        EncodeError::FrameTooLong { length: 2, max: 1 },
        EncodeError::BufferTooShort {
            needed: 2,
            available: 1,
        },
        EncodeError::InvalidSemantic,
        EncodeError::TlvValueTooLong {
            kind: 127,
            length: 512,
            max: 511,
        },
        EncodeError::TooManyTlvs { max: MAX_TLVS },
        EncodeError::InvalidTlvKind { kind: 128 },
        EncodeError::LengthOverflow,
    ];

    for error in errors {
        assert!(!error.to_string().is_empty());
    }
}
