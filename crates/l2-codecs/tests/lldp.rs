use std::{
    io,
    panic::{AssertUnwindSafe, catch_unwind},
};

use l2_codecs::{DecodeError, LldpFrame, MAX_FRAME_LEN, MAX_TLVS, Tlv, Validity, decode_lldp};

const CHASSIS_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const PORT_NAME: &[u8] = b"Gi1/0/1";

fn tlv(kind: u8, value: &[u8]) -> Vec<u8> {
    assert!(kind <= 0x7f);
    let Some(length) = u16::try_from(value.len()).ok() else {
        return Vec::new();
    };
    assert!(length <= 0x01ff);

    let header = (u16::from(kind) << 9) | length;
    let mut bytes = header.to_be_bytes().to_vec();
    bytes.extend_from_slice(value);
    bytes
}

fn end() -> Vec<u8> {
    vec![0, 0]
}

fn valid_lldp() -> Vec<u8> {
    let mut chassis = vec![4];
    chassis.extend_from_slice(&CHASSIS_MAC);
    let mut port = vec![5];
    port.extend_from_slice(PORT_NAME);

    let mut bytes = tlv(1, &chassis);
    bytes.extend(tlv(2, &port));
    bytes.extend(tlv(3, &120_u16.to_be_bytes()));
    bytes.extend(end());
    bytes
}

fn decoded(input: &[u8]) -> Option<LldpFrame<'_>> {
    let result = decode_lldp(input);
    assert!(result.is_ok(), "unexpected structural error: {result:?}");
    result.ok()
}

#[test]
fn decodes_golden_lldp_with_offsets() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = valid_lldp();
    let Some(decoded) = decoded(&bytes) else {
        return Ok(());
    };

    assert_eq!(decoded.validity, Validity::Valid);
    assert_eq!(decoded.padding, &[]);
    assert_eq!(
        decoded.tlvs,
        vec![
            Tlv {
                kind: 1,
                value: &[4, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
                offset: 0,
            },
            Tlv {
                kind: 2,
                value: &[5, b'G', b'i', b'1', b'/', b'0', b'/', b'1'],
                offset: 9,
            },
            Tlv {
                kind: 3,
                value: &[0x00, 0x78],
                offset: 19,
            },
        ]
    );
    let first = decoded
        .tlvs
        .first()
        .ok_or_else(|| io::Error::other("golden frame lost its chassis TLV"))?;
    let chassis_value = bytes
        .get(2..)
        .ok_or_else(|| io::Error::other("golden frame lacked its TLV header"))?;
    assert!(std::ptr::eq(first.value.as_ptr(), chassis_value.as_ptr()));
    Ok(())
}

#[test]
fn retains_unknown_and_duplicate_tlvs() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = valid_lldp();
    let end_offset = bytes.len() - 2;
    bytes.splice(end_offset..end_offset, tlv(42, &[0xde, 0xad]));
    bytes.splice(end_offset + 4..end_offset + 4, tlv(42, &[0xbe]));

    let Some(decoded) = decoded(&bytes) else {
        return Ok(());
    };

    assert_eq!(decoded.validity, Validity::Valid);
    let mut unknowns = decoded.tlvs.iter().skip(3);
    let first_unknown = unknowns
        .next()
        .ok_or_else(|| io::Error::other("first unknown TLV was not retained"))?;
    let second_unknown = unknowns
        .next()
        .ok_or_else(|| io::Error::other("second unknown TLV was not retained"))?;
    assert_eq!(first_unknown.kind, 42);
    assert_eq!(first_unknown.value, &[0xde, 0xad]);
    assert_eq!(second_unknown.kind, 42);
    assert_eq!(second_unknown.value, &[0xbe]);
    Ok(())
}

#[test]
fn preserves_all_bytes_end_padding() {
    let mut bytes = valid_lldp();
    bytes.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0x00]);

    let Some(decoded) = decoded(&bytes) else {
        return;
    };

    assert_eq!(decoded.padding, &[0xaa, 0xbb, 0xcc, 0x00]);
    assert_eq!(decoded.tlvs.len(), 3);
}

#[test]
fn accepts_valid_ipv6_network_identifiers() {
    let chassis_ipv4 = vec![5, 1, 192, 0, 2, 1];
    let port_ipv4 = vec![4, 1, 198, 51, 100, 7];
    let mut bytes = tlv(1, &chassis_ipv4);
    bytes.extend(tlv(2, &port_ipv4));
    bytes.extend(tlv(3, &120_u16.to_be_bytes()));
    bytes.extend(end());

    let Some(ipv4_decoded) = decoded(&bytes) else {
        return;
    };
    assert_eq!(ipv4_decoded.validity, Validity::Valid);

    let chassis_ipv6 = vec![5, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let port_ipv6 = vec![4, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let mut bytes = tlv(1, &chassis_ipv6);
    bytes.extend(tlv(2, &port_ipv6));
    bytes.extend(tlv(3, &120_u16.to_be_bytes()));
    bytes.extend(end());

    let Some(decoded) = decoded(&bytes) else {
        return;
    };
    assert_eq!(decoded.validity, Validity::Valid);
}

#[test]
fn missing_misordered_mandatory_tlvs_invalid() {
    let cases = [
        {
            let mut chassis = vec![4];
            chassis.extend_from_slice(&CHASSIS_MAC);
            let mut bytes = tlv(1, &chassis);
            bytes.extend(tlv(3, &120_u16.to_be_bytes()));
            bytes.extend(end());
            bytes
        },
        {
            let mut port = vec![5];
            port.extend_from_slice(PORT_NAME);
            let mut chassis = vec![4];
            chassis.extend_from_slice(&CHASSIS_MAC);
            let mut bytes = tlv(2, &port);
            bytes.extend(tlv(1, &chassis));
            bytes.extend(tlv(3, &120_u16.to_be_bytes()));
            bytes.extend(end());
            bytes
        },
        {
            let mut chassis = vec![4];
            chassis.extend_from_slice(&CHASSIS_MAC);
            let mut port = vec![5];
            port.extend_from_slice(PORT_NAME);
            let mut bytes = tlv(1, &chassis);
            bytes.extend(tlv(42, &[0x01]));
            bytes.extend(tlv(2, &port));
            bytes.extend(tlv(3, &120_u16.to_be_bytes()));
            bytes.extend(end());
            bytes
        },
    ];

    for bytes in cases {
        let Some(decoded) = decoded(&bytes) else {
            continue;
        };
        assert_eq!(decoded.validity, Validity::Invalid);
    }
}

#[test]
fn marks_duplicate_mandatory_tlvs_invalid() {
    let mut bytes = valid_lldp();
    let end_offset = bytes.len() - 2;
    bytes.splice(end_offset..end_offset, tlv(3, &120_u16.to_be_bytes()));

    let Some(decoded) = decoded(&bytes) else {
        return;
    };

    assert_eq!(decoded.validity, Validity::Invalid);
}

#[test]
fn rejects_invalid_lldp_identifiers() {
    let cases = [
        (vec![0, 0xaa], vec![5, b'p']),
        (vec![8, 0, 0, 0, 0, 0], vec![5, b'p']),
        (vec![4, 0xaa], vec![5, b'p']),
        (vec![4], vec![5, b'p']),
        (vec![4, 0xaa, 0xbb, 0xcc, 0xdd, 0xee], vec![5, b'p']),
        (vec![4, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], vec![0]),
        (vec![5, 1], vec![5, b'p']),
    ];

    for (chassis, port) in cases {
        let mut bytes = tlv(1, &chassis);
        bytes.extend(tlv(2, &port));
        bytes.extend(tlv(3, &120_u16.to_be_bytes()));
        bytes.extend(end());

        let Some(decoded) = decoded(&bytes) else {
            continue;
        };
        assert_eq!(decoded.validity, Validity::Invalid);
    }
}

#[test]
fn rejects_oversized_lldp_identifier() {
    let chassis = vec![1; 257];
    let mut bytes = tlv(1, &chassis);
    bytes.extend(tlv(2, &[5, b'p']));
    bytes.extend(tlv(3, &120_u16.to_be_bytes()));
    bytes.extend(end());

    let Some(decoded) = decoded(&bytes) else {
        return;
    };
    assert_eq!(decoded.validity, Validity::Invalid);
}

#[test]
fn accepts_identifier_802_1ab_limit() {
    let chassis = vec![1; 256];
    let mut bytes = tlv(1, &chassis);
    bytes.extend(tlv(2, &[5, b'p']));
    bytes.extend(tlv(3, &120_u16.to_be_bytes()));
    bytes.extend(end());

    let Some(decoded) = decoded(&bytes) else {
        return;
    };
    assert_eq!(decoded.validity, Validity::Valid);
}

#[test]
fn accepts_short_non_network_identifier() {
    let mut bytes = tlv(1, &[1, 1]);
    bytes.extend(tlv(2, &[5, b'p']));
    bytes.extend(tlv(3, &120_u16.to_be_bytes()));
    bytes.extend(end());

    let Some(decoded) = decoded(&bytes) else {
        return;
    };
    assert_eq!(decoded.validity, Validity::Valid);
}

#[test]
fn rejects_invalid_network_address_fields() {
    let valid_chassis = {
        let mut value = vec![4];
        value.extend_from_slice(&CHASSIS_MAC);
        value
    };
    let valid_port = vec![5, b'p'];
    let cases = [
        // IPv4 addresses require four address bytes after the family byte
        (vec![5, 1, 192, 0, 2], valid_port.clone()),
        (valid_chassis.clone(), vec![4, 1, 198, 51, 100]),
        // IPv6 addresses require sixteen address bytes after the family byte
        (
            vec![5, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            valid_port.clone(),
        ),
        (
            valid_chassis.clone(),
            vec![4, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ),
        // Unknown address families still need at least one address byte
        (vec![5, 99], valid_port),
        (valid_chassis, vec![4, 99]),
    ];

    for (chassis, port) in cases {
        let mut bytes = tlv(1, &chassis);
        bytes.extend(tlv(2, &port));
        bytes.extend(tlv(3, &120_u16.to_be_bytes()));
        bytes.extend(end());

        let Some(decoded) = decoded(&bytes) else {
            continue;
        };
        assert_eq!(decoded.validity, Validity::Invalid);
    }
}

#[test]
fn invalid_port_identifier_length() {
    let mut chassis = vec![4];
    chassis.extend_from_slice(&CHASSIS_MAC);
    let mut bytes = tlv(1, &chassis);
    bytes.extend(tlv(2, &[3, 0, 1, 2, 3, 4]));
    bytes.extend(tlv(3, &120_u16.to_be_bytes()));
    bytes.extend(end());

    let Some(decoded) = decoded(&bytes) else {
        return;
    };
    assert_eq!(decoded.validity, Validity::Invalid);
}

#[test]
fn ttl_field_width_validation() {
    for ttl in [&[][..], &[0][..], &[0, 1, 2][..]] {
        let mut chassis = vec![4];
        chassis.extend_from_slice(&CHASSIS_MAC);
        let mut port = vec![5];
        port.extend_from_slice(PORT_NAME);
        let mut bytes = tlv(1, &chassis);
        bytes.extend(tlv(2, &port));
        bytes.extend(tlv(3, ttl));
        bytes.extend(end());

        let Some(decoded) = decoded(&bytes) else {
            continue;
        };
        assert_eq!(decoded.validity, Validity::Invalid);
    }
}

#[test]
fn reports_structural_tlv_errors() -> Result<(), Box<dyn std::error::Error>> {
    let mut without_end = valid_lldp();
    without_end.truncate(without_end.len() - 2);
    assert_eq!(
        decode_lldp(&without_end),
        Err(DecodeError::MissingEnd {
            offset: without_end.len()
        })
    );

    let mut nonzero_end = valid_lldp();
    let end_offset = nonzero_end.len() - 2;
    let length_byte = nonzero_end
        .get_mut(end_offset + 1)
        .ok_or_else(|| io::Error::other("golden frame lacked its End TLV"))?;
    *length_byte = 1;
    assert_eq!(
        decode_lldp(&nonzero_end),
        Err(DecodeError::NonZeroEndLength {
            offset: end_offset,
            length: 1,
        })
    );

    for end in 0..valid_lldp().len() {
        let bytes = valid_lldp();
        let truncated = bytes.get(..end).unwrap_or_default();
        let result = catch_unwind(AssertUnwindSafe(|| decode_lldp(truncated)));
        assert!(result.is_ok(), "decoder panicked for {end}-byte input");
    }
    Ok(())
}

#[test]
fn rejects_lldp_value_past_input() {
    let bytes = [0x02, 0x08, 0x04, 0, 1, 2, 3, 4, 5];

    assert_eq!(
        decode_lldp(&bytes),
        Err(DecodeError::TruncatedValue {
            offset: 0,
            kind: 1,
            declared: 8,
            available: 7,
        })
    );
}

#[test]
fn structural_errors_nonempty_lldp_diagnostics() {
    let errors = [
        DecodeError::FrameTooLong {
            length: MAX_FRAME_LEN + 1,
            max: MAX_FRAME_LEN,
        },
        DecodeError::TruncatedHeader {
            offset: 4,
            available: 1,
        },
        DecodeError::TruncatedValue {
            offset: 4,
            kind: 42,
            declared: 10,
            available: 2,
        },
        DecodeError::MissingEnd { offset: 12 },
        DecodeError::NonZeroEndLength {
            offset: 12,
            length: 3,
        },
        DecodeError::TooManyTlvs { max: MAX_TLVS },
    ];

    for error in errors {
        let message = error.to_string();
        assert!(!message.trim().is_empty());
        assert!(message.contains("LLDP"));
    }
}

#[test]
fn enforces_frame_tlv_count_bounds() {
    let too_long = vec![0; MAX_FRAME_LEN + 1];
    assert_eq!(
        decode_lldp(&too_long),
        Err(DecodeError::FrameTooLong {
            length: MAX_FRAME_LEN + 1,
            max: MAX_FRAME_LEN,
        })
    );

    let mut too_many = Vec::new();
    for _ in 0..=MAX_TLVS {
        too_many.extend(tlv(42, &[]));
    }
    too_many.extend(end());
    assert_eq!(
        decode_lldp(&too_many),
        Err(DecodeError::TooManyTlvs { max: MAX_TLVS })
    );

    let mut at_limit = Vec::new();
    for _ in 0..MAX_TLVS {
        at_limit.extend(tlv(42, &[]));
    }
    at_limit.extend(end());
    let Some(decoded) = decoded(&at_limit) else {
        return;
    };
    assert_eq!(decoded.tlvs.len(), MAX_TLVS);
    assert_eq!(decoded.validity, Validity::Invalid);
}

#[test]
fn bounds_oversized_lldp_padding() {
    let mut bytes = valid_lldp();
    bytes.resize(MAX_FRAME_LEN, 0xa5);

    let Some(decoded) = decoded(&bytes) else {
        return;
    };
    assert_eq!(decoded.padding.len(), MAX_FRAME_LEN - valid_lldp().len());
    assert!(decoded.padding.iter().all(|byte| *byte == 0xa5));
}
