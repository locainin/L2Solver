use l2_codecs::{BridgeId, PortRole, StpBpduType, StpContext, StpError, StpVersion, decode_stp};

const ROOT_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const BRIDGE_MAC: [u8; 6] = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];

fn bridge_id(priority_and_extension: u16, mac: [u8; 6]) -> [u8; 8] {
    let mut bytes = [0; 8];
    if let Some(prefix) = bytes.get_mut(..2) {
        prefix.copy_from_slice(&priority_and_extension.to_be_bytes());
    }
    if let Some(address) = bytes.get_mut(2..) {
        address.copy_from_slice(&mac);
    }
    bytes
}

fn configuration_bpdu() -> Vec<u8> {
    let mut bytes = vec![0, 0, 0, 0, 0x81];
    bytes.extend(bridge_id(0x8001, ROOT_MAC));
    bytes.extend(0x0000_0010_u32.to_be_bytes());
    bytes.extend(bridge_id(0x9002, BRIDGE_MAC));
    bytes.extend(0x8001_u16.to_be_bytes());
    bytes.extend(0x0100_u16.to_be_bytes());
    bytes.extend(0x1400_u16.to_be_bytes());
    bytes.extend(0x0200_u16.to_be_bytes());
    bytes.extend(0x0f00_u16.to_be_bytes());
    bytes
}

fn rstp_bpdu() -> Vec<u8> {
    let mut bytes = vec![0, 0, 2, 2, 0x7e];
    bytes.extend(bridge_id(0x8001, ROOT_MAC));
    bytes.extend(0x0000_0010_u32.to_be_bytes());
    bytes.extend(bridge_id(0x9002, BRIDGE_MAC));
    bytes.extend(0x8001_u16.to_be_bytes());
    bytes.extend(0x0100_u16.to_be_bytes());
    bytes.extend(0x1400_u16.to_be_bytes());
    bytes.extend(0x0200_u16.to_be_bytes());
    bytes.extend(0x0f00_u16.to_be_bytes());
    bytes.push(0);
    bytes
}

#[test]
fn decodes_configuration_bpdu_fields() -> Result<(), StpError> {
    let bytes = configuration_bpdu();
    let frame = decode_stp(&bytes)?;

    assert_eq!(frame.raw, &bytes);
    assert_eq!(frame.version, StpVersion::Stp);
    assert_eq!(frame.bpdu_type, StpBpduType::Configuration);
    assert_eq!(frame.flags.raw, 0x81);
    assert!(frame.flags.topology_change());
    assert!(frame.flags.topology_change_ack());
    assert_eq!(frame.root, Some(BridgeId::from_wire(0x8001, ROOT_MAC)));
    assert_eq!(frame.bridge, Some(BridgeId::from_wire(0x9002, BRIDGE_MAC)));
    assert_eq!(frame.cost, Some(16));
    assert_eq!(frame.port.map(|port| port.raw), Some(0x8001));
    assert_eq!(frame.timers.map(|timers| timers.message_age), Some(0x0100));
    assert_eq!(frame.padding, []);
    Ok(())
}

#[test]
fn decodes_rstp_llc_encapsulated_rstp() -> Result<(), StpError> {
    let bpdu = rstp_bpdu();
    let frame = decode_stp(&bpdu)?;
    assert_eq!(frame.version, StpVersion::Rstp);
    assert_eq!(frame.bpdu_type, StpBpduType::Rapid);
    assert_eq!(frame.flags.port_role(), PortRole::Designated);
    assert!(frame.flags.proposal());
    assert!(frame.flags.learning());
    assert!(frame.flags.forwarding());
    assert!(frame.flags.agreement());
    assert_eq!(frame.version_1_length, Some(0));

    let mut llc = vec![0x42, 0x42, 0x03];
    llc.extend_from_slice(&bpdu);
    let encapsulated = decode_stp(&llc)?;
    assert_eq!(encapsulated.raw, &bpdu);
    assert_eq!(encapsulated.wire, &llc);
    Ok(())
}

#[test]
fn tcn_bpdu_without_tree_fields() -> Result<(), StpError> {
    let bytes = [0, 0, 0, 0x80, 0xaa, 0xbb];
    let frame = decode_stp(&bytes)?;

    assert_eq!(frame.version, StpVersion::Stp);
    assert_eq!(frame.bpdu_type, StpBpduType::TopologyChange);
    assert_eq!(frame.root, None);
    assert_eq!(frame.bridge, None);
    assert_eq!(frame.port, None);
    assert_eq!(frame.cost, None);
    assert_eq!(frame.timers, None);
    assert_eq!(frame.padding, &[0xaa, 0xbb]);
    Ok(())
}

#[test]
fn minimum_tcn_header_without_padding() -> Result<(), StpError> {
    let frame = decode_stp(&[0, 0, 0, 0x80])?;

    assert_eq!(frame.raw, &[0, 0, 0, 0x80]);
    assert_eq!(frame.padding, []);
    Ok(())
}

#[test]
fn rejects_invalid_stp_headers() {
    let mut bad_protocol = configuration_bpdu();
    if let Some(byte) = bad_protocol.get_mut(1) {
        *byte = 1;
    }
    assert_eq!(
        decode_stp(&bad_protocol),
        Err(StpError::InvalidProtocolIdentifier { value: 1 })
    );

    let mut bad_version = configuration_bpdu();
    if let Some(byte) = bad_version.get_mut(2) {
        *byte = 1;
    }
    assert_eq!(
        decode_stp(&bad_version),
        Err(StpError::UnsupportedVersion { value: 1 })
    );

    let mut bad_type = configuration_bpdu();
    if let Some(byte) = bad_type.get_mut(3) {
        *byte = 3;
    }
    assert_eq!(
        decode_stp(&bad_type),
        Err(StpError::UnsupportedType {
            version: 0,
            value: 3,
        })
    );

    let mut unknown_version = configuration_bpdu();
    if let Some(byte) = unknown_version.get_mut(2) {
        *byte = 3;
    }
    assert_eq!(
        decode_stp(&unknown_version),
        Err(StpError::UnsupportedVersion { value: 3 })
    );

    let mut extension = rstp_bpdu();
    if let Some(byte) = extension.get_mut(35) {
        *byte = 1;
    }
    assert_eq!(
        decode_stp(&extension),
        Err(StpError::UnsupportedExtension {
            version: 2,
            length: 1,
        })
    );

    let bytes = configuration_bpdu();
    for end in 0..=bytes.len() {
        let truncated = bytes.get(..end).unwrap_or_default();
        let result = std::panic::catch_unwind(|| decode_stp(truncated));
        assert!(result.is_ok(), "decoder panicked for {end}-byte input");
        if end < bytes.len() {
            assert!(result.is_ok_and(|value| value.is_err()));
        } else {
            assert!(result.is_ok_and(|value| value.is_ok()));
        }
    }

    assert_eq!(
        decode_stp(&[0]),
        Err(StpError::Truncated {
            context: StpContext::CommonHeader,
            needed: 4,
            available: 1,
        })
    );
}

#[test]
fn never_panics_rstp_tcn_prefix() {
    for bytes in [rstp_bpdu(), vec![0, 0, 0, 0x80]] {
        for end in 0..bytes.len() {
            let truncated = bytes.get(..end).unwrap_or_default();
            let result = std::panic::catch_unwind(|| decode_stp(truncated));
            assert!(result.is_ok(), "decoder panicked for {end}-byte input");
        }
    }
}

#[test]
fn llc_truncation_invalid_llc_values() {
    assert_eq!(
        decode_stp(&[0x42, 0x42]),
        Err(StpError::Truncated {
            context: l2_codecs::StpContext::LlcHeader,
            needed: 3,
            available: 2,
        })
    );
    assert_eq!(
        decode_stp(&[0x42, 0x41, 0x03]),
        Err(StpError::InvalidLlc {
            dsap: 0x42,
            ssap: 0x41,
            control: 0x03,
        })
    );
}

#[test]
fn keeps_the_frame_budget_bounded() {
    let bytes = vec![0; l2_codecs::MAX_FRAME_LEN + 1];
    assert_eq!(
        decode_stp(&bytes),
        Err(StpError::FrameTooLong {
            length: l2_codecs::MAX_FRAME_LEN + 1,
            max: l2_codecs::MAX_FRAME_LEN,
        })
    );

    let mut exact = configuration_bpdu();
    exact.resize(l2_codecs::MAX_FRAME_LEN, 0);
    assert!(decode_stp(&exact).is_ok());
}

#[test]
fn reports_first_missing_config_field() {
    let bytes = configuration_bpdu();
    for end in 0..bytes.len() {
        let input = bytes.get(..end).unwrap_or_default();
        let Some(expected) = (match end {
            0..=3 => Some(StpError::Truncated {
                context: StpContext::CommonHeader,
                needed: 4,
                available: end,
            }),
            4 => Some(StpError::Truncated {
                context: StpContext::ConfigurationBody,
                needed: 5,
                available: end,
            }),
            5..=12 => Some(StpError::Truncated {
                context: StpContext::ConfigurationBody,
                needed: 13,
                available: end,
            }),
            13..=16 => Some(StpError::Truncated {
                context: StpContext::ConfigurationBody,
                needed: 17,
                available: end,
            }),
            17..=24 => Some(StpError::Truncated {
                context: StpContext::ConfigurationBody,
                needed: 25,
                available: end,
            }),
            25..=26 => Some(StpError::Truncated {
                context: StpContext::ConfigurationBody,
                needed: 27,
                available: end,
            }),
            27..=28 => Some(StpError::Truncated {
                context: StpContext::ConfigurationBody,
                needed: 29,
                available: end,
            }),
            29..=30 => Some(StpError::Truncated {
                context: StpContext::ConfigurationBody,
                needed: 31,
                available: end,
            }),
            31..=32 => Some(StpError::Truncated {
                context: StpContext::ConfigurationBody,
                needed: 33,
                available: end,
            }),
            33..=34 => Some(StpError::Truncated {
                context: StpContext::ConfigurationBody,
                needed: 35,
                available: end,
            }),
            _ => None,
        }) else {
            continue;
        };
        assert_eq!(
            decode_stp(input),
            Err(expected),
            "unexpected result at {end}"
        );
    }
}

#[test]
fn stp_error_context_diagnostic_text() {
    let contexts = [
        StpContext::LlcHeader,
        StpContext::CommonHeader,
        StpContext::ConfigurationBody,
        StpContext::RapidExtension,
    ];
    for context in contexts {
        assert_ne!(context.to_string(), "");
    }

    let errors = [
        StpError::FrameTooLong { length: 2, max: 1 },
        StpError::Truncated {
            context: StpContext::CommonHeader,
            needed: 4,
            available: 1,
        },
        StpError::InvalidLlc {
            dsap: 0x42,
            ssap: 0x41,
            control: 0x03,
        },
        StpError::InvalidProtocolIdentifier { value: 1 },
        StpError::UnsupportedVersion { value: 3 },
        StpError::UnsupportedType {
            version: 0,
            value: 3,
        },
        StpError::UnsupportedExtension {
            version: 2,
            length: 1,
        },
    ];
    for error in errors {
        assert_ne!(error.to_string(), "");
    }
}
