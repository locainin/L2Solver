use l2_core::{EthernetFrame, FrameField, VlanTag};
use l2_discovery::{
    Discovery, FingerprintStatus, IdentityRole, NetworkAddress, Protocol, discover,
};

const SOURCE_MAC: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

const fn ethernet(field: FrameField, payload: &[u8]) -> EthernetFrame<'_> {
    EthernetFrame {
        destination: [0xff; 6],
        source: SOURCE_MAC,
        vlan_tags: Vec::<VlanTag>::new(),
        payload,
        padding: &[],
        field,
    }
}

fn ipv4(protocol: u8, body: &[u8]) -> Vec<u8> {
    let total_length = u16::try_from(20 + body.len()).unwrap_or(u16::MAX);
    let mut packet = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 255, protocol, 0, 0];
    packet.extend_from_slice(&[192, 0, 2, 1, 224, 0, 0, 18]);
    if let Some(field) = packet.get_mut(2..4) {
        field.copy_from_slice(&total_length.to_be_bytes());
    }
    packet.extend_from_slice(body);
    packet
}

fn ipv6(next_header: u8, body: &[u8]) -> Vec<u8> {
    let payload_length = u16::try_from(body.len()).unwrap_or(u16::MAX);
    let mut packet = vec![0x60, 0, 0, 0];
    packet.extend_from_slice(&payload_length.to_be_bytes());
    packet.extend_from_slice(&[next_header, 255]);
    packet.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    packet.extend_from_slice(&[0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12]);
    packet.extend_from_slice(body);
    packet
}

fn udp(source: u16, destination: u16, body: &[u8]) -> Vec<u8> {
    let udp_length = u16::try_from(8 + body.len()).unwrap_or(u16::MAX);
    let mut packet = Vec::with_capacity(8 + body.len());
    packet.extend_from_slice(&source.to_be_bytes());
    packet.extend_from_slice(&destination.to_be_bytes());
    packet.extend_from_slice(&udp_length.to_be_bytes());
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(body);
    packet
}

fn vrrp(version: u8, address_count: u8, addresses: &[u8]) -> Vec<u8> {
    let mut body = vec![(version << 4) | 1, 1, 100, address_count, 0, 100, 0, 0];
    body.extend_from_slice(addresses);
    body
}

fn dhcp(message_type: u8) -> Vec<u8> {
    let mut body = vec![0; 236];
    body.extend_from_slice(&[0x63, 0x82, 0x53, 0x63, 53, 1, message_type, 255]);
    body
}

fn discovery(field: FrameField, payload: &[u8]) -> Result<Discovery, &'static str> {
    discover(&ethernet(field, payload)).ok_or("expected protocol discovery")
}

mod vrrp_family {
    use super::*;

    #[test]
    fn v2_over_ipv4_is_valid() -> Result<(), &'static str> {
        let packet = ipv4(112, &vrrp(2, 1, &[192, 0, 2, 254]));
        let result = discovery(FrameField::EtherType(0x0800), &packet)?;

        assert_eq!(result.fingerprint.status, FingerprintStatus::Observed);
        assert_eq!(
            result.identity.and_then(|identity| identity.address),
            Some(NetworkAddress::Ipv4([192, 0, 2, 1]))
        );
        Ok(())
    }

    #[test]
    fn v2_over_ipv6_is_unsupported() -> Result<(), &'static str> {
        let packet = ipv6(112, &vrrp(2, 1, &[0; 16]));
        let result = discovery(FrameField::EtherType(0x86dd), &packet)?;

        assert_eq!(result.fingerprint.status, FingerprintStatus::Unsupported);
        assert_eq!(result.identity, None);
        Ok(())
    }

    #[test]
    fn v3_over_ipv4_is_valid() -> Result<(), &'static str> {
        let packet = ipv4(112, &vrrp(3, 1, &[192, 0, 2, 254]));
        let result = discovery(FrameField::EtherType(0x0800), &packet)?;

        assert_eq!(result.fingerprint.status, FingerprintStatus::Observed);
        assert_eq!(
            result.identity.and_then(|identity| identity.address),
            Some(NetworkAddress::Ipv4([192, 0, 2, 1]))
        );
        Ok(())
    }

    #[test]
    fn v3_over_ipv6_is_valid() -> Result<(), &'static str> {
        let packet = ipv6(112, &vrrp(3, 1, &[0; 16]));
        let result = discovery(FrameField::EtherType(0x86dd), &packet)?;

        assert_eq!(result.fingerprint.status, FingerprintStatus::Observed);
        assert_eq!(
            result.identity.and_then(|identity| identity.address),
            Some(NetworkAddress::Ipv6([
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ]))
        );
        Ok(())
    }

    #[test]
    fn zero_address_count_is_malformed() -> Result<(), &'static str> {
        for (field, packet) in [
            (FrameField::EtherType(0x0800), ipv4(112, &vrrp(3, 0, &[]))),
            (FrameField::EtherType(0x86dd), ipv6(112, &vrrp(3, 0, &[]))),
        ] {
            assert_eq!(
                discovery(field, &packet)?.fingerprint.status,
                FingerprintStatus::Malformed
            );
        }
        Ok(())
    }

    #[test]
    fn truncated_addresses_are_reported() -> Result<(), &'static str> {
        for (field, packet) in [
            (
                FrameField::EtherType(0x0800),
                ipv4(112, &vrrp(3, 1, &[0; 3])),
            ),
            (
                FrameField::EtherType(0x86dd),
                ipv6(112, &vrrp(3, 1, &[0; 15])),
            ),
        ] {
            assert_eq!(
                discovery(field, &packet)?.fingerprint.status,
                FingerprintStatus::Truncated
            );
        }
        Ok(())
    }
}

mod dhcp_message_type {
    use super::*;

    #[test]
    fn every_assigned_value_is_observed() -> Result<(), &'static str> {
        for message_type in 1..=18 {
            let packet = ipv4(17, &udp(67, 68, &dhcp(message_type)));
            assert_eq!(
                discovery(FrameField::EtherType(0x0800), &packet)?
                    .fingerprint
                    .status,
                FingerprintStatus::Observed,
                "message type {message_type}"
            );
        }
        Ok(())
    }

    #[test]
    fn unassigned_value_is_unsupported() -> Result<(), &'static str> {
        let packet = ipv4(17, &udp(67, 68, &dhcp(19)));
        assert_eq!(
            discovery(FrameField::EtherType(0x0800), &packet)?
                .fingerprint
                .status,
            FingerprintStatus::Unsupported
        );
        Ok(())
    }

    #[test]
    fn broken_option_framing_is_malformed() -> Result<(), &'static str> {
        let mut body = vec![0; 236];
        body.extend_from_slice(&[0x63, 0x82, 0x53, 0x63, 53, 2, 1, 2, 255]);
        let packet = ipv4(17, &udp(67, 68, &body));

        assert_eq!(
            discovery(FrameField::EtherType(0x0800), &packet)?
                .fingerprint
                .status,
            FingerprintStatus::Malformed
        );
        Ok(())
    }

    #[test]
    fn duplicate_message_type_is_malformed() -> Result<(), &'static str> {
        let mut body = vec![0; 236];
        body.extend_from_slice(&[0x63, 0x82, 0x53, 0x63, 53, 1, 1, 53, 1, 3, 255]);
        let packet = ipv4(17, &udp(67, 68, &body));

        assert_eq!(
            discovery(FrameField::EtherType(0x0800), &packet)?
                .fingerprint
                .status,
            FingerprintStatus::Malformed
        );
        Ok(())
    }
}

mod mka_recognition {
    use super::*;

    fn eapol(packet_type: u8, body: &[u8]) -> Vec<u8> {
        let body_length = u16::try_from(body.len()).unwrap_or(u16::MAX);
        let mut packet = vec![3, packet_type];
        packet.extend_from_slice(&body_length.to_be_bytes());
        packet.extend_from_slice(body);
        packet
    }

    fn mkpdu(version: u8, basic_body_length: u16) -> Vec<u8> {
        let [length_high, length_low] = basic_body_length.to_be_bytes();
        let mut body = vec![version, 128, length_high & 0x0f, length_low];
        body.resize(48, 0);
        body
    }

    #[test]
    fn valid_basic_set_is_mka() -> Result<(), &'static str> {
        let packet = eapol(5, &mkpdu(3, 28));
        let result = discovery(FrameField::EtherType(0x888e), &packet)?;

        assert_eq!(result.fingerprint.protocol, Protocol::Mka);
        assert_eq!(result.fingerprint.status, FingerprintStatus::Observed);
        assert_eq!(
            result.identity.map(|identity| identity.role),
            Some(IdentityRole::LinkSecurityParticipant)
        );
        Ok(())
    }

    #[test]
    fn short_basic_set_is_malformed() -> Result<(), &'static str> {
        let packet = eapol(5, &mkpdu(3, 27));
        let result = discovery(FrameField::EtherType(0x888e), &packet)?;

        assert_eq!(result.fingerprint.protocol, Protocol::Mka);
        assert_eq!(result.fingerprint.status, FingerprintStatus::Malformed);
        Ok(())
    }

    #[test]
    fn missing_icv_is_malformed() -> Result<(), &'static str> {
        let body = mkpdu(3, 28);
        let packet = eapol(5, body.get(..32).ok_or("MKA fixture is too short")?);
        let result = discovery(FrameField::EtherType(0x888e), &packet)?;

        assert_eq!(result.fingerprint.protocol, Protocol::Mka);
        assert_eq!(result.fingerprint.status, FingerprintStatus::Malformed);
        Ok(())
    }

    #[test]
    fn future_version_is_unsupported() -> Result<(), &'static str> {
        let packet = eapol(5, &mkpdu(4, 28));
        let result = discovery(FrameField::EtherType(0x888e), &packet)?;

        assert_eq!(result.fingerprint.protocol, Protocol::Mka);
        assert_eq!(result.fingerprint.status, FingerprintStatus::Unsupported);
        Ok(())
    }

    #[test]
    fn unknown_parameter_set_keeps_alignment() -> Result<(), &'static str> {
        let mut body = mkpdu(3, 28);
        body.splice(32..32, [200, 0, 0, 0]);
        let packet = eapol(5, &body);

        assert_eq!(
            discovery(FrameField::EtherType(0x888e), &packet)?
                .fingerprint
                .status,
            FingerprintStatus::Observed
        );
        Ok(())
    }

    #[test]
    fn default_icv_indicator_is_observed() -> Result<(), &'static str> {
        let mut body = mkpdu(3, 28);
        body.splice(32..32, [255, 0, 0, 16]);
        let packet = eapol(5, &body);

        assert_eq!(
            discovery(FrameField::EtherType(0x888e), &packet)?
                .fingerprint
                .status,
            FingerprintStatus::Observed
        );
        Ok(())
    }

    #[test]
    fn nondefault_icv_length_is_unsupported() -> Result<(), &'static str> {
        let mut body = mkpdu(3, 28);
        body.splice(32..32, [255, 0, 0, 32]);
        body.extend_from_slice(&[0; 16]);
        let packet = eapol(5, &body);

        assert_eq!(
            discovery(FrameField::EtherType(0x888e), &packet)?
                .fingerprint
                .status,
            FingerprintStatus::Unsupported
        );
        Ok(())
    }

    #[test]
    fn parameter_length_cannot_enter_icv() -> Result<(), &'static str> {
        let mut body = mkpdu(3, 28);
        body.splice(32..32, [1, 0, 0, 4]);
        let packet = eapol(5, &body);

        assert_eq!(
            discovery(FrameField::EtherType(0x888e), &packet)?
                .fingerprint
                .status,
            FingerprintStatus::Malformed
        );
        Ok(())
    }

    #[test]
    fn other_eapol_type_stays_generic() -> Result<(), &'static str> {
        let packet = eapol(0, &[]);
        let result = discovery(FrameField::EtherType(0x888e), &packet)?;

        assert_eq!(result.fingerprint.protocol, Protocol::Eapol);
        assert_eq!(result.fingerprint.status, FingerprintStatus::Observed);
        Ok(())
    }
}
