use l2_core::{EthernetFrame, FrameField, VlanTag};
use l2_discovery::{
    Fingerprint, FingerprintStatus, IdentityRole, NetworkAddress, Protocol, discover, fingerprint,
};
use std::error::Error;

const DESTINATION: [u8; 6] = [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb];
const SOURCE: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

const fn ethernet(ether_type: u16, payload: &[u8]) -> EthernetFrame<'_> {
    EthernetFrame {
        destination: DESTINATION,
        source: SOURCE,
        vlan_tags: Vec::<VlanTag>::new(),
        payload,
        padding: &[],
        field: FrameField::EtherType(ether_type),
    }
}

const fn expected(protocol: Protocol, status: FingerprintStatus) -> Fingerprint {
    Fingerprint { protocol, status }
}

fn ipv4_packet(ip_protocol: u8, body: &[u8], total_length: Option<u16>) -> Vec<u8> {
    let total = total_length
        .unwrap_or_else(|| u16::try_from(20_usize.saturating_add(body.len())).unwrap_or(u16::MAX));
    let mut packet = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, ip_protocol, 0, 0];
    packet.extend_from_slice(&[192, 0, 2, 1, 224, 0, 0, 251]);
    if let Some(field) = packet.get_mut(2..4) {
        field.copy_from_slice(&total.to_be_bytes());
    }
    packet.extend_from_slice(body);
    packet
}

fn ipv4_udp(
    source_port: u16,
    destination_port: u16,
    body: &[u8],
    udp_length: Option<u16>,
    total_length: Option<u16>,
) -> Vec<u8> {
    let udp_total = udp_length
        .unwrap_or_else(|| u16::try_from(8_usize.saturating_add(body.len())).unwrap_or(u16::MAX));
    let ip_total = total_length.unwrap_or_else(|| {
        u16::try_from(20_usize.saturating_add(usize::from(udp_total))).unwrap_or(u16::MAX)
    });
    let mut udp = Vec::with_capacity(8 + body.len());
    udp.extend_from_slice(&source_port.to_be_bytes());
    udp.extend_from_slice(&destination_port.to_be_bytes());
    udp.extend_from_slice(&udp_total.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(body);
    ipv4_packet(17, &udp, Some(ip_total))
}

fn ipv6_packet(next_header: u8, body: &[u8], payload_length: Option<u16>) -> Vec<u8> {
    let payload_length =
        payload_length.unwrap_or_else(|| u16::try_from(body.len()).unwrap_or(u16::MAX));
    let mut packet = vec![0x60, 0, 0, 0, 0, 0, next_header, 64];
    packet.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    packet.extend_from_slice(&[0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0c]);
    if let Some(field) = packet.get_mut(4..6) {
        field.copy_from_slice(&payload_length.to_be_bytes());
    }
    packet.extend_from_slice(body);
    packet
}

fn ipv6_udp(
    source_port: u16,
    destination_port: u16,
    body: &[u8],
    udp_length: Option<u16>,
    payload_length: Option<u16>,
) -> Vec<u8> {
    let udp_total = udp_length
        .unwrap_or_else(|| u16::try_from(8_usize.saturating_add(body.len())).unwrap_or(u16::MAX));
    let mut udp = Vec::with_capacity(8 + body.len());
    udp.extend_from_slice(&source_port.to_be_bytes());
    udp.extend_from_slice(&destination_port.to_be_bytes());
    udp.extend_from_slice(&udp_total.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(body);
    ipv6_packet(17, &udp, payload_length)
}

#[track_caller]
fn assert_status(frame: &EthernetFrame<'_>, protocol: Protocol, status: FingerprintStatus) {
    assert_eq!(fingerprint(frame), Some(expected(protocol, status)));
}

mod names {
    use super::*;

    #[test]
    fn protocol_names_are_stable() {
        for (protocol, display, json) in [
            (Protocol::Igmp, "IGMP", "\"igmp\""),
            (Protocol::Mdns, "mDNS", "\"mdns\""),
            (Protocol::Ssdp, "SSDP", "\"ssdp\""),
            (Protocol::Netbios, "NetBIOS", "\"netbios\""),
        ] {
            assert_eq!(protocol.to_string(), display);
            assert_eq!(serde_json::to_string(&protocol).unwrap_or_default(), json);
        }
    }
}

mod igmp {
    use super::*;

    #[test]
    fn recognizes_versions_and_group_records() {
        let v1_query = [0x11, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            fingerprint(&ethernet(0x0800, &ipv4_packet(2, &v1_query, None),)),
            Some(expected(Protocol::Igmp, FingerprintStatus::Observed))
        );

        let v2_report = [0x16, 0, 0, 0, 239, 1, 1, 1];
        assert_eq!(
            fingerprint(&ethernet(0x0800, &ipv4_packet(2, &v2_report, None),)),
            Some(expected(Protocol::Igmp, FingerprintStatus::Observed))
        );

        let v3_query = [0x11, 0, 0, 0, 239, 1, 1, 1, 0, 0, 0, 0];
        assert_eq!(
            fingerprint(&ethernet(0x0800, &ipv4_packet(2, &v3_query, None),)),
            Some(expected(Protocol::Igmp, FingerprintStatus::Observed))
        );

        let v3_report = [
            0x22, 0, 0, 0, 0, 0, 0, 1, // one group record
            1, 0, 0, 0, 239, 1, 1, 1, // MODE_IS_INCLUDE, no sources or aux data
        ];
        assert_eq!(
            fingerprint(&ethernet(0x0800, &ipv4_packet(2, &v3_report, None),)),
            Some(expected(Protocol::Igmp, FingerprintStatus::Observed))
        );
    }

    #[test]
    fn rejects_short_and_invalid_messages() {
        for length in 0..8 {
            let body = vec![0x11; length];
            assert_status(
                &ethernet(0x0800, &ipv4_packet(2, &body, None)),
                Protocol::Igmp,
                FingerprintStatus::Truncated,
            );
        }

        let malformed_query = [0x11, 0, 0, 0, 239, 1, 1, 1, 0];
        assert_status(
            &ethernet(0x0800, &ipv4_packet(2, &malformed_query, None)),
            Protocol::Igmp,
            FingerprintStatus::Malformed,
        );
        let malformed_record = [
            0x22, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 239, 1, 1, 1, // reserved record type
        ];
        assert_status(
            &ethernet(0x0800, &ipv4_packet(2, &malformed_record, None)),
            Protocol::Igmp,
            FingerprintStatus::Malformed,
        );

        let unsupported = [0x13, 0, 0, 0, 0, 0, 0, 0];
        assert_status(
            &ethernet(0x0800, &ipv4_packet(2, &unsupported, None)),
            Protocol::Igmp,
            FingerprintStatus::Unsupported,
        );
    }

    #[test]
    fn honors_capture_and_record_limits() {
        let truncated_query = [0x11, 0, 0, 0, 239, 1, 1, 1, 0, 0, 0, 1, 192, 0, 2, 2];
        let mut truncated_packet = ipv4_packet(2, &truncated_query, Some(36));
        truncated_packet.truncate(35);
        assert_status(
            &ethernet(0x0800, &truncated_packet),
            Protocol::Igmp,
            FingerprintStatus::Truncated,
        );

        // A complete message remains capture-truncated when the IPv4 envelope declares more bytes
        let complete_v2_report = [0x16, 0, 0, 0, 239, 1, 1, 1];
        assert_status(
            &ethernet(0x0800, &ipv4_packet(2, &complete_v2_report, Some(29))),
            Protocol::Igmp,
            FingerprintStatus::Truncated,
        );

        // Ethernet padding after the declared IPv4 packet is not part of the IGMP message
        let mut padded_v2_report = ipv4_packet(2, &complete_v2_report, None);
        padded_v2_report.push(0xaa);
        assert_status(
            &ethernet(0x0800, &padded_v2_report),
            Protocol::Igmp,
            FingerprintStatus::Observed,
        );

        // The configured record limit accepts its boundary and rejects one additional record
        let mut maximum_records = vec![0x22, 0, 0, 0, 0, 0, 1, 0];
        for _ in 0..256 {
            maximum_records.extend_from_slice(&[1, 0, 0, 0, 239, 1, 1, 1]);
        }
        assert_status(
            &ethernet(0x0800, &ipv4_packet(2, &maximum_records, None)),
            Protocol::Igmp,
            FingerprintStatus::Observed,
        );
        let excessive_records = [0x22, 0, 0, 0, 0, 0, 1, 1];
        assert_status(
            &ethernet(0x0800, &ipv4_packet(2, &excessive_records, None)),
            Protocol::Igmp,
            FingerprintStatus::Unsupported,
        );
    }

    #[test]
    fn checks_record_and_fragment_boundaries() {
        // A declared source needs four bytes, while trailing bytes are malformed input
        let missing_source = [
            0x22, 0, 0, 0, 0, 0, 0, 1, // one group record
            1, 0, 0, 1, 239, 1, 1, 1, // one source declared but absent
        ];
        assert_status(
            &ethernet(0x0800, &ipv4_packet(2, &missing_source, None)),
            Protocol::Igmp,
            FingerprintStatus::Truncated,
        );
        let mut trailing_record_byte = [
            0x22, 0, 0, 0, 0, 0, 0, 1, // one group record
            1, 0, 0, 0, 239, 1, 1, 1, // exact record
        ]
        .to_vec();
        trailing_record_byte.push(0xaa);
        assert_status(
            &ethernet(0x0800, &ipv4_packet(2, &trailing_record_byte, None)),
            Protocol::Igmp,
            FingerprintStatus::Malformed,
        );

        let fragmented = ipv4_udp(5353, 5353, &[], None, None);
        let mut fragmented = fragmented;
        if let Some(field) = fragmented.get_mut(6..8) {
            field.copy_from_slice(&0x2000_u16.to_be_bytes());
        }
        assert_eq!(fingerprint(&ethernet(0x0800, &fragmented)), None);
    }
}

mod mdns {
    use super::*;

    #[test]
    fn recognizes_over_ipv4_and_ipv6() {
        let opaque_payload = [0xde, 0xad, 0xbe, 0xef];
        assert_status(
            &ethernet(0x0800, &ipv4_udp(5353, 5353, &opaque_payload, None, None)),
            Protocol::Mdns,
            FingerprintStatus::Observed,
        );
        assert_status(
            &ethernet(0x86dd, &ipv6_udp(5353, 5353, &opaque_payload, None, None)),
            Protocol::Mdns,
            FingerprintStatus::Observed,
        );
        assert_status(
            &ethernet(0x0800, &ipv4_udp(5353, 42000, &[], None, None)),
            Protocol::Mdns,
            FingerprintStatus::Observed,
        );
        assert_eq!(
            fingerprint(&ethernet(
                0x0800,
                &ipv4_udp(42000, 42001, &opaque_payload, None, None),
            )),
            None
        );
    }

    #[test]
    fn udp_boundaries_ip_version_safely() {
        let complete = ipv4_udp(5353, 5353, &[], None, None);
        let mut truncated = complete;
        truncated.truncate(truncated.len().saturating_sub(1));
        assert_status(
            &ethernet(0x0800, &truncated),
            Protocol::Mdns,
            FingerprintStatus::Truncated,
        );

        assert_status(
            &ethernet(0x0800, &ipv4_udp(5353, 5353, &[], Some(4), Some(24))),
            Protocol::Mdns,
            FingerprintStatus::Malformed,
        );
        assert_status(
            &ethernet(0x0800, &ipv4_udp(5353, 5353, &[], Some(20), Some(28))),
            Protocol::Mdns,
            FingerprintStatus::Truncated,
        );

        // Captured bytes beyond the IPv4 total length are Ethernet padding
        let mut padded = ipv4_udp(5353, 5353, &[], None, None);
        padded.push(0xaa);
        assert_status(
            &ethernet(0x0800, &padded),
            Protocol::Mdns,
            FingerprintStatus::Observed,
        );

        // Captured bytes beyond UDP length are malformed even when the outer IPv4 packet is cut short
        assert_status(
            &ethernet(
                0x0800,
                &ipv4_udp(5353, 5353, &[0xaa, 0xbb, 0xcc, 0xdd], Some(8), Some(40)),
            ),
            Protocol::Mdns,
            FingerprintStatus::Malformed,
        );

        let mut unsupported_version = ipv4_packet(17, &[], Some(20));
        if let Some(first) = unsupported_version.first_mut() {
            *first = 0x65;
        }
        assert_eq!(fingerprint(&ethernet(0x0800, &unsupported_version)), None);
    }
}

mod ssdp {
    use super::*;

    #[test]
    fn recognizes_over_ipv4_and_ipv6() {
        let opaque_payload = b"M-SEARCH * HTTP/1.1\r\n\r\n";
        assert_status(
            &ethernet(0x0800, &ipv4_udp(1900, 1900, opaque_payload, None, None)),
            Protocol::Ssdp,
            FingerprintStatus::Observed,
        );
        assert_status(
            &ethernet(0x86dd, &ipv6_udp(1900, 49152, opaque_payload, None, None)),
            Protocol::Ssdp,
            FingerprintStatus::Observed,
        );
    }

    #[test]
    fn reports_udp_boundaries_and_lengths() {
        let complete = ipv6_udp(1900, 1900, &[], None, None);
        let mut truncated = complete;
        truncated.truncate(truncated.len().saturating_sub(2));
        assert_status(
            &ethernet(0x86dd, &truncated),
            Protocol::Ssdp,
            FingerprintStatus::Truncated,
        );
        assert_status(
            &ethernet(0x86dd, &ipv6_udp(1900, 1900, &[], Some(4), Some(8))),
            Protocol::Ssdp,
            FingerprintStatus::Malformed,
        );
        assert_status(
            &ethernet(
                0x86dd,
                &ipv6_udp(1900, 1900, &[0, 0, 0, 0], Some(8), Some(12)),
            ),
            Protocol::Ssdp,
            FingerprintStatus::Malformed,
        );
    }
}

mod netbios {
    use super::*;

    #[test]
    fn recognizes_name_ports_over_ipv4() {
        for ports in [(137, 137), (137, 40000), (40000, 137), (138, 138)] {
            assert_status(
                &ethernet(0x0800, &ipv4_udp(ports.0, ports.1, &[0xaa], None, None)),
                Protocol::Netbios,
                FingerprintStatus::Observed,
            );
        }
        assert_eq!(
            fingerprint(&ethernet(0x86dd, &ipv6_udp(137, 137, &[0xaa], None, None),)),
            None
        );
    }

    #[test]
    fn reports_udp_boundaries_and_lengths() {
        let complete = ipv4_udp(138, 138, &[], None, None);
        let mut truncated = complete;
        truncated.truncate(truncated.len().saturating_sub(1));
        assert_status(
            &ethernet(0x0800, &truncated),
            Protocol::Netbios,
            FingerprintStatus::Truncated,
        );
        assert_status(
            &ethernet(0x0800, &ipv4_udp(138, 138, &[], Some(4), Some(24))),
            Protocol::Netbios,
            FingerprintStatus::Malformed,
        );
        assert_status(
            &ethernet(
                0x0800,
                &ipv4_udp(138, 138, &[0, 0, 0, 0], Some(8), Some(32)),
            ),
            Protocol::Netbios,
            FingerprintStatus::Malformed,
        );
    }
}

mod identities {
    use super::*;

    #[test]
    fn retain_validated_ip_sources() -> Result<(), Box<dyn Error>> {
        let igmp = ipv4_packet(2, &[0x11, 0, 0, 0, 0, 0, 0, 0], None);
        let discovery = discover(&ethernet(0x0800, &igmp)).ok_or("IGMP fingerprint")?;
        let identity = discovery.identity.ok_or("IGMP identity")?;
        assert_eq!(identity.role, IdentityRole::MulticastParticipant);
        assert_eq!(identity.address, Some(NetworkAddress::Ipv4([192, 0, 2, 1])));

        let mdns = ipv6_udp(5353, 5353, &[], None, None);
        let discovery = discover(&ethernet(0x86dd, &mdns)).ok_or("mDNS fingerprint")?;
        let identity = discovery.identity.ok_or("mDNS identity")?;
        assert_eq!(identity.role, IdentityRole::MulticastParticipant);
        assert_eq!(
            identity.address,
            Some(NetworkAddress::Ipv6([
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ]))
        );

        let netbios = ipv4_udp(137, 137, &[], None, None);
        let discovery = discover(&ethernet(0x0800, &netbios)).ok_or("NetBIOS fingerprint")?;
        let identity = discovery.identity.ok_or("NetBIOS identity")?;
        assert_eq!(identity.role, IdentityRole::MulticastParticipant);
        assert_eq!(identity.address, Some(NetworkAddress::Ipv4([192, 0, 2, 1])));
        Ok(())
    }
}
