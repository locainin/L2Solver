use l2_core::{EthernetFrame, FrameField};
use l2_discovery::{NetworkAddress, TransportHeader, ip_header, ip_packet};

const fn ethernet(field: u16, payload: &[u8]) -> EthernetFrame<'_> {
    EthernetFrame {
        destination: [2, 0, 0, 0, 0, 2],
        source: [2, 0, 0, 0, 0, 1],
        vlan_tags: Vec::new(),
        payload,
        padding: &[],
        field: FrameField::EtherType(field),
    }
}

fn ipv4(protocol: u8, body: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x45, 0];
    packet.extend_from_slice(
        &u16::try_from(20 + body.len())
            .unwrap_or_default()
            .to_be_bytes(),
    );
    packet.extend_from_slice(&[0, 1, 0, 0, 64, protocol, 0, 0]);
    packet.extend_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
    packet.extend_from_slice(body);
    packet
}

fn ipv6(protocol: u8, body: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x60, 0, 0, 0];
    packet.extend_from_slice(&u16::try_from(body.len()).unwrap_or_default().to_be_bytes());
    packet.extend_from_slice(&[protocol, 64]);
    packet.extend_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    packet.extend_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    packet.extend_from_slice(body);
    packet
}

fn ipv6_fragment(next_header: u8, reserved: u8, flags_and_offset: u16, body: &[u8]) -> Vec<u8> {
    let mut fragment = vec![next_header, reserved];
    fragment.extend_from_slice(&flags_and_offset.to_be_bytes());
    fragment.extend_from_slice(&[0; 4]);
    fragment.extend_from_slice(body);
    ipv6(44, &fragment)
}

#[test]
fn ordinary_udp_addresses_ports_trailer() -> Result<(), &'static str> {
    let mut bytes = ipv4(17, &[0x30, 0x39, 0x01, 0xbb, 0, 8, 0, 0]);
    bytes.extend_from_slice(&[0, 7, 0]);
    let frame = ethernet(0x0800, &bytes);
    let packet = ip_packet(&frame).ok_or("missing IP packet")?;
    assert_eq!(packet.source, NetworkAddress::Ipv4([192, 0, 2, 1]));
    assert_eq!(packet.destination, NetworkAddress::Ipv4([192, 0, 2, 2]));
    assert_eq!(packet.protocol, 17);
    assert_eq!(packet.ports(), Some((12345, 443)));
    assert_eq!(packet.declared_len, 28);
    assert_eq!(packet.trailing_bytes, [0, 7, 0]);
    assert!(!packet.fragmented);
    let transport = packet.transport.ok_or("missing UDP envelope")?;
    assert_eq!(transport.ports, (12345, 443));
    assert_eq!(transport.header, TransportHeader::Udp);
    assert_eq!(transport.payload_offset, packet.declared_len);
    assert_eq!(transport.payload, []);
    assert_eq!(transport.trailing_bytes, []);
    Ok(())
}

#[test]
fn udp_payload_inside_ip_envelope() -> Result<(), &'static str> {
    let mut body = vec![0x30, 0x39, 0x01, 0xbb, 0, 10, 0, 0];
    body.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
    let mut bytes = ipv4(17, &body);
    bytes.push(0xdd);
    let packet = ip_packet(&ethernet(0x0800, &bytes)).ok_or("missing UDP packet")?;
    let transport = packet.transport.ok_or("missing UDP envelope")?;

    assert_eq!(transport.payload_offset, 28);
    assert_eq!(transport.payload, [0xaa, 0xbb]);
    assert_eq!(transport.trailing_bytes, [0xcc]);
    assert_eq!(packet.trailing_bytes, [0xdd]);
    assert_eq!(
        transport.payload_offset + transport.payload.len() + transport.trailing_bytes.len(),
        packet.declared_len
    );
    Ok(())
}

#[test]
fn empty_ipv4_within_declared_envelope() -> Result<(), &'static str> {
    let bytes = ipv4(59, &[]);
    let frame = ethernet(0x0800, &bytes);
    let packet = ip_packet(&frame).ok_or("missing header-only IPv4 packet")?;
    assert_eq!(packet.declared_len, 20);
    assert_eq!(packet.trailing_bytes, []);
    assert_eq!(packet.ports(), None);
    assert!(packet.transport.is_none());
    Ok(())
}

#[test]
fn ipv4_options_not_tcp_port() -> Result<(), &'static str> {
    let mut tcp = vec![0x30, 0x39, 0x01, 0xbb];
    tcp.extend_from_slice(&[0; 8]);
    tcp.extend_from_slice(&[0x50, 0x02, 0, 0, 0, 0, 0, 0]);
    let mut bytes = ipv4(6, &tcp);
    bytes.splice(20..20, [0x99, 0x88, 0x77, 0x66]);
    *bytes.first_mut().ok_or("short IPv4 fixture")? = 0x46;
    bytes
        .get_mut(2..4)
        .ok_or("short IPv4 fixture")?
        .copy_from_slice(&44_u16.to_be_bytes());
    let frame = ethernet(0x0800, &bytes);
    let packet = ip_packet(&frame).ok_or("missing TCP envelope")?;
    assert_eq!(packet.ports(), Some((12345, 443)));
    assert_eq!(packet.declared_len, 44);
    Ok(())
}

#[test]
fn tcp_fields_ip_options() -> Result<(), &'static str> {
    let mut tcp = vec![0x30, 0x39, 0x01, 0xbb];
    tcp.extend_from_slice(&0x1234_5678_u32.to_be_bytes());
    tcp.extend_from_slice(&0x9abc_def0_u32.to_be_bytes());
    tcp.extend_from_slice(&[0x60, 0x12, 0, 0, 0, 0, 0, 0]);
    tcp.extend_from_slice(&[1, 1, 1, 1]);
    tcp.extend_from_slice(&[0xde, 0xad]);
    let mut bytes = ipv4(6, &tcp);
    bytes.splice(20..20, [0x99, 0x88, 0x77, 0x66]);
    *bytes.first_mut().ok_or("short IPv4 fixture")? = 0x46;
    bytes
        .get_mut(2..4)
        .ok_or("short IPv4 fixture")?
        .copy_from_slice(&50_u16.to_be_bytes());
    let packet = ip_packet(&ethernet(0x0800, &bytes)).ok_or("missing TCP packet")?;
    let transport = packet.transport.ok_or("missing TCP envelope")?;

    assert_eq!(transport.ports, (12345, 443));
    assert_eq!(
        transport.header,
        TransportHeader::Tcp {
            sequence: 0x1234_5678,
            acknowledgement: 0x9abc_def0,
            flags: 0x12,
        }
    );
    assert_eq!(transport.payload_offset, 48);
    assert_eq!(transport.payload, [0xde, 0xad]);
    assert_eq!(transport.trailing_bytes, []);
    assert_eq!(
        transport.payload_offset + transport.payload.len(),
        packet.declared_len
    );
    Ok(())
}

#[test]
fn invalid_or_truncated_ip_rejected() {
    let valid = ipv4(17, &[0, 1, 0, 2, 0, 8, 0, 0]);
    for length in 0..valid.len() {
        assert!(ip_packet(&ethernet(0x0800, valid.get(..length).unwrap_or_default())).is_none());
    }
    for (offset, value) in [(0, 0x44), (0, 0x65), (3, 19)] {
        let mut bytes = valid.clone();
        if let Some(byte) = bytes.get_mut(offset) {
            *byte = value;
        }
        assert!(ip_packet(&ethernet(0x0800, &bytes)).is_none());
    }
}

#[test]
fn header_facts_without_exposing_payload() -> Result<(), &'static str> {
    for (ethertype, bytes, header_length) in [
        (0x0800, ipv4(17, &[0; 8]), 20),
        (0x86dd, ipv6(17, &[0; 8]), 40),
    ] {
        let prefix = bytes.get(..header_length).ok_or("short IP fixture")?;
        let frame = ethernet(ethertype, prefix);
        let header = ip_header(&frame).ok_or("missing complete header facts")?;
        assert_eq!(header.protocol, 17);
        assert_eq!(header.header_len, header_length);
        assert_eq!(header.total_len, header_length + 8);
        assert!(!header.fragmented);
        assert!(ip_packet(&frame).is_none());
        for length in 0..header_length {
            let truncated = prefix.get(..length).ok_or("invalid header prefix")?;
            assert!(ip_header(&ethernet(ethertype, truncated)).is_none());
        }
    }
    Ok(())
}

#[test]
fn complete_ipv6_missing_transport_body() -> Result<(), &'static str> {
    for kind in [0, 43, 60] {
        let complete = ipv6(kind, &[17, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 8, 0, 0]);
        let prefix = complete.get(..48).ok_or("missing extension fixture")?;
        let frame = ethernet(0x86dd, prefix);
        let header = ip_header(&frame).ok_or("missing complete extension facts")?;
        assert_eq!(
            (header.protocol, header.header_len, header.total_len),
            (17, 48, 56)
        );
        assert!(ip_packet(&frame).is_none());
        for length in 40..48 {
            let truncated = prefix.get(..length).ok_or("bad extension prefix")?;
            assert!(ip_header(&ethernet(0x86dd, truncated)).is_none());
        }
    }
    Ok(())
}

#[test]
fn ipv4_reserved_malformed_base_header() -> Result<(), &'static str> {
    let mut bytes = ipv4(17, &[0, 1, 0, 2, 0, 8, 0, 0]);
    bytes
        .get_mut(6..8)
        .ok_or("short IPv4 fixture")?
        .copy_from_slice(&0x8000_u16.to_be_bytes());

    assert!(ip_packet(&ethernet(0x0800, &bytes)).is_none());
    Ok(())
}

#[test]
fn fragments_not_claim_transport_ports() -> Result<(), &'static str> {
    for flags in [0x2000_u16, 0x0001, 0x2001] {
        let mut bytes = ipv4(17, &[0, 1, 0, 2, 0, 8, 0, 0]);
        bytes
            .get_mut(6..8)
            .ok_or("short IPv4 fixture")?
            .copy_from_slice(&flags.to_be_bytes());
        let frame = ethernet(0x0800, &bytes);
        let packet = ip_packet(&frame).ok_or("missing fragment")?;
        assert!(packet.fragmented);
        assert_eq!(packet.ports(), None);
        assert!(packet.transport.is_none());
    }
    Ok(())
}

#[test]
fn ipv6_walks_extensions_reading_udp() -> Result<(), &'static str> {
    let bytes = ipv6(0, &[17, 0, 0, 0, 0, 0, 0, 0, 0x30, 0x39, 0, 53, 0, 8, 0, 0]);
    let frame = ethernet(0x86dd, &bytes);
    let packet = ip_packet(&frame).ok_or("missing IPv6 packet")?;
    assert_eq!(packet.protocol, 17);
    assert_eq!(packet.ports(), Some((12345, 53)));
    assert!(matches!(packet.source, NetworkAddress::Ipv6(_)));
    Ok(())
}

#[test]
fn noninitial_ipv6_body_not_extension() -> Result<(), &'static str> {
    let bytes = ipv6(44, &[60, 0, 0, 9, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff]);
    let frame = ethernet(0x86dd, &bytes);
    let packet = ip_packet(&frame).ok_or("missing IPv6 fragment")?;
    assert_eq!(packet.protocol, 60);
    assert_eq!(packet.ports(), None);
    assert!(packet.transport.is_none());
    assert!(packet.fragmented);
    Ok(())
}

#[test]
fn atomic_ipv6_complete_transport_headers() -> Result<(), &'static str> {
    let bytes = ipv6(
        44,
        &[17, 0, 0, 0, 0, 0, 0, 1, 0x30, 0x39, 0, 53, 0, 8, 0, 0],
    );
    let frame = ethernet(0x86dd, &bytes);
    let packet = ip_packet(&frame).ok_or("missing atomic fragment")?;
    assert_eq!(packet.ports(), Some((12345, 53)));
    assert!(!packet.fragmented);
    Ok(())
}

#[test]
fn atomic_ipv6_fragment_excludes_padding() -> Result<(), &'static str> {
    let udp = [0x30, 0x39, 0, 53, 0, 10, 0, 0, 0xde, 0xad];
    let mut bytes = ipv6_fragment(17, 0xa5, 0x0006, &udp);
    bytes.extend_from_slice(&[0xee, 0]);
    let packet = ip_packet(&ethernet(0x86dd, &bytes)).ok_or("missing atomic IPv6 fragment")?;
    let transport = packet.transport.ok_or("missing atomic UDP envelope")?;

    assert!(!packet.fragmented);
    assert_eq!(packet.declared_len, 58);
    assert_eq!(packet.trailing_bytes, [0xee, 0]);
    assert_eq!(transport.ports, (12345, 53));
    assert_eq!(transport.payload_offset, 56);
    assert_eq!(transport.payload, [0xde, 0xad]);
    assert_eq!(transport.trailing_bytes, []);
    assert_eq!(
        transport.payload_offset + transport.payload.len() + transport.trailing_bytes.len(),
        packet.declared_len
    );
    assert_eq!(
        packet.declared_len + packet.trailing_bytes.len(),
        bytes.len()
    );

    for flags_and_offset in [0x0007, 0x000e, 0x000f] {
        let fragment_bytes = ipv6_fragment(17, 0xa5, flags_and_offset, &udp[..8]);
        let fragment = ip_packet(&ethernet(0x86dd, &fragment_bytes))
            .ok_or("missing fragmented IPv6 packet")?;

        assert!(
            fragment.fragmented,
            "fragment field {flags_and_offset:#06x}"
        );
        assert_eq!(fragment.declared_len, 56);
        assert!(fragment.transport.is_none());
    }
    Ok(())
}

#[test]
fn ipv6_truncation_overlong_extensions_rejected() {
    let valid = ipv6(0, &[17, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 8, 0, 0]);
    for length in 0..valid.len() {
        assert!(ip_packet(&ethernet(0x86dd, valid.get(..length).unwrap_or_default())).is_none());
    }
    // Captured padding cannot satisfy an extension beyond the declared payload
    let mut bytes = ipv6(0, &[59, 1, 0, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(&[0; 8]);
    assert!(ip_packet(&ethernet(0x86dd, &bytes)).is_none());
}

#[test]
fn ipv6_jumbo_not_guessed_padding() {
    let mut bytes = ipv6(0, &[]);
    bytes.extend_from_slice(&[59, 0, 0xc2, 4, 0, 1, 0, 0]);
    assert!(ip_packet(&ethernet(0x86dd, &bytes)).is_none());
    assert!(ip_packet(&ethernet(0x86dd, &ipv6(59, &[]))).is_some());
}

#[test]
fn invalid_transports_leave_ports_unknown() -> Result<(), &'static str> {
    let mut oversized_tcp_header = vec![0; 20];
    *oversized_tcp_header
        .get_mut(12)
        .ok_or("short TCP fixture")? = 0x60;
    for (protocol, body) in [
        (17, vec![0, 1, 0, 2, 0, 7, 0, 0]),
        (17, vec![0, 1, 0, 2, 0, 9, 0, 0]),
        (6, vec![0; 20]),
        (6, oversized_tcp_header),
    ] {
        let bytes = ipv4(protocol, &body);
        let frame = ethernet(0x0800, &bytes);
        let packet = ip_packet(&frame).ok_or("missing IP packet")?;
        assert_eq!(packet.ports(), None);
        assert!(packet.transport.is_none());
    }
    Ok(())
}

#[test]
fn extension_walk_hard_limit() {
    let mut body = vec![0; 8 * 9];
    if let Some(last) = body.get_mut(64) {
        *last = 59;
    }
    assert!(ip_packet(&ethernet(0x86dd, &ipv6(0, &body))).is_none());
    // Exactly eight supported extension headers fit the configured walk boundary
    let mut allowed = vec![0; 8 * 8];
    if let Some(last) = allowed.get_mut(56) {
        *last = 59;
    }
    assert!(ip_packet(&ethernet(0x86dd, &ipv6(0, &allowed))).is_some());
}

#[test]
fn raw_ip_payloads_expose_udp_tcp_and_reject_invalid_bounds() -> Result<(), &'static str> {
    use l2_discovery::{ip_header_from_payload, ip_packet_from_payload};

    let udp = [0x30, 0x39, 0, 53, 0, 10, 0, 0, 0xaa, 0xbb];
    let mut tcp = vec![0x30, 0x39, 0x01, 0xbb];
    tcp.extend_from_slice(&[0; 8]);
    tcp.extend_from_slice(&[0x50, 0x02, 0, 0, 0, 0, 0, 0, 0xcc]);
    for (ether_type, bytes, expected_protocol, expected_offset, expected_payload) in [
        (0x0800, ipv4(17, &udp), 17, 28, &[0xaa, 0xbb][..]),
        (0x86dd, ipv6(17, &udp), 17, 48, &[0xaa, 0xbb][..]),
        (0x0800, ipv4(6, &tcp), 6, 40, &[0xcc][..]),
        (0x86dd, ipv6(6, &tcp), 6, 60, &[0xcc][..]),
    ] {
        let header = ip_header_from_payload(ether_type, &bytes).ok_or("missing IP header")?;
        assert_eq!(header.protocol, expected_protocol);
        let packet = ip_packet_from_payload(ether_type, &bytes).ok_or("missing IP packet")?;
        let transport = packet.transport.ok_or("missing transport")?;
        assert_eq!(transport.ports.0, 12345);
        assert_eq!(transport.payload_offset, expected_offset);
        assert_eq!(transport.payload, expected_payload);
        assert!(
            ip_packet_from_payload(
                ether_type,
                bytes.get(..bytes.len() - 1).ok_or("short fixture")?
            )
            .is_none()
        );
    }
    assert!(ip_header_from_payload(0x0806, &ipv4(17, &udp)).is_none());
    assert!(ip_packet_from_payload(0x86dd, &ipv4(17, &udp)).is_none());
    let mut invalid = ipv4(17, &udp);
    *invalid.get_mut(3).ok_or("short fixture")? = 19;
    assert!(ip_header_from_payload(0x0800, &invalid).is_none());
    Ok(())
}
