use l2_core::{EthernetFrame, FrameField};
use l2_discovery::{IpFamily, fragment_packet, fragment_transport};

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

fn ipv4(flags: u16, payload: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut bytes = vec![0x45, 0];
    bytes.extend_from_slice(
        &u16::try_from(20 + payload.len())
            .map_err(|_| "long fixture")?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&42_u16.to_be_bytes());
    bytes.extend_from_slice(&flags.to_be_bytes());
    bytes.extend_from_slice(&[64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2]);
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

#[test]
fn ipv4_fragments_ids_declared_lengths() -> Result<(), &'static str> {
    let bytes = ipv4(0x2002, b"abcdefgh")?;
    let fragment = fragment_packet(&ethernet(0x0800, &bytes)).ok_or("missing fragment")?;
    assert_eq!(fragment.family, IpFamily::V4);
    assert_eq!(fragment.identification, 42);
    assert_eq!(fragment.offset, 16);
    assert!(fragment.more);
    assert_eq!(fragment.payload, b"abcdefgh");
    assert_eq!(fragment.payload_offset, 20);
    assert_eq!(fragment.declared_payload_length, 8);
    assert!(fragment.captured_complete);
    Ok(())
}

#[test]
fn truncated_fragment_only_available_bytes() -> Result<(), &'static str> {
    let mut bytes = ipv4(0x2000, b"abcdefgh")?;
    bytes.truncate(23);
    let fragment = fragment_packet(&ethernet(0x0800, &bytes)).ok_or("missing partial fragment")?;
    assert_eq!(fragment.payload, b"abc");
    assert_eq!(fragment.declared_payload_length, 8);
    assert!(!fragment.captured_complete);
    Ok(())
}

#[test]
fn nonfragmented_ipv4_no_fragment_observation() -> Result<(), &'static str> {
    let bytes = ipv4(0, b"abcdefgh")?;
    assert!(fragment_packet(&ethernet(0x0800, &bytes)).is_none());
    Ok(())
}

#[test]
fn ipv6_offsets_fragment_extensions_literal() -> Result<(), &'static str> {
    let mut bytes = vec![0x60, 0, 0, 0, 0, 16, 44, 64];
    bytes.extend_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    bytes.extend_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    bytes.extend_from_slice(&[60, 0xa5, 0, 0x0f, 0, 0, 0, 42]);
    bytes.extend_from_slice(b"abcdefgh");
    let fragment = fragment_packet(&ethernet(0x86dd, &bytes)).ok_or("missing IPv6 fragment")?;
    assert_eq!(fragment.family, IpFamily::V6);
    assert_eq!(fragment.identification, 42);
    assert_eq!(fragment.protocol, 60);
    assert_eq!(fragment.offset, 8);
    assert!(fragment.more);
    assert_eq!(fragment.payload_offset, 48);
    assert_eq!(fragment.payload, b"abcdefgh");
    Ok(())
}

#[test]
fn reassembled_payload_canonical_transport_boundaries() -> Result<(), &'static str> {
    let bytes = [
        17, 0, 0, 0, 0, 0, 0, 0, 0x9c, 0x40, 0, 53, 0, 10, 0, 0, b'a', b'b',
    ];
    let transport = fragment_transport(IpFamily::V6, 60, &bytes).ok_or("missing UDP")?;
    assert_eq!(transport.ports, (40_000, 53));
    assert_eq!(transport.payload_offset, 16);
    assert_eq!(transport.payload, b"ab");
    assert!(fragment_transport(IpFamily::V6, 44, &bytes).is_none());
    Ok(())
}

#[test]
fn raw_fragment_payloads_keep_family_offsets_and_truncation() -> Result<(), &'static str> {
    use l2_discovery::fragment_packet_from_payload;

    let mut v4 = ipv4(0x2002, b"abcdefgh")?;
    let v4_fragment = fragment_packet_from_payload(0x0800, &v4).ok_or("missing IPv4 fragment")?;
    assert_eq!(
        (
            v4_fragment.family,
            v4_fragment.offset,
            v4_fragment.payload_offset
        ),
        (IpFamily::V4, 16, 20)
    );
    assert_eq!(v4_fragment.payload, b"abcdefgh");
    v4.truncate(23);
    let partial = fragment_packet_from_payload(0x0800, &v4).ok_or("missing partial fragment")?;
    assert_eq!(partial.payload, b"abc");
    assert!(!partial.captured_complete);

    let mut v6 = vec![0x60, 0, 0, 0, 0, 16, 44, 64];
    v6.extend_from_slice(&[0; 32]);
    v6.extend_from_slice(&[17, 0, 0, 9, 0, 0, 0, 42]);
    v6.extend_from_slice(b"abcdefgh");
    let v6_fragment = fragment_packet_from_payload(0x86dd, &v6).ok_or("missing IPv6 fragment")?;
    assert_eq!(
        (
            v6_fragment.family,
            v6_fragment.offset,
            v6_fragment.payload_offset
        ),
        (IpFamily::V6, 8, 48)
    );
    assert_eq!(v6_fragment.payload, b"abcdefgh");
    assert!(fragment_packet_from_payload(0x0806, &v6).is_none());
    assert!(fragment_packet_from_payload(0x86dd, v6.get(..47).ok_or("short fixture")?).is_none());
    Ok(())
}
