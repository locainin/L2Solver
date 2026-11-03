use crate::cooked_analysis;
use l2_capture::{CaptureMetadata, CapturedFrame};
use l2_workbench::{
    evidence::Case,
    query::{Selector, select},
};
use std::{error::Error, net::Ipv6Addr};

#[test]
fn cooked_tcp_packet_filters_match_the_original_frame_bytes() -> Result<(), Box<dyn Error>> {
    for version in [113, 276] {
        let result = cooked_analysis::case(vec![cooked_analysis::frame(version, 37, 9000, 0x18)?])?;
        assert!(result.complete);
        let selector = Selector::parse(&[
            "kind=packet",
            "src=192.0.2.1/32",
            "dst=192.0.2.2/32",
            "proto=tcp",
            "sport=40000",
            "dport=9000",
            "field.ip.proto=6",
        ])?;
        let matches = select(&result.case, &selector);
        assert_eq!(matches.len(), 1, "link type {version}");
        assert_eq!(
            matches
                .first()
                .ok_or("packet match missing")?
                .packet_numbers,
            [1]
        );
    }
    Ok(())
}

#[test]
fn cooked_ipv6_udp_filters_use_the_network_payload() -> Result<(), Box<dyn Error>> {
    for version in [113, 276] {
        let original = cooked_analysis::frame(version, 37, 9000, 0x18)?;
        let header_len = if version == 113 { 16 } else { 20 };
        let mut bytes = original
            .bytes()
            .get(..header_len)
            .ok_or("short header")?
            .to_vec();
        let protocol_offset = if version == 113 { 14 } else { 0 };
        bytes
            .get_mut(protocol_offset..protocol_offset + 2)
            .ok_or("missing protocol field")?
            .copy_from_slice(&0x86dd_u16.to_be_bytes());
        bytes.extend_from_slice(&[0x60, 0, 0, 0, 0, 12, 17, 64]);
        bytes.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>()?.octets());
        bytes.extend_from_slice(&"2001:db8::2".parse::<Ipv6Addr>()?.octets());
        bytes.extend_from_slice(&[0xcf, 0x08, 0, 53, 0, 12, 0, 0, b'd', b'a', b't', b'a']);
        let metadata =
            CaptureMetadata::unknown(original.metadata().interface(), u32::try_from(bytes.len())?)
                .with_link_type(original.metadata().link_type());
        let frame = CapturedFrame::new(bytes, metadata)?;
        let result = cooked_analysis::case(vec![frame])?;
        let selector = Selector::parse(&[
            "kind=packet",
            "src=2001:db8::1/128",
            "dst=2001:db8::2/128",
            "proto=udp",
            "sport=53000",
            "dport=53",
            "field.ipv6.nxt=17",
        ])?;
        assert_eq!(
            select(&result.case, &selector).len(),
            1,
            "link type {version}"
        );
    }
    Ok(())
}

#[test]
fn cooked_filters_use_bytes_instead_of_saved_address_claims() -> Result<(), Box<dyn Error>> {
    let frame = cooked_analysis::frame(276, 37, 9000, 0x18)?;
    let mut case = Case::new();
    let blob = case.add_blob(frame.bytes())?;
    case.add_node(
        "packet",
        Some(&blob),
        Vec::new(),
        serde_json::json!({
            "record": 1,
            "link_type": 276,
            "source_ip": "203.0.113.77",
            "destination_ip": "203.0.113.88",
            "protocol": 17,
        }),
    )?;
    let actual = Selector::parse(&["kind=packet", "src=192.0.2.1", "proto=tcp", "dport=9000"])?;
    let claimed = Selector::parse(&["kind=packet", "src=203.0.113.77"])?;
    assert_eq!(select(&case, &actual).len(), 1);
    assert_eq!(select(&case, &claimed).len(), 0);
    Ok(())
}

#[test]
fn cooked_ip_header_remains_searchable_when_transport_bytes_are_truncated()
-> Result<(), Box<dyn Error>> {
    for version in [113, 276] {
        let original = cooked_analysis::frame(version, 37, 9000, 0x18)?;
        let header_len = if version == 113 { 16 } else { 20 };
        let bytes = original
            .bytes()
            .get(..header_len + 20)
            .ok_or("IP header missing")?
            .to_vec();
        let frame = CapturedFrame::new(bytes, original.metadata().clone())?;
        let result = cooked_analysis::case(vec![frame])?;
        let header = Selector::parse(&["kind=packet", "src=192.0.2.1", "proto=tcp"])?;
        let transport = Selector::parse(&["kind=packet", "dport=9000"])?;
        assert_eq!(
            select(&result.case, &header).len(),
            1,
            "link type {version}"
        );
        assert!(
            select(&result.case, &transport).is_empty(),
            "link type {version}"
        );
    }
    Ok(())
}

#[test]
fn opaque_and_truncated_cooked_frames_do_not_match_ip_filters() -> Result<(), Box<dyn Error>> {
    for version in [113, 276] {
        let original = cooked_analysis::frame(version, 37, 9000, 0x18)?;
        let mut opaque = original.bytes().to_vec();
        let protocol_offset = if version == 113 { 14 } else { 0 };
        opaque
            .get_mut(protocol_offset..protocol_offset + 2)
            .ok_or("missing protocol field")?
            .copy_from_slice(&0x8100_u16.to_be_bytes());
        let opaque = CapturedFrame::new(opaque, original.metadata().clone())?;
        let truncated = CapturedFrame::new(
            original.bytes().get(..8).ok_or("short fixture")?.to_vec(),
            original.metadata().clone(),
        )?;
        let result = cooked_analysis::case(vec![opaque, truncated])?;
        let selector = Selector::parse(&["kind=packet", "src=192.0.2.1"])?;
        assert!(
            select(&result.case, &selector).is_empty(),
            "link type {version}"
        );
    }
    Ok(())
}
