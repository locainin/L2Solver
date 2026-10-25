use super::support::{frame, metadata, report, run};
use l2_capture::CapturedFrame;
use l2_core::{EthernetFrame, FrameField, VlanTag};
use serde_json::json;
use std::error::Error;

#[test]
fn interface_vlan_without_pcp_identity() -> Result<(), Box<dyn Error>> {
    let vlan_7 = VlanTag {
        tpid: 0x8100,
        tci: 7,
    };
    let vlan_8 = VlanTag { tci: 8, ..vlan_7 };
    let priority_vlan_7 = VlanTag {
        tci: 0xe007,
        ..vlan_7
    };
    let mut reverse = frame(10, 0x10, b"XY", vec![vlan_7], 0)?.bytes().to_vec();
    // Swap IPv4 endpoints and TCP ports while retaining a valid bounded layout
    for (left, right) in [(30, 34), (31, 35), (32, 36), (33, 37), (42, 44), (43, 45)] {
        reverse.swap(left, right);
    }
    let original = u32::try_from(reverse.len())?;
    let reverse = CapturedFrame::new(reverse, metadata(0, original))?;
    let frames = [
        frame(10, 0x10, b"ab", vec![vlan_7], 0)?,
        frame(10, 0x10, b"XY", vec![vlan_8], 0)?,
        frame(10, 0x10, b"XY", vec![vlan_7], 1)?,
        reverse,
        frame(12, 0x10, b"cd", vec![priority_vlan_7], 0)?,
    ];
    let output = run(
        &frames,
        &["--packet", "1", "--length", "4", "--format", "json"],
    )?;
    assert!(
        output.status.success(),
        "exit={:?} report={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout)
    );
    let value = report(&output)?;
    assert_eq!(value.pointer("/matching_packets"), Some(&json!(2)));
    assert_eq!(value.pointer("/range/conflicting_bytes"), Some(&json!(0)));
    assert_eq!(
        value.pointer("/flow/scope/vlan_ids"),
        Some(&json!([[0x8100, 7]]))
    );
    assert_eq!(
        value.pointer("/range/observations/1/payload_frame_offset"),
        Some(&json!(66))
    );
    Ok(())
}

#[test]
fn unresolved_packet_blocks_complete_range() -> Result<(), Box<dyn Error>> {
    let good = frame(10, 0x10, b"ab", vec![], 0)?;
    let bytes = good
        .bytes()
        .get(..42)
        .ok_or("missing truncation boundary")?
        .to_vec();
    let truncated = CapturedFrame::new(bytes, good.metadata().clone())?;
    let output = run(
        &[good, truncated],
        &["--packet", "1", "--length", "2", "--format", "json"],
    )?;
    assert_eq!(output.status.code(), Some(3));
    let value = report(&output)?;
    assert_eq!(value.pointer("/unresolved_packets"), Some(&json!(1)));
    assert_eq!(value.pointer("/range/missing_bytes"), Some(&json!(0)));
    assert_eq!(value.pointer("/complete"), Some(&json!(false)));
    assert_eq!(
        value.pointer("/unresolved_sources/0/source/packet_index"),
        Some(&json!(2))
    );
    assert_eq!(
        value.pointer("/unresolved_sources/0/reason"),
        Some(&json!("truncated_capture"))
    );
    Ok(())
}

#[test]
fn unresolved_references_bounded_counts_continue() -> Result<(), Box<dyn Error>> {
    let good = frame(10, 0x10, b"ab", vec![], 0)?;
    let prefix = good
        .bytes()
        .get(..42)
        .ok_or("missing truncated header")?
        .to_vec();
    let truncated = CapturedFrame::new(prefix, good.metadata().clone())?;
    let mut frames = vec![good];
    frames.extend(std::iter::repeat_n(truncated, 130));
    let output = run(
        &frames,
        &["--packet", "1", "--length", "2", "--format", "json"],
    )?;
    assert_eq!(output.status.code(), Some(3));
    let value = report(&output)?;
    assert_eq!(value.pointer("/unresolved_packets"), Some(&json!(130)));
    let references = value
        .get("unresolved_sources")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing unresolved references")?;
    assert_eq!(references.len(), 128);
    assert_eq!(
        references
            .last()
            .and_then(|source| source.pointer("/source/packet_index")),
        Some(&json!(129))
    );
    Ok(())
}

#[test]
fn same_ip_cannot_fill_gap() -> Result<(), Box<dyn Error>> {
    let first = frame(10, 0x10, b"ab", vec![], 0)?;
    let mut bytes = frame(12, 0x10, b"cd", vec![], 0)?.bytes().to_vec();
    *bytes.get_mut(38).ok_or("missing TCP port byte")? ^= 1;
    let other_port = CapturedFrame::new(bytes, first.metadata().clone())?;
    let output = run(
        &[first, other_port],
        &["--packet", "1", "--length", "4", "--format", "json"],
    )?;
    assert_eq!(output.status.code(), Some(3));
    let value = report(&output)?;
    assert_eq!(value.pointer("/matching_packets"), Some(&json!(1)));
    assert_eq!(value.pointer("/range/missing_bytes"), Some(&json!(2)));
    Ok(())
}

#[test]
fn truncated_arp_not_tcp_range() -> Result<(), Box<dyn Error>> {
    let anchor = frame(10, 0x10, b"ab", vec![], 0)?;
    let mut bytes = anchor
        .bytes()
        .get(..22)
        .ok_or("missing Ethernet bytes")?
        .to_vec();
    bytes
        .get_mut(12..14)
        .ok_or("missing EtherType")?
        .copy_from_slice(&0x0806_u16.to_be_bytes());
    let truncated_arp = CapturedFrame::new(bytes, metadata(0, 60))?;

    let output = run(
        &[anchor, truncated_arp],
        &["--packet", "1", "--length", "2", "--format", "json"],
    )?;
    assert!(
        output.status.success(),
        "exit={:?} report={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout)
    );
    let value = report(&output)?;
    assert_eq!(value.pointer("/complete"), Some(&json!(true)));
    assert_eq!(value.pointer("/unresolved_packets"), Some(&json!(0)));
    assert_eq!(value.pointer("/range/observed_bytes"), Some(&json!(2)));
    Ok(())
}

#[test]
fn fragmented_udp_cannot_tcp_tuple() -> Result<(), Box<dyn Error>> {
    let anchor = frame(10, 0x10, b"a", vec![], 0)?;
    let udp_fragment = ipv4_fragment(17)?;
    let output = run(
        &[anchor, udp_fragment],
        &["--packet", "1", "--length", "1", "--format", "json"],
    )?;
    assert!(
        output.status.success(),
        "exit={:?} report={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout)
    );
    let value = report(&output)?;
    assert_eq!(value.pointer("/complete"), Some(&json!(true)));
    assert_eq!(value.pointer("/matching_packets"), Some(&json!(1)));
    assert_eq!(value.pointer("/unresolved_packets"), Some(&json!(0)));
    Ok(())
}

#[test]
fn truncated_udp_cannot_tcp_tuple() -> Result<(), Box<dyn Error>> {
    let anchor = frame(10, 0x10, b"a", vec![], 0)?;
    let udp_packet = truncated_ipv4_packet(17)?;
    let output = run(
        &[anchor, udp_packet],
        &["--packet", "1", "--length", "1", "--format", "json"],
    )?;
    assert!(
        output.status.success(),
        "exit={:?} report={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout)
    );
    let value = report(&output)?;
    assert_eq!(value.pointer("/complete"), Some(&json!(true)));
    assert_eq!(value.pointer("/matching_packets"), Some(&json!(1)));
    assert_eq!(value.pointer("/unresolved_packets"), Some(&json!(0)));
    Ok(())
}

#[test]
fn ipv6_fragment_cannot_tcp_tuple() -> Result<(), Box<dyn Error>> {
    let anchor = ipv6_tcp_frame(10, b"a")?;
    let fragment = ipv6_udp_fragment()?;
    let output = run(
        &[anchor, fragment],
        &["--packet", "1", "--length", "1", "--format", "json"],
    )?;
    assert!(
        output.status.success(),
        "exit={:?} report={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout)
    );
    let value = report(&output)?;
    assert_eq!(value.pointer("/complete"), Some(&json!(true)));
    assert_eq!(value.pointer("/matching_packets"), Some(&json!(1)));
    assert_eq!(value.pointer("/unresolved_packets"), Some(&json!(0)));
    Ok(())
}

#[test]
fn fragmented_tcp_remains_unresolved() -> Result<(), Box<dyn Error>> {
    let anchor = frame(10, 0x10, b"a", vec![], 0)?;
    let tcp_fragment = ipv4_fragment(6)?;
    let output = run(
        &[anchor, tcp_fragment],
        &["--packet", "1", "--length", "1", "--format", "json"],
    )?;
    assert_eq!(output.status.code(), Some(3));
    let value = report(&output)?;
    assert_eq!(value.pointer("/complete"), Some(&json!(false)));
    assert_eq!(value.pointer("/unresolved_packets"), Some(&json!(1)));
    assert_eq!(
        value.pointer("/unresolved_sources/0/reason"),
        Some(&json!("ip_fragment"))
    );
    Ok(())
}

#[test]
fn ipv6_fragment_extension_remains_unresolved() -> Result<(), Box<dyn Error>> {
    let anchor = ipv6_tcp_frame(10, b"a")?;
    let fragment = ipv6_fragment_with_destination_options()?;
    let output = run(
        &[anchor, fragment],
        &["--packet", "1", "--length", "1", "--format", "json"],
    )?;
    assert_eq!(output.status.code(), Some(3));
    let value = report(&output)?;
    assert_eq!(value.pointer("/complete"), Some(&json!(false)));
    assert_eq!(value.pointer("/unresolved_packets"), Some(&json!(1)));
    assert_eq!(
        value.pointer("/unresolved_sources/0/reason"),
        Some(&json!("ip_fragment"))
    );
    Ok(())
}

fn ipv4_fragment(protocol: u8) -> Result<CapturedFrame, Box<dyn Error>> {
    let mut bytes = frame(10, 0x10, b"", vec![], 0)?.bytes().to_vec();
    let ip = 14;
    *bytes.get_mut(ip + 9).ok_or("missing IPv4 protocol")? = protocol;
    bytes
        .get_mut(ip + 6..ip + 8)
        .ok_or("missing IPv4 fragment flags")?
        .copy_from_slice(&0x2000_u16.to_be_bytes());
    if protocol == 17 {
        let udp = ip + 24;
        bytes
            .get_mut(udp..udp + 8)
            .ok_or("missing UDP fragment header")?
            .copy_from_slice(&[0x9c, 0x40, 0x9c, 0x41, 0, 32, 0, 0]);
        bytes
            .get_mut(udp + 8..udp + 24)
            .ok_or("missing UDP fragment payload")?
            .fill(0);
    }
    // The fragment body is 24 bytes, a full multiple of eight
    let original_length = u32::try_from(bytes.len())?;
    Ok(CapturedFrame::new(bytes, metadata(0, original_length))?)
}

fn truncated_ipv4_packet(protocol: u8) -> Result<CapturedFrame, Box<dyn Error>> {
    let mut bytes = frame(10, 0x10, b"", vec![], 0)?.bytes().to_vec();
    let original_length = u32::try_from(bytes.len())?;
    let ip = 14;
    *bytes.get_mut(ip + 9).ok_or("missing IPv4 protocol")? = protocol;
    bytes.truncate(ip + 24);
    Ok(CapturedFrame::new(bytes, metadata(0, original_length))?)
}

fn ipv6_tcp_frame(sequence: u32, payload: &[u8]) -> Result<CapturedFrame, Box<dyn Error>> {
    let tcp = tcp_bytes(sequence, payload);
    let ip = ipv6_packet(6, &tcp)?;
    ethernet_ipv6(&ip)
}

fn ipv6_fragment_with_destination_options() -> Result<CapturedFrame, Box<dyn Error>> {
    let mut following_header = vec![6, 0, 0, 0, 0, 0, 0, 0];
    following_header.extend_from_slice(&tcp_bytes(99, b"data"));
    ipv6_fragment(60, &following_header)
}

fn ipv6_udp_fragment() -> Result<CapturedFrame, Box<dyn Error>> {
    let mut udp = vec![0x9c, 0x40, 0x9c, 0x41, 0, 32, 0, 0];
    udp.extend_from_slice(&[0; 16]);
    ipv6_fragment(17, &udp)
}

fn ipv6_fragment(next_header: u8, fragment_body: &[u8]) -> Result<CapturedFrame, Box<dyn Error>> {
    let mut fragment_payload = vec![next_header, 0];
    fragment_payload.extend_from_slice(&1_u16.to_be_bytes());
    fragment_payload.extend_from_slice(&0x1234_5678_u32.to_be_bytes());
    fragment_payload.extend_from_slice(fragment_body);
    let ip = ipv6_packet(44, &fragment_payload)?;
    ethernet_ipv6(&ip)
}

fn tcp_bytes(sequence: u32, payload: &[u8]) -> Vec<u8> {
    let mut tcp = Vec::new();
    tcp.extend_from_slice(&40_000_u16.to_be_bytes());
    tcp.extend_from_slice(&40_001_u16.to_be_bytes());
    tcp.extend_from_slice(&sequence.to_be_bytes());
    tcp.extend_from_slice(&0_u32.to_be_bytes());
    tcp.extend_from_slice(&[0x50, 0x10, 0x20, 0, 0, 0, 0, 0]);
    tcp.extend_from_slice(payload);
    tcp
}

fn ipv6_packet(next_header: u8, payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut ip = vec![0x60, 0, 0, 0];
    ip.extend_from_slice(&u16::try_from(payload.len())?.to_be_bytes());
    ip.extend_from_slice(&[next_header, 64]);
    ip.extend_from_slice(&ipv6_source());
    ip.extend_from_slice(&ipv6_destination());
    ip.extend_from_slice(payload);
    Ok(ip)
}

fn ethernet_ipv6(ip: &[u8]) -> Result<CapturedFrame, Box<dyn Error>> {
    let ethernet = EthernetFrame {
        destination: [2, 0, 0, 0, 0, 2],
        source: [2, 0, 0, 0, 0, 1],
        vlan_tags: vec![],
        payload: ip,
        padding: &[],
        field: FrameField::EtherType(0x86dd),
    };
    let mut bytes = vec![0; l2_core::encoded_len(&ethernet)?];
    l2_core::encode(&ethernet, &mut bytes)?;
    let original_length = u32::try_from(bytes.len())?;
    Ok(CapturedFrame::new(bytes, metadata(0, original_length))?)
}

const fn ipv6_source() -> [u8; 16] {
    [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
}

const fn ipv6_destination() -> [u8; 16] {
    [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]
}
