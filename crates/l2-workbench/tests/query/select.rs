use crate::behavior_support::{PacketSpec, case_with_packets, tcp_frame, udp_frame};
use l2_workbench::query::{Selector, select};
use std::error::Error;

#[test]
fn packet_filters_supported_evidence_nodes() -> Result<(), Box<dyn Error>> {
    let mut case = case_with_packets(vec![
        PacketSpec::new(tcp_frame(
            [192, 0, 2, 10],
            [198, 51, 100, 20],
            40_000,
            443,
            0x02,
        ))
        .with_ticks(1),
        PacketSpec::new(tcp_frame(
            [192, 0, 2, 10],
            [198, 51, 100, 21],
            40_001,
            80,
            0x02,
        )),
    ])?;
    let packet = case.nodes().first().ok_or("packet node missing")?.id;
    let evidence = case.add_node("connection_note", None, Vec::new(), serde_json::json!({}))?;
    case.add_edge(l2_workbench::evidence::Edge {
        from: packet,
        to: evidence,
        relation: "supports".to_owned(),
        status: l2_workbench::evidence::EvidenceStatus::Observed,
        reason: "one retained packet supports this generic note".to_owned(),
    })?;

    let selector = Selector::parse(&[
        "dst=198.51.100.20/32",
        "proto=tcp",
        "dport=443",
        "packet=1..1",
    ])?;
    let matches = select(&case, &selector);

    assert!(matches.iter().any(|item| item.node_id == packet));
    assert!(matches.iter().any(|item| item.node_id == evidence));
    assert_eq!(matches.len(), 2);
    let support = matches
        .iter()
        .find(|item| item.node_id == evidence)
        .ok_or("supported evidence node missing")?;
    assert_eq!(support.source_ranges.len(), 1);
    assert_eq!(
        support.source_ranges.first().map(|range| range.packet),
        Some(Some(1))
    );
    Ok(())
}

#[test]
fn status_kind_without_other_packets() -> Result<(), Box<dyn Error>> {
    let case = case_with_packets(vec![
        PacketSpec::new(tcp_frame(
            [192, 0, 2, 10],
            [198, 51, 100, 20],
            40_000,
            443,
            0x02,
        ))
        .with_scope(2, vec![37]),
        PacketSpec::new(tcp_frame(
            [192, 0, 2, 10],
            [198, 51, 100, 21],
            40_001,
            443,
            0x02,
        ))
        .with_scope(3, vec![38]),
    ])?;
    let selector = Selector::parse(&[
        "src=192.0.2.0/24",
        "interface=0:2",
        "vlan=37",
        "kind=packet",
        "status=hypothesis",
    ])?;

    assert!(select(&case, &selector).is_empty());

    let selector = Selector::parse(&[
        "src=192.0.2.0/24",
        "interface=0:2",
        "vlan=37",
        "kind=packet",
    ])?;
    assert_eq!(select(&case, &selector).len(), 1);
    Ok(())
}

#[test]
fn raw_packet_unverified_address_details() -> Result<(), Box<dyn Error>> {
    let mut case = case_with_packets(vec![PacketSpec::new(tcp_frame(
        [192, 0, 2, 10],
        [198, 51, 100, 20],
        40_000,
        443,
        0x02,
    ))])?;
    let bytes = tcp_frame([192, 0, 2, 11], [198, 51, 100, 21], 40_001, 80, 0x02);
    let blob = case.add_blob(&bytes)?;
    case.add_node(
        "packet",
        Some(&blob),
        Vec::new(),
        serde_json::json!({
            "record": 100,
            "link_type": 1,
            "source_ip": "192.0.2.99",
            "destination_ip": "198.51.100.99",
            "protocol": 17,
        }),
    )?;

    let selector = Selector::parse(&["dst=198.51.100.21/32", "proto=tcp", "packet=100..100"])?;
    let matches = select(&case, &selector);

    let selected = matches.first().ok_or("matching packet was not selected")?;
    assert_eq!(matches.len(), 1);
    assert_eq!(selected.packet_numbers, [100]);
    Ok(())
}

#[test]
fn non_ethernet_types_not_ethernet() -> Result<(), Box<dyn Error>> {
    let mut case = l2_workbench::evidence::Case::new();
    let bytes = tcp_frame([192, 0, 2, 10], [198, 51, 100, 20], 40_000, 443, 0x02);
    let blob = case.add_blob(&bytes)?;
    case.add_node(
        "packet",
        Some(&blob),
        Vec::new(),
        serde_json::json!({"record":1,"link_type":999}),
    )?;
    let selector = Selector::parse(&["dst=198.51.100.20/32", "proto=tcp"])?;

    let matches = select(&case, &selector);

    assert!(matches.is_empty());
    Ok(())
}

#[test]
fn vlan_filters_tags_auxiliary_metadata() -> Result<(), Box<dyn Error>> {
    let mut frame = tcp_frame([192, 0, 2, 10], [198, 51, 100, 20], 40_000, 443, 0x02);
    frame.splice(12..14, [0x81, 0x00, 0x00, 0x05, 0x08, 0x00]);
    let mut case = l2_workbench::evidence::Case::new();
    let blob = case.add_blob(&frame)?;
    case.add_node(
        "packet",
        Some(&blob),
        Vec::new(),
        serde_json::json!({
            "record": 1,
            "link_type": 1,
            "scope": {
                "vlan_ids": [[33024, 20]],
                "vlan_aux": [33024, 7],
            },
        }),
    )?;

    let forged_scope = Selector::parse(&["vlan=20"])?;
    let wire_tag = Selector::parse(&["vlan=5"])?;
    let auxiliary_tag = Selector::parse(&["vlan=7"])?;

    assert!(select(&case, &forged_scope).is_empty());
    let wire_match = select(&case, &wire_tag);
    assert_eq!(wire_match.len(), 1);
    let wire_match = wire_match.first().ok_or("wire VLAN match missing")?;
    assert_eq!(
        wire_match.vlan_evidence,
        [l2_workbench::query::VlanEvidence {
            packet_number: 1,
            vlan_id: 5,
            source: l2_workbench::query::VlanEvidenceSource::InBandBytes,
        }]
    );
    let auxiliary_match = select(&case, &auxiliary_tag);
    assert_eq!(auxiliary_match.len(), 1);
    let auxiliary_match = auxiliary_match
        .first()
        .ok_or("auxiliary VLAN match missing")?;
    assert_eq!(
        auxiliary_match.vlan_evidence,
        [l2_workbench::query::VlanEvidence {
            packet_number: 1,
            vlan_id: 7,
            source: l2_workbench::query::VlanEvidenceSource::CaptureParserMetadata,
        }]
    );
    Ok(())
}

#[test]
fn udp_port_retained_transport_header() -> Result<(), Box<dyn Error>> {
    let case = case_with_packets(vec![PacketSpec::new(udp_frame(
        [192, 0, 2, 8],
        [198, 51, 100, 9],
        53000,
        53,
    ))])?;
    let selector = Selector::parse(&["proto=udp", "dport=53"])?;

    let matches = select(&case, &selector);

    assert_eq!(matches.len(), 1);
    assert_eq!(
        matches
            .first()
            .and_then(|item| item.packet_numbers.first())
            .copied(),
        Some(1)
    );
    Ok(())
}

#[test]
fn query_match_serializes_provenance_fields() -> Result<(), Box<dyn Error>> {
    let case = case_with_packets(vec![PacketSpec::new(tcp_frame(
        [192, 0, 2, 8],
        [198, 51, 100, 9],
        53_000,
        443,
        0x02,
    ))])?;
    let selector = Selector::parse(&["proto=tcp"])?;
    let selected = select(&case, &selector);
    let first = selected.first().ok_or("packet match missing")?;

    let encoded = serde_json::to_value(first)?;

    assert_eq!(encoded.get("node_id"), Some(&serde_json::json!(1)));
    assert_eq!(encoded.get("kind"), Some(&serde_json::json!("packet")));
    assert_eq!(encoded.get("packet_numbers"), Some(&serde_json::json!([1])));
    assert!(encoded.get("source_ranges").is_some());
    assert!(encoded.get("statuses").is_some());
    assert_eq!(encoded.get("vlan_evidence"), Some(&serde_json::json!([])));
    Ok(())
}

#[test]
fn arp_icmp_decoded_packet_headers() -> Result<(), Box<dyn Error>> {
    let case = case_with_packets(vec![
        PacketSpec::new(arp_frame([192, 0, 2, 10], [192, 0, 2, 1])),
        PacketSpec::new(icmp_frame([192, 0, 2, 10], [198, 51, 100, 1], 8)),
        PacketSpec::new(icmpv6_frame(
            [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            128,
        )),
    ])?;

    for (filter, packet_number) in [
        ("proto=arp", 1),
        ("proto=icmp", 2),
        ("proto=icmpv6", 3),
        ("proto=1", 2),
        ("proto=58", 3),
    ] {
        let selected = select(&case, &Selector::parse(&[filter])?);
        assert_eq!(selected.len(), 1, "{filter}");
        let matched = selected.first().ok_or("selected packet missing")?;
        assert_eq!(matched.packet_numbers, [packet_number], "{filter}");
    }
    let arp_fields = Selector::parse(&[
        "proto=arp",
        "field.arp.opcode=1",
        "field.arp.src.proto_ipv4=192.0.2.10",
        "field.eth.type=0x0806",
    ])?;
    let arp_matches = select(&case, &arp_fields);
    assert_eq!(arp_matches.len(), 1);
    assert_eq!(
        arp_matches
            .first()
            .ok_or("ARP field match missing")?
            .packet_numbers,
        [1]
    );
    let icmpv6_field = Selector::parse(&["field.icmpv6.type=128"])?;
    let icmpv6_matches = select(&case, &icmpv6_field);
    assert_eq!(icmpv6_matches.len(), 1);
    assert_eq!(
        icmpv6_matches
            .first()
            .ok_or("ICMPv6 field match missing")?
            .packet_numbers,
        [3]
    );
    Ok(())
}

#[test]
fn exact_ip_retained_packet_facts() -> Result<(), Box<dyn Error>> {
    let case = case_with_packets(vec![
        PacketSpec::new(icmp_frame([192, 0, 2, 10], [198, 51, 100, 1], 8)).with_ticks(123_000_000),
        PacketSpec::new(icmp_frame([192, 0, 2, 11], [198, 51, 100, 1], 0)).with_ticks(220_000_000),
    ])?;
    let selector = Selector::parse(&["src=192.0.2.10", "time=12..12", "field.ip.proto=1"])?;

    let selected = select(&case, &selector);

    assert_eq!(selected.len(), 1);
    assert_eq!(
        selected
            .first()
            .ok_or("exact filter match missing")?
            .packet_numbers,
        [1]
    );
    assert!(
        select(&case, &Selector::parse(&["time=22..22"])?)
            .iter()
            .any(|item| item.packet_numbers == [2])
    );
    let untimed = case_with_packets(vec![PacketSpec::new(icmp_frame(
        [192, 0, 2, 10],
        [198, 51, 100, 1],
        8,
    ))])?;
    assert!(select(&untimed, &Selector::parse(&["time=0..2147483647"])?).is_empty());
    Ok(())
}

#[test]
fn fragmented_icmp_not_message_types() -> Result<(), Box<dyn std::error::Error>> {
    let mut fragment = icmp_frame([192, 0, 2, 10], [198, 51, 100, 1], 8);
    fragment
        .get_mut(20..22)
        .ok_or("ICMP type bytes missing from the frame")?
        .copy_from_slice(&1_u16.to_be_bytes());
    let case = case_with_packets(vec![PacketSpec::new(fragment)])?;

    let selected = select(&case, &Selector::parse(&["field.icmp.type=8"])?);

    assert!(selected.is_empty());
    Ok(())
}

fn arp_frame(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
    let mut frame = vec![0xff; 6];
    frame.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&[0x08, 0x06]);
    frame.extend_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    frame.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&[0; 6]);
    frame.extend_from_slice(&destination);
    frame
}

fn icmp_frame(source: [u8; 4], destination: [u8; 4], message_type: u8) -> Vec<u8> {
    let mut frame = vec![2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 8, 0];
    frame.extend_from_slice(&[0x45, 0, 0, 28, 0, 1, 0, 0, 64, 1, 0, 0]);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&[message_type, 0, 0, 0, 0, 0, 0, 0]);
    frame
}

fn icmpv6_frame(source: [u8; 16], destination: [u8; 16], message_type: u8) -> Vec<u8> {
    let mut frame = vec![2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x86, 0xdd];
    frame.extend_from_slice(&[0x60, 0, 0, 0, 0, 8, 58, 64]);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&[message_type, 0, 0, 0, 0, 0, 0, 0]);
    frame
}
