use super::support::{PacketSpec, case_with_packets, tcp_frame};
use l2_workbench::{
    behavior::{BehaviorConfig, BehaviorKind, analyze_case},
    evidence::{Edge, EvidenceStatus},
    query::IpCidr,
};
use serde_json::json;
use std::error::Error;

#[test]
fn directional_syn_configured_network_boundary() -> Result<(), Box<dyn Error>> {
    let packets = (0..4)
        .map(|index| {
            PacketSpec::new(tcp_frame(
                [192, 0, 2, 10],
                [198, 51, 100, 20],
                40_000,
                8443,
                0x02,
            ))
            .with_scope(0, vec![37])
            .with_ticks(100 + index * 10)
        })
        .collect();
    let case = case_with_packets(packets)?;
    let mut config = BehaviorConfig::default();
    config
        .internal_networks
        .push(IpCidr::parse("192.0.2.0/24")?);

    let report = analyze_case(&case, &config)?;
    let sequence = report
        .findings
        .iter()
        .find(|finding| finding.kind == BehaviorKind::OutboundPacketSequence)
        .ok_or("outbound sequence was not retained")?;

    assert_eq!(sequence.packet_numbers, vec![1, 2, 3, 4]);
    assert_eq!(sequence.status, EvidenceStatus::Observed);
    assert_eq!(sequence.details.get("direction"), Some(&json!("outbound")));
    Ok(())
}

#[test]
fn syn_fan_sweeps_observed_targets() -> Result<(), Box<dyn Error>> {
    let mut packets = Vec::new();
    for destination in [[198, 51, 100, 20], [198, 51, 100, 21], [198, 51, 100, 22]] {
        packets.push(PacketSpec::new(tcp_frame(
            [192, 0, 2, 10],
            destination,
            40_000,
            443,
            0x02,
        )));
    }
    for port in [80, 443, 8443] {
        packets.push(PacketSpec::new(tcp_frame(
            [192, 0, 2, 11],
            [198, 51, 100, 30],
            40_001,
            port,
            0x02,
        )));
    }
    let case = case_with_packets(packets)?;
    let mut config = BehaviorConfig::default();
    config
        .internal_networks
        .push(IpCidr::parse("192.0.2.0/24")?);

    let report = analyze_case(&case, &config)?;

    assert!(report.findings.iter().any(|finding| {
        finding.kind == BehaviorKind::TcpSynFanOut
            && finding.packet_numbers == [1, 2, 3]
            && finding.status == EvidenceStatus::Hypothesis
    }));
    assert!(report.findings.iter().any(|finding| {
        finding.kind == BehaviorKind::TcpSynServiceSweep && finding.packet_numbers == [4, 5, 6]
    }));
    assert!(
        report
            .limitations
            .iter()
            .any(|text| text.contains("malicious"))
    );
    Ok(())
}

#[test]
fn syn_fanout_without_network_configuration() -> Result<(), Box<dyn Error>> {
    let packets = [[198, 51, 100, 20], [198, 51, 100, 21], [198, 51, 100, 22]]
        .into_iter()
        .map(|destination| {
            PacketSpec::new(tcp_frame([192, 0, 2, 10], destination, 40_000, 443, 0x02))
        })
        .collect();
    let case = case_with_packets(packets)?;

    let report = analyze_case(&case, &BehaviorConfig::default())?;

    assert!(report.findings.iter().any(|finding| {
        finding.kind == BehaviorKind::TcpSynFanOut && finding.packet_numbers == [1, 2, 3]
    }));
    Ok(())
}

#[test]
fn syn_fanout_internal_lateral_targets() -> Result<(), Box<dyn Error>> {
    let mut packets = Vec::new();
    for destination in [[192, 0, 2, 20], [192, 0, 2, 21], [192, 0, 2, 22]] {
        packets.push(PacketSpec::new(tcp_frame(
            [192, 0, 2, 10],
            destination,
            40_000,
            443,
            0x02,
        )));
    }
    for port in [80, 443, 8443] {
        packets.push(PacketSpec::new(tcp_frame(
            [192, 0, 2, 11],
            [192, 0, 2, 30],
            40_001,
            port,
            0x02,
        )));
    }
    let case = case_with_packets(packets)?;
    let mut config = BehaviorConfig::default();
    config
        .internal_networks
        .push(IpCidr::parse("192.0.2.0/24")?);

    let report = analyze_case(&case, &config)?;

    assert!(report.findings.iter().any(|finding| {
        finding.kind == BehaviorKind::TcpSynFanOut && finding.packet_numbers == [1, 2, 3]
    }));
    assert!(report.findings.iter().any(|finding| {
        finding.kind == BehaviorKind::TcpSynServiceSweep && finding.packet_numbers == [4, 5, 6]
    }));
    Ok(())
}

#[test]
fn contradictory_syn_not_qualify_attempts() -> Result<(), Box<dyn Error>> {
    let packets = [
        ([198, 51, 100, 20], 0x03),
        ([198, 51, 100, 21], 0x06),
        ([198, 51, 100, 22], 0x12),
    ]
    .into_iter()
    .map(|(destination, flags)| {
        PacketSpec::new(tcp_frame([192, 0, 2, 10], destination, 40_000, 443, flags))
    })
    .collect();
    let case = case_with_packets(packets)?;
    let mut config = BehaviorConfig::default();
    config
        .internal_networks
        .push(IpCidr::parse("192.0.2.0/24")?);

    let report = analyze_case(&case, &config)?;

    assert!(report.findings.iter().all(|finding| {
        !matches!(
            finding.kind,
            BehaviorKind::TcpSynFanOut | BehaviorKind::TcpSynServiceSweep
        )
    }));
    Ok(())
}

#[test]
fn regular_syn_exact_deltas_counterexamples() -> Result<(), Box<dyn Error>> {
    let packets = [100, 110, 120, 145]
        .into_iter()
        .map(|ticks| {
            PacketSpec::new(tcp_frame(
                [192, 0, 2, 10],
                [198, 51, 100, 20],
                40_000,
                8443,
                0x02,
            ))
            .with_ticks(ticks)
        })
        .collect();
    let case = case_with_packets(packets)?;
    let mut config = BehaviorConfig::default();
    config
        .internal_networks
        .push(IpCidr::parse("192.0.2.0/24")?);

    let report = analyze_case(&case, &config)?;
    let intervals = report
        .findings
        .iter()
        .find(|finding| finding.kind == BehaviorKind::RegularConnectionIntervals)
        .ok_or("regular interval report was not retained")?;

    assert_eq!(intervals.status, EvidenceStatus::ConstraintFailed);
    assert_eq!(
        intervals.details.get("baseline_delta_ticks"),
        Some(&json!(10))
    );
    assert_eq!(
        intervals.details.pointer("/counterexamples/0/from_packet"),
        Some(&json!(3))
    );
    assert_eq!(
        intervals.details.pointer("/counterexamples/0/to_packet"),
        Some(&json!(4))
    );
    assert_eq!(
        intervals.details.pointer("/counterexamples/0/delta_ticks"),
        Some(&json!(25))
    );
    Ok(())
}

#[test]
fn tick_locators_packet_byte_mappings() -> Result<(), Box<dyn Error>> {
    let packets = [100, 110, 120]
        .into_iter()
        .zip([24_u64, 64, 104])
        .map(|(ticks, timestamp_offset)| {
            let mut packet = PacketSpec::new(tcp_frame(
                [192, 0, 2, 10],
                [198, 51, 100, 20],
                40_000,
                8443,
                0x02,
            ))
            .with_ticks(ticks);
            packet.timestamp_source_offset = Some(timestamp_offset);
            packet
        })
        .collect();
    let case = case_with_packets(packets)?;
    let report = analyze_case(&case, &BehaviorConfig::default())?;
    let intervals = report
        .findings
        .iter()
        .find(|finding| finding.kind == BehaviorKind::RegularConnectionIntervals)
        .ok_or("regular interval report was not retained")?;

    assert_eq!(
        intervals.details.pointer("/timestamp_locator/kind"),
        Some(&json!("parser_reported_capture_record_metadata"))
    );
    assert_eq!(
        intervals
            .details
            .pointer("/timestamp_locator/is_byte_mapping_receipt"),
        Some(&json!(false))
    );
    assert_eq!(
        intervals
            .details
            .pointer("/timestamp_locator/unlocated_packet_numbers"),
        Some(&json!([]))
    );
    assert_eq!(
        intervals
            .details
            .pointer("/intervals/0/from_timestamp_source_ranges/0/offset"),
        Some(&json!(24))
    );
    assert_eq!(
        intervals
            .details
            .pointer("/intervals/0/to_timestamp_source_ranges/0/offset"),
        Some(&json!(64))
    );
    assert_eq!(
        intervals.source_ranges.first().map(|range| range.offset),
        Some(0)
    );
    Ok(())
}

#[test]
fn ticks_without_locators_marked_unlocated() -> Result<(), Box<dyn Error>> {
    let packets = [100, 110]
        .into_iter()
        .map(|ticks| {
            PacketSpec::new(tcp_frame(
                [192, 0, 2, 10],
                [198, 51, 100, 20],
                40_000,
                8443,
                0x02,
            ))
            .with_ticks(ticks)
        })
        .collect();
    let case = case_with_packets(packets)?;

    let report = analyze_case(&case, &BehaviorConfig::default())?;

    let intervals = report
        .findings
        .iter()
        .find(|finding| finding.kind == BehaviorKind::RegularConnectionIntervals)
        .ok_or("regular interval report was not retained")?;
    assert_eq!(
        intervals
            .details
            .pointer("/timestamp_locator/unlocated_packet_numbers"),
        Some(&json!([1, 2]))
    );
    Ok(())
}

#[test]
fn timestamp_locators_source_rejected_receipts() -> Result<(), Box<dyn Error>> {
    let mut invalid = PacketSpec::new(tcp_frame(
        [192, 0, 2, 10],
        [198, 51, 100, 20],
        40_000,
        8443,
        0x02,
    ))
    .with_ticks(100);
    invalid.timestamp_source_offset = Some(u64::MAX - 2);
    let case = case_with_packets(vec![invalid, {
        let mut packet = PacketSpec::new(tcp_frame(
            [192, 0, 2, 10],
            [198, 51, 100, 20],
            40_000,
            8443,
            0x02,
        ))
        .with_ticks(110);
        packet.timestamp_source_offset = Some(100);
        packet
    }])?;

    let report = analyze_case(&case, &BehaviorConfig::default())?;

    let intervals = report
        .findings
        .iter()
        .find(|finding| finding.kind == BehaviorKind::RegularConnectionIntervals)
        .ok_or("regular interval report was not retained")?;
    assert_eq!(
        intervals
            .details
            .pointer("/timestamp_locator/invalid_locator_packet_numbers"),
        Some(&json!([1]))
    );
    assert_eq!(
        intervals
            .details
            .pointer("/timestamp_locator/unlocated_packet_numbers"),
        Some(&json!([1]))
    );
    assert_eq!(
        intervals
            .details
            .pointer("/timestamp_locator/source_ranges/0/packet"),
        Some(&json!(2))
    );
    assert!(
        intervals
            .details
            .pointer("/timestamp_locator/source_ranges/1")
            .is_none()
    );
    Ok(())
}

#[test]
fn timing_not_ticks_mismatched_clocks() -> Result<(), Box<dyn Error>> {
    let mut middle = PacketSpec::new(tcp_frame(
        [192, 0, 2, 10],
        [198, 51, 100, 20],
        40_000,
        8443,
        0x02,
    ))
    .with_ticks(110);
    middle.timestamp_source = "independent_capture_clock";
    let case = case_with_packets(vec![
        PacketSpec::new(tcp_frame(
            [192, 0, 2, 10],
            [198, 51, 100, 20],
            40_000,
            8443,
            0x02,
        ))
        .with_ticks(100),
        middle,
        PacketSpec::new(tcp_frame(
            [192, 0, 2, 10],
            [198, 51, 100, 20],
            40_000,
            8443,
            0x02,
        ))
        .with_ticks(120),
    ])?;

    let report = analyze_case(&case, &BehaviorConfig::default())?;

    let mismatch = report
        .findings
        .iter()
        .find(|finding| finding.kind == BehaviorKind::TimestampClockMismatch)
        .ok_or("clock mismatch was not retained")?;
    assert_eq!(mismatch.status, EvidenceStatus::Unresolved);
    assert_eq!(mismatch.details.get("delta_ticks"), Some(&json!(null)));
    let intervals = report
        .findings
        .iter()
        .find(|finding| finding.kind == BehaviorKind::RegularConnectionIntervals)
        .ok_or("regular interval report was not retained")?;
    assert_eq!(intervals.status, EvidenceStatus::Unresolved);
    assert_eq!(
        intervals.details.pointer("/intervals/0/status"),
        Some(&json!("clock_mismatch"))
    );
    Ok(())
}

#[test]
fn tick_anomalies_not_endpoint_timestomping() -> Result<(), Box<dyn Error>> {
    let packets = [100, 100, 90, 250]
        .into_iter()
        .map(|ticks| {
            PacketSpec::new(tcp_frame(
                [192, 0, 2, 10],
                [198, 51, 100, 20],
                40_000,
                8443,
                0x02,
            ))
            .with_ticks(ticks)
        })
        .collect();
    let case = case_with_packets(packets)?;
    let config = BehaviorConfig {
        large_forward_gap_ticks: Some(50),
        ..BehaviorConfig::default()
    };
    let report = analyze_case(&case, &config)?;

    let anomaly_count = report
        .findings
        .iter()
        .filter(|finding| finding.kind == BehaviorKind::CaptureClockAnomaly)
        .count();
    assert_eq!(anomaly_count, 3);
    assert!(
        report
            .limitations
            .iter()
            .any(|text| text.contains("endpoint timestamp"))
    );
    Ok(())
}

#[test]
fn arp_dns_reused_canonical_findings() -> Result<(), Box<dyn Error>> {
    let mut case = case_with_packets(Vec::new())?;
    case.add_node(
        "arp_claim_sequence",
        None,
        Vec::new(),
        json!({
            "address": "192.0.2.30",
            "previous_mac": "02:00:00:00:00:01",
            "claimed_mac": "02:00:00:00:00:02",
            "previous_packet": 2,
            "packet": 4,
            "followup_packet": 5,
        }),
    )?;
    case.add_node(
        "dns_address_sequence",
        None,
        Vec::new(),
        json!({
            "query_packet": 8,
            "response_packet": 9,
            "packet": 12,
            "answer_record": 0,
            "address": "198.51.100.40",
            "client_matches_requester": true,
        }),
    )?;

    let report = analyze_case(&case, &BehaviorConfig::default())?;

    assert!(report.findings.iter().any(|finding| {
        finding.kind == BehaviorKind::ArpClaimChange && finding.packet_numbers == [2, 4, 5]
    }));
    assert!(report.findings.iter().any(|finding| {
        finding.kind == BehaviorKind::DnsAnswerDestinationChain
            && finding.packet_numbers == [8, 9, 12]
    }));
    Ok(())
}

#[test]
fn behavior_finding_budget_incomplete() -> Result<(), Box<dyn Error>> {
    let mut case = l2_workbench::evidence::Case::new();
    for _ in 0..=4096 {
        case.add_node("arp_claim_sequence", None, Vec::new(), json!({}))?;
    }

    let report = analyze_case(&case, &BehaviorConfig::default())?;

    assert_eq!(report.findings.len(), 4096);
    assert_eq!(report.omitted_findings, 1);
    assert!(!report.complete);
    assert!(
        report
            .limitations
            .iter()
            .any(|limitation| limitation.contains("omitted"))
    );
    Ok(())
}

#[test]
fn scope_changes_separate_directional_sequences() -> Result<(), Box<dyn Error>> {
    let case = case_with_packets(vec![
        PacketSpec::new(tcp_frame(
            [192, 0, 2, 10],
            [198, 51, 100, 20],
            40_000,
            443,
            0x02,
        ))
        .with_scope(1, vec![37]),
        PacketSpec::new(tcp_frame(
            [192, 0, 2, 10],
            [198, 51, 100, 20],
            40_001,
            443,
            0x02,
        ))
        .with_scope(2, vec![37]),
    ])?;
    let mut config = BehaviorConfig::default();
    config
        .internal_networks
        .push(IpCidr::parse("192.0.2.0/24")?);

    let report = analyze_case(&case, &config)?;

    assert!(
        report
            .findings
            .iter()
            .all(|finding| { finding.kind != BehaviorKind::OutboundPacketSequence })
    );
    Ok(())
}

#[test]
fn udp_packets_not_tcp_syn() -> Result<(), Box<dyn Error>> {
    let packets = [80, 443, 8443]
        .into_iter()
        .map(|port| {
            PacketSpec::new(super::support::udp_frame(
                [192, 0, 2, 10],
                [198, 51, 100, 30],
                40_000,
                port,
            ))
        })
        .collect();
    let case = case_with_packets(packets)?;
    let mut config = BehaviorConfig::default();
    config
        .internal_networks
        .push(IpCidr::parse("192.0.2.0/24")?);

    let report = analyze_case(&case, &config)?;

    assert!(report.findings.iter().all(|finding| {
        finding.kind != BehaviorKind::TcpSynServiceSweep
            && finding.kind != BehaviorKind::TcpSynFanOut
    }));
    Ok(())
}

#[test]
fn reused_tuple_separate_tcp_episode() -> Result<(), Box<dyn Error>> {
    let packets = [100, 110, 500, 510]
        .into_iter()
        .map(|ticks| {
            PacketSpec::new(tcp_frame(
                [192, 0, 2, 10],
                [198, 51, 100, 20],
                40_000,
                8443,
                0x02,
            ))
            .with_ticks(ticks)
        })
        .collect();
    let mut case = case_with_packets(packets)?;
    let first_episode = case.add_node(
        "tcp_episode",
        None,
        Vec::new(),
        json!({"generation_ambiguous": false}),
    )?;
    let second_episode = case.add_node(
        "tcp_episode",
        None,
        Vec::new(),
        json!({"generation_ambiguous": false}),
    )?;
    for packet in [1, 2] {
        case.add_edge(Edge {
            from: packet,
            to: first_episode,
            relation: "supports".to_owned(),
            status: EvidenceStatus::Hypothesis,
            reason: "packet belongs to a bounded TCP episode candidate".to_owned(),
        })?;
    }
    for packet in [3, 4] {
        case.add_edge(Edge {
            from: packet,
            to: second_episode,
            relation: "supports".to_owned(),
            status: EvidenceStatus::Hypothesis,
            reason: "tuple is observed in another TCP episode".to_owned(),
        })?;
    }

    let report = analyze_case(&case, &BehaviorConfig::default())?;
    let interval_groups: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.kind == BehaviorKind::RegularConnectionIntervals)
        .collect();

    assert_eq!(interval_groups.len(), 2);
    let grouped_packets: Vec<_> = interval_groups
        .iter()
        .map(|finding| finding.packet_numbers.clone())
        .collect();
    assert_eq!(grouped_packets, [vec![1, 2], vec![3, 4]]);
    Ok(())
}
