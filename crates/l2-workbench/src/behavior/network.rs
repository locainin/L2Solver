use super::{BehaviorConfig, BehaviorFinding, BehaviorKind, visitor::FindingVisitor};
use crate::{
    evidence::{Case, EvidenceStatus, Node, SourceRange},
    query::{
        IpCidr,
        packet::{PacketFacts, PacketTimestamp, packet_facts},
    },
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, error::Error, net::IpAddr};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FlowKey {
    source: IpAddr,
    destination: IpAddr,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    protocol: Option<&'static str>,
    source_id: Option<String>,
    scope: String,
    episode: Option<u64>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct HostKey {
    host: IpAddr,
    protocol: Option<&'static str>,
    source_id: Option<String>,
    scope: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DirectionKey {
    source_id: Option<String>,
    scope: String,
    direction: &'static str,
    internal_ip: IpAddr,
    protocol: Option<&'static str>,
}

struct FlowMeasurements<'a> {
    intervals: Vec<Value>,
    deltas: Vec<(&'a PacketFacts, &'a PacketFacts, Option<u64>)>,
    anomalies: Vec<Value>,
    mismatches: Vec<Value>,
}

impl FlowMeasurements<'_> {
    fn with_capacity(packet_count: usize) -> Self {
        Self {
            intervals: Vec::with_capacity(packet_count.saturating_sub(1)),
            deltas: Vec::new(),
            anomalies: Vec::new(),
            mismatches: Vec::new(),
        }
    }
}

pub(super) fn analyze(
    case: &Case,
    config: &BehaviorConfig,
    report: &mut FindingVisitor<'_>,
) -> Result<(), Box<dyn Error>> {
    let facts = packet_facts(case);
    if facts.iter().any(|packet| packet.source_id.is_none()) {
        report.add_limitation("Some packet nodes lack source identity ranges and are excluded from cross-packet behavior grouping");
    }
    directional_sequences(&facts, config, report)?;
    syn_scans(&facts, report)?;
    flow_timing(&facts, config, report)?;
    canonical_sequences(case, report)
}

fn directional_sequences(
    facts: &[PacketFacts],
    config: &BehaviorConfig,
    report: &mut FindingVisitor<'_>,
) -> Result<(), Box<dyn Error>> {
    let mut groups: BTreeMap<DirectionKey, Vec<&PacketFacts>> = BTreeMap::new();
    for packet in facts {
        if packet.source_id.is_none() {
            continue;
        }
        let (Some(source), Some(destination)) = (packet.source_ip, packet.destination_ip) else {
            continue;
        };
        let direction = direction(source, destination, &config.internal_networks);
        let Some((name, internal_ip)) = direction else {
            continue;
        };
        groups
            .entry(DirectionKey {
                source_id: packet.source_id.clone(),
                scope: scope_key(&packet.scope),
                direction: name,
                internal_ip,
                protocol: packet.protocol,
            })
            .or_default()
            .push(packet);
    }
    for (key, mut packets) in groups {
        packets.sort_by_key(|packet| packet.packet_number);
        if packets.len() < 2 {
            continue;
        }
        let kind = if key.direction == "outbound" {
            BehaviorKind::OutboundPacketSequence
        } else {
            BehaviorKind::InboundPacketSequence
        };
        let finding = BehaviorFinding {
            kind,
            status: EvidenceStatus::Observed,
            node_ids: Vec::new(),
            packet_numbers: packets.iter().map(|packet| packet.packet_number).collect(),
            source_ranges: ranges_for_packets(&packets),
            details: json!({
                "direction": key.direction,
                "internal_address": key.internal_ip.to_string(),
                "protocol": key.protocol,
                "event_count": packets.len(),
                "endpoint_pairs": endpoint_pairs(&packets),
            }),
        };
        report.push(finding)?;
    }
    Ok(())
}

fn direction(
    source: IpAddr,
    destination: IpAddr,
    networks: &[IpCidr],
) -> Option<(&'static str, IpAddr)> {
    let source_internal = networks.iter().any(|network| network.contains(source));
    let destination_internal = networks.iter().any(|network| network.contains(destination));
    match (source_internal, destination_internal) {
        (true, false) => Some(("outbound", source)),
        (false, true) => Some(("inbound", destination)),
        _ => None,
    }
}

fn syn_scans(facts: &[PacketFacts], report: &mut FindingVisitor<'_>) -> Result<(), Box<dyn Error>> {
    let mut fanout: BTreeMap<(HostKey, u16), Vec<&PacketFacts>> = BTreeMap::new();
    let mut service: BTreeMap<(HostKey, IpAddr), Vec<&PacketFacts>> = BTreeMap::new();
    for packet in facts {
        if packet.source_id.is_none()
            || packet.protocol != Some("tcp")
            || packet.tcp_flags.is_none_or(|flags| flags & 0x17 != 0x02)
        {
            continue;
        }
        let (Some(source), Some(destination), Some(destination_port)) = (
            packet.source_ip,
            packet.destination_ip,
            packet.destination_port,
        ) else {
            continue;
        };
        let host = HostKey {
            host: source,
            protocol: packet.protocol,
            source_id: packet.source_id.clone(),
            scope: scope_key(&packet.scope),
        };
        fanout
            .entry((host.clone(), destination_port))
            .or_default()
            .push(packet);
        service.entry((host, destination)).or_default().push(packet);
    }
    for ((key, port), mut packets) in fanout {
        packets.sort_by_key(|packet| packet.packet_number);
        let destinations = unique_destinations(&packets);
        if destinations.len() >= 3 {
            report.push(scan_finding(
                BehaviorKind::TcpSynFanOut,
                &packets,
                json!({"source":key.host.to_string(),"destination_port":port,"destinations":destinations}),
            ))?;
        }
    }
    for ((key, destination), mut packets) in service {
        packets.sort_by_key(|packet| packet.packet_number);
        let ports: Vec<_> = unique_ports(&packets);
        if ports.len() >= 3 {
            report.push(scan_finding(
                BehaviorKind::TcpSynServiceSweep,
                &packets,
                json!({"source":key.host.to_string(),"destination":destination.to_string(),"destination_ports":ports}),
            ))?;
        }
    }
    Ok(())
}

fn scan_finding(kind: BehaviorKind, packets: &[&PacketFacts], details: Value) -> BehaviorFinding {
    BehaviorFinding {
        kind,
        status: EvidenceStatus::Hypothesis,
        node_ids: Vec::new(),
        packet_numbers: packets.iter().map(|packet| packet.packet_number).collect(),
        source_ranges: ranges_for_packets(packets),
        details,
    }
}

fn unique_destinations(packets: &[&PacketFacts]) -> Vec<String> {
    let mut addresses = packets
        .iter()
        .filter_map(|packet| packet.destination_ip)
        .collect::<Vec<_>>();
    addresses.sort_unstable();
    addresses.dedup();
    addresses
        .into_iter()
        .map(|address| address.to_string())
        .collect()
}

fn unique_ports(packets: &[&PacketFacts]) -> Vec<u16> {
    let mut ports = packets
        .iter()
        .filter_map(|packet| packet.destination_port)
        .collect::<Vec<_>>();
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn endpoint_pairs(packets: &[&PacketFacts]) -> Vec<Value> {
    packets
        .iter()
        .map(|packet| {
            json!({
                "source": packet.source_ip.map(|address| address.to_string()),
                "destination": packet.destination_ip.map(|address| address.to_string()),
                "source_port": packet.source_port,
                "destination_port": packet.destination_port,
            })
        })
        .collect()
}

fn flow_timing(
    facts: &[PacketFacts],
    config: &BehaviorConfig,
    report: &mut FindingVisitor<'_>,
) -> Result<(), Box<dyn Error>> {
    let mut groups: BTreeMap<FlowKey, Vec<&PacketFacts>> = BTreeMap::new();
    for packet in facts {
        if packet.source_id.is_none() {
            continue;
        }
        let (Some(source), Some(destination)) = (packet.source_ip, packet.destination_ip) else {
            continue;
        };
        groups
            .entry(FlowKey {
                source,
                destination,
                source_port: packet.source_port,
                destination_port: packet.destination_port,
                protocol: packet.protocol,
                source_id: packet.source_id.clone(),
                scope: scope_key(&packet.scope),
                episode: packet.tcp_episode,
            })
            .or_default()
            .push(packet);
    }
    for mut packets in groups.into_values() {
        packets.sort_by_key(|packet| packet.packet_number);
        if packets.len() > 1 {
            measure_flow(&packets, config, report)?;
        }
    }
    Ok(())
}

fn measure_flow(
    packets: &[&PacketFacts],
    config: &BehaviorConfig,
    report: &mut FindingVisitor<'_>,
) -> Result<(), Box<dyn Error>> {
    let mut measurements = FlowMeasurements::with_capacity(packets.len());
    for pair in packets.windows(2) {
        let (Some(&from), Some(&to)) = (pair.first(), pair.get(1)) else {
            continue;
        };
        record_interval(from, to, config, &mut measurements);
    }
    report_clock_anomalies(packets, measurements.anomalies, report)?;
    report_clock_mismatches(packets, measurements.mismatches, report)?;
    interval_summary(
        packets,
        &measurements.intervals,
        &measurements.deltas,
        report,
    )
}

fn record_interval<'a>(
    from: &'a PacketFacts,
    to: &'a PacketFacts,
    config: &BehaviorConfig,
    measurements: &mut FlowMeasurements<'a>,
) {
    let (Some(left), Some(right)) = (&from.timestamp, &to.timestamp) else {
        measurements.intervals.push(json!({
            "from_packet":from.packet_number,
            "to_packet":to.packet_number,
            "status":"missing_timestamp",
            "from_timestamp_source_ranges":from.timestamp_source_ranges,
            "to_timestamp_source_ranges":to.timestamp_source_ranges,
        }));
        return;
    };
    if !same_clock(left, right) {
        measurements.mismatches.push(json!({
            "from_packet":from.packet_number,
            "to_packet":to.packet_number,
            "from_clock":clock_value(left),
            "to_clock":clock_value(right),
        }));
        measurements.intervals.push(json!({
            "from_packet":from.packet_number,
            "to_packet":to.packet_number,
            "status":"clock_mismatch",
            "from_timestamp_source_ranges":from.timestamp_source_ranges,
            "to_timestamp_source_ranges":to.timestamp_source_ranges,
        }));
        return;
    }
    let delta = right.ticks.checked_sub(left.ticks);
    let reason = anomaly_reason(delta, config.large_forward_gap_ticks);
    if let Some(reason) = reason {
        measurements.anomalies.push(json!({
            "from_packet":from.packet_number,
            "to_packet":to.packet_number,
            "from_ticks":left.ticks,
            "to_ticks":right.ticks,
            "delta_ticks":delta,
            "reason":reason,
            "from_timestamp_source_ranges":from.timestamp_source_ranges,
            "to_timestamp_source_ranges":to.timestamp_source_ranges,
        }));
    }
    measurements.intervals.push(json!({
        "from_packet":from.packet_number,
        "to_packet":to.packet_number,
        "status":if delta.is_some(){"measured"}else{"backwards"},
        "delta_ticks":delta,
        "from_timestamp_source_ranges":from.timestamp_source_ranges,
        "to_timestamp_source_ranges":to.timestamp_source_ranges,
    }));
    measurements.deltas.push((from, to, delta));
}

fn anomaly_reason(delta: Option<u64>, large_gap: Option<u64>) -> Option<&'static str> {
    match delta {
        None => Some("backwards"),
        Some(0) => Some("duplicate"),
        Some(value) if large_gap.is_some_and(|limit| value > limit) => Some("large_forward_gap"),
        _ => None,
    }
}

fn report_clock_anomalies(
    packets: &[&PacketFacts],
    anomalies: Vec<Value>,
    report: &mut FindingVisitor<'_>,
) -> Result<(), Box<dyn Error>> {
    for anomaly in anomalies {
        let selected = packets_for_numbers(packets, &anomaly);
        let finding = BehaviorFinding {
            kind: BehaviorKind::CaptureClockAnomaly,
            status: EvidenceStatus::Observed,
            node_ids: Vec::new(),
            packet_numbers: anomaly_packets(&anomaly),
            source_ranges: ranges_for_packets(&selected),
            details: json!({
                "anomaly":anomaly,
                "interpretation":"capture_timestamp_only",
                "timestamp_locator":timestamp_locator(&selected),
            }),
        };
        report.push(finding)?;
    }
    Ok(())
}

fn report_clock_mismatches(
    packets: &[&PacketFacts],
    mismatches: Vec<Value>,
    report: &mut FindingVisitor<'_>,
) -> Result<(), Box<dyn Error>> {
    for mismatch in mismatches {
        let selected = packets_for_numbers(packets, &mismatch);
        report.push(BehaviorFinding {
            kind: BehaviorKind::TimestampClockMismatch,
            status: EvidenceStatus::Unresolved,
            node_ids: Vec::new(),
            packet_numbers: anomaly_packets(&mismatch),
            source_ranges: ranges_for_packets(&selected),
            details: json!({
                "comparison":mismatch,
                "delta_ticks":null,
                "timestamp_locator":timestamp_locator(&selected),
            }),
        })?;
    }
    Ok(())
}

fn interval_summary(
    packets: &[&PacketFacts],
    intervals: &[Value],
    deltas: &[(&PacketFacts, &PacketFacts, Option<u64>)],
    report: &mut FindingVisitor<'_>,
) -> Result<(), Box<dyn Error>> {
    let measured: Vec<_> = deltas
        .iter()
        .filter_map(|(from, to, delta)| delta.map(|value| (*from, *to, value)))
        .collect();
    let baseline = measured.first().map(|item| item.2);
    let counterexamples: Vec<_> = measured.iter().skip(1).filter(|item| Some(item.2) != baseline).map(|(from, to, delta)| json!({"from_packet":from.packet_number,"to_packet":to.packet_number,"delta_ticks":delta})).collect();
    let has_unmeasured = intervals
        .iter()
        .any(|item| item.get("status").and_then(Value::as_str) != Some("measured"));
    let status = if has_unmeasured || measured.len() < 2 {
        EvidenceStatus::Unresolved
    } else if counterexamples.is_empty() {
        EvidenceStatus::ConstraintSatisfied
    } else {
        EvidenceStatus::ConstraintFailed
    };
    report.push(BehaviorFinding {
        kind: BehaviorKind::RegularConnectionIntervals,
        status,
        node_ids: Vec::new(),
        packet_numbers: packets.iter().map(|packet| packet.packet_number).collect(),
        source_ranges: ranges_for_packets(packets),
        details: json!({
            "baseline_delta_ticks":baseline,
            "intervals":intervals,
            "counterexamples":counterexamples,
            "constraint":"adjacent deltas equal the first measured delta",
            "timestamp_locator":timestamp_locator(packets),
        }),
    })
}

fn same_clock(left: &PacketTimestamp, right: &PacketTimestamp) -> bool {
    left.source == right.source
        && left.radix == right.radix
        && left.exponent == right.exponent
        && left.offset_seconds == right.offset_seconds
}

fn clock_value(clock: &PacketTimestamp) -> Value {
    json!({"source":clock.source,"radix":clock.radix,"exponent":clock.exponent,"offset_seconds":clock.offset_seconds})
}

fn anomaly_packets(value: &Value) -> Vec<u64> {
    [value.get("from_packet"), value.get("to_packet")]
        .into_iter()
        .flatten()
        .filter_map(Value::as_u64)
        .collect()
}

fn packets_for_numbers<'a>(packets: &[&'a PacketFacts], value: &Value) -> Vec<&'a PacketFacts> {
    let numbers = anomaly_packets(value);
    packets
        .iter()
        .copied()
        .filter(|packet| numbers.contains(&packet.packet_number))
        .collect()
}

fn ranges_for_packets(packets: &[&PacketFacts]) -> Vec<SourceRange> {
    let mut ranges = Vec::new();
    for packet in packets {
        for range in &packet.ranges {
            if !ranges.contains(range) {
                ranges.push(range.clone());
            }
        }
    }
    ranges
}

fn timestamp_locator(packets: &[&PacketFacts]) -> Value {
    let mut ranges = Vec::new();
    let mut unlocated_packets = Vec::new();
    let mut invalid_locator_packets = Vec::new();
    for packet in packets {
        if packet.timestamp.is_some() && packet.timestamp_source_ranges.is_empty() {
            unlocated_packets.push(packet.packet_number);
        }
        if packet.timestamp_source_ranges_invalid {
            invalid_locator_packets.push(packet.packet_number);
        }
        for range in &packet.timestamp_source_ranges {
            if !ranges.contains(range) {
                ranges.push(range.clone());
            }
        }
    }
    json!({
        "kind":"parser_reported_capture_record_metadata",
        "requires_independent_revalidation":true,
        "is_byte_mapping_receipt":false,
        "source_ranges":ranges,
        "unlocated_packet_numbers":unlocated_packets,
        "invalid_locator_packet_numbers":invalid_locator_packets,
    })
}

fn scope_key(scope: &Value) -> String {
    scope.to_string()
}

fn canonical_sequences(case: &Case, report: &mut FindingVisitor<'_>) -> Result<(), Box<dyn Error>> {
    for node in case.nodes() {
        let (kind, packets) = match node.kind.as_str() {
            "arp_claim_sequence" => (
                BehaviorKind::ArpClaimChange,
                canonical_packet_numbers(node, &["previous_packet", "packet", "followup_packet"]),
            ),
            "dns_address_sequence" => (
                BehaviorKind::DnsAnswerDestinationChain,
                canonical_packet_numbers(node, &["query_packet", "response_packet", "packet"]),
            ),
            _ => continue,
        };
        report.push(BehaviorFinding {
            kind,
            status: EvidenceStatus::Observed,
            node_ids: vec![node.id],
            packet_numbers: packets,
            source_ranges: node.ranges.clone(),
            details: node.details.clone(),
        })?;
    }
    Ok(())
}

fn canonical_packet_numbers(node: &Node, fields: &[&str]) -> Vec<u64> {
    let mut packets: Vec<_> = fields
        .iter()
        .filter_map(|field| node.details.get(*field).and_then(Value::as_u64))
        .collect();
    packets.dedup();
    packets
}
