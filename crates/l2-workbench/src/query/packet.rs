use crate::evidence::{Case, Node, SourceRange};
use l2_capture::{CapturedFrame, LinkType};
use l2_core::FrameField;
use l2_discovery::{
    NetworkAddress, TransportHeader, ip_header_from_payload, ip_packet_from_payload,
    link::{NetworkEnvelope, decode_network_frame},
};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

/// Facts decoded from one retained packet node without changing its source locator
#[derive(Clone, Debug)]
pub struct PacketFacts {
    pub node_id: u64,
    pub packet_number: u64,
    pub source_ip: Option<IpAddr>,
    pub destination_ip: Option<IpAddr>,
    pub protocol: Option<&'static str>,
    pub protocol_number: Option<u8>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub tcp_flags: Option<u8>,
    pub source_mac: Option<[u8; 6]>,
    pub destination_mac: Option<[u8; 6]>,
    pub eth_type: Option<u16>,
    pub arp_operation: Option<u16>,
    pub arp_source_ip: Option<IpAddr>,
    pub arp_destination_ip: Option<IpAddr>,
    pub icmp_type: Option<u8>,
    pub icmpv6_type: Option<u8>,
    pub scope: Value,
    pub section: Option<u32>,
    pub interface: Option<u32>,
    pub vlan_ids: Vec<u16>,
    pub auxiliary_vlan_id: Option<u16>,
    pub timestamp: Option<PacketTimestamp>,
    pub timestamp_source_ranges: Vec<SourceRange>,
    pub timestamp_source_ranges_invalid: bool,
    pub source_id: Option<String>,
    pub ranges: Vec<SourceRange>,
    pub tcp_episode: Option<u64>,
}

/// Exact capture tick metadata retained with a packet node
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketTimestamp {
    pub ticks: u64,
    pub radix: u8,
    pub exponent: u8,
    pub offset_seconds: i64,
    pub source: String,
}

/// Decode bounded packet facts from retained packet nodes
pub fn packet_facts(case: &Case) -> Vec<PacketFacts> {
    let blobs: HashMap<_, _> = case
        .blobs()
        .iter()
        .map(|blob| (blob.id.as_str(), blob.bytes.as_slice()))
        .collect();
    let source_lengths: HashMap<_, _> = case
        .sources()
        .iter()
        .map(|source| (source.id.as_str(), source.length))
        .collect();
    let episode_nodes: HashSet<_> = case
        .nodes()
        .iter()
        .filter(|node| node.kind == "tcp_episode")
        .map(|node| node.id)
        .collect();
    let episodes = packet_episodes(case, &episode_nodes);
    case.nodes()
        .iter()
        .filter(|node| node.kind == "packet")
        .map(|node| {
            facts_for_node(
                node,
                &blobs,
                &source_lengths,
                episodes.get(&node.id).copied().flatten(),
            )
        })
        .collect()
}

/// Decode the same source-bound facts from one retained capture frame
#[must_use]
pub fn frame_facts(frame: &CapturedFrame, range: SourceRange) -> PacketFacts {
    let packet_number = range.packet.unwrap_or_default();
    let metadata = frame.metadata();
    let network = decode_network_frame(metadata.link_type(), frame.bytes());
    let scope = network.as_ref().map_or_else(
        || metadata_scope(frame),
        |decoded| {
            serde_json::json!(l2_audit::ForensicScope::from_network_frame(
                metadata, decoded
            ))
        },
    );
    let mut facts = empty_facts(0, packet_number);
    facts.scope = scope;
    facts.section = Some(metadata.interface().section);
    facts.interface = Some(metadata.interface().index);
    facts.auxiliary_vlan_id = metadata.vlan().map(|tag| tag.tci & 0x0fff);
    facts.timestamp = metadata.timestamp().map(|time| PacketTimestamp {
        ticks: time.ticks(),
        radix: time.resolution().radix(),
        exponent: time.resolution().exponent(),
        offset_seconds: time.offset_seconds(),
        source: format!("{:?}", time.source()),
    });
    facts.source_id = Some(range.source.clone());
    facts.ranges.push(range);
    if let Some(network) = network.as_ref() {
        decode_frame(&mut facts, network);
    }
    facts
}

fn metadata_scope(frame: &CapturedFrame) -> Value {
    let metadata = frame.metadata();
    let interface = metadata.interface();
    serde_json::json!({
        "section": interface.section,
        "interface": interface.index,
        "vlan_ids": [],
        "vlan_aux": metadata.vlan().map(|tag| [tag.tpid, tag.tci & 0x0fff]),
    })
}

const fn empty_facts(node_id: u64, packet_number: u64) -> PacketFacts {
    PacketFacts {
        node_id,
        packet_number,
        source_ip: None,
        destination_ip: None,
        protocol: None,
        protocol_number: None,
        source_port: None,
        destination_port: None,
        tcp_flags: None,
        source_mac: None,
        destination_mac: None,
        eth_type: None,
        arp_operation: None,
        arp_source_ip: None,
        arp_destination_ip: None,
        icmp_type: None,
        icmpv6_type: None,
        scope: Value::Null,
        section: None,
        interface: None,
        vlan_ids: Vec::new(),
        auxiliary_vlan_id: None,
        timestamp: None,
        timestamp_source_ranges: Vec::new(),
        timestamp_source_ranges_invalid: false,
        source_id: None,
        ranges: Vec::new(),
        tcp_episode: None,
    }
}

fn packet_episodes(case: &Case, episode_nodes: &HashSet<u64>) -> HashMap<u64, Option<u64>> {
    let mut episodes = HashMap::new();
    for edge in case.edges() {
        if episode_nodes.contains(&edge.to) {
            episodes
                .entry(edge.from)
                .and_modify(|episode| *episode = None)
                .or_insert(Some(edge.to));
        }
    }
    episodes
}

fn facts_for_node(
    node: &Node,
    blobs: &HashMap<&str, &[u8]>,
    source_lengths: &HashMap<&str, u64>,
    tcp_episode: Option<u64>,
) -> PacketFacts {
    let packet_number = node
        .details
        .get("record")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| {
            node.ranges
                .iter()
                .find_map(|range| range.packet)
                .unwrap_or(node.id)
        });
    let mut facts = facts_from_details(node, packet_number, source_lengths);
    facts.source_id = node.ranges.first().map(|range| range.source.clone());
    facts.tcp_episode = tcp_episode;
    // Decode facts from retained bytes, not address claims in node details
    if let Some(link_type) = node
        .details
        .get("link_type")
        .and_then(Value::as_u64)
        .and_then(|raw| u16::try_from(raw).ok())
        && let Some(blob_id) = node.blob.as_deref()
        && let Some(bytes) = blobs.get(blob_id)
        && let Some(frame) = decode_network_frame(LinkType::from_raw(link_type), bytes)
    {
        // The SLL2 interface index comes from frame bytes, not saved detail claims
        if let Some(cooked) = frame.cooked() {
            if let Some(ifindex) = cooked.interface_index() {
                if let Some(scope) = facts.scope.as_object_mut() {
                    scope.insert("cooked_ifindex".to_owned(), Value::from(ifindex));
                } else {
                    facts.scope = serde_json::json!({
                        "declared_scope": std::mem::take(&mut facts.scope),
                        "cooked_ifindex": ifindex,
                    });
                }
            } else if let Some(scope) = facts.scope.as_object_mut() {
                scope.remove("cooked_ifindex");
            }
        }
        decode_frame(&mut facts, &frame);
    }
    facts
}

fn facts_from_details(
    node: &Node,
    packet_number: u64,
    source_lengths: &HashMap<&str, u64>,
) -> PacketFacts {
    let scope = node.details.get("scope").cloned().unwrap_or(Value::Null);
    let (section, interface, auxiliary_vlan_id) = scope_facts(&scope);
    let (timestamp_source_ranges, timestamp_source_ranges_invalid) = parse_timestamp_ranges(
        node.details.get("timestamp_source_ranges"),
        packet_number,
        source_lengths,
    );
    let mut facts = empty_facts(node.id, packet_number);
    facts.scope = scope;
    facts.section = section;
    facts.interface = interface;
    facts.auxiliary_vlan_id = auxiliary_vlan_id;
    facts.timestamp = parse_timestamp(node.details.get("timestamp"));
    facts.timestamp_source_ranges = timestamp_source_ranges;
    facts.timestamp_source_ranges_invalid = timestamp_source_ranges_invalid;
    facts.ranges.clone_from(&node.ranges);
    facts
}

fn decode_frame(facts: &mut PacketFacts, frame: &NetworkEnvelope<'_>) {
    if let Some(ethernet) = frame.ethernet() {
        facts.source_mac = Some(ethernet.source);
        facts.destination_mac = Some(ethernet.destination);
        facts.eth_type = match ethernet.field {
            FrameField::EtherType(value) => Some(value),
            FrameField::Length(_) => None,
        };
        facts.vlan_ids = ethernet
            .vlan_tags
            .iter()
            .map(|tag| tag.tci & 0x0fff)
            .collect();
        if let Some(arp) = l2_discovery::arp_packet(ethernet) {
            facts.protocol = Some("arp");
            facts.arp_operation = Some(arp.operation);
            facts.arp_source_ip = Some(IpAddr::from(arp.sender_ip));
            facts.arp_destination_ip = Some(IpAddr::from(arp.target_ip));
        }
    }
    // Opaque cooked protocol layouts cannot select an IP decoder
    let Some(FrameField::EtherType(protocol)) = frame.field() else {
        return;
    };
    let payload = frame.payload();
    if let Some(header) = ip_header_from_payload(protocol, payload) {
        facts.source_ip = Some(to_ip_address(header.source));
        facts.destination_ip = Some(to_ip_address(header.destination));
        facts.protocol_number = Some(header.protocol);
        facts.protocol = protocol_name(header.protocol, header.source);
        let message_type = (!header.fragmented && header.header_len < header.total_len)
            .then(|| payload.get(header.header_len))
            .flatten();
        match (header.source, header.protocol, message_type) {
            (NetworkAddress::Ipv4(_), 1, Some(message_type)) => {
                facts.icmp_type = Some(*message_type);
            }
            (NetworkAddress::Ipv6(_), 58, Some(message_type)) => {
                facts.icmpv6_type = Some(*message_type);
            }
            _ => {}
        }
    }
    let Some(packet) = ip_packet_from_payload(protocol, payload) else {
        return;
    };
    let Some(transport) = packet.transport else {
        return;
    };
    facts.source_port = Some(transport.ports.0);
    facts.destination_port = Some(transport.ports.1);
    facts.tcp_flags = match transport.header {
        TransportHeader::Tcp { flags, .. } => Some(flags),
        TransportHeader::Udp => None,
    };
}

const fn protocol_name(protocol: u8, source: NetworkAddress) -> Option<&'static str> {
    match (protocol, source) {
        (6, _) => Some("tcp"),
        (17, _) => Some("udp"),
        (1, NetworkAddress::Ipv4(_)) => Some("icmp"),
        (58, NetworkAddress::Ipv6(_)) => Some("icmpv6"),
        _ => None,
    }
}

impl PacketFacts {
    pub(super) fn matches_field(&self, name: &str, expected: &str) -> bool {
        let actual = match name {
            "frame.number" => return self.packet_number.to_string() == expected,
            "eth.src" => return mac_text(self.source_mac).as_deref() == Some(expected),
            "eth.dst" => return mac_text(self.destination_mac).as_deref() == Some(expected),
            "eth.type" => {
                return self
                    .eth_type
                    .map(|value| format!("0x{value:04x}"))
                    .as_deref()
                    == Some(expected);
            }
            "vlan.id" => return self.vlan_ids.iter().any(|id| id.to_string() == expected),
            "ip.src" => self
                .source_ip
                .filter(IpAddr::is_ipv4)
                .map(|ip| ip.to_string()),
            "ip.dst" => self
                .destination_ip
                .filter(IpAddr::is_ipv4)
                .map(|ip| ip.to_string()),
            "ip.proto" => self
                .source_ip
                .filter(IpAddr::is_ipv4)
                .and(self.protocol_number)
                .map(|number| number.to_string()),
            "ipv6.src" => self
                .source_ip
                .filter(IpAddr::is_ipv6)
                .map(|ip| ip.to_string()),
            "ipv6.dst" => self
                .destination_ip
                .filter(IpAddr::is_ipv6)
                .map(|ip| ip.to_string()),
            "ipv6.nxt" => self
                .source_ip
                .filter(IpAddr::is_ipv6)
                .and(self.protocol_number)
                .map(|number| number.to_string()),
            "tcp.srcport" if self.protocol == Some("tcp") => {
                self.source_port.map(|port| port.to_string())
            }
            "tcp.dstport" if self.protocol == Some("tcp") => {
                self.destination_port.map(|port| port.to_string())
            }
            "udp.srcport" if self.protocol == Some("udp") => {
                self.source_port.map(|port| port.to_string())
            }
            "udp.dstport" if self.protocol == Some("udp") => {
                self.destination_port.map(|port| port.to_string())
            }
            "arp.opcode" => self.arp_operation.map(|value| value.to_string()),
            "arp.src.proto_ipv4" => self.arp_source_ip.map(|ip| ip.to_string()),
            "arp.dst.proto_ipv4" => self.arp_destination_ip.map(|ip| ip.to_string()),
            "icmp.type" => self.icmp_type.map(|value| value.to_string()),
            "icmpv6.type" => self.icmpv6_type.map(|value| value.to_string()),
            _ => None,
        };
        actual.as_deref() == Some(expected)
    }

    pub(super) fn epoch_second(&self) -> Option<i64> {
        let timestamp = self.timestamp.as_ref()?;
        let whole_seconds = match (timestamp.radix, timestamp.exponent) {
            (10, exponent) if exponent <= 38 => {
                u128::from(timestamp.ticks) / 10_u128.checked_pow(u32::from(exponent))?
            }
            (2, exponent) if exponent < 64 => u128::from(timestamp.ticks) / (1_u128 << exponent),
            (2 | 10, _) => 0,
            _ => return None,
        };
        i64::try_from(whole_seconds)
            .ok()?
            .checked_add(timestamp.offset_seconds)
    }
}

pub fn mac_text(mac: Option<[u8; 6]>) -> Option<String> {
    let [first, second, third, fourth, fifth, sixth] = mac?;
    Some(format!(
        "{first:02x}:{second:02x}:{third:02x}:{fourth:02x}:{fifth:02x}:{sixth:02x}"
    ))
}

fn to_ip_address(address: NetworkAddress) -> IpAddr {
    match address {
        NetworkAddress::Ipv4(octets) => octets.into(),
        NetworkAddress::Ipv6(octets) => octets.into(),
    }
}

fn parse_timestamp(value: Option<&Value>) -> Option<PacketTimestamp> {
    let value = value?.as_object()?;
    Some(PacketTimestamp {
        ticks: value.get("ticks")?.as_u64()?,
        radix: u8::try_from(value.get("radix")?.as_u64()?).ok()?,
        exponent: u8::try_from(value.get("exponent")?.as_u64()?).ok()?,
        offset_seconds: value.get("offset_seconds")?.as_i64()?,
        source: value.get("source")?.as_str()?.to_owned(),
    })
}

fn parse_timestamp_ranges(
    value: Option<&Value>,
    packet_number: u64,
    source_lengths: &HashMap<&str, u64>,
) -> (Vec<SourceRange>, bool) {
    let Some(value) = value else {
        return (Vec::new(), false);
    };
    let Some(values) = value.as_array() else {
        return (Vec::new(), true);
    };
    let mut ranges = Vec::with_capacity(values.len().min(1024));
    let mut invalid = values.len() > 1024;
    for value in values.iter().take(1024) {
        match serde_json::from_value::<SourceRange>(value.clone()) {
            Ok(range) if timestamp_range_is_valid(&range, packet_number, source_lengths) => {
                ranges.push(range);
            }
            Ok(_) | Err(_) => invalid = true,
        }
    }
    (ranges, invalid)
}

fn timestamp_range_is_valid(
    range: &SourceRange,
    packet_number: u64,
    source_lengths: &HashMap<&str, u64>,
) -> bool {
    range.packet == Some(packet_number)
        && range.length == 8
        && source_lengths
            .get(range.source.as_str())
            .is_some_and(|source_length| {
                range
                    .offset
                    .checked_add(range.length)
                    .is_some_and(|end| end <= *source_length)
            })
}

fn scope_facts(scope: &Value) -> (Option<u32>, Option<u32>, Option<u16>) {
    let section = scope
        .get("section")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok());
    let interface = scope
        .get("interface")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok());
    let auxiliary_vlan = scope
        .get("vlan_aux")
        .and_then(Value::as_array)
        .and_then(|items| items.get(1))
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok());
    (section, interface, auxiliary_vlan)
}

#[cfg(test)]
#[path = "../../tests/query/packet.rs"]
mod tests;
