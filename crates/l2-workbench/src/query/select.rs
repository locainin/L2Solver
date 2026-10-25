use super::{
    Selector,
    packet::{PacketFacts, packet_facts},
};
use crate::evidence::{Case, Edge, EvidenceStatus, Node, SourceRange};
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};

/// Evidence source for a VLAN filter match
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VlanEvidenceSource {
    /// VLAN tag decoded directly from retained Ethernet bytes
    InBandBytes,
    /// VLAN value copied from capture-parser auxiliary metadata
    CaptureParserMetadata,
}

/// One packet's evidence for a selected VLAN ID
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct VlanEvidence {
    /// Original one-based packet record number
    pub packet_number: u64,
    /// Selected VLAN identifier
    pub vlan_id: u16,
    /// Exact fact source used for this VLAN value
    pub source: VlanEvidenceSource,
}

/// One node selected by the filters and its directly supporting packet numbers
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueryMatch {
    /// Stable evidence node identifier
    pub node_id: u64,
    /// Exact stored node kind
    pub kind: String,
    /// Packet record numbers that matched the packet-specific filters
    pub packet_numbers: Vec<u64>,
    /// Source locations copied from the selected node
    pub source_ranges: Vec<SourceRange>,
    /// Statuses on directly connected graph edges
    pub statuses: Vec<EvidenceStatus>,
    /// Exact byte or parser-metadata facts supporting a VLAN filter
    pub vlan_evidence: Vec<VlanEvidence>,
}

/// Select evidence using explicit node, packet, and graph-edge filters
#[must_use]
pub fn select(case: &Case, selector: &Selector) -> Vec<QueryMatch> {
    let facts = packet_facts(case);
    let packets = PacketIndex::new(&facts);
    let edge_index = edge_index(case);
    case.nodes()
        .iter()
        .filter_map(|node| {
            select_node(
                node,
                selector,
                &packets,
                edge_index.get(&node.id).map_or(&[], Vec::as_slice),
            )
        })
        .collect()
}

struct PacketIndex<'a> {
    nodes: HashMap<u64, &'a PacketFacts>,
    references: HashMap<(&'a str, u64), Vec<&'a PacketFacts>>,
}

impl<'a> PacketIndex<'a> {
    fn new(facts: &'a [PacketFacts]) -> Self {
        let nodes = facts.iter().map(|fact| (fact.node_id, fact)).collect();
        let mut references: HashMap<_, Vec<_>> = HashMap::new();
        for fact in facts {
            if let Some(source) = fact.source_id.as_deref() {
                references
                    .entry((source, fact.packet_number))
                    .or_default()
                    .push(fact);
            }
        }
        Self { nodes, references }
    }

    fn supporting_nodes(&self, node: &Node, edges: &[&Edge]) -> BTreeSet<u64> {
        // A packet is selected using its own bytes, never a neighboring packet's facts
        if self.nodes.contains_key(&node.id) {
            return BTreeSet::from([node.id]);
        }
        let mut candidates = BTreeSet::new();
        for range in &node.ranges {
            if let Some(packet) = range.packet
                && let Some(facts) = self.references.get(&(range.source.as_str(), packet))
            {
                candidates.extend(facts.iter().map(|fact| fact.node_id));
            }
        }
        // Only direct packet links and explicit ranges count as support; graph reachability is not proof
        for edge in edges {
            let other = if edge.from == node.id {
                edge.to
            } else {
                edge.from
            };
            if self.nodes.contains_key(&other) {
                candidates.insert(other);
            }
        }
        candidates
    }
}

fn edge_index(case: &Case) -> HashMap<u64, Vec<&Edge>> {
    let mut index = HashMap::new();
    for edge in case.edges() {
        index.entry(edge.from).or_insert_with(Vec::new).push(edge);
        index.entry(edge.to).or_insert_with(Vec::new).push(edge);
    }
    index
}

fn select_node(
    node: &Node,
    selector: &Selector,
    packets: &PacketIndex<'_>,
    edges: &[&Edge],
) -> Option<QueryMatch> {
    if selector
        .kind
        .as_ref()
        .is_some_and(|kind| kind != &node.kind)
    {
        return None;
    }
    let mut statuses = Vec::new();
    let mut matched_packets = BTreeSet::new();
    let mut packet_ranges = Vec::new();
    let mut vlan_evidence = Vec::new();
    for id in packets.supporting_nodes(node, edges) {
        if let Some(facts) = packets.nodes.get(&id)
            && packet_matches(facts, selector)
        {
            matched_packets.insert(facts.packet_number);
            extend_ranges(&mut packet_ranges, &facts.ranges);
            record_vlan_evidence(&mut vlan_evidence, facts, selector);
        }
    }
    if selector.has_network_filter() && matched_packets.is_empty() {
        return None;
    }
    // A status selects a saved relation, independently of which supporting packet matched
    for edge in edges {
        push_status(&mut statuses, edge.status);
    }
    if selector
        .status
        .is_some_and(|wanted| !statuses.contains(&wanted))
    {
        return None;
    }
    let mut source_ranges = node.ranges.clone();
    extend_ranges(&mut source_ranges, &packet_ranges);
    Some(QueryMatch {
        node_id: node.id,
        kind: node.kind.clone(),
        packet_numbers: matched_packets.into_iter().collect(),
        source_ranges,
        statuses: statuses.into_iter().collect(),
        vlan_evidence,
    })
}

fn record_vlan_evidence(
    evidence: &mut Vec<VlanEvidence>,
    facts: &PacketFacts,
    selector: &Selector,
) {
    let Some(vlan_id) = selector.vlan else {
        return;
    };
    let mut sources = Vec::new();
    if facts.vlan_ids.contains(&vlan_id) {
        sources.push(VlanEvidenceSource::InBandBytes);
    }
    if facts.auxiliary_vlan_id == Some(vlan_id) {
        sources.push(VlanEvidenceSource::CaptureParserMetadata);
    }
    for source in sources {
        let fact = VlanEvidence {
            packet_number: facts.packet_number,
            vlan_id,
            source,
        };
        if !evidence.contains(&fact) {
            evidence.push(fact);
        }
    }
}

fn extend_ranges(target: &mut Vec<SourceRange>, source: &[SourceRange]) {
    for range in source {
        if !target.contains(range) {
            target.push(range.clone());
        }
    }
}

fn push_status(statuses: &mut Vec<EvidenceStatus>, status: EvidenceStatus) {
    if !statuses.contains(&status) {
        statuses.push(status);
    }
}

fn packet_matches(facts: &PacketFacts, selector: &Selector) -> bool {
    if selector
        .packet_range
        .is_some_and(|range| facts.packet_number < range.first || facts.packet_number > range.last)
    {
        return false;
    }
    if selector.time_range.is_some_and(|range| {
        facts
            .epoch_second()
            .is_none_or(|second| second < range.first || second > range.last)
    }) {
        return false;
    }
    if selector.ip.is_some_and(|network| {
        let matched = match selector.ip_direction {
            super::IpDirection::Either => {
                facts.source_ip.is_some_and(|ip| network.contains(ip))
                    || facts.destination_ip.is_some_and(|ip| network.contains(ip))
            }
            super::IpDirection::Source => facts.source_ip.is_some_and(|ip| network.contains(ip)),
            super::IpDirection::Destination => {
                facts.destination_ip.is_some_and(|ip| network.contains(ip))
            }
        };
        !matched
    }) {
        return false;
    }
    if selector
        .source_ip
        .is_some_and(|network| !facts.source_ip.is_some_and(|ip| network.contains(ip)))
        || selector
            .destination_ip
            .is_some_and(|network| !facts.destination_ip.is_some_and(|ip| network.contains(ip)))
    {
        return false;
    }
    if selector.protocol.as_deref().is_some_and(|protocol| {
        protocol.parse::<u8>().map_or_else(
            |_| facts.protocol != Some(protocol),
            |number| facts.protocol_number != Some(number),
        )
    }) {
        return false;
    }
    if selector
        .fields
        .iter()
        .any(|field| !facts.matches_field(&field.name, &field.value))
    {
        return false;
    }
    if selector
        .source_port
        .is_some_and(|port| facts.source_port != Some(port))
        || selector
            .destination_port
            .is_some_and(|port| facts.destination_port != Some(port))
        || selector.port.is_some_and(|port| {
            facts.source_port != Some(port) && facts.destination_port != Some(port)
        })
    {
        return false;
    }
    if selector.interface.is_some_and(|scope| {
        facts.section != Some(scope.section) || facts.interface != Some(scope.index)
    }) || selector.vlan.is_some_and(|vlan| {
        !facts.vlan_ids.contains(&vlan) && facts.auxiliary_vlan_id != Some(vlan)
    }) {
        return false;
    }
    true
}
