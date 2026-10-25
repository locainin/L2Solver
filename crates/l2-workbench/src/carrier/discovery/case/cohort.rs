//! Expand one verified endpoint cohort across its original connection tuples

use super::super::model::{DiscoveryError, DiscoveryView};
use super::context::{PacketEndpoints, packet_endpoints, packet_payload_is_empty};
use crate::evidence::{Blob, Case, Node};
use std::collections::{HashMap, HashSet};

pub(super) struct CohortSelection {
    pub(super) packets: Vec<(u64, Option<u64>)>,
    pub(super) omitted_empty_sample_ids: Vec<u64>,
    pub(super) direction: String,
    pub(super) local_identity: String,
}

#[derive(Clone, Copy)]
struct CohortIdentity<'a> {
    scope: &'a serde_json::Value,
    endpoint: &'a str,
    local_address: &'a str,
    direction: &'a str,
    protocol: u8,
    protocol_name: &'static str,
    port: u16,
}

pub(super) fn members(
    case: &Case,
    cohort: &Node,
    nodes: &HashMap<u64, &Node>,
    blobs: &HashMap<&str, &Blob>,
    view: DiscoveryView,
    max_input_bytes: usize,
) -> Result<CohortSelection, DiscoveryError> {
    let identity = read_identity(cohort)?;
    let edges = edge_indexes(case)?;
    let series_ids = edges
        .includes_connection
        .get(&cohort.id)
        .ok_or(DiscoveryError::InvalidSelection)?;
    let mut collector = PacketCollector::new(identity, view, nodes, blobs, max_input_bytes);
    for series_id in series_ids {
        let series = nodes
            .get(series_id)
            .copied()
            .filter(|node| node.kind == "carrier_series")
            .ok_or(DiscoveryError::InvalidCaseMapping {
                node_id: *series_id,
            })?;
        let endpoints = validate_series(series, &identity)?;
        collector.append_series(
            series,
            endpoints,
            edges.supports.get(series_id).map_or(&[][..], Vec::as_slice),
        )?;
    }
    collector
        .selected_packets
        .sort_unstable_by_key(|(node_id, _)| {
            nodes
                .get(node_id)
                .and_then(|node| node.details.get("record"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(*node_id)
        });
    if collector.selected_packets.is_empty() {
        return Err(DiscoveryError::InvalidSelection);
    }
    Ok(CohortSelection {
        packets: collector.selected_packets,
        omitted_empty_sample_ids: collector.omitted_empty_sample_ids,
        direction: format!(
            "{} {} {}",
            identity.protocol_name,
            identity.direction,
            socket_text(identity.endpoint, identity.port)
        ),
        local_identity: format!("{} {}", identity.protocol_name, identity.local_address),
    })
}

fn read_identity(cohort: &Node) -> Result<CohortIdentity<'_>, DiscoveryError> {
    let error = || DiscoveryError::UnresolvedCaseContext { node_id: cohort.id };
    let scope = cohort.details.get("scope").ok_or_else(error)?;
    let endpoint = cohort
        .details
        .get("endpoint")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(error)?;
    let local_address = cohort
        .details
        .get("local_address")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(error)?;
    let direction = cohort
        .details
        .get("direction")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(error)?;
    let protocol = number_u8(cohort, "protocol").ok_or_else(error)?;
    let protocol_name = protocol_name(protocol).ok_or_else(error)?;
    let port = number_u16(cohort, "port").ok_or_else(error)?;
    if endpoint.is_empty()
        || local_address.is_empty()
        || !matches!(direction, "to_endpoint" | "from_endpoint")
    {
        return Err(error());
    }
    Ok(CohortIdentity {
        scope,
        endpoint,
        local_address,
        direction,
        protocol,
        protocol_name,
        port,
    })
}

fn number_u8(node: &Node, key: &str) -> Option<u8> {
    u8::try_from(node.details.get(key)?.as_u64()?).ok()
}

fn number_u16(node: &Node, key: &str) -> Option<u16> {
    u16::try_from(node.details.get(key)?.as_u64()?).ok()
}

const fn protocol_name(protocol: u8) -> Option<&'static str> {
    match protocol {
        6 => Some("tcp"),
        17 => Some("udp"),
        _ => None,
    }
}

struct CohortEdges {
    includes_connection: HashMap<u64, Vec<u64>>,
    supports: HashMap<u64, Vec<u64>>,
}

fn edge_indexes(case: &Case) -> Result<CohortEdges, DiscoveryError> {
    let mut includes_connection: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut supports: HashMap<u64, Vec<u64>> = HashMap::new();
    includes_connection
        .try_reserve(case.edges().len())
        .map_err(|_| DiscoveryError::AllocationFailed)?;
    supports
        .try_reserve(case.edges().len())
        .map_err(|_| DiscoveryError::AllocationFailed)?;
    for edge in case.edges() {
        match edge.relation.as_str() {
            "includes_connection" => includes_connection
                .entry(edge.from)
                .or_default()
                .push(edge.to),
            "supports" => supports.entry(edge.to).or_default().push(edge.from),
            _ => {}
        }
    }
    Ok(CohortEdges {
        includes_connection,
        supports,
    })
}

fn validate_series(
    series: &Node,
    identity: &CohortIdentity<'_>,
) -> Result<PacketEndpoints, DiscoveryError> {
    if series.details.get("scope") != Some(identity.scope) {
        return Err(DiscoveryError::MixedIdentity);
    }
    let endpoints = series_endpoints(series)
        .ok_or(DiscoveryError::InvalidCaseMapping { node_id: series.id })?;
    if !matches_identity(endpoints, identity) {
        return Err(DiscoveryError::MixedIdentity);
    }
    Ok(endpoints)
}

struct PacketCollector<'case, 'nodes, 'identity> {
    identity: CohortIdentity<'identity>,
    view: DiscoveryView,
    nodes: &'nodes HashMap<u64, &'case Node>,
    blobs: &'nodes HashMap<&'case str, &'case Blob>,
    max_input_bytes: usize,
    seen_packets: HashSet<u64>,
    selected_packets: Vec<(u64, Option<u64>)>,
    omitted_empty_sample_ids: Vec<u64>,
}

impl<'case, 'nodes, 'identity> PacketCollector<'case, 'nodes, 'identity> {
    fn new(
        identity: CohortIdentity<'identity>,
        view: DiscoveryView,
        nodes: &'nodes HashMap<u64, &'case Node>,
        blobs: &'nodes HashMap<&'case str, &'case Blob>,
        max_input_bytes: usize,
    ) -> Self {
        Self {
            identity,
            view,
            nodes,
            blobs,
            max_input_bytes,
            seen_packets: HashSet::new(),
            selected_packets: Vec::new(),
            omitted_empty_sample_ids: Vec::new(),
        }
    }

    fn append_series(
        &mut self,
        series: &Node,
        endpoints: PacketEndpoints,
        packet_ids: &[u64],
    ) -> Result<(), DiscoveryError> {
        for packet_id in packet_ids {
            self.append_packet(series, endpoints, *packet_id)?;
        }
        Ok(())
    }

    fn append_packet(
        &mut self,
        series: &Node,
        endpoints: PacketEndpoints,
        packet_id: u64,
    ) -> Result<(), DiscoveryError> {
        let Some(packet) = self.nodes.get(&packet_id).copied() else {
            return Ok(());
        };
        if packet.kind != "packet" {
            return Ok(());
        }
        if packet.details.get("scope") != Some(self.identity.scope)
            || packet_endpoints(packet, self.blobs)? != endpoints
            || !self.seen_packets.insert(packet.id)
        {
            return Err(DiscoveryError::InvalidCaseMapping { node_id: packet.id });
        }
        // Empty transport payloads still identify a real connection packet but cannot form a byte sample
        if self.view == DiscoveryView::Payload && packet_payload_is_empty(packet, self.blobs)? {
            self.omitted_empty_sample_ids
                .try_reserve(1)
                .map_err(|_| DiscoveryError::AllocationFailed)?;
            self.omitted_empty_sample_ids.push(packet.id);
        } else {
            self.selected_packets
                .try_reserve(1)
                .map_err(|_| DiscoveryError::AllocationFailed)?;
            self.selected_packets.push((packet.id, Some(series.id)));
        }
        let selected_count = self
            .selected_packets
            .len()
            .checked_add(self.omitted_empty_sample_ids.len())
            .ok_or(DiscoveryError::InvalidSelection)?;
        if selected_count > self.max_input_bytes {
            return Err(DiscoveryError::InputBudgetExceeded {
                observed: selected_count,
                limit: self.max_input_bytes,
            });
        }
        Ok(())
    }
}

fn series_endpoints(node: &Node) -> Option<PacketEndpoints> {
    let source = serde_json::from_value(node.details.get("source")?.clone()).ok()?;
    let destination = serde_json::from_value(node.details.get("destination")?.clone()).ok()?;
    let ports = node.details.get("ports")?.as_array()?;
    let (Some(source_port), Some(destination_port)) = (ports.first(), ports.get(1)) else {
        return None;
    };
    Some(PacketEndpoints {
        protocol: number_u8(node, "protocol")?,
        source,
        destination,
        ports: Some((
            u16::try_from(source_port.as_u64()?).ok()?,
            u16::try_from(destination_port.as_u64()?).ok()?,
        )),
    })
}

fn matches_identity(tuple: PacketEndpoints, identity: &CohortIdentity<'_>) -> bool {
    if tuple.protocol != identity.protocol {
        return false;
    }
    let Some((source_port, destination_port)) = tuple.ports else {
        return false;
    };
    match identity.direction {
        "to_endpoint" => {
            tuple.destination.to_string() == identity.endpoint
                && destination_port == identity.port
                && tuple.source.to_string() == identity.local_address
        }
        "from_endpoint" => {
            tuple.source.to_string() == identity.endpoint
                && source_port == identity.port
                && tuple.destination.to_string() == identity.local_address
        }
        _ => false,
    }
}

fn socket_text(address: &str, port: u16) -> String {
    if address.contains(':') {
        format!("[{address}]:{port}")
    } else {
        format!("{address}:{port}")
    }
}
