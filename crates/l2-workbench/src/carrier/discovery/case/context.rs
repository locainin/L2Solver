//! Resolve packet and stream identity without dropping each sample's original tuple

use super::super::model::{DiscoveryError, DiscoveryMapping};
use crate::evidence::{Blob, Node};
use std::collections::{BTreeSet, HashMap};

pub(super) struct CaseContext {
    pub(super) source_scope: String,
    pub(super) direction: String,
    pub(super) local_identity: String,
    pub(super) session_id: u64,
    pub(super) sequence: u64,
    pub(super) ambiguous: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PacketEndpoints {
    pub(super) protocol: u8,
    pub(super) source: l2_discovery::NetworkAddress,
    pub(super) destination: l2_discovery::NetworkAddress,
    pub(super) ports: Option<(u16, u16)>,
}

struct RawContext<'a> {
    scope: Option<&'a serde_json::Value>,
    source: Option<String>,
    destination: Option<String>,
    protocol: String,
    session_id: u64,
    sequence: Option<u64>,
    ambiguous: bool,
}

pub(super) fn case_context(
    node: &Node,
    nodes: &HashMap<u64, &Node>,
    blobs: &HashMap<&str, &Blob>,
    packet_episodes: &HashMap<u64, Vec<u64>>,
    contains: &HashMap<u64, Vec<u64>>,
    mappings: &[DiscoveryMapping],
    session_fallback: Option<u64>,
) -> Result<CaseContext, DiscoveryError> {
    let raw = match node.kind.as_str() {
        "packet" => packet_context(node, blobs, packet_episodes, session_fallback)?,
        "udp_payload" => udp_context(node),
        "tcp_byte_run" => tcp_context(node, nodes, contains)?,
        _ => return Err(DiscoveryError::UnsupportedNodeKind { node_id: node.id }),
    };
    finish_context(node, mappings, raw)
}

fn packet_context<'a>(
    node: &'a Node,
    blobs: &HashMap<&str, &Blob>,
    packet_episodes: &HashMap<u64, Vec<u64>>,
    session_fallback: Option<u64>,
) -> Result<RawContext<'a>, DiscoveryError> {
    let endpoints = packet_endpoints(node, blobs)?;
    let protocol = protocol_label(endpoints.protocol);
    let source = socket_identity(endpoints.source, endpoints.ports.map(|(source, _)| source));
    let destination = socket_identity(
        endpoints.destination,
        endpoints.ports.map(|(_, destination)| destination),
    );
    let episodes = packet_episodes.get(&node.id);
    let session_id = episodes
        .filter(|episodes| episodes.len() == 1)
        .and_then(|episodes| episodes.first())
        .copied()
        .or(session_fallback)
        .unwrap_or(node.id);
    let ambiguous = node
        .details
        .get("truncated")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
        || node
            .details
            .get("fragmented")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
        || episodes.is_some_and(|episodes| episodes.len() != 1);
    Ok(RawContext {
        scope: node.details.get("scope"),
        source: Some(source),
        destination: Some(destination),
        protocol,
        session_id,
        sequence: node
            .details
            .get("record")
            .and_then(serde_json::Value::as_u64),
        ambiguous,
    })
}

fn udp_context(node: &Node) -> RawContext<'_> {
    RawContext {
        scope: node.details.get("scope"),
        source: node.details.get("source").and_then(endpoint_identity),
        destination: node.details.get("destination").and_then(endpoint_identity),
        protocol: "udp".to_owned(),
        session_id: node.id,
        sequence: node
            .details
            .get("available_at_record")
            .and_then(serde_json::Value::as_u64),
        ambiguous: node
            .details
            .get("identity_ambiguous")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
            || node
                .details
                .get("from_fragments")
                .and_then(serde_json::Value::as_bool)
                == Some(true),
    }
}

fn tcp_context<'a>(
    node: &Node,
    nodes: &HashMap<u64, &'a Node>,
    contains: &HashMap<u64, Vec<u64>>,
) -> Result<RawContext<'a>, DiscoveryError> {
    let direction = containing_node(node.id, nodes, contains, "tcp_direction")
        .ok_or(DiscoveryError::UnresolvedCaseContext { node_id: node.id })?;
    let episode = containing_node(direction.id, nodes, contains, "tcp_episode")
        .ok_or(DiscoveryError::UnresolvedCaseContext { node_id: node.id })?;
    Ok(RawContext {
        scope: episode.details.get("scope"),
        source: direction.details.get("source").and_then(endpoint_identity),
        destination: direction
            .details
            .get("destination")
            .and_then(endpoint_identity),
        protocol: "tcp".to_owned(),
        session_id: episode.id,
        sequence: node
            .details
            .get("offset")
            .and_then(serde_json::Value::as_u64),
        ambiguous: node
            .details
            .get("start_known")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
            || node
                .details
                .get("generation_ambiguous")
                .and_then(serde_json::Value::as_bool)
                == Some(true)
            || direction
                .details
                .get("sequence_ambiguous")
                .and_then(serde_json::Value::as_bool)
                != Some(false),
    })
}

fn containing_node<'a>(
    child_id: u64,
    nodes: &HashMap<u64, &'a Node>,
    contains: &HashMap<u64, Vec<u64>>,
    kind: &str,
) -> Option<&'a Node> {
    let mut parent = None;
    for parent_id in contains.get(&child_id)? {
        let Some(candidate) = nodes
            .get(parent_id)
            .copied()
            .filter(|candidate| candidate.kind == kind)
        else {
            continue;
        };
        // Repeated edges to one parent are harmless, but distinct matching parents leave context unresolved
        if parent.is_some_and(|parent: &Node| parent.id != candidate.id) {
            return None;
        }
        parent = Some(candidate);
    }
    parent
}

fn finish_context(
    node: &Node,
    mappings: &[DiscoveryMapping],
    raw: RawContext<'_>,
) -> Result<CaseContext, DiscoveryError> {
    let error = || DiscoveryError::UnresolvedCaseContext { node_id: node.id };
    let scope = raw.scope.ok_or_else(error)?;
    let source = raw.source.ok_or_else(error)?;
    let destination = raw.destination.ok_or_else(error)?;
    let sequence = raw.sequence.ok_or_else(error)?;
    let source_ids: BTreeSet<_> = mappings
        .iter()
        .map(|mapping| mapping.range.source.as_str())
        .collect();
    let source_scope = serde_json::to_string(&(scope, source_ids)).map_err(|_| error())?;
    Ok(CaseContext {
        source_scope,
        direction: format!(
            "{} {source} -> {} {destination}",
            raw.protocol, raw.protocol
        ),
        local_identity: format!("{} {source}", raw.protocol),
        session_id: raw.session_id,
        sequence,
        ambiguous: raw.ambiguous,
    })
}

pub(super) fn endpoint_identity(value: &serde_json::Value) -> Option<String> {
    if let Some(identity) = value.as_str() {
        return Some(identity.to_owned());
    }
    let address =
        serde_json::from_value::<l2_discovery::NetworkAddress>(value.get("address")?.clone())
            .ok()?;
    let port = u16::try_from(value.get("port")?.as_u64()?).ok()?;
    Some(socket_identity(address, Some(port)))
}

pub(super) fn packet_endpoints(
    node: &Node,
    blobs: &HashMap<&str, &Blob>,
) -> Result<PacketEndpoints, DiscoveryError> {
    let blob_id = node
        .blob
        .as_deref()
        .ok_or(DiscoveryError::MissingBlob { node_id: node.id })?;
    let bytes = blobs
        .get(blob_id)
        .map(|blob| blob.bytes.as_slice())
        .ok_or(DiscoveryError::MissingBlob { node_id: node.id })?;
    let frame = l2_core::decode(bytes)
        .map_err(|_| DiscoveryError::UnresolvedCaseContext { node_id: node.id })?;
    let ip = l2_discovery::ip_packet(&frame)
        .filter(|packet| !packet.fragmented)
        .ok_or(DiscoveryError::UnresolvedCaseContext { node_id: node.id })?;
    Ok(PacketEndpoints {
        protocol: ip.protocol,
        source: ip.source,
        destination: ip.destination,
        ports: ip.transport.map(|transport| transport.ports),
    })
}

pub(super) fn packet_payload_is_empty(
    node: &Node,
    blobs: &HashMap<&str, &Blob>,
) -> Result<bool, DiscoveryError> {
    let blob_id = node
        .blob
        .as_deref()
        .ok_or(DiscoveryError::MissingBlob { node_id: node.id })?;
    let bytes = blobs
        .get(blob_id)
        .map(|blob| blob.bytes.as_slice())
        .ok_or(DiscoveryError::MissingBlob { node_id: node.id })?;
    let frame = l2_core::decode(bytes)
        .map_err(|_| DiscoveryError::InvalidPacketPayload { node_id: node.id })?;
    let ip = l2_discovery::ip_packet(&frame)
        .filter(|packet| !packet.fragmented)
        .ok_or(DiscoveryError::InvalidPacketPayload { node_id: node.id })?;
    let transport = ip
        .transport
        .ok_or(DiscoveryError::InvalidPacketPayload { node_id: node.id })?;
    Ok(transport.payload.is_empty())
}

fn protocol_label(protocol: u8) -> String {
    match protocol {
        6 => "tcp".to_owned(),
        17 => "udp".to_owned(),
        _ => format!("ip-{protocol}"),
    }
}

fn socket_identity(address: l2_discovery::NetworkAddress, port: Option<u16>) -> String {
    let address = address.to_string();
    match (address.contains(':'), port) {
        (true, Some(port)) => format!("[{address}]:{port}"),
        (false, Some(port)) => format!("{address}:{port}"),
        (_, None) => address,
    }
}
