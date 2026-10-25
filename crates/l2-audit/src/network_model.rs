//! Deterministic correlations derived from bounded passive identity observations

use crate::{ForensicScope, InterfaceObservation, ProtocolIdentityObservation};
use l2_discovery::{IdentityRole, NetworkAddress, Protocol};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

const MAX_GROUP_VALUES: usize = 64;
const MAX_ADDRESS_CONFLICTS: usize = 4_096;

type VlanTags = Vec<(u16, u16)>;
type InfrastructureKey = (ForensicScope, Protocol, IdentityRole);
type ConflictKey = (ForensicScope, NetworkAddress);

/// One source-MAC-scoped node without claiming identity across capture interfaces
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NetworkNode {
    pub section: u32,
    pub interface: u32,
    pub source_mac: String,
    pub protocols: Vec<Protocol>,
    pub roles: Vec<IdentityRole>,
    pub claimed_macs: Vec<String>,
    pub addresses: Vec<NetworkAddress>,
    pub vlan_contexts: Vec<VlanTags>,
    pub evidence_packets: Vec<u64>,
    /// The complete identity inventory remains available when this summary is abbreviated
    pub truncated: bool,
}

/// Different retained ARP address claims within one capture and VLAN scope
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AddressConflict {
    pub section: u32,
    pub interface: u32,
    pub address: NetworkAddress,
    /// Outer-to-inner (TPID, VID) pairs, with priority bits removed
    pub vlan_tags: VlanTags,
    /// Auxiliary (TPID, VID) source metadata remains separate from captured tags
    pub vlan_aux: Option<(u16, u16)>,
    pub claimed_macs: Vec<String>,
    pub evidence_packets: Vec<u64>,
    pub truncated: bool,
}

/// One protocol role grouped by capture interface and normalized VLAN scope
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InfrastructureGroup {
    pub section: u32,
    pub interface: u32,
    pub protocol: Protocol,
    pub role: IdentityRole,
    /// Outer-to-inner (TPID, VID) pairs, with priority bits removed
    pub vlan_tags: VlanTags,
    /// Auxiliary (TPID, VID) source metadata remains separate from captured tags
    pub vlan_aux: Option<(u16, u16)>,
    pub source_macs: Vec<String>,
    pub addresses: Vec<NetworkAddress>,
    pub evidence_packets: Vec<u64>,
    pub truncated: bool,
}

/// Passive network correlations kept separate from policy findings
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct NetworkModel {
    pub nodes: Vec<NetworkNode>,
    pub infrastructure: Vec<InfrastructureGroup>,
    pub address_conflicts: Vec<AddressConflict>,
    /// At least one summary ceiling was reached; raw inventory remains authoritative
    pub truncated: bool,
}

#[derive(Default)]
struct NodeBuilder {
    protocols: BTreeSet<Protocol>,
    roles: BTreeSet<IdentityRole>,
    claimed_macs: BTreeSet<String>,
    addresses: BTreeSet<NetworkAddress>,
    vlan_contexts: BTreeSet<VlanTags>,
    evidence_packets: BTreeSet<u64>,
}

#[derive(Default)]
struct GroupBuilder {
    source_macs: BTreeSet<String>,
    addresses: BTreeSet<NetworkAddress>,
    evidence_packets: BTreeSet<u64>,
}

#[derive(Default)]
struct ConflictBuilder {
    claimed_macs: BTreeSet<String>,
    evidence_packets: BTreeSet<u64>,
}

/// Build a bounded, stable model from already bounded interface observations
#[must_use]
pub fn build_network_model(interfaces: &[InterfaceObservation]) -> NetworkModel {
    let mut nodes = BTreeMap::new();
    let mut groups = BTreeMap::new();
    let mut conflicts = BTreeMap::new();

    for interface in interfaces {
        for identity in &interface.identities {
            collect_node(&mut nodes, interface, identity);
            collect_infrastructure(&mut groups, interface, identity);
            collect_arp_claim(&mut conflicts, interface, identity);
        }
    }

    let (nodes, nodes_truncated) = finish_nodes(nodes);
    let (infrastructure, groups_truncated) = finish_groups(groups);
    let (address_conflicts, conflicts_truncated) = finish_conflicts(conflicts);
    NetworkModel {
        nodes,
        infrastructure,
        address_conflicts,
        truncated: nodes_truncated || groups_truncated || conflicts_truncated,
    }
}

fn collect_node(
    nodes: &mut BTreeMap<(u32, u32, String), NodeBuilder>,
    interface: &InterfaceObservation,
    identity: &ProtocolIdentityObservation,
) {
    let node = nodes
        .entry((
            interface.section,
            interface.index,
            identity.source_mac.clone(),
        ))
        .or_default();
    node.protocols.insert(identity.protocol);
    node.roles.insert(identity.role);
    if let Some(claimed) = &identity.claimed_mac {
        node.claimed_macs.insert(claimed.clone());
    }
    if let Some(address) = identity.address {
        node.addresses.insert(address);
    }
    node.vlan_contexts.insert(identity.vlan_tags.clone());
    node.evidence_packets.insert(identity.packet);
}

fn collect_infrastructure(
    groups: &mut BTreeMap<InfrastructureKey, GroupBuilder>,
    interface: &InterfaceObservation,
    identity: &ProtocolIdentityObservation,
) {
    if !matches!(
        identity.role,
        IdentityRole::DhcpServer | IdentityRole::Ipv6Router | IdentityRole::FirstHopRouter
    ) {
        return;
    }
    let group = groups
        .entry((scope(interface, identity), identity.protocol, identity.role))
        .or_default();
    group.source_macs.insert(identity.source_mac.clone());
    if let Some(address) = identity.address {
        group.addresses.insert(address);
    }
    group.evidence_packets.insert(identity.packet);
}

fn collect_arp_claim(
    conflicts: &mut BTreeMap<ConflictKey, ConflictBuilder>,
    interface: &InterfaceObservation,
    identity: &ProtocolIdentityObservation,
) {
    if identity.protocol != Protocol::Arp || identity.role != IdentityRole::AddressClaim {
        return;
    }
    let (Some(address), Some(claimed_mac)) = (identity.address, &identity.claimed_mac) else {
        return;
    };
    let scope = scope(interface, identity);
    if !scope.supports_binding_comparison() {
        return;
    }
    let conflict = conflicts.entry((scope, address)).or_default();
    conflict.claimed_macs.insert(claimed_mac.clone());
    conflict.evidence_packets.insert(identity.packet);
}

fn scope(
    interface: &InterfaceObservation,
    identity: &ProtocolIdentityObservation,
) -> ForensicScope {
    ForensicScope::from_parts(
        l2_capture::InterfaceId {
            section: interface.section,
            index: interface.index,
        },
        identity.vlan_tags.iter().copied(),
        identity.vlan_aux,
    )
}

fn finish_nodes(builders: BTreeMap<(u32, u32, String), NodeBuilder>) -> (Vec<NetworkNode>, bool) {
    let mut any_truncated = false;
    let nodes = builders
        .into_iter()
        .map(|((section, interface, source_mac), builder)| {
            // Protocol and role enums have fewer than the 64-value summary bound
            let (protocols, _) = bounded(builder.protocols);
            let (roles, _) = bounded(builder.roles);
            let (claimed_macs, claimed_truncated) = bounded(builder.claimed_macs);
            let (addresses, addresses_truncated) = bounded(builder.addresses);
            let (vlan_contexts, vlans_truncated) = bounded(builder.vlan_contexts);
            let (evidence_packets, evidence_truncated) = bounded(builder.evidence_packets);
            let truncated =
                claimed_truncated || addresses_truncated || vlans_truncated || evidence_truncated;
            any_truncated |= truncated;
            NetworkNode {
                section,
                interface,
                source_mac,
                protocols,
                roles,
                claimed_macs,
                addresses,
                vlan_contexts,
                evidence_packets,
                truncated,
            }
        })
        .collect();
    (nodes, any_truncated)
}

fn finish_groups(
    builders: BTreeMap<InfrastructureKey, GroupBuilder>,
) -> (Vec<InfrastructureGroup>, bool) {
    let mut any_truncated = false;
    let groups = builders
        .into_iter()
        .map(|((scope, protocol, role), builder)| {
            let (source_macs, sources_truncated) = bounded(builder.source_macs);
            let (addresses, addresses_truncated) = bounded(builder.addresses);
            let (evidence_packets, evidence_truncated) = bounded(builder.evidence_packets);
            let truncated = sources_truncated || addresses_truncated || evidence_truncated;
            any_truncated |= truncated;
            InfrastructureGroup {
                section: scope.section,
                interface: scope.interface,
                protocol,
                role,
                vlan_tags: scope.vlan_ids,
                vlan_aux: scope.vlan_aux,
                source_macs,
                addresses,
                evidence_packets,
                truncated,
            }
        })
        .collect();
    (groups, any_truncated)
}

fn finish_conflicts(
    builders: BTreeMap<ConflictKey, ConflictBuilder>,
) -> (Vec<AddressConflict>, bool) {
    let mut output = Vec::new();
    let mut any_truncated = false;
    for ((scope, address), builder) in builders {
        if builder.claimed_macs.len() < 2 {
            continue;
        }
        if output.len() == MAX_ADDRESS_CONFLICTS {
            any_truncated = true;
            break;
        }
        let (claimed_macs, claims_truncated) = bounded(builder.claimed_macs);
        let (evidence_packets, evidence_truncated) = bounded(builder.evidence_packets);
        let truncated = claims_truncated || evidence_truncated;
        any_truncated |= truncated;
        output.push(AddressConflict {
            section: scope.section,
            interface: scope.interface,
            address,
            vlan_tags: scope.vlan_ids,
            vlan_aux: scope.vlan_aux,
            claimed_macs,
            evidence_packets,
            truncated,
        });
    }
    (output, any_truncated)
}

fn bounded<T: Ord>(values: BTreeSet<T>) -> (Vec<T>, bool) {
    let truncated = values.len() > MAX_GROUP_VALUES;
    (
        values.into_iter().take(MAX_GROUP_VALUES).collect(),
        truncated,
    )
}
