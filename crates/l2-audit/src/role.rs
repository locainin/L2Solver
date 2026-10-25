//! Conservative port-role inference from passive inventory facts

use crate::{FingerprintStatus, InterfaceObservation, Protocol, Vid};
use serde::Serialize;
use std::{collections::BTreeSet, fmt};

const MAX_ROLE_EVIDENCE: usize = 8;
const MAX_ROLE_REASONS: usize = 8;

/// A likely port role inferred from a bounded passive sample
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PortRole {
    Unknown,
    EndpointAccess,
    MultiEndpoint,
    TaggedTrunk,
    SwitchUplink,
    AggregatedLink,
}

impl fmt::Display for PortRole {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Unknown => "unknown",
            Self::EndpointAccess => "endpoint access candidate",
            Self::MultiEndpoint => "multi-endpoint candidate",
            Self::TaggedTrunk => "tagged trunk candidate",
            Self::SwitchUplink => "switch uplink candidate",
            Self::AggregatedLink => "aggregated link candidate",
        };
        output.write_str(name)
    }
}

/// Evidence and scope behind one non-authoritative port-role inference
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PortRoleInference {
    pub section: u32,
    pub interface: u32,
    pub role: PortRole,
    pub reasons: Vec<String>,
    pub evidence_packets: Vec<u64>,
}

struct RoleSignals {
    aggregation: Vec<Protocol>,
    has_stp: bool,
    infrastructure: Vec<Protocol>,
    nested_tags: bool,
    ordinary_vlans: BTreeSet<u16>,
}

/// Infer a likely port role without turning absence of traffic into proof
#[must_use]
pub fn infer_port_role(interface: &InterfaceObservation) -> PortRoleInference {
    let signals = role_signals(interface);
    let mut evidence = Vec::new();
    let mut reasons = Vec::new();
    let role = classify_role(interface, &signals, &mut evidence, &mut reasons);

    evidence.sort_unstable();
    evidence.dedup();
    evidence.truncate(MAX_ROLE_EVIDENCE);
    reasons.truncate(MAX_ROLE_REASONS);
    PortRoleInference {
        section: interface.section,
        interface: interface.index,
        role,
        reasons,
        evidence_packets: evidence,
    }
}

fn role_signals(interface: &InterfaceObservation) -> RoleSignals {
    RoleSignals {
        ordinary_vlans: ordinary_vlans(interface),
        nested_tags: interface.vlans.iter().any(|vlan| vlan.tags.len() > 1),
        aggregation: observed_protocols(interface, &[Protocol::Lacp, Protocol::Pagp]),
        infrastructure: observed_protocols(
            interface,
            &[
                Protocol::Cdp,
                Protocol::Dtp,
                Protocol::PvstPlus,
                Protocol::Vtp,
            ],
        ),
        has_stp: interface.stp_frames > 0 || !interface.stp.is_empty(),
    }
}

fn classify_role(
    interface: &InterfaceObservation,
    signals: &RoleSignals,
    evidence: &mut Vec<u64>,
    reasons: &mut Vec<String>,
) -> PortRole {
    if !signals.aggregation.is_empty() {
        return aggregation_role(interface, signals, evidence, reasons);
    }
    if !signals.infrastructure.is_empty()
        && (signals.has_stp || !interface.neighbors.is_empty())
        && signals.ordinary_vlans.len() >= 2
    {
        return uplink_role(interface, signals, evidence, reasons);
    }
    if signals.ordinary_vlans.len() >= 3 || signals.nested_tags {
        return trunk_role(interface, signals, evidence, reasons);
    }
    if interface.macs.len() >= 4 {
        return multi_endpoint_role(interface, evidence, reasons);
    }
    if interface.untagged_packet.is_some()
        && !interface.macs.is_empty()
        && interface.macs.len() <= 3
        && signals.ordinary_vlans.len() <= 1
        && signals.infrastructure.is_empty()
    {
        return endpoint_role(interface, evidence, reasons);
    }
    reasons.push("sample lacks enough independent evidence to infer a port role".into());
    PortRole::Unknown
}

fn aggregation_role(
    interface: &InterfaceObservation,
    signals: &RoleSignals,
    evidence: &mut Vec<u64>,
    reasons: &mut Vec<String>,
) -> PortRole {
    push_protocol_evidence(interface, &signals.aggregation, evidence);
    reasons.push(format!(
        "{} aggregation control traffic observed",
        protocol_names(&signals.aggregation)
    ));
    PortRole::AggregatedLink
}

fn uplink_role(
    interface: &InterfaceObservation,
    signals: &RoleSignals,
    evidence: &mut Vec<u64>,
    reasons: &mut Vec<String>,
) -> PortRole {
    push_protocol_evidence(interface, &signals.infrastructure, evidence);
    if let Some(packet) = interface.stp_packet {
        evidence.push(packet);
    }
    evidence.extend(interface.neighbors.iter().map(|neighbor| neighbor.packet));
    push_vlan_evidence(interface, evidence);
    reasons.push(format!(
        "{} infrastructure control traffic observed",
        protocol_names(&signals.infrastructure)
    ));
    reasons.push(format!(
        "{} ordinary VLAN identifiers observed",
        signals.ordinary_vlans.len()
    ));
    let topology_reason = if signals.has_stp {
        "STP advertisements observed"
    } else {
        "neighbor discovery identifies infrastructure"
    };
    reasons.push(topology_reason.into());
    PortRole::SwitchUplink
}

fn trunk_role(
    interface: &InterfaceObservation,
    signals: &RoleSignals,
    evidence: &mut Vec<u64>,
    reasons: &mut Vec<String>,
) -> PortRole {
    push_vlan_evidence(interface, evidence);
    if signals.ordinary_vlans.len() >= 3 {
        reasons.push(format!(
            "{} ordinary VLAN identifiers observed",
            signals.ordinary_vlans.len()
        ));
    }
    if signals.nested_tags {
        reasons.push("stacked VLAN tags observed".into());
    }
    PortRole::TaggedTrunk
}

fn multi_endpoint_role(
    interface: &InterfaceObservation,
    evidence: &mut Vec<u64>,
    reasons: &mut Vec<String>,
) -> PortRole {
    if let Some(packet) = interface.untagged_packet {
        evidence.push(packet);
    }
    push_vlan_evidence(interface, evidence);
    reasons.push(format!(
        "{} distinct source MAC addresses observed",
        interface.macs.len()
    ));
    PortRole::MultiEndpoint
}

fn endpoint_role(
    interface: &InterfaceObservation,
    evidence: &mut Vec<u64>,
    reasons: &mut Vec<String>,
) -> PortRole {
    if let Some(packet) = interface.untagged_packet {
        evidence.push(packet);
    }
    reasons.push("small source-MAC population on untagged traffic".into());
    PortRole::EndpointAccess
}

/// Infer every interface in stable section and interface order
#[must_use]
pub fn infer_port_roles(interfaces: &[InterfaceObservation]) -> Vec<PortRoleInference> {
    let mut roles: Vec<_> = interfaces.iter().map(infer_port_role).collect();
    roles.sort_by_key(|role| (role.section, role.interface));
    roles
}

fn observed_protocols(interface: &InterfaceObservation, candidates: &[Protocol]) -> Vec<Protocol> {
    candidates
        .iter()
        .copied()
        .filter(|candidate| {
            interface.protocols.iter().any(|observation| {
                observation.protocol == *candidate
                    && observation.status == FingerprintStatus::Observed
            })
        })
        .collect()
}

fn ordinary_vlans(interface: &InterfaceObservation) -> BTreeSet<u16> {
    interface
        .vlans
        .iter()
        .flat_map(crate::VlanObservation::vids)
        .filter_map(|vid| match vid {
            Vid::Vlan(id) => Some(id.get()),
            Vid::PriorityTagged | Vid::Reserved => None,
        })
        .collect()
}

fn protocol_names(protocols: &[Protocol]) -> String {
    protocols
        .iter()
        .map(|protocol| protocol.as_str())
        .collect::<Vec<_>>()
        .join(" and ")
}

fn push_protocol_evidence(
    interface: &InterfaceObservation,
    protocols: &[Protocol],
    evidence: &mut Vec<u64>,
) {
    evidence.extend(
        interface
            .protocols
            .iter()
            .filter(|observation| {
                protocols.contains(&observation.protocol)
                    && observation.status == FingerprintStatus::Observed
            })
            .map(|observation| observation.packet),
    );
}

fn push_vlan_evidence(interface: &InterfaceObservation, evidence: &mut Vec<u64>) {
    evidence.extend(interface.vlans.iter().map(|vlan| vlan.packet));
}
