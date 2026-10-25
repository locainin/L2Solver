//! Inventory additions return whether the source packet must be kept as evidence

use crate::{
    BridgeIdentity, InterfaceObservation, Neighbor, ProtocolIdentityObservation,
    ProtocolObservation, ResourceLimit, ResourceLimitStatus, StpObservation, VlanObservation,
};
use l2_capture::VlanAuxData;
use l2_codecs::{LldpFrame, StpFrame};
use l2_core::{EthernetFrame, VlanTag};
use l2_discovery::{Fingerprint, IdentityRole, NetworkAddress, Protocol, ProtocolIdentity};
use std::collections::{BTreeMap, BTreeSet};

type VlanTags = Vec<(u16, u16)>;
type VlanKey = (u32, u32, VlanTags);

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct IdentityKey {
    section: u32,
    interface: u32,
    protocol: Protocol,
    role: IdentityRole,
    source_mac: [u8; 6],
    claimed_mac: Option<[u8; 6]>,
    address: Option<NetworkAddress>,
    vlan_tags: VlanTags,
    vlan_aux: Option<(u16, u16)>,
}

// Counts apply across all interfaces so a multi-interface file keeps one process budget
pub struct InventoryTracker {
    mac_facts: usize,
    max_mac_facts: usize,
    max_neighbors: usize,
    max_protocol_identities: usize,
    max_stp_transitions: usize,
    max_vlan_contexts: usize,
    neighbors: usize,
    protocol_identities: usize,
    stp_transitions: usize,
    vlan_contexts: usize,
    mac_keys: BTreeSet<(u32, u32, [u8; 6])>,
    vlan_keys: BTreeSet<VlanKey>,
    identity_indexes: BTreeMap<IdentityKey, usize>,
}

impl InventoryTracker {
    pub const fn new(
        max_mac_facts: usize,
        max_vlan_contexts: usize,
        max_neighbors: usize,
        max_protocol_identities: usize,
        max_stp_transitions: usize,
    ) -> Self {
        Self {
            mac_facts: 0,
            max_mac_facts,
            max_neighbors,
            max_protocol_identities,
            max_stp_transitions,
            max_vlan_contexts,
            neighbors: 0,
            protocol_identities: 0,
            stp_transitions: 0,
            vlan_contexts: 0,
            mac_keys: BTreeSet::new(),
            vlan_keys: BTreeSet::new(),
            identity_indexes: BTreeMap::new(),
        }
    }

    fn reserve_mac(&mut self, status: &mut ResourceLimitStatus) -> bool {
        reserve(
            &mut self.mac_facts,
            self.max_mac_facts,
            status,
            ResourceLimit::MacFacts,
        )
    }

    fn reserve_neighbor(&mut self, status: &mut ResourceLimitStatus) -> bool {
        reserve(
            &mut self.neighbors,
            self.max_neighbors,
            status,
            ResourceLimit::Neighbors,
        )
    }

    fn reserve_stp_transition(&mut self, status: &mut ResourceLimitStatus) -> bool {
        reserve(
            &mut self.stp_transitions,
            self.max_stp_transitions,
            status,
            ResourceLimit::StpTransitions,
        )
    }

    fn reserve_protocol_identity(&mut self, status: &mut ResourceLimitStatus) -> bool {
        reserve(
            &mut self.protocol_identities,
            self.max_protocol_identities,
            status,
            ResourceLimit::ProtocolIdentities,
        )
    }

    fn reserve_vlan(&mut self, status: &mut ResourceLimitStatus) -> bool {
        reserve(
            &mut self.vlan_contexts,
            self.max_vlan_contexts,
            status,
            ResourceLimit::VlanContexts,
        )
    }
}

fn reserve(
    count: &mut usize,
    maximum: usize,
    status: &mut ResourceLimitStatus,
    resource: ResourceLimit,
) -> bool {
    // Saturation marks collection incomplete before any fact is appended
    if *count >= maximum {
        status.mark(resource);
        return false;
    }
    *count += 1;
    true
}

pub fn mac(address: [u8; 6]) -> String {
    let [first, second, third, fourth, fifth, sixth] = address;
    format!("{first:02x}:{second:02x}:{third:02x}:{fourth:02x}:{fifth:02x}:{sixth:02x}")
}

pub fn ethernet(
    interface: &mut InterfaceObservation,
    frame: &EthernetFrame<'_>,
    sequence: u64,
    tracker: &mut InventoryTracker,
    status: &mut ResourceLimitStatus,
) -> bool {
    let mut changed = false;
    let scope = (interface.section, interface.index);
    // MAC and VLAN facts are independent observations from the same valid frame
    let mac_key = (scope.0, scope.1, frame.source);
    if !tracker.mac_keys.contains(&mac_key) && tracker.reserve_mac(status) {
        tracker.mac_keys.insert(mac_key);
        interface.macs.push(mac(frame.source));
        changed = true;
    }
    if !frame.vlan_tags.is_empty() {
        let tags: Vec<_> = frame
            .vlan_tags
            .iter()
            .map(|tag| (tag.tpid, tag.tci))
            .collect();
        let vlan_key = (scope.0, scope.1, tags.clone());
        if !tracker.vlan_keys.contains(&vlan_key) && tracker.reserve_vlan(status) {
            tracker.vlan_keys.insert(vlan_key);
            interface.vlans.push(VlanObservation {
                tags,
                packet: sequence,
            });
            changed = true;
        }
    }
    if frame.vlan_tags.is_empty() && interface.untagged_packet.is_none() {
        interface.untagged_packet = Some(sequence);
        changed = true;
    }
    changed
}

pub fn lldp(
    interface: &mut InterfaceObservation,
    frame: &LldpFrame<'_>,
    sequence: u64,
    tracker: &mut InventoryTracker,
    status: &mut ResourceLimitStatus,
) -> bool {
    // Chassis and port form the stable LLDP neighbor key within one source
    let field = |kind| {
        frame
            .tlvs
            .iter()
            .find(|tlv| tlv.kind == kind)
            .map_or(&[][..], |tlv| tlv.value)
    };
    let chassis = field(1);
    let port = field(2);
    // System Name is a singleton field; duplicates are ambiguous, not first-wins
    let mut names = frame.tlvs.iter().filter(|tlv| tlv.kind == 5);
    let name = match (names.next(), names.next()) {
        (Some(name), None) => name.value,
        _ => &[],
    };
    if let Some(neighbor) = interface
        .neighbors
        .iter_mut()
        .find(|n| n.chassis_id == chassis && n.port_id == port)
    {
        if neighbor.system_name == name {
            return false;
        }
        neighbor.system_name = name.to_vec();
        neighbor.packet = sequence;
    } else if tracker.reserve_neighbor(status) {
        interface.neighbors.push(Neighbor {
            chassis_id: chassis.to_vec(),
            port_id: port.to_vec(),
            system_name: name.to_vec(),
            packet: sequence,
        });
        interface.neighbors.sort_by(|left, right| {
            (&left.chassis_id, &left.port_id).cmp(&(&right.chassis_id, &right.port_id))
        });
    } else {
        return false;
    }
    true
}

pub fn protocol(
    interface: &mut InterfaceObservation,
    fingerprint: Fingerprint,
    sequence: u64,
) -> bool {
    // Repeated protocol states increase counts without consuming new evidence slots
    if let Some(observation) = interface.protocols.iter_mut().find(|observation| {
        observation.protocol == fingerprint.protocol && observation.status == fingerprint.status
    }) {
        observation.frames += 1;
        return false;
    }
    interface.protocols.push(ProtocolObservation {
        protocol: fingerprint.protocol,
        status: fingerprint.status,
        frames: 1,
        packet: sequence,
    });
    interface
        .protocols
        .sort_by_key(|observation| (observation.protocol, observation.status));
    true
}

pub fn protocol_identity(
    interface: &mut InterfaceObservation,
    protocol: l2_discovery::Protocol,
    identity: ProtocolIdentity,
    vlan_context: (&[VlanTag], Option<VlanAuxData>),
    sequence: u64,
    tracker: &mut InventoryTracker,
    status: &mut ResourceLimitStatus,
) -> bool {
    // Identity keys retain source and VLAN scope to avoid cross-segment merging
    let key = IdentityKey {
        section: interface.section,
        interface: interface.index,
        protocol,
        role: identity.role,
        source_mac: identity.source_mac,
        claimed_mac: identity.claimed_mac,
        address: identity.address,
        vlan_tags: vlan_context
            .0
            .iter()
            .map(|tag| (tag.tpid, tag.tci))
            .collect(),
        vlan_aux: vlan_context.1.map(|tag| (tag.tpid, tag.tci)),
    };
    if let Some(index) = tracker.identity_indexes.get(&key) {
        if let Some(observation) = interface.identities.get_mut(*index) {
            observation.frames += 1;
        }
        return false;
    }
    if !tracker.reserve_protocol_identity(status) {
        return false;
    }
    let index = interface.identities.len();
    interface.identities.push(ProtocolIdentityObservation {
        protocol,
        role: identity.role,
        source_mac: mac(identity.source_mac),
        claimed_mac: identity.claimed_mac.map(mac),
        address: identity.address,
        vlan_tags: key.vlan_tags.clone(),
        vlan_aux: key.vlan_aux,
        frames: 1,
        packet: sequence,
    });
    tracker.identity_indexes.insert(key, index);
    true
}

pub fn sort_interfaces(interfaces: &mut [InterfaceObservation]) {
    // Deterministic ordering keeps JSON, baselines, and review diffs stable
    for interface in interfaces {
        interface.macs.sort_unstable();
        interface
            .vlans
            .sort_by(|left, right| left.tags.cmp(&right.tags));
        interface.neighbors.sort_by(|left, right| {
            (&left.chassis_id, &left.port_id).cmp(&(&right.chassis_id, &right.port_id))
        });
        interface.identities.sort_by(|left, right| {
            (
                left.protocol,
                left.role,
                &left.source_mac,
                &left.claimed_mac,
                left.address,
                &left.vlan_tags,
                left.vlan_aux,
            )
                .cmp(&(
                    right.protocol,
                    right.role,
                    &right.source_mac,
                    &right.claimed_mac,
                    right.address,
                    &right.vlan_tags,
                    right.vlan_aux,
                ))
        });
    }
}

pub fn stp(
    interface: &mut InterfaceObservation,
    frame: StpFrame<'_>,
    sequence: u64,
    untagged: bool,
    tracker: &mut InventoryTracker,
    status: &mut ResourceLimitStatus,
) -> bool {
    interface.stp_frames += 1;
    let changed = interface.stp_packet.is_none();
    interface.stp_packet.get_or_insert(sequence);
    // Tagged domains are visible but never folded into the untagged root history
    if !untagged {
        return changed;
    }
    let Some(root) = frame.root else {
        return changed;
    };
    let root_identity = BridgeIdentity {
        priority: root.priority,
        system_id_extension: root.system_id_extension,
        mac: mac(root.mac),
    };
    let version = format!("{:?}", frame.version);
    if let Some(previous) = interface.stp.last_mut()
        && previous.root == root_identity
        && previous.version == version
    {
        previous.frames += 1;
        return changed;
    }
    if !tracker.reserve_stp_transition(status) {
        return changed;
    }
    interface.stp.push(StpObservation {
        root: root_identity,
        version,
        packet: sequence,
        frames: 1,
    });
    true
}
