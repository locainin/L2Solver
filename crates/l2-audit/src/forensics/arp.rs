use super::{
    ArpBindingChange, ArpObservation, ForensicScope,
    tracker::{ForensicTracker, PacketCount},
};
use crate::{ResourceLimit, ResourceLimitStatus, inventory};
use l2_core::EthernetFrame;
use l2_discovery::{ArpPacket, IpPacket, NetworkAddress};

pub(super) type BindingKey = (ForensicScope, NetworkAddress);

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct ArpKey {
    scope: ForensicScope,
    source_mac: [u8; 6],
    arp: ArpPacket,
}

pub(super) struct BindingState {
    mac: [u8; 6],
    packet: u64,
    pending_change: Option<usize>,
}

impl ForensicTracker {
    pub(super) fn arp(
        &mut self,
        scope: &ForensicScope,
        frame: &EthernetFrame<'_>,
        arp: ArpPacket,
        packet: u64,
        status: &mut ResourceLimitStatus,
    ) -> bool {
        let key = ArpKey {
            scope: scope.clone(),
            source_mac: frame.source,
            arp,
        };
        let mut changed = if let Some(count) = self.arp_observations.get_mut(&key) {
            count.frames += 1;
            false
        } else if self.reserve(status) {
            self.arp_observations
                .insert(key, PacketCount { frames: 1, packet });
            true
        } else {
            return false;
        };
        if arp.is_binding_claim() && scope.supports_binding_comparison() {
            changed |= self.binding(scope, arp, packet, status);
        }
        changed
    }

    fn binding(
        &mut self,
        scope: &ForensicScope,
        arp: ArpPacket,
        packet: u64,
        status: &mut ResourceLimitStatus,
    ) -> bool {
        let key = (scope.clone(), NetworkAddress::Ipv4(arp.sender_ip));
        let pending_change = if let Some(previous) = self.bindings.get(&key) {
            if previous.mac == arp.sender_mac {
                return false;
            }
            let previous_mac = previous.mac;
            let previous_packet = previous.packet;
            if !self.reserve(status) {
                return false;
            }
            let index = self.arp_changes.len();
            self.arp_changes.push(ArpBindingChange {
                scope: scope.clone(),
                address: key.1,
                previous_mac: inventory::mac(previous_mac),
                claimed_mac: inventory::mac(arp.sender_mac),
                previous_packet,
                packet,
                followup_packet: None,
            });
            Some(index)
        } else {
            // The first claim establishes an observed starting point, not a change
            None
        };
        self.bindings.insert(
            key,
            BindingState {
                mac: arp.sender_mac,
                packet,
                pending_change,
            },
        );
        true
    }

    pub(super) fn followup(
        &mut self,
        scope: &ForensicScope,
        frame: &EthernetFrame<'_>,
        ip: IpPacket<'_>,
        packet: u64,
        status: &ResourceLimitStatus,
    ) -> bool {
        // Omitted facts stop all later correlation, so a stale claim cannot complete a chain
        if status.is_reached(ResourceLimit::ForensicRecords) {
            return false;
        }
        let Some(binding) = self.bindings.get_mut(&(scope.clone(), ip.destination)) else {
            return false;
        };
        if binding.mac != frame.destination {
            return false;
        }
        let Some(index) = binding.pending_change.take() else {
            return false;
        };
        let Some(change) = self.arp_changes.get_mut(index) else {
            return false;
        };
        change.followup_packet = Some(packet);
        true
    }
}

impl ArpKey {
    pub(super) fn finish(self, count: PacketCount) -> ArpObservation {
        ArpObservation {
            scope: self.scope,
            source_mac: inventory::mac(self.source_mac),
            operation: self.arp.operation,
            sender_mac: inventory::mac(self.arp.sender_mac),
            sender_address: NetworkAddress::Ipv4(self.arp.sender_ip),
            target_mac: inventory::mac(self.arp.target_mac),
            target_address: NetworkAddress::Ipv4(self.arp.target_ip),
            frames: count.frames,
            packet: count.packet,
        }
    }
}
