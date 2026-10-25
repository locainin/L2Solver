use super::{
    ForensicScope, IpCommunication,
    tracker::{ForensicTracker, PacketCount},
};
use crate::{ResourceLimitStatus, inventory};
use l2_core::EthernetFrame;
use l2_discovery::{IpPacket, NetworkAddress};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct CommunicationKey {
    scope: ForensicScope,
    source: NetworkAddress,
    destination: NetworkAddress,
    source_mac: [u8; 6],
    destination_mac: [u8; 6],
    protocol: u8,
    ports: Option<(u16, u16)>,
    fragmented: bool,
}

impl ForensicTracker {
    pub(super) fn communication(
        &mut self,
        scope: &ForensicScope,
        frame: &EthernetFrame<'_>,
        ip: IpPacket<'_>,
        packet: u64,
        status: &mut ResourceLimitStatus,
    ) -> bool {
        let key = CommunicationKey {
            scope: scope.clone(),
            source: ip.source,
            destination: ip.destination,
            source_mac: frame.source,
            destination_mac: frame.destination,
            protocol: ip.protocol,
            ports: ip.ports(),
            fragmented: ip.fragmented,
        };
        if let Some(count) = self.communications.get_mut(&key) {
            count.frames += 1;
            return false;
        }
        if !self.reserve(status) {
            return false;
        }
        self.communications
            .insert(key, PacketCount { frames: 1, packet });
        true
    }
}

impl CommunicationKey {
    pub(super) fn finish(self, count: PacketCount) -> IpCommunication {
        IpCommunication {
            scope: self.scope,
            source: self.source,
            destination: self.destination,
            source_mac: inventory::mac(self.source_mac),
            destination_mac: inventory::mac(self.destination_mac),
            protocol: self.protocol,
            ports: self.ports,
            fragmented: self.fragmented,
            frames: count.frames,
            packet: count.packet,
        }
    }
}
