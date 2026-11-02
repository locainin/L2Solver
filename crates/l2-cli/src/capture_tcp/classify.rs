use super::model::{FlowSelection, UnresolvedReason};
use l2_audit::ForensicScope;
use l2_capture::{CapturedFrame, LinkType};
use l2_core::FrameField;
use l2_discovery::{
    NetworkAddress, TransportHeader, ip_header_from_payload, ip_packet_from_payload,
    link::decode_network_frame,
};
use l2_workbench::tcp_range::Segment;

pub(super) enum PacketMatch<'a> {
    Other,
    Unresolved(UnresolvedReason),
    Segment(Segment<'a>),
}

impl FlowSelection {
    pub(super) fn classify<'a>(
        &self,
        packet: &'a CapturedFrame,
        packet_index: u32,
    ) -> PacketMatch<'a> {
        let interface = packet.metadata().interface();
        if interface.section != self.scope.section || interface.index != self.scope.interface {
            return PacketMatch::Other;
        }
        let link_type = packet.metadata().link_type();
        if !matches!(
            link_type,
            LinkType::Ethernet | LinkType::LinuxSll | LinkType::LinuxSll2
        ) {
            return PacketMatch::Unresolved(UnresolvedReason::LinkType);
        }
        let Some(frame) = decode_network_frame(link_type, packet.bytes()) else {
            // Missing header bytes can conceal membership in the selected scope
            return PacketMatch::Unresolved(if link_type == LinkType::Ethernet {
                UnresolvedReason::EthernetLayout
            } else {
                UnresolvedReason::CookedLayout
            });
        };
        if ForensicScope::from_network_frame(packet.metadata(), &frame) != self.scope {
            return PacketMatch::Other;
        }
        let Some(field) = frame.field() else {
            // Unsupported cooked protocol meanings may conceal relevant IP data
            return PacketMatch::Unresolved(UnresolvedReason::UnsupportedProtocol);
        };
        let FrameField::EtherType(protocol @ (0x0800 | 0x86dd)) = field else {
            return PacketMatch::Other;
        };
        if packet.is_truncated() {
            return self.classify_truncated(protocol, frame.payload());
        }
        let Some(ip) = ip_packet_from_payload(protocol, frame.payload()) else {
            return PacketMatch::Unresolved(UnresolvedReason::IpLayout);
        };
        if ip.source != self.source || ip.destination != self.destination {
            return PacketMatch::Other;
        }
        if !tcp_possible(ip.protocol, ip.fragmented, ip.source) {
            return PacketMatch::Other;
        }
        if ip.fragmented {
            return PacketMatch::Unresolved(UnresolvedReason::IpFragment);
        }
        let Some(transport) = ip.transport else {
            return PacketMatch::Unresolved(UnresolvedReason::TcpLayout);
        };
        if transport.ports != self.ports {
            return PacketMatch::Other;
        }
        let TransportHeader::Tcp {
            sequence, flags, ..
        } = transport.header
        else {
            return PacketMatch::Other;
        };
        PacketMatch::Segment(Segment {
            packet_index,
            payload_frame_offset: frame.payload_offset() + transport.payload_offset,
            sequence,
            flags,
            payload: transport.payload,
        })
    }

    fn classify_truncated(&self, protocol: u16, payload: &[u8]) -> PacketMatch<'static> {
        // Complete headers can rule out membership without borrowing a missing body
        if let Some(header) = ip_header_from_payload(protocol, payload)
            && (header.source != self.source
                || header.destination != self.destination
                || !tcp_possible(header.protocol, header.fragmented, header.source))
        {
            return PacketMatch::Other;
        }
        PacketMatch::Unresolved(UnresolvedReason::TruncatedCapture)
    }
}

const fn tcp_possible(protocol: u8, fragmented: bool, source: NetworkAddress) -> bool {
    // IPv6 may place another extension after a non-atomic fragment header
    protocol == 6
        || (fragmented
            && matches!(source, NetworkAddress::Ipv6(_))
            && matches!(protocol, 0 | 43 | 44 | 51 | 60))
}
