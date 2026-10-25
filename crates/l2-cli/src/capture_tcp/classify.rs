use super::model::{FlowSelection, UnresolvedReason};
use l2_audit::ForensicScope;
use l2_capture::{CapturedFrame, LinkType};
use l2_core::{EthernetFrame, FrameField};
use l2_discovery::{NetworkAddress, TransportHeader, ip_header, ip_packet};
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
        if packet.metadata().link_type() != LinkType::Ethernet {
            return PacketMatch::Unresolved(UnresolvedReason::LinkType);
        }
        let Ok(frame) = l2_core::decode(packet.bytes()) else {
            // Missing tag bytes can conceal membership in the selected scope
            return PacketMatch::Unresolved(UnresolvedReason::EthernetLayout);
        };
        if ForensicScope::new(packet.metadata(), &frame) != self.scope {
            return PacketMatch::Other;
        }
        if !matches!(frame.field, FrameField::EtherType(0x0800 | 0x86dd)) {
            return PacketMatch::Other;
        }
        if packet.is_truncated() {
            return self.classify_truncated(&frame);
        }
        let Some(ip) = ip_packet(&frame) else {
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
            payload_frame_offset: packet.captured_len() - frame.payload.len()
                + transport.payload_offset,
            sequence,
            flags,
            payload: transport.payload,
        })
    }

    fn classify_truncated(&self, frame: &EthernetFrame<'_>) -> PacketMatch<'static> {
        // Complete headers can rule out membership without borrowing a missing body
        if let Some(header) = ip_header(frame)
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
