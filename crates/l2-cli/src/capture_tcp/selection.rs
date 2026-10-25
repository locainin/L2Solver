use super::{
    classify::PacketMatch,
    model::{
        CaptureTcpReport, FlowSelection, FrameSource, LIMITATIONS, MAX_UNRESOLVED_SOURCES,
        UnresolvedSource,
    },
};
use crate::arguments::CaptureTcpOptions;
use l2_audit::ForensicScope;
use l2_capture::{CapturedFrame, LinkType};
use l2_discovery::{TransportHeader, ip_packet};
use l2_workbench::tcp_range::TcpRange;
use std::error::Error;

pub(super) struct Selection {
    flow: FlowSelection,
    range: TcpRange,
    sources: Vec<FrameSource>,
    matching_packets: u64,
    unresolved_packets: u64,
    unresolved_sources: Vec<UnresolvedSource>,
}

impl Selection {
    pub(super) fn new(
        packet: &CapturedFrame,
        options: &CaptureTcpOptions,
    ) -> Result<Self, Box<dyn Error>> {
        if packet.metadata().link_type() != LinkType::Ethernet || packet.is_truncated() {
            return Err("selected packet must be a complete Ethernet TCP packet".into());
        }
        let frame = l2_core::decode(packet.bytes())?;
        let ip =
            ip_packet(&frame).ok_or("selected packet has no supported complete IP envelope")?;
        let transport = ip
            .transport
            .ok_or("selected packet has no complete unfragmented TCP envelope")?;
        let TransportHeader::Tcp {
            sequence, flags, ..
        } = transport.header
        else {
            return Err("selected packet is not TCP".into());
        };
        if transport.payload.is_empty() && options.sequence.is_none() {
            return Err("selected packet has no payload; supply an explicit --sequence".into());
        }
        let start = options
            .sequence
            .unwrap_or_else(|| sequence.wrapping_add(u32::from(flags & 0x02 != 0)));
        Ok(Self {
            flow: FlowSelection {
                scope: ForensicScope::new(packet.metadata(), &frame),
                source: ip.source,
                destination: ip.destination,
                ports: transport.ports,
            },
            range: TcpRange::new(start, options.length)?,
            sources: Vec::new(),
            matching_packets: 0,
            unresolved_packets: 0,
            unresolved_sources: Vec::new(),
        })
    }

    pub(super) fn observe(
        &mut self,
        packet: &CapturedFrame,
        packet_index: u32,
    ) -> Result<(), Box<dyn Error>> {
        let segment = match self.flow.classify(packet, packet_index) {
            PacketMatch::Other => return Ok(()),
            PacketMatch::Unresolved(reason) => {
                self.unresolved_packets += 1;
                // Keep representative references bounded while the exact total keeps growing
                if self.unresolved_sources.len() < MAX_UNRESOLVED_SOURCES {
                    self.unresolved_sources.push(UnresolvedSource {
                        source: FrameSource::new(packet, packet_index),
                        reason,
                    });
                }
                return Ok(());
            }
            PacketMatch::Segment(segment) => segment,
        };
        self.matching_packets += 1;
        let retained = self.range.observe(segment)?;
        if retained {
            // Every retained byte/control observation gets its corresponding source hash
            self.sources.push(FrameSource::new(packet, packet_index));
        }
        Ok(())
    }

    pub(super) fn finish(
        self,
        first_packet: u32,
        last_packet: u32,
        capture_packets: u32,
    ) -> CaptureTcpReport {
        let range = self.range.finish();
        CaptureTcpReport {
            schema_version: 1,
            tool_version: env!("CARGO_PKG_VERSION"),
            complete: range.has_unique_coverage() && self.unresolved_packets == 0,
            first_packet,
            last_packet,
            capture_packets,
            matching_packets: self.matching_packets,
            unresolved_packets: self.unresolved_packets,
            unresolved_sources: self.unresolved_sources,
            flow: self.flow,
            sources: self.sources,
            range,
            limitations: LIMITATIONS,
        }
    }
}
