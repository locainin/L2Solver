use super::{
    ArpBindingChange, ForensicReport, ForensicScope, TrailingData, TrailingProtocol,
    arp::{ArpKey, BindingKey, BindingState},
    communications::CommunicationKey,
    dns::DnsTracker,
};
use crate::{ResourceLimit, ResourceLimitStatus};
use l2_capture::CapturedFrame;
use l2_core::{EthernetFrame, FrameField};
use l2_discovery::{
    IpPacket, NetworkAddress, arp_packet, dns, ip_packet_from_payload, link::NetworkEnvelope,
};
use std::collections::BTreeMap;

#[derive(Clone, Copy)]
pub(super) struct PacketCount {
    pub frames: u64,
    pub packet: u64,
}

#[derive(Clone, Copy)]
struct IpContext<'a, 'frame> {
    source: &'a CapturedFrame,
    ethernet: Option<&'a EthernetFrame<'frame>>,
    payload_offset: usize,
    packet: u64,
}

pub struct ForensicTracker {
    pub(super) communications: BTreeMap<CommunicationKey, PacketCount>,
    pub(super) arp_observations: BTreeMap<ArpKey, PacketCount>,
    pub(super) bindings: BTreeMap<BindingKey, BindingState>,
    pub(super) arp_changes: Vec<ArpBindingChange>,
    pub(super) trailing_data: Vec<TrailingData>,
    pub(super) trailer_frames_unchecked: u64,
    pub(super) dns: DnsTracker,
    max_records: usize,
    ip_frames_seen: u64,
    ip_frames_parsed: u64,
}

impl ForensicTracker {
    #[must_use]
    pub const fn new(max_records: usize, max_dns_messages: usize) -> Self {
        Self {
            communications: BTreeMap::new(),
            arp_observations: BTreeMap::new(),
            bindings: BTreeMap::new(),
            arp_changes: Vec::new(),
            trailing_data: Vec::new(),
            trailer_frames_unchecked: 0,
            dns: DnsTracker::new(max_dns_messages),
            max_records,
            ip_frames_seen: 0,
            ip_frames_parsed: 0,
        }
    }

    pub(super) fn reserve(&self, status: &mut ResourceLimitStatus) -> bool {
        let retained = self.communications.len()
            + self.arp_observations.len()
            + self.arp_changes.len()
            + self.trailing_data.len()
            + self.dns.record_count();
        if retained == self.max_records {
            status.mark(ResourceLimit::ForensicRecords);
            return false;
        }
        true
    }

    pub fn observe(
        &mut self,
        source: &CapturedFrame,
        frame: &EthernetFrame<'_>,
        packet: u64,
        can_reference: bool,
        status: &mut ResourceLimitStatus,
    ) -> bool {
        if let FrameField::EtherType(protocol @ (0x0800 | 0x86dd)) = frame.field {
            let scope = ForensicScope::new(source.metadata(), frame);
            let context = IpContext {
                source,
                ethernet: Some(frame),
                payload_offset: 14 + frame.vlan_tags.len() * 4,
                packet,
            };
            return self.observe_ip_frame(
                &scope,
                context,
                protocol,
                frame.payload,
                can_reference,
                status,
            );
        }
        // Later facts cannot cite an unindexed packet, even if the frame parses correctly
        if !can_reference {
            if arp_packet(frame).is_some() || !frame.padding.is_empty() {
                status.mark(ResourceLimit::EvidenceReferences);
            }
            return false;
        }
        // Counters still describe parsing coverage after new record retention stops
        if status.is_reached(ResourceLimit::ForensicRecords) {
            return false;
        }
        let scope = ForensicScope::new(source.metadata(), frame);
        if let Some(arp) = arp_packet(frame) {
            let mut changed = self.arp(&scope, frame, arp, packet, status);
            if !status.is_reached(ResourceLimit::ForensicRecords) {
                // The supported Ethernet/IPv4 ARP layout has exactly 28 protocol bytes
                let trailer = frame.payload.get(28..).unwrap_or_default();
                changed |= self.trailer(
                    &scope,
                    source,
                    TrailingProtocol::Arp,
                    trailer,
                    packet,
                    status,
                );
            }
            return changed;
        }
        self.trailer(
            &scope,
            source,
            TrailingProtocol::Ieee8023,
            frame.padding,
            packet,
            status,
        )
    }

    /// Observe decoded network facts while reserving Ethernet-only claims for Ethernet frames
    ///
    /// Cooked frames can contribute DNS and bounded trailing-byte facts, but not
    /// Ethernet communication pairs or Ethernet-dependent ARP correlations
    pub fn observe_network(
        &mut self,
        source: &CapturedFrame,
        frame: &NetworkEnvelope<'_>,
        packet: u64,
        can_reference: bool,
        status: &mut ResourceLimitStatus,
    ) -> bool {
        if let Some(ethernet) = frame.ethernet() {
            return self.observe(source, ethernet, packet, can_reference, status);
        }
        let Some(FrameField::EtherType(protocol @ (0x0800 | 0x86dd))) = frame.field() else {
            return false;
        };
        let scope = ForensicScope::from_network_frame(source.metadata(), frame);
        let context = IpContext {
            source,
            ethernet: None,
            payload_offset: frame.payload_offset(),
            packet,
        };
        self.observe_ip_frame(
            &scope,
            context,
            protocol,
            frame.payload(),
            can_reference,
            status,
        )
    }

    fn observe_ip_frame(
        &mut self,
        scope: &ForensicScope,
        context: IpContext<'_, '_>,
        protocol: u16,
        payload: &[u8],
        can_reference: bool,
        status: &mut ResourceLimitStatus,
    ) -> bool {
        // Coverage includes valid headers whose facts cannot be retained
        self.ip_frames_seen += 1;
        let ip = ip_packet_from_payload(protocol, payload);
        self.ip_frames_parsed += u64::from(ip.is_some());
        let dns = ip.and_then(dns::udp_message);
        if let Some(decoding) = &dns {
            self.dns.count(decoding);
        }
        if !can_reference {
            if ip.is_some() {
                status.mark(ResourceLimit::EvidenceReferences);
            }
            return false;
        }
        if status.is_reached(ResourceLimit::ForensicRecords) {
            return false;
        }
        let Some(ip) = ip else {
            return false;
        };
        let mut changed = false;
        if let Some(decoding) = dns {
            changed |= self.dns_observe(
                scope,
                (context.payload_offset, context.packet),
                ip,
                decoding,
                status,
            );
        }
        changed | self.observe_ip(scope, context, ip, status)
    }

    fn observe_ip(
        &mut self,
        scope: &ForensicScope,
        context: IpContext<'_, '_>,
        ip: IpPacket<'_>,
        status: &mut ResourceLimitStatus,
    ) -> bool {
        if status.is_reached(ResourceLimit::ForensicRecords) {
            return false;
        }
        let mut changed = false;
        if let Some(frame) = context.ethernet {
            changed |= self.communication(scope, frame, ip, context.packet, status);
            changed |= self.followup(scope, frame, ip, context.packet, status);
        }
        if status.is_reached(ResourceLimit::ForensicRecords) {
            return changed;
        }
        changed |= self.dns_followup(scope, ip, context.packet, status);
        if status.is_reached(ResourceLimit::ForensicRecords) {
            return changed;
        }
        if let Some(transport) = ip.transport {
            // These bytes lie inside the declared IP envelope, before any possible FCS
            let offset =
                context.payload_offset + transport.payload_offset + transport.payload.len();
            changed |= self.record_trailer(
                scope,
                TrailingProtocol::Udp,
                (offset, transport.trailing_bytes),
                context.packet,
                status,
            );
        }
        if !status.is_reached(ResourceLimit::ForensicRecords) {
            let protocol = match ip.source {
                NetworkAddress::Ipv4(_) => TrailingProtocol::Ipv4,
                NetworkAddress::Ipv6(_) => TrailingProtocol::Ipv6,
            };
            changed |= self.trailer(
                scope,
                context.source,
                protocol,
                ip.trailing_bytes,
                context.packet,
                status,
            );
        }
        changed
    }

    #[must_use]
    pub fn finish(self) -> ForensicReport {
        ForensicReport {
            communications: self
                .communications
                .into_iter()
                .map(|(key, count)| key.finish(count))
                .collect(),
            arp_observations: self
                .arp_observations
                .into_iter()
                .map(|(key, count)| key.finish(count))
                .collect(),
            arp_changes: self.arp_changes,
            trailing_data: self.trailing_data,
            dns_observations: self.dns.observations,
            dns_matches: self.dns.matches,
            dns_address_uses: self.dns.uses,
            dns_candidates_seen: self.dns.candidates_seen,
            dns_messages_parsed: self.dns.messages_parsed,
            ip_frames_seen: self.ip_frames_seen,
            ip_frames_parsed: self.ip_frames_parsed,
            trailer_frames_unchecked: self.trailer_frames_unchecked,
            limitations: super::model::LIMITATIONS,
        }
    }
}
