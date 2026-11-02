use super::{DnsObservation, DnsPlan, DnsResponseMatch, PendingAddress, matching};
use crate::{ForensicScope, ResourceLimit, ResourceLimitStatus, forensics::ForensicTracker};
use l2_discovery::{IpPacket, dns::DnsDecoding};

impl ForensicTracker {
    pub(in crate::forensics) fn dns_observe(
        &mut self,
        scope: &ForensicScope,
        context: (usize, u64),
        ip: IpPacket<'_>,
        decoding: DnsDecoding,
        status: &mut ResourceLimitStatus,
    ) -> bool {
        if status.is_reached(ResourceLimit::DnsMessages) {
            return false;
        }
        if self.dns.observations.len() == self.dns.max_messages {
            status.mark(ResourceLimit::DnsMessages);
            // After an omitted message, stale pending state cannot produce later DNS chains
            self.dns.pending.clear();
            self.dns.addresses.clear();
            return false;
        }
        if !self.reserve(status) {
            return false;
        }
        let Some(transport) = ip.transport else {
            return false;
        };
        let plan = match &decoding {
            DnsDecoding::Decoded { message } => matching::plan(scope, ip, message),
            DnsDecoding::Unresolved { .. } => None,
        };
        let (payload_offset, packet) = context;
        self.dns.observations.push(DnsObservation {
            scope: scope.clone(),
            source: ip.source,
            destination: ip.destination,
            ports: transport.ports,
            packet,
            payload_offset: payload_offset + transport.payload_offset,
            payload_length: transport.payload.len(),
            decoding,
        });
        if let Some(plan) = plan {
            self.dns_transaction(plan, packet, status);
        }
        true
    }

    fn dns_transaction(&mut self, plan: DnsPlan, packet: u64, status: &mut ResourceLimitStatus) {
        if !plan.response {
            self.dns.pending.entry(plan.key).or_default().push(packet);
            return;
        }
        if !self.reserve(status) {
            return;
        }
        let candidates = self.dns.pending.get(&plan.key);
        let candidate_queries = candidates.map_or(0, Vec::len);
        let query_packet = match candidates.map(Vec::as_slice) {
            Some([query]) => Some(*query),
            _ => None,
        };
        self.dns.matches.push(DnsResponseMatch {
            response_packet: packet,
            query_packet,
            candidate_queries,
        });
        let Some(query) = query_packet else {
            return;
        };
        // Only a unique observed match consumes a query; collisions remain explicitly ambiguous
        self.dns.pending.remove(&plan.key);
        for (record, address) in plan.addresses {
            let pending = self
                .dns
                .addresses
                .entry((plan.key.scope.clone(), address))
                .or_default();
            // One address may have duplicate RRs, but it needs only one source record for this response
            if pending
                .last()
                .is_some_and(|previous| previous.response == packet)
            {
                continue;
            }
            pending.push(PendingAddress {
                query,
                response: packet,
                record,
                requester: plan.key.client,
                same_seen: false,
                other_seen: false,
            });
        }
    }
}
