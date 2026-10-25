use super::DnsAddressUse;
use crate::{ForensicScope, ResourceLimit, ResourceLimitStatus, forensics::ForensicTracker};
use l2_discovery::IpPacket;

impl ForensicTracker {
    pub(in crate::forensics) fn dns_followup(
        &mut self,
        scope: &ForensicScope,
        ip: IpPacket<'_>,
        packet: u64,
        status: &mut ResourceLimitStatus,
    ) -> bool {
        if status.is_reached(ResourceLimit::DnsMessages) {
            return false;
        }
        let key = (scope.clone(), ip.destination);
        let mut changed = false;
        // Temporarily remove this bucket so shared quota checks can borrow the full tracker
        let Some(mut pending) = self.dns.addresses.remove(&key) else {
            return false;
        };
        for answer in &mut pending {
            let same_client = ip.source == answer.requester;
            let seen = if same_client {
                &mut answer.same_seen
            } else {
                &mut answer.other_seen
            };
            if *seen || answer.response >= packet {
                continue;
            }
            if !self.reserve(status) {
                break;
            }
            self.dns.uses.push(DnsAddressUse {
                query_packet: answer.query,
                response_packet: answer.response,
                packet,
                answer_record: answer.record,
                address: ip.destination,
                client_matches_requester: same_client,
            });
            *seen = true;
            changed = true;
        }
        // Completed first-use pairs need no further per-packet scanning
        pending.retain(|answer| !answer.same_seen || !answer.other_seen);
        if !pending.is_empty() {
            self.dns.addresses.insert(key, pending);
        }
        changed
    }
}
