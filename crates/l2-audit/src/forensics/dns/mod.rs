//! DNS header observations and bounded capture-order correlations

mod answers;
mod matching;
mod model;
mod tracker;
mod uses;

use crate::ForensicScope;
use l2_discovery::{NetworkAddress, dns::DnsDecoding};
pub use model::{DnsAddressUse, DnsObservation, DnsResponseMatch};
use std::collections::BTreeMap;

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct QueryKey {
    scope: ForensicScope,
    client: NetworkAddress,
    server: NetworkAddress,
    client_port: u16,
    server_port: u16,
    id: u16,
    questions: Vec<(Vec<u8>, u16, u16)>,
}

struct DnsPlan {
    key: QueryKey,
    response: bool,
    addresses: Vec<(usize, NetworkAddress)>,
}

struct PendingAddress {
    query: u64,
    response: u64,
    record: usize,
    requester: NetworkAddress,
    // These two bits bound followups to the first observation in each client category
    same_seen: bool,
    other_seen: bool,
}

pub struct DnsTracker {
    pub(super) observations: Vec<DnsObservation>,
    pub(super) matches: Vec<DnsResponseMatch>,
    pub(super) uses: Vec<DnsAddressUse>,
    pending: BTreeMap<QueryKey, Vec<u64>>,
    addresses: BTreeMap<(ForensicScope, NetworkAddress), Vec<PendingAddress>>,
    max_messages: usize,
    pub(super) candidates_seen: u64,
    pub(super) messages_parsed: u64,
}

impl DnsTracker {
    pub const fn new(max_messages: usize) -> Self {
        Self {
            observations: Vec::new(),
            matches: Vec::new(),
            uses: Vec::new(),
            pending: BTreeMap::new(),
            addresses: BTreeMap::new(),
            max_messages,
            candidates_seen: 0,
            messages_parsed: 0,
        }
    }

    pub fn count(&mut self, decoding: &DnsDecoding) {
        self.candidates_seen += 1;
        self.messages_parsed += u64::from(matches!(decoding, DnsDecoding::Decoded { .. }));
    }

    pub const fn record_count(&self) -> usize {
        self.observations.len() + self.matches.len() + self.uses.len()
    }
}
