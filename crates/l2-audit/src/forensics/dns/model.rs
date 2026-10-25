use crate::ForensicScope;
use l2_discovery::{NetworkAddress, dns::DnsDecoding};
use serde::Serialize;

/// A port-selected UDP payload and its bounded wire-layout result
#[derive(Debug, Serialize)]
pub struct DnsObservation {
    pub scope: ForensicScope,
    pub source: NetworkAddress,
    pub destination: NetworkAddress,
    pub ports: (u16, u16),
    pub packet: u64,
    /// Captured-frame offset of the DNS message; record RDATA offsets are message-relative
    pub payload_offset: usize,
    pub payload_length: usize,
    pub decoding: DnsDecoding,
}

/// Matching observed outstanding queries, without asserting resolver acceptance
#[derive(Debug, Serialize)]
pub struct DnsResponseMatch {
    pub response_packet: u64,
    /// Present only for exactly one matching retained query
    pub query_packet: Option<u64>,
    pub candidate_queries: usize,
}

/// A later IP destination co-occurs with an address returned in a matched answer
#[derive(Debug, Serialize)]
pub struct DnsAddressUse {
    pub query_packet: u64,
    pub response_packet: u64,
    pub packet: u64,
    /// Index into the response message's wire-ordered records
    pub answer_record: usize,
    pub address: NetworkAddress,
    /// Other clients are reported separately and never inherit the requester's identity
    pub client_matches_requester: bool,
}
