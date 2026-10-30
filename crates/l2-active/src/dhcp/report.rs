//! Actual source-backed DHCP offer claims and bounded execution accounting

use std::net::Ipv4Addr;

use l2_capture::CapturedFrame;
use l2_onpath::MacAddress;

use crate::RunSummary;

use super::decode::Offer;

/// Classification of the offers actually observed during this one request
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DhcpStatus {
    /// At least one correlated offer was observed and no offer violated the allowlist
    Observed,
    /// An observed offer advertised a server ID outside the supplied allowlist
    UnexpectedServer,
    /// No correlated offer was observed
    Inconclusive,
}

/// One distinct offer and the exact captured Ethernet frame supporting it
#[derive(Debug)]
pub struct DhcpObservation {
    pub(super) offer: Offer,
    pub(super) frame: CapturedFrame,
}

impl DhcpObservation {
    /// Return the unauthenticated server identifier in DHCP option 54
    #[must_use]
    pub const fn server_identifier(&self) -> Ipv4Addr {
        self.offer.server
    }

    /// Return the IPv4 address offered to this client
    #[must_use]
    pub const fn offered_address(&self) -> Ipv4Addr {
        self.offer.address
    }

    /// Return the lease duration advertised with the offer
    #[must_use]
    pub const fn lease_seconds(&self) -> u32 {
        self.offer.lease_seconds
    }

    /// Return the observed Ethernet sender, which may be a relay
    #[must_use]
    pub const fn source_mac(&self) -> MacAddress {
        self.offer.source_mac
    }

    /// Return the observed IPv4 sender, which may differ from the server ID
    #[must_use]
    pub const fn source_ip(&self) -> Ipv4Addr {
        self.offer.source_ip
    }

    /// Return the relay address reported in the DHCP message
    #[must_use]
    pub const fn relay_ip(&self) -> Ipv4Addr {
        self.offer.relay_ip
    }

    /// Return whether UDP carried a checksum; a zero checksum is valid in IPv4
    #[must_use]
    pub const fn udp_checksum_present(&self) -> bool {
        self.offer.udp_checksum_present
    }

    /// Borrow the original packet bytes and capture provenance
    #[must_use]
    pub const fn frame(&self) -> &CapturedFrame {
        &self.frame
    }
}

/// Bounded offer observations and the actual active-link execution summary
///
/// DHCP has no built-in authentication. Correlated fields and an allowlist
/// comparison describe only observed claims and never establish protection
#[derive(Debug)]
pub struct DhcpReport {
    pub(super) summary: RunSummary,
    pub(super) allowed: Option<Vec<Ipv4Addr>>,
    pub(super) observations: Vec<DhcpObservation>,
}

impl DhcpReport {
    /// Classify observed claims without inferring a guard result from silence
    #[must_use]
    pub fn status(&self) -> DhcpStatus {
        if self.observations.is_empty() {
            return DhcpStatus::Inconclusive;
        }
        if self
            .observations
            .iter()
            .any(|offer| self.expected_match(offer.server_identifier()) == Some(false))
        {
            return DhcpStatus::UnexpectedServer;
        }
        DhcpStatus::Observed
    }

    /// Compare an advertised server ID with the operator's optional allowlist
    #[must_use]
    pub fn expected_match(&self, server: Ipv4Addr) -> Option<bool> {
        self.allowed
            .as_ref()
            .map(|allowed| allowed.contains(&server))
    }

    /// Borrow distinct correlated offers in observation order
    #[must_use]
    pub fn observations(&self) -> &[DhcpObservation] {
        &self.observations
    }

    /// Return exact send, receive, loss, and termination accounting
    #[must_use]
    pub const fn summary(&self) -> &RunSummary {
        &self.summary
    }
}
