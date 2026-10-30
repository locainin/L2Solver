//! Shared interpretation of unauthenticated neighbor identity claims

use l2_onpath::MacAddress;

/// What correlated ARP or NDP identity claims establish
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NeighborStatus {
    /// At least one matching reply was observed
    Observed,
    /// A matching reply claimed a MAC other than the configured expectation
    UnexpectedIdentity,
    /// No qualifying reply was observed
    Inconclusive,
}

// The protocol reports retain the observations; this only classifies their MACs
pub fn classify(
    expected: Option<MacAddress>,
    claims: impl Iterator<Item = MacAddress>,
) -> NeighborStatus {
    let mut observed = false;
    for mac in claims {
        observed = true;
        if expected.is_some_and(|expected| expected != mac) {
            return NeighborStatus::UnexpectedIdentity;
        }
    }
    if observed {
        NeighborStatus::Observed
    } else {
        NeighborStatus::Inconclusive
    }
}
