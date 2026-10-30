//! Shared presentation of IPv4 and IPv6 neighbor identity claims

use l2_active::NeighborStatus;

use super::report_common::Evidence;

pub const fn evidence(status: NeighborStatus, conflicts: bool) -> Evidence {
    match status {
        NeighborStatus::Inconclusive => Evidence::Inconclusive,
        NeighborStatus::UnexpectedIdentity => Evidence::Findings,
        NeighborStatus::Observed if conflicts => Evidence::Findings,
        NeighborStatus::Observed => Evidence::Observed,
    }
}

pub const fn status_name(status: NeighborStatus) -> &'static str {
    match status {
        NeighborStatus::Observed => "observed",
        NeighborStatus::UnexpectedIdentity => "unexpected_identity",
        NeighborStatus::Inconclusive => "inconclusive",
    }
}
