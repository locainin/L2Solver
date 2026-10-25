//! Observed neighbor and switch transition dispositions

/// Why one observed neighbor state was accepted or rejected
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NeighborDisposition {
    /// The original binding remained stable
    Stable,
    /// A conflicting ARP claim was rejected
    ConflictRejected,
    /// A conflicting ARP claim was accepted
    ConflictAccepted,
    /// An unsolicited IPv6 advertisement was rejected
    UnsolicitedAdvertisementRejected,
    /// An unsolicited IPv6 advertisement was accepted
    UnsolicitedAdvertisementAccepted,
    /// An unexpected router advertisement was rejected
    RouterAdvertisementRejected,
    /// An unexpected router advertisement was accepted
    RouterAdvertisementAccepted,
    /// A MAC move or source change was rejected
    MacMoveRejected,
    /// A MAC move or source change was accepted
    MacMoveAccepted,
    /// A MITM path was blocked
    MitmBlocked,
    /// A MITM path was observed
    MitmObserved,
    /// The observation did not establish a disposition
    Unknown,
}

impl NeighborDisposition {
    /// Stable operator-facing transition label
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::ConflictRejected => "conflict_rejected",
            Self::ConflictAccepted => "conflict_accepted",
            Self::UnsolicitedAdvertisementRejected => "unsolicited_advertisement_rejected",
            Self::UnsolicitedAdvertisementAccepted => "unsolicited_advertisement_accepted",
            Self::RouterAdvertisementRejected => "router_advertisement_rejected",
            Self::RouterAdvertisementAccepted => "router_advertisement_accepted",
            Self::MacMoveRejected => "mac_move_rejected",
            Self::MacMoveAccepted => "mac_move_accepted",
            Self::MitmBlocked => "mitm_blocked",
            Self::MitmObserved => "mitm_observed",
            Self::Unknown => "unknown",
        }
    }

    /// Return whether this receipt directly establishes a vulnerability
    #[must_use]
    pub const fn is_vulnerable(self) -> bool {
        matches!(
            self,
            Self::ConflictAccepted
                | Self::UnsolicitedAdvertisementAccepted
                | Self::RouterAdvertisementAccepted
                | Self::MacMoveAccepted
                | Self::MitmObserved
        )
    }

    /// Return whether this receipt is a clean protection observation
    #[must_use]
    pub const fn is_clean(self) -> bool {
        matches!(
            self,
            Self::Stable
                | Self::ConflictRejected
                | Self::UnsolicitedAdvertisementRejected
                | Self::RouterAdvertisementRejected
                | Self::MacMoveRejected
                | Self::MitmBlocked
        )
    }

    /// Return whether this accepted disposition must carry a changed binding
    #[must_use]
    pub const fn requires_changed_binding(self) -> bool {
        matches!(
            self,
            Self::ConflictAccepted
                | Self::UnsolicitedAdvertisementAccepted
                | Self::RouterAdvertisementAccepted
                | Self::MacMoveAccepted
        )
    }
}
