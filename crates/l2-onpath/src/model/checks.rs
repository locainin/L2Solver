//! Stable check kinds and descriptor lookup errors

use super::{ActivityClass, AddressFamily, NeighborDisposition, ProtocolFamily, RiskClass};

/// Every bounded active check represented by the foundation catalog
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CheckKind {
    /// ARP spoof susceptibility
    ArpSpoofSusceptibility,
    /// Gratuitous ARP handling
    GratuitousArp,
    /// Gateway identity conflict handling
    GatewayConflict,
    /// Host identity conflict handling
    HostConflict,
    /// Dynamic ARP Inspection behavior
    Dai,
    /// IP source guard behavior
    SourceGuard,
    /// Static ARP protection behavior
    StaticArp,
    /// Duplicate IPv4 address handling
    DuplicateAddressHandling,
    /// Authenticated ARP MITM path proof
    ArpMitmProof,
    /// NDP spoof susceptibility
    NdpSpoofSusceptibility,
    /// Unsolicited Neighbor Advertisement handling
    UnsolicitedNa,
    /// IPv6 router impersonation handling
    RouterImpersonation,
    /// Router Advertisement Guard behavior
    RaGuard,
    /// `DHCPv6` Guard behavior
    Dhcpv6Guard,
    /// Authenticated NDP MITM path proof
    NdpMitmProof,
    /// Port-security admission behavior
    PortSecurity,
    /// Sticky-MAC move behavior
    StickyMacMove,
    /// Unknown-unicast forwarding behavior
    UnknownUnicast,
    /// Client or PVLAN isolation behavior
    ClientPvlanIsolation,
    /// Learned-MAC aging behavior
    MacAging,
    /// Bounded MAC population handling
    BoundedMacPopulation,
    /// Disruptive CAM-table protection
    DisruptiveCamProtection,
}

impl CheckKind {
    /// Return this check's immutable catalog descriptor
    #[must_use]
    pub fn descriptor(self) -> &'static crate::CheckDescriptor {
        crate::descriptor(self)
    }

    /// Stable machine label used by plans and reports
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ArpSpoofSusceptibility => "arp-spoof-susceptibility",
            Self::GratuitousArp => "gratuitous-arp",
            Self::GatewayConflict => "gateway-conflict",
            Self::HostConflict => "host-conflict",
            Self::Dai => "dai",
            Self::SourceGuard => "source-guard",
            Self::StaticArp => "static-arp",
            Self::DuplicateAddressHandling => "duplicate-address-handling",
            Self::ArpMitmProof => "arp-mitm-proof",
            Self::NdpSpoofSusceptibility => "ndp-spoof-susceptibility",
            Self::UnsolicitedNa => "unsolicited-na",
            Self::RouterImpersonation => "router-impersonation",
            Self::RaGuard => "ra-guard",
            Self::Dhcpv6Guard => "dhcpv6-guard",
            Self::NdpMitmProof => "ndp-mitm-proof",
            Self::PortSecurity => "port-security",
            Self::StickyMacMove => "sticky-mac-move",
            Self::UnknownUnicast => "unknown-unicast",
            Self::ClientPvlanIsolation => "client-pvlan-isolation",
            Self::MacAging => "mac-aging",
            Self::BoundedMacPopulation => "bounded-mac-population",
            Self::DisruptiveCamProtection => "disruptive-cam-protection",
        }
    }

    /// Return the protocol family exercised by this check
    #[must_use]
    pub const fn family(self) -> ProtocolFamily {
        match self {
            Self::ArpSpoofSusceptibility
            | Self::GratuitousArp
            | Self::GatewayConflict
            | Self::HostConflict
            | Self::Dai
            | Self::SourceGuard
            | Self::StaticArp
            | Self::DuplicateAddressHandling
            | Self::ArpMitmProof => ProtocolFamily::ArpIpv4,
            Self::NdpSpoofSusceptibility
            | Self::UnsolicitedNa
            | Self::RouterImpersonation
            | Self::RaGuard
            | Self::Dhcpv6Guard
            | Self::NdpMitmProof => ProtocolFamily::NdpIpv6,
            Self::PortSecurity
            | Self::StickyMacMove
            | Self::UnknownUnicast
            | Self::ClientPvlanIsolation
            | Self::MacAging
            | Self::BoundedMacPopulation
            | Self::DisruptiveCamProtection => ProtocolFamily::MacSwitch,
        }
    }

    /// Return the activity class from the immutable catalog
    #[must_use]
    pub const fn activity(self) -> ActivityClass {
        match self {
            Self::Dai | Self::SourceGuard | Self::StaticArp | Self::RaGuard | Self::Dhcpv6Guard => {
                ActivityClass::SafeActive
            }
            Self::DisruptiveCamProtection => ActivityClass::Disruptive,
            Self::ArpMitmProof
            | Self::NdpMitmProof
            | Self::ArpSpoofSusceptibility
            | Self::GratuitousArp
            | Self::GatewayConflict
            | Self::HostConflict
            | Self::DuplicateAddressHandling
            | Self::NdpSpoofSusceptibility
            | Self::UnsolicitedNa
            | Self::RouterImpersonation
            | Self::PortSecurity
            | Self::StickyMacMove
            | Self::UnknownUnicast
            | Self::ClientPvlanIsolation
            | Self::MacAging
            | Self::BoundedMacPopulation => ActivityClass::Stateful,
        }
    }

    /// Return the risk class from the immutable catalog
    #[must_use]
    pub const fn risk(self) -> RiskClass {
        match self {
            Self::ArpMitmProof | Self::NdpMitmProof | Self::DisruptiveCamProtection => {
                RiskClass::Critical
            }
            Self::ArpSpoofSusceptibility
            | Self::GatewayConflict
            | Self::HostConflict
            | Self::DuplicateAddressHandling
            | Self::NdpSpoofSusceptibility
            | Self::RouterImpersonation
            | Self::UnknownUnicast
            | Self::ClientPvlanIsolation
            | Self::BoundedMacPopulation => RiskClass::High,
            Self::GratuitousArp
            | Self::Dai
            | Self::SourceGuard
            | Self::StaticArp
            | Self::UnsolicitedNa
            | Self::RaGuard
            | Self::Dhcpv6Guard
            | Self::PortSecurity
            | Self::StickyMacMove
            | Self::MacAging => RiskClass::Moderate,
        }
    }

    /// Return whether an endpoint with the given family can exercise this check
    #[must_use]
    pub fn accepts_family(self, family: AddressFamily) -> bool {
        match self.family() {
            ProtocolFamily::MacSwitch => true,
            family_kind => family_kind == family.protocol(),
        }
    }

    /// Return whether a transition disposition belongs to this exact check
    /// category
    ///
    /// Stable and unknown remain valid conservative observations for every
    /// check. Active dispositions use this table: generic NDP spoof checks
    /// accept unsolicited and router evidence, RA evidence cannot stand in for
    /// `DHCPv6` evidence, MAC move evidence is limited to port-security and
    /// sticky-MAC checks, and MITM evidence is explicit
    #[must_use]
    pub const fn accepts_disposition(self, disposition: NeighborDisposition) -> bool {
        match disposition {
            NeighborDisposition::Stable | NeighborDisposition::Unknown => true,
            NeighborDisposition::ConflictRejected | NeighborDisposition::ConflictAccepted => {
                matches!(
                    self,
                    Self::ArpSpoofSusceptibility
                        | Self::GratuitousArp
                        | Self::GatewayConflict
                        | Self::HostConflict
                        | Self::Dai
                        | Self::SourceGuard
                        | Self::StaticArp
                        | Self::DuplicateAddressHandling
                )
            }
            NeighborDisposition::UnsolicitedAdvertisementRejected
            | NeighborDisposition::UnsolicitedAdvertisementAccepted => {
                matches!(self, Self::NdpSpoofSusceptibility | Self::UnsolicitedNa)
            }
            NeighborDisposition::RouterAdvertisementRejected
            | NeighborDisposition::RouterAdvertisementAccepted => matches!(
                self,
                Self::NdpSpoofSusceptibility | Self::RouterImpersonation | Self::RaGuard
            ),
            NeighborDisposition::MacMoveRejected | NeighborDisposition::MacMoveAccepted => {
                matches!(self, Self::PortSecurity | Self::StickyMacMove)
            }
            NeighborDisposition::MitmBlocked | NeighborDisposition::MitmObserved => {
                matches!(self, Self::ArpMitmProof | Self::NdpMitmProof)
            }
        }
    }
}
