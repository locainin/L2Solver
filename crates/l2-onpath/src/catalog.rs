//! Static descriptor catalog for endpoint and on-path checks

use crate::{ActivityClass, Budget, CheckKind, ProtocolFamily, RiskClass};

/// A data-only description of one bounded check
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckDescriptor {
    /// Stable enum key
    kind: CheckKind,
    /// Stable report identifier
    id: &'static str,
    /// Operator-facing title
    title: &'static str,
    /// Protocol family exercised by the descriptor
    family: ProtocolFamily,
    /// Interaction class used by the descriptor
    activity: ActivityClass,
    /// Explicit operator risk class
    risk: RiskClass,
    /// Packet, byte, and duration ceilings
    budget: Budget,
    /// Minimum number of controlled endpoints
    required_endpoints: u8,
}

impl CheckDescriptor {
    /// Construct one static descriptor
    pub(crate) const fn new(
        kind: CheckKind,
        id: &'static str,
        title: &'static str,
        family: ProtocolFamily,
        activity: ActivityClass,
        risk: RiskClass,
        budget: Budget,
    ) -> Self {
        Self {
            kind,
            id,
            title,
            family,
            activity,
            risk,
            budget,
            required_endpoints: 2,
        }
    }

    /// Return the enum key
    #[must_use]
    pub const fn kind(self) -> CheckKind {
        self.kind
    }

    /// Return the stable catalog identifier
    #[must_use]
    pub const fn id(self) -> &'static str {
        self.id
    }

    /// Return the operator-facing title
    #[must_use]
    pub const fn title(self) -> &'static str {
        self.title
    }

    /// Return the protocol family under test
    #[must_use]
    pub const fn family(self) -> ProtocolFamily {
        self.family
    }

    /// Return the activity class
    #[must_use]
    pub const fn activity(self) -> ActivityClass {
        self.activity
    }

    /// Return the explicit risk class
    #[must_use]
    pub const fn risk(self) -> RiskClass {
        self.risk
    }

    /// Return packet, byte, and duration ceilings
    #[must_use]
    pub const fn budget(self) -> Budget {
        self.budget
    }

    /// Return the packet ceiling without unpacking the budget
    #[must_use]
    pub const fn packet_budget(self) -> u64 {
        self.budget.packets()
    }

    /// Return the byte ceiling without unpacking the budget
    #[must_use]
    pub const fn byte_budget(self) -> u64 {
        self.budget.bytes()
    }

    /// Return the duration ceiling in milliseconds
    #[must_use]
    pub const fn duration_budget_millis(self) -> u64 {
        self.budget.duration_millis()
    }

    /// Return the minimum number of controlled endpoints needed
    #[must_use]
    pub const fn required_endpoints(self) -> u8 {
        self.required_endpoints
    }

    /// Return whether this descriptor still requires physical qualification
    #[must_use]
    pub const fn physical_integration_gated(self) -> bool {
        true
    }
}

const ARP_BUDGET: Budget = Budget::const_new(256, 65_536, 30_000);
const NDP_BUDGET: Budget = Budget::const_new(256, 65_536, 30_000);
const SWITCH_BUDGET: Budget = Budget::const_new(256, 65_536, 30_000);
const CAM_BUDGET: Budget = Budget::const_new(512, 131_072, 60_000);

// Catalog entries describe authorization and evidence requirements only
static CATALOG: [CheckDescriptor; crate::MAX_CHECKS] = [
    CheckDescriptor::new(
        CheckKind::ArpSpoofSusceptibility,
        "ARP-SPOOF-001",
        "ARP spoof susceptibility",
        ProtocolFamily::ArpIpv4,
        ActivityClass::Stateful,
        RiskClass::High,
        ARP_BUDGET,
    ),
    CheckDescriptor::new(
        CheckKind::GratuitousArp,
        "ARP-GRATUITOUS-001",
        "gratuitous ARP handling",
        ProtocolFamily::ArpIpv4,
        ActivityClass::Stateful,
        RiskClass::Moderate,
        ARP_BUDGET,
    ),
    CheckDescriptor::new(
        CheckKind::GatewayConflict,
        "ARP-GATEWAY-CONFLICT-001",
        "gateway identity conflict handling",
        ProtocolFamily::ArpIpv4,
        ActivityClass::Stateful,
        RiskClass::High,
        ARP_BUDGET,
    ),
    CheckDescriptor::new(
        CheckKind::HostConflict,
        "ARP-HOST-CONFLICT-001",
        "host identity conflict handling",
        ProtocolFamily::ArpIpv4,
        ActivityClass::Stateful,
        RiskClass::High,
        ARP_BUDGET,
    ),
    CheckDescriptor::new(
        CheckKind::Dai,
        "ARP-DAI-001",
        "Dynamic ARP Inspection",
        ProtocolFamily::ArpIpv4,
        ActivityClass::SafeActive,
        RiskClass::Moderate,
        ARP_BUDGET,
    ),
    CheckDescriptor::new(
        CheckKind::SourceGuard,
        "ARP-SOURCE-GUARD-001",
        "IP source guard",
        ProtocolFamily::ArpIpv4,
        ActivityClass::SafeActive,
        RiskClass::Moderate,
        ARP_BUDGET,
    ),
    CheckDescriptor::new(
        CheckKind::StaticArp,
        "ARP-STATIC-001",
        "static ARP enforcement",
        ProtocolFamily::ArpIpv4,
        ActivityClass::SafeActive,
        RiskClass::Moderate,
        ARP_BUDGET,
    ),
    CheckDescriptor::new(
        CheckKind::DuplicateAddressHandling,
        "ARP-DUPLICATE-001",
        "duplicate IPv4 address handling",
        ProtocolFamily::ArpIpv4,
        ActivityClass::Stateful,
        RiskClass::High,
        ARP_BUDGET,
    ),
    CheckDescriptor::new(
        CheckKind::ArpMitmProof,
        "ARP-MITM-001",
        "authenticated ARP MITM path proof",
        ProtocolFamily::ArpIpv4,
        ActivityClass::Stateful,
        RiskClass::Critical,
        ARP_BUDGET,
    ),
    CheckDescriptor::new(
        CheckKind::NdpSpoofSusceptibility,
        "NDP-SPOOF-001",
        "NDP spoof susceptibility",
        ProtocolFamily::NdpIpv6,
        ActivityClass::Stateful,
        RiskClass::High,
        NDP_BUDGET,
    ),
    CheckDescriptor::new(
        CheckKind::UnsolicitedNa,
        "NDP-UNSOLICITED-NA-001",
        "unsolicited Neighbor Advertisement handling",
        ProtocolFamily::NdpIpv6,
        ActivityClass::Stateful,
        RiskClass::Moderate,
        NDP_BUDGET,
    ),
    CheckDescriptor::new(
        CheckKind::RouterImpersonation,
        "NDP-ROUTER-001",
        "IPv6 router impersonation handling",
        ProtocolFamily::NdpIpv6,
        ActivityClass::Stateful,
        RiskClass::High,
        NDP_BUDGET,
    ),
    CheckDescriptor::new(
        CheckKind::RaGuard,
        "NDP-RA-GUARD-001",
        "Router Advertisement Guard",
        ProtocolFamily::NdpIpv6,
        ActivityClass::SafeActive,
        RiskClass::Moderate,
        NDP_BUDGET,
    ),
    CheckDescriptor::new(
        CheckKind::Dhcpv6Guard,
        "NDP-DHCPV6-GUARD-001",
        "DHCPv6 Guard",
        ProtocolFamily::NdpIpv6,
        ActivityClass::SafeActive,
        RiskClass::Moderate,
        NDP_BUDGET,
    ),
    CheckDescriptor::new(
        CheckKind::NdpMitmProof,
        "NDP-MITM-001",
        "authenticated NDP MITM path proof",
        ProtocolFamily::NdpIpv6,
        ActivityClass::Stateful,
        RiskClass::Critical,
        NDP_BUDGET,
    ),
    CheckDescriptor::new(
        CheckKind::PortSecurity,
        "MAC-PORT-SECURITY-001",
        "port-security admission",
        ProtocolFamily::MacSwitch,
        ActivityClass::Stateful,
        RiskClass::Moderate,
        SWITCH_BUDGET,
    ),
    CheckDescriptor::new(
        CheckKind::StickyMacMove,
        "MAC-STICKY-MOVE-001",
        "sticky-MAC move handling",
        ProtocolFamily::MacSwitch,
        ActivityClass::Stateful,
        RiskClass::Moderate,
        SWITCH_BUDGET,
    ),
    CheckDescriptor::new(
        CheckKind::UnknownUnicast,
        "MAC-UNKNOWN-UNICAST-001",
        "unknown-unicast forwarding",
        ProtocolFamily::MacSwitch,
        ActivityClass::Stateful,
        RiskClass::High,
        SWITCH_BUDGET,
    ),
    CheckDescriptor::new(
        CheckKind::ClientPvlanIsolation,
        "MAC-CLIENT-ISOLATION-001",
        "client or PVLAN isolation",
        ProtocolFamily::MacSwitch,
        ActivityClass::Stateful,
        RiskClass::High,
        SWITCH_BUDGET,
    ),
    CheckDescriptor::new(
        CheckKind::MacAging,
        "MAC-AGING-001",
        "learned-MAC aging",
        ProtocolFamily::MacSwitch,
        ActivityClass::Stateful,
        RiskClass::Moderate,
        SWITCH_BUDGET,
    ),
    CheckDescriptor::new(
        CheckKind::BoundedMacPopulation,
        "MAC-POPULATION-001",
        "bounded MAC population",
        ProtocolFamily::MacSwitch,
        ActivityClass::Stateful,
        RiskClass::High,
        SWITCH_BUDGET,
    ),
    CheckDescriptor::new(
        CheckKind::DisruptiveCamProtection,
        "MAC-CAM-PROTECTION-001",
        "disruptive CAM-table protection",
        ProtocolFamily::MacSwitch,
        ActivityClass::Disruptive,
        RiskClass::Critical,
        CAM_BUDGET,
    ),
];

/// Return every static endpoint/on-path descriptor in stable order
#[must_use]
pub fn catalog() -> &'static [CheckDescriptor] {
    &CATALOG
}

/// Return the descriptor for one check kind
#[must_use]
pub fn descriptor(kind: CheckKind) -> &'static CheckDescriptor {
    // Destructuring makes a catalog-size mismatch fail at compile time
    let [
        arp_spoof,
        gratuitous_arp,
        gateway_conflict,
        host_conflict,
        dai,
        source_guard,
        static_arp,
        duplicate_address,
        arp_mitm,
        ndp_spoof,
        unsolicited_na,
        router_impersonation,
        ra_guard,
        dhcpv6_guard,
        ndp_mitm,
        port_security,
        sticky_mac_move,
        unknown_unicast,
        client_isolation,
        mac_aging,
        bounded_mac_population,
        cam_protection,
    ] = &CATALOG;
    match kind {
        CheckKind::ArpSpoofSusceptibility => arp_spoof,
        CheckKind::GratuitousArp => gratuitous_arp,
        CheckKind::GatewayConflict => gateway_conflict,
        CheckKind::HostConflict => host_conflict,
        CheckKind::Dai => dai,
        CheckKind::SourceGuard => source_guard,
        CheckKind::StaticArp => static_arp,
        CheckKind::DuplicateAddressHandling => duplicate_address,
        CheckKind::ArpMitmProof => arp_mitm,
        CheckKind::NdpSpoofSusceptibility => ndp_spoof,
        CheckKind::UnsolicitedNa => unsolicited_na,
        CheckKind::RouterImpersonation => router_impersonation,
        CheckKind::RaGuard => ra_guard,
        CheckKind::Dhcpv6Guard => dhcpv6_guard,
        CheckKind::NdpMitmProof => ndp_mitm,
        CheckKind::PortSecurity => port_security,
        CheckKind::StickyMacMove => sticky_mac_move,
        CheckKind::UnknownUnicast => unknown_unicast,
        CheckKind::ClientPvlanIsolation => client_isolation,
        CheckKind::MacAging => mac_aging,
        CheckKind::BoundedMacPopulation => bounded_mac_population,
        CheckKind::DisruptiveCamProtection => cam_protection,
    }
}
