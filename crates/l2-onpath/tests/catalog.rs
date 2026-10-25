use std::collections::BTreeSet;

use l2_onpath::{ActivityClass, CheckKind, ProtocolFamily, RiskClass, catalog, descriptor};

#[test]
fn catalog_covers_requested_checks() {
    let required = [
        CheckKind::ArpSpoofSusceptibility,
        CheckKind::GratuitousArp,
        CheckKind::GatewayConflict,
        CheckKind::HostConflict,
        CheckKind::Dai,
        CheckKind::SourceGuard,
        CheckKind::StaticArp,
        CheckKind::DuplicateAddressHandling,
        CheckKind::ArpMitmProof,
        CheckKind::NdpSpoofSusceptibility,
        CheckKind::UnsolicitedNa,
        CheckKind::RouterImpersonation,
        CheckKind::RaGuard,
        CheckKind::Dhcpv6Guard,
        CheckKind::NdpMitmProof,
        CheckKind::PortSecurity,
        CheckKind::StickyMacMove,
        CheckKind::UnknownUnicast,
        CheckKind::ClientPvlanIsolation,
        CheckKind::MacAging,
        CheckKind::BoundedMacPopulation,
        CheckKind::DisruptiveCamProtection,
    ];
    let ids: BTreeSet<_> = catalog().iter().map(|item| item.id()).collect();
    assert_eq!(catalog().len(), required.len());
    assert_eq!(catalog().len(), l2_onpath::MAX_CHECKS);
    assert!(
        catalog().iter().map(|item| item.kind()).eq(required),
        "catalog order must stay aligned with CheckKind catalog indices"
    );
    for kind in required {
        let item = descriptor(kind);
        assert_eq!(item.kind(), kind);
        assert!(ids.contains(item.id()));
        assert!(item.budget().packets() > 0);
        assert!(item.budget().bytes() > 0);
        assert!(item.budget().duration_millis() > 0);
        assert!(item.physical_integration_gated());
    }

    assert_eq!(
        descriptor(CheckKind::ArpSpoofSusceptibility).family(),
        ProtocolFamily::ArpIpv4
    );
    assert_eq!(
        descriptor(CheckKind::NdpSpoofSusceptibility).family(),
        ProtocolFamily::NdpIpv6
    );
    assert_eq!(
        descriptor(CheckKind::PortSecurity).family(),
        ProtocolFamily::MacSwitch
    );
    assert_eq!(
        descriptor(CheckKind::DisruptiveCamProtection).activity(),
        ActivityClass::Disruptive
    );
    assert_eq!(
        descriptor(CheckKind::ArpMitmProof).risk(),
        RiskClass::Critical
    );
}

#[test]
fn catalog_entry_fields() {
    let item = descriptor(CheckKind::ArpSpoofSusceptibility);
    assert_eq!(item.kind(), CheckKind::ArpSpoofSusceptibility);
    assert_eq!(item.id(), "ARP-SPOOF-001");
    assert_eq!(item.title(), "ARP spoof susceptibility");
    assert_eq!(item.family(), ProtocolFamily::ArpIpv4);
    assert_eq!(item.activity(), ActivityClass::Stateful);
    assert_eq!(item.risk(), RiskClass::High);
    assert_eq!(item.packet_budget(), 256);
    assert_eq!(item.byte_budget(), 65_536);
    assert_eq!(item.duration_budget_millis(), 30_000);
    assert_eq!(item.required_endpoints(), 2);
    assert!(item.physical_integration_gated());
}

#[test]
fn classification_display_labels() {
    // Stable labels keep reports consistent across activity and risk classes
    assert_eq!(ActivityClass::Passive.as_str(), "passive");
    assert_eq!(ActivityClass::SafeActive.as_str(), "safe_active");
    assert_eq!(ActivityClass::Stateful.as_str(), "stateful");
    assert_eq!(ActivityClass::Disruptive.as_str(), "disruptive");
    assert_eq!(RiskClass::Low.as_str(), "low");
    assert_eq!(RiskClass::Moderate.as_str(), "moderate");
    assert_eq!(RiskClass::High.as_str(), "high");
    assert_eq!(RiskClass::Critical.as_str(), "critical");
}

#[test]
fn check_address_families() {
    assert!(CheckKind::ArpSpoofSusceptibility.accepts_family(l2_onpath::AddressFamily::Ipv4));
    assert!(!CheckKind::ArpSpoofSusceptibility.accepts_family(l2_onpath::AddressFamily::Ipv6));
    assert!(CheckKind::PortSecurity.accepts_family(l2_onpath::AddressFamily::Ipv4));
    assert!(CheckKind::PortSecurity.accepts_family(l2_onpath::AddressFamily::Ipv6));
}

#[test]
fn check_descriptor_identifier() {
    assert_eq!(
        CheckKind::DisruptiveCamProtection.descriptor().id(),
        "MAC-CAM-PROTECTION-001"
    );
}
