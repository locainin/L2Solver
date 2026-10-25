use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use l2_canary::{Canary, CanaryIdentity, RunId};
use l2_onpath::{
    ActivityClass, AddressFamily, AgentId, Budget, CanaryExpectation, CheckKind,
    ControlledEndpoint, MacAddress, NeighborBinding, NeighborDisposition, PathExpectation,
    ProtocolFamily, RiskClass, Stimulus, StimulusId,
};

// Keep type construction deterministic so accessor checks remain small
const fn agent(value: u8) -> Result<AgentId, l2_onpath::AgentIdError> {
    AgentId::new([value; l2_onpath::ID_LEN])
}

fn make_canary(
    run: u8,
    source: u8,
    destination: u8,
    sequence: u64,
    nonce: [u8; l2_onpath::NONCE_LEN],
) -> Result<Canary, Box<dyn Error>> {
    let identity = CanaryIdentity::new(
        RunId::from_recorded([run; l2_onpath::ID_LEN])?,
        agent(source)?,
        agent(destination)?,
    )?;
    Ok(Canary::new(identity, sequence, nonce)?)
}

#[test]
fn families_expose_checked_values() -> Result<(), Box<dyn Error>> {
    let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let v6 = IpAddr::V6("2001:db8::10".parse::<Ipv6Addr>()?);
    assert_eq!(ProtocolFamily::ArpIpv4.as_str(), "arp_ipv4");
    assert_eq!(ProtocolFamily::NdpIpv6.as_str(), "ndp_ipv6");
    assert_eq!(ProtocolFamily::MacSwitch.as_str(), "mac_switch");
    assert_eq!(AddressFamily::Ipv4.as_str(), "ipv4");
    assert_eq!(AddressFamily::Ipv6.as_str(), "ipv6");
    assert_eq!(AddressFamily::Ipv4.protocol(), ProtocolFamily::ArpIpv4);
    assert_eq!(AddressFamily::Ipv6.protocol(), ProtocolFamily::NdpIpv6);
    assert!(AddressFamily::Ipv4.matches(&v4));
    assert!(!AddressFamily::Ipv4.matches(&v6));
    assert!(!AddressFamily::Ipv6.matches(&v4));
    assert!(AddressFamily::Ipv6.matches(&v6));
    Ok(())
}

#[test]
fn bindings_expose_checked_values() -> Result<(), Box<dyn Error>> {
    // Binding and endpoint accessors retain both address family and identity
    let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let mac = MacAddress::new([0x02, 1, 2, 3, 4, 5])?;
    assert_eq!(mac.bytes(), [0x02, 1, 2, 3, 4, 5]);
    assert_eq!(mac.as_bytes(), &[0x02, 1, 2, 3, 4, 5]);
    let binding = NeighborBinding::new(agent(3)?, v4, mac)?;
    assert_eq!(binding.address(), v4);
    assert_eq!(binding.mac(), mac);
    assert_eq!(binding.family(), AddressFamily::Ipv4);
    let interface = l2_onpath::InterfaceBindingRequest::new(1, 2, 3, 1)?;
    let endpoint = ControlledEndpoint::new(binding, interface);
    assert_eq!(endpoint.id(), agent(3)?);
    assert_eq!(endpoint.family(), AddressFamily::Ipv4);
    assert_eq!(endpoint.interface(), interface);
    Ok(())
}

#[test]
fn budgets_expose_checked_values() -> Result<(), Box<dyn Error>> {
    // Budget values expose their bounded scalar fields
    let budget = Budget::new(7, 8, 9)?;
    assert_eq!(budget.packets(), 7);
    assert_eq!(budget.bytes(), 8);
    assert_eq!(budget.duration_millis(), 9);
    Ok(())
}

#[test]
fn classes_expose_stable_labels() {
    assert_eq!(ActivityClass::Passive.as_str(), "passive");
    assert_eq!(RiskClass::Critical.as_str(), "critical");
}

#[test]
fn stimuli_expose_checked_values() -> Result<(), Box<dyn Error>> {
    // Stimulus accessors retain the checked identifier and bounded sequence
    let stimulus_id = StimulusId::new(7)?;
    assert_eq!(stimulus_id.get(), 7);
    let stimulus = Stimulus::new(7, CheckKind::ArpSpoofSusceptibility, agent(3)?, 11)?;
    assert_eq!(stimulus.id(), stimulus_id);
    assert_eq!(stimulus.check(), CheckKind::ArpSpoofSusceptibility);
    assert_eq!(stimulus.endpoint(), agent(3)?);
    assert_eq!(stimulus.sequence(), 11);
    Ok(())
}

#[test]
fn canary_expectations_check_identity() -> Result<(), Box<dyn Error>> {
    // Canary expectations compare every authenticated identity component
    let canary = make_canary(1, 3, 4, 11, [9; l2_onpath::NONCE_LEN])?;
    let stimulus_id = StimulusId::new(7)?;
    let expectation =
        CanaryExpectation::new(canary, PathExpectation::Forwarded, stimulus_id.get())?;
    assert_eq!(expectation.canary(), canary);
    assert_eq!(expectation.expectation(), PathExpectation::Forwarded);
    assert_eq!(expectation.stimulus(), stimulus_id);
    assert!(expectation.matches(&canary));
    for changed in [
        make_canary(2, 3, 4, 11, [9; l2_onpath::NONCE_LEN])?,
        make_canary(1, 5, 4, 11, [9; l2_onpath::NONCE_LEN])?,
        make_canary(1, 3, 5, 11, [9; l2_onpath::NONCE_LEN])?,
        make_canary(1, 3, 4, 12, [9; l2_onpath::NONCE_LEN])?,
        make_canary(1, 3, 4, 11, [8; l2_onpath::NONCE_LEN])?,
    ] {
        assert!(!expectation.matches(&changed));
    }
    Ok(())
}

#[test]
fn dispositions_expose_stable_labels() {
    // Every disposition keeps its label and conservative classification stable
    let values = [
        (NeighborDisposition::Stable, "stable", false, true),
        (
            NeighborDisposition::ConflictRejected,
            "conflict_rejected",
            false,
            true,
        ),
        (
            NeighborDisposition::ConflictAccepted,
            "conflict_accepted",
            true,
            false,
        ),
        (
            NeighborDisposition::UnsolicitedAdvertisementRejected,
            "unsolicited_advertisement_rejected",
            false,
            true,
        ),
        (
            NeighborDisposition::UnsolicitedAdvertisementAccepted,
            "unsolicited_advertisement_accepted",
            true,
            false,
        ),
        (
            NeighborDisposition::RouterAdvertisementRejected,
            "router_advertisement_rejected",
            false,
            true,
        ),
        (
            NeighborDisposition::RouterAdvertisementAccepted,
            "router_advertisement_accepted",
            true,
            false,
        ),
        (
            NeighborDisposition::MacMoveRejected,
            "mac_move_rejected",
            false,
            true,
        ),
        (
            NeighborDisposition::MacMoveAccepted,
            "mac_move_accepted",
            true,
            false,
        ),
        (
            NeighborDisposition::MitmBlocked,
            "mitm_blocked",
            false,
            true,
        ),
        (
            NeighborDisposition::MitmObserved,
            "mitm_observed",
            true,
            false,
        ),
        (NeighborDisposition::Unknown, "unknown", false, false),
    ];
    for (value, label, vulnerable, clean) in values {
        assert_eq!(value.as_str(), label);
        assert_eq!(value.is_vulnerable(), vulnerable);
        assert_eq!(value.is_clean(), clean);
    }
}

#[test]
fn dhcpv6_guard_router_advertisement_evidence() {
    // Router Advertisements exercise RA policy, not DHCPv6 Guard
    assert!(
        !CheckKind::Dhcpv6Guard
            .accepts_disposition(NeighborDisposition::RouterAdvertisementRejected)
    );
    assert!(
        !CheckKind::Dhcpv6Guard
            .accepts_disposition(NeighborDisposition::RouterAdvertisementAccepted)
    );

    // The RA-specific checks still accept the exact same observations
    for check in [
        CheckKind::NdpSpoofSusceptibility,
        CheckKind::RouterImpersonation,
        CheckKind::RaGuard,
    ] {
        assert!(check.accepts_disposition(NeighborDisposition::RouterAdvertisementRejected));
        assert!(check.accepts_disposition(NeighborDisposition::RouterAdvertisementAccepted));
    }
}
