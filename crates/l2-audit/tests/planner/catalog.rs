use super::support::entry;
use l2_audit::{CoverageStatus, PlannerInput, Policy, Protocol, RiskClass, catalog, plan_passive};
use std::error::Error;

#[test]
fn catalog_contains_sorted_risk_classes() {
    let input = PlannerInput::new()
        .with_protocol(Protocol::Arp)
        .with_protocol(Protocol::Stp);
    let plan = plan_passive(&input, &Policy::default());

    let risks: Vec<_> = plan.entries.iter().map(|entry| entry.risk).collect();
    assert!(risks.contains(&RiskClass::Passive));
    assert!(risks.contains(&RiskClass::SafeActive));
    assert!(risks.contains(&RiskClass::Stateful));
    assert!(risks.contains(&RiskClass::Disruptive));

    let ids: Vec<_> = plan
        .entries
        .iter()
        .map(|entry| entry.check_id.as_str())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted);

    let mut unique = ids.clone();
    unique.dedup();
    assert_eq!(ids, unique, "check identifiers must be unique");
    assert_eq!(catalog().len(), ids.len());
}

#[test]
fn passive_protocols_have_inventory_checks() -> Result<(), Box<dyn Error>> {
    let expected = [
        (Protocol::Arp, "ARP-INVENTORY-001"),
        (Protocol::Cdp, "CDP-OBS-001"),
        (Protocol::Dhcp, "DHCP-INVENTORY-001"),
        (Protocol::Dhcpv6, "DHCPV6-OBS-001"),
        (Protocol::Eapol, "DOT1X-OBS-001"),
        (Protocol::Dtp, "DTP-OBS-001"),
        (Protocol::Hsrp, "HSRP-OBS-001"),
        (Protocol::Igmp, "IGMP-OBS-001"),
        (Protocol::Ipv6Nd, "IPV6-ND-001"),
        (Protocol::Ipv6Ra, "IPV6-RA-OBS-001"),
        (Protocol::Lacp, "LACP-OBS-001"),
        (Protocol::Lldp, "LLDP-001"),
        (Protocol::Macsec, "MACSEC-OBS-001"),
        (Protocol::Mka, "MKA-OBS-001"),
        (Protocol::Mdns, "MDNS-OBS-001"),
        (Protocol::Mld, "MLD-001"),
        (Protocol::Netbios, "NETBIOS-OBS-001"),
        (Protocol::Pagp, "PAGP-OBS-001"),
        (Protocol::PvstPlus, "PVST-OBS-001"),
        (Protocol::Ssdp, "SSDP-OBS-001"),
        (Protocol::Stp, "STP-001"),
        (Protocol::Vrrp, "VRRP-OBS-001"),
        (Protocol::Vtp, "VTP-OBS-001"),
    ];

    for (protocol, check_id) in expected {
        let plan = plan_passive(
            &PlannerInput::new().with_protocol(protocol),
            &Policy::default(),
        );
        let planned = entry(&plan, check_id)?;
        assert!(planned.applicable, "{check_id} should be applicable");
        assert_eq!(planned.coverage, CoverageStatus::Tested, "{check_id}");
        assert_eq!(planned.risk, RiskClass::Passive, "{check_id}");
        assert!(!planned.recommendation, "{check_id}");
        assert!(planned.missing_requirements.is_empty(), "{check_id}");
    }
    Ok(())
}

#[test]
fn stateful_checks_not_safe_active() -> Result<(), Box<dyn Error>> {
    let input = PlannerInput::new()
        .with_protocol(Protocol::Dtp)
        .with_protocol(Protocol::Lacp);
    let plan = plan_passive(&input, &Policy::default());

    for check_id in ["DTP-001", "LACP-001"] {
        let planned = entry(&plan, check_id)?;
        assert_eq!(planned.risk, RiskClass::Stateful, "{check_id}");
        assert_eq!(planned.coverage, CoverageStatus::NotTested, "{check_id}");
    }
    assert_eq!(entry(&plan, "STORM-001")?.risk, RiskClass::Disruptive);
    Ok(())
}

#[test]
fn observed_protocols_enable_follow_ups() -> Result<(), Box<dyn Error>> {
    let input = PlannerInput::new()
        .with_protocol(Protocol::Eapol)
        .with_protocol(Protocol::Dtp)
        .with_protocol(Protocol::Dhcp)
        .with_protocol(Protocol::Ipv6Ra);
    let plan = plan_passive(&input, &Policy::default());

    for check_id in ["DOT1X-001", "DTP-001", "DHCP-001", "IPV6-001"] {
        let planned = entry(&plan, check_id)?;
        assert!(planned.applicable, "{check_id} should be applicable");
        assert!(planned.recommendation, "{check_id} should be recommended");
        assert_eq!(planned.coverage, CoverageStatus::NotTested);
    }
    assert!(
        plan.recommendations
            .iter()
            .any(|recommendation| recommendation.check_id == "DOT1X-001")
    );
    Ok(())
}
