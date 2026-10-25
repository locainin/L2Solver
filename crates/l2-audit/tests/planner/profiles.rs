use std::error::Error;

use l2_audit::{
    AssessmentProfile, Capability, PlannerInput, Policy, PortRole, Requirement, RequirementKind,
    RiskClass, plan_passive,
};

use super::support::entry;

#[test]
fn requirement_kinds_are_explicit() {
    assert_eq!(
        Requirement::Capability(Capability::ActiveTransmit).kind(),
        RequirementKind::Capability
    );
    assert_eq!(
        Requirement::DiscoveryHint(l2_audit::Protocol::Dtp).kind(),
        RequirementKind::DiscoveryHint
    );
}

#[test]
fn opportunistic_profile_requires_discovery() -> Result<(), Box<dyn Error>> {
    let plan = plan_passive(&PlannerInput::new(), &Policy::default());

    assert!(!entry(&plan, "DTP-001")?.applicable);
    Ok(())
}

#[test]
fn standard_profile_uses_access_role() -> Result<(), Box<dyn Error>> {
    let input = PlannerInput::new()
        .with_profile(AssessmentProfile::Standard)
        .with_port_role(PortRole::EndpointAccess);
    let plan = plan_passive(&input, &Policy::default());
    let dtp = entry(&plan, "DTP-001")?;

    assert!(dtp.applicable);
    assert_eq!(dtp.risk, RiskClass::Stateful);
    assert!(
        dtp.missing_requirements
            .iter()
            .any(|item| item.contains("transmit"))
    );
    Ok(())
}

#[test]
fn profile_not_need_passive_hint() -> Result<(), Box<dyn Error>> {
    let input = PlannerInput::new().with_profile(AssessmentProfile::Full);
    let plan = plan_passive(&input, &Policy::default());

    for check_id in ["DTP-001", "DHCP-001", "IPV6-001", "STP-GUARD-001"] {
        let planned = entry(&plan, check_id)?;
        assert!(planned.applicable, "{check_id}");
        assert!(planned.recommendation, "{check_id}");
    }
    assert!(!entry(&plan, "DTP-OBS-001")?.applicable);
    Ok(())
}
