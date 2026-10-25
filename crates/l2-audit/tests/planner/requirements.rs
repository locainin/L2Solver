use super::support::{entry, segmentation_policy};
use l2_audit::{
    Capability, CoverageStatus, Disposition, PlannerInput, Policy, Protocol, plan_passive,
};
use std::error::Error;

#[test]
fn missing_active_requirements_are_reported() -> Result<(), Box<dyn Error>> {
    let input = PlannerInput::new().with_protocol(Protocol::Stp);
    let plan = plan_passive(&input, &segmentation_policy());

    let segmentation = entry(&plan, "SEG-001")?;
    assert!(segmentation.applicable);
    assert_eq!(segmentation.coverage, CoverageStatus::NotTested);
    assert!(
        segmentation
            .missing_requirements
            .iter()
            .any(|missing| missing.contains("agent"))
    );

    let bpdu_guard = entry(&plan, "STP-GUARD-001")?;
    assert!(bpdu_guard.applicable);
    assert!(
        bpdu_guard
            .missing_requirements
            .iter()
            .any(|missing| missing.contains("transmit"))
    );
    Ok(())
}

#[test]
fn passive_planning_stays_non_transmitting() -> Result<(), Box<dyn Error>> {
    let input = PlannerInput::new()
        .with_protocol(Protocol::Stp)
        .with_agent_count(2)?
        .with_capability(Capability::ActiveTransmit);
    let plan = plan_passive(&input, &segmentation_policy());

    let segmentation = entry(&plan, "SEG-001")?;
    assert!(segmentation.applicable);
    assert_eq!(segmentation.coverage, CoverageStatus::NotTested);
    assert!(
        segmentation
            .missing_requirements
            .iter()
            .all(|missing| !missing.contains("agent") && !missing.contains("transmit"))
    );
    assert!(segmentation.reason.contains("passive planner"));
    Ok(())
}

#[test]
fn segmentation_requires_directed_policy() -> Result<(), Box<dyn Error>> {
    let input = PlannerInput::new()
        .with_agent_count(2)?
        .with_capability(Capability::ActiveTransmit);
    let plan = plan_passive(&input, &Policy::default());
    let segmentation = entry(&plan, "SEG-001")?;

    assert!(!segmentation.applicable);
    assert_eq!(segmentation.coverage, CoverageStatus::NotApplicable);
    assert!(
        segmentation
            .missing_requirements
            .iter()
            .any(|missing| missing.contains("directed segmentation"))
    );
    Ok(())
}

#[test]
fn control_protocol_policy_is_tested() -> Result<(), Box<dyn Error>> {
    let mut policy = segmentation_policy();
    let segment = policy
        .segments
        .as_mut()
        .and_then(|segments| segments.get_mut("guest"))
        .ok_or("missing guest segment")?;
    segment
        .protocols
        .insert(Protocol::Dtp, Disposition::Forbidden);

    let plan = plan_passive(&PlannerInput::new(), &policy);
    let protocol_policy = entry(&plan, "CTRL-POLICY-001")?;

    assert!(protocol_policy.applicable);
    assert_eq!(protocol_policy.coverage, CoverageStatus::Tested);
    Ok(())
}

#[test]
fn endpoint_policies_are_tested() -> Result<(), Box<dyn Error>> {
    let mut policy = segmentation_policy();
    let segment = policy
        .segments
        .as_mut()
        .and_then(|segments| segments.get_mut("guest"))
        .ok_or("missing guest segment")?;
    segment.lldp = Disposition::Forbidden;
    segment.stp_endpoint = Disposition::Forbidden;

    let plan = plan_passive(&PlannerInput::new(), &policy);
    for check_id in ["LLDP-002", "STP-003"] {
        let planned = entry(&plan, check_id)?;
        assert!(planned.applicable, "{check_id}");
        assert_eq!(planned.coverage, CoverageStatus::Tested, "{check_id}");
        assert_eq!(planned.risk, l2_audit::RiskClass::Passive, "{check_id}");
    }

    let empty_plan = plan_passive(&PlannerInput::new(), &Policy::default());
    for check_id in ["LLDP-002", "STP-003"] {
        assert_eq!(
            entry(&empty_plan, check_id)?.coverage,
            CoverageStatus::NotApplicable,
            "{check_id}"
        );
    }
    Ok(())
}

#[test]
fn absent_protocols_are_not_applicable() -> Result<(), Box<dyn Error>> {
    let plan = plan_passive(&PlannerInput::new(), &Policy::default());

    for check_id in ["DOT1X-001", "DTP-001", "DHCP-001", "IPV6-001"] {
        let planned = entry(&plan, check_id)?;
        assert!(!planned.applicable, "{check_id} should not be applicable");
        assert_eq!(planned.coverage, CoverageStatus::NotApplicable);
        assert!(!planned.recommendation);
    }
    Ok(())
}

#[test]
fn required_8021x_recommended_without_eapol() -> Result<(), Box<dyn Error>> {
    let policy: Policy = serde_json::from_str(
        r#"{
            "schema_version": 2,
            "segments": {
                "workstation": { "require_8021x": true }
            },
            "ports": [
                { "section": 0, "index": 0, "segment": "workstation", "role": "access" }
            ]
        }"#,
    )?;
    policy.validate()?;

    let plan = plan_passive(&PlannerInput::new(), &policy);
    let planned = entry(&plan, "DOT1X-POLICY-001")?;

    assert!(planned.applicable);
    assert!(planned.recommendation);
    assert_eq!(planned.coverage, CoverageStatus::NotTested);
    assert!(
        planned
            .missing_requirements
            .iter()
            .any(|missing| missing.contains("transmit"))
    );

    let unavailable = plan_passive(&PlannerInput::new().with_capture_available(false), &policy);
    assert_eq!(
        entry(&unavailable, "DOT1X-POLICY-001")?.coverage,
        CoverageStatus::NotApplicable
    );
    Ok(())
}

#[test]
fn agent_count_is_bounded() {
    let input = PlannerInput::new().with_agent_count(65);
    assert!(input.is_err());
}
