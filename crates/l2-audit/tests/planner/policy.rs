use super::support::{entry, interface, segmentation_policy};
use l2_audit::{
    BridgeIdentity, CoverageStatus, Disposition, PlannerInput, Policy, PortBinding, Protocol,
    Quality, SegmentExpectations, assess, plan_passive,
};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

#[test]
fn policy_requires_capture_matching_source() -> Result<(), Box<dyn Error>> {
    let policy: Policy = serde_json::from_str(
        r#"{
            "schema_version": 2,
            "segments": {
                "guest": { "lldp": "forbidden" }
            },
            "ports": [
                { "section": 0, "index": 7, "segment": "guest", "role": "access" }
            ]
        }"#,
    )?;
    policy.validate()?;

    let unmatched = assess(&[interface(8)], &policy, &Quality::default())?;
    assert_eq!(
        entry(&unmatched.plan, "LLDP-002")?.coverage,
        CoverageStatus::NotApplicable
    );
    let matched = assess(&[interface(7)], &policy, &Quality::default())?;
    assert_eq!(
        entry(&matched.plan, "LLDP-002")?.coverage,
        CoverageStatus::Tested
    );

    let flat = Policy {
        allowed_vlans: Some(vec![10]),
        ..Policy::default()
    };
    let unavailable = plan_passive(&PlannerInput::new().with_capture_available(false), &flat);
    assert_eq!(
        entry(&unavailable, "VLAN-001")?.coverage,
        CoverageStatus::NotApplicable
    );
    Ok(())
}

#[test]
fn legacy_policy_uses_default_source() -> Result<(), Box<dyn Error>> {
    let policy = Policy {
        allowed_vlans: Some(vec![10]),
        ..Policy::default()
    };

    let default_source = plan_passive(&PlannerInput::new(), &policy);
    assert!(entry(&default_source, "VLAN-001")?.applicable);

    let non_default_source = PlannerInput::from_interfaces(&[interface(8)]);
    let non_default = plan_passive(&non_default_source, &policy);
    assert!(!entry(&non_default, "VLAN-001")?.applicable);
    Ok(())
}

#[test]
fn legacy_fields_keep_independent_scope() -> Result<(), Box<dyn Error>> {
    let policy = Policy {
        allowed_vlans: Some(vec![10]),
        allow_untagged: Some(true),
        allow_priority_tagged: Some(false),
        max_vlan_depth: Some(2),
        expected_stp_bridge: Some(BridgeIdentity {
            priority: 32_768,
            system_id_extension: 1,
            mac: String::from("00:11:22:33:44:55"),
        }),
        ..Policy::default()
    };
    let input = PlannerInput::new().with_protocol(Protocol::Stp);
    let plan = plan_passive(&input, &policy);

    for check_id in ["STP-002", "VLAN-001", "VLAN-002", "VLAN-003", "VLAN-004"] {
        assert!(entry(&plan, check_id)?.applicable, "{check_id}");
    }
    Ok(())
}

#[test]
fn scoped_policy_requires_bound_fields() -> Result<(), Box<dyn Error>> {
    let mut scoped = SegmentExpectations {
        allowed_vlans: Some(BTreeSet::new()),
        priority_tagged: Disposition::Forbidden,
        untagged: Disposition::Allowed,
        max_vlan_depth: Some(1),
        expected_stp_bridge: Some(BridgeIdentity {
            priority: 32_768,
            system_id_extension: 1,
            mac: "00:11:22:33:44:55".into(),
        }),
        lldp: Disposition::Forbidden,
        stp_endpoint: Disposition::Forbidden,
        require_8021x: Some(true),
        protocols: BTreeMap::from([(Protocol::Dtp, Disposition::Forbidden)]),
        isolation_from: BTreeSet::from([String::from("other")]),
        allow_to: BTreeSet::new(),
    };
    let policy = Policy {
        schema_version: Some(2),
        segments: Some(BTreeMap::from([
            ("scoped".into(), scoped.clone()),
            ("other".into(), SegmentExpectations::default()),
        ])),
        ports: Some(vec![PortBinding {
            section: 0,
            index: 7,
            segment: "scoped".into(),
            role: "access".into(),
        }]),
        ..Policy::default()
    };
    policy.validate()?;

    let policy_checks = [
        "CTRL-POLICY-001",
        "DOT1X-POLICY-001",
        "LLDP-002",
        "SEG-001",
        "STP-002",
        "STP-003",
        "VLAN-001",
        "VLAN-002",
        "VLAN-003",
        "VLAN-004",
        "VLAN-QINQ-001",
    ];
    let matched_input = PlannerInput::from_interfaces(&[interface(7)]).with_protocol(Protocol::Stp);
    let matched = plan_passive(&matched_input, &policy);
    for check_id in policy_checks {
        assert!(entry(&matched, check_id)?.applicable, "{check_id}");
    }

    let unmatched_input =
        PlannerInput::from_interfaces(&[interface(8)]).with_protocol(Protocol::Stp);
    let unmatched = plan_passive(&unmatched_input, &policy);
    for check_id in policy_checks {
        assert!(!entry(&unmatched, check_id)?.applicable, "{check_id}");
    }

    // Omitted fields remain unspecified even when the segment has other fields
    scoped.allowed_vlans = None;
    let omitted_vlan_policy = Policy {
        segments: Some(BTreeMap::from([
            ("scoped".into(), scoped),
            ("other".into(), SegmentExpectations::default()),
        ])),
        ..policy
    };
    let omitted_vlan = plan_passive(&matched_input, &omitted_vlan_policy);
    assert!(!entry(&omitted_vlan, "VLAN-001")?.applicable);
    Ok(())
}

#[test]
fn policy_reports_unscoped_bound_field() -> Result<(), Box<dyn Error>> {
    let policy = Policy {
        schema_version: Some(2),
        segments: Some(BTreeMap::from([
            (
                "scoped".into(),
                SegmentExpectations {
                    allowed_vlans: Some(BTreeSet::from([10])),
                    ..SegmentExpectations::default()
                },
            ),
            ("unspecified".into(), SegmentExpectations::default()),
        ])),
        ports: Some(vec![
            PortBinding {
                section: 0,
                index: 0,
                segment: "scoped".into(),
                role: "access".into(),
            },
            PortBinding {
                section: 0,
                index: 1,
                segment: "unspecified".into(),
                role: "access".into(),
            },
        ]),
        ..Policy::default()
    };
    policy.validate()?;
    let input = PlannerInput::from_interfaces(&[interface(0), interface(1)]);
    let planned = plan_passive(&input, &policy);
    let vlan = entry(&planned, "VLAN-001")?;

    assert!(vlan.applicable);
    assert_eq!(vlan.coverage, CoverageStatus::NotTested);
    assert!(
        vlan.missing_requirements
            .iter()
            .any(|missing| missing.contains("allowed-VLAN") && missing.contains("every matched"))
    );
    Ok(())
}

#[test]
fn policy_ignores_unbound_sources() -> Result<(), Box<dyn Error>> {
    let segment = SegmentExpectations {
        allowed_vlans: Some(BTreeSet::from([10])),
        ..SegmentExpectations::default()
    };
    let policy = Policy {
        schema_version: Some(2),
        segments: Some(BTreeMap::from([("scoped".into(), segment)])),
        ports: Some(vec![
            PortBinding {
                section: 0,
                index: 0,
                segment: "scoped".into(),
                role: "access".into(),
            },
            PortBinding {
                section: 0,
                index: 2,
                segment: "scoped".into(),
                role: "access".into(),
            },
        ]),
        ..Policy::default()
    };
    policy.validate()?;

    let one_bound_one_unbound = plan_passive(
        &PlannerInput::from_interfaces(&[interface(0), interface(1)]),
        &policy,
    );
    assert_eq!(
        entry(&one_bound_one_unbound, "VLAN-001")?.coverage,
        CoverageStatus::Tested
    );

    let both_bound = plan_passive(
        &PlannerInput::from_interfaces(&[interface(0), interface(2)]),
        &policy,
    );
    assert_eq!(
        entry(&both_bound, "VLAN-001")?.coverage,
        CoverageStatus::Tested
    );
    Ok(())
}

#[test]
fn unspecified_fields_not_enable_checks() -> Result<(), Box<dyn Error>> {
    let policy = Policy {
        schema_version: Some(2),
        segments: Some(BTreeMap::from([(
            String::from("segment"),
            SegmentExpectations::default(),
        )])),
        ports: Some(vec![PortBinding {
            section: 0,
            index: 7,
            segment: String::from("segment"),
            role: String::from("access"),
        }]),
        ..Policy::default()
    };
    let input = PlannerInput::from_interfaces(&[interface(7)]).with_protocol(Protocol::Stp);
    let plan = plan_passive(&input, &policy);

    for check_id in [
        "CTRL-POLICY-001",
        "LLDP-002",
        "SEG-001",
        "STP-002",
        "STP-003",
        "VLAN-001",
        "VLAN-002",
        "VLAN-003",
        "VLAN-004",
        "VLAN-QINQ-001",
    ] {
        assert!(!entry(&plan, check_id)?.applicable, "{check_id}");
    }
    Ok(())
}

#[test]
fn observed_scope_needs_capture() -> Result<(), Box<dyn Error>> {
    let input = PlannerInput::new()
        .with_protocol(Protocol::Lldp)
        .with_capture_available(false);
    let plan = plan_passive(&input, &Policy::default());
    let lldp = entry(&plan, "LLDP-001")?;

    assert!(!lldp.applicable);
    assert_eq!(lldp.coverage, CoverageStatus::NotApplicable);
    Ok(())
}

#[test]
fn passive_recommendations_require_qinq_policy() -> Result<(), Box<dyn Error>> {
    let mut policy = segmentation_policy();
    let plan = plan_passive(&PlannerInput::new(), &policy);

    assert!(
        plan.recommendations
            .iter()
            .all(|recommendation| recommendation.risk != l2_audit::RiskClass::Disruptive)
    );
    assert_eq!(
        entry(&plan, "VLAN-QINQ-001")?.coverage,
        CoverageStatus::NotApplicable
    );
    assert!(entry(&plan, "STORM-001")?.applicable);
    assert!(!entry(&plan, "STORM-001")?.recommendation);

    let segment = policy
        .segments
        .as_mut()
        .and_then(|segments| segments.get_mut("guest"))
        .ok_or("missing guest segment")?;
    segment.max_vlan_depth = Some(1);
    let qinq_plan = plan_passive(&PlannerInput::new(), &policy);
    assert!(entry(&qinq_plan, "VLAN-QINQ-001")?.applicable);
    Ok(())
}
