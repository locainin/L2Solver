use super::support::{entry, interface};
use l2_audit::{
    BridgeIdentity, CoverageStatus, PlannerInput, Policy, PortBinding, SegmentExpectations,
    plan_passive,
};
use std::collections::BTreeMap;
use std::error::Error;

fn multi_source_policy(expected: &BridgeIdentity) -> Policy {
    Policy {
        schema_version: Some(2),
        segments: Some(BTreeMap::from([(
            "access".into(),
            SegmentExpectations {
                expected_stp_bridge: Some(expected.clone()),
                ..SegmentExpectations::default()
            },
        )])),
        ports: Some(
            [0, 1]
                .into_iter()
                .map(|index| PortBinding {
                    section: 0,
                    index,
                    segment: "access".into(),
                    role: "access".into(),
                })
                .collect(),
        ),
        ..Policy::default()
    }
}

fn root_interface(
    index: u32,
    expected: BridgeIdentity,
    packet: u64,
) -> l2_audit::InterfaceObservation {
    let mut source = interface(index);
    source.stp_frames = 1;
    source.stp.push(l2_audit::StpObservation {
        root: expected,
        version: "Rstp".into(),
        packet,
        frames: 1,
    });
    source
}

#[test]
fn root_policy_needs_root_advertisement() -> Result<(), Box<dyn Error>> {
    let policy = Policy {
        expected_stp_root: Some("00:11:22:33:44:55".into()),
        ..Policy::default()
    };
    let mut tcn_only = interface(0);
    tcn_only.stp_frames = 1;
    let planned = plan_passive(&PlannerInput::from_interfaces(&[tcn_only]), &policy);

    assert_eq!(entry(&planned, "STP-001")?.coverage, CoverageStatus::Tested);
    let expected_root = entry(&planned, "STP-002")?;
    assert!(expected_root.applicable);
    assert_eq!(expected_root.coverage, CoverageStatus::NotTested);
    assert_eq!(
        expected_root.missing_requirements,
        ["a root-bearing STP advertisement"]
    );
    Ok(())
}

#[test]
fn root_policy_needs_evidence_source() -> Result<(), Box<dyn Error>> {
    let expected = BridgeIdentity {
        priority: 32_768,
        system_id_extension: 1,
        mac: "00:11:22:33:44:55".into(),
    };
    let policy = multi_source_policy(&expected);
    policy.validate()?;

    let root_bearing = root_interface(0, expected, 1);
    let mut tcn_only = interface(1);
    tcn_only.stp_frames = 1;
    let planned = plan_passive(
        &PlannerInput::from_interfaces(&[root_bearing, tcn_only]),
        &policy,
    );

    let expected_root = entry(&planned, "STP-002")?;
    assert!(expected_root.applicable);
    assert_eq!(expected_root.coverage, CoverageStatus::NotTested);
    assert_eq!(
        expected_root.missing_requirements,
        ["a root-bearing STP advertisement from every matched source"]
    );

    Ok(())
}

#[test]
fn root_policy_accepts_bound_sources() -> Result<(), Box<dyn Error>> {
    let expected = BridgeIdentity {
        priority: 32_768,
        system_id_extension: 1,
        mac: "00:11:22:33:44:55".into(),
    };
    let policy = multi_source_policy(&expected);
    policy.validate()?;
    let first = root_interface(0, expected.clone(), 1);
    let second = root_interface(1, expected, 2);
    let complete = plan_passive(&PlannerInput::from_interfaces(&[first, second]), &policy);
    assert_eq!(
        entry(&complete, "STP-002")?.coverage,
        CoverageStatus::Tested
    );
    Ok(())
}
