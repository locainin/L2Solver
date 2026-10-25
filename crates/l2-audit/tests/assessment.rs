use l2_audit::{
    AssessmentResult, AuditError, BridgeIdentity, CheckCategory, CoverageStatus,
    InterfaceObservation, Neighbor, PlannerInput, Policy, Protocol, Quality, Severity,
    StpObservation, Verdict, VlanObservation, assess, assess_with_input,
};
use std::{collections::BTreeMap, error::Error};

fn interface() -> InterfaceObservation {
    InterfaceObservation {
        section: 0,
        index: 0,
        frames: 4,
        macs: vec!["00:11:22:33:44:55".into()],
        vlans: Vec::new(),
        untagged_packet: Some(1),
        neighbors: Vec::new(),
        protocols: Vec::new(),
        identities: Vec::new(),
        stp_frames: 0,
        stp_packet: None,
        stp: Vec::new(),
    }
}

fn clean_quality() -> Quality {
    Quality {
        frames: 4,
        ..Quality::default()
    }
}

fn category(
    assessment: &AssessmentResult,
    category: CheckCategory,
) -> Result<&l2_audit::CoverageMetric, Box<dyn Error>> {
    assessment
        .coverage_summary
        .iter()
        .find(|entry| entry.category == category)
        .ok_or_else(|| format!("missing coverage category {category:?}").into())
}

fn coverage<'a>(
    assessment: &'a AssessmentResult,
    check_id: &str,
) -> Result<&'a l2_audit::CoverageEntry, Box<dyn Error>> {
    assessment
        .coverage
        .iter()
        .find(|entry| entry.check_id == check_id)
        .ok_or_else(|| format!("missing coverage entry {check_id}").into())
}

#[test]
fn assessment_separates_inventory_findings_coverage() -> Result<(), Box<dyn Error>> {
    let mut observed = interface();
    observed.neighbors.push(Neighbor {
        chassis_id: vec![1, 2, 3],
        port_id: vec![4, 5],
        system_name: b"core01".to_vec(),
        packet: 2,
    });
    observed.stp_frames = 1;
    observed.stp_packet = Some(3);
    observed.stp.push(StpObservation {
        root: BridgeIdentity {
            priority: 32_768,
            system_id_extension: 1,
            mac: "00:11:22:33:44:55".into(),
        },
        version: "Rstp".into(),
        packet: 3,
        frames: 1,
    });

    let assessment = assess(&[observed], &Policy::default(), &clean_quality())?;

    assert!(assessment.findings.is_empty());
    assert_eq!(assessment.exposures.len(), 2);
    assert!(assessment.exposures.iter().any(|exposure| {
        exposure.check_id == "LLDP-001"
            && exposure.severity == Severity::Info
            && exposure.evidence_packets == [2]
    }));
    assert!(assessment.exposures.iter().any(|exposure| {
        exposure.check_id == "STP-001"
            && exposure.severity == Severity::Info
            && exposure.evidence_packets == [3]
    }));

    let segmentation = coverage(&assessment, "SEG-001")?;
    assert_eq!(segmentation.status, CoverageStatus::NotApplicable);
    assert!(segmentation.reason.contains("segmentation path policy"));

    let dot1x = coverage(&assessment, "DOT1X-001")?;
    assert_eq!(dot1x.status, CoverageStatus::NotApplicable);
    assert!(dot1x.reason.contains("EAPOL"));
    Ok(())
}

#[test]
fn coverage_excludes_not_applicable_checks() -> Result<(), Box<dyn Error>> {
    let observed = stp_interface(BridgeIdentity {
        priority: 32_768,
        system_id_extension: 1,
        mac: "00:11:22:33:44:55".into(),
    });

    let assessment = assess(&[observed], &Policy::default(), &clean_quality())?;
    let spanning_tree = category(&assessment, CheckCategory::SpanningTree)?;

    assert_eq!(spanning_tree.tested, 2);
    assert_eq!(spanning_tree.not_tested, 1);
    assert_eq!(spanning_tree.not_applicable, 3);
    assert_eq!(spanning_tree.percent, Some(66));

    let vlan = category(&assessment, CheckCategory::Vlan)?;
    assert_eq!(vlan.tested, 0);
    assert_eq!(vlan.not_tested, 0);
    assert_eq!(vlan.not_applicable, 5);
    assert_eq!(vlan.percent, None);
    Ok(())
}

#[test]
fn dirty_capture_changes_tested_coverage() -> Result<(), Box<dyn Error>> {
    let mut observed = interface();
    observed.protocols.push(l2_audit::ProtocolObservation {
        protocol: Protocol::Arp,
        status: l2_audit::FingerprintStatus::Observed,
        frames: 1,
        packet: 9,
    });
    let dirty = Quality {
        incomplete: true,
        ..clean_quality()
    };
    let assessment = assess(&[observed], &Policy::default(), &dirty)?;
    let tested = coverage(&assessment, "ARP-INVENTORY-001")?;
    assert_eq!(tested.status, CoverageStatus::Tested);
    assert!(tested.reason.contains("capture quality is incomplete"));

    let mut clean_observed = interface();
    clean_observed
        .protocols
        .push(l2_audit::ProtocolObservation {
            protocol: Protocol::Arp,
            status: l2_audit::FingerprintStatus::Observed,
            frames: 1,
            packet: 9,
        });
    let clean_assessment = assess(&[clean_observed], &Policy::default(), &clean_quality())?;
    let clean_tested = coverage(&clean_assessment, "ARP-INVENTORY-001")?;
    assert!(
        !clean_tested
            .reason
            .contains("capture quality is incomplete")
    );

    let clean = assess(&[], &Policy::default(), &clean_quality())?;
    let not_tested = coverage(&clean, "ARP-001")?;
    assert_ne!(not_tested.status, CoverageStatus::Tested);
    assert!(!not_tested.reason.contains("capture quality is incomplete"));
    Ok(())
}

fn stp_interface(root: BridgeIdentity) -> InterfaceObservation {
    let mut observed = interface();
    observed.stp_frames = 1;
    observed.stp_packet = Some(3);
    observed.stp.push(StpObservation {
        root,
        version: "Rstp".into(),
        packet: 3,
        frames: 1,
    });
    observed
}

fn bridge_policy(priority: u16, system_id_extension: u16) -> Policy {
    Policy {
        expected_stp_bridge: Some(BridgeIdentity {
            priority,
            system_id_extension,
            mac: "00:11:22:33:44:55".into(),
        }),
        ..Policy::default()
    }
}

#[test]
fn stp_bridge_compares_priority_extension() -> Result<(), Box<dyn Error>> {
    let observed = BridgeIdentity {
        priority: 32_768,
        system_id_extension: 7,
        mac: "00:11:22:33:44:55".into(),
    };

    let priority_mismatch = assess(
        &[stp_interface(observed.clone())],
        &bridge_policy(36_864, 7),
        &clean_quality(),
    )?;
    let priority_finding = priority_mismatch
        .findings
        .iter()
        .find(|finding| finding.check_id == "STP-002")
        .ok_or("priority mismatch did not produce a finding")?;
    assert!(priority_finding.expected.contains("priority=36864"));
    assert!(priority_finding.expected.contains("system_id_extension=7"));
    assert!(
        priority_finding
            .observed
            .contains("priority=32768 system_id_extension=7 mac=00:11:22:33:44:55")
    );

    let extension_mismatch = assess(
        &[stp_interface(observed.clone())],
        &bridge_policy(32_768, 8),
        &clean_quality(),
    )?;
    assert!(
        extension_mismatch
            .findings
            .iter()
            .any(|finding| finding.check_id == "STP-002")
    );

    let matching = assess(
        &[stp_interface(observed)],
        &bridge_policy(32_768, 7),
        &clean_quality(),
    )?;
    assert!(matching.findings.is_empty());
    Ok(())
}

#[test]
fn legacy_stp_root_mac_only() -> Result<(), Box<dyn Error>> {
    let observed = stp_interface(BridgeIdentity {
        priority: 36_864,
        system_id_extension: 8,
        mac: "00:11:22:33:44:55".into(),
    });
    let assessment = assess(
        &[observed],
        &Policy {
            expected_stp_root: Some("00:11:22:33:44:55".into()),
            ..Policy::default()
        },
        &clean_quality(),
    )?;
    assert!(assessment.findings.is_empty());
    Ok(())
}

#[test]
fn policy_findings_exposure_status() -> Result<(), Box<dyn Error>> {
    let mut observed = interface();
    observed.vlans.push(VlanObservation {
        tags: vec![(0x8100, 20)],
        packet: 7,
    });
    observed.neighbors.push(Neighbor {
        chassis_id: vec![1],
        port_id: vec![2],
        system_name: vec![3],
        packet: 8,
    });

    let assessment = assess(
        &[observed],
        &Policy {
            allowed_vlans: Some(vec![10]),
            ..Policy::default()
        },
        &clean_quality(),
    )?;

    let finding = assessment
        .findings
        .iter()
        .find(|finding| finding.check_id == "VLAN-001");
    let finding = finding.ok_or("missing VLAN policy finding")?;
    assert_eq!(finding.verdict, Verdict::Fail);
    assert_eq!(finding.evidence_packets, [7]);
    assert!(
        assessment
            .findings
            .iter()
            .all(|finding| !matches!(finding.check_id.as_str(), "LLDP-001" | "STP-001"))
    );
    assert!(
        assessment
            .exposures
            .iter()
            .any(|exposure| exposure.check_id == "LLDP-001")
    );
    Ok(())
}

#[test]
fn assessment_order_is_deterministic() -> Result<(), Box<dyn Error>> {
    let first_later = interface_with_neighbor(9, 1, 9, 9);
    let first_earlier = interface_with_neighbor(1, 1, 1, 1);
    let second_earlier = interface_with_neighbor(1, 1, 1, 1);
    let second_later = interface_with_neighbor(9, 1, 9, 9);
    let first = assess(
        &[first_later, first_earlier],
        &Policy::default(),
        &clean_quality(),
    )?;
    let second = assess(
        &[second_earlier, second_later],
        &Policy::default(),
        &clean_quality(),
    )?;

    let first_scope: Vec<_> = first
        .exposures
        .iter()
        .map(|exposure| exposure.source_interfaces.clone())
        .collect();
    let second_scope: Vec<_> = second
        .exposures
        .iter()
        .map(|exposure| exposure.source_interfaces.clone())
        .collect();
    assert_eq!(first_scope, second_scope);
    Ok(())
}

#[test]
fn policy_finding_order_is_deterministic() -> Result<(), Box<dyn Error>> {
    let mut first = interface_with_neighbor(8, 1, 8, 8);
    first.vlans.push(VlanObservation {
        tags: vec![(0x8100, 80)],
        packet: 8,
    });
    let mut second = interface_with_neighbor(2, 1, 2, 2);
    second.vlans.push(VlanObservation {
        tags: vec![(0x8100, 20)],
        packet: 2,
    });
    let policy = Policy {
        allowed_vlans: Some(vec![10]),
        ..Policy::default()
    };
    let first_assessment = assess(&[first, second], &policy, &clean_quality())?;

    let mut second_first = interface_with_neighbor(2, 1, 2, 2);
    second_first.vlans.push(VlanObservation {
        tags: vec![(0x8100, 20)],
        packet: 2,
    });
    let mut second_second = interface_with_neighbor(8, 1, 8, 8);
    second_second.vlans.push(VlanObservation {
        tags: vec![(0x8100, 80)],
        packet: 8,
    });
    let second_assessment = assess(&[second_first, second_second], &policy, &clean_quality())?;

    let first_order: Vec<_> = first_assessment
        .findings
        .iter()
        .map(|finding| {
            (
                finding.source_interfaces.clone(),
                finding.evidence_packets.clone(),
            )
        })
        .collect();
    let second_order: Vec<_> = second_assessment
        .findings
        .iter()
        .map(|finding| {
            (
                finding.source_interfaces.clone(),
                finding.evidence_packets.clone(),
            )
        })
        .collect();
    assert_eq!(first_order, second_order);
    Ok(())
}

#[test]
fn discovery_fingerprints_drive_coverage_plan() -> Result<(), Box<dyn Error>> {
    let input = PlannerInput::new().with_protocol(Protocol::Eapol);
    let assessment = assess_with_input(&[], &Policy::default(), &clean_quality(), &input)?;
    let dot1x = coverage(&assessment, "DOT1X-001")?;
    assert_eq!(dot1x.status, CoverageStatus::NotTested);
    assert!(
        assessment
            .plan
            .recommendations
            .iter()
            .any(|recommendation| recommendation.check_id == "DOT1X-001")
    );
    Ok(())
}

#[test]
fn assessment_invalid_schema_building_result() -> Result<(), Box<dyn Error>> {
    let policy = Policy {
        schema_version: Some(2),
        ..Policy::default()
    };
    let error = assess(&[], &policy, &Quality::default())
        .err()
        .ok_or_else(|| std::io::Error::other("invalid schema must not produce an assessment"))?;
    assert!(matches!(error, AuditError::Policy(_)));

    let error = assess_with_input(&[], &policy, &Quality::default(), &PlannerInput::new())
        .err()
        .ok_or_else(|| {
            std::io::Error::other("invalid schema must not produce an input assessment")
        })?;
    assert!(matches!(error, AuditError::Policy(_)));
    Ok(())
}

#[test]
fn assessment_mixed_fields_without_policy() -> Result<(), Box<dyn Error>> {
    let policy = Policy {
        allowed_vlans: Some(vec![10]),
        schema_version: Some(2),
        segments: Some(BTreeMap::new()),
        ports: Some(Vec::new()),
        ..Policy::default()
    };
    let before = serde_json::to_value(&policy)?;
    let error = assess(&[], &policy, &Quality::default())
        .err()
        .ok_or_else(|| std::io::Error::other("mixed policy fields must be rejected"))?;
    assert_eq!(
        error,
        AuditError::Policy("versioned and legacy policy fields cannot be mixed")
    );
    assert_eq!(serde_json::to_value(&policy)?, before);
    Ok(())
}

fn interface_with_neighbor(
    section: u32,
    index: u32,
    identity: u8,
    packet: u64,
) -> InterfaceObservation {
    let mut observed = interface();
    observed.section = section;
    observed.index = index;
    observed.neighbors.push(Neighbor {
        chassis_id: vec![identity],
        port_id: vec![identity],
        system_name: vec![identity],
        packet,
    });
    observed
}
