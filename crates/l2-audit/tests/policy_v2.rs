use l2_audit::{
    BridgeIdentity, CoverageStatus, Disposition, FingerprintStatus, InterfaceObservation, Neighbor,
    Policy, PortBinding, Protocol, ProtocolObservation, Quality, SegmentExpectations,
    StpObservation, VlanObservation, assess,
};
use std::collections::{BTreeMap, BTreeSet};

fn bridge(priority: u16, extension: u16, mac: &str) -> BridgeIdentity {
    BridgeIdentity {
        priority,
        system_id_extension: extension,
        mac: mac.into(),
    }
}

fn segment(
    vlan: u16,
    expected_bridge: Option<BridgeIdentity>,
    isolation_from: &[&str],
) -> SegmentExpectations {
    SegmentExpectations {
        allowed_vlans: Some(BTreeSet::from([vlan])),
        priority_tagged: Disposition::Forbidden,
        untagged: Disposition::Allowed,
        max_vlan_depth: Some(1),
        expected_stp_bridge: expected_bridge,
        lldp: Disposition::Allowed,
        stp_endpoint: Disposition::Forbidden,
        require_8021x: Some(true),
        protocols: BTreeMap::new(),
        isolation_from: isolation_from
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
        allow_to: BTreeSet::new(),
    }
}

fn policy_v2() -> Policy {
    Policy {
        schema_version: Some(2),
        segments: Some(BTreeMap::from([
            (
                "trusted".into(),
                segment(10, Some(bridge(32_768, 1, "00:11:22:33:44:55")), &["guest"]),
            ),
            ("guest".into(), segment(20, None, &[])),
        ])),
        ports: Some(vec![
            PortBinding {
                section: 0,
                index: 2,
                segment: "guest".into(),
                role: "access".into(),
            },
            PortBinding {
                section: 0,
                index: 1,
                segment: "trusted".into(),
                role: "access".into(),
            },
        ]),
        ..Policy::default()
    }
}

fn interface(index: u32, vlan: u16, root: Option<BridgeIdentity>) -> InterfaceObservation {
    InterfaceObservation {
        section: 0,
        index,
        frames: 1,
        macs: vec![format!("02:00:00:00:00:{index:02x}")],
        vlans: vec![VlanObservation {
            tags: vec![(0x8100, vlan)],
            packet: u64::from(index),
        }],
        untagged_packet: None,
        neighbors: Vec::new(),
        protocols: Vec::new(),
        identities: Vec::new(),
        stp_frames: u64::from(root.is_some()),
        stp_packet: root.as_ref().map(|_| u64::from(index)),
        stp: root.map_or_else(Vec::new, |root| {
            vec![StpObservation {
                root,
                version: "Rstp".into(),
                packet: u64::from(index),
                frames: 1,
            }]
        }),
    }
}

mod control_findings {
    use super::*;

    #[test]
    fn forbidden_control_is_scoped() -> Result<(), Box<dyn std::error::Error>> {
        let mut policy = policy_v2();
        let Some(segments) = policy.segments.as_mut() else {
            return Ok(());
        };
        let Some(guest) = segments.get_mut("guest") else {
            return Ok(());
        };
        guest
            .protocols
            .insert(Protocol::Dtp, Disposition::Forbidden);
        let Some(trusted) = segments.get_mut("trusted") else {
            return Ok(());
        };
        trusted
            .protocols
            .insert(Protocol::Dtp, Disposition::Allowed);

        let mut trusted = interface(1, 10, None);
        trusted.protocols.push(ProtocolObservation {
            protocol: Protocol::Dtp,
            status: FingerprintStatus::Observed,
            frames: 1,
            packet: 31,
        });
        let mut guest = interface(2, 20, None);
        guest.protocols.push(ProtocolObservation {
            protocol: Protocol::Dtp,
            status: FingerprintStatus::Observed,
            frames: 1,
            packet: 32,
        });

        let assessment = assess(&[trusted, guest], &policy, &Quality::default())?;

        assert!(assessment.findings.iter().any(|finding| {
            finding.check_id == "CTRL-POLICY-001"
                && finding.source_interfaces == ["0:2"]
                && finding.evidence_packets == [32]
                && finding.observed.contains("DTP")
        }));
        assert!(assessment.findings.iter().all(|finding| {
            !(finding.check_id == "CTRL-POLICY-001" && finding.source_interfaces == ["0:1"])
        }));
        Ok(())
    }
}

mod policy_validation {
    use super::*;

    #[test]
    fn dedicated_controls_reject_redundant_rules() {
        for (protocol, disposition) in [
            (Protocol::Dtp, Disposition::Unspecified),
            (Protocol::Lldp, Disposition::Forbidden),
            (Protocol::Stp, Disposition::Forbidden),
        ] {
            let mut policy = policy_v2();
            if let Some(segment) = policy
                .segments
                .as_mut()
                .and_then(|segments| segments.get_mut("guest"))
            {
                segment.protocols.insert(protocol, disposition);
            }
            assert!(policy.validate().is_err());
        }
    }
}

mod resolution {
    use super::*;

    #[test]
    fn selects_segment_expectations_source_role() {
        let policy = policy_v2();
        assert!(policy.validate().is_ok());

        let trusted = policy.expectations_for(0, 1);
        assert_eq!(
            trusted.as_ref().map(|value| value.segment.as_str()),
            Some("trusted")
        );
        assert_eq!(
            trusted.as_ref().map(|value| value.role.as_str()),
            Some("access")
        );
        assert_eq!(
            trusted.as_ref().map(|value| &value.allowed_vlans),
            Some(&BTreeSet::from([10]))
        );
        assert_eq!(
            trusted
                .as_ref()
                .and_then(|value| value.expected_stp_bridge.as_ref())
                .map(|value| value.system_id_extension),
            Some(1)
        );

        let guest = policy.expectations_for(0, 2);
        assert_eq!(
            guest.as_ref().map(|value| value.segment.as_str()),
            Some("guest")
        );
        assert_eq!(
            guest.as_ref().map(|value| value.role.as_str()),
            Some("access")
        );
        assert_eq!(
            guest.as_ref().map(|value| value.allowed_vlans.clone()),
            Some(BTreeSet::from([20]))
        );
        assert!(policy.expectations_for(0, 3).is_none());
    }

    #[test]
    fn omitted_empty_vlans_distinct_meanings() -> Result<(), Box<dyn std::error::Error>> {
        let unspecified: Policy = serde_json::from_str(
            r#"{
            "schema_version": 2,
            "segments": { "guest": {} },
            "ports": [
                { "section": 0, "index": 1, "segment": "guest", "role": "access" }
            ]
        }"#,
        )?;
        unspecified.validate()?;
        assert!(
            !unspecified
                .expectations_for(0, 1)
                .ok_or("missing unspecified expectations")?
                .has_allowed_vlan_policy()
        );

        let empty: Policy = serde_json::from_str(
            r#"{
            "schema_version": 2,
            "segments": { "guest": { "allowed_vlans": [] } },
            "ports": [
                { "section": 0, "index": 1, "segment": "guest", "role": "access" }
            ]
        }"#,
        )?;
        empty.validate()?;
        assert!(
            empty
                .expectations_for(0, 1)
                .ok_or("missing explicit expectations")?
                .has_allowed_vlan_policy()
        );

        let unspecified_result =
            assess(&[interface(1, 20, None)], &unspecified, &Quality::default())?;
        assert!(
            unspecified_result
                .findings
                .iter()
                .all(|finding| finding.check_id != "VLAN-001")
        );
        let empty_result = assess(&[interface(1, 20, None)], &empty, &Quality::default())?;
        assert!(
            empty_result
                .findings
                .iter()
                .any(|finding| finding.check_id == "VLAN-001")
        );
        Ok(())
    }

    #[test]
    fn bound_segment_drives_interface_checks() -> Result<(), Box<dyn std::error::Error>> {
        let policy = policy_v2();
        let interfaces = [
            interface(1, 10, Some(bridge(32_768, 1, "00:11:22:33:44:55"))),
            interface(2, 10, Some(bridge(32_768, 2, "00:11:22:33:44:55"))),
        ];
        let assessment = assess(
            &interfaces,
            &policy,
            &Quality {
                frames: 2,
                ..Quality::default()
            },
        )?;

        assert!(assessment.findings.iter().any(|finding| {
            finding.check_id == "VLAN-001" && finding.source_interfaces == ["0:2"]
        }));
        assert!(assessment.findings.iter().any(|finding| {
            finding.check_id == "STP-003" && finding.source_interfaces == ["0:2"]
        }));
        assert!(
            assessment
                .findings
                .iter()
                .all(|finding| finding.check_id != "SEG-001")
        );
        Ok(())
    }

    #[test]
    fn flat_policy_resolves_legacy_expectations() {
        let policy = Policy {
            allowed_vlans: Some(vec![10]),
            allow_priority_tagged: Some(false),
            allow_untagged: Some(true),
            max_vlan_depth: Some(1),
            expected_stp_root: Some("00:11:22:33:44:55".into()),
            ..Policy::default()
        };
        assert!(policy.validate().is_ok());
        let resolved = policy.expectations_for(0, 0);
        assert_eq!(
            resolved.as_ref().map(|value| &value.allowed_vlans),
            Some(&BTreeSet::from([10]))
        );
        assert_eq!(
            resolved.as_ref().map(|value| value.priority_tagged),
            Some(Disposition::Forbidden)
        );
        assert_eq!(
            resolved
                .as_ref()
                .and_then(|value| value.expected_stp_root.as_deref()),
            Some("00:11:22:33:44:55")
        );
        assert!(policy.expectations_for(12, 34).is_none());
    }

    #[test]
    fn flat_policy_nondefault_pcapng_interface() -> Result<(), Box<dyn std::error::Error>> {
        let observed = interface(34, 20, None);
        let assessment = assess(
            &[observed],
            &Policy {
                allowed_vlans: Some(vec![10]),
                ..Policy::default()
            },
            &Quality {
                frames: 1,
                ..Quality::default()
            },
        )?;

        assert!(assessment.findings.is_empty());
        assert_eq!(
            assessment
                .coverage
                .iter()
                .find(|entry| entry.check_id == "VLAN-001")
                .map(|entry| entry.status),
            Some(CoverageStatus::NotApplicable)
        );
        Ok(())
    }
}

mod serialization {
    use super::*;

    #[test]
    fn serialization_sorts_ports_deterministically() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = serde_json::to_string(&policy_v2())?;
        let first_port = encoded.find("\"index\":1").ok_or("first port")?;
        let second_port = encoded.find("\"index\":2").ok_or("second port")?;
        assert!(first_port < second_port);
        assert!(encoded.contains("\"schema_version\":2"));
        assert!(encoded.contains("\"priority_tagged\":\"forbidden\""));
        assert!(encoded.contains("\"isolation_from\":[\"guest\"]"));
        Ok(())
    }
}

mod schema_validation {
    use super::*;

    #[test]
    fn mixed_legacy_fields_invalid_versions() {
        for policy in [
            Policy {
                schema_version: Some(2),
                segments: Some(BTreeMap::new()),
                ports: Some(Vec::new()),
                allowed_vlans: Some(vec![10]),
                ..Policy::default()
            },
            Policy {
                schema_version: None,
                segments: Some(BTreeMap::new()),
                ports: Some(Vec::new()),
                ..Policy::default()
            },
            Policy {
                schema_version: Some(1),
                segments: Some(BTreeMap::new()),
                ports: Some(Vec::new()),
                ..Policy::default()
            },
            Policy {
                schema_version: Some(2),
                segments: None,
                ports: None,
                ..Policy::default()
            },
        ] {
            assert!(policy.validate().is_err());
        }
    }

    #[test]
    fn rejects_unknown_fields_and_sources() {
        assert!(
            serde_json::from_str::<Policy>(
                r#"{"schema_version":2,"segments":{},"ports":[],"unexpected":true}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<Policy>(
                r#"{"schema_version":2,"segments":{"guest":{},"guest":{}},"ports":[]}"#
            )
            .is_err()
        );

        let mut policy = policy_v2();
        policy.ports = Some(vec![
            PortBinding {
                section: 0,
                index: 1,
                segment: "trusted".into(),
                role: "access".into(),
            },
            PortBinding {
                section: 0,
                index: 1,
                segment: "guest".into(),
                role: "access".into(),
            },
        ]);
        assert!(policy.validate().is_err());

        let mut broken = policy_v2();
        if let Some(trusted) = broken
            .segments
            .as_mut()
            .and_then(|segments| segments.get_mut("trusted"))
        {
            trusted.isolation_from.insert("missing".into());
        }
        assert!(broken.validate().is_err());
        broken.ports = Some(vec![PortBinding {
            section: 0,
            index: 1,
            segment: "missing".into(),
            role: "access".into(),
        }]);
        assert!(broken.validate().is_err());
    }

    #[test]
    fn enforces_vlan_name_collection_boundaries() {
        let mut valid = policy_v2();
        if let Some(guest) = valid
            .segments
            .as_mut()
            .and_then(|segments| segments.get_mut("guest"))
        {
            guest.allowed_vlans = Some(BTreeSet::from([1, 4094]));
            guest.max_vlan_depth = Some(4);
            guest.isolation_from = BTreeSet::from(["trusted".into()]);
        }
        assert!(valid.validate().is_ok());

        let mut invalid_vlan = valid.clone();
        if let Some(guest) = invalid_vlan
            .segments
            .as_mut()
            .and_then(|segments| segments.get_mut("guest"))
        {
            guest.allowed_vlans = Some(BTreeSet::from([0]));
        }
        assert!(invalid_vlan.validate().is_err());

        let mut invalid_depth = valid.clone();
        if let Some(guest) = invalid_depth
            .segments
            .as_mut()
            .and_then(|segments| segments.get_mut("guest"))
        {
            guest.max_vlan_depth = Some(5);
        }
        assert!(invalid_depth.validate().is_err());

        let mut invalid_name = valid.clone();
        if let Some(guest) = invalid_name
            .segments
            .as_mut()
            .and_then(|segments| segments.get_mut("guest"))
        {
            guest.isolation_from = BTreeSet::from([String::new()]);
        }
        assert!(invalid_name.validate().is_err());
    }
}

mod lldp_findings {
    use super::*;

    #[test]
    fn forbidden_lldp_scoped_allowed_inventory() -> Result<(), Box<dyn std::error::Error>> {
        let mut policy = policy_v2();
        let Some(segments) = policy.segments.as_mut() else {
            return Ok(());
        };
        let Some(guest) = segments.get_mut("guest") else {
            return Ok(());
        };
        guest.lldp = Disposition::Forbidden;

        let mut trusted = interface(1, 10, None);
        trusted.neighbors.push(Neighbor {
            chassis_id: vec![1],
            port_id: vec![2],
            system_name: b"trusted-switch".to_vec(),
            packet: 11,
        });
        let mut guest = interface(2, 20, None);
        guest.neighbors.push(Neighbor {
            chassis_id: vec![3],
            port_id: vec![4],
            system_name: b"guest-switch".to_vec(),
            packet: 12,
        });

        let assessment = assess(&[trusted, guest], &policy, &Quality::default())?;

        assert!(assessment.findings.iter().any(|finding| {
            finding.check_id == "LLDP-002"
                && finding.source_interfaces == ["0:2"]
                && finding.evidence_packets == [12]
        }));
        assert!(assessment.findings.iter().all(
            |finding| !(finding.check_id == "LLDP-002" && finding.source_interfaces == ["0:1"])
        ));
        Ok(())
    }
}
