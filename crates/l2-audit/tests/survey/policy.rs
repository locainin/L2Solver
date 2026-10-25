use l2_audit::{BridgeIdentity, Policy};

#[test]
fn unknown_duplicate_reserved_bad_values() {
    assert!(serde_json::from_str::<Policy>(r#"{"allowd_vlans":[10]}"#).is_err());
    for vlans in [vec![4095], vec![10, 10], vec![65535]] {
        assert!(
            Policy {
                allowed_vlans: Some(vlans),
                ..Policy::default()
            }
            .validate()
            .is_err()
        );
    }
    assert!(
        Policy {
            expected_stp_root: Some("not-a-mac".into()),
            ..Policy::default()
        }
        .validate()
        .is_err()
    );
}

#[test]
fn validates_and_serializes_stp_bridge() -> Result<(), Box<dyn std::error::Error>> {
    let valid = Policy {
        expected_stp_bridge: Some(BridgeIdentity {
            priority: 61_440,
            system_id_extension: 4_095,
            mac: "AA:bb:00:11:22:33".into(),
        }),
        ..Policy::default()
    };
    assert!(valid.validate().is_ok());
    let encoded = serde_json::to_value(&valid)?;
    assert_eq!(
        encoded.pointer("/expected_stp_bridge"),
        Some(&serde_json::json!({
            "priority": 61440,
            "system_id_extension": 4095,
            "mac": "AA:bb:00:11:22:33"
        }))
    );

    for priority in [1, 4_095, 61_441, 65_535] {
        assert!(
            Policy {
                expected_stp_bridge: Some(BridgeIdentity {
                    priority,
                    system_id_extension: 0,
                    mac: "00:11:22:33:44:55".into(),
                }),
                ..Policy::default()
            }
            .validate()
            .is_err(),
            "accepted invalid bridge priority {priority}"
        );
    }
    assert!(
        Policy {
            expected_stp_bridge: Some(BridgeIdentity {
                priority: 32_768,
                system_id_extension: 4_096,
                mac: "00:11:22:33:44:55".into(),
            }),
            ..Policy::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        Policy {
            expected_stp_bridge: Some(BridgeIdentity {
                priority: 32_768,
                system_id_extension: 0,
                mac: "00:11:22:33:44:5".into(),
            }),
            ..Policy::default()
        }
        .validate()
        .is_err()
    );
    Ok(())
}

#[test]
fn rejects_combined_stp_expectations() {
    let policy = Policy {
        expected_stp_root: Some("00:11:22:33:44:55".into()),
        expected_stp_bridge: Some(BridgeIdentity {
            priority: 32_768,
            system_id_extension: 0,
            mac: "00:11:22:33:44:55".into(),
        }),
        ..Policy::default()
    };
    assert!(policy.validate().is_err());
}

#[test]
fn accepts_limits_rejects_above_bounds() {
    assert!(
        Policy {
            max_vlan_depth: Some(4),
            ..Policy::default()
        }
        .validate()
        .is_ok()
    );
    assert!(
        Policy {
            max_vlan_depth: Some(5),
            ..Policy::default()
        }
        .validate()
        .is_err()
    );

    // Ordinary membership VLANs exclude priority-tag VID 0 and reserved VID 4095
    let all_vlan_ids: Vec<u16> = (1_u16..=4094).collect();
    assert!(
        Policy {
            allowed_vlans: Some(all_vlan_ids),
            ..Policy::default()
        }
        .validate()
        .is_ok()
    );
}

#[test]
fn rejects_malformed_root_addresses() {
    let valid = Policy {
        expected_stp_root: Some("AA:bb:00:11:22:33".into()),
        ..Policy::default()
    };
    assert!(valid.validate().is_ok());

    for root in [
        "00:11:22:33:44:5",     // one-octet length is too short
        "00:11:22:33:44:55:66", // seven octets
        "00:11:22:33:44:gg",    // non-hexadecimal octet
        "00:11:22:33:4:55",     // one-octet component
    ] {
        assert!(
            Policy {
                expected_stp_root: Some(root.into()),
                ..Policy::default()
            }
            .validate()
            .is_err(),
            "accepted malformed root {root}"
        );
    }
}
