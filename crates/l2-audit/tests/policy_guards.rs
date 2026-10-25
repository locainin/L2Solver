use l2_audit::{Policy, PortBinding, SegmentExpectations};
use std::collections::{BTreeMap, BTreeSet};

fn segment() -> SegmentExpectations {
    SegmentExpectations::default()
}

fn versioned_policy(segment: SegmentExpectations) -> Policy {
    Policy {
        schema_version: Some(2),
        segments: Some(BTreeMap::from([(String::from("segment"), segment)])),
        ports: Some(vec![PortBinding {
            section: 0,
            index: 0,
            segment: String::from("segment"),
            role: String::from("access"),
        }]),
        ..Policy::default()
    }
}

#[test]
fn policy_limits_accept_bounds() {
    let mut segments = BTreeMap::new();
    for index in 0..4_096 {
        segments.insert(format!("s{index:04}"), segment());
    }
    let valid_segments = Policy {
        schema_version: Some(2),
        segments: Some(segments.clone()),
        ports: Some(vec![PortBinding {
            section: 0,
            index: 0,
            segment: String::from("s0000"),
            role: String::from("access"),
        }]),
        ..Policy::default()
    };
    assert!(valid_segments.validate().is_ok());

    segments.insert(String::from("s4096"), segment());
    let too_many_segments = Policy {
        segments: Some(segments),
        ..valid_segments
    };
    assert!(too_many_segments.validate().is_err());

    let ports: Vec<_> = (0..4_096)
        .map(|index| PortBinding {
            section: 0,
            index,
            segment: String::from("segment"),
            role: String::from("access"),
        })
        .collect();
    let valid_ports = versioned_policy(segment());
    let valid_ports = Policy {
        ports: Some(ports.clone()),
        ..valid_ports
    };
    assert!(valid_ports.validate().is_ok());

    let mut too_many_ports = ports;
    too_many_ports.push(PortBinding {
        section: 1,
        index: 0,
        segment: String::from("segment"),
        role: String::from("access"),
    });
    let too_many_ports = Policy {
        ports: Some(too_many_ports),
        ..versioned_policy(segment())
    };
    assert!(too_many_ports.validate().is_err());
}

#[test]
fn policy_rejects_invalid_labels() -> Result<(), Box<dyn std::error::Error>> {
    for name in [String::new(), String::from("bad/name"), "a".repeat(65)] {
        let mut policy = versioned_policy(segment());
        let segments = policy
            .segments
            .as_mut()
            .ok_or_else(|| std::io::Error::other("fixture segments missing"))?;
        let value = segments
            .remove("segment")
            .ok_or_else(|| std::io::Error::other("fixture segment missing"))?;
        segments.insert(name, value);
        assert!(policy.validate().is_err());
    }

    for role in [String::new(), String::from("bad/role"), "r".repeat(65)] {
        let mut policy = versioned_policy(segment());
        let ports = policy
            .ports
            .as_mut()
            .ok_or_else(|| std::io::Error::other("fixture ports missing"))?;
        let port = ports
            .first_mut()
            .ok_or_else(|| std::io::Error::other("fixture port missing"))?;
        port.role = role;
        assert!(policy.validate().is_err());
    }

    let valid = versioned_policy(segment());
    assert!(valid.validate().is_ok());

    let boundary_name = "a".repeat(64);
    let mut boundary = versioned_policy(segment());
    let segments = boundary
        .segments
        .as_mut()
        .ok_or_else(|| std::io::Error::other("fixture segments missing"))?;
    let value = segments
        .remove("segment")
        .ok_or_else(|| std::io::Error::other("fixture segment missing"))?;
    segments.insert(boundary_name.clone(), value);
    let ports = boundary
        .ports
        .as_mut()
        .ok_or_else(|| std::io::Error::other("fixture ports missing"))?;
    let port = ports
        .first_mut()
        .ok_or_else(|| std::io::Error::other("fixture port missing"))?;
    port.segment = boundary_name;
    port.role = "r".repeat(64);
    assert!(boundary.validate().is_ok());
    Ok(())
}

#[test]
fn policy_reports_segment_shape_errors() {
    let optional_error =
        serde_json::from_str::<Policy>(r#"{"schema_version":2,"segments":[],"ports":[]}"#)
            .err()
            .map_or_else(
                || String::from("unexpected successful parse"),
                |error| error.to_string(),
            );
    assert!(
        optional_error.contains("a segment expectation object with unique names"),
        "{optional_error}"
    );

    let unique_error =
        serde_json::from_str::<Policy>(r#"{"schema_version":2,"segments":1,"ports":[]}"#)
            .err()
            .map_or_else(
                || String::from("unexpected successful parse"),
                |error| error.to_string(),
            );
    assert!(unique_error.contains("segment expectation"));
}

#[test]
fn field_presence_selects_versioned_validation() {
    for policy in [
        Policy {
            schema_version: Some(2),
            ..Policy::default()
        },
        Policy {
            segments: Some(BTreeMap::new()),
            ..Policy::default()
        },
        Policy {
            ports: Some(Vec::new()),
            ..Policy::default()
        },
    ] {
        assert!(policy.validate().is_err());
    }

    let empty = SegmentExpectations {
        allowed_vlans: Some(BTreeSet::new()),
        ..SegmentExpectations::default()
    };
    assert!(versioned_policy(empty).validate().is_ok());
}
