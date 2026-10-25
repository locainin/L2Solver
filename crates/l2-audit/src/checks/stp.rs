//! Passive stp findings use only explicit observations and policy

use super::{Finding, InterfaceObservation, Severity, Verdict, scoped};
use crate::{BridgeIdentity, Disposition, ResolvedExpectations};

/// Evaluate only an observed root mismatch covered by an explicit policy
pub(super) fn evaluate_stp_policy(
    interface: &InterfaceObservation,
    policy: &ResolvedExpectations,
    findings: &mut Vec<Finding>,
) {
    if policy.stp_endpoint == Disposition::Forbidden
        && let Some(packet) = interface.stp_packet
    {
        findings.push(scoped(
            Some(interface),
            Some(packet),
            Finding {
                check_id: "STP-003".into(),
                verdict: Verdict::Fail,
                severity: Severity::Medium,
                title: "STP advertisements violate the endpoint-port policy".into(),
                expected: "No STP advertisements are visible in the endpoint capture scope".into(),
                observed: format!("{} STP frame(s) observed", interface.stp_frames),
                evidence_packets: Vec::new(),
                source_interfaces: Vec::new(),
                remediation: "Review endpoint STP filtering and port-role configuration".into(),
                limitations: vec![
                    "Passive receipt does not establish whether the endpoint transmitted a BPDU"
                        .into(),
                ],
            },
        ));
    }
    if let Some(expected) = policy.expected_stp_bridge.as_ref() {
        evaluate_expected_bridge(interface, expected, findings);
    } else if let Some(expected) = policy.expected_stp_root.as_deref() {
        evaluate_expected_root(interface, expected, findings);
    }
}

fn evaluate_expected_bridge(
    interface: &InterfaceObservation,
    expected: &BridgeIdentity,
    findings: &mut Vec<Finding>,
) {
    for observed in &interface.stp {
        let priority_matches = observed.root.priority == expected.priority;
        let extension_matches = observed.root.system_id_extension == expected.system_id_extension;
        let mac_matches = observed.root.mac.eq_ignore_ascii_case(&expected.mac);
        if priority_matches && extension_matches && mac_matches {
            continue;
        }
        let expected_description = describe_bridge(expected);
        let observed_description = describe_bridge(&observed.root);
        findings.push(scoped(
            Some(interface),
            Some(observed.packet),
            Finding {
                check_id: "STP-002".into(),
                verdict: Verdict::Fail,
                severity: Severity::Medium,
                title: "Unexpected untagged STP root was advertised".into(),
                expected: format!("expected STP bridge {expected_description}"),
                observed: format!("advertised STP bridge {observed_description}"),
                evidence_packets: Vec::new(),
                source_interfaces: Vec::new(),
                remediation: "Review bridge priority and root-protection policy".into(),
                limitations: vec![
                    "The observation is an unauthenticated control-plane advertisement".into(),
                ],
            },
        ));
    }
}

fn evaluate_expected_root(
    interface: &InterfaceObservation,
    expected: &str,
    findings: &mut Vec<Finding>,
) {
    for observed in &interface.stp {
        if observed.root.mac.eq_ignore_ascii_case(expected) {
            continue;
        }
        findings.push(scoped(
            Some(interface),
            Some(observed.packet),
            Finding {
                check_id: "STP-002".into(),
                verdict: Verdict::Fail,
                severity: Severity::Medium,
                title: "Unexpected untagged STP root was advertised".into(),
                expected: "The advertised root differs from the expected policy root".into(),
                observed: format!(
                    "advertised root {}; expected {}",
                    observed.root.mac, expected
                ),
                evidence_packets: Vec::new(),
                source_interfaces: Vec::new(),
                remediation: "Review bridge priority and root-protection policy".into(),
                limitations: vec![
                    "The observation is an unauthenticated control-plane advertisement".into(),
                ],
            },
        ));
    }
}

fn describe_bridge(bridge: &BridgeIdentity) -> String {
    format!(
        "priority={} system_id_extension={} mac={}",
        bridge.priority, bridge.system_id_extension, bridge.mac
    )
}
