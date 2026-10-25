//! Passive vlan findings use only explicit observations and policy

use super::{Finding, InterfaceObservation, Severity, Verdict, Vid, scoped};
use crate::{Disposition, ResolvedExpectations};

/// Evaluate VLAN observations only when an explicit policy makes them assertions
pub(super) fn evaluate_vlan_policy(
    interface: &InterfaceObservation,
    policy: &ResolvedExpectations,
    findings: &mut Vec<Finding>,
) {
    for vlan in &interface.vlans {
        evaluate_depth(interface, vlan, policy, findings);
        evaluate_allowed_vlans(interface, vlan, policy, findings);
        evaluate_priority_tag(interface, vlan, policy, findings);
    }

    if policy.untagged == Disposition::Forbidden
        && let Some(packet) = interface.untagged_packet
    {
        findings.push(scoped(
            Some(interface),
            Some(packet),
            Finding {
                check_id: "VLAN-002".into(),
                verdict: Verdict::Fail,
                severity: Severity::Medium,
                title: "Untagged frame observed where policy disallows it".into(),
                expected: "No untagged frames are allowed by the explicit policy".into(),
                observed: "An untagged Ethernet frame was captured".into(),
                evidence_packets: Vec::new(),
                source_interfaces: Vec::new(),
                remediation:
                    "Review the access/native VLAN policy and require the intended tagging".into(),
                limitations: vec![
                    "The packet proves an observed untagged frame, not its forwarding scope".into(),
                ],
            },
        ));
    }
}

fn evaluate_allowed_vlans(
    interface: &InterfaceObservation,
    vlan: &crate::model::VlanObservation,
    policy: &ResolvedExpectations,
    findings: &mut Vec<Finding>,
) {
    let disallowed = vlan
        .vids()
        .filter_map(|vid| match vid {
            Vid::Vlan(value) => Some(value.get()),
            Vid::PriorityTagged | Vid::Reserved => None,
        })
        .any(|id| !policy.allowed_vlans.contains(&id));
    if !policy.has_allowed_vlan_policy() || !disallowed {
        return;
    }
    findings.push(scoped(
        Some(interface),
        Some(vlan.packet),
        Finding {
            check_id: "VLAN-001".into(),
            verdict: Verdict::Fail,
            severity: Severity::Medium,
            title: "Disallowed tagged VLAN observed".into(),
            expected: "The observed VLAN is outside the explicit allowed-VLAN policy".into(),
            observed: format!("tagged VLAN stack {:?} observed (TPID, TCI)", vlan.tags),
            evidence_packets: Vec::new(),
            source_interfaces: Vec::new(),
            remediation: "Review the switch VLAN and trunk policy before allowing this VLAN".into(),
            limitations: vec!["The packet proves capture of a tag, not forwarding behavior".into()],
        },
    ));
}

fn evaluate_priority_tag(
    interface: &InterfaceObservation,
    vlan: &crate::model::VlanObservation,
    policy: &ResolvedExpectations,
    findings: &mut Vec<Finding>,
) {
    let forbidden = policy.priority_tagged == Disposition::Forbidden;
    if !forbidden || !vlan.vids().any(|vid| vid == Vid::PriorityTagged) {
        return;
    }
    findings.push(scoped(
        Some(interface),
        Some(vlan.packet),
        Finding {
            check_id: "VLAN-004".into(),
            verdict: Verdict::Fail,
            severity: Severity::Medium,
            title: "Priority-tagged frame violates the explicit policy".into(),
            expected: "IEEE 802.1Q priority-tagged frames are disallowed".into(),
            observed: format!("priority tag observed in stack {:?} (TPID, TCI)", vlan.tags),
            evidence_packets: Vec::new(),
            source_interfaces: Vec::new(),
            remediation: "Review endpoint priority-tag handling and port policy".into(),
            limitations: vec!["VID 0 carries priority without ordinary VLAN membership".into()],
        },
    ));
}

fn evaluate_depth(
    interface: &InterfaceObservation,
    stack: &crate::model::VlanObservation,
    policy: &ResolvedExpectations,
    findings: &mut Vec<Finding>,
) {
    if let Some(maximum) = policy.max_vlan_depth
        && stack.tags.len() > usize::from(maximum)
    {
        findings.push(scoped(
            Some(interface),
            Some(stack.packet),
            Finding {
                check_id: "VLAN-003".into(),
                verdict: Verdict::Fail,
                severity: Severity::Medium,
                title: "VLAN tag stack exceeds the explicit depth policy".into(),
                expected: format!("At most {maximum} VLAN tags per frame"),
                observed: format!(
                    "{} tags observed: {:?} (TPID, TCI)",
                    stack.tags.len(),
                    stack.tags
                ),
                evidence_packets: Vec::new(),
                source_interfaces: Vec::new(),
                remediation: "Review access-port and stacked-VLAN configuration".into(),
                limitations: vec![
                    "Captured tag headers do not prove a boundary can be crossed".into(),
                ],
            },
        ));
    }
}
