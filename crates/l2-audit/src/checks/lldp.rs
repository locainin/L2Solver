//! LLDP findings require an explicit per-interface disclosure policy

use super::{Finding, InterfaceObservation, Severity, Verdict, scoped};
use crate::{Disposition, ResolvedExpectations};

pub(super) fn evaluate_lldp_policy(
    interface: &InterfaceObservation,
    policy: &ResolvedExpectations,
    findings: &mut Vec<Finding>,
) {
    if policy.lldp != Disposition::Forbidden {
        return;
    }
    for neighbor in &interface.neighbors {
        findings.push(scoped(
            Some(interface),
            Some(neighbor.packet),
            Finding {
                check_id: "LLDP-002".into(),
                verdict: Verdict::Fail,
                severity: Severity::Low,
                title: "LLDP metadata violates the interface disclosure policy".into(),
                expected: "No LLDP neighbor metadata is visible in this capture scope".into(),
                observed: format!(
                    "LLDP advertised chassis {:?}, port {:?}, and system name {:?}",
                    neighbor.chassis_id, neighbor.port_id, neighbor.system_name
                ),
                evidence_packets: Vec::new(),
                source_interfaces: Vec::new(),
                remediation: "Review LLDP advertisement policy on the selected switch port".into(),
                limitations: vec![
                    "LLDP identity fields are unauthenticated control-plane claims".into(),
                ],
            },
        ));
    }
}
