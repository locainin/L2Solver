//! Observation-only policy checks for the passive survey

use crate::{
    AuditError, SourceLabelMap,
    model::{Finding, InterfaceObservation, Severity, Verdict, Vid},
    policy::{Policy, ResolvedExpectations},
};
use l2_capture::InterfaceId;
use std::collections::BTreeMap;

#[path = "checks/lldp.rs"]
mod lldp;
#[path = "checks/protocol.rs"]
mod protocol;
#[path = "checks/stp.rs"]
mod stp;
#[path = "checks/vlan.rs"]
mod vlan;

/// Evaluate only assertions supported by an explicit policy
///
/// Inventory surfaces such as LLDP and STP visibility are intentionally kept
/// out of this vector. The assessment layer reports those observations as
/// informational exposures and reports untestable checks as coverage entries
/// instead of manufacturing a security finding
pub fn evaluate_policy(interfaces: &[InterfaceObservation], policy: &Policy) -> Vec<Finding> {
    evaluate_policy_inner(interfaces, |interface| {
        policy.expectations_for(interface.section, interface.index)
    })
}

/// Evaluate policy assertions after resolving capture interfaces by stable labels
///
/// # Errors
/// Returns a source-mapping error before evaluating any policy assertion when
/// a stable policy cannot be resolved for one of the observed interfaces
pub fn evaluate_policy_with_source_labels(
    interfaces: &[InterfaceObservation],
    policy: &Policy,
    labels: &SourceLabelMap,
) -> Result<Vec<Finding>, AuditError> {
    let mut resolved = BTreeMap::new();
    for interface in interfaces {
        let source = InterfaceId {
            section: interface.section,
            index: interface.index,
        };
        if let Some(expectations) = policy.expectations_for_source(source, labels)? {
            resolved.insert(source, expectations);
        }
    }
    Ok(evaluate_policy_inner(interfaces, |interface| {
        resolved
            .get(&InterfaceId {
                section: interface.section,
                index: interface.index,
            })
            .cloned()
    }))
}

fn evaluate_policy_inner<F>(interfaces: &[InterfaceObservation], mut resolve: F) -> Vec<Finding>
where
    F: FnMut(&InterfaceObservation) -> Option<ResolvedExpectations>,
{
    let mut findings = Vec::new();
    // Direct callers may provide interfaces in any order; keep finding order stable
    let mut ordered: Vec<_> = interfaces.iter().collect();
    ordered.sort_by_key(|interface| (interface.section, interface.index));
    for interface in ordered {
        let Some(expectations) = resolve(interface) else {
            continue;
        };
        lldp::evaluate_lldp_policy(interface, &expectations, &mut findings);
        protocol::evaluate_protocol_policy(interface, &expectations, &mut findings);
        vlan::evaluate_vlan_policy(interface, &expectations, &mut findings);
        stp::evaluate_stp_policy(interface, &expectations, &mut findings);
    }
    findings
}

fn scoped(
    interface: Option<&InterfaceObservation>,
    packet: Option<u64>,
    mut finding: Finding,
) -> Finding {
    finding.evidence_packets = packet.into_iter().collect();
    finding.source_interfaces = interface.map_or_else(Vec::new, |interface| {
        vec![format!("{}:{}", interface.section, interface.index)]
    });
    finding
}
