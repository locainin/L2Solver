//! Protocol visibility becomes a finding only when a scoped policy forbids it

use super::{Finding, InterfaceObservation, Severity, Verdict, scoped};
use crate::{Disposition, FingerprintStatus, Protocol, ResolvedExpectations};

pub(super) fn evaluate_protocol_policy(
    interface: &InterfaceObservation,
    policy: &ResolvedExpectations,
    findings: &mut Vec<Finding>,
) {
    for observation in &interface.protocols {
        if observation.status != FingerprintStatus::Observed
            || policy.protocols.get(&observation.protocol) != Some(&Disposition::Forbidden)
        {
            continue;
        }
        findings.push(scoped(
            Some(interface),
            Some(observation.packet),
            Finding {
                check_id: "CTRL-POLICY-001".into(),
                verdict: Verdict::Fail,
                severity: protocol_severity(observation.protocol),
                title: "Control protocol violates the interface policy".into(),
                expected: format!(
                    "{} traffic is forbidden for segment {} role {}",
                    observation.protocol, policy.segment, policy.role
                ),
                observed: format!(
                    "{} valid {} frame(s) observed",
                    observation.frames, observation.protocol
                ),
                evidence_packets: Vec::new(),
                source_interfaces: Vec::new(),
                remediation: format!(
                    "Review {} exposure and switch-port role configuration",
                    observation.protocol
                ),
                limitations: vec![
                    "Passive visibility does not establish whether active negotiation succeeds"
                        .into(),
                ],
            },
        ));
    }
}

const fn protocol_severity(protocol: Protocol) -> Severity {
    match protocol {
        Protocol::Dtp | Protocol::Vtp | Protocol::PvstPlus => Severity::Medium,
        Protocol::Cdp
        | Protocol::Pagp
        | Protocol::Lacp
        | Protocol::Eapol
        | Protocol::Mka
        | Protocol::Macsec
        | Protocol::Arp
        | Protocol::Dhcp
        | Protocol::Hsrp
        | Protocol::Vrrp
        | Protocol::Ipv6Ra
        | Protocol::Ipv6Nd
        | Protocol::Mld
        | Protocol::Dhcpv6
        | Protocol::Igmp
        | Protocol::Mdns
        | Protocol::Ssdp
        | Protocol::Netbios
        | Protocol::CiscoSnap => Severity::Low,
        Protocol::Lldp | Protocol::Stp => Severity::Info,
    }
}
