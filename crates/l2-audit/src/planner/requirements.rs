//! Requirement labels and scope/resource evaluation

use super::coverage::PolicyCoverage;
use super::input::PlannerInput;
use super::types::{AssessmentProfile, Capability, PolicyRequirement, Requirement};
use crate::{PortRole, Protocol, assessment::CoverageStatus};
use std::fmt;

/// Decide whether a prerequisite has enough observed scope to apply a check
pub(super) fn scope_available(
    requirement: Requirement,
    input: &PlannerInput,
    policy_coverage: PolicyCoverage,
) -> bool {
    match requirement {
        Requirement::Observed(protocol) => {
            input.capture_available() && input.protocols.contains(&protocol)
        }
        Requirement::DiscoveryHint(protocol) => {
            input.capture_available() && discovery_hint_available(protocol, input, policy_coverage)
        }
        Requirement::Policy(field) => policy_coverage.contains_any(field),
        Requirement::Capture => input.capture_available(),
        Requirement::Capability(_)
        | Requirement::AgentsAtLeast(_)
        | Requirement::StpRootAdvertisement => true,
    }
}

/// Decide whether a prerequisite's local resources are ready for execution
pub(super) fn resource_available(
    requirement: Requirement,
    input: &PlannerInput,
    policy_coverage: PolicyCoverage,
) -> bool {
    match requirement {
        Requirement::Capability(capability) => input.capabilities.contains(&capability),
        Requirement::AgentsAtLeast(required) => input.agent_count() >= required,
        Requirement::Capture => input.capture_available(),
        Requirement::Policy(field) => policy_coverage.contains_all(field),
        Requirement::StpRootAdvertisement => policy_coverage.all_have_stp_root_advertisements(),
        Requirement::Observed(_) | Requirement::DiscoveryHint(_) => true,
    }
}

/// Explain a policy requirement that is only covered by some matched sources
pub(super) fn resource_requirement_label(
    requirement: Requirement,
    policy_coverage: PolicyCoverage,
) -> String {
    if let Requirement::Policy(field) = requirement
        && policy_coverage.contains_any(field)
        && !policy_coverage.contains_all(field)
    {
        return format!("{} for every matched source", policy_label(field));
    }
    if requirement == Requirement::StpRootAdvertisement
        && policy_coverage.has_multiple_sources()
        && !policy_coverage.all_have_stp_root_advertisements()
    {
        return format!("{requirement} from every matched source");
    }
    requirement.to_string()
}

/// Explain why a catalog entry was or was not evaluated
pub(super) fn reason_for(applicable: bool, coverage: CoverageStatus, missing: &[String]) -> String {
    if !applicable {
        return format!("not applicable: requires {}", missing.join(", "));
    }
    if coverage == CoverageStatus::Tested {
        return "passive check evaluated from the observed inventory and policy".into();
    }
    if missing.is_empty() {
        return "applicable; the passive planner leaves active execution disabled".into();
    }
    format!("not tested: requires {}", missing.join(", "))
}

impl fmt::Display for Requirement {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Observed(protocol) => write!(output, "{protocol} observed"),
            Self::DiscoveryHint(protocol) => write!(output, "{protocol} discovery hint"),
            Self::Policy(policy) => write!(output, "{}", policy_label(*policy)),
            Self::Capability(capability) => {
                write!(output, "{} capability", capability_label(*capability))
            }
            Self::AgentsAtLeast(count) => write!(output, "at least {count} controlled agent(s)"),
            Self::Capture => output.write_str("a capture scope"),
            Self::StpRootAdvertisement => output.write_str("a root-bearing STP advertisement"),
        }
    }
}

fn discovery_hint_available(
    protocol: Protocol,
    input: &PlannerInput,
    policy_coverage: PolicyCoverage,
) -> bool {
    if input.protocols().contains(&protocol) {
        return true;
    }
    match input.profile() {
        AssessmentProfile::Opportunistic => false,
        AssessmentProfile::Full => true,
        AssessmentProfile::Standard => standard_relevance(protocol, input, policy_coverage),
    }
}

fn standard_relevance(
    protocol: Protocol,
    input: &PlannerInput,
    policy_coverage: PolicyCoverage,
) -> bool {
    let endpoint = input
        .port_roles()
        .iter()
        .any(|role| matches!(role, PortRole::EndpointAccess | PortRole::MultiEndpoint));
    match protocol {
        Protocol::Eapol => {
            endpoint || policy_coverage.contains_any(PolicyRequirement::Dot1xRequired)
        }
        Protocol::Stp
        | Protocol::Dtp
        | Protocol::Dhcp
        | Protocol::Arp
        | Protocol::Igmp
        | Protocol::Mld => endpoint,
        Protocol::Ipv6Ra | Protocol::Dhcpv6 => {
            endpoint
                || input.protocols().iter().any(|observed| {
                    matches!(
                        observed,
                        Protocol::Ipv6Nd | Protocol::Ipv6Ra | Protocol::Dhcpv6 | Protocol::Mld
                    )
                })
        }
        Protocol::Lacp => input.port_roles().contains(&PortRole::AggregatedLink),
        Protocol::Macsec | Protocol::Mka => {
            policy_coverage.contains_any(PolicyRequirement::ProtocolPolicy)
        }
        Protocol::Lldp
        | Protocol::Cdp
        | Protocol::Vtp
        | Protocol::Pagp
        | Protocol::PvstPlus
        | Protocol::Hsrp
        | Protocol::Vrrp
        | Protocol::Ipv6Nd
        | Protocol::Mdns
        | Protocol::Ssdp
        | Protocol::Netbios
        | Protocol::CiscoSnap => false,
    }
}

const fn capability_label(capability: Capability) -> &'static str {
    match capability {
        Capability::PassiveCapture => "passive capture",
        Capability::ActiveTransmit => "active transmit",
        Capability::AuthenticatedEndpoint => "authenticated endpoint",
        Capability::StatefulProbe => "stateful probe",
        Capability::DisruptiveProbe => "disruptive probe",
    }
}

const fn policy_label(policy: PolicyRequirement) -> &'static str {
    match policy {
        PolicyRequirement::AllowedVlans => "an allowed-VLAN policy",
        PolicyRequirement::Dot1xRequired => "a policy requiring 802.1X",
        PolicyRequirement::LldpVisibility => "an LLDP visibility policy",
        PolicyRequirement::PriorityTaggedFrames => "a priority-tag policy",
        PolicyRequirement::StpEndpointVisibility => "an endpoint STP visibility policy",
        PolicyRequirement::UntaggedFrames => "an untagged-frame policy",
        PolicyRequirement::MaximumVlanDepth => "a maximum VLAN-depth policy",
        PolicyRequirement::ExpectedStpRoot => "an expected STP-root policy",
        PolicyRequirement::ProtocolPolicy => "a control-protocol policy",
        PolicyRequirement::SegmentationPaths => "a directed segmentation path policy",
    }
}
