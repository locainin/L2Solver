//! Reusable prerequisite groups for the immutable check catalog

use super::super::types::{Capability, PolicyRequirement, Requirement};
use l2_discovery::Protocol;

// Endpoint and address-control checks use discovery as a priority hint
pub(super) const ARP_REQUIREMENTS: &[Requirement] = &[
    Requirement::DiscoveryHint(Protocol::Arp),
    Requirement::Capability(Capability::ActiveTransmit),
    Requirement::AgentsAtLeast(1),
];
pub(super) const ARP_INVENTORY_REQUIREMENTS: &[Requirement] =
    &[Requirement::Observed(Protocol::Arp)];
pub(super) const CDP_REQUIREMENTS: &[Requirement] = &[Requirement::Observed(Protocol::Cdp)];
pub(super) const DHCP_REQUIREMENTS: &[Requirement] = &[
    Requirement::DiscoveryHint(Protocol::Dhcp),
    Requirement::Capability(Capability::ActiveTransmit),
    Requirement::AgentsAtLeast(1),
];
pub(super) const DHCP_INVENTORY_REQUIREMENTS: &[Requirement] =
    &[Requirement::Observed(Protocol::Dhcp)];
pub(super) const DHCPV6_GUARD_REQUIREMENTS: &[Requirement] = &[
    Requirement::DiscoveryHint(Protocol::Dhcpv6),
    Requirement::Capability(Capability::ActiveTransmit),
    Requirement::AgentsAtLeast(1),
];
pub(super) const DHCPV6_INVENTORY_REQUIREMENTS: &[Requirement] =
    &[Requirement::Observed(Protocol::Dhcpv6)];
pub(super) const CONTROL_POLICY_REQUIREMENTS: &[Requirement] = &[
    Requirement::Capture,
    Requirement::Policy(PolicyRequirement::ProtocolPolicy),
];
// Access-control checks can be enabled by discovery or an explicit policy
pub(super) const DOT1X_REQUIREMENTS: &[Requirement] = &[
    Requirement::DiscoveryHint(Protocol::Eapol),
    Requirement::Capability(Capability::ActiveTransmit),
    Requirement::Capability(Capability::AuthenticatedEndpoint),
    Requirement::AgentsAtLeast(1),
];
pub(super) const DOT1X_POLICY_REQUIREMENTS: &[Requirement] = &[
    Requirement::Policy(PolicyRequirement::Dot1xRequired),
    Requirement::Capability(Capability::ActiveTransmit),
    Requirement::Capability(Capability::AuthenticatedEndpoint),
    Requirement::AgentsAtLeast(1),
];
pub(super) const DOT1X_OBSERVATION_REQUIREMENTS: &[Requirement] =
    &[Requirement::Observed(Protocol::Eapol)];
pub(super) const DTP_REQUIREMENTS: &[Requirement] = &[
    Requirement::DiscoveryHint(Protocol::Dtp),
    Requirement::Capability(Capability::ActiveTransmit),
    Requirement::AgentsAtLeast(1),
];
pub(super) const DTP_OBSERVATION_REQUIREMENTS: &[Requirement] =
    &[Requirement::Observed(Protocol::Dtp)];
pub(super) const HSRP_REQUIREMENTS: &[Requirement] = &[Requirement::Observed(Protocol::Hsrp)];
// Multicast protection needs peers while passive inventory needs only observation
pub(super) const IGMP_REQUIREMENTS: &[Requirement] = &[Requirement::Observed(Protocol::Igmp)];
pub(super) const IGMP_SNOOP_REQUIREMENTS: &[Requirement] = &[
    Requirement::DiscoveryHint(Protocol::Igmp),
    Requirement::Capability(Capability::ActiveTransmit),
    Requirement::AgentsAtLeast(2),
];
pub(super) const IPV6_REQUIREMENTS: &[Requirement] = &[
    Requirement::DiscoveryHint(Protocol::Ipv6Ra),
    Requirement::Capability(Capability::ActiveTransmit),
    Requirement::AgentsAtLeast(1),
];
pub(super) const IPV6_ND_REQUIREMENTS: &[Requirement] = &[Requirement::Observed(Protocol::Ipv6Nd)];
pub(super) const IPV6_RA_REQUIREMENTS: &[Requirement] = &[Requirement::Observed(Protocol::Ipv6Ra)];
pub(super) const LACP_REQUIREMENTS: &[Requirement] = &[
    Requirement::DiscoveryHint(Protocol::Lacp),
    Requirement::Capability(Capability::ActiveTransmit),
    Requirement::AgentsAtLeast(1),
];
pub(super) const LACP_OBSERVATION_REQUIREMENTS: &[Requirement] =
    &[Requirement::Observed(Protocol::Lacp)];
pub(super) const LLDP_REQUIREMENTS: &[Requirement] = &[Requirement::Observed(Protocol::Lldp)];
pub(super) const LLDP_POLICY_REQUIREMENTS: &[Requirement] = &[
    Requirement::Capture,
    Requirement::Policy(PolicyRequirement::LldpVisibility),
];
pub(super) const MACSEC_REQUIREMENTS: &[Requirement] = &[
    Requirement::DiscoveryHint(Protocol::Macsec),
    Requirement::Capability(Capability::StatefulProbe),
    Requirement::AgentsAtLeast(1),
];
// MACsec data traffic and MKA advertisements remain distinct passive facts
pub(super) const MACSEC_OBSERVATION_REQUIREMENTS: &[Requirement] =
    &[Requirement::Observed(Protocol::Macsec)];
pub(super) const MKA_OBSERVATION_REQUIREMENTS: &[Requirement] =
    &[Requirement::Observed(Protocol::Mka)];
pub(super) const MDNS_REQUIREMENTS: &[Requirement] = &[Requirement::Observed(Protocol::Mdns)];
pub(super) const MLD_REQUIREMENTS: &[Requirement] = &[Requirement::Observed(Protocol::Mld)];
pub(super) const MLD_SNOOP_REQUIREMENTS: &[Requirement] = &[
    Requirement::DiscoveryHint(Protocol::Mld),
    Requirement::Capability(Capability::ActiveTransmit),
    Requirement::AgentsAtLeast(2),
];
pub(super) const NETBIOS_REQUIREMENTS: &[Requirement] = &[Requirement::Observed(Protocol::Netbios)];
pub(super) const PAGP_REQUIREMENTS: &[Requirement] = &[Requirement::Observed(Protocol::Pagp)];
pub(super) const PVST_REQUIREMENTS: &[Requirement] = &[Requirement::Observed(Protocol::PvstPlus)];
pub(super) const SSDP_REQUIREMENTS: &[Requirement] = &[Requirement::Observed(Protocol::Ssdp)];
pub(super) const SEGMENTATION_REQUIREMENTS: &[Requirement] = &[
    Requirement::Capture,
    Requirement::Policy(PolicyRequirement::SegmentationPaths),
    Requirement::Capability(Capability::ActiveTransmit),
    Requirement::AgentsAtLeast(2),
];
// Resource checks are always held behind the disruptive capability class
pub(super) const LOOP_REQUIREMENTS: &[Requirement] = &[
    Requirement::DiscoveryHint(Protocol::Stp),
    Requirement::Capability(Capability::DisruptiveProbe),
    Requirement::AgentsAtLeast(1),
];
pub(super) const MAC_TABLE_REQUIREMENTS: &[Requirement] = &[
    Requirement::Capture,
    Requirement::Capability(Capability::DisruptiveProbe),
    Requirement::AgentsAtLeast(1),
];
pub(super) const PORT_SECURITY_REQUIREMENTS: &[Requirement] = &[
    Requirement::Capture,
    Requirement::Capability(Capability::DisruptiveProbe),
    Requirement::AgentsAtLeast(1),
];
pub(super) const STORM_REQUIREMENTS: &[Requirement] = &[
    Requirement::Capture,
    Requirement::Capability(Capability::DisruptiveProbe),
    Requirement::AgentsAtLeast(1),
];
pub(super) const STP_REQUIREMENTS: &[Requirement] = &[Requirement::Observed(Protocol::Stp)];
// Root policy uses observed bridge evidence rather than generic STP visibility
pub(super) const STP_ROOT_REQUIREMENTS: &[Requirement] = &[
    Requirement::Observed(Protocol::Stp),
    Requirement::Policy(PolicyRequirement::ExpectedStpRoot),
    Requirement::StpRootAdvertisement,
];
pub(super) const STP_ENDPOINT_POLICY_REQUIREMENTS: &[Requirement] = &[
    Requirement::Capture,
    Requirement::Policy(PolicyRequirement::StpEndpointVisibility),
];
pub(super) const STP_GUARD_REQUIREMENTS: &[Requirement] = &[
    Requirement::DiscoveryHint(Protocol::Stp),
    Requirement::Capability(Capability::ActiveTransmit),
    Requirement::AgentsAtLeast(1),
];
pub(super) const VLAN_POLICY_REQUIREMENTS: &[Requirement] = &[
    Requirement::Capture,
    Requirement::Policy(PolicyRequirement::AllowedVlans),
];
// VLAN policy distinguishes untagged, priority-tagged, and nested-tag behavior
pub(super) const VLAN_UNTAGGED_REQUIREMENTS: &[Requirement] = &[
    Requirement::Capture,
    Requirement::Policy(PolicyRequirement::UntaggedFrames),
];
pub(super) const VLAN_PRIORITY_REQUIREMENTS: &[Requirement] = &[
    Requirement::Capture,
    Requirement::Policy(PolicyRequirement::PriorityTaggedFrames),
];
pub(super) const VLAN_DEPTH_REQUIREMENTS: &[Requirement] = &[
    Requirement::Capture,
    Requirement::Policy(PolicyRequirement::MaximumVlanDepth),
];
pub(super) const VLAN_QINQ_REQUIREMENTS: &[Requirement] = &[
    Requirement::Capture,
    Requirement::Policy(PolicyRequirement::SegmentationPaths),
    Requirement::Policy(PolicyRequirement::MaximumVlanDepth),
    Requirement::Capability(Capability::ActiveTransmit),
    Requirement::AgentsAtLeast(2),
];
pub(super) const VRRP_REQUIREMENTS: &[Requirement] = &[Requirement::Observed(Protocol::Vrrp)];
pub(super) const VTP_REQUIREMENTS: &[Requirement] = &[Requirement::Observed(Protocol::Vtp)];
