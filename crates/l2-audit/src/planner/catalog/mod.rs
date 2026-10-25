//! Immutable check catalog assembled in stable operator-facing order

use super::MAX_PLAN_ENTRIES;
use super::types::CheckDescriptor;

mod access_control;
mod aggregation;
mod arp;
mod broadcast;
mod dhcp;
mod first_hop;
mod ipv6;
mod link_security;
mod multicast;
mod neighbor;
mod requirements;
mod resilience;
mod segmentation;
mod spanning_tree;
mod trunking;
mod vlan;

// Keep this table lexicographically ordered so JSON and terminal output are stable
pub(super) const CATALOG: &[CheckDescriptor] = &[
    arp::ARP_001,
    arp::ARP_CONFLICT_001,
    arp::ARP_INVENTORY_001,
    neighbor::CDP_OBS_001,
    access_control::CTRL_POLICY_001,
    dhcp::DHCP_001,
    dhcp::DHCP_INVENTORY_001,
    dhcp::DHCP_MULTIPLE_001,
    dhcp::DHCPV6_GUARD_001,
    dhcp::DHCPV6_OBS_001,
    access_control::DOT1X_001,
    access_control::DOT1X_OBS_001,
    access_control::DOT1X_POLICY_001,
    trunking::DTP_001,
    trunking::DTP_OBS_001,
    first_hop::HSRP_OBS_001,
    multicast::IGMP_OBS_001,
    multicast::IGMP_SNOOP_001,
    ipv6::IPV6_001,
    ipv6::IPV6_ND_001,
    ipv6::IPV6_RA_MULTIPLE_001,
    ipv6::IPV6_RA_OBS_001,
    aggregation::LACP_001,
    aggregation::LACP_OBS_001,
    neighbor::LLDP_001,
    neighbor::LLDP_002,
    resilience::LOOP_001,
    link_security::MACSEC_001,
    link_security::MACSEC_OBS_001,
    resilience::MACTABLE_001,
    broadcast::MDNS_OBS_001,
    link_security::MKA_OBS_001,
    multicast::MLD_001,
    multicast::MLD_SNOOP_001,
    broadcast::NETBIOS_OBS_001,
    aggregation::PAGP_OBS_001,
    access_control::PORTSEC_001,
    spanning_tree::PVST_OBS_001,
    segmentation::SEG_001,
    segmentation::SEG_BROADCAST_001,
    segmentation::SEG_CLIENT_001,
    segmentation::SEG_MULTICAST_001,
    segmentation::SEG_UNKNOWN_UNICAST_001,
    broadcast::SSDP_OBS_001,
    resilience::STORM_001,
    spanning_tree::STP_001,
    spanning_tree::STP_002,
    spanning_tree::STP_003,
    spanning_tree::STP_CHANGE_001,
    spanning_tree::STP_GUARD_001,
    vlan::VLAN_001,
    vlan::VLAN_002,
    vlan::VLAN_003,
    vlan::VLAN_004,
    vlan::VLAN_QINQ_001,
    first_hop::VRRP_OBS_001,
    trunking::VTP_OBS_001,
];

const _: () = assert!(CATALOG.len() <= MAX_PLAN_ENTRIES);
