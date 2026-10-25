//! DHCP and address-assignment protection checks

use super::super::types::{CheckCategory, CheckDescriptor, CleanupPolicy, RiskClass};
use super::requirements::{
    DHCP_INVENTORY_REQUIREMENTS, DHCP_REQUIREMENTS, DHCPV6_GUARD_REQUIREMENTS,
    DHCPV6_INVENTORY_REQUIREMENTS,
};
use std::time::Duration;

pub(super) const DHCP_001: CheckDescriptor = CheckDescriptor {
    id: "DHCP-001",
    title: "DHCP snooping validation",
    category: CheckCategory::DhcpProtection,
    prerequisites: DHCP_REQUIREMENTS,
    risk: RiskClass::Stateful,
    required_agents: 1,
    packet_budget: 256,
    byte_budget: 65_536,
    duration_budget: Duration::from_secs(30),
    cleanup: CleanupPolicy::Verified,
};

pub(super) const DHCP_INVENTORY_001: CheckDescriptor = CheckDescriptor {
    id: "DHCP-INVENTORY-001",
    title: "DHCP participant inventory",
    category: CheckCategory::DhcpProtection,
    prerequisites: DHCP_INVENTORY_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};

pub(super) const DHCP_MULTIPLE_001: CheckDescriptor = CheckDescriptor {
    id: "DHCP-MULTIPLE-001",
    title: "Multiple DHCP server observation",
    category: CheckCategory::DhcpProtection,
    prerequisites: DHCP_INVENTORY_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};

pub(super) const DHCPV6_GUARD_001: CheckDescriptor = CheckDescriptor {
    id: "DHCPV6-GUARD-001",
    title: "DHCPv6 Guard validation",
    category: CheckCategory::Ipv6Protection,
    prerequisites: DHCPV6_GUARD_REQUIREMENTS,
    risk: RiskClass::Stateful,
    required_agents: 1,
    packet_budget: 256,
    byte_budget: 65_536,
    duration_budget: Duration::from_secs(30),
    cleanup: CleanupPolicy::Verified,
};

pub(super) const DHCPV6_OBS_001: CheckDescriptor = CheckDescriptor {
    id: "DHCPV6-OBS-001",
    title: "DHCPv6 participant inventory",
    category: CheckCategory::Ipv6Protection,
    prerequisites: DHCPV6_INVENTORY_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};
