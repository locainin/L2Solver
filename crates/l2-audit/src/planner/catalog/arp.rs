//! ARP assessment checks

use super::super::types::{CheckCategory, CheckDescriptor, CleanupPolicy, RiskClass};
use super::requirements::{ARP_INVENTORY_REQUIREMENTS, ARP_REQUIREMENTS};
use std::time::Duration;

pub(super) const ARP_001: CheckDescriptor = CheckDescriptor {
    id: "ARP-001",
    title: "ARP protection validation",
    category: CheckCategory::ArpProtection,
    prerequisites: ARP_REQUIREMENTS,
    risk: RiskClass::Stateful,
    required_agents: 1,
    packet_budget: 256,
    byte_budget: 65_536,
    duration_budget: Duration::from_secs(30),
    cleanup: CleanupPolicy::Verified,
};

pub(super) const ARP_CONFLICT_001: CheckDescriptor = CheckDescriptor {
    id: "ARP-CONFLICT-001",
    title: "Conflicting ARP claim observation",
    category: CheckCategory::ArpProtection,
    prerequisites: ARP_INVENTORY_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};

pub(super) const ARP_INVENTORY_001: CheckDescriptor = CheckDescriptor {
    id: "ARP-INVENTORY-001",
    title: "ARP identity and conflict inventory",
    category: CheckCategory::ArpProtection,
    prerequisites: ARP_INVENTORY_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};
