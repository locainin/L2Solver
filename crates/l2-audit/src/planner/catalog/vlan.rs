//! VLAN policy and tag-boundary checks

use super::super::types::{CheckCategory, CheckDescriptor, CleanupPolicy, RiskClass};
use super::requirements::{
    VLAN_DEPTH_REQUIREMENTS, VLAN_POLICY_REQUIREMENTS, VLAN_PRIORITY_REQUIREMENTS,
    VLAN_QINQ_REQUIREMENTS, VLAN_UNTAGGED_REQUIREMENTS,
};
use std::time::Duration;

pub(super) const VLAN_001: CheckDescriptor = CheckDescriptor {
    id: "VLAN-001",
    title: "Allowed VLAN policy comparison",
    category: CheckCategory::Vlan,
    prerequisites: VLAN_POLICY_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};

pub(super) const VLAN_002: CheckDescriptor = CheckDescriptor {
    id: "VLAN-002",
    title: "Untagged-frame policy comparison",
    category: CheckCategory::Vlan,
    prerequisites: VLAN_UNTAGGED_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};

pub(super) const VLAN_003: CheckDescriptor = CheckDescriptor {
    id: "VLAN-003",
    title: "VLAN tag-depth policy comparison",
    category: CheckCategory::Vlan,
    prerequisites: VLAN_DEPTH_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};

pub(super) const VLAN_004: CheckDescriptor = CheckDescriptor {
    id: "VLAN-004",
    title: "Priority-tagged frame policy comparison",
    category: CheckCategory::Vlan,
    prerequisites: VLAN_PRIORITY_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};

pub(super) const VLAN_QINQ_001: CheckDescriptor = CheckDescriptor {
    id: "VLAN-QINQ-001",
    title: "QinQ boundary validation",
    category: CheckCategory::Vlan,
    prerequisites: VLAN_QINQ_REQUIREMENTS,
    risk: RiskClass::SafeActive,
    required_agents: 2,
    packet_budget: 512,
    byte_budget: 131_072,
    duration_budget: Duration::from_mins(1),
    cleanup: CleanupPolicy::Verified,
};
