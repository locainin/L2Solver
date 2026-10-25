//! Controlled segmentation and broadcast-boundary checks

use super::super::types::{CheckCategory, CheckDescriptor, CleanupPolicy, RiskClass};
use super::requirements::SEGMENTATION_REQUIREMENTS;
use std::time::Duration;

pub(super) const SEG_001: CheckDescriptor = CheckDescriptor {
    id: "SEG-001",
    title: "Segmentation and client-isolation validation",
    category: CheckCategory::Segmentation,
    prerequisites: SEGMENTATION_REQUIREMENTS,
    risk: RiskClass::SafeActive,
    required_agents: 2,
    packet_budget: 512,
    byte_budget: 131_072,
    duration_budget: Duration::from_mins(1),
    cleanup: CleanupPolicy::Verified,
};

pub(super) const SEG_BROADCAST_001: CheckDescriptor = CheckDescriptor {
    id: "SEG-BROADCAST-001",
    title: "Broadcast boundary validation",
    category: CheckCategory::Segmentation,
    prerequisites: SEGMENTATION_REQUIREMENTS,
    risk: RiskClass::SafeActive,
    required_agents: 2,
    packet_budget: 512,
    byte_budget: 131_072,
    duration_budget: Duration::from_mins(1),
    cleanup: CleanupPolicy::Verified,
};

pub(super) const SEG_CLIENT_001: CheckDescriptor = CheckDescriptor {
    id: "SEG-CLIENT-001",
    title: "Client-isolation validation",
    category: CheckCategory::Segmentation,
    prerequisites: SEGMENTATION_REQUIREMENTS,
    risk: RiskClass::SafeActive,
    required_agents: 2,
    packet_budget: 512,
    byte_budget: 131_072,
    duration_budget: Duration::from_mins(1),
    cleanup: CleanupPolicy::Verified,
};

pub(super) const SEG_MULTICAST_001: CheckDescriptor = CheckDescriptor {
    id: "SEG-MULTICAST-001",
    title: "Multicast boundary validation",
    category: CheckCategory::Segmentation,
    prerequisites: SEGMENTATION_REQUIREMENTS,
    risk: RiskClass::SafeActive,
    required_agents: 2,
    packet_budget: 512,
    byte_budget: 131_072,
    duration_budget: Duration::from_mins(1),
    cleanup: CleanupPolicy::Verified,
};

pub(super) const SEG_UNKNOWN_UNICAST_001: CheckDescriptor = CheckDescriptor {
    id: "SEG-UNKNOWN-UNICAST-001",
    title: "Unknown-unicast boundary validation",
    category: CheckCategory::Segmentation,
    prerequisites: SEGMENTATION_REQUIREMENTS,
    risk: RiskClass::SafeActive,
    required_agents: 2,
    packet_budget: 512,
    byte_budget: 131_072,
    duration_budget: Duration::from_mins(1),
    cleanup: CleanupPolicy::Verified,
};
