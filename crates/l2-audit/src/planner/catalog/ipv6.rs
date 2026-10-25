//! IPv6 neighbor and router-advertisement checks

use super::super::types::{CheckCategory, CheckDescriptor, CleanupPolicy, RiskClass};
use super::requirements::{IPV6_ND_REQUIREMENTS, IPV6_RA_REQUIREMENTS, IPV6_REQUIREMENTS};
use std::time::Duration;

pub(super) const IPV6_001: CheckDescriptor = CheckDescriptor {
    id: "IPV6-001",
    title: "IPv6 router-advertisement protection validation",
    category: CheckCategory::Ipv6Protection,
    prerequisites: IPV6_REQUIREMENTS,
    risk: RiskClass::Stateful,
    required_agents: 1,
    packet_budget: 256,
    byte_budget: 65_536,
    duration_budget: Duration::from_secs(30),
    cleanup: CleanupPolicy::Verified,
};

pub(super) const IPV6_ND_001: CheckDescriptor = CheckDescriptor {
    id: "IPV6-ND-001",
    title: "IPv6 neighbor-discovery inventory",
    category: CheckCategory::Ipv6Protection,
    prerequisites: IPV6_ND_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};

pub(super) const IPV6_RA_MULTIPLE_001: CheckDescriptor = CheckDescriptor {
    id: "IPV6-RA-MULTIPLE-001",
    title: "Multiple IPv6 router observation",
    category: CheckCategory::Ipv6Protection,
    prerequisites: IPV6_RA_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};

pub(super) const IPV6_RA_OBS_001: CheckDescriptor = CheckDescriptor {
    id: "IPV6-RA-OBS-001",
    title: "IPv6 router-advertisement inventory",
    category: CheckCategory::Ipv6Protection,
    prerequisites: IPV6_RA_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};
