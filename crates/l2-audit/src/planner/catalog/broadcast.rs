//! Broadcast-domain inventory checks

use super::super::types::{CheckCategory, CheckDescriptor, CleanupPolicy, RiskClass};
use super::requirements::{MDNS_REQUIREMENTS, NETBIOS_REQUIREMENTS, SSDP_REQUIREMENTS};
use std::time::Duration;

pub(super) const MDNS_OBS_001: CheckDescriptor = CheckDescriptor {
    id: "MDNS-OBS-001",
    title: "mDNS broadcast-domain inventory",
    category: CheckCategory::BroadcastHygiene,
    prerequisites: MDNS_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};

pub(super) const NETBIOS_OBS_001: CheckDescriptor = CheckDescriptor {
    id: "NETBIOS-OBS-001",
    title: "NetBIOS broadcast-domain inventory",
    category: CheckCategory::BroadcastHygiene,
    prerequisites: NETBIOS_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};

pub(super) const SSDP_OBS_001: CheckDescriptor = CheckDescriptor {
    id: "SSDP-OBS-001",
    title: "SSDP broadcast-domain inventory",
    category: CheckCategory::BroadcastHygiene,
    prerequisites: SSDP_REQUIREMENTS,
    risk: RiskClass::Passive,
    required_agents: 0,
    packet_budget: 0,
    byte_budget: 0,
    duration_budget: Duration::ZERO,
    cleanup: CleanupPolicy::None,
};
