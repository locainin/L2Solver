use serde::{Deserialize, Serialize};

/// Operational risk for a future controlled wireless check
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RiskClass {
    SafeActive,
    Stateful,
}

/// Bounded prerequisites for one wireless active check
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct WirelessCheckDescriptor {
    id: &'static str,
    risk: RiskClass,
    requires_transmit: bool,
    required_agents: u8,
    packet_budget: u16,
    duration_ms: u32,
}

impl WirelessCheckDescriptor {
    #[must_use]
    pub const fn id(self) -> &'static str {
        self.id
    }

    #[must_use]
    pub const fn risk(self) -> RiskClass {
        self.risk
    }

    #[must_use]
    pub const fn requires_transmit(self) -> bool {
        self.requires_transmit
    }

    #[must_use]
    pub const fn required_agents(self) -> u8 {
        self.required_agents
    }

    #[must_use]
    pub const fn packet_budget(self) -> u16 {
        self.packet_budget
    }

    #[must_use]
    pub const fn duration_ms(self) -> u32 {
        self.duration_ms
    }
}

const SAFE: RiskClass = RiskClass::SafeActive;
const STATEFUL: RiskClass = RiskClass::Stateful;

const ACTIVE_CATALOG: &[WirelessCheckDescriptor] = &[
    check("WIFI-ASSOC-001", STATEFUL, true, 1, 24, 15_000),
    check("WIFI-CLIENT-ISOLATION", SAFE, true, 2, 12, 10_000),
    check("WIFI-GUEST-WIRED-SEG", SAFE, true, 2, 12, 10_000),
    check("WIFI-NAC-PREAUTH", SAFE, true, 2, 12, 10_000),
    check("WIFI-NAC-POSTAUTH", STATEFUL, true, 2, 24, 30_000),
    check("WIFI-PMF-ENFORCEMENT", STATEFUL, true, 1, 12, 10_000),
    check("WIFI-ROAM-SEGMENTATION", STATEFUL, true, 2, 36, 60_000),
    check("WIFI-SSID-SEGMENTATION", SAFE, true, 2, 12, 10_000),
    check("WIFI-WIRELESS-WIRED-SEG", SAFE, true, 2, 12, 10_000),
];

const fn check(
    id: &'static str,
    risk: RiskClass,
    requires_transmit: bool,
    required_agents: u8,
    packet_budget: u16,
    duration_ms: u32,
) -> WirelessCheckDescriptor {
    WirelessCheckDescriptor {
        id,
        risk,
        requires_transmit,
        required_agents,
        packet_budget,
        duration_ms,
    }
}

/// Active wireless checks remain catalogued as unavailable until radio control exists
#[must_use]
pub const fn active_catalog() -> &'static [WirelessCheckDescriptor] {
    ACTIVE_CATALOG
}
