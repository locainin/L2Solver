//! Activity, risk, and per-check resource budgets

use super::limits::{MAX_BYTE_BUDGET, MAX_DURATION_BUDGET_MILLIS, MAX_PACKET_BUDGET};
use crate::BudgetError;

/// Activity class describing how a descriptor interacts with a network
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ActivityClass {
    /// Reads existing evidence only
    Passive,
    /// Sends a bounded, non-state-changing validation stimulus
    SafeActive,
    /// Exercises endpoint or neighbor state with a bounded stimulus
    Stateful,
    /// May alter forwarding state or fill a bounded switch table
    Disruptive,
}

impl ActivityClass {
    /// Stable operator-facing activity label
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passive => "passive",
            Self::SafeActive => "safe_active",
            Self::Stateful => "stateful",
            Self::Disruptive => "disruptive",
        }
    }
}

/// Risk class shown with every catalog descriptor
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RiskClass {
    /// No state mutation is expected
    Low,
    /// A bounded state change is expected and reversible
    Moderate,
    /// A neighbor or forwarding policy may be exercised
    High,
    /// A direct identity-conflict or table-exhaustion proof is involved
    Critical,
}

impl RiskClass {
    /// Stable operator-facing risk label
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Moderate => "moderate",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Fixed packet, byte, and duration ceilings for one check
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Budget {
    /// Maximum committed packets
    packets: u64,
    /// Maximum committed bytes
    bytes: u64,
    /// Maximum test duration in milliseconds
    duration_millis: u64,
}

impl Budget {
    /// Construct a budget after checking all absolute ceilings
    ///
    /// # Errors
    /// Returns [`BudgetError`] when a value is zero or exceeds its absolute ceiling
    pub const fn new(packets: u64, bytes: u64, duration_millis: u64) -> Result<Self, BudgetError> {
        if packets == 0 {
            return Err(BudgetError::ZeroPackets);
        }
        if bytes == 0 {
            return Err(BudgetError::ZeroBytes);
        }
        if duration_millis == 0 {
            return Err(BudgetError::ZeroDuration);
        }
        if packets > MAX_PACKET_BUDGET {
            return Err(BudgetError::PacketsExceeded {
                value: packets,
                maximum: MAX_PACKET_BUDGET,
            });
        }
        if bytes > MAX_BYTE_BUDGET {
            return Err(BudgetError::BytesExceeded {
                value: bytes,
                maximum: MAX_BYTE_BUDGET,
            });
        }
        if duration_millis > MAX_DURATION_BUDGET_MILLIS {
            return Err(BudgetError::DurationExceeded {
                value: duration_millis,
                maximum: MAX_DURATION_BUDGET_MILLIS,
            });
        }
        Ok(Self {
            packets,
            bytes,
            duration_millis,
        })
    }

    /// Construct static catalog data known to satisfy the absolute ceilings
    pub(crate) const fn const_new(packets: u64, bytes: u64, duration_millis: u64) -> Self {
        Self {
            packets,
            bytes,
            duration_millis,
        }
    }

    /// Return the packet ceiling
    #[must_use]
    pub const fn packets(self) -> u64 {
        self.packets
    }

    /// Return the byte ceiling
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.bytes
    }

    /// Return the duration ceiling in milliseconds
    #[must_use]
    pub const fn duration_millis(self) -> u64 {
        self.duration_millis
    }
}
