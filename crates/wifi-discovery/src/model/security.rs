//! Security evidence values and conservative merge rules

use serde::{Deserialize, Serialize};

/// Coarse security posture supported by decoded advertisement evidence
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum SecurityMode {
    Unknown,
    Open,
    Wep,
    WpaLegacy,
    WpaMixedLegacy,
    Wpa2Personal,
    Wpa2Enterprise,
    Wpa3Personal,
    Wpa3Enterprise,
    Wpa2Wpa3PersonalTransition,
    Owe,
    UnknownProtected,
}

/// Protected-management-frame posture from an RSN advertisement
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum PmfStatus {
    Unknown,
    Disabled,
    Capable,
    Required,
}

impl PmfStatus {
    const fn rank(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Disabled => 1,
            Self::Capable => 2,
            Self::Required => 3,
        }
    }
}

/// Security properties retained from one or more advertisements
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct SecurityEvidence {
    mode: SecurityMode,
    tkip: bool,
    wps: bool,
    pmf: PmfStatus,
    quality: SecurityQuality,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
enum SecurityQuality {
    // Complete means policy-relevant selectors were classified
    Complete,
    Incomplete,
    Inconsistent,
}

impl SecurityEvidence {
    #[must_use]
    pub const fn new(mode: SecurityMode, tkip: bool, wps: bool, pmf: PmfStatus) -> Self {
        Self {
            mode,
            tkip,
            wps,
            pmf,
            quality: SecurityQuality::Complete,
        }
    }

    /// Build evidence whose security advertisement could not be interpreted
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            mode: SecurityMode::Unknown,
            tkip: false,
            wps: false,
            pmf: PmfStatus::Unknown,
            quality: SecurityQuality::Incomplete,
        }
    }

    /// Mark whether security evidence supports a definitive result
    #[must_use]
    pub const fn with_complete(mut self, value: bool) -> Self {
        self.quality = if value {
            SecurityQuality::Complete
        } else {
            SecurityQuality::Incomplete
        };
        self
    }

    #[must_use]
    pub const fn mode(self) -> SecurityMode {
        self.mode
    }

    #[must_use]
    pub const fn tkip(self) -> bool {
        self.tkip
    }

    #[must_use]
    pub const fn wps(self) -> bool {
        self.wps
    }

    #[must_use]
    pub const fn pmf(self) -> PmfStatus {
        self.pmf
    }

    #[must_use]
    pub const fn complete(self) -> bool {
        matches!(self.quality, SecurityQuality::Complete)
    }

    #[must_use]
    pub const fn inconsistent(self) -> bool {
        matches!(self.quality, SecurityQuality::Inconsistent)
    }

    pub(crate) const fn mark_inconsistent(mut self) -> Self {
        self.quality = SecurityQuality::Inconsistent;
        self
    }

    #[must_use]
    pub fn merged(self, observed: Self) -> Self {
        let mode_changed = !matches!(self.mode, SecurityMode::Unknown)
            && !matches!(observed.mode, SecurityMode::Unknown)
            && self.mode != observed.mode;
        Self {
            mode: weaker_mode(self.mode, observed.mode),
            tkip: self.tkip || observed.tkip,
            wps: self.wps || observed.wps,
            pmf: weaker_pmf(self.pmf, observed.pmf),
            quality: merged_security_quality(self.quality, observed.quality, mode_changed),
        }
    }
}

const fn merged_security_quality(
    left: SecurityQuality,
    right: SecurityQuality,
    mode_changed: bool,
) -> SecurityQuality {
    if mode_changed
        || matches!(left, SecurityQuality::Inconsistent)
        || matches!(right, SecurityQuality::Inconsistent)
    {
        SecurityQuality::Inconsistent
    } else if matches!(left, SecurityQuality::Complete)
        && matches!(right, SecurityQuality::Complete)
    {
        SecurityQuality::Complete
    } else {
        SecurityQuality::Incomplete
    }
}

const fn weaker_mode(left: SecurityMode, right: SecurityMode) -> SecurityMode {
    if matches!(left, SecurityMode::Unknown) {
        return right;
    }
    if matches!(right, SecurityMode::Unknown) {
        return left;
    }
    if security_risk(left) >= security_risk(right) {
        left
    } else {
        right
    }
}

const fn security_risk(mode: SecurityMode) -> u8 {
    match mode {
        SecurityMode::Unknown => 0,
        SecurityMode::Wep => 10,
        SecurityMode::Open => 9,
        SecurityMode::WpaLegacy => 8,
        SecurityMode::WpaMixedLegacy => 7,
        SecurityMode::Wpa2Wpa3PersonalTransition => 6,
        SecurityMode::UnknownProtected => 5,
        SecurityMode::Wpa2Personal | SecurityMode::Owe => 4,
        SecurityMode::Wpa2Enterprise => 3,
        SecurityMode::Wpa3Personal => 2,
        SecurityMode::Wpa3Enterprise => 1,
    }
}

const fn weaker_pmf(left: PmfStatus, right: PmfStatus) -> PmfStatus {
    if matches!(left, PmfStatus::Unknown) {
        return right;
    }
    if matches!(right, PmfStatus::Unknown) {
        return left;
    }
    if left.rank() <= right.rank() {
        left
    } else {
        right
    }
}
