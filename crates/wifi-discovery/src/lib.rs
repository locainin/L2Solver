//! Bounded passive wireless inventory and channel-coverage accounting

#![forbid(unsafe_code)]

mod error;
pub(crate) mod model;
mod security;
mod survey;

pub use error::SurveyError;
pub use model::{
    AccessPoint, ChannelCoverage, ChannelDwell, Diagnostic, DiagnosticKind, ObservationContext,
    ObservationStatus, PmfStatus, SecurityEvidence, SecurityMode, Station, SurveyLimits,
    WirelessInput,
};
pub use survey::Survey;

/// Absolute access-point inventory ceiling
pub const ABSOLUTE_MAX_ACCESS_POINTS: usize = 4_096;

/// Absolute station inventory ceiling
pub const ABSOLUTE_MAX_STATIONS: usize = 65_536;

/// Absolute diagnostic inventory ceiling
pub const ABSOLUTE_MAX_DIAGNOSTICS: usize = 4_096;

/// Absolute radio/channel accounting ceiling
pub const ABSOLUTE_MAX_CHANNELS: usize = 1_024;
