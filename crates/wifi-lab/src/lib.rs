//! Deterministic wireless channel and capture simulation for tests
//!
//! The lab stores raw, explicitly typed capture inputs and delivers them only
//! when a virtual radio is tuned to the input frequency at the input time. It
//! has no operating-system, socket, timer, or transmit capabilities.

#![forbid(unsafe_code)]

mod accounting;
mod air;
mod capture;
mod coverage;
mod error;
mod input;
mod limits;
mod radio;
mod schedule;

pub use accounting::{CaptureAccounting, RadioAccounting};
pub use air::{CaptureReport, VirtualAir};
pub use capture::{CaptureLoss, CapturedFrame, LossReason, RawCapture};
pub use coverage::{ChannelDwell, CoverageInput};
pub use error::LabError;
pub use input::{CaptureInput, LinkType};
pub use limits::{
    LabLimits, MAX_CHANNELS, MAX_FRAME_BYTES, MAX_INPUT_BYTES, MAX_OBSERVATIONS,
    MAX_OBSERVED_BYTES, MAX_RADIOS, MAX_RECORDS, MAX_WINDOWS,
};
pub use radio::VirtualRadio;
pub use schedule::DwellWindow;
