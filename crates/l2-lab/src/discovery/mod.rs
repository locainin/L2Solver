//! Bounded, simulated LLDP and CDP neighbor identity assessment
//!
//! Frames, clocks, receivers, and observations are synthetic. No socket or
//! physical network interface is opened by this module

mod capture;
mod error;
mod execution;
mod model;
mod receiver;

pub use error::DiscoveryError;
pub use execution::{DiscoveryLab, DiscoveryRun, MAX_FRAME_BYTES, MAX_PROBES};
pub use model::{Check, Expectation, Identity, Observation, Observed, Probe, Protocol};
