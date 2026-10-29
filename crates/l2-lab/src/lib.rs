//! Stateless virtual access-port isolation tests using synthetic Ethernet frames
//!
//! All bindings, clocks, transmissions, captures, and receipts are modeled
//! values. No operating-system interface is opened and no physical control is
//! established. An evaluation describes only the configured virtual model

mod capture;
mod error;
mod execution;
mod frame;
mod options;
mod receipts;
mod topology;

pub use capture::{CapturedFrame, VirtualCapture};
pub use error::LabError;
pub use execution::{VirtualLab, VirtualRun};
pub use options::{Cancellation, ObservationMode, RunOptions};
pub use topology::{BridgeMode, VirtualEndpoint, VlanId};
