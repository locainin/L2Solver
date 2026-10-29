//! Bounded synthetic STP root and edge-port protection experiments
//!
//! All frames, bridge states, snapshots, and receipts are virtual. This model
//! does not open an interface or establish the behavior of a real bridge

mod admission;
mod bridge;
mod capture;
mod error;
mod scenario;

pub use bridge::{Bridge, BridgeState, PortState};
pub use capture::{Capture, CapturedFrame};
pub use error::Error;
pub use scenario::{CleanupMode, Guard, GuardExpectation, Options, Port, Report, Scenario};
