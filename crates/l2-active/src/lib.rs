//! Bounded protocol operations over an explicitly selected active link

#![forbid(unsafe_code)]

mod arp;
pub mod dhcp;
pub mod discovery;
pub mod dot1x;
mod error;
mod limits;
mod link;
mod ndp;
mod report;
mod session;
pub mod stp;

pub use arp::{ArpObservation, ArpProbe, ArpReport, ArpStatus, validate_ipv4_target};
pub use error::{PlanError, RunError};
pub use limits::{Limits, MAX_RECEIVED_BYTES, MAX_RECEIVED_PACKETS, MAX_TIMEOUT};
pub use link::{ActiveLink, PreSendUsage, ReceiveEvent};
pub use ndp::{NdpObservation, NdpPlanError, NdpProbe, NdpReport, NdpStatus};
pub use report::{RunSummary, StopReason};
