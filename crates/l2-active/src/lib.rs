//! Bounded protocol operations over an explicitly selected active link

#![forbid(unsafe_code)]

mod arp;
pub mod dhcp;
pub mod discovery;
pub mod dot1x;
mod error;
pub mod first_hop;
pub mod isl;
mod limits;
mod link;
pub mod mpls;
mod ndp;
mod neighbor;
mod report;
mod session;
pub mod stp;
pub mod switching;

pub use arp::{ArpObservation, ArpProbe, ArpReport, validate_ipv4_target};
pub use error::{PlanError, RunError};
pub use limits::{Limits, MAX_RECEIVED_BYTES, MAX_RECEIVED_PACKETS, MAX_TIMEOUT};
pub use link::{ActiveLink, PreSendUsage, ReceiveEvent};
pub use ndp::{NdpObservation, NdpPlanError, NdpProbe, NdpReport};
pub use neighbor::NeighborStatus;
pub use report::{RunSummary, StopReason};
