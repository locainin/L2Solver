//! Bounded `DHCPv4` server-selection assessment in an in-memory lab
//!
//! The transcript and state snapshots are synthetic model observations, not
//! DHCP wire packets, physical-interface evidence, or proof about a real guard

mod error;
mod evaluation;
mod execution;
mod state;
mod types;

pub use error::Error;
pub use execution::Scenario;
pub use types::{
    Config, ExchangeSnapshot, Fault, IngressPolicy, Lease, Message, MessageKind, Options, Outcome,
    Run, Server, StateSnapshot,
};
