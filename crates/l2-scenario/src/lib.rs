//! Bounded deterministic execution for controlled Layer-2 laboratory scenarios
//!
//! This crate schedules modeled stimuli and reports execution accounting only
//! Protocol verdicts belong to independent observation evaluators

mod error;
mod runner;
mod schedule;
mod stimulus;

pub use error::{AdmissionError, RunError};
pub use runner::{Cleanup, Control, RunReport, Runner, StopReason};
pub use schedule::{MAX_STIMULI, Schedule};
pub use stimulus::{Dispatch, Stimulus};
