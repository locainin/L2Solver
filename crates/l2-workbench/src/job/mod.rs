//! Shared progress and cancellation state for one recovery job

pub mod cache;

mod model;

pub use model::{
    Counter, Job, JobError, JobSnapshot, Phase, PhaseOutcome, PhaseSnapshot, PhaseState,
};
