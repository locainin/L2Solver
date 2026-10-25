//! Bounded, explicit byte mutations for offline protocol-shape experiments
//!
//! Every parser result remains a candidate observation; this module never
//! executes recovered bytes or contacts a non-loopback target

mod engine;
mod loopback;
mod mutation;
mod plan;
mod report;

pub use engine::run;
pub use plan::{Mutation, MutationPlan};
pub use report::{
    CandidateSummary, ExperimentMode, ExperimentOutcome, ExperimentReport, ExperimentStatus,
    ExperimentStep, MutationFailure, ParserSummary, TransportReceipt,
};

use std::{error::Error, fmt, io};

pub const MAX_INPUT_BYTES: usize = 64 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 65 * 1024;
pub const MAX_MUTATIONS: usize = 64;
pub const MAX_PLAN_BYTES: usize = 1024 * 1024;
pub const MAX_TOTAL_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug)]
pub enum ExperimentError {
    InputTooLarge { length: usize, maximum: usize },
    TooManyMutations { count: usize, maximum: usize },
    PlanTooLarge { length: usize, maximum: usize },
    Loopback(io::Error),
}

impl fmt::Display for ExperimentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { length, maximum } => {
                write!(
                    formatter,
                    "experiment input has {length} bytes; maximum is {maximum}"
                )
            }
            Self::TooManyMutations { count, maximum } => {
                write!(
                    formatter,
                    "experiment plan has {count} mutations; maximum is {maximum}"
                )
            }
            Self::PlanTooLarge { length, maximum } => {
                write!(
                    formatter,
                    "experiment plan has {length} bytes; maximum is {maximum}"
                )
            }
            Self::Loopback(error) => write!(formatter, "loopback transfer failed: {error}"),
        }
    }
}

impl Error for ExperimentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Loopback(error) => Some(error),
            Self::InputTooLarge { .. }
            | Self::TooManyMutations { .. }
            | Self::PlanTooLarge { .. } => None,
        }
    }
}
