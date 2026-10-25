//! Bounded decoding hypotheses with explicit checks and reproducible derivations

mod engine;
mod keys;
mod model;
mod operations;
mod validate;
pub mod workflow;

pub use engine::{search, search_with_limits, validate_search_plan};
pub use model::{
    Candidate, CandidateStatus, Family, KeyTest, KeyTestStatus, SearchError, SearchLimit,
    SearchLimits, SearchPlan, SearchReport,
};

pub const MAX_INPUT_BYTES: usize = 65_536;
pub const MAX_WORK_BYTES: usize = 16 * 1024 * 1024;
