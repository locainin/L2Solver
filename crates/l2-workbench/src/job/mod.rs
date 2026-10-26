//! Shared progress and cancellation state for one recovery job

pub mod cache;

mod cache_fallback;
mod model;

pub use cache_fallback::{
    CacheFallbackKind, CacheFallbackRecord, CacheFallbackSummary, CacheStage,
};
pub use model::{
    Counter, Job, JobError, JobSnapshot, Phase, PhaseOutcome, PhaseSnapshot, PhaseState,
};
