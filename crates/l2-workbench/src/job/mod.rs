//! Shared progress and cancellation state for one recovery job

pub mod cache;

mod cache_fallback;
mod model;
mod recovery_transition;

pub use cache_fallback::{
    CacheFallbackKind, CacheFallbackRecord, CacheFallbackSummary, CacheStage,
};
pub use model::{
    Counter, Job, JobError, JobSnapshot, Phase, PhaseOutcome, PhaseSnapshot, PhaseState,
};

pub use recovery_transition::{
    RecoveryTransition, RecoveryTransitionOutcome, RecoveryTransitionRecord,
    RecoveryTransitionSample, RecoveryTransitionSourceRange, RecoveryTransitionStage,
    RecoveryTransitionSummary,
};
