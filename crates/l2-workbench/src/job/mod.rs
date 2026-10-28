//! Shared progress and cancellation state for one recovery job

pub mod cache;

mod cache_fallback;
mod memory;
mod model;
mod recovery_transition;

pub use cache_fallback::{
    CacheFallbackKind, CacheFallbackRecord, CacheFallbackSummary, CacheStage,
};
pub use memory::{
    BufferedCase, BufferedCaseSnapshot, MemoryBudget, MemoryClass, MemoryError, MemoryLease,
    MemorySnapshot,
};
pub use model::{
    Counter, Job, JobError, JobSnapshot, Phase, PhaseOutcome, PhaseSnapshot, PhaseState,
    WorkSnapshot,
};

pub use recovery_transition::{
    RecoveryArtifactSample, RecoveryCandidateSample, RecoveryCohortReason, RecoveryCohortSample,
    RecoveryPublicationSample, RecoveryPublicationSourceBasis, RecoveryTransition,
    RecoveryTransitionOutcome, RecoveryTransitionRecord, RecoveryTransitionSample,
    RecoveryTransitionSourceRange, RecoveryTransitionStage, RecoveryTransitionSummary,
};
