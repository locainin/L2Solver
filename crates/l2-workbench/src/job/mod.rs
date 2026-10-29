//! Shared progress and cancellation state for one recovery job

pub mod cache;

mod cache_fallback;
mod json_memory;
mod memory;
mod model;
mod recovery_transition;

pub use cache_fallback::{
    CacheFallbackKind, CacheFallbackRecord, CacheFallbackSummary, CacheStage,
};
pub use json_memory::{JsonMemoryAdmission, JsonMemoryError, admit_json};
pub use memory::{
    BufferedCase, BufferedCaseSnapshot, CgroupMemoryEvents, CgroupMemorySnapshot, MemoryBudget,
    MemoryClass, MemoryError, MemoryLease, MemorySnapshot, MemoryWorkingSet, SystemMemorySnapshot,
    WorkingSetSnapshot,
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
