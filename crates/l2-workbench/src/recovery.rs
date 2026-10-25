//! Bounded recovery coordination over already retained evidence

mod case_refs;
mod evidence_quota;
mod frontier;
mod model;
mod resources;

pub mod proposals;

pub use evidence_quota::classify_case_evidence_quota;
pub use frontier::{RecoveryCoordinator, RecoveryError};
pub use model::{
    ContextRegistration, EnqueueOutcome, RecoveryCandidate, RecoveryCandidateId,
    RecoveryCandidateState, RecoveryInput, RecoveryResource, RecoveryResult,
    RecoveryResultEvidenceContract, RecoveryStage, RecoveryTask,
    TransformProposalAssociationOutcome,
};
pub use resources::{BudgetCheck, RecoveryResourcePolicy};
