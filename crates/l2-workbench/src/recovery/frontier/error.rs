//! Describe typed recovery admission, execution, and resource failures

use super::super::RecoveryCandidateId;
use std::{error::Error, fmt};

/// Error returned for invalid candidate references or unsupported result evidence
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryError {
    /// The requested evidence node is not present in the supplied Case
    UnknownEvidenceNode { node_id: u64 },
    /// The node has no retained byte blob
    InputBlobMissing { node_id: u64 },
    /// No source nodes were supplied for the candidate
    EmptyInputBatch,
    /// A coordinator handle does not identify a retained candidate
    UnknownCandidate { id: RecoveryCandidateId },
    /// A single-input convenience method received a multi-input candidate
    MultipleInputs {
        id: RecoveryCandidateId,
        input_count: usize,
    },
    /// The candidate is not currently running
    CandidateNotRunning { id: RecoveryCandidateId },
    /// A terminal result cannot be reported for this task category
    InvalidResultStage,
    /// Result evidence has no direct supporting Case edge to one candidate origin
    UnlinkedResultEvidence {
        candidate_id: RecoveryCandidateId,
        evidence_node_id: u64,
        origin_node_id: u64,
    },
    /// A child lacks a directed observed `derived_from` edge to its parent receipt
    UnlinkedDerivedInput {
        parent_candidate_id: RecoveryCandidateId,
        child_node_id: u64,
    },
    /// Exact bytes lack an observed `validated_range` edge to the validation receipt
    UnlinkedValidatedInput {
        parent_candidate_id: RecoveryCandidateId,
        child_node_id: u64,
    },
    /// The parent has no complete retained `Derived` result for expansion
    ParentNotDerived { id: RecoveryCandidateId },
    /// The parent has no complete retained structural validation result
    ParentNotValidated { id: RecoveryCandidateId },
    /// Parents in one derived batch do not have the same recursion depth
    ParentDepthMismatch { first: usize, second: usize },
    /// A bounded recovery batch allocation could not be reserved
    AllocationFailed,
    /// The candidate has no pending late origin context
    ContextNotPending { id: RecoveryCandidateId },
    /// Case references or coordinator state violate an internal invariant
    InvariantFailure,
    /// A task could not be encoded for exact duplicate indexing
    IdentityEncoding,
    /// A transform task exceeded the canonical derivation identity limits
    InvalidTaskIdentity(crate::derivation::DerivationError),
    /// One coordinator cannot be reused across distinct evidence cases
    DifferentCase,
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownEvidenceNode { node_id } => {
                write!(formatter, "recovery evidence node {node_id} does not exist")
            }
            Self::InputBlobMissing { node_id } => {
                write!(
                    formatter,
                    "recovery input node {node_id} has no retained blob"
                )
            }
            Self::EmptyInputBatch => formatter.write_str("recovery input batch cannot be empty"),
            Self::UnknownCandidate { id } => {
                write!(
                    formatter,
                    "recovery candidate {} does not exist",
                    id.index()
                )
            }
            Self::MultipleInputs { id, input_count } => write!(
                formatter,
                "recovery candidate {} has {input_count} inputs",
                id.index()
            ),
            Self::CandidateNotRunning { id } => {
                write!(
                    formatter,
                    "recovery candidate {} is not running",
                    id.index()
                )
            }
            Self::InvalidResultStage => {
                formatter.write_str("recovery result does not match the current task stage")
            }
            Self::UnlinkedResultEvidence {
                candidate_id,
                evidence_node_id,
                origin_node_id,
            } => write!(
                formatter,
                "result evidence node {evidence_node_id} is not linked to candidate {} origin {origin_node_id}",
                candidate_id.index()
            ),
            Self::UnlinkedDerivedInput {
                parent_candidate_id,
                child_node_id,
            } => format_unlinked_child(formatter, "derived", *child_node_id, *parent_candidate_id),
            Self::UnlinkedValidatedInput {
                parent_candidate_id,
                child_node_id,
            } => {
                format_unlinked_child(formatter, "validated", *child_node_id, *parent_candidate_id)
            }
            Self::ParentNotDerived { id } => format_ineligible_parent(formatter, *id, "derived"),
            Self::ParentNotValidated { id } => {
                format_ineligible_parent(formatter, *id, "structural validation")
            }
            Self::ParentDepthMismatch { first, second } => write!(
                formatter,
                "derived batch parents have different depths ({first} and {second})"
            ),
            Self::AllocationFailed => formatter.write_str("recovery batch allocation failed"),
            Self::ContextNotPending { id } => write!(
                formatter,
                "recovery candidate {} has no pending context",
                id.index()
            ),
            Self::InvariantFailure => formatter.write_str("recovery invariant failed"),
            Self::IdentityEncoding => {
                formatter.write_str("recovery task identity could not be encoded")
            }
            Self::InvalidTaskIdentity(error) => {
                write!(
                    formatter,
                    "recovery transform task identity is invalid: {error}"
                )
            }
            Self::DifferentCase => {
                formatter.write_str("recovery coordinator is bound to a different evidence case")
            }
        }
    }
}

fn format_unlinked_child(
    formatter: &mut fmt::Formatter<'_>,
    evidence: &str,
    child_node_id: u64,
    parent_candidate_id: RecoveryCandidateId,
) -> fmt::Result {
    write!(
        formatter,
        "{evidence} byte node {child_node_id} is not linked to its receipt for candidate {}",
        parent_candidate_id.index()
    )
}

fn format_ineligible_parent(
    formatter: &mut fmt::Formatter<'_>,
    id: RecoveryCandidateId,
    result: &str,
) -> fmt::Result {
    write!(
        formatter,
        "recovery candidate {} has no eligible {result} result",
        id.index()
    )
}

impl Error for RecoveryError {}
