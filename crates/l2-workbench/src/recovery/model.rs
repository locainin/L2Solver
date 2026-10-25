use crate::derivation::{Operation, Recipe};
use crate::evidence::EvidenceStatus;
use crate::protocol::{FramingKind, RecordSchema};
use serde::Serialize;
use std::collections::HashSet;

/// Stable handle for one unique candidate task
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RecoveryCandidateId(pub(super) usize);

impl RecoveryCandidateId {
    /// Return the coordinator-local index used for this candidate
    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }
}

/// Typed unit of recovery work attached to a retained evidence blob
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "task", content = "operation", rename_all = "snake_case")]
pub enum RecoveryTask {
    /// Apply one complete canonical recipe with its ordered operations and checks
    Transform(Recipe),
    /// Propose canonical encodings or compressed formats from complete syntax and headers
    TransformDiscovery,
    /// Search a retained byte span for plausible frame boundaries
    FramingDiscovery,
    /// Materialize one explicit framing rule over retained messages
    MaterializeFraming(FramingKind),
    /// Search a retained byte span for plausible record layouts
    RecordDiscovery,
    /// Assemble records with one explicit normalized schema
    AssembleRecords(RecordSchema),
    /// Discover nested or embedded content inside retained bytes
    EmbeddedDiscovery,
    /// Check a candidate against explicit structural constraints
    StructuralValidation,
    /// Queue a retained derived blob for another caller-selected recovery pass
    RecursiveExpansion,
}

impl RecoveryTask {
    /// Create a one-step recipe task from an existing canonical operation
    #[must_use]
    pub fn transform(operation: Operation) -> Self {
        Self::Transform(Recipe {
            steps: vec![operation],
            constraints: Vec::new(),
        })
    }

    pub(super) const fn stage(&self) -> RecoveryStage {
        match self {
            Self::Transform(_) => RecoveryStage::Transform,
            Self::TransformDiscovery => RecoveryStage::TransformDiscovery,
            Self::FramingDiscovery => RecoveryStage::FramingDiscovery,
            Self::MaterializeFraming(_) => RecoveryStage::MaterializeFraming,
            Self::RecordDiscovery => RecoveryStage::RecordDiscovery,
            Self::AssembleRecords(_) => RecoveryStage::AssembleRecords,
            Self::EmbeddedDiscovery => RecoveryStage::EmbeddedDiscovery,
            Self::StructuralValidation => RecoveryStage::StructuralValidation,
            Self::RecursiveExpansion => RecoveryStage::RecursiveExpansion,
        }
    }
}

/// Task category currently reached by one candidate
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryStage {
    /// Canonical byte transformation task
    Transform,
    /// Syntax-gated canonical transform proposal task
    TransformDiscovery,
    /// Framing discovery task
    FramingDiscovery,
    /// Explicit framing materialization task
    MaterializeFraming,
    /// Record-layout discovery task
    RecordDiscovery,
    /// Explicit record assembly task
    AssembleRecords,
    /// Embedded-content discovery task
    EmbeddedDiscovery,
    /// Structural validation task
    StructuralValidation,
    /// Recursive expansion task
    RecursiveExpansion,
}

/// One ordered input position and all Case nodes supplying its blob
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryInput {
    pub(super) blob_id: String,
    pub(super) origin_node_ids: Vec<u64>,
    pub(super) origin_node_id_set: HashSet<u64>,
}

impl RecoveryInput {
    /// Return the retained canonical blob identifier for this position
    #[must_use]
    pub fn blob_id(&self) -> &str {
        &self.blob_id
    }

    /// Return all Case node identifiers supplying this exact position
    #[must_use]
    pub fn origin_node_ids(&self) -> &[u64] {
        &self.origin_node_ids
    }
}

/// Resource dimension enforced by the recovery coordinator
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryResource {
    /// Total distinct candidate tasks
    CandidateCount,
    /// Pending FIFO entries
    FrontierCount,
    /// Number of positions in one candidate input batch
    InputCount,
    /// Distinct evidence origins retained for one candidate
    OriginCount,
    /// Bytes in one retained input position
    InputBytesPerItem,
    /// Total bytes across one candidate input batch
    TotalInputBytes,
    /// Bytes retained from one candidate output
    OutputBytes,
    /// Cumulative bytes charged across all candidate work
    WorkBytes,
    /// Unique transform-proposal report-node and recipe associations
    TransformProposalAssociations,
    /// Serialized task-identity bytes retained across candidates
    CandidateTaskIdentityBytes,
    /// Canonical recipe-identity bytes retained for transform proposals
    TransformProposalIdentityBytes,
    /// Evidence relationships retained in the Case graph
    EvidenceEdges,
    /// Evidence nodes retained in the Case graph
    EvidenceNodes,
    /// Distinct blobs retained in the Case graph
    EvidenceBlobs,
    /// Aggregate bytes retained across Case blobs
    EvidenceBlobBytes,
    /// Aggregate serialized details bytes retained across Case nodes
    EvidenceTotalDetailsBytes,
    /// Aggregate source ranges retained across Case nodes
    EvidenceSourceRanges,
    /// Case-level limitation statements retained
    EvidenceLimitations,
    /// Distinct derivation parent links retained across all candidates
    ParentLinks,
    /// Input-position and origin-node context references retained across candidates
    ContextAliases,
    /// Pending direct result links retained for late candidate origins
    PendingOriginLinks,
    /// Candidate visits and parent-edge examinations during cycle analysis
    LineageWork,
    /// Maximum allowed expansion depth
    RecursionDepth,
}

/// Terminal interpretation or execution outcome for a candidate
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryResult {
    /// A candidate matched a retained direct validation observation
    ObservedValidation { node_id: u64 },
    /// A retained derivation receipt backed by bytes and linked to candidate origins
    Derived { evidence_node_id: u64 },
    /// A candidate remains a possible explanation without direct validation
    Hypothesis { node_id: u64 },
    /// Parser or explicit constraint evidence rejected the candidate
    Rejected { node_id: u64 },
    /// The selected executor does not support this candidate task
    Unsupported,
    /// Work was intentionally left out of this recovery run
    Omitted,
    /// A caller-selected resource budget prevented additional work
    ResourceExhausted {
        resource: RecoveryResource,
        limit: usize,
        used: usize,
        requested: usize,
    },
}

/// Evidence link required to record a recovery result
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryResultEvidenceContract {
    /// Result node linked to each candidate input origin
    pub node_id: u64,
    /// Evidence relation connecting the result node to each origin
    pub relation: &'static str,
    /// Evidence status required on each result link
    pub status: EvidenceStatus,
    /// Whether the result node must retain a blob
    pub requires_blob: bool,
}

impl RecoveryResult {
    /// Return the required evidence link for results that produce one
    #[must_use]
    pub const fn evidence_link_contract(&self) -> Option<RecoveryResultEvidenceContract> {
        match self {
            Self::ObservedValidation { node_id } => Some(RecoveryResultEvidenceContract {
                node_id: *node_id,
                relation: "recovery_result",
                status: EvidenceStatus::ConstraintSatisfied,
                requires_blob: false,
            }),
            Self::Derived { evidence_node_id } => Some(RecoveryResultEvidenceContract {
                node_id: *evidence_node_id,
                relation: "derived_from",
                status: EvidenceStatus::Observed,
                requires_blob: true,
            }),
            Self::Hypothesis { node_id } => Some(RecoveryResultEvidenceContract {
                node_id: *node_id,
                relation: "recovery_result",
                status: EvidenceStatus::Hypothesis,
                requires_blob: false,
            }),
            Self::Rejected { node_id } => Some(RecoveryResultEvidenceContract {
                node_id: *node_id,
                relation: "recovery_result",
                status: EvidenceStatus::ConstraintFailed,
                requires_blob: false,
            }),
            Self::Unsupported | Self::Omitted | Self::ResourceExhausted { .. } => None,
        }
    }
}

/// Current queue, execution, or terminal state for one candidate
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryCandidateState {
    /// Waiting in the deterministic FIFO frontier
    Queued,
    /// Being handled by the task category
    Running(RecoveryStage),
    /// Finished by the task category with an explicit result
    Finished {
        stage: RecoveryStage,
        result: RecoveryResult,
    },
    /// Finished work still needs direct evidence links for new origins
    ContextPending {
        stage: RecoveryStage,
        result: RecoveryResult,
    },
}

/// One content, task, and depth identity with all evidence origins retained
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryCandidate {
    pub(super) inputs: Vec<RecoveryInput>,
    pub(super) task: RecoveryTask,
    pub(super) depth: usize,
    pub(super) parent_ids: Vec<RecoveryCandidateId>,
    pub(super) parent_id_set: HashSet<RecoveryCandidateId>,
    pub(super) origin_node_ids: HashSet<u64>,
    pub(super) pending_origin_node_ids: Vec<u64>,
    pub(super) state: RecoveryCandidateState,
}

impl RecoveryCandidate {
    /// Return inputs in their exact candidate order, including repeated blobs
    #[must_use]
    pub fn inputs(&self) -> &[RecoveryInput] {
        &self.inputs
    }

    /// Return distinct derivation parents in first-seen enqueue order
    #[must_use]
    pub fn parent_ids(&self) -> &[RecoveryCandidateId] {
        &self.parent_ids
    }

    /// Return the exact canonical task assigned to this candidate
    #[must_use]
    pub const fn task(&self) -> &RecoveryTask {
        &self.task
    }

    /// Return the expansion depth assigned to this candidate
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.depth
    }

    /// Return origins awaiting direct evidence links for a terminal result
    #[must_use]
    pub fn pending_origin_node_ids(&self) -> &[u64] {
        &self.pending_origin_node_ids
    }

    /// Return the current queue or terminal state
    #[must_use]
    pub const fn state(&self) -> &RecoveryCandidateState {
        &self.state
    }
}

/// Result of adding work to the candidate frontier
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnqueueOutcome {
    /// A new unique candidate was appended to the FIFO frontier
    Queued(RecoveryCandidateId),
    /// Existing work was reused and the additional origin was retained
    Merged(RecoveryCandidateId),
    /// Existing terminal work gained origins that still need explicit result links
    MergedNeedsContext(RecoveryCandidateId),
    /// Existing ancestor work is a fixed point and gained the skipped input context
    CycleSkipped { candidate_id: RecoveryCandidateId },
    /// The selected input, context, or coordinator budget prevented work
    ResourceExhausted {
        resource: RecoveryResource,
        limit: usize,
        used: usize,
        requested: usize,
    },
}

/// Result of metering one report-node and canonical-recipe association
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransformProposalAssociationOutcome {
    /// The unique association was retained and charged
    Admitted,
    /// The same report node already retained this canonical recipe
    AlreadyRetained,
    /// The selected global association budget prevented retention
    ResourceExhausted {
        resource: RecoveryResource,
        limit: usize,
        used: usize,
        requested: usize,
    },
}

/// State after checking direct result links for late origins
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextRegistration {
    /// Every merged origin has a direct link to the retained result evidence
    Complete,
    /// Some merged origins still need result evidence links
    Pending { origins: usize },
    /// The refreshed pending link set exceeds the caller's global budget
    ResourceExhausted {
        resource: RecoveryResource,
        limit: usize,
        used: usize,
        requested: usize,
    },
}
