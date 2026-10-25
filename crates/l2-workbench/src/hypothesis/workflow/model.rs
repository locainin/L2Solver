use super::super::{SearchError, SearchLimits, SearchPlan, SearchReport};
use crate::{
    derivation::{ConstraintReport, DerivationError, DerivationStatus, Recipe, StepReport},
    protocol::{
        FramingKind, HoldoutBasis, MessageContext, MessageRecord, MessageRole, StreamTransition,
    },
    reconstruction::{InputSelection, Limits as ReconstructionLimits},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, error::Error, fmt};

/// Candidate framing rules and decoder recipes evaluated over reconstructed TCP sessions
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowPlan {
    /// Competing caller-selected framing interpretations
    pub framing_candidates: Vec<FramingKind>,
    /// Existing bounded transformation search and explicit structural constraints
    pub search_plan: SearchPlan,
    /// Runtime budgets retained in the final report
    #[serde(default)]
    pub limits: WorkflowLimits,
}

/// Configured retention and execution budgets for one complete workflow
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowLimits {
    /// Packet, session, and stream-reconstruction budgets used before this workflow
    pub reconstruction: ReconstructionLimits,
    /// Candidate framing and source-report budgets
    pub protocol: crate::protocol::ProtocolLimits,
    /// Canonical transform and aggregate search budgets
    pub search: SearchLimits,
    /// Aggregate candidate, key-test, recipe-assessment, and held-out-check rows retained
    #[serde(default = "default_max_result_rows")]
    pub max_result_rows: usize,
}

impl Default for WorkflowLimits {
    fn default() -> Self {
        Self {
            reconstruction: ReconstructionLimits::default(),
            protocol: crate::protocol::ProtocolLimits::default(),
            search: SearchLimits::default(),
            max_result_rows: default_max_result_rows(),
        }
    }
}

const fn default_max_result_rows() -> usize {
    65_536
}

/// Candidate search result for one source-mapped message
#[derive(Debug, Serialize)]
pub struct FrameSearch {
    /// Index into `WorkflowReport::frames`
    pub frame_index: usize,
    /// Complete rejected and accepted alternatives when the input fit the configured budget
    pub outcome: FrameSearchOutcome,
}

/// Search was run or explicitly omitted under an input or aggregate work budget
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum FrameSearchOutcome {
    /// Canonical decoding search with every candidate result retained
    Completed { report: Box<SearchReport> },
    /// Message bytes exceeded the configured search input budget
    InputTooLarge { length: usize, maximum: usize },
    /// Earlier frames consumed the workflow's remaining transformation budget
    WorkBudgetExceeded { length: usize, remaining: usize },
    /// Earlier result rows exhausted the workflow's retained-output budget
    ResultBudgetExceeded { length: usize, remaining: usize },
}

/// How a candidate recipe compared with distinct held-out session observations
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipeAssessmentStatus {
    /// Every tested held-out observation satisfied the explicit recipe constraints
    ConstraintsSatisfiedOnHeldoutObservations,
    /// A held-out observation contradicted a required operation or explicit constraint
    ContradictedByHeldoutObservation,
    /// No eligible whole session was available for held-out observations
    NoEligibleHeldoutSessions,
    /// Held-out sessions existed, but none produced this candidate framing
    NoMatchingFramedObservation,
    /// Input or aggregate work budgets prevented a held-out check
    UnresolvedOnBudget,
}

/// Exact result of running one discovered recipe on a whole held-out message
#[derive(Debug, Serialize)]
pub struct HeldoutCheck {
    /// Index into `WorkflowReport::frames`
    pub frame_index: usize,
    /// Exact message context and candidate interpretation
    pub context: MessageContext,
    pub framing: FramingKind,
    /// Hashes bind the check to the observed input and canonical output
    pub input_sha256: String,
    pub output_sha256: Option<String>,
    pub output_length: Option<usize>,
    pub derivation_status: Option<DerivationStatus>,
    /// Canonical step and constraint receipts, without output bytes
    pub steps: Vec<StepReport>,
    pub constraints: Vec<ConstraintReport>,
    pub constraints_satisfied: bool,
    /// Canonical transformation work charged to the shared workflow budget
    pub work_bytes: usize,
    pub status: HeldoutCheckStatus,
    /// Application role remains unknown unless external evidence supplies one
    pub role: Option<MessageRole>,
    /// Assumption needed for this candidate assessment
    pub assumption: String,
}

/// Holdout check outcome for one exact candidate frame
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HeldoutCheckStatus {
    ConstraintsSatisfied,
    ConstraintFailed,
    OperationFailed,
    InputTooLarge,
    WorkBudgetExceeded,
    ResourceBudgetExceeded,
}

/// One distinct recipe and framing interpretation with discovery and held-out evidence
#[derive(Debug, Serialize)]
pub struct RecipeAssessment {
    /// SHA-256 of the serialized canonical recipe
    pub recipe_sha256: String,
    pub recipe: Recipe,
    pub framing: FramingKind,
    /// Distinct underlying message evidence; equivalent framing aliases are collapsed
    pub discovery_evidence: Vec<usize>,
    pub heldout_checks: Vec<HeldoutCheck>,
    /// Distinct held-out frames omitted after the aggregate row budget was exhausted
    pub omitted_heldout_checks: usize,
    pub status: RecipeAssessmentStatus,
    pub assumption: String,
}

/// Compact reconstruction facts linked to a directional extraction report
#[derive(Debug, Serialize)]
pub struct StreamReceipt {
    pub context: MessageContext,
    pub generation_ambiguous: bool,
    pub sequence_ambiguous: bool,
    pub input_bytes: usize,
    pub omitted_candidates: usize,
    pub partial: bool,
}

/// Source-mapped candidate frames, alternatives, and held-out session observations
#[derive(Debug, Serialize)]
pub struct WorkflowReport {
    pub schema_version: u32,
    pub source_id: String,
    pub reconstruction: ReconstructionReceipt,
    pub limits: WorkflowLimits,
    pub holdout_basis: Option<HoldoutBasis>,
    /// Whole session identifiers assigned to each side of the evidence split
    pub discovery_sessions: Vec<u32>,
    pub heldout_sessions: Vec<u32>,
    /// Source-mapped candidate frames from every selected session and direction
    pub frames: Vec<MessageRecord>,
    pub streams: Vec<StreamReceipt>,
    pub transitions: Vec<StreamTransition>,
    /// All per-frame decoder reports, including failed candidates and input omissions
    pub searches: Vec<FrameSearch>,
    /// Every caller-supplied framing rule, including rules that produced no frames
    pub framing_candidates: Vec<FramingKind>,
    /// Original caller plan; individual search reports may show a smaller effective candidate limit
    pub search_plan: SearchPlan,
    /// Hash of the effective workflow plan, including framing rules and runtime budgets
    pub effective_plan_sha256: String,
    /// Aggregate canonical transformation work across search and held-out checks
    pub work_bytes: usize,
    /// Number of candidate, key-test, recipe-assessment, and held-out-check rows retained
    pub retained_result_rows: usize,
    /// Discovery frame searches skipped because the aggregate row budget was exhausted
    pub omitted_searches: usize,
    /// Recipe assessments omitted because the aggregate row budget was exhausted
    pub omitted_recipe_assessments: usize,
    /// Held-out checks omitted because the aggregate row budget was exhausted
    pub omitted_heldout_checks: usize,
    /// Distinct recipe and framing alternatives with whole-session checks
    pub recipes: Vec<RecipeAssessment>,
    pub omitted_streams: usize,
    pub partial_streams: usize,
    pub partial: bool,
    pub assumptions: Vec<&'static str>,
}

/// Reconstruction completeness and source selection facts
#[derive(Debug, Serialize)]
pub struct ReconstructionReceipt {
    pub frames: u64,
    pub input_selection: Option<InputSelection>,
    pub complete: bool,
    pub omitted_frames: u64,
    pub unsupported_frames: u64,
    pub omitted_fragments: usize,
    pub omitted_tcp_records: usize,
    pub omitted_ranges: usize,
    pub omitted_state_observations: usize,
}

#[derive(Debug)]
pub enum WorkflowError {
    InvalidPlan(&'static str),
    Protocol(crate::protocol::ProtocolError),
    Search(SearchError),
    Derivation(DerivationError),
    Serialization(serde_json::Error),
}

impl fmt::Display for WorkflowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPlan(reason) => formatter.write_str(reason),
            Self::Protocol(error) => error.fmt(formatter),
            Self::Search(error) => error.fmt(formatter),
            Self::Derivation(error) => error.fmt(formatter),
            Self::Serialization(error) => error.fmt(formatter),
        }
    }
}

impl Error for WorkflowError {}

impl From<crate::protocol::ProtocolError> for WorkflowError {
    fn from(error: crate::protocol::ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<SearchError> for WorkflowError {
    fn from(error: SearchError) -> Self {
        Self::Search(error)
    }
}

impl From<DerivationError> for WorkflowError {
    fn from(error: DerivationError) -> Self {
        Self::Derivation(error)
    }
}

impl From<serde_json::Error> for WorkflowError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct EvidenceKey {
    context: MessageContext,
    stream_start: usize,
    stream_end: usize,
    sha256: String,
}

impl EvidenceKey {
    pub(super) fn from_message(message: &MessageRecord) -> Self {
        Self {
            context: message.context.clone(),
            stream_start: message.stream_range.start,
            stream_end: message.stream_range.end,
            sha256: message.sha256.clone(),
        }
    }
}

pub(super) struct AssessmentBuilder {
    pub(super) recipe_sha256: String,
    pub(super) recipe: Recipe,
    pub(super) framing: FramingKind,
    pub(super) discovery_evidence: Vec<usize>,
    pub(super) evidence_keys: BTreeSet<EvidenceKey>,
}

pub(super) struct WorkflowBudget {
    pub(super) remaining_work_bytes: usize,
    pub(super) work_bytes: usize,
    pub(super) remaining_result_rows: usize,
    pub(super) retained_result_rows: usize,
}

impl WorkflowBudget {
    pub(super) const fn new(limits: WorkflowLimits) -> Self {
        Self {
            remaining_work_bytes: limits.search.max_work_bytes,
            work_bytes: 0,
            remaining_result_rows: limits.max_result_rows,
            retained_result_rows: 0,
        }
    }

    pub(super) fn charge_work(&mut self, charge: usize) -> Result<(), WorkflowError> {
        let total = self
            .work_bytes
            .checked_add(charge)
            .ok_or(WorkflowError::InvalidPlan(
                "workflow work accounting overflowed",
            ))?;
        let remaining =
            self.remaining_work_bytes
                .checked_sub(charge)
                .ok_or(WorkflowError::InvalidPlan(
                    "workflow exceeded its aggregate work budget",
                ))?;
        self.work_bytes = total;
        self.remaining_work_bytes = remaining;
        Ok(())
    }

    pub(super) fn retain_rows(&mut self, count: usize) -> Result<(), WorkflowError> {
        let remaining =
            self.remaining_result_rows
                .checked_sub(count)
                .ok_or(WorkflowError::InvalidPlan(
                    "workflow exceeded its aggregate result-row budget",
                ))?;
        let retained =
            self.retained_result_rows
                .checked_add(count)
                .ok_or(WorkflowError::InvalidPlan(
                    "workflow result-row count overflowed",
                ))?;
        self.remaining_result_rows = remaining;
        self.retained_result_rows = retained;
        Ok(())
    }

    pub(super) fn retain_row(&mut self) -> Result<(), WorkflowError> {
        self.retain_rows(1)
    }
}
