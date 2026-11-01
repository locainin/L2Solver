//! Bounded cohort progress based only on observed candidate transitions

use super::{
    RecoveryCandidateSample, RecoveryPublicationSample, RecoveryTransitionOutcome,
    RecoveryTransitionStage, digest,
};
use crate::job::MemoryLease;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer, de,
    ser::{SerializeSeq, SerializeStruct},
};
use std::{fmt, marker::PhantomData, sync::Arc};

pub(in crate::job) const MAX_COHORTS: usize = 64;
const MAX_SESSIONS: usize = 128;
/// Largest set of input nodes retained for one cohort
pub const MAX_RECOVERY_FUNNEL_INPUTS: usize = 1024;
const MAX_HYPOTHESES: usize = 512;

pub(in crate::job) const fn cohort_capacity_charge() -> usize {
    // Reserve full bounded vector capacity plus equal allocator and transient headroom
    2 * (std::mem::size_of::<Cohort>()
        + MAX_SESSIONS * std::mem::size_of::<u64>()
        + MAX_RECOVERY_FUNNEL_INPUTS * std::mem::size_of::<RecoveryFunnelInput>()
        + MAX_HYPOTHESES * std::mem::size_of::<Hypothesis>()
        + RecoveryTransitionStage::ALL.len()
            * (std::mem::size_of::<StageView>() + 4 * std::mem::size_of::<NoSurvivorReason>()))
}

/// Source and grouping identity for one observed recovery cohort
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RecoveryFunnelIdentity {
    /// Digest of the capture or other source
    pub source_sha256: [u8; 32],
    /// Digest of the source, scope, endpoints, and direction
    pub cohort_sha256: [u8; 32],
}

/// A source-backed input and its Case-local session identity
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryFunnelInput {
    /// Input node in the Case
    pub node_id: u64,
    /// Session or episode node in the same Case
    pub session_node_id: u64,
}

/// Scheduler outcome for one eligible source cohort
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryFunnelAdmission<'a> {
    /// A discovery candidate was queued or reused
    Admitted(&'a RecoveryCandidateSample),
    /// A coordinator resource limit prevented the candidate
    ResourceExhausted,
    /// A previously visited ancestor made this candidate a fixed point
    CycleSkipped,
    /// The caller observed the inputs without a scheduler outcome
    Unknown,
}

/// Bounded input associations for an eligible source cohort
#[derive(Clone, Copy, Debug)]
pub struct RecoveryFunnelRegistration<'a> {
    /// Exact source and cohort identity
    pub identity: RecoveryFunnelIdentity,
    /// Input associations retained for later candidate attribution
    pub inputs: &'a [RecoveryFunnelInput],
    /// Number of inputs before any caller-side association cap
    pub total_inputs: usize,
    /// Scheduler result, kept separate from source eligibility
    pub admission: RecoveryFunnelAdmission<'a>,
}

/// One observed outcome and the evidence links used to attribute it
#[derive(Clone, Copy, Debug)]
pub struct RecoveryFunnelEvent<'a> {
    /// Stage where the candidate ran
    pub stage: RecoveryTransitionStage,
    /// Outcome observed for this candidate
    pub outcome: RecoveryTransitionOutcome,
    /// Candidate identity and its retained evidence reference
    pub candidate: &'a RecoveryCandidateSample,
    /// Candidate input nodes available for direct cohort attribution
    pub input_nodes: &'a [u64],
    /// Candidate parents available for attribution through derivation
    pub parent_candidates: &'a [u64],
    /// Whether the input and parent lists cover the candidate's complete associations
    pub attribution_complete: bool,
    /// Whether this outcome applies to the candidate or only to the listed inputs
    pub attribution: RecoveryFunnelAttribution,
    /// Digest of exact validated artifact bytes, when established by the validation receipt
    pub validated_artifact_sha256: Option<[u8; 32]>,
}

/// Evidence used to attribute an outcome to cohorts
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryFunnelAttribution {
    /// A candidate result applies to its input or parent cohorts
    CandidateAndParents,
    /// A contradiction applies only to the listed exact input nodes
    ExactInputs,
}

#[derive(Clone, Debug, Default)]
pub(super) struct Funnel {
    pub(super) cohorts: Vec<Cohort>,
    // Snapshot copies share immutable cohorts and the charge for their entire lifetime
    frozen: Option<Arc<FrozenCohorts>>,
    pub(super) omission_reasons: FunnelOmissionReasons,
}

#[derive(Debug)]
struct FrozenCohorts {
    cohorts: Vec<Cohort>,
    // Fields are dropped in declaration order, so data is released before its charge
    _memory: Option<MemoryLease>,
}

impl PartialEq for Funnel {
    fn eq(&self, other: &Self) -> bool {
        self.cohorts() == other.cohorts() && self.omission_reasons == other.omission_reasons
    }
}

impl Eq for Funnel {}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct FunnelOmissionReasons {
    cohort_limit: u64,
    memory_admission: u64,
    unattributed_candidate: u64,
    association_limit: u64,
    checkpoint_size: u64,
    unclassified: u64,
}

#[derive(Clone, Copy)]
pub(in crate::job) enum FunnelOmissionReason {
    CohortLimit,
    MemoryAdmission,
    UnattributedCandidate,
    AssociationLimit,
    CheckpointSize,
}

impl FunnelOmissionReasons {
    pub(super) const fn from_legacy(count: u64) -> Self {
        Self {
            unclassified: count,
            unattributed_candidate: 0,
            cohort_limit: 0,
            memory_admission: 0,
            association_limit: 0,
            checkpoint_size: 0,
        }
    }
    pub(super) const fn total(self) -> u64 {
        self.cohort_limit
            .saturating_add(self.memory_admission)
            .saturating_add(self.unattributed_candidate)
            .saturating_add(self.association_limit)
            .saturating_add(self.checkpoint_size)
            .saturating_add(self.unclassified)
    }

    const fn add(&mut self, reason: FunnelOmissionReason, amount: u64) {
        let count = match reason {
            FunnelOmissionReason::CohortLimit => &mut self.cohort_limit,
            FunnelOmissionReason::MemoryAdmission => &mut self.memory_admission,
            FunnelOmissionReason::UnattributedCandidate => &mut self.unattributed_candidate,
            FunnelOmissionReason::AssociationLimit => &mut self.association_limit,
            FunnelOmissionReason::CheckpointSize => &mut self.checkpoint_size,
        };
        *count = count.saturating_add(amount);
    }

    const fn merge(&mut self, other: Self) {
        self.cohort_limit = self.cohort_limit.saturating_add(other.cohort_limit);
        self.memory_admission = self.memory_admission.saturating_add(other.memory_admission);
        self.unattributed_candidate = self
            .unattributed_candidate
            .saturating_add(other.unattributed_candidate);
        self.association_limit = self
            .association_limit
            .saturating_add(other.association_limit);
        self.checkpoint_size = self.checkpoint_size.saturating_add(other.checkpoint_size);
        self.unclassified = self.unclassified.saturating_add(other.unclassified);
    }
}

#[derive(Serialize)]
struct StageTotals {
    stage: RecoveryTransitionStage,
    observed_cohorts: usize,
    cohorts_with_survivors: usize,
    cohorts_with_rejections: usize,
    cohorts_with_input_contradictions: usize,
    cohorts_with_omissions: usize,
    cohorts_with_unsupported: usize,
    candidate_cohort_pairs_with_survivors: usize,
    counts_are_lower_bounds: bool,
}

pub(super) struct FunnelView<'a> {
    funnel: &'a Funnel,
    publication_incomplete: bool,
}

impl Serialize for FunnelView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let funnel = self.funnel;
        let cohorts = funnel.cohorts();
        let omitted_events = funnel.omission_reasons.total();
        // Empty jobs retain their previous compact checkpoint size
        if cohorts.is_empty() && omitted_events == 0 {
            return serializer.serialize_struct("Funnel", 0)?.end();
        }
        if cohorts.is_empty() {
            let mut state = serializer.serialize_struct("Funnel", 2)?;
            state.serialize_field("funnel_omitted_events", &omitted_events)?;
            state.serialize_field("funnel_omission_reasons", &funnel.omission_reasons)?;
            return state.end();
        }
        let lower_bounds = omitted_events != 0
            || cohorts.iter().any(|cohort| {
                cohort.input_limit_reached
                    || cohort.hypothesis_limit_reached
                    || !cohort.admission_omissions.is_empty()
                    || cohort.checkpoint.is_some()
            });
        let mut totals = RecoveryTransitionStage::ALL
            .into_iter()
            .map(|stage| StageTotals {
                stage,
                observed_cohorts: 0,
                cohorts_with_survivors: 0,
                cohorts_with_rejections: 0,
                cohorts_with_input_contradictions: 0,
                cohorts_with_omissions: 0,
                cohorts_with_unsupported: 0,
                candidate_cohort_pairs_with_survivors: 0,
                counts_are_lower_bounds: lower_bounds
                    || (stage == RecoveryTransitionStage::Publication
                        && self.publication_incomplete),
            })
            .collect::<Vec<_>>();
        for cohort in cohorts {
            for (total, stage) in totals.iter_mut().zip(cohort.stages()) {
                total.observed_cohorts += usize::from(stage.observed_candidates > 0);
                total.cohorts_with_survivors += usize::from(stage.candidates_with_survivors > 0);
                total.cohorts_with_rejections += usize::from(stage.rejected_candidates > 0);
                total.cohorts_with_input_contradictions +=
                    usize::from(stage.input_contradictions > 0);
                total.cohorts_with_omissions += usize::from(stage.omitted_candidates > 0);
                total.cohorts_with_unsupported += usize::from(stage.unsupported_candidates > 0);
                total.candidate_cohort_pairs_with_survivors += stage.candidates_with_survivors;
            }
        }
        let mut state = serializer.serialize_struct("Funnel", 4)?;
        state.serialize_field("cohorts", cohorts)?;
        state.serialize_field("funnel_omitted_events", &omitted_events)?;
        state.serialize_field("funnel_omission_reasons", &funnel.omission_reasons)?;
        state.serialize_field("funnel_stages", &totals)?;
        state.end()
    }
}

pub(super) struct CheckpointFunnel<'a> {
    funnel: &'a Funnel,
    include_cohorts: bool,
}

impl Serialize for CheckpointFunnel<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let cohorts = self.funnel.cohorts();
        let mut reasons = self.funnel.omission_reasons;
        if !self.include_cohorts {
            reasons.add(
                FunnelOmissionReason::CheckpointSize,
                u64::try_from(cohorts.len()).unwrap_or(u64::MAX),
            );
        }
        let count = usize::from(self.include_cohorts && !cohorts.is_empty());
        let mut state = serializer.serialize_struct("Funnel", count + 2)?;
        if count > 0 {
            state.serialize_field("cohorts", &CheckpointCohorts(cohorts))?;
        }
        state.serialize_field("funnel_omitted_events", &reasons.total())?;
        state.serialize_field("funnel_omission_reasons", &reasons)?;
        state.end()
    }
}

struct CheckpointCohorts<'a>(&'a [Cohort]);

impl Serialize for CheckpointCohorts<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for cohort in self.0 {
            sequence.serialize_element(&CheckpointCohort(cohort))?;
        }
        sequence.end()
    }
}

struct CheckpointCohort<'a>(&'a Cohort);

impl Serialize for CheckpointCohort<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_cohort(self.0, serializer, true)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Cohort {
    identity: RecoveryFunnelIdentity,
    sessions: Vec<u64>,
    inputs: Vec<RecoveryFunnelInput>,
    hypotheses: Vec<Hypothesis>,
    input_limit_reached: bool,
    hypothesis_limit_reached: bool,
    admission_omissions: AdmissionOmissions,
    checkpoint: Option<CheckpointBaseline>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
struct AdmissionOmissions {
    resource_exhausted: bool,
    cycle_skipped: bool,
}

impl AdmissionOmissions {
    fn count(self) -> usize {
        usize::from(self.resource_exhausted) + usize::from(self.cycle_skipped)
    }

    const fn is_empty(self) -> bool {
        !self.resource_exhausted && !self.cycle_skipped
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CheckpointBaseline {
    stages: Vec<StageView>,
    omitted_input_links: u64,
    omitted_hypotheses: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct Hypothesis {
    stage: RecoveryTransitionStage,
    candidate_index: u64,
    #[serde(with = "digest")]
    input_batch_sha256: [u8; 32],
    #[serde(with = "digest")]
    task_sha256: [u8; 32],
    #[serde(with = "digest")]
    input_blob_sha256: [u8; 32],
    #[serde(default, with = "digest::optional")]
    validated_artifact_sha256: Option<[u8; 32]>,
    outcomes: u32,
    evidence_node_id: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum NoSurvivorReason {
    InsufficientTrainingMessages,
    NoStructuralCandidateSpace,
    NoSchemaSurvivedStrictParsing,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StageView {
    stage: RecoveryTransitionStage,
    observed_candidates: usize,
    candidates_with_survivors: usize,
    rejected_candidates: usize,
    input_contradictions: usize,
    omitted_candidates: usize,
    unsupported_candidates: usize,
    #[serde(deserialize_with = "bounded_no_survivor_reasons")]
    no_survivor_reasons: Vec<NoSurvivorReason>,
    search_complete_within_plan: Option<bool>,
}

impl Cohort {
    fn checkpoint_omissions(&self) -> (u64, u64) {
        let previous = self.checkpoint.as_ref();
        (
            previous
                .map_or(0, |item| item.omitted_input_links)
                .saturating_add(u64::try_from(self.inputs.len()).unwrap_or(u64::MAX)),
            previous
                .map_or(0, |item| item.omitted_hypotheses)
                .saturating_add(u64::try_from(self.hypotheses.len()).unwrap_or(u64::MAX)),
        )
    }

    pub(super) const fn identity(&self) -> RecoveryFunnelIdentity {
        self.identity
    }

    const fn new(identity: RecoveryFunnelIdentity) -> Self {
        Self {
            identity,
            sessions: Vec::new(),
            inputs: Vec::new(),
            hypotheses: Vec::new(),
            input_limit_reached: false,
            hypothesis_limit_reached: false,
            admission_omissions: AdmissionOmissions {
                resource_exhausted: false,
                cycle_skipped: false,
            },
            checkpoint: None,
        }
    }

    fn register(&mut self, registration: &RecoveryFunnelRegistration<'_>) {
        if registration.total_inputs > registration.inputs.len()
            || registration.inputs.len() > MAX_RECOVERY_FUNNEL_INPUTS
        {
            self.input_limit_reached = true;
        }
        for input in registration.inputs.iter().take(MAX_RECOVERY_FUNNEL_INPUTS) {
            if !insert_bounded(&mut self.sessions, input.session_node_id, MAX_SESSIONS) {
                self.input_limit_reached = true;
                continue;
            }
            if !insert_bounded(&mut self.inputs, *input, MAX_RECOVERY_FUNNEL_INPUTS) {
                self.input_limit_reached = true;
            }
        }
        match registration.admission {
            RecoveryFunnelAdmission::Admitted(candidate) => self.record(
                RecoveryTransitionStage::Cohort,
                RecoveryTransitionOutcome::CohortAdmitted,
                *candidate,
                None,
            ),
            RecoveryFunnelAdmission::ResourceExhausted => {
                self.admission_omissions.resource_exhausted = true;
            }
            RecoveryFunnelAdmission::CycleSkipped => {
                self.admission_omissions.cycle_skipped = true;
            }
            RecoveryFunnelAdmission::Unknown => {}
        }
    }

    fn record(
        &mut self,
        stage: RecoveryTransitionStage,
        outcome: RecoveryTransitionOutcome,
        sample: RecoveryCandidateSample,
        validated_artifact_sha256: Option<[u8; 32]>,
    ) {
        let mask = outcome_mask(outcome);
        if let Some(existing) = self.hypotheses.iter_mut().find(|item| {
            item.stage == stage
                && item.input_batch_sha256 == sample.input_batch_sha256
                && item.task_sha256 == sample.task_sha256
        }) {
            existing.outcomes |= mask;
            existing.evidence_node_id =
                least_available(existing.evidence_node_id, sample.evidence_node_id);
            existing.validated_artifact_sha256 = existing
                .validated_artifact_sha256
                .or(validated_artifact_sha256);
            return;
        }
        if self.hypotheses.len() >= MAX_HYPOTHESES {
            self.hypothesis_limit_reached = true;
            return;
        }
        self.hypotheses.push(Hypothesis {
            stage,
            candidate_index: sample.candidate_index,
            input_batch_sha256: sample.input_batch_sha256,
            task_sha256: sample.task_sha256,
            input_blob_sha256: sample.input_blob_sha256,
            validated_artifact_sha256,
            outcomes: mask,
            evidence_node_id: sample.evidence_node_id,
        });
        self.hypotheses.sort_unstable();
    }

    fn matches(&self, event: &RecoveryFunnelEvent<'_>) -> bool {
        (event.attribution == RecoveryFunnelAttribution::CandidateAndParents
            && self.hypotheses.iter().any(|item| {
                item.candidate_index == event.candidate.candidate_index
                    || event
                        .parent_candidates
                        .iter()
                        .take(MAX_RECOVERY_FUNNEL_INPUTS)
                        .any(|parent| *parent == item.candidate_index)
            }))
            || event
                .input_nodes
                .iter()
                .take(MAX_RECOVERY_FUNNEL_INPUTS)
                .any(|node| {
                    self.inputs
                        .binary_search_by_key(node, |input| input.node_id)
                        .is_ok()
                })
    }

    fn stages(&self) -> Vec<StageView> {
        RecoveryTransitionStage::ALL
            .into_iter()
            .map(|stage| {
                let hypotheses = self.hypotheses.iter().filter(|item| item.stage == stage);
                let mut view = StageView {
                    stage,
                    observed_candidates: 0,
                    candidates_with_survivors: 0,
                    rejected_candidates: 0,
                    input_contradictions: 0,
                    omitted_candidates: 0,
                    unsupported_candidates: 0,
                    no_survivor_reasons: Vec::new(),
                    search_complete_within_plan: None,
                };
                let mut complete_reports = 0;
                for hypothesis in hypotheses {
                    view.observed_candidates += 1;
                    view.candidates_with_survivors +=
                        usize::from(hypothesis.outcomes & surviving_mask() != 0);
                    view.rejected_candidates +=
                        usize::from(hypothesis.outcomes & rejected_mask() != 0);
                    view.input_contradictions += usize::from(
                        hypothesis.outcomes
                            & outcome_mask(RecoveryTransitionOutcome::InputContradicted)
                            != 0,
                    );
                    view.omitted_candidates +=
                        usize::from(hypothesis.outcomes & omitted_mask() != 0);
                    view.unsupported_candidates += usize::from(
                        hypothesis.outcomes & outcome_mask(RecoveryTransitionOutcome::Unsupported)
                            != 0,
                    );
                    complete_reports += usize::from(
                        hypothesis.outcomes
                            & outcome_mask(RecoveryTransitionOutcome::SearchCompleteWithinPlan)
                            != 0,
                    );
                    view.add_no_survivor_reasons(hypothesis.outcomes);
                }
                if stage == RecoveryTransitionStage::Cohort {
                    // A retained source only establishes eligibility, not admission
                    let omitted = self.admission_omissions.count();
                    view.observed_candidates += omitted;
                    view.omitted_candidates += omitted;
                }
                if view.omitted_candidates > 0 || view.unsupported_candidates > 0 {
                    view.search_complete_within_plan = Some(false);
                } else if stage == RecoveryTransitionStage::Schema
                    && view.observed_candidates > 0
                    && complete_reports == view.observed_candidates
                    && !self.input_limit_reached
                    && !self.hypothesis_limit_reached
                {
                    // A diagnostic cap makes coverage unknown, not an omitted search
                    view.search_complete_within_plan = Some(true);
                }
                if let Some(previous) = self
                    .checkpoint
                    .as_ref()
                    .and_then(|checkpoint| checkpoint.stages.iter().find(|row| row.stage == stage))
                {
                    view.include_baseline(previous);
                }
                view
            })
            .collect()
    }
}

impl StageView {
    fn add_no_survivor_reasons(&mut self, outcomes: u32) {
        for (outcome, reason) in [
            (
                RecoveryTransitionOutcome::InsufficientTrainingMessages,
                NoSurvivorReason::InsufficientTrainingMessages,
            ),
            (
                RecoveryTransitionOutcome::NoStructuralCandidateSpace,
                NoSurvivorReason::NoStructuralCandidateSpace,
            ),
            (
                RecoveryTransitionOutcome::NoSchemaSurvivedStrictParsing,
                NoSurvivorReason::NoSchemaSurvivedStrictParsing,
            ),
        ] {
            if outcomes & outcome_mask(outcome) != 0 && !self.no_survivor_reasons.contains(&reason)
            {
                self.no_survivor_reasons.push(reason);
            }
        }
    }

    fn include_baseline(&mut self, previous: &Self) {
        let new_observations = self.observed_candidates;
        // The resumed and saved candidates may overlap, so the maximum is a lower bound
        self.observed_candidates = self.observed_candidates.max(previous.observed_candidates);
        self.candidates_with_survivors = self
            .candidates_with_survivors
            .max(previous.candidates_with_survivors);
        self.rejected_candidates = self.rejected_candidates.max(previous.rejected_candidates);
        self.input_contradictions = self.input_contradictions.max(previous.input_contradictions);
        self.omitted_candidates = self.omitted_candidates.max(previous.omitted_candidates);
        self.unsupported_candidates = self
            .unsupported_candidates
            .max(previous.unsupported_candidates);
        for reason in &previous.no_survivor_reasons {
            if !self.no_survivor_reasons.contains(reason) {
                self.no_survivor_reasons.push(*reason);
            }
        }
        self.search_complete_within_plan = match (
            previous.search_complete_within_plan,
            self.search_complete_within_plan,
        ) {
            (Some(false), _) | (_, Some(false)) => Some(false),
            (prior, _) if new_observations == 0 => prior,
            (Some(true), Some(true)) => Some(true),
            _ => None,
        };
    }
}

impl Serialize for Cohort {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_cohort(self, serializer, false)
    }
}

fn serialize_cohort<S: Serializer>(
    cohort: &Cohort,
    serializer: S,
    compact: bool,
) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct Digest<'a>(#[serde(with = "digest")] &'a [u8; 32]);
    let stages = cohort.stages();
    let last_viable = stages
        .iter()
        .rev()
        .find(|stage| stage.candidates_with_survivors > 0)
        .map(|stage| stage.stage);
    let checkpointed = compact || cohort.checkpoint.is_some();
    let (omitted_links, omitted_hypotheses) = if compact {
        cohort.checkpoint_omissions()
    } else {
        cohort.checkpoint.as_ref().map_or((0, 0), |item| {
            (item.omitted_input_links, item.omitted_hypotheses)
        })
    };
    let inputs: &[RecoveryFunnelInput] = if compact { &[] } else { &cohort.inputs };
    let hypotheses: &[Hypothesis] = if compact { &[] } else { &cohort.hypotheses };
    let fields = if checkpointed { 12 } else { 9 };
    let mut state = serializer.serialize_struct(
        "Cohort",
        fields + usize::from(!cohort.admission_omissions.is_empty()),
    )?;
    state.serialize_field("source_sha256", &Digest(&cohort.identity.source_sha256))?;
    state.serialize_field("cohort_sha256", &Digest(&cohort.identity.cohort_sha256))?;
    state.serialize_field("sessions", &cohort.sessions)?;
    state.serialize_field("stages", &stages)?;
    state.serialize_field("last_viable_stage", &last_viable)?;
    state.serialize_field(
        "input_limit_reached",
        &(cohort.input_limit_reached || omitted_links > 0),
    )?;
    state.serialize_field(
        "hypothesis_limit_reached",
        &(cohort.hypothesis_limit_reached || omitted_hypotheses > 0),
    )?;
    state.serialize_field("input_links", inputs)?;
    state.serialize_field("hypotheses", hypotheses)?;
    if !cohort.admission_omissions.is_empty() {
        state.serialize_field("admission_omissions", &cohort.admission_omissions)?;
    }
    if checkpointed {
        state.serialize_field("checkpoint_projection_version", &1_u32)?;
        state.serialize_field("checkpoint_omitted_input_links", &omitted_links)?;
        state.serialize_field("checkpoint_omitted_hypotheses", &omitted_hypotheses)?;
    }
    state.end()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CohortWire {
    #[serde(with = "digest")]
    source_sha256: [u8; 32],
    #[serde(with = "digest")]
    cohort_sha256: [u8; 32],
    #[serde(deserialize_with = "bounded_sessions")]
    sessions: Vec<u64>,
    #[serde(deserialize_with = "bounded_inputs")]
    input_links: Vec<RecoveryFunnelInput>,
    #[serde(deserialize_with = "bounded_hypotheses")]
    hypotheses: Vec<Hypothesis>,
    input_limit_reached: bool,
    hypothesis_limit_reached: bool,
    #[serde(default)]
    admission_omissions: AdmissionOmissions,
    #[serde(deserialize_with = "bounded_stages")]
    stages: Vec<StageView>,
    last_viable_stage: Option<RecoveryTransitionStage>,
    #[serde(default)]
    checkpoint_projection_version: Option<u32>,
    #[serde(default)]
    checkpoint_omitted_input_links: u64,
    #[serde(default)]
    checkpoint_omitted_hypotheses: u64,
}

impl<'de> Deserialize<'de> for Cohort {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = CohortWire::deserialize(deserializer)?;
        let omitted = usize::try_from(wire.checkpoint_omitted_hypotheses)
            .unwrap_or(MAX_HYPOTHESES)
            .min(MAX_HYPOTHESES);
        let candidate_bound = wire
            .hypotheses
            .len()
            .saturating_add(omitted)
            .min(MAX_HYPOTHESES);
        let cohort_candidate_bound = wire
            .hypotheses
            .iter()
            .filter(|item| item.stage == RecoveryTransitionStage::Cohort)
            .count()
            .saturating_add(omitted)
            .min(MAX_HYPOTHESES);
        let checkpoint = match wire.checkpoint_projection_version {
            None if wire.checkpoint_omitted_input_links == 0
                && wire.checkpoint_omitted_hypotheses == 0 =>
            {
                None
            }
            Some(1)
                if valid_checkpoint_stages(
                    &wire.stages,
                    wire.last_viable_stage,
                    candidate_bound,
                    cohort_candidate_bound,
                    wire.admission_omissions.count(),
                ) && (wire.checkpoint_omitted_input_links == 0 || wire.input_limit_reached)
                    && (wire.checkpoint_omitted_hypotheses == 0
                        || wire.hypothesis_limit_reached) =>
            {
                Some(CheckpointBaseline {
                    stages: wire.stages,
                    omitted_input_links: wire.checkpoint_omitted_input_links,
                    omitted_hypotheses: wire.checkpoint_omitted_hypotheses,
                })
            }
            _ => {
                return Err(de::Error::custom(
                    "invalid recovery funnel checkpoint projection",
                ));
            }
        };
        let mut candidate_keys = std::collections::BTreeSet::new();
        if !strictly_ordered(&wire.sessions)
            || !strictly_ordered(&wire.input_links)
            || !strictly_ordered(&wire.hypotheses)
            || wire.hypotheses.iter().any(|item| {
                item.outcomes == 0
                    || item.outcomes >= (1_u32 << RecoveryTransitionOutcome::ALL.len())
                    || !candidate_keys.insert((
                        item.stage,
                        item.input_batch_sha256,
                        item.task_sha256,
                    ))
            })
            || wire
                .input_links
                .iter()
                .any(|item| wire.sessions.binary_search(&item.session_node_id).is_err())
        {
            return Err(de::Error::custom("invalid recovery funnel cohort"));
        }
        Ok(Self {
            identity: RecoveryFunnelIdentity {
                source_sha256: wire.source_sha256,
                cohort_sha256: wire.cohort_sha256,
            },
            sessions: wire.sessions,
            inputs: wire.input_links,
            hypotheses: wire.hypotheses,
            input_limit_reached: wire.input_limit_reached,
            hypothesis_limit_reached: wire.hypothesis_limit_reached,
            admission_omissions: wire.admission_omissions,
            checkpoint,
        })
    }
}

impl Funnel {
    pub(super) const fn view(&self, publication_incomplete: bool) -> FunnelView<'_> {
        FunnelView {
            funnel: self,
            publication_incomplete,
        }
    }

    pub(super) fn validation_identities_unavailable(&self, compact: bool) -> bool {
        self.omission_reasons.total() > 0
            || self.cohorts().iter().any(|cohort| {
                cohort.input_limit_reached
                    || cohort.hypothesis_limit_reached
                    || cohort.hypotheses.iter().any(|item| {
                        item.stage == RecoveryTransitionStage::Validation
                            && item.outcomes & outcome_mask(RecoveryTransitionOutcome::Validated)
                                != 0
                            && (compact || item.validated_artifact_sha256.is_none())
                    })
                    || cohort.checkpoint.as_ref().is_some_and(|checkpoint| {
                        checkpoint.omitted_hypotheses > 0
                            && checkpoint.stages.iter().any(|stage| {
                                stage.stage == RecoveryTransitionStage::Validation
                                    && stage.candidates_with_survivors > 0
                            })
                    })
            })
    }

    pub(super) const fn checkpoint_view(&self, include_cohorts: bool) -> CheckpointFunnel<'_> {
        CheckpointFunnel {
            funnel: self,
            include_cohorts,
        }
    }

    pub(super) fn has_checkpoint_projection(&self) -> bool {
        self.omission_reasons.checkpoint_size > 0
            || self
                .cohorts()
                .iter()
                .any(|cohort| cohort.checkpoint.is_some())
    }

    pub(super) fn compact_checkpoint(&mut self) {
        for cohort in &mut self.cohorts {
            let stages = cohort.stages();
            let (omitted_input_links, omitted_hypotheses) = cohort.checkpoint_omissions();
            cohort.input_limit_reached |= omitted_input_links > 0;
            cohort.hypothesis_limit_reached |= omitted_hypotheses > 0;
            cohort.inputs = Vec::new();
            cohort.hypotheses = Vec::new();
            cohort.checkpoint = Some(CheckpointBaseline {
                stages,
                omitted_input_links,
                omitted_hypotheses,
            });
        }
    }

    pub(super) fn omit_checkpoint_cohorts(&mut self) {
        let count = u64::try_from(self.cohorts.len()).unwrap_or(u64::MAX);
        self.cohorts = Vec::new();
        self.omit(FunnelOmissionReason::CheckpointSize, count);
    }

    pub(super) fn cohorts(&self) -> &[Cohort] {
        self.frozen
            .as_ref()
            .map_or(self.cohorts.as_slice(), |frozen| frozen.cohorts.as_slice())
    }

    pub(super) const fn from_checkpoint(
        cohorts: Vec<Cohort>,
        omission_reasons: FunnelOmissionReasons,
    ) -> Self {
        Self {
            cohorts,
            frozen: None,
            omission_reasons,
        }
    }

    pub(super) fn snapshot_copy(&self, cohort_limit: usize, memory_limit: usize) -> Self {
        let source = self.cohorts();
        let within_cohort_limit = source.len().min(cohort_limit);
        let retained = within_cohort_limit.min(memory_limit);
        let mut copy = Self {
            cohorts: source.iter().take(retained).cloned().collect(),
            frozen: None,
            omission_reasons: self.omission_reasons,
        };
        copy.omit(
            FunnelOmissionReason::CohortLimit,
            u64::try_from(source.len() - within_cohort_limit).unwrap_or(u64::MAX),
        );
        copy.omit(
            FunnelOmissionReason::MemoryAdmission,
            u64::try_from(within_cohort_limit - retained).unwrap_or(u64::MAX),
        );
        copy
    }

    pub(super) fn freeze(&mut self, memory: Option<MemoryLease>) {
        if self.cohorts.is_empty() {
            return;
        }
        let cohorts = std::mem::take(&mut self.cohorts);
        self.frozen = Some(Arc::new(FrozenCohorts {
            cohorts,
            _memory: memory,
        }));
    }

    pub(super) fn thaw(&mut self, cohort_limit: usize, memory_limit: usize) {
        let count = self.cohorts().len();
        let within_cohort_limit = count.min(cohort_limit);
        let retained = within_cohort_limit.min(memory_limit);
        if let Some(frozen) = self.frozen.take() {
            self.cohorts = match Arc::try_unwrap(frozen) {
                Ok(mut owned) => {
                    if retained < count {
                        owned.cohorts.truncate(retained);
                        owned.cohorts.shrink_to_fit();
                    }
                    std::mem::take(&mut owned.cohorts)
                }
                Err(shared) => shared.cohorts.iter().take(retained).cloned().collect(),
            };
        } else if retained < count {
            self.cohorts.truncate(retained);
            self.cohorts.shrink_to_fit();
        }
        self.omit(
            FunnelOmissionReason::CohortLimit,
            u64::try_from(count - within_cohort_limit).unwrap_or(u64::MAX),
        );
        self.omit(
            FunnelOmissionReason::MemoryAdmission,
            u64::try_from(within_cohort_limit - retained).unwrap_or(u64::MAX),
        );
    }

    pub(super) fn contains(&self, identity: RecoveryFunnelIdentity) -> bool {
        self.cohorts()
            .binary_search_by_key(&identity, |cohort| cohort.identity)
            .is_ok()
    }

    pub(super) const fn omit(&mut self, reason: FunnelOmissionReason, amount: u64) {
        self.omission_reasons.add(reason, amount);
    }

    pub(super) fn register(&mut self, registration: RecoveryFunnelRegistration<'_>) {
        let index = self
            .cohorts
            .binary_search_by_key(&registration.identity, |cohort| cohort.identity);
        let index = match index {
            Ok(index) => index,
            Err(index) if self.cohorts.len() < MAX_COHORTS => {
                self.cohorts
                    .insert(index, Cohort::new(registration.identity));
                index
            }
            Err(_) => {
                self.omit(FunnelOmissionReason::CohortLimit, 1);
                return;
            }
        };
        if let Some(cohort) = self.cohorts.get_mut(index) {
            cohort.register(&registration);
        }
    }

    pub(super) fn record(&mut self, event: RecoveryFunnelEvent<'_>) {
        let mut matched = false;
        for cohort in &mut self.cohorts {
            if cohort.matches(&event) {
                matched = true;
                cohort.record(
                    event.stage,
                    event.outcome,
                    *event.candidate,
                    event.validated_artifact_sha256,
                );
            }
        }
        if !matched
            || !event.attribution_complete
            || event.input_nodes.len() > MAX_RECOVERY_FUNNEL_INPUTS
            || event.parent_candidates.len() > MAX_RECOVERY_FUNNEL_INPUTS
        {
            let reason = if event.attribution_complete
                && event.input_nodes.len() <= MAX_RECOVERY_FUNNEL_INPUTS
                && event.parent_candidates.len() <= MAX_RECOVERY_FUNNEL_INPUTS
            {
                FunnelOmissionReason::UnattributedCandidate
            } else {
                FunnelOmissionReason::AssociationLimit
            };
            self.omit(reason, 1);
        }
    }

    pub(super) fn record_for_cohort(
        &mut self,
        identity: RecoveryFunnelIdentity,
        stage: RecoveryTransitionStage,
        outcome: RecoveryTransitionOutcome,
        sample: RecoveryCandidateSample,
    ) {
        if let Ok(index) = self
            .cohorts
            .binary_search_by_key(&identity, |cohort| cohort.identity)
            && let Some(cohort) = self.cohorts.get_mut(index)
        {
            cohort.record(stage, outcome, sample, None);
        } else {
            self.omit(FunnelOmissionReason::UnattributedCandidate, 1);
        }
    }

    pub(super) fn record_publication(
        &mut self,
        outcome: RecoveryTransitionOutcome,
        publication: RecoveryPublicationSample,
    ) {
        if publication.artifact_count == Some(0) {
            // A sample cannot identify an artifact in a declared empty set
            return;
        }
        let Some(artifact) = publication.artifact else {
            return;
        };
        for cohort in &mut self.cohorts {
            // Publication samples identify one exact artifact, not every output in the set
            let validated = cohort
                .hypotheses
                .iter()
                .filter(|item| {
                    item.stage == RecoveryTransitionStage::Validation
                        && item.outcomes & outcome_mask(RecoveryTransitionOutcome::Validated) != 0
                        && item.validated_artifact_sha256 == Some(artifact.sha256)
                })
                .cloned()
                .collect::<Vec<_>>();
            for item in validated {
                cohort.record(
                    RecoveryTransitionStage::Publication,
                    outcome,
                    RecoveryCandidateSample {
                        candidate_index: item.candidate_index,
                        input_node_id: 0,
                        input_blob_sha256: item.input_blob_sha256,
                        input_batch_sha256: item.input_batch_sha256,
                        task_sha256: item.task_sha256,
                        source_range: None,
                        input_count: 0,
                        evidence_node_id: item.evidence_node_id,
                    },
                    None,
                );
            }
        }
    }

    pub(super) fn merge(&mut self, other: Self) {
        let mut other = other;
        other.thaw(MAX_COHORTS, MAX_COHORTS);
        self.omission_reasons.merge(other.omission_reasons);
        for incoming in other.cohorts {
            match self
                .cohorts
                .binary_search_by_key(&incoming.identity, |cohort| cohort.identity)
            {
                Ok(index) => {
                    let Some(current) = self.cohorts.get_mut(index) else {
                        continue;
                    };
                    if let Some(incoming_checkpoint) = incoming.checkpoint {
                        if let Some(existing) = &mut current.checkpoint {
                            for (row, previous) in
                                existing.stages.iter_mut().zip(&incoming_checkpoint.stages)
                            {
                                row.include_baseline(previous);
                            }
                            existing.omitted_input_links = existing
                                .omitted_input_links
                                .saturating_add(incoming_checkpoint.omitted_input_links);
                            existing.omitted_hypotheses = existing
                                .omitted_hypotheses
                                .saturating_add(incoming_checkpoint.omitted_hypotheses);
                        } else {
                            current.checkpoint = Some(incoming_checkpoint);
                        }
                    }
                    current.input_limit_reached |= incoming.input_limit_reached;
                    current.hypothesis_limit_reached |= incoming.hypothesis_limit_reached;
                    current.admission_omissions.resource_exhausted |=
                        incoming.admission_omissions.resource_exhausted;
                    current.admission_omissions.cycle_skipped |=
                        incoming.admission_omissions.cycle_skipped;
                    for session in incoming.sessions {
                        current.input_limit_reached |=
                            !insert_bounded(&mut current.sessions, session, MAX_SESSIONS);
                    }
                    for input in incoming.inputs {
                        if current
                            .sessions
                            .binary_search(&input.session_node_id)
                            .is_err()
                        {
                            current.input_limit_reached = true;
                            continue;
                        }
                        current.input_limit_reached |=
                            !insert_bounded(&mut current.inputs, input, MAX_RECOVERY_FUNNEL_INPUTS);
                    }
                    for item in incoming.hypotheses {
                        if let Some(existing) = current.hypotheses.iter_mut().find(|existing| {
                            existing.stage == item.stage
                                && existing.input_batch_sha256 == item.input_batch_sha256
                                && existing.task_sha256 == item.task_sha256
                        }) {
                            existing.outcomes |= item.outcomes;
                            existing.validated_artifact_sha256 = existing
                                .validated_artifact_sha256
                                .or(item.validated_artifact_sha256);
                            existing.evidence_node_id =
                                least_available(existing.evidence_node_id, item.evidence_node_id);
                        } else if current.hypotheses.len() < MAX_HYPOTHESES {
                            current.hypotheses.push(item);
                        } else {
                            current.hypothesis_limit_reached = true;
                        }
                    }
                    current.hypotheses.sort_unstable();
                }
                Err(index) if self.cohorts.len() < MAX_COHORTS => {
                    self.cohorts.insert(index, incoming);
                }
                Err(_) => self.omit(FunnelOmissionReason::CohortLimit, 1),
            }
        }
    }
}

fn insert_bounded<T: Ord>(values: &mut Vec<T>, value: T, limit: usize) -> bool {
    match values.binary_search(&value) {
        Ok(_) => true,
        Err(index) if values.len() < limit => {
            values.insert(index, value);
            true
        }
        Err(_) => false,
    }
}

fn strictly_ordered<T: Ord>(values: &[T]) -> bool {
    values
        .windows(2)
        .all(|pair| matches!(pair, [left, right] if left < right))
}

fn least_available(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn valid_checkpoint_stages(
    stages: &[StageView],
    last_viable: Option<RecoveryTransitionStage>,
    candidate_bound: usize,
    cohort_candidate_bound: usize,
    admission_omissions: usize,
) -> bool {
    stages.len() == RecoveryTransitionStage::ALL.len()
        && stages
            .iter()
            .zip(RecoveryTransitionStage::ALL)
            .all(|(row, stage)| {
                let bound = if stage == RecoveryTransitionStage::Cohort {
                    cohort_candidate_bound.saturating_add(admission_omissions)
                } else {
                    candidate_bound
                };
                row.stage == stage
                    && row.observed_candidates <= bound
                    && (stage != RecoveryTransitionStage::Cohort
                        || row.candidates_with_survivors <= cohort_candidate_bound)
                    && [
                        row.candidates_with_survivors,
                        row.rejected_candidates,
                        row.input_contradictions,
                        row.omitted_candidates,
                        row.unsupported_candidates,
                    ]
                    .into_iter()
                    .all(|count| count <= row.observed_candidates)
                    && row
                        .no_survivor_reasons
                        .iter()
                        .enumerate()
                        .all(|(index, reason)| {
                            row.no_survivor_reasons
                                .iter()
                                .take(index)
                                .all(|prior| prior != reason)
                        })
                    && (stage == RecoveryTransitionStage::Schema
                        || row.no_survivor_reasons.is_empty())
                    && (row.observed_candidates > 0 || row.no_survivor_reasons.is_empty())
                    && (row.search_complete_within_plan != Some(true)
                        || (stage == RecoveryTransitionStage::Schema
                            && row.observed_candidates > 0
                            && row.omitted_candidates == 0
                            && row.unsupported_candidates == 0))
            })
        && stages
            .iter()
            .rev()
            .find(|row| row.candidates_with_survivors > 0)
            .map(|row| row.stage)
            == last_viable
}

const fn outcome_mask(outcome: RecoveryTransitionOutcome) -> u32 {
    // Explicit bit assignments keep checkpoint meanings stable when outcomes are added
    let position = match outcome {
        RecoveryTransitionOutcome::Derived => 0,
        RecoveryTransitionOutcome::ReportRetained => 1,
        RecoveryTransitionOutcome::Hypothesis => 2,
        RecoveryTransitionOutcome::Validated => 3,
        RecoveryTransitionOutcome::Contradicted => 4,
        RecoveryTransitionOutcome::InputContradicted => 5,
        RecoveryTransitionOutcome::BudgetExhausted => 6,
        RecoveryTransitionOutcome::WorkOmitted => 7,
        RecoveryTransitionOutcome::Unsupported => 8,
        RecoveryTransitionOutcome::CohortAdmitted => 9,
        RecoveryTransitionOutcome::CohortOmitted => 10,
        RecoveryTransitionOutcome::LearningSampleOmitted => 11,
        RecoveryTransitionOutcome::Published => 12,
        RecoveryTransitionOutcome::PublishedDurabilityUncertain => 13,
        RecoveryTransitionOutcome::PublishedReplacementUncertain => 14,
        RecoveryTransitionOutcome::PublicationFailed => 15,
        RecoveryTransitionOutcome::InsufficientTrainingMessages => 16,
        RecoveryTransitionOutcome::NoStructuralCandidateSpace => 17,
        RecoveryTransitionOutcome::NoSchemaSurvivedStrictParsing => 18,
        RecoveryTransitionOutcome::SearchCompleteWithinPlan => 19,
    };
    1_u32 << position
}
fn surviving_mask() -> u32 {
    [
        RecoveryTransitionOutcome::Derived,
        RecoveryTransitionOutcome::Hypothesis,
        RecoveryTransitionOutcome::Validated,
        RecoveryTransitionOutcome::CohortAdmitted,
        RecoveryTransitionOutcome::Published,
        RecoveryTransitionOutcome::PublishedDurabilityUncertain,
        RecoveryTransitionOutcome::PublishedReplacementUncertain,
    ]
    .into_iter()
    .fold(0, |mask, outcome| mask | outcome_mask(outcome))
}
const fn rejected_mask() -> u32 {
    outcome_mask(RecoveryTransitionOutcome::Contradicted)
}
fn omitted_mask() -> u32 {
    [
        RecoveryTransitionOutcome::BudgetExhausted,
        RecoveryTransitionOutcome::WorkOmitted,
        RecoveryTransitionOutcome::CohortOmitted,
        RecoveryTransitionOutcome::LearningSampleOmitted,
        RecoveryTransitionOutcome::PublicationFailed,
    ]
    .into_iter()
    .fold(0, |mask, outcome| mask | outcome_mask(outcome))
}

pub(super) fn bounded_cohorts<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<Cohort>, D::Error> {
    bounded_vec::<D, Cohort, MAX_COHORTS>(deserializer)
}
fn bounded_sessions<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u64>, D::Error> {
    bounded_vec::<D, u64, MAX_SESSIONS>(deserializer)
}
fn bounded_inputs<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<RecoveryFunnelInput>, D::Error> {
    bounded_vec::<D, RecoveryFunnelInput, MAX_RECOVERY_FUNNEL_INPUTS>(deserializer)
}
fn bounded_hypotheses<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<Hypothesis>, D::Error> {
    bounded_vec::<D, Hypothesis, MAX_HYPOTHESES>(deserializer)
}
fn bounded_stages<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<StageView>, D::Error> {
    bounded_vec::<D, StageView, 8>(deserializer)
}
fn bounded_no_survivor_reasons<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<NoSurvivorReason>, D::Error> {
    bounded_vec::<D, NoSurvivorReason, 3>(deserializer)
}

fn bounded_vec<'de, D: Deserializer<'de>, T: Deserialize<'de>, const MAX: usize>(
    deserializer: D,
) -> Result<Vec<T>, D::Error> {
    struct Bounded<T, const N: usize>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const N: usize> de::Visitor<'de> for Bounded<T, N> {
        type Value = Vec<T>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {N} entries")
        }
        fn visit_seq<A: de::SeqAccess<'de>>(self, mut sequence: A) -> Result<Vec<T>, A::Error> {
            let mut values = Vec::new();
            values
                .try_reserve(sequence.size_hint().unwrap_or_default().min(N))
                .map_err(de::Error::custom)?;
            while values.len() < N {
                let Some(value) = sequence.next_element()? else {
                    return Ok(values);
                };
                values.push(value);
            }
            if sequence.next_element::<de::IgnoredAny>()?.is_some() {
                return Err(de::Error::custom("recovery funnel limit exceeded"));
            }
            Ok(values)
        }
    }
    deserializer.deserialize_seq(Bounded::<T, MAX>(PhantomData))
}
