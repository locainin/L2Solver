//! Deterministic fixed-point execution over retained evidence bytes

#[cfg(test)]
#[path = "../../../tests/workbench/recovery_case_index.rs"]
mod case_index_tests;
mod case_scan;
mod derived_discovery;
mod discovery;
mod embedded;
mod evidence;
mod expansion;
mod format;
mod framing;
mod framing_discovery;
#[cfg(test)]
#[path = "../../../tests/workbench/recovery_executor_job.rs"]
mod job_tests;
mod lineage;
mod model;
mod peer_cohort;
mod policy;
mod record_discovery;
mod records;
mod relational;
mod scheduler;
mod tcp_ancestry;
mod transform;
mod validation;

use super::framing_materialize::FramingSelectionBasis;
use crate::arguments::RecoveryProfile;
use case_scan::{
    CONTENT_ID_BYTES, CaseIndexScanLedger, INDEX_RADIX_PASSES, case_index_scan_bound,
    case_index_suffix_scan_bound,
};
use discovery::TransformDiscoveryState;
use l2_workbench::{
    evidence::{Case, EvidenceStatus},
    job::{Counter, Job, JobError, Phase},
    recovery::{
        RecoveryCandidateId, RecoveryCoordinator, RecoveryError, RecoveryStage, RecoveryTask,
    },
};
use lineage::{TransformCohort, TransformSlot};
#[cfg(test)]
use model::TransformExplorationBudget;
pub use model::{
    RecoveryDiscoveryStatus, RecoveryExecutionError, RecoveryOmission, RecoveryResourceSummary,
    RecoveryRunSummary,
};
use model::{RecoveryExecutionOutcome, RecoveryExecutionPolicy, RecoveryPlan};
#[cfg(test)]
use policy::normal_policy;
use policy::{policy_for_profile, resolve_policy, source_priority};
use relational::{RelationalDiscoveryContext, RelationalSampleCollections};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

pub(super) use super::{decode::service::DecodeBatchLimits, expand::ExpansionLimits};

const DERIVED_REASON: &str = "The selected operation retained these exact output bytes and its receipt records the input and parameters";
const RESULT_REASON: &str =
    "This retained evidence node records the completed operation for its exact input origins";
const CONTEXT_REASON: &str =
    "This retained evidence node supports the completed task for these exact input bytes";
const RECORD_SCHEMA_SELECTED_FROM_REASON: &str =
    "This strict schema survived discovery for this exact session and framing cohort";
const PROPOSED_BY_REASON: &str =
    "This canonical transform receipt was scheduled from a syntax-gated proposal report";

/// Run the empty exact plan used by top-level export
#[cfg(test)]
pub fn recover_case(case: &mut Case) -> Result<RecoveryRunSummary, RecoveryExecutionError> {
    recover_case_with_job(
        case,
        RecoveryProfile::Normal,
        policy::DEFAULT_MEMORY_LIMIT_BYTES as u64,
        None,
    )
}

/// Run default recovery with a bounded profile, memory allowance, and optional progress job
pub fn recover_case_with_job(
    case: &mut Case,
    profile: RecoveryProfile,
    memory_limit_bytes: u64,
    job: Option<&Job>,
) -> Result<RecoveryRunSummary, RecoveryExecutionError> {
    if let Some(job) = job {
        job.check_cancelled()?;
    }
    let policy = policy_for_profile(case, profile, memory_limit_bytes)?;
    let plan = RecoveryPlan {
        discover_transforms: true,
        discover_framing: true,
        discover_records: true,
        ..RecoveryPlan::default()
    };
    let progress = job.cloned().map(JobProgress::new);
    let outcome = execute_internal(case, &plan, &policy, false, progress.as_ref())?;
    Ok(RecoveryRunSummary {
        case_evidence_collection_complete: case.collection_complete(),
        discovery: RecoveryDiscoveryStatus {
            input_coverage_complete: discovery_input_coverage_complete(&outcome.omissions),
            search_exhaustive_within_plan: search_exhaustive_within_plan(&outcome.omissions),
            report_details_complete: report_details_complete(&outcome.omissions),
        },
        omissions: outcome.omissions,
        candidate_count: outcome.candidate_count,
        complete_negative_transform_searches: outcome.complete_negative_transform_searches,
        validated_artifact_count: outcome.validated_artifact_count,
        cycle_skips: outcome.cycle_skips,
        resources: outcome.resources,
    })
}

fn discovery_input_coverage_complete(omissions: &[RecoveryOmission]) -> bool {
    omissions.iter().all(|omission| match omission {
        RecoveryOmission::RelationalTransformAnalysis {
            input_coverage_complete,
            ..
        } => *input_coverage_complete,
        RecoveryOmission::FramingDiscoveryInputs { omitted_runs, .. } => *omitted_runs == 0,
        RecoveryOmission::RecordDiscoveryInputs { omitted_frames, .. } => *omitted_frames == 0,
        RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::FramingDiscovery | RecoveryTask::RecordDiscovery,
            resource,
            ..
        } => matches!(
            resource,
            l2_workbench::recovery::RecoveryResource::OutputBytes
                | l2_workbench::recovery::RecoveryResource::EvidenceNodes
                | l2_workbench::recovery::RecoveryResource::EvidenceEdges
                | l2_workbench::recovery::RecoveryResource::EvidenceBlobs
                | l2_workbench::recovery::RecoveryResource::EvidenceBlobBytes
                | l2_workbench::recovery::RecoveryResource::EvidenceTotalDetailsBytes
                | l2_workbench::recovery::RecoveryResource::EvidenceSourceRanges
                | l2_workbench::recovery::RecoveryResource::EvidenceLimitations
        ),
        _ => true,
    })
}

fn search_exhaustive_within_plan(omissions: &[RecoveryOmission]) -> bool {
    omissions.iter().all(|omission| match omission {
        RecoveryOmission::TransformDiscoveryAnalysis {
            omitted_candidates, ..
        } => *omitted_candidates == 0,
        RecoveryOmission::TransformProposalAssociations { .. }
        | RecoveryOmission::RelationalTransformAnalysis {
            search_exhaustive_within_plan: false,
            ..
        }
        | RecoveryOmission::StageWorkLimit {
            task: RecoveryTask::TransformDiscovery,
            ..
        } => false,
        RecoveryOmission::FramingDiscoveryAnalysis {
            search_exhaustive_within_plan,
            ..
        }
        | RecoveryOmission::RecordDiscoveryAnalysis {
            search_exhaustive_within_plan,
            ..
        } => *search_exhaustive_within_plan,
        RecoveryOmission::ResourceExhausted {
            task:
                RecoveryTask::TransformDiscovery
                | RecoveryTask::FramingDiscovery
                | RecoveryTask::RecordDiscovery,
            resource,
            ..
        } => matches!(
            resource,
            l2_workbench::recovery::RecoveryResource::OutputBytes
                | l2_workbench::recovery::RecoveryResource::EvidenceNodes
                | l2_workbench::recovery::RecoveryResource::EvidenceEdges
                | l2_workbench::recovery::RecoveryResource::EvidenceBlobs
                | l2_workbench::recovery::RecoveryResource::EvidenceBlobBytes
                | l2_workbench::recovery::RecoveryResource::EvidenceTotalDetailsBytes
                | l2_workbench::recovery::RecoveryResource::EvidenceSourceRanges
                | l2_workbench::recovery::RecoveryResource::EvidenceLimitations
        ),
        _ => true,
    })
}

fn report_details_complete(omissions: &[RecoveryOmission]) -> bool {
    omissions.iter().all(|omission| match omission {
        RecoveryOmission::TransformDiscoveryAnalysis {
            omitted_reports, ..
        } => *omitted_reports == 0,
        RecoveryOmission::RelationalTransformAnalysis {
            report_details_complete,
            ..
        }
        | RecoveryOmission::FramingDiscoveryAnalysis {
            report_details_complete,
            ..
        }
        | RecoveryOmission::RecordDiscoveryAnalysis {
            report_details_complete,
            ..
        } => *report_details_complete,
        RecoveryOmission::FramingDiscoveryReportDetails { .. }
        | RecoveryOmission::RecordDiscoveryReportDetails { .. }
        | RecoveryOmission::ResourceExhausted {
            task:
                RecoveryTask::TransformDiscovery
                | RecoveryTask::FramingDiscovery
                | RecoveryTask::RecordDiscovery,
            resource:
                l2_workbench::recovery::RecoveryResource::OutputBytes
                | l2_workbench::recovery::RecoveryResource::EvidenceNodes
                | l2_workbench::recovery::RecoveryResource::EvidenceEdges
                | l2_workbench::recovery::RecoveryResource::EvidenceBlobs
                | l2_workbench::recovery::RecoveryResource::EvidenceBlobBytes
                | l2_workbench::recovery::RecoveryResource::EvidenceTotalDetailsBytes
                | l2_workbench::recovery::RecoveryResource::EvidenceSourceRanges
                | l2_workbench::recovery::RecoveryResource::EvidenceLimitations,
            ..
        } => false,
        _ => true,
    })
}

/// Execute exact plan operations over all retained compatible sources and their outputs
///
/// No file or directory is published here; validated nodes remain in the Case for later
/// publication while the outcome summarizes the recovery pass
#[cfg(test)]
fn execute(
    case: &mut Case,
    plan: &RecoveryPlan,
    policy: &RecoveryExecutionPolicy,
) -> Result<RecoveryExecutionOutcome, RecoveryExecutionError> {
    execute_internal(case, plan, policy, true, None)
}

fn execute_internal(
    case: &mut Case,
    plan: &RecoveryPlan,
    policy: &RecoveryExecutionPolicy,
    snapshot_candidates: bool,
    job: Option<&JobProgress>,
) -> Result<RecoveryExecutionOutcome, RecoveryExecutionError> {
    let policy = resolve_policy(policy.clone())?;
    let resources = policy.resources;
    let case_index_ledger = CaseIndexScanLedger::new()?;
    let mut executor = Executor {
        case,
        plan,
        policy,
        coordinator: RecoveryCoordinator::new(resources),
        case_index: CaseIndex::with_ledger(case_index_ledger),
        candidate_ids: Vec::new(),
        candidate_index: HashSet::new(),
        snapshot_candidates,
        job: job.cloned(),
        validated_artifacts: HashSet::new(),
        transform_cohorts: Vec::new(),
        derived_discovery: derived_discovery::DerivedDiscovery::default(),
        transform_discoveries: HashMap::new(),
        framing_selection_bases: HashMap::new(),
        framing_discoveries: HashMap::new(),
        record_discoveries: HashMap::new(),
        record_discovery_context_by_report: HashMap::new(),
        deferred_record_discovery_plan: None,
        record_schema_report_links: HashMap::new(),
        record_schema_associations_charged: 0,
        record_phase_work_charged: 0,
        pending_record_assemblies: VecDeque::new(),
        pending_record_assembly_count: 0,
        relational_samples: RelationalSampleCollections::default(),
        relational_discoveries: HashMap::new(),
        transform_proposal_receipts: HashMap::new(),
        omissions: Vec::new(),
        complete_negative_transform_searches: 0,
        cycle_skips: 0,
    };

    execute_executor(&mut executor)?;
    finish_executor(executor)
}

fn execute_executor(executor: &mut Executor<'_>) -> Result<(), RecoveryExecutionError> {
    executor.enqueue_framing_discovery_if_enabled()?;
    let seed_nodes = executor.initialize_case_index()?;
    for (node_id, kind) in seed_nodes {
        executor.enqueue_root(node_id, &kind)?;
    }
    let mut record_discovery_barrier_reached = false;
    let mut evidence_stop = None;
    let mut evidence_stop_reported = false;
    loop {
        while let Some(candidate_id) = executor.coordinator.pop_next()? {
            if evidence_stop.is_none() {
                let task = executor
                    .coordinator
                    .candidate(candidate_id)
                    .ok_or(RecoveryError::UnknownCandidate { id: candidate_id })?
                    .task();
                evidence_stop = evidence::saturated_case_evidence(executor.case, task);
            }
            if let Some(stop) = evidence_stop {
                executor.stop_candidate_for_case_evidence(
                    candidate_id,
                    stop,
                    !evidence_stop_reported,
                )?;
                evidence_stop_reported = true;
                continue;
            }

            let omission_start = executor.omissions.len();
            let candidate_task = executor
                .coordinator
                .candidate(candidate_id)
                .ok_or(RecoveryError::UnknownCandidate { id: candidate_id })?
                .task()
                .clone();
            if let Some(progress) = &executor.job {
                progress.begin_candidate(&candidate_task)?;
            }
            if let Err(error) = executor.execute_candidate(candidate_id) {
                evidence_stop = Some(executor.stop_after_case_evidence_error(candidate_id, error)?);
                evidence_stop_reported = true;
                continue;
            }
            if let Some(progress) = &executor.job {
                progress.finish_candidate(candidate_id, &executor.coordinator)?;
            }
            if let Some(stop) = evidence::recent_case_evidence_stop(
                executor
                    .omissions
                    .get(omission_start..)
                    .ok_or(RecoveryError::InvariantFailure)?,
            ) {
                evidence_stop = Some(stop);
                evidence_stop_reported = true;
            }
        }
        if evidence_stop.is_some() {
            break;
        }
        if executor.flush_transform_cohorts()? {
            continue;
        }
        if executor.flush_derived_discovery()? {
            continue;
        }
        if !record_discovery_barrier_reached && executor.plan.discover_records {
            record_discovery_barrier_reached = true;
            executor.enqueue_record_discovery_if_enabled()?;
        }
        if executor.flush_relational_cohorts()? {
            continue;
        }
        if executor.flush_pending_record_assemblies()? {
            continue;
        }
        if executor.enqueue_deferred_record_discovery()? {
            continue;
        }
        break;
    }

    Ok(())
}

fn finish_executor(
    executor: Executor<'_>,
) -> Result<RecoveryExecutionOutcome, RecoveryExecutionError> {
    #[cfg(test)]
    let mut executor = executor;
    let candidate_count = executor.coordinator.candidate_count();
    #[cfg(test)]
    let candidates = snapshot_candidates(&mut executor)?;
    #[cfg(test)]
    let complete = executor.omissions.is_empty() && executor.case.collection_complete();
    let resources = resource_summary(&executor)?;
    Ok(RecoveryExecutionOutcome {
        #[cfg(test)]
        candidates,
        candidate_count,
        complete_negative_transform_searches: executor.complete_negative_transform_searches,
        validated_artifact_count: executor.validated_artifacts.len(),
        omissions: executor.omissions,
        cycle_skips: executor.cycle_skips,
        resources,
        #[cfg(test)]
        complete,
    })
}

fn resource_summary(
    executor: &Executor<'_>,
) -> Result<RecoveryResourceSummary, RecoveryExecutionError> {
    Ok(RecoveryResourceSummary {
        max_input_bytes: executor.policy.resources.max_input_bytes_per_item,
        max_output_bytes: executor.policy.resources.max_output_bytes,
        max_work_bytes: executor.policy.resources.max_work_bytes,
        work_charged_bytes: executor.coordinator.work_bytes_charged(),
        work_remaining_bytes: executor.coordinator.remaining_work_bytes(),
        max_case_index_work_units: executor.case_index.scan_ledger.maximum(),
        case_index_work_units_charged: executor.case_index.scan_ledger.charged(),
        case_index_work_units_remaining: executor.case_index.scan_ledger.remaining()?,
        max_record_phase_work: executor.policy.record_phase_work_limit,
        record_phase_work_charged: executor.record_phase_work_charged,
        record_phase_work_remaining: executor
            .policy
            .record_phase_work_limit
            .checked_sub(executor.record_phase_work_charged)
            .ok_or(RecoveryError::InvariantFailure)?,
        max_candidate_task_identity_bytes: executor
            .policy
            .resources
            .max_candidate_task_identity_bytes,
        candidate_task_identity_bytes_charged: executor
            .coordinator
            .candidate_task_identity_bytes_charged(),
        candidate_task_identity_bytes_remaining: executor
            .coordinator
            .remaining_candidate_task_identity_bytes(),
        max_transform_proposal_identity_bytes: executor
            .policy
            .resources
            .max_transform_proposal_identity_bytes,
        transform_proposal_identity_bytes_charged: executor
            .coordinator
            .transform_proposal_identity_bytes_charged(),
        transform_proposal_identity_bytes_remaining: executor
            .coordinator
            .remaining_transform_proposal_identity_bytes(),
        max_transform_proposal_associations: executor
            .policy
            .resources
            .max_transform_proposal_associations,
        transform_proposal_associations_charged: executor
            .coordinator
            .transform_proposal_associations_charged(),
        transform_proposal_associations_remaining: executor
            .coordinator
            .remaining_transform_proposal_associations(),
        max_parent_links: executor.policy.resources.max_parent_links,
        parent_links_retained: executor.coordinator.parent_links_retained(),
        parent_links_remaining: executor
            .policy
            .resources
            .max_parent_links
            .checked_sub(executor.coordinator.parent_links_retained())
            .ok_or(RecoveryError::InvariantFailure)?,
        max_lineage_work: executor.policy.resources.max_lineage_work,
        lineage_work_charged: executor.coordinator.lineage_work_charged(),
        lineage_work_remaining: executor.coordinator.remaining_lineage_work(),
        max_context_aliases: executor.policy.resources.max_context_aliases,
        context_aliases_retained: executor.coordinator.context_aliases_retained(),
        context_aliases_remaining: executor
            .policy
            .resources
            .max_context_aliases
            .checked_sub(executor.coordinator.context_aliases_retained())
            .ok_or(RecoveryError::InvariantFailure)?,
        max_pending_origin_links: executor.policy.resources.max_pending_origin_links,
        pending_origin_links_retained: executor.coordinator.pending_origin_links_retained(),
        pending_origin_links_remaining: executor
            .policy
            .resources
            .max_pending_origin_links
            .checked_sub(executor.coordinator.pending_origin_links_retained())
            .ok_or(RecoveryError::InvariantFailure)?,
        max_depth: executor.policy.resources.max_depth,
    })
}

#[cfg(test)]
fn snapshot_candidates(
    executor: &mut Executor<'_>,
) -> Result<Vec<l2_workbench::recovery::RecoveryCandidate>, RecoveryExecutionError> {
    let mut candidates = Vec::new();
    if !executor.snapshot_candidates {
        return Ok(candidates);
    }
    executor.candidate_ids.sort_unstable_by_key(|id| id.index());
    candidates
        .try_reserve_exact(executor.candidate_ids.len())
        .map_err(|error| RecoveryExecutionError::Operational {
            stage: RecoveryStage::StructuralValidation,
            source: Box::new(error),
        })?;
    for candidate_id in &executor.candidate_ids {
        let candidate = executor
            .coordinator
            .candidate(*candidate_id)
            .ok_or(RecoveryError::UnknownCandidate { id: *candidate_id })?;
        candidates.push(candidate.clone());
    }
    Ok(candidates)
}

struct Executor<'a> {
    case: &'a mut Case,
    plan: &'a RecoveryPlan,
    policy: RecoveryExecutionPolicy,
    coordinator: RecoveryCoordinator,
    case_index: CaseIndex,
    candidate_ids: Vec<RecoveryCandidateId>,
    candidate_index: HashSet<RecoveryCandidateId>,
    snapshot_candidates: bool,
    job: Option<JobProgress>,
    validated_artifacts: HashSet<String>,
    transform_cohorts: Vec<TransformCohort>,
    derived_discovery: derived_discovery::DerivedDiscovery,
    transform_discoveries: HashMap<RecoveryCandidateId, TransformDiscoveryState>,
    framing_selection_bases: HashMap<RecoveryCandidateId, FramingSelectionBasis>,
    framing_discoveries: HashMap<RecoveryCandidateId, framing_discovery::FramingDiscoveryContext>,
    record_discoveries: HashMap<RecoveryCandidateId, Vec<record_discovery::RecordDiscoveryContext>>,
    record_discovery_context_by_report: HashMap<u64, record_discovery::RecordDiscoveryContext>,
    deferred_record_discovery_plan: Option<record_discovery::RecordDiscoveryPlan>,
    record_schema_report_links:
        HashMap<RecoveryCandidateId, record_discovery::RecordSchemaReportLinks>,
    record_schema_associations_charged: usize,
    record_phase_work_charged: usize,
    pending_record_assemblies: VecDeque<VecDeque<scheduler::PendingRecordAssembly>>,
    pending_record_assembly_count: usize,
    relational_samples: RelationalSampleCollections,
    relational_discoveries: HashMap<RecoveryCandidateId, Vec<RelationalDiscoveryContext>>,
    transform_proposal_receipts: HashMap<RecoveryCandidateId, discovery::OrderedProposalReceipts>,
    omissions: Vec<RecoveryOmission>,
    complete_negative_transform_searches: usize,
    cycle_skips: usize,
}

#[derive(Clone)]
struct JobProgress {
    job: Job,
}

impl JobProgress {
    const fn new(job: Job) -> Self {
        Self { job }
    }

    fn begin_candidate(&self, task: &RecoveryTask) -> Result<(), RecoveryExecutionError> {
        self.job.check_cancelled()?;
        let phase = phase_for_task(task);
        self.job
            .record_work(phase, Counter::CandidatesExamined, 1)?;
        match self.job.set_current(phase, task_progress_label(task)) {
            Ok(()) | Err(JobError::PhaseNotInProgress(_)) => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn finish_candidate(
        &self,
        candidate_id: RecoveryCandidateId,
        coordinator: &RecoveryCoordinator,
    ) -> Result<(), RecoveryExecutionError> {
        let rejected = coordinator
            .candidate(candidate_id)
            .is_some_and(|candidate| {
                matches!(
                    candidate.state(),
                    l2_workbench::recovery::RecoveryCandidateState::Finished {
                        result: l2_workbench::recovery::RecoveryResult::Rejected { .. },
                        ..
                    }
                )
            });
        if rejected {
            self.job.increment(Counter::CandidatesRejected, 1)?;
        }
        Ok(())
    }
}

const fn task_progress_label(task: &RecoveryTask) -> &'static str {
    match task {
        RecoveryTask::Transform(_) => "running transform",
        RecoveryTask::TransformDiscovery => "discovering transforms",
        RecoveryTask::FramingDiscovery => "discovering framing",
        RecoveryTask::MaterializeFraming(_) => "materializing frames",
        RecoveryTask::RecordDiscovery => "discovering records",
        RecoveryTask::RelationalTransformDiscovery => "discovering relational transforms",
        RecoveryTask::AssembleRecords(_) => "assembling records",
        RecoveryTask::EmbeddedDiscovery => "discovering embedded content",
        RecoveryTask::StructuralValidation => "validating structure",
        RecoveryTask::RecursiveExpansion => "expanding validated content",
    }
}

const fn phase_for_task(task: &RecoveryTask) -> Phase {
    match task {
        RecoveryTask::FramingDiscovery
        | RecoveryTask::MaterializeFraming(_)
        | RecoveryTask::RecordDiscovery => Phase::FramingRecordDiscovery,
        RecoveryTask::TransformDiscovery | RecoveryTask::RelationalTransformDiscovery => {
            Phase::TransformDiscovery
        }
        RecoveryTask::Transform(_)
        | RecoveryTask::AssembleRecords(_)
        | RecoveryTask::EmbeddedDiscovery
        | RecoveryTask::StructuralValidation
        | RecoveryTask::RecursiveExpansion => Phase::AssemblyValidation,
    }
}

impl Executor<'_> {
    fn initialize_case_index(&mut self) -> Result<Vec<(u64, String)>, RecoveryExecutionError> {
        self.case_index.initialize(self.case)
    }

    fn refresh_case_index(&mut self) -> Result<(), RecoveryExecutionError> {
        self.case_index.refresh(self.case)
    }
}

type EdgeIdentity = (u64, u64, String, u8, String);
type ContextualDecodingViewKey = (String, u64, u64);

#[derive(Default)]
struct CaseIndex {
    node_positions: HashMap<u64, usize>,
    blob_positions: HashMap<String, usize>,
    edge_identities: HashSet<EdgeIdentity>,
    decoding_outputs: HashMap<u64, u64>,
    contextual_decoding_views: HashMap<ContextualDecodingViewKey, u64>,
    validated_ranges_by_receipt: HashMap<u64, BTreeSet<u64>>,
    has_relational_frames: bool,
    node_count: usize,
    blob_count: usize,
    edge_count: usize,
    scan_ledger: CaseIndexScanLedger,
}

impl CaseIndex {
    fn with_ledger(scan_ledger: CaseIndexScanLedger) -> Self {
        Self {
            scan_ledger,
            ..Self::default()
        }
    }

    #[cfg(test)]
    fn new(case: &Case) -> Result<Self, RecoveryExecutionError> {
        let mut index = Self::with_ledger(CaseIndexScanLedger::new()?);
        index.initialize(case)?;
        Ok(index)
    }

    fn initialize(&mut self, case: &Case) -> Result<Vec<(u64, String)>, RecoveryExecutionError> {
        let scan_bound = case_index_scan_bound(case)?;
        if scan_bound > self.scan_ledger.remaining()? {
            return Err(RecoveryError::InvariantFailure.into());
        }
        let (actual_work, seeds) = self.refresh_inner(case, true)?;
        if actual_work > scan_bound {
            return Err(RecoveryError::InvariantFailure.into());
        }
        self.scan_ledger.charge(scan_bound, actual_work)?;
        Ok(seeds)
    }

    fn refresh(&mut self, case: &Case) -> Result<(), RecoveryExecutionError> {
        let scan_bound =
            case_index_suffix_scan_bound(self.node_count, self.blob_count, self.edge_count, case)?;
        if scan_bound > self.scan_ledger.remaining()? {
            return Err(RecoveryError::InvariantFailure.into());
        }
        let (actual_work, _) = self.refresh_inner(case, false)?;
        if actual_work > scan_bound {
            return Err(RecoveryError::InvariantFailure.into());
        }
        self.scan_ledger.charge(scan_bound, actual_work)
    }

    fn validated_range_inputs(&self, validation_node_id: u64) -> Option<&BTreeSet<u64>> {
        self.validated_ranges_by_receipt.get(&validation_node_id)
    }

    fn refresh_inner(
        &mut self,
        case: &Case,
        collect_seeds: bool,
    ) -> Result<(usize, Vec<(u64, String)>), RecoveryExecutionError> {
        if self.node_count > case.nodes().len()
            || self.blob_count > case.blobs().len()
            || self.edge_count > case.edges().len()
        {
            return Err(RecoveryError::InvariantFailure.into());
        }

        let mut seeds = Vec::new();
        if collect_seeds {
            seeds
                .try_reserve_exact(case.nodes().len())
                .map_err(|source| RecoveryExecutionError::Operational {
                    stage: RecoveryStage::StructuralValidation,
                    source: Box::new(source),
                })?;
        }
        let mut work = self.index_new_nodes(case, collect_seeds, &mut seeds)?;
        work = work
            .checked_add(self.index_new_blobs(case)?)
            .ok_or(RecoveryError::InvariantFailure)?;
        work = work
            .checked_add(self.index_new_edges(case)?)
            .ok_or(RecoveryError::InvariantFailure)?;

        self.node_count = case.nodes().len();
        self.blob_count = case.blobs().len();
        self.edge_count = case.edges().len();
        let roots = if collect_seeds {
            let (roots, sort_work) = sort_root_seeds(&seeds)?;
            work = work
                .checked_add(sort_work)
                .ok_or(RecoveryError::InvariantFailure)?;
            roots
        } else {
            Vec::new()
        };
        Ok((work, roots))
    }

    fn index_new_nodes(
        &mut self,
        case: &Case,
        collect_seeds: bool,
        seeds: &mut Vec<RootSeed>,
    ) -> Result<usize, RecoveryExecutionError> {
        let mut work = 0_usize;
        for (position, node) in case.nodes().iter().enumerate().skip(self.node_count) {
            self.node_positions.insert(node.id, position);
            // Cache this marker while visiting new nodes, before validation needs lineage
            self.has_relational_frames |= node.kind == relational::DECODED_FRAME_KIND;
            work = work
                .checked_add(std::mem::size_of::<u64>())
                .and_then(|total| total.checked_add(std::mem::size_of::<usize>()))
                .and_then(|total| total.checked_add(node.kind.len()))
                .and_then(|total| total.checked_add(node.blob.as_deref().map_or(0, str::len)))
                .ok_or(RecoveryError::InvariantFailure)?;
            if node.kind == "decoding_output"
                && let (Some(blob_id), Some(receipt_node), Some(input_node)) = (
                    node.blob.as_ref(),
                    node.details
                        .get("shared_transform_receipt")
                        .and_then(serde_json::Value::as_u64),
                    node.details
                        .get("source_input_node")
                        .and_then(serde_json::Value::as_u64),
                )
            {
                work = work
                    .checked_add(blob_id.len())
                    .and_then(|total| total.checked_add(2 * std::mem::size_of::<u64>()))
                    .ok_or(RecoveryError::InvariantFailure)?;
                self.contextual_decoding_views
                    .entry((blob_id.clone(), receipt_node, input_node))
                    .or_insert(node.id);
            }
            if collect_seeds
                && let (Some(priority), Some(blob_id)) =
                    (source_priority(&node.kind), node.blob.as_ref())
            {
                seeds
                    .try_reserve(1)
                    .map_err(|source| RecoveryExecutionError::Operational {
                        stage: RecoveryStage::StructuralValidation,
                        source: Box::new(source),
                    })?;
                work = work
                    .checked_add(2)
                    .and_then(|total| total.checked_add(std::mem::size_of::<u64>()))
                    .and_then(|total| total.checked_add(node.kind.len()))
                    .and_then(|total| total.checked_add(blob_id.len()))
                    .ok_or(RecoveryError::InvariantFailure)?;
                seeds.push(RootSeed {
                    priority,
                    node_id: node.id,
                    kind: node.kind.clone(),
                    blob_id: blob_id.clone(),
                });
            }
        }
        Ok(work)
    }

    fn index_new_blobs(&mut self, case: &Case) -> Result<usize, RecoveryExecutionError> {
        let mut work = 0_usize;
        for (position, blob) in case.blobs().iter().enumerate().skip(self.blob_count) {
            self.blob_positions.insert(blob.id.clone(), position);
            work = work
                .checked_add(blob.id.len())
                .and_then(|total| total.checked_add(std::mem::size_of::<usize>()))
                .ok_or(RecoveryError::InvariantFailure)?;
        }
        Ok(work)
    }

    fn index_new_edges(&mut self, case: &Case) -> Result<usize, RecoveryExecutionError> {
        let mut work = 0_usize;
        for edge in case.edges().iter().skip(self.edge_count) {
            self.edge_identities.insert(edge_identity(
                edge.from,
                edge.to,
                &edge.relation,
                edge.status,
                &edge.reason,
            ));
            work = work
                .checked_add(edge.relation.len())
                .and_then(|total| total.checked_add(edge.reason.len()))
                .and_then(|total| total.checked_add(17))
                .ok_or(RecoveryError::InvariantFailure)?;
            if edge.relation == "produced"
                && let Some(target) = self
                    .node_positions
                    .get(&edge.to)
                    .and_then(|position| case.nodes().get(*position))
            {
                work = work
                    .checked_add(target.kind.len())
                    .ok_or(RecoveryError::InvariantFailure)?;
                if target.kind == "decoding_output" {
                    self.decoding_outputs.entry(edge.from).or_insert(edge.to);
                }
            }
            if edge.relation == "validated_range" && edge.status == EvidenceStatus::Observed {
                let inputs = self.validated_ranges_by_receipt.entry(edge.to).or_default();
                if inputs.insert(edge.from) {
                    let map_entry_bytes = if inputs.len() == 1 {
                        2 * std::mem::size_of::<u64>()
                    } else {
                        std::mem::size_of::<u64>()
                    };
                    work = work
                        .checked_add(map_entry_bytes)
                        .ok_or(RecoveryError::InvariantFailure)?;
                }
            }
        }
        Ok(work)
    }
}

struct RootSeed {
    priority: (u8, u8),
    node_id: u64,
    kind: String,
    blob_id: String,
}

fn sort_root_seeds(
    seeds: &[RootSeed],
) -> Result<(Vec<(u64, String)>, usize), RecoveryExecutionError> {
    if seeds.len() <= 1 {
        return collect_root_seed_order(seeds, 0..seeds.len(), 0);
    }

    let mut order = Vec::new();
    order
        .try_reserve_exact(seeds.len())
        .map_err(|source| RecoveryExecutionError::Operational {
            stage: RecoveryStage::StructuralValidation,
            source: Box::new(source),
        })?;
    order.extend(0..seeds.len());
    let mut scratch = Vec::new();
    scratch.try_reserve_exact(seeds.len()).map_err(|source| {
        RecoveryExecutionError::Operational {
            stage: RecoveryStage::StructuralValidation,
            source: Box::new(source),
        }
    })?;
    scratch.resize(seeds.len(), 0_usize);
    let mut work = 0_usize;
    for pass in 0..INDEX_RADIX_PASSES {
        let mut counts = root_seed_bucket_offsets(seeds, &order, pass)?;
        distribute_root_seed_pass(seeds, &order, &mut counts, &mut scratch, pass)?;
        std::mem::swap(&mut order, &mut scratch);
        work = work
            .checked_add(
                seeds
                    .len()
                    .checked_mul(2)
                    .ok_or(RecoveryError::InvariantFailure)?,
            )
            .and_then(|total| total.checked_add(256))
            .ok_or(RecoveryError::InvariantFailure)?;
    }
    collect_root_seed_order(seeds, order, work)
}

fn root_seed_bucket_offsets(
    seeds: &[RootSeed],
    order: &[usize],
    pass: usize,
) -> Result<[usize; 256], RecoveryExecutionError> {
    let mut counts = [0_usize; 256];
    for index in order {
        let seed = seeds.get(*index).ok_or(RecoveryError::InvariantFailure)?;
        let bucket = usize::from(root_seed_sort_byte(seed, pass)?);
        let count = counts
            .get_mut(bucket)
            .ok_or(RecoveryError::InvariantFailure)?;
        *count = count
            .checked_add(1)
            .ok_or(RecoveryError::InvariantFailure)?;
    }
    let mut next_position = 0_usize;
    for count in &mut counts {
        let current = *count;
        *count = next_position;
        next_position = next_position
            .checked_add(current)
            .ok_or(RecoveryError::InvariantFailure)?;
    }
    Ok(counts)
}

fn distribute_root_seed_pass(
    seeds: &[RootSeed],
    order: &[usize],
    counts: &mut [usize; 256],
    scratch: &mut [usize],
    pass: usize,
) -> Result<(), RecoveryExecutionError> {
    for index in order {
        let seed = seeds.get(*index).ok_or(RecoveryError::InvariantFailure)?;
        let bucket = usize::from(root_seed_sort_byte(seed, pass)?);
        let position = counts
            .get_mut(bucket)
            .ok_or(RecoveryError::InvariantFailure)?;
        let destination = scratch
            .get_mut(*position)
            .ok_or(RecoveryError::InvariantFailure)?;
        *destination = *index;
        *position = position
            .checked_add(1)
            .ok_or(RecoveryError::InvariantFailure)?;
    }
    Ok(())
}

fn collect_root_seed_order(
    seeds: &[RootSeed],
    order: impl IntoIterator<Item = usize>,
    mut work: usize,
) -> Result<(Vec<(u64, String)>, usize), RecoveryExecutionError> {
    let mut roots = Vec::new();
    roots
        .try_reserve_exact(seeds.len())
        .map_err(|source| RecoveryExecutionError::Operational {
            stage: RecoveryStage::StructuralValidation,
            source: Box::new(source),
        })?;
    for index in order {
        let seed = seeds.get(index).ok_or(RecoveryError::InvariantFailure)?;
        roots.push((seed.node_id, seed.kind.clone()));
        work = work
            .checked_add(seed.kind.len())
            .ok_or(RecoveryError::InvariantFailure)?;
    }
    Ok((roots, work))
}

fn root_seed_sort_byte(seed: &RootSeed, pass: usize) -> Result<u8, RecoveryExecutionError> {
    const NODE_ID_BYTES: usize = std::mem::size_of::<u64>();
    if pass < NODE_ID_BYTES {
        let byte = seed
            .node_id
            .to_le_bytes()
            .get(pass)
            .copied()
            .ok_or(RecoveryError::InvariantFailure)?;
        return Ok(byte);
    }
    if pass < NODE_ID_BYTES + CONTENT_ID_BYTES {
        let byte_index = CONTENT_ID_BYTES
            .checked_sub(1)
            .and_then(|last| last.checked_sub(pass - NODE_ID_BYTES))
            .ok_or(RecoveryError::InvariantFailure)?;
        let byte = seed
            .blob_id
            .as_bytes()
            .get(byte_index)
            .copied()
            .ok_or(RecoveryError::InvariantFailure)?;
        return Ok(byte);
    }
    if pass == NODE_ID_BYTES + CONTENT_ID_BYTES {
        return Ok(seed.priority.1);
    }
    if pass == NODE_ID_BYTES + CONTENT_ID_BYTES + 1 {
        return Ok(seed.priority.0);
    }
    Err(RecoveryError::InvariantFailure.into())
}

fn edge_identity(
    from: u64,
    to: u64,
    relation: &str,
    status: EvidenceStatus,
    reason: &str,
) -> EdgeIdentity {
    let status = match status {
        EvidenceStatus::Observed => 0,
        EvidenceStatus::Hypothesis => 1,
        EvidenceStatus::ConstraintSatisfied => 2,
        EvidenceStatus::ConstraintFailed => 3,
        EvidenceStatus::Unresolved => 4,
    };
    (from, to, relation.to_owned(), status, reason.to_owned())
}

#[cfg(test)]
#[path = "../../../tests/workbench/recovery_framing_discovery.rs"]
mod framing_discovery_tests;
#[cfg(test)]
#[path = "../../../tests/workbench/recovery_record_associations.rs"]
mod record_association_tests;
#[cfg(test)]
#[path = "../../../tests/workbench/recovery_record_discovery.rs"]
mod record_discovery_tests;
#[cfg(test)]
#[path = "../../../tests/workbench/recovery_record_work_budget.rs"]
mod record_work_budget_tests;
#[cfg(test)]
#[path = "../../../tests/workbench/recovery_executor_support.rs"]
mod test_support;
#[cfg(test)]
#[path = "../../../tests/workbench/recovery_executor.rs"]
mod tests;
