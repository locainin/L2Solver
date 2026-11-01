//! Saved executor data without live jobs, leases, or derived indexes

use super::super::{
    Case, CaseIndex, Executor, FramingSelectionBasis, RecoveryCandidateId, RecoveryCoordinator,
    RecoveryError, RecoveryExecutionPolicy, RecoveryOmission, RecoveryPlan,
    RelationalDiscoveryContext, RelationalSampleCollections, TransformCohort,
    TransformDiscoveryState, derived_discovery, discovery, framing_discovery, record_discovery,
    scheduler,
};
use l2_workbench::job::MemoryBudget;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Serialize)]
pub(super) struct StateRef<'a> {
    candidate_ids: &'a Vec<RecoveryCandidateId>,
    snapshot_candidates: &'a bool,
    #[serde(with = "super::collections::hash_set")]
    validated_artifacts: &'a HashSet<String>,
    transform_cohorts: &'a Vec<TransformCohort>,
    derived_discovery: &'a derived_discovery::DerivedDiscovery,
    #[serde(with = "super::collections::hash_map")]
    transform_discoveries: &'a HashMap<RecoveryCandidateId, TransformDiscoveryState>,
    #[serde(with = "super::collections::hash_map")]
    framing_selection_bases: &'a HashMap<RecoveryCandidateId, FramingSelectionBasis>,
    #[serde(with = "super::collections::hash_map")]
    framing_discoveries:
        &'a HashMap<RecoveryCandidateId, framing_discovery::FramingDiscoveryContext>,
    deferred_record_discovery_plan: &'a Option<record_discovery::RecordDiscoveryPlan>,
    #[serde(with = "super::collections::hash_map")]
    record_schema_report_links:
        &'a HashMap<RecoveryCandidateId, record_discovery::RecordSchemaReportLinks>,
    record_schema_associations_charged: &'a usize,
    record_phase_work_charged: &'a usize,
    pending_record_assemblies: &'a VecDeque<VecDeque<scheduler::PendingRecordAssembly>>,
    pending_record_suffixes: &'a VecDeque<record_discovery::PendingRecordSuffix>,
    relational_samples: &'a RelationalSampleCollections,
    #[serde(with = "super::collections::hash_map")]
    relational_discoveries: &'a HashMap<RecoveryCandidateId, Vec<RelationalDiscoveryContext>>,
    #[serde(with = "super::collections::hash_map")]
    transform_proposal_receipts:
        &'a HashMap<RecoveryCandidateId, discovery::OrderedProposalReceipts>,
    omissions: &'a Vec<RecoveryOmission>,
    complete_negative_transform_searches: &'a usize,
    cycle_skips: &'a usize,
    records: record_discovery::checkpoint::ContextsRef<'a>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    candidate_ids: Vec<RecoveryCandidateId>,
    snapshot_candidates: bool,
    #[serde(with = "super::collections::hash_set")]
    validated_artifacts: HashSet<String>,
    transform_cohorts: Vec<TransformCohort>,
    derived_discovery: derived_discovery::DerivedDiscovery,
    #[serde(with = "super::collections::hash_map")]
    transform_discoveries: HashMap<RecoveryCandidateId, TransformDiscoveryState>,
    #[serde(with = "super::collections::hash_map")]
    framing_selection_bases: HashMap<RecoveryCandidateId, FramingSelectionBasis>,
    #[serde(with = "super::collections::hash_map")]
    framing_discoveries: HashMap<RecoveryCandidateId, framing_discovery::FramingDiscoveryContext>,
    deferred_record_discovery_plan: Option<record_discovery::RecordDiscoveryPlan>,
    #[serde(with = "super::collections::hash_map")]
    record_schema_report_links:
        HashMap<RecoveryCandidateId, record_discovery::RecordSchemaReportLinks>,
    record_schema_associations_charged: usize,
    record_phase_work_charged: usize,
    pending_record_assemblies: VecDeque<VecDeque<scheduler::PendingRecordAssembly>>,
    pending_record_suffixes: VecDeque<record_discovery::PendingRecordSuffix>,
    relational_samples: RelationalSampleCollections,
    #[serde(with = "super::collections::hash_map")]
    relational_discoveries: HashMap<RecoveryCandidateId, Vec<RelationalDiscoveryContext>>,
    #[serde(with = "super::collections::hash_map")]
    transform_proposal_receipts: HashMap<RecoveryCandidateId, discovery::OrderedProposalReceipts>,
    omissions: Vec<RecoveryOmission>,
    complete_negative_transform_searches: usize,
    cycle_skips: usize,
    records: record_discovery::checkpoint::Contexts,
}

impl<'a> StateRef<'a> {
    pub(super) fn capture(executor: &'a Executor<'_>) -> Result<Self, RecoveryError> {
        Ok(Self {
            candidate_ids: &executor.candidate_ids,
            snapshot_candidates: &executor.snapshot_candidates,
            validated_artifacts: &executor.validated_artifacts,
            transform_cohorts: &executor.transform_cohorts,
            derived_discovery: &executor.derived_discovery,
            transform_discoveries: &executor.transform_discoveries,
            framing_selection_bases: &executor.framing_selection_bases,
            framing_discoveries: &executor.framing_discoveries,
            deferred_record_discovery_plan: &executor.deferred_record_discovery_plan,
            record_schema_report_links: &executor.record_schema_report_links,
            record_schema_associations_charged: &executor.record_schema_associations_charged,
            record_phase_work_charged: &executor.record_phase_work_charged,
            pending_record_assemblies: &executor.pending_record_assemblies,
            pending_record_suffixes: &executor.pending_record_suffixes,
            relational_samples: &executor.relational_samples,
            relational_discoveries: &executor.relational_discoveries,
            transform_proposal_receipts: &executor.transform_proposal_receipts,
            omissions: &executor.omissions,
            complete_negative_transform_searches: &executor.complete_negative_transform_searches,
            cycle_skips: &executor.cycle_skips,
            records: record_discovery::checkpoint::ContextsRef::capture(
                &executor.record_discoveries,
                &executor.record_discovery_context_by_report,
            )?,
        })
    }
}

impl State {
    pub(super) fn restore<'a>(
        self,
        case: &'a mut Case,
        plan: &'a RecoveryPlan,
        policy: RecoveryExecutionPolicy,
        coordinator: RecoveryCoordinator,
        case_index: CaseIndex,
        memory: Option<&MemoryBudget>,
    ) -> Result<Executor<'a>, RecoveryError> {
        let mut candidate_index = HashSet::new();
        candidate_index
            .try_reserve(self.candidate_ids.len())
            .map_err(|_| RecoveryError::AllocationFailed)?;
        for id in &self.candidate_ids {
            if coordinator.candidate(*id).is_none() || !candidate_index.insert(*id) {
                return Err(RecoveryError::InvalidCheckpoint);
            }
        }
        let (record_discoveries, record_discovery_context_by_report) = self.records.restore()?;
        let pending_record_assembly_count = self
            .pending_record_assemblies
            .iter()
            .try_fold(0_usize, |count, group| count.checked_add(group.len()))
            .ok_or(RecoveryError::InvalidCheckpoint)?;
        Ok(Executor {
            memory: memory.cloned(),
            checkpoint_memory: None,
            case,
            plan,
            policy,
            coordinator,
            case_index,
            candidate_index,
            job: None,
            pending_record_assembly_count,
            record_discoveries,
            record_discovery_context_by_report,
            candidate_ids: self.candidate_ids,
            snapshot_candidates: self.snapshot_candidates,
            validated_artifacts: self.validated_artifacts,
            transform_cohorts: self.transform_cohorts,
            derived_discovery: self.derived_discovery,
            transform_discoveries: self.transform_discoveries,
            framing_selection_bases: self.framing_selection_bases,
            framing_discoveries: self.framing_discoveries,
            deferred_record_discovery_plan: self.deferred_record_discovery_plan,
            record_schema_report_links: self.record_schema_report_links,
            record_schema_associations_charged: self.record_schema_associations_charged,
            record_phase_work_charged: self.record_phase_work_charged,
            pending_record_assemblies: self.pending_record_assemblies,
            pending_record_suffixes: self.pending_record_suffixes,
            relational_samples: self.relational_samples,
            relational_discoveries: self.relational_discoveries,
            transform_proposal_receipts: self.transform_proposal_receipts,
            omissions: self.omissions,
            complete_negative_transform_searches: self.complete_negative_transform_searches,
            cycle_skips: self.cycle_skips,
            family_memory: Vec::new(),
        })
    }
}
