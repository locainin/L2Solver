use super::super::framing_materialize::FramingSelectionBasis;
use super::evidence::add_transaction_edge;
use super::evidence::{add_transaction_links, canonical_result_link};
use super::lineage::DerivedTaskEnqueue;
use super::policy::task_templates_for_node;
use super::validation::classify_validation;
use super::{
    CONTEXT_REASON, DERIVED_REASON, Executor, RECORD_SCHEMA_SELECTED_FROM_REASON,
    RecoveryCandidateId, RecoveryExecutionError, RecoveryExecutionPolicy, RecoveryOmission,
    RecoveryStage, RecoveryTask, TransformSlot,
};
use l2_workbench::{
    artifact::ArtifactValidator,
    evidence::{Edge, EvidenceError, EvidenceStatus},
    protocol::{FramingKind, RecordSchema},
    recovery::{
        ContextRegistration, EnqueueOutcome, RecoveryCandidateState, RecoveryError,
        RecoveryResource, RecoveryResult,
    },
};
use std::collections::{BTreeSet, HashSet, VecDeque};

struct CandidateInputs {
    task: RecoveryTask,
    input_node: u64,
    origins: Vec<u64>,
    input_length: usize,
}

#[derive(Clone, Copy)]
enum ChildTaskPolicy {
    Standard,
    TransformCohort,
    DiscoveredRecords,
}

pub(super) struct PendingRecordAssembly {
    input_node_ids: Vec<u64>,
    parent_child_pairs: Option<Vec<(RecoveryCandidateId, u64)>>,
    schema: RecordSchema,
    report_node_id: Option<u64>,
}

const fn transform_input_limit(
    task: &RecoveryTask,
    input_length: usize,
    policy: &RecoveryExecutionPolicy,
) -> Option<(RecoveryResource, usize)> {
    match task {
        RecoveryTask::Transform(_) if input_length > policy.derivation_limits.max_input_bytes => {
            Some((
                RecoveryResource::InputBytesPerItem,
                policy.derivation_limits.max_input_bytes,
            ))
        }
        RecoveryTask::Transform(_)
            if input_length > policy.decode_batch_limits.total_input_bytes =>
        {
            Some((
                RecoveryResource::TotalInputBytes,
                policy.decode_batch_limits.total_input_bytes,
            ))
        }
        _ => None,
    }
}

impl Executor<'_> {
    /// Whether the queued task should run before another deferred assembly
    pub(super) fn next_candidate_precedes_deferred_assembly(&self) -> bool {
        self.coordinator
            .peek_next_id()
            .and_then(|candidate_id| self.coordinator.candidate(candidate_id))
            .is_some_and(|candidate| {
                candidate.completion_priority()
                    || candidate.task() == &RecoveryTask::RecordDiscovery
            })
    }

    pub(super) fn enqueue_root(
        &mut self,
        node_id: u64,
        kind: &str,
    ) -> Result<(), RecoveryExecutionError> {
        for task in self.tasks_for_node(kind, false) {
            if let RecoveryTask::AssembleRecords(schema) = &task {
                self.defer_root_record_assembly(node_id, schema)?;
                continue;
            }
            let result = self.coordinator.enqueue(self.case, node_id, task.clone())?;
            let candidate_id = enqueue_candidate_id(&result);
            let framing_candidate = match &result {
                EnqueueOutcome::Queued(id)
                | EnqueueOutcome::Merged(id)
                | EnqueueOutcome::MergedNeedsContext(id) => Some(*id),
                EnqueueOutcome::CycleSkipped { .. } | EnqueueOutcome::ResourceExhausted { .. } => {
                    None
                }
            };
            self.record_enqueue(result, &task, &[node_id])?;
            if let (RecoveryTask::TransformDiscovery, Some(candidate_id)) = (&task, candidate_id) {
                self.register_transform_discovery_context(candidate_id, None, node_id)?;
            }
            if let (RecoveryTask::MaterializeFraming(_), Some(candidate_id)) =
                (&task, framing_candidate)
            {
                self.remember_caller_framing_basis(candidate_id);
            }
        }
        Ok(())
    }

    pub(super) fn enqueue_discovered_framing(
        &mut self,
        input_node: u64,
        rule: &FramingKind,
        report_node: u64,
    ) -> Result<(), RecoveryExecutionError> {
        let task = RecoveryTask::MaterializeFraming(rule.clone());
        let result = self
            .coordinator
            .enqueue(self.case, input_node, task.clone())?;
        let scheduled_candidate = match &result {
            EnqueueOutcome::Queued(id) => Some((*id, false)),
            EnqueueOutcome::Merged(id) | EnqueueOutcome::MergedNeedsContext(id) => {
                Some((*id, true))
            }
            EnqueueOutcome::CycleSkipped { .. } | EnqueueOutcome::ResourceExhausted { .. } => None,
        };
        self.record_enqueue(result, &task, &[input_node])?;
        if let Some((candidate_id, merged)) = scheduled_candidate {
            self.remember_discovered_framing_basis(candidate_id, report_node, merged)?;
        }
        Ok(())
    }

    pub(super) fn enqueue_discovered_framing_derived(
        &mut self,
        parent_id: RecoveryCandidateId,
        input_node: u64,
        rule: &FramingKind,
        report_node: u64,
    ) -> Result<(), RecoveryExecutionError> {
        let task = RecoveryTask::MaterializeFraming(rule.clone());
        let result =
            self.coordinator
                .enqueue_derived(parent_id, self.case, &[input_node], task.clone())?;
        let scheduled_candidate = match &result {
            EnqueueOutcome::Queued(id) => Some((*id, false)),
            EnqueueOutcome::Merged(id) | EnqueueOutcome::MergedNeedsContext(id) => {
                Some((*id, true))
            }
            EnqueueOutcome::CycleSkipped { .. } | EnqueueOutcome::ResourceExhausted { .. } => None,
        };
        self.record_enqueue(result, &task, &[input_node])?;
        if let Some((candidate_id, merged)) = scheduled_candidate {
            self.remember_discovered_framing_basis(candidate_id, report_node, merged)?;
        }
        Ok(())
    }

    fn remember_caller_framing_basis(&mut self, candidate_id: RecoveryCandidateId) {
        match self.framing_selection_bases.entry(candidate_id) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(FramingSelectionBasis::CallerSupplied {});
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                if let FramingSelectionBasis::Discovered { report_node } = *entry.get() {
                    entry.insert(FramingSelectionBasis::CallerAndDiscovered { report_node });
                }
            }
        }
    }

    fn remember_discovered_framing_basis(
        &mut self,
        candidate_id: RecoveryCandidateId,
        report_node: u64,
        merged: bool,
    ) -> Result<(), RecoveryExecutionError> {
        match self.framing_selection_bases.entry(candidate_id) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                let basis = if merged {
                    FramingSelectionBasis::CallerAndDiscovered { report_node }
                } else {
                    FramingSelectionBasis::Discovered { report_node }
                };
                entry.insert(basis);
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => match *entry.get() {
                FramingSelectionBasis::CallerSupplied {} => {
                    entry.insert(FramingSelectionBasis::CallerAndDiscovered { report_node });
                }
                FramingSelectionBasis::Discovered {
                    report_node: retained,
                }
                | FramingSelectionBasis::CallerAndDiscovered {
                    report_node: retained,
                } => {
                    if retained != report_node {
                        return Err(RecoveryError::InvariantFailure.into());
                    }
                }
            },
        }
        Ok(())
    }

    pub(super) fn enqueue_derived_children(
        &mut self,
        parent_id: RecoveryCandidateId,
        children: &[u64],
        include_expansion: bool,
    ) -> Result<(), RecoveryExecutionError> {
        self.enqueue_derived_children_with_policy(
            parent_id,
            children,
            include_expansion,
            ChildTaskPolicy::Standard,
        )
    }

    pub(super) fn enqueue_derived_children_filtered(
        &mut self,
        parent_id: RecoveryCandidateId,
        children: &[u64],
        include_expansion: bool,
        skip_cohort_tasks: bool,
    ) -> Result<(), RecoveryExecutionError> {
        let policy = if skip_cohort_tasks {
            ChildTaskPolicy::TransformCohort
        } else {
            ChildTaskPolicy::Standard
        };
        self.enqueue_derived_children_with_policy(parent_id, children, include_expansion, policy)
    }

    pub(super) fn enqueue_discovered_record_children(
        &mut self,
        parent_id: RecoveryCandidateId,
        children: &[u64],
    ) -> Result<(), RecoveryExecutionError> {
        self.enqueue_derived_children_with_policy(
            parent_id,
            children,
            false,
            ChildTaskPolicy::DiscoveredRecords,
        )
    }

    fn enqueue_derived_children_with_policy(
        &mut self,
        parent_id: RecoveryCandidateId,
        children: &[u64],
        include_expansion: bool,
        policy: ChildTaskPolicy,
    ) -> Result<(), RecoveryExecutionError> {
        let parent_result = self.derived_result(parent_id)?;
        let mut unique = BTreeSet::new();
        for child_id in children.iter().copied() {
            if !unique.insert(child_id) {
                continue;
            }
            let child = self
                .case
                .node(child_id)
                .ok_or(RecoveryError::UnknownEvidenceNode { node_id: child_id })?;
            let child_kind = child.kind.clone();
            let child_details = child.details.clone();
            for task in self.tasks_for_node(&child_kind, include_expansion) {
                let allowed = match policy {
                    ChildTaskPolicy::Standard => true,
                    ChildTaskPolicy::TransformCohort => !matches!(
                        task,
                        RecoveryTask::Transform(_) | RecoveryTask::AssembleRecords(_)
                    ),
                    ChildTaskPolicy::DiscoveredRecords => {
                        super::records::discovered_record_task_allowed(
                            &child_kind,
                            &child_details,
                            &task,
                        )
                    }
                };
                if !allowed {
                    continue;
                }
                self.ensure_edge(
                    child_id,
                    parent_result,
                    "derived_from",
                    EvidenceStatus::Observed,
                    DERIVED_REASON,
                )?;
                self.enqueue_derived_task(parent_id, child_id, &task)?;
            }
        }
        Ok(())
    }

    pub(super) fn enqueue_derived_task(
        &mut self,
        parent_id: RecoveryCandidateId,
        child_id: u64,
        task: &RecoveryTask,
    ) -> Result<Option<RecoveryCandidateId>, RecoveryExecutionError> {
        if let RecoveryTask::AssembleRecords(schema) = task {
            self.defer_derived_record_assembly(parent_id, child_id, schema)?;
            return Ok(None);
        }
        match self.enqueue_derived_task_detailed(parent_id, child_id, task)? {
            DerivedTaskEnqueue::Candidate(candidate)
            | DerivedTaskEnqueue::CycleSkipped(candidate) => Ok(Some(candidate)),
            DerivedTaskEnqueue::ResourceExhausted => Ok(None),
        }
    }

    pub(super) fn enqueue_validated_task(
        &mut self,
        parent_id: RecoveryCandidateId,
        child_id: u64,
        task: &RecoveryTask,
    ) -> Result<Option<RecoveryCandidateId>, RecoveryExecutionError> {
        let result =
            self.coordinator
                .enqueue_validated(parent_id, self.case, &[child_id], task.clone())?;
        let candidate_id = enqueue_candidate_id(&result);
        self.record_completion_enqueue_from_parent(result, parent_id, task, &[child_id])?;
        Ok(candidate_id)
    }

    pub(super) fn enqueue_derived_task_detailed(
        &mut self,
        parent_id: RecoveryCandidateId,
        child_id: u64,
        task: &RecoveryTask,
    ) -> Result<DerivedTaskEnqueue, RecoveryExecutionError> {
        let result =
            self.coordinator
                .enqueue_derived(parent_id, self.case, &[child_id], task.clone())?;
        let outcome = match &result {
            EnqueueOutcome::Queued(id)
            | EnqueueOutcome::Merged(id)
            | EnqueueOutcome::MergedNeedsContext(id) => DerivedTaskEnqueue::Candidate(*id),
            EnqueueOutcome::CycleSkipped { candidate_id } => {
                DerivedTaskEnqueue::CycleSkipped(*candidate_id)
            }
            EnqueueOutcome::ResourceExhausted { .. } => DerivedTaskEnqueue::ResourceExhausted,
        };
        self.record_completion_enqueue_from_parent(result, parent_id, task, &[child_id])?;
        if let (RecoveryTask::TransformDiscovery, DerivedTaskEnqueue::Candidate(candidate)) =
            (task, &outcome)
        {
            self.register_transform_discovery_context(*candidate, Some(parent_id), child_id)?;
        }
        Ok(outcome)
    }

    pub(super) fn enqueue_derived_record_batch(
        &mut self,
        parent_child_pairs: &[(RecoveryCandidateId, u64)],
        schema: &RecordSchema,
    ) -> Result<(), RecoveryExecutionError> {
        if parent_child_pairs.is_empty() {
            return Ok(());
        }
        let mut node_ids = Vec::new();
        node_ids
            .try_reserve_exact(parent_child_pairs.len())
            .map_err(|source| RecoveryExecutionError::Operational {
                stage: RecoveryStage::AssembleRecords,
                source: Box::new(source),
            })?;
        node_ids.extend(parent_child_pairs.iter().map(|(_, node_id)| *node_id));
        let mut pairs = Vec::new();
        pairs
            .try_reserve_exact(parent_child_pairs.len())
            .map_err(|source| RecoveryExecutionError::Operational {
                stage: RecoveryStage::AssembleRecords,
                source: Box::new(source),
            })?;
        pairs.extend_from_slice(parent_child_pairs);
        self.defer_record_assembly(PendingRecordAssembly {
            input_node_ids: node_ids,
            parent_child_pairs: Some(pairs),
            schema: schema.clone(),
            report_node_id: None,
        })
    }

    fn enqueue_derived_record_batch_now(
        &mut self,
        parent_child_pairs: &[(RecoveryCandidateId, u64)],
        schema: &RecordSchema,
    ) -> Result<(), RecoveryExecutionError> {
        if parent_child_pairs.is_empty() {
            return Ok(());
        }
        let task = RecoveryTask::AssembleRecords(schema.clone());
        let node_ids = parent_child_pairs
            .iter()
            .map(|(_, node_id)| *node_id)
            .collect::<Vec<_>>();
        let result =
            self.coordinator
                .enqueue_derived_many(self.case, parent_child_pairs, task.clone())?;
        let retry_as_singletons = matches!(
            result,
            EnqueueOutcome::ResourceExhausted {
                resource: RecoveryResource::InputCount
                    | RecoveryResource::InputBytesPerItem
                    | RecoveryResource::TotalInputBytes
                    | RecoveryResource::OriginCount,
                ..
            }
        );
        self.record_completion_enqueue(result, &task, &node_ids)?;
        if retry_as_singletons {
            let mut scheduled = HashSet::new();
            scheduled
                .try_reserve(parent_child_pairs.len())
                .map_err(|source| RecoveryExecutionError::Operational {
                    stage: RecoveryStage::AssembleRecords,
                    source: Box::new(source),
                })?;
            for (parent_id, child_id) in parent_child_pairs {
                if scheduled.insert((*parent_id, *child_id)) {
                    self.enqueue_derived_task_now(*parent_id, *child_id, &task)?;
                }
            }
        }
        Ok(())
    }

    fn enqueue_derived_task_now(
        &mut self,
        parent_id: RecoveryCandidateId,
        child_id: u64,
        task: &RecoveryTask,
    ) -> Result<Option<RecoveryCandidateId>, RecoveryExecutionError> {
        let result =
            self.coordinator
                .enqueue_derived(parent_id, self.case, &[child_id], task.clone())?;
        let candidate_id = enqueue_candidate_id(&result);
        self.record_enqueue(result, task, &[child_id])?;
        Ok(candidate_id)
    }

    fn defer_root_record_assembly(
        &mut self,
        node_id: u64,
        schema: &RecordSchema,
    ) -> Result<(), RecoveryExecutionError> {
        self.defer_record_assembly(PendingRecordAssembly {
            input_node_ids: vec![node_id],
            parent_child_pairs: None,
            schema: schema.clone(),
            report_node_id: None,
        })
    }

    fn defer_derived_record_assembly(
        &mut self,
        parent_id: RecoveryCandidateId,
        node_id: u64,
        schema: &RecordSchema,
    ) -> Result<(), RecoveryExecutionError> {
        self.defer_record_assembly(PendingRecordAssembly {
            input_node_ids: vec![node_id],
            parent_child_pairs: Some(vec![(parent_id, node_id)]),
            schema: schema.clone(),
            report_node_id: None,
        })
    }

    fn defer_record_assembly(
        &mut self,
        pending: PendingRecordAssembly,
    ) -> Result<(), RecoveryExecutionError> {
        self.defer_record_assembly_group(VecDeque::from([pending]))
    }

    fn defer_record_assembly_group(
        &mut self,
        mut group: VecDeque<PendingRecordAssembly>,
    ) -> Result<(), RecoveryExecutionError> {
        if group.is_empty() {
            return Ok(());
        }
        let remaining = self
            .policy
            .resources
            .max_candidates
            .checked_sub(self.pending_record_assembly_count)
            .ok_or(RecoveryError::InvariantFailure)?;
        let omitted = if group.len() > remaining {
            Some(group.split_off(remaining))
        } else {
            None
        };
        if let Some(omitted) = omitted {
            let example = omitted.front().ok_or(RecoveryError::InvariantFailure)?;
            self.omissions.push(RecoveryOmission::ResourceExhausted {
                task: RecoveryTask::AssembleRecords(example.schema.clone()),
                input_node_ids: example.input_node_ids.clone(),
                resource: RecoveryResource::CandidateCount,
                limit: self.policy.resources.max_candidates,
                used: self
                    .pending_record_assembly_count
                    .checked_add(group.len())
                    .ok_or(RecoveryError::InvariantFailure)?,
                requested: omitted.len(),
            });
        }
        if group.is_empty() {
            return Ok(());
        }
        self.pending_record_assemblies
            .try_reserve(1)
            .map_err(|source| RecoveryExecutionError::Operational {
                stage: RecoveryStage::AssembleRecords,
                source: Box::new(source),
            })?;
        self.pending_record_assembly_count = self
            .pending_record_assembly_count
            .checked_add(group.len())
            .ok_or(RecoveryError::InvariantFailure)?;
        self.pending_record_assemblies.push_back(group);
        Ok(())
    }

    pub(super) fn flush_pending_record_assemblies(
        &mut self,
    ) -> Result<bool, RecoveryExecutionError> {
        if self.pending_record_assemblies.is_empty() {
            return Ok(false);
        }
        let mut group = self
            .pending_record_assemblies
            .pop_front()
            .ok_or(RecoveryError::InvariantFailure)?;
        let request = group.pop_front().ok_or(RecoveryError::InvariantFailure)?;
        self.pending_record_assembly_count = self
            .pending_record_assembly_count
            .checked_sub(1)
            .ok_or(RecoveryError::InvariantFailure)?;
        if !group.is_empty() {
            self.pending_record_assemblies.push_back(group);
        }
        if let Some(parent_child_pairs) = request.parent_child_pairs {
            self.enqueue_derived_record_batch_now(&parent_child_pairs, &request.schema)?;
        } else if let Some(report_node_id) = request.report_node_id {
            self.enqueue_record_schema_now(
                &request.input_node_ids,
                &request.schema,
                report_node_id,
            )?;
        } else {
            self.enqueue_root_record_batch(&request.input_node_ids, &request.schema)?;
        }
        Ok(true)
    }

    fn enqueue_root_record_batch(
        &mut self,
        node_ids: &[u64],
        schema: &RecordSchema,
    ) -> Result<(), RecoveryExecutionError> {
        let task = RecoveryTask::AssembleRecords(schema.clone());
        let result = self
            .coordinator
            .enqueue_nodes(self.case, node_ids, task.clone())?;
        self.record_completion_enqueue(result, &task, node_ids)
    }

    #[cfg(test)]
    pub(super) fn enqueue_record_schema_from_report(
        &mut self,
        node_ids: &[u64],
        schema: &RecordSchema,
        report_node_id: u64,
    ) -> Result<(), RecoveryExecutionError> {
        self.enqueue_record_schema_now(node_ids, schema, report_node_id)
    }

    pub(super) fn defer_record_schema_group(
        &mut self,
        requests: Vec<(Vec<u64>, RecordSchema, u64)>,
    ) -> Result<(), RecoveryExecutionError> {
        let mut group = VecDeque::new();
        group.try_reserve(requests.len()).map_err(|source| {
            RecoveryExecutionError::Operational {
                stage: RecoveryStage::AssembleRecords,
                source: Box::new(source),
            }
        })?;
        group.extend(
            requests
                .into_iter()
                .map(
                    |(input_node_ids, schema, report_node_id)| PendingRecordAssembly {
                        input_node_ids,
                        parent_child_pairs: None,
                        schema,
                        report_node_id: Some(report_node_id),
                    },
                ),
        );
        self.defer_record_assembly_group(group)
    }

    fn enqueue_record_schema_now(
        &mut self,
        node_ids: &[u64],
        schema: &RecordSchema,
        report_node_id: u64,
    ) -> Result<(), RecoveryExecutionError> {
        let task = RecoveryTask::AssembleRecords(schema.clone());
        let result = self
            .coordinator
            .enqueue_nodes(self.case, node_ids, task.clone())?;
        let candidate_id = enqueue_candidate_id(&result);
        self.record_completion_enqueue(result, &task, node_ids)?;
        let Some(candidate_id) = candidate_id else {
            return Ok(());
        };
        if self
            .record_schema_report_links
            .get(&candidate_id)
            .is_some_and(|receipts| receipts.contains(report_node_id))
        {
            return Ok(());
        }
        if self.record_schema_associations_charged >= self.policy.resources.max_pending_origin_links
        {
            self.omissions.push(RecoveryOmission::ResourceExhausted {
                task,
                input_node_ids: node_ids.to_vec(),
                resource: RecoveryResource::PendingOriginLinks,
                limit: self.policy.resources.max_pending_origin_links,
                used: self.record_schema_associations_charged,
                requested: 1,
            });
            return Ok(());
        }
        let receipts = self
            .record_schema_report_links
            .entry(candidate_id)
            .or_default();
        if receipts.try_insert(report_node_id).map_err(|source| {
            RecoveryExecutionError::Operational {
                stage: RecoveryStage::AssembleRecords,
                source: Box::new(source),
            }
        })? {
            self.record_schema_associations_charged = self
                .record_schema_associations_charged
                .checked_add(1)
                .ok_or_else(|| {
                    RecoveryExecutionError::InvalidPolicy(
                        "record schema association count overflowed".to_owned(),
                    )
                })?;
        }
        let receipt_node_id = self
            .coordinator
            .candidate(candidate_id)
            .and_then(|candidate| match candidate.state() {
                RecoveryCandidateState::Finished {
                    result: RecoveryResult::Derived { evidence_node_id },
                    ..
                } => Some(*evidence_node_id),
                RecoveryCandidateState::Finished {
                    result: RecoveryResult::Rejected { node_id },
                    ..
                } => Some(*node_id),
                _ => None,
            });
        if let Some(receipt_node_id) = receipt_node_id {
            self.link_late_record_schema_reports(candidate_id, receipt_node_id, &task, node_ids)?;
        }
        Ok(())
    }

    fn link_late_record_schema_reports(
        &mut self,
        candidate_id: RecoveryCandidateId,
        receipt_node_id: u64,
        task: &RecoveryTask,
        node_ids: &[u64],
    ) -> Result<(), RecoveryExecutionError> {
        let report_nodes = self
            .record_schema_report_links
            .get(&candidate_id)
            .map(|links| links.pending_for(receipt_node_id).to_vec())
            .unwrap_or_default();
        if report_nodes.is_empty() {
            return Ok(());
        }
        let linked = self.case_transaction(|case| {
            for report_node_id in &report_nodes {
                add_transaction_edge(
                    case,
                    Edge {
                        from: *report_node_id,
                        to: receipt_node_id,
                        relation: "record_schema_selected_from".to_owned(),
                        status: EvidenceStatus::Unresolved,
                        reason: RECORD_SCHEMA_SELECTED_FROM_REASON.to_owned(),
                    },
                )?;
            }
            Ok(())
        });
        match linked {
            Ok(()) => {
                if let Some(links) = self.record_schema_report_links.get_mut(&candidate_id) {
                    links.mark_linked(receipt_node_id);
                }
                Ok(())
            }
            Err(RecoveryExecutionError::Evidence(EvidenceError::QuotaExceeded {
                field: "edges",
                maximum,
            })) => {
                self.omissions.push(RecoveryOmission::ResourceExhausted {
                    task: task.clone(),
                    input_node_ids: node_ids.to_vec(),
                    resource: RecoveryResource::EvidenceEdges,
                    limit: maximum,
                    used: self.case.edges().len(),
                    requested: report_nodes.len(),
                });
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    pub(super) fn enqueue_framed_children(
        &mut self,
        parent_id: RecoveryCandidateId,
        frame_node_ids: &[u64],
        tail_node_id: Option<u64>,
    ) -> Result<(), RecoveryExecutionError> {
        let frame_tasks = if let Some(frame_node_id) = frame_node_ids.first() {
            let frame_kind = self.node_kind(*frame_node_id)?.to_owned();
            self.tasks_for_node(&frame_kind, false)
        } else {
            Vec::new()
        };
        for task in frame_tasks {
            match &task {
                RecoveryTask::Transform(_) => {
                    let mut slots = Vec::new();
                    slots
                        .try_reserve_exact(frame_node_ids.len())
                        .map_err(|source| RecoveryExecutionError::Operational {
                            stage: RecoveryStage::Transform,
                            source: Box::new(source),
                        })?;
                    for input_node_id in frame_node_ids {
                        if let DerivedTaskEnqueue::Candidate(candidate) =
                            self.enqueue_transform_slot(parent_id, *input_node_id, &task)?
                        {
                            slots.push(TransformSlot {
                                parent: parent_id,
                                input_node: *input_node_id,
                                candidate,
                            });
                        }
                    }
                    self.enqueue_transform_cohort(task.clone(), slots);
                }
                RecoveryTask::AssembleRecords(schema) => {
                    let pairs = frame_node_ids
                        .iter()
                        .map(|node_id| (parent_id, *node_id))
                        .collect::<Vec<_>>();
                    self.enqueue_derived_record_batch(&pairs, schema)?;
                }
                other => {
                    for frame_node_id in frame_node_ids {
                        self.enqueue_derived_task(parent_id, *frame_node_id, other)?;
                    }
                }
            }
        }
        if let Some(tail_node_id) = tail_node_id {
            self.enqueue_derived_children(parent_id, &[tail_node_id], false)?;
        }
        Ok(())
    }

    fn tasks_for_node(&self, kind: &str, include_expansion: bool) -> Vec<RecoveryTask> {
        task_templates_for_node(self.plan, kind, include_expansion)
    }

    pub(super) fn record_enqueue(
        &mut self,
        result: EnqueueOutcome,
        task: &RecoveryTask,
        node_ids: &[u64],
    ) -> Result<(), RecoveryExecutionError> {
        match result {
            EnqueueOutcome::Queued(id)
            | EnqueueOutcome::Merged(id)
            | EnqueueOutcome::MergedNeedsContext(id) => {
                self.remember_candidate(id)?;
                if matches!(result, EnqueueOutcome::MergedNeedsContext(_)) {
                    self.refresh_late_context(id)?;
                }
            }
            EnqueueOutcome::ResourceExhausted {
                resource,
                limit,
                used,
                requested,
            } => self.omissions.push(RecoveryOmission::ResourceExhausted {
                task: task.clone(),
                input_node_ids: node_ids.to_vec(),
                resource,
                limit,
                used,
                requested,
            }),
            EnqueueOutcome::CycleSkipped { candidate_id } => {
                self.remember_candidate(candidate_id)?;
                self.cycle_skips = self.cycle_skips.saturating_add(1);
                self.refresh_late_context(candidate_id)?;
            }
        }
        Ok(())
    }

    fn record_completion_enqueue(
        &mut self,
        result: EnqueueOutcome,
        task: &RecoveryTask,
        node_ids: &[u64],
    ) -> Result<(), RecoveryExecutionError> {
        self.record_enqueue(result, task, node_ids)?;
        self.coordinator.prioritize_newly_queued(&result)?;
        Ok(())
    }

    fn record_completion_enqueue_from_parent(
        &mut self,
        result: EnqueueOutcome,
        parent_id: RecoveryCandidateId,
        task: &RecoveryTask,
        node_ids: &[u64],
    ) -> Result<(), RecoveryExecutionError> {
        self.record_enqueue(result, task, node_ids)?;
        if is_record_completion_task(task) {
            self.coordinator
                .prioritize_queued_from_parent(&result, parent_id)?;
        }
        Ok(())
    }

    fn remember_candidate(
        &mut self,
        candidate_id: RecoveryCandidateId,
    ) -> Result<(), RecoveryExecutionError> {
        if self.snapshot_candidates && self.candidate_index.insert(candidate_id) {
            self.candidate_ids.try_reserve(1).map_err(|error| {
                RecoveryExecutionError::Operational {
                    stage: RecoveryStage::StructuralValidation,
                    source: Box::new(error),
                }
            })?;
            self.candidate_ids.push(candidate_id);
        }
        Ok(())
    }

    fn refresh_late_context(
        &mut self,
        candidate_id: RecoveryCandidateId,
    ) -> Result<(), RecoveryExecutionError> {
        let candidate = self
            .coordinator
            .candidate(candidate_id)
            .ok_or(RecoveryError::UnknownCandidate { id: candidate_id })?;
        let RecoveryCandidateState::ContextPending { result, .. } = candidate.state() else {
            return Ok(());
        };
        let result = result.clone();
        let task = candidate.task().clone();
        let Some((result_node, relation, status)) = canonical_result_link(&result) else {
            return Err(RecoveryError::InvariantFailure.into());
        };
        let pending = candidate.pending_origin_node_ids().to_vec();
        let relation = relation.to_owned();
        self.case_transaction(|case| {
            add_transaction_links(
                case,
                result_node,
                &pending,
                &relation,
                status,
                CONTEXT_REASON,
            )
        })?;
        match self.coordinator.refresh_context(self.case, candidate_id)? {
            ContextRegistration::Complete => {
                self.enqueue_late_validated_expansions(candidate_id, &task, &result)?;
                Ok(())
            }
            ContextRegistration::Pending { .. } => Err(RecoveryError::InvariantFailure.into()),
            ContextRegistration::ResourceExhausted {
                resource,
                limit,
                used,
                requested,
            } => {
                self.omissions.push(RecoveryOmission::ResourceExhausted {
                    task,
                    input_node_ids: pending,
                    resource,
                    limit,
                    used,
                    requested,
                });
                Ok(())
            }
        }
    }

    fn enqueue_late_validated_expansions(
        &mut self,
        parent_id: RecoveryCandidateId,
        task: &RecoveryTask,
        result: &RecoveryResult,
    ) -> Result<(), RecoveryExecutionError> {
        if task != &RecoveryTask::StructuralValidation {
            return Ok(());
        }
        let RecoveryResult::ObservedValidation { node_id } = result else {
            return Ok(());
        };
        let format = self
            .case
            .node(*node_id)
            .and_then(|node| node.details.get("format"))
            .and_then(serde_json::Value::as_str);
        if !matches!(format, Some("der" | "png" | "zip")) {
            return Ok(());
        }

        let mut exact_inputs = Vec::new();
        if let Some(inputs) = self.case_index.validated_range_inputs(*node_id) {
            exact_inputs
                .try_reserve_exact(inputs.len())
                .map_err(|source| RecoveryExecutionError::Operational {
                    stage: RecoveryStage::StructuralValidation,
                    source: Box::new(source),
                })?;
            exact_inputs.extend(inputs.iter().copied());
        }
        for exact_input in exact_inputs {
            self.enqueue_validated_task(parent_id, exact_input, &RecoveryTask::RecursiveExpansion)?;
        }
        Ok(())
    }

    pub(super) fn execute_candidate(
        &mut self,
        candidate_id: RecoveryCandidateId,
    ) -> Result<(), RecoveryExecutionError> {
        let candidate = self
            .coordinator
            .candidate(candidate_id)
            .ok_or(RecoveryError::UnknownCandidate { id: candidate_id })?
            .clone();
        let task = candidate.task().clone();
        if task == RecoveryTask::FramingDiscovery {
            return self.run_framing_discovery(candidate_id);
        }
        if task == RecoveryTask::RecordDiscovery {
            return self.run_record_discovery(candidate_id);
        }
        if matches!(
            task,
            RecoveryTask::RelationalTransformDiscovery
                | RecoveryTask::RelationalTransformDiscoveryIncremental
        ) {
            return self.run_relational_transform_discovery(candidate_id);
        }
        if let RecoveryTask::AssembleRecords(schema) = &task {
            return self.execute_record_candidate(candidate_id, &candidate, schema);
        }
        if self.reject_expansion_at_depth(candidate_id, &candidate, &task)? {
            return Ok(());
        }
        let Some(inputs) = self.prepare_candidate_inputs(candidate_id, &candidate, task)? else {
            return Ok(());
        };
        self.execute_candidate_task(candidate_id, &candidate, &inputs)
    }

    fn reject_expansion_at_depth(
        &mut self,
        candidate_id: RecoveryCandidateId,
        candidate: &l2_workbench::recovery::RecoveryCandidate,
        task: &RecoveryTask,
    ) -> Result<bool, RecoveryExecutionError> {
        if task != &RecoveryTask::RecursiveExpansion
            || candidate.depth() < self.policy.resources.max_depth
        {
            return Ok(false);
        }
        let resource = RecoveryResource::RecursionDepth;
        let limit = self.policy.resources.max_depth;
        let used = candidate.depth();
        let requested = 1;
        self.omissions.push(RecoveryOmission::ResourceExhausted {
            task: task.clone(),
            input_node_ids: candidate
                .inputs()
                .first()
                .ok_or(RecoveryError::InvariantFailure)?
                .origin_node_ids()
                .to_vec(),
            resource,
            limit,
            used,
            requested,
        });
        self.finish(
            candidate_id,
            RecoveryResult::ResourceExhausted {
                resource,
                limit,
                used,
                requested,
            },
        )?;
        Ok(true)
    }

    fn prepare_candidate_inputs(
        &mut self,
        candidate_id: RecoveryCandidateId,
        candidate: &l2_workbench::recovery::RecoveryCandidate,
        task: RecoveryTask,
    ) -> Result<Option<CandidateInputs>, RecoveryExecutionError> {
        let input = candidate
            .inputs()
            .first()
            .ok_or(RecoveryError::InvariantFailure)?;
        let input_node = input
            .origin_node_ids()
            .first()
            .copied()
            .ok_or(RecoveryError::InvariantFailure)?;
        let origins = input.origin_node_ids().to_vec();
        let input_length = self
            .coordinator
            .input_blob(self.case, candidate_id)?
            .bytes
            .len();
        if !self.charge_work(candidate_id, &task, input.origin_node_ids(), input_length)? {
            return Ok(None);
        }
        if let Some((resource, limit)) = transform_input_limit(&task, input_length, &self.policy) {
            self.omissions.push(RecoveryOmission::ResourceExhausted {
                task: task.clone(),
                input_node_ids: origins,
                resource,
                limit,
                used: 0,
                requested: input_length,
            });
            self.finish(
                candidate_id,
                RecoveryResult::ResourceExhausted {
                    resource,
                    limit,
                    used: 0,
                    requested: input_length,
                },
            )?;
            return Ok(None);
        }
        Ok(Some(CandidateInputs {
            task,
            input_node,
            origins,
            input_length,
        }))
    }

    fn execute_candidate_task(
        &mut self,
        candidate_id: RecoveryCandidateId,
        candidate: &l2_workbench::recovery::RecoveryCandidate,
        inputs: &CandidateInputs,
    ) -> Result<(), RecoveryExecutionError> {
        match &inputs.task {
            RecoveryTask::Transform(recipe) => {
                self.run_transform(candidate_id, inputs.input_node, recipe)
            }
            RecoveryTask::TransformDiscovery => {
                self.run_transform_discovery(candidate_id, inputs.input_node, inputs.input_length)
            }
            RecoveryTask::FramingDiscovery => self.run_framing_discovery(candidate_id),
            RecoveryTask::MaterializeFraming(rule) => {
                let basis = self
                    .framing_selection_bases
                    .get(&candidate_id)
                    .copied()
                    .unwrap_or(FramingSelectionBasis::CallerSupplied {});
                self.run_framing(
                    candidate_id,
                    inputs.input_node,
                    &inputs.origins,
                    rule,
                    basis,
                )
            }
            RecoveryTask::EmbeddedDiscovery => self.run_embedded(candidate_id, &inputs.origins),
            RecoveryTask::StructuralValidation => {
                self.run_structural_validation(candidate_id, inputs)
            }
            RecoveryTask::RecursiveExpansion => {
                self.run_expansion(candidate_id, &inputs.origins, inputs.input_node)
            }
            RecoveryTask::AssembleRecords(schema) => {
                self.execute_record_candidate(candidate_id, candidate, schema)
            }
            RecoveryTask::RecordDiscovery => self.run_record_discovery(candidate_id),
            RecoveryTask::RelationalTransformDiscovery
            | RecoveryTask::RelationalTransformDiscoveryIncremental => {
                self.run_relational_transform_discovery(candidate_id)
            }
        }
    }

    fn run_structural_validation(
        &mut self,
        candidate_id: RecoveryCandidateId,
        inputs: &CandidateInputs,
    ) -> Result<(), RecoveryExecutionError> {
        let available_work = self.coordinator.remaining_work_bytes();
        let configured_zip_work = self
            .policy
            .artifact_validation_policy
            .zip_limits
            .max_total_expanded_bytes;
        let global_zip_work_limited = available_work <= configured_zip_work;
        let mut validation_policy = self.policy.artifact_validation_policy;
        validation_policy.zip_limits.max_total_expanded_bytes =
            configured_zip_work.min(available_work);
        let validator = ArtifactValidator::new(validation_policy)
            .map_err(|error| RecoveryExecutionError::InvalidPolicy(error.to_string()))?;
        let attempt = {
            let input = self.coordinator.input_blob(self.case, candidate_id)?;
            classify_validation(validator.validate(&input.bytes), global_zip_work_limited)?
        };
        if attempt.zip_work_bytes > 0
            && !self.charge_work(
                candidate_id,
                &RecoveryTask::StructuralValidation,
                &inputs.origins,
                attempt.zip_work_bytes,
            )?
        {
            return Ok(());
        }
        let global_zip_work_request = attempt.global_zip_work_request;
        self.run_validation(
            candidate_id,
            &inputs.origins,
            inputs.input_node,
            inputs.input_length,
            attempt.decision,
        )?;
        if let Some(requested) = global_zip_work_request {
            self.record_validation_work_limit(&inputs.origins, requested);
        }
        Ok(())
    }

    fn record_validation_work_limit(&mut self, origins: &[u64], requested: usize) {
        // The archive boundary can validate while bounded member extraction stays incomplete
        let resource = RecoveryResource::WorkBytes;
        let limit = self.policy.resources.max_work_bytes;
        let used = self.coordinator.work_bytes_charged();
        self.omissions.push(RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::StructuralValidation,
            input_node_ids: origins.to_vec(),
            resource,
            limit,
            used,
            requested,
        });
    }
}

const fn is_record_completion_task(task: &RecoveryTask) -> bool {
    matches!(
        task,
        RecoveryTask::AssembleRecords(_)
            | RecoveryTask::StructuralValidation
            | RecoveryTask::RecursiveExpansion
    )
}

pub(super) const fn enqueue_candidate_id(outcome: &EnqueueOutcome) -> Option<RecoveryCandidateId> {
    match outcome {
        EnqueueOutcome::Queued(id)
        | EnqueueOutcome::Merged(id)
        | EnqueueOutcome::MergedNeedsContext(id)
        | EnqueueOutcome::CycleSkipped { candidate_id: id } => Some(*id),
        EnqueueOutcome::ResourceExhausted { .. } => None,
    }
}
