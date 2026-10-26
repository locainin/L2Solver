use super::evidence::case_evidence_quota;
use super::policy::task_templates_for_node;
use super::{
    Executor, RecoveryCandidateId, RecoveryExecutionError, RecoveryOmission, RecoveryStage,
    RecoveryTask,
};
use l2_workbench::{
    evidence::EvidenceError,
    recovery::{RecoveryCandidateState, RecoveryError, RecoveryResource, RecoveryResult},
};
use std::collections::{HashMap, HashSet};

#[cfg(test)]
#[path = "../../../tests/workbench/recovery_lineage.rs"]
mod tests;

pub(super) struct TransformCohort {
    pub(super) task: RecoveryTask,
    pub(super) slots: Vec<TransformSlot>,
}

#[derive(Eq, PartialEq)]
pub(super) struct TransformSlot {
    /// Candidate that produced this ordered input
    pub(super) parent: RecoveryCandidateId,
    pub(super) input_node: u64,
    pub(super) candidate: RecoveryCandidateId,
}

struct TransformCohortState {
    slot_counts: HashMap<RecoveryCandidateId, usize>,
    covered_inputs: HashMap<RecoveryCandidateId, HashSet<u64>>,
    successful_outputs: HashMap<RecoveryCandidateId, (u64, u64)>,
    successful_output_order: Vec<RecoveryCandidateId>,
    contextual_view_admission_blocked: bool,
}

fn transform_slot_capacity(cohorts: &[TransformCohort]) -> Result<usize, RecoveryExecutionError> {
    cohorts
        .iter()
        .try_fold(0_usize, |total, cohort| {
            total.checked_add(cohort.slots.len())
        })
        .ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy(
                "transform cohort slot count overflowed".to_owned(),
            )
        })
}

fn prepare_transform_cohort_state(
    cohorts: &[TransformCohort],
    slot_capacity: usize,
) -> Result<TransformCohortState, RecoveryExecutionError> {
    let mut slot_counts = HashMap::new();
    slot_counts.try_reserve(slot_capacity).map_err(|source| {
        RecoveryExecutionError::Operational {
            stage: RecoveryStage::Transform,
            source: Box::new(source),
        }
    })?;
    for slot in cohorts.iter().flat_map(|cohort| &cohort.slots) {
        let count = slot_counts.entry(slot.candidate).or_insert(0_usize);
        *count = count.checked_add(1).ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy(
                "transform cohort slot count overflowed".to_owned(),
            )
        })?;
    }
    let mut covered_inputs = HashMap::new();
    covered_inputs
        .try_reserve(slot_counts.len())
        .map_err(|source| RecoveryExecutionError::Operational {
            stage: RecoveryStage::Transform,
            source: Box::new(source),
        })?;
    let mut successful_outputs = HashMap::new();
    successful_outputs
        .try_reserve(slot_counts.len())
        .map_err(|source| RecoveryExecutionError::Operational {
            stage: RecoveryStage::Transform,
            source: Box::new(source),
        })?;
    let mut successful_output_order = Vec::new();
    successful_output_order
        .try_reserve_exact(slot_capacity)
        .map_err(|source| RecoveryExecutionError::Operational {
            stage: RecoveryStage::Transform,
            source: Box::new(source),
        })?;
    Ok(TransformCohortState {
        slot_counts,
        covered_inputs,
        successful_outputs,
        successful_output_order,
        contextual_view_admission_blocked: false,
    })
}

fn reserve_next_transform_slots(
    slot_capacity: usize,
    task_count: usize,
) -> Result<Vec<Vec<TransformSlot>>, RecoveryExecutionError> {
    let mut next_slots = Vec::new();
    next_slots.try_reserve_exact(task_count).map_err(|source| {
        RecoveryExecutionError::Operational {
            stage: RecoveryStage::Transform,
            source: Box::new(source),
        }
    })?;
    for _ in 0..task_count {
        let mut slots = Vec::new();
        slots.try_reserve_exact(slot_capacity).map_err(|source| {
            RecoveryExecutionError::Operational {
                stage: RecoveryStage::Transform,
                source: Box::new(source),
            }
        })?;
        next_slots.push(slots);
    }
    Ok(next_slots)
}

fn same_ordered_slots(left: &[TransformSlot], right: &[TransformSlot]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.parent == right.parent
                && left.input_node == right.input_node
                && left.candidate == right.candidate
        })
}

impl Executor<'_> {
    pub(super) fn flush_transform_cohorts(&mut self) -> Result<bool, RecoveryExecutionError> {
        if self.transform_cohorts.is_empty() {
            return Ok(false);
        }
        let cohorts = std::mem::take(&mut self.transform_cohorts);
        let slot_capacity = transform_slot_capacity(&cohorts)?;
        let mut state = prepare_transform_cohort_state(&cohorts, slot_capacity)?;
        let tasks = task_templates_for_node(self.plan, "decoding_output", false);
        let record_tasks = tasks
            .iter()
            .filter(|task| matches!(task, RecoveryTask::AssembleRecords(_)))
            .cloned()
            .collect::<Vec<_>>();
        let transform_tasks = tasks
            .into_iter()
            .filter(|task| matches!(task, RecoveryTask::Transform(_)))
            .collect::<Vec<_>>();
        for cohort in &cohorts {
            self.process_transform_cohort(cohort, &record_tasks, &transform_tasks, &mut state)?;
        }
        self.enqueue_uncovered_transform_outputs(&record_tasks, &transform_tasks, state)?;
        Ok(true)
    }

    pub(super) fn enqueue_transform_cohort(
        &mut self,
        task: RecoveryTask,
        slots: Vec<TransformSlot>,
    ) {
        if slots.is_empty() {
            return;
        }
        let cohort = TransformCohort { task, slots };
        // Candidate IDs carry normalized task identity; ordered slots carry lineage context
        if !self
            .transform_cohorts
            .iter()
            .any(|existing| same_ordered_slots(&existing.slots, &cohort.slots))
        {
            self.transform_cohorts.push(cohort);
        }
    }

    fn process_transform_cohort(
        &mut self,
        cohort: &TransformCohort,
        record_tasks: &[RecoveryTask],
        transform_tasks: &[RecoveryTask],
        state: &mut TransformCohortState,
    ) -> Result<(), RecoveryExecutionError> {
        let mut record_inputs = Vec::new();
        record_inputs
            .try_reserve_exact(cohort.slots.len())
            .map_err(|source| RecoveryExecutionError::Operational {
                stage: RecoveryStage::AssembleRecords,
                source: Box::new(source),
            })?;
        let mut next_slots =
            reserve_next_transform_slots(cohort.slots.len(), transform_tasks.len())?;
        for slot in &cohort.slots {
            let result = self.process_transform_slot(
                slot,
                transform_tasks,
                state,
                &mut record_inputs,
                &mut next_slots,
            )?;
            // Rejected proposals finish a speculative search without omitting a required input
            // Explicit record batches still account for every excluded sibling
            if let Some(result) = result
                && (!record_tasks.is_empty()
                    || !matches!(
                        result,
                        RecoveryResult::Rejected { .. } | RecoveryResult::Unsupported
                    ))
            {
                self.omissions
                    .push(RecoveryOmission::SiblingTransformExcluded {
                        input_node_id: slot.input_node,
                        task: cohort.task.clone(),
                        result,
                    });
            }
        }
        self.enqueue_cohort_records(record_tasks, &record_inputs)?;
        for (task, slots) in transform_tasks.iter().cloned().zip(next_slots) {
            self.enqueue_transform_cohort(task, slots);
        }
        Ok(())
    }

    fn process_transform_slot(
        &mut self,
        slot: &TransformSlot,
        transform_tasks: &[RecoveryTask],
        state: &mut TransformCohortState,
        record_inputs: &mut Vec<(RecoveryCandidateId, u64)>,
        next_slots: &mut [Vec<TransformSlot>],
    ) -> Result<Option<RecoveryResult>, RecoveryExecutionError> {
        let candidate = slot.candidate;
        state
            .covered_inputs
            .entry(candidate)
            .or_default()
            .insert(slot.input_node);
        let (output_is_shared, result) = {
            let candidate_state = self
                .coordinator
                .candidate(candidate)
                .ok_or(RecoveryError::UnknownCandidate { id: candidate })?;
            let RecoveryCandidateState::Finished { result, .. } = candidate_state.state() else {
                return Err(RecoveryError::InvariantFailure.into());
            };
            let output_is_shared = candidate_state
                .inputs()
                .first()
                .is_some_and(|input| input.origin_node_ids().len() > 1)
                || state.slot_counts.get(&candidate).copied().unwrap_or(0) > 1;
            (output_is_shared, result.clone())
        };
        let RecoveryResult::Derived {
            evidence_node_id: receipt_node,
        } = result
        else {
            return Ok(Some(result));
        };
        let Some(output_node) = self.contextual_transform_output(
            candidate,
            slot.input_node,
            receipt_node,
            output_is_shared,
            state,
        )?
        else {
            return Ok(None);
        };
        record_inputs.push((candidate, output_node));
        for (task, slots) in transform_tasks.iter().zip(next_slots) {
            match self.enqueue_transform_slot(candidate, output_node, task)? {
                DerivedTaskEnqueue::Candidate(next_candidate) => slots.push(TransformSlot {
                    parent: candidate,
                    input_node: output_node,
                    candidate: next_candidate,
                }),
                DerivedTaskEnqueue::CycleSkipped(ancestor) => {
                    // This merged input is already represented by the ancestor result
                    state
                        .covered_inputs
                        .entry(ancestor)
                        .or_default()
                        .insert(output_node);
                }
                DerivedTaskEnqueue::ResourceExhausted => {}
            }
        }
        Ok(None)
    }

    fn enqueue_cohort_records(
        &mut self,
        record_tasks: &[RecoveryTask],
        record_inputs: &[(RecoveryCandidateId, u64)],
    ) -> Result<(), RecoveryExecutionError> {
        for task in record_tasks {
            if let RecoveryTask::AssembleRecords(schema) = task {
                self.enqueue_derived_record_batch(record_inputs, schema)?;
            }
        }
        Ok(())
    }

    fn contextual_transform_output(
        &mut self,
        candidate: RecoveryCandidateId,
        input_node: u64,
        receipt_node: u64,
        output_is_shared: bool,
        state: &mut TransformCohortState,
    ) -> Result<Option<u64>, RecoveryExecutionError> {
        self.refresh_case_index()?;
        let output_node = self
            .case_index
            .decoding_outputs
            .get(&receipt_node)
            .copied()
            .ok_or(RecoveryError::InvariantFailure)?;
        if let std::collections::hash_map::Entry::Vacant(entry) =
            state.successful_outputs.entry(candidate)
        {
            entry.insert((receipt_node, output_node));
            state.successful_output_order.push(candidate);
        }
        let has_tcp_context = self.derived_discovery.has_context(input_node);
        let contextual_node = if output_is_shared || has_tcp_context {
            let Some(view_node) = self.try_contextual_decoding_view(
                candidate,
                output_node,
                receipt_node,
                input_node,
                state,
            )?
            else {
                return Ok(None);
            };
            view_node
        } else {
            output_node
        };
        if has_tcp_context {
            self.register_derived_transform_output(
                input_node,
                contextual_node,
                receipt_node,
                candidate,
            )?;
        }
        Ok(Some(contextual_node))
    }

    fn enqueue_uncovered_transform_outputs(
        &mut self,
        record_tasks: &[RecoveryTask],
        transform_tasks: &[RecoveryTask],
        mut state: TransformCohortState,
    ) -> Result<(), RecoveryExecutionError> {
        for index in 0..state.successful_output_order.len() {
            let candidate = *state
                .successful_output_order
                .get(index)
                .ok_or(RecoveryError::InvariantFailure)?;
            let (receipt_node, output_node) = *state
                .successful_outputs
                .get(&candidate)
                .ok_or(RecoveryError::InvariantFailure)?;
            let origins = self
                .coordinator
                .candidate(candidate)
                .ok_or(RecoveryError::UnknownCandidate { id: candidate })?
                .inputs()
                .first()
                .ok_or(RecoveryError::InvariantFailure)?
                .origin_node_ids()
                .to_vec();
            let covered = state
                .covered_inputs
                .get(&candidate)
                .ok_or(RecoveryError::InvariantFailure)?
                .clone();
            for origin in origins {
                if covered.contains(&origin) {
                    continue;
                }
                let Some(view_node) = self.try_contextual_decoding_view(
                    candidate,
                    output_node,
                    receipt_node,
                    origin,
                    &mut state,
                )?
                else {
                    continue;
                };
                if self.derived_discovery.has_context(origin) {
                    self.register_derived_transform_output(
                        origin,
                        view_node,
                        receipt_node,
                        candidate,
                    )?;
                }
                for task in record_tasks {
                    self.enqueue_derived_task(candidate, view_node, task)?;
                }
                for task in transform_tasks {
                    match self.enqueue_transform_slot(candidate, view_node, task)? {
                        DerivedTaskEnqueue::Candidate(next_candidate) => {
                            self.enqueue_transform_cohort(
                                task.clone(),
                                vec![TransformSlot {
                                    parent: candidate,
                                    input_node: view_node,
                                    candidate: next_candidate,
                                }],
                            );
                        }
                        DerivedTaskEnqueue::CycleSkipped(ancestor) => {
                            // Do not revisit the context merged into this finished ancestor
                            state
                                .covered_inputs
                                .entry(ancestor)
                                .or_default()
                                .insert(view_node);
                        }
                        DerivedTaskEnqueue::ResourceExhausted => {}
                    }
                }
            }
        }
        Ok(())
    }

    fn try_contextual_decoding_view(
        &mut self,
        candidate: RecoveryCandidateId,
        output_node: u64,
        receipt_node: u64,
        input_node: u64,
        state: &mut TransformCohortState,
    ) -> Result<Option<u64>, RecoveryExecutionError> {
        if state.contextual_view_admission_blocked {
            return Ok(None);
        }

        match self.contextual_decoding_view(output_node, receipt_node, input_node) {
            Ok(view_node) => Ok(Some(view_node)),
            Err(RecoveryExecutionError::Evidence(error)) => {
                let Some((resource, limit, used)) = case_evidence_quota(self.case, &error) else {
                    return Err(RecoveryExecutionError::Evidence(error));
                };
                let task = self
                    .coordinator
                    .candidate(candidate)
                    .ok_or(RecoveryError::UnknownCandidate { id: candidate })?
                    .task()
                    .clone();
                let requested = contextual_view_quota_request(resource, &error, used);
                self.omissions.push(RecoveryOmission::ResourceExhausted {
                    task,
                    input_node_ids: vec![input_node],
                    resource,
                    limit,
                    used,
                    requested,
                });
                if matches!(
                    resource,
                    RecoveryResource::EvidenceEdges | RecoveryResource::EvidenceNodes
                ) {
                    state.contextual_view_admission_blocked = true;
                }
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    pub(super) fn enqueue_transform_slot(
        &mut self,
        parent: RecoveryCandidateId,
        input_node: u64,
        task: &RecoveryTask,
    ) -> Result<DerivedTaskEnqueue, RecoveryExecutionError> {
        self.enqueue_derived_task_detailed(parent, input_node, task)
    }
}

pub(super) enum DerivedTaskEnqueue {
    Candidate(RecoveryCandidateId),
    CycleSkipped(RecoveryCandidateId),
    ResourceExhausted,
}

const fn contextual_view_quota_request(
    resource: RecoveryResource,
    error: &EvidenceError,
    used: usize,
) -> usize {
    match resource {
        RecoveryResource::EvidenceEdges => 3,
        RecoveryResource::EvidenceTotalDetailsBytes => match error {
            EvidenceError::TotalDetailsTooLarge { length, .. } => length.saturating_sub(used),
            _ => 1,
        },
        _ => 1,
    }
}
