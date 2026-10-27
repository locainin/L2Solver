use super::support::{add_bytes_node, add_derived_edge, fail, recovery_policy, require};
use l2_workbench::{
    evidence::Case,
    recovery::{
        EnqueueOutcome, RecoveryCandidate, RecoveryCandidateId, RecoveryCandidateState,
        RecoveryCoordinator, RecoveryResourcePolicy, RecoveryResult, RecoveryTask,
    },
};

const MAX_INPUT_BYTES: usize = 64;
const MAX_OPERATIONS: usize = 20;
const MAX_CANDIDATES: usize = 6;
const SOURCE_NODE_COUNT: usize = 6;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Snapshot {
    count: usize,
    head: Option<RecoveryCandidateId>,
    parent_links: usize,
    context_aliases: usize,
    pending_links: usize,
    task_identity_bytes: usize,
    candidates: Vec<RecoveryCandidate>,
}

struct QueueDriver {
    policy: RecoveryResourcePolicy,
    case: Case,
    derived_output_id: u64,
    coordinator: RecoveryCoordinator,
    ids: Vec<RecoveryCandidateId>,
    outcomes: [Option<EnqueueOutcome>; MAX_OPERATIONS],
    popped: [bool; MAX_CANDIDATES],
}

pub fn exercise(input: &[u8]) {
    let input = input
        .get(..input.len().min(MAX_INPUT_BYTES))
        .unwrap_or_default();
    let Some(settings) = input.get(..4) else {
        return;
    };
    let mut driver = QueueDriver::new(input, settings);
    let operations = input.get(4..).unwrap_or_default().as_chunks::<3>().0;
    for (index, operation) in operations.iter().take(MAX_OPERATIONS).enumerate() {
        driver.execute(operation, index);
    }
}

impl QueueDriver {
    fn new(input: &[u8], settings: &[u8]) -> Self {
        let &[
            candidate_setting,
            frontier_setting,
            depth_setting,
            lineage_setting,
        ] = settings
        else {
            fail();
        };
        let max_candidates = 1 + usize::from(candidate_setting % 6);
        let mut policy = recovery_policy(8);
        policy.max_candidates = max_candidates;
        policy.max_frontier = 1 + usize::from(frontier_setting) % max_candidates;
        policy.max_depth = usize::from(depth_setting % 4);
        policy.max_lineage_work = usize::from(lineage_setting % 32);
        policy.max_candidate_task_identity_bytes =
            (policy.max_candidate_task_identity_bytes / 4).saturating_mul(max_candidates);

        let (case, derived_output_id) = queue_case(input);
        Self {
            coordinator: RecoveryCoordinator::new(policy),
            policy,
            case,
            derived_output_id,
            ids: Vec::with_capacity(max_candidates),
            outcomes: [None; MAX_OPERATIONS],
            popped: [false; MAX_CANDIDATES],
        }
    }

    fn execute(&mut self, operation: &[u8], index: usize) {
        let &[kind, first, second] = operation else {
            fail();
        };
        let work_before = (
            self.coordinator.work_bytes_charged(),
            self.coordinator.lineage_work_charged(),
            self.coordinator.parent_links_retained(),
            self.coordinator.context_aliases_retained(),
            self.coordinator.candidate_task_identity_bytes_charged(),
        );
        match kind % 7 {
            0 => self.enqueue_root(first, second, index),
            1 => self.enqueue_child(first, second, index),
            2 => self.prioritize_new(first, index),
            3 => self.prioritize_from_parent(first, second, index),
            4 => self.pop_next(),
            kind @ (5 | 6) => self.finish(first, second, kind),
            _ => fail(),
        }
        require(self.coordinator.work_bytes_charged() >= work_before.0);
        require(self.coordinator.lineage_work_charged() >= work_before.1);
        require(self.coordinator.parent_links_retained() >= work_before.2);
        require(self.coordinator.context_aliases_retained() >= work_before.3);
        require(self.coordinator.candidate_task_identity_bytes_charged() >= work_before.4);
        self.check_invariants();
    }

    fn enqueue_root(&mut self, node_selector: u8, task_selector: u8, index: usize) {
        let node_id = self.source_node(node_selector);
        self.enqueue(node_id, selected_task(task_selector), None, index);
    }

    fn enqueue_child(&mut self, parent_selector: u8, child_task_selector: u8, index: usize) {
        if self.ids.is_empty() {
            return;
        }
        let parent_id = self.selected_id(parent_selector);
        let child_id = self.source_node(child_task_selector);
        let task = selected_task((child_task_selector >> 3) % 4);
        self.enqueue(child_id, task, Some(parent_id), index);
    }

    fn enqueue(
        &mut self,
        node_id: u64,
        task: RecoveryTask,
        parent_id: Option<RecoveryCandidateId>,
        index: usize,
    ) {
        let before = self.snapshot();
        let result = match parent_id {
            Some(parent) => self
                .coordinator
                .enqueue_derived(parent, &self.case, &[node_id], task),
            None => self.coordinator.enqueue(&self.case, node_id, task),
        };
        match result {
            Ok(outcome) => {
                if matches!(outcome, EnqueueOutcome::ResourceExhausted { .. }) {
                    require(self.snapshot() == before);
                }
                self.remember_outcome(outcome, index);
            }
            Err(_) => require(self.snapshot() == before),
        }
    }

    fn prioritize_new(&mut self, selector: u8, index: usize) {
        let Some(outcome) = self.prior_outcome(selector, index) else {
            return;
        };
        let before = self.snapshot();
        if self.coordinator.prioritize_newly_queued(&outcome).is_err() {
            require(self.snapshot() == before);
        }
    }

    fn prioritize_from_parent(&mut self, outcome_selector: u8, parent_selector: u8, index: usize) {
        if self.ids.is_empty() {
            return;
        }
        let Some(outcome) = self.prior_outcome(outcome_selector, index) else {
            return;
        };
        let parent_id = self.selected_id(parent_selector);
        let repeat_target = self.merged_priority_target(outcome, parent_id);
        let before = self.snapshot();
        if self
            .coordinator
            .prioritize_queued_from_parent(&outcome, parent_id)
            .is_err()
        {
            require(self.snapshot() == before);
        } else if let Some((merged_id, work_before)) = repeat_target {
            self.check_repeated_promotion(outcome, parent_id, merged_id, work_before);
        }
    }

    fn merged_priority_target(
        &self,
        outcome: EnqueueOutcome,
        parent_id: RecoveryCandidateId,
    ) -> Option<(RecoveryCandidateId, usize)> {
        let EnqueueOutcome::Merged(merged_id) = outcome else {
            return None;
        };
        let parent_is_priority = self
            .coordinator
            .candidate(parent_id)
            .is_some_and(RecoveryCandidate::completion_priority);
        let target_needs_promotion =
            self.coordinator
                .candidate(merged_id)
                .is_some_and(|candidate| {
                    candidate.state() == &RecoveryCandidateState::Queued
                        && !candidate.completion_priority()
                });
        (parent_is_priority && target_needs_promotion)
            .then(|| (merged_id, self.coordinator.lineage_work_charged()))
    }

    fn check_repeated_promotion(
        &mut self,
        outcome: EnqueueOutcome,
        parent_id: RecoveryCandidateId,
        merged_id: RecoveryCandidateId,
        work_before: usize,
    ) {
        let Some(candidate) = self.coordinator.candidate(merged_id) else {
            fail();
        };
        require(candidate.completion_priority());
        let work_after_first = self.coordinator.lineage_work_charged();
        require(work_after_first >= work_before);
        let before_repeat = self.snapshot();
        require(
            self.coordinator
                .prioritize_queued_from_parent(&outcome, parent_id)
                .is_ok(),
        );
        require(self.snapshot() == before_repeat);
        require(self.coordinator.lineage_work_charged() == work_after_first);
    }

    fn pop_next(&mut self) {
        if let Some(id) = self.coordinator.pop_next().unwrap_or_else(|_| fail()) {
            require(id.index() < self.popped.len());
            require(self.ids.contains(&id));
            let Some(was_popped) = self.popped.get_mut(id.index()) else {
                fail();
            };
            require(!*was_popped);
            *was_popped = true;
            let Some(candidate) = self.coordinator.candidate(id) else {
                fail();
            };
            require(matches!(
                candidate.state(),
                RecoveryCandidateState::Running(_)
            ));
        }
    }

    fn finish(&mut self, selector: u8, result_selector: u8, kind: u8) {
        if self.ids.is_empty() {
            return;
        }
        let id = self.selected_id(selector);
        let result = if kind == 6 || result_selector % 3 == 2 {
            RecoveryResult::Derived {
                evidence_node_id: self.derived_output_id,
            }
        } else if result_selector.is_multiple_of(3) {
            RecoveryResult::Unsupported
        } else {
            RecoveryResult::Omitted
        };
        let before = self.snapshot();
        if self.coordinator.finish(&self.case, id, result).is_err() {
            require(self.snapshot() == before);
        }
    }

    fn source_node(&self, selector: u8) -> u64 {
        self.case
            .nodes()
            .get(usize::from(selector) % SOURCE_NODE_COUNT)
            .map_or_else(|| fail(), |node| node.id)
    }

    fn selected_id(&self, selector: u8) -> RecoveryCandidateId {
        self.ids
            .get(usize::from(selector) % self.ids.len())
            .copied()
            .unwrap_or_else(|| fail())
    }

    fn prior_outcome(&self, selector: u8, index: usize) -> Option<EnqueueOutcome> {
        if index == 0 {
            return None;
        }
        self.outcomes
            .get(usize::from(selector) % index)
            .copied()
            .flatten()
    }

    fn remember_outcome(&mut self, outcome: EnqueueOutcome, index: usize) {
        let Some(slot) = self.outcomes.get_mut(index) else {
            fail();
        };
        *slot = Some(outcome);
        let id = match outcome {
            EnqueueOutcome::Queued(id)
            | EnqueueOutcome::Merged(id)
            | EnqueueOutcome::MergedNeedsContext(id) => Some(id),
            EnqueueOutcome::CycleSkipped { candidate_id } => Some(candidate_id),
            EnqueueOutcome::ResourceExhausted { .. } => None,
        };
        let Some(id) = id else {
            return;
        };
        if self.ids.contains(&id) {
            return;
        }
        require(self.ids.len() < MAX_CANDIDATES);
        require(self.ids.len() < self.policy.max_candidates);
        self.ids.push(id);
    }

    fn check_invariants(&self) {
        let policy = self.policy;
        require(self.ids.len() <= MAX_CANDIDATES);
        require(self.ids.len() <= policy.max_candidates);
        require(self.coordinator.candidate_count() == self.ids.len());
        require(self.coordinator.work_bytes_charged() <= policy.max_work_bytes);
        require(
            self.coordinator.remaining_work_bytes()
                == policy.max_work_bytes - self.coordinator.work_bytes_charged(),
        );
        require(self.coordinator.lineage_work_charged() <= policy.max_lineage_work);
        require(
            self.coordinator.remaining_lineage_work()
                == policy.max_lineage_work - self.coordinator.lineage_work_charged(),
        );
        require(self.coordinator.parent_links_retained() <= policy.max_parent_links);
        require(self.coordinator.context_aliases_retained() <= policy.max_context_aliases);
        require(
            self.coordinator.pending_origin_links_retained() <= policy.max_pending_origin_links,
        );
        require(
            self.coordinator.candidate_task_identity_bytes_charged()
                <= policy.max_candidate_task_identity_bytes,
        );
        require(
            self.coordinator.remaining_candidate_task_identity_bytes()
                == policy.max_candidate_task_identity_bytes
                    - self.coordinator.candidate_task_identity_bytes_charged(),
        );

        let mut queued = 0;
        for (position, id) in self.ids.iter().enumerate() {
            require(id.index() < policy.max_candidates);
            require(!self.ids.iter().take(position).any(|prior| prior == id));
            let Some(candidate) = self.coordinator.candidate(*id) else {
                fail();
            };
            if candidate.state() == &RecoveryCandidateState::Queued {
                queued += 1;
            }
            if self
                .popped
                .get(id.index())
                .copied()
                .unwrap_or_else(|| fail())
            {
                require(candidate.state() != &RecoveryCandidateState::Queued);
            }
        }
        require(queued <= policy.max_frontier);
        require(self.coordinator.peek_next_id().is_some() == (queued > 0));
    }

    fn snapshot(&self) -> Snapshot {
        let candidates = self
            .ids
            .iter()
            .map(|id| {
                self.coordinator
                    .candidate(*id)
                    .cloned()
                    .unwrap_or_else(|| fail())
            })
            .collect();
        Snapshot {
            count: self.coordinator.candidate_count(),
            head: self.coordinator.peek_next_id(),
            parent_links: self.coordinator.parent_links_retained(),
            context_aliases: self.coordinator.context_aliases_retained(),
            pending_links: self.coordinator.pending_origin_links_retained(),
            task_identity_bytes: self.coordinator.candidate_task_identity_bytes_charged(),
            candidates,
        }
    }
}

fn queue_case(input: &[u8]) -> (Case, u64) {
    let mut case = Case::new();
    let marker = input.first().copied().unwrap_or_default();
    let nodes: [u64; SOURCE_NODE_COUNT] = std::array::from_fn(|index| {
        let class = u8::try_from(index / 2).unwrap_or_else(|_| fail());
        add_bytes_node(&mut case, "queue_source", &[marker, class])
    });
    let output = add_bytes_node(&mut case, "queue_derived_output", &[marker, 0xD0]);
    for node_id in nodes {
        add_derived_edge(&mut case, output, node_id);
    }
    (case, output)
}

fn selected_task(selector: u8) -> RecoveryTask {
    match selector % 4 {
        0 => RecoveryTask::EmbeddedDiscovery,
        1 => RecoveryTask::RecursiveExpansion,
        2 => RecoveryTask::StructuralValidation,
        3 => RecoveryTask::FramingDiscovery,
        _ => fail(),
    }
}
