//! Track candidate ancestry and reject cyclic recovery paths

use super::super::case_refs;
use super::super::{
    EnqueueOutcome, RecoveryCandidateId, RecoveryInput, RecoveryResource, RecoveryTask,
};
use super::identity::{candidate_work_identity, same_task_identity, task_has_origin_context};
use super::{RecoveryCoordinator, RecoveryError};
use crate::evidence::Case;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};

pub(super) enum LineageSearchOutcome {
    NoAncestor,
    Ancestor(RecoveryCandidateId),
    Exhausted(EnqueueOutcome),
}

enum LineageWorkOutcome<T> {
    Complete(T),
    Exhausted(EnqueueOutcome),
}

struct LineageCandidate {
    depth: usize,
    id: RecoveryCandidateId,
    parent_ids: Vec<RecoveryCandidateId>,
}

struct LineageScan {
    candidates: Vec<LineageCandidate>,
    matches: HashSet<RecoveryCandidateId>,
}

struct CleanPathNode {
    id: RecoveryCandidateId,
    resolved: bool,
    clean: bool,
    has_clean_parent: bool,
    unresolved_parent_count: usize,
    children: Vec<usize>,
}

struct CleanPathGraph {
    candidate_indices: HashMap<RecoveryCandidateId, usize>,
    nodes: Vec<CleanPathNode>,
}

impl RecoveryCoordinator {
    pub(super) fn cycle_ancestor(
        &mut self,
        case: &Case,
        parent_ids: &[RecoveryCandidateId],
        work_identity: &(String, String),
        task: &RecoveryTask,
        inputs: &[RecoveryInput],
        blobs: &[&crate::evidence::Blob],
    ) -> Result<LineageSearchOutcome, RecoveryError> {
        if parent_ids.is_empty() {
            return Ok(LineageSearchOutcome::NoAncestor);
        }
        let scan = match self.scan_lineage(case, parent_ids, work_identity, task, inputs, blobs)? {
            LineageWorkOutcome::Complete(scan) => scan,
            LineageWorkOutcome::Exhausted(outcome) => {
                return Ok(LineageSearchOutcome::Exhausted(outcome));
            }
        };
        if scan.matches.is_empty() {
            return Ok(LineageSearchOutcome::NoAncestor);
        }
        match self.has_clean_parent_path(parent_ids, &scan)? {
            LineageWorkOutcome::Complete(true) => return Ok(LineageSearchOutcome::NoAncestor),
            LineageWorkOutcome::Complete(false) => {}
            LineageWorkOutcome::Exhausted(outcome) => {
                return Ok(LineageSearchOutcome::Exhausted(outcome));
            }
        }

        let nearest = scan
            .candidates
            .iter()
            .rev()
            .find(|candidate| scan.matches.contains(&candidate.id))
            .map(|candidate| candidate.id)
            .ok_or(RecoveryError::InvariantFailure)?;
        Ok(LineageSearchOutcome::Ancestor(nearest))
    }

    fn scan_lineage(
        &mut self,
        case: &Case,
        parent_ids: &[RecoveryCandidateId],
        work_identity: &(String, String),
        task: &RecoveryTask,
        inputs: &[RecoveryInput],
        blobs: &[&crate::evidence::Blob],
    ) -> Result<LineageWorkOutcome<LineageScan>, RecoveryError> {
        let mut lineage = Vec::new();
        let mut pending = VecDeque::new();
        pending
            .try_reserve(parent_ids.len())
            .map_err(|_| RecoveryError::AllocationFailed)?;
        for parent_id in parent_ids {
            if let Some(exhausted) = self.charge_lineage_work() {
                return Ok(LineageWorkOutcome::Exhausted(exhausted));
            }
            pending.push_back(*parent_id);
        }

        let mut seen = HashSet::new();
        let mut matches = HashSet::new();
        while let Some(id) = pending.pop_front() {
            if !seen.insert(id) {
                continue;
            }
            if let Some(exhausted) = self.charge_lineage_work() {
                return Ok(LineageWorkOutcome::Exhausted(exhausted));
            }
            let (matches_task, depth, candidate_parents) = {
                let candidate = self.candidate(id).ok_or(RecoveryError::InvariantFailure)?;
                let matches_task = candidate_work_identity(candidate.inputs(), candidate.task())?
                    == *work_identity
                    && same_task_identity(candidate.task(), task)
                    && (!task_has_origin_context(task)
                        || case_refs::same_origin_context(candidate.inputs(), inputs))
                    && case_refs::same_input_bytes(case, candidate.inputs(), blobs);
                let mut parents = Vec::new();
                parents
                    .try_reserve_exact(candidate.parent_ids.len())
                    .map_err(|_| RecoveryError::AllocationFailed)?;
                parents.extend_from_slice(&candidate.parent_ids);
                (matches_task, candidate.depth(), parents)
            };
            for parent_id in &candidate_parents {
                if let Some(exhausted) = self.charge_lineage_work() {
                    return Ok(LineageWorkOutcome::Exhausted(exhausted));
                }
                pending
                    .try_reserve(1)
                    .map_err(|_| RecoveryError::AllocationFailed)?;
                pending.push_back(*parent_id);
            }
            lineage
                .try_reserve(1)
                .map_err(|_| RecoveryError::AllocationFailed)?;
            lineage.push(LineageCandidate {
                depth,
                id,
                parent_ids: candidate_parents,
            });
            if matches_task {
                matches.insert(id);
            }
        }
        // Keep candidate and edge visits deterministic when lineage work is budgeted
        lineage.sort_unstable_by_key(|candidate| (candidate.depth, candidate.id.index()));
        Ok(LineageWorkOutcome::Complete(LineageScan {
            candidates: lineage,
            matches,
        }))
    }

    fn has_clean_parent_path(
        &mut self,
        parent_ids: &[RecoveryCandidateId],
        scan: &LineageScan,
    ) -> Result<LineageWorkOutcome<bool>, RecoveryError> {
        let mut graph = match self.build_clean_path_graph(scan)? {
            LineageWorkOutcome::Complete(graph) => graph,
            LineageWorkOutcome::Exhausted(outcome) => {
                return Ok(LineageWorkOutcome::Exhausted(outcome));
            }
        };
        Self::resolve_clean_path_graph(&mut graph)?;

        for parent_id in parent_ids {
            if let Some(exhausted) = self.charge_lineage_work() {
                return Ok(LineageWorkOutcome::Exhausted(exhausted));
            }
            let index = *graph
                .candidate_indices
                .get(parent_id)
                .ok_or(RecoveryError::InvariantFailure)?;
            let candidate = graph
                .nodes
                .get(index)
                .ok_or(RecoveryError::InvariantFailure)?;
            if candidate.clean {
                return Ok(LineageWorkOutcome::Complete(true));
            }
        }
        Ok(LineageWorkOutcome::Complete(false))
    }

    fn build_clean_path_graph(
        &mut self,
        scan: &LineageScan,
    ) -> Result<LineageWorkOutcome<CleanPathGraph>, RecoveryError> {
        let candidate_count = scan.candidates.len();
        let mut candidate_indices = HashMap::new();
        candidate_indices
            .try_reserve(candidate_count)
            .map_err(|_| RecoveryError::AllocationFailed)?;
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(candidate_count)
            .map_err(|_| RecoveryError::AllocationFailed)?;
        for (index, candidate) in scan.candidates.iter().enumerate() {
            if candidate_indices.insert(candidate.id, index).is_some() {
                return Err(RecoveryError::InvariantFailure);
            }
            let is_match = scan.matches.contains(&candidate.id);
            let is_root = candidate.parent_ids.is_empty();
            nodes.push(CleanPathNode {
                id: candidate.id,
                resolved: is_match || is_root,
                clean: !is_match && is_root,
                has_clean_parent: false,
                unresolved_parent_count: 0,
                children: Vec::new(),
            });
        }

        // Matches block clean paths, and unmatched roots already have a clean path
        // Count each relevant parent edge once, matching the existing lineage-work charge
        for (index, candidate) in scan.candidates.iter().enumerate() {
            let candidate_is_resolved = nodes
                .get(index)
                .ok_or(RecoveryError::InvariantFailure)?
                .resolved;
            if candidate_is_resolved {
                continue;
            }
            for parent_id in &candidate.parent_ids {
                if let Some(exhausted) = self.charge_lineage_work() {
                    return Ok(LineageWorkOutcome::Exhausted(exhausted));
                }
                let parent_index = *candidate_indices
                    .get(parent_id)
                    .ok_or(RecoveryError::InvariantFailure)?;
                let parent = nodes
                    .get(parent_index)
                    .ok_or(RecoveryError::InvariantFailure)?;
                if parent.resolved {
                    let parent_is_clean = parent.clean;
                    let candidate = nodes
                        .get_mut(index)
                        .ok_or(RecoveryError::InvariantFailure)?;
                    candidate.has_clean_parent |= parent_is_clean;
                } else {
                    let candidate = nodes
                        .get_mut(index)
                        .ok_or(RecoveryError::InvariantFailure)?;
                    candidate.unresolved_parent_count = candidate
                        .unresolved_parent_count
                        .checked_add(1)
                        .ok_or(RecoveryError::InvariantFailure)?;
                    let parent = nodes
                        .get_mut(parent_index)
                        .ok_or(RecoveryError::InvariantFailure)?;
                    parent
                        .children
                        .try_reserve(1)
                        .map_err(|_| RecoveryError::AllocationFailed)?;
                    parent.children.push(index);
                }
            }
        }

        Ok(LineageWorkOutcome::Complete(CleanPathGraph {
            candidate_indices,
            nodes,
        }))
    }

    fn resolve_clean_path_graph(graph: &mut CleanPathGraph) -> Result<(), RecoveryError> {
        let node_count = graph.nodes.len();
        // Resolve candidates only after every unresolved parent has a known clean-path value
        let mut ready = BinaryHeap::new();
        ready
            .try_reserve(node_count)
            .map_err(|_| RecoveryError::AllocationFailed)?;
        for (index, candidate) in graph.nodes.iter().enumerate() {
            if !candidate.resolved && candidate.unresolved_parent_count == 0 {
                ready.push(Reverse((candidate.id.index(), index)));
            }
        }
        while let Some(Reverse((_, index))) = ready.pop() {
            let (candidate_is_clean, children) = {
                let candidate = graph
                    .nodes
                    .get_mut(index)
                    .ok_or(RecoveryError::InvariantFailure)?;
                if candidate.resolved {
                    return Err(RecoveryError::InvariantFailure);
                }
                candidate.resolved = true;
                candidate.clean = candidate.has_clean_parent;
                (candidate.clean, std::mem::take(&mut candidate.children))
            };
            for child_index in &children {
                let child = graph
                    .nodes
                    .get_mut(*child_index)
                    .ok_or(RecoveryError::InvariantFailure)?;
                child.unresolved_parent_count = child
                    .unresolved_parent_count
                    .checked_sub(1)
                    .ok_or(RecoveryError::InvariantFailure)?;
                child.has_clean_parent |= candidate_is_clean;
                if child.unresolved_parent_count == 0 {
                    ready.push(Reverse((child.id.index(), *child_index)));
                }
            }
            graph
                .nodes
                .get_mut(index)
                .ok_or(RecoveryError::InvariantFailure)?
                .children = children;
        }

        // Kahn leaves cycles and their descendants unresolved. A clean alternate parent still
        // makes that candidate clean, so carry clean paths through the remaining graph
        let mut clean_residual = BinaryHeap::new();
        clean_residual
            .try_reserve(node_count)
            .map_err(|_| RecoveryError::AllocationFailed)?;
        for (index, candidate) in graph.nodes.iter_mut().enumerate() {
            if !candidate.resolved && candidate.has_clean_parent {
                candidate.clean = true;
                clean_residual.push(Reverse((candidate.id.index(), index)));
            }
        }
        while let Some(Reverse((_, index))) = clean_residual.pop() {
            let children = std::mem::take(
                &mut graph
                    .nodes
                    .get_mut(index)
                    .ok_or(RecoveryError::InvariantFailure)?
                    .children,
            );
            for child_index in &children {
                let child = graph
                    .nodes
                    .get_mut(*child_index)
                    .ok_or(RecoveryError::InvariantFailure)?;
                if !child.resolved && !child.clean {
                    child.clean = true;
                    clean_residual.push(Reverse((child.id.index(), *child_index)));
                }
            }
            graph
                .nodes
                .get_mut(index)
                .ok_or(RecoveryError::InvariantFailure)?
                .children = children;
        }
        Ok(())
    }

    const fn charge_lineage_work(&mut self) -> Option<EnqueueOutcome> {
        if self.lineage_work >= self.resources.max_lineage_work {
            return Some(EnqueueOutcome::ResourceExhausted {
                resource: RecoveryResource::LineageWork,
                limit: self.resources.max_lineage_work,
                used: self.lineage_work,
                requested: 1,
            });
        }
        self.lineage_work += 1;
        None
    }
}
