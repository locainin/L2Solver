/// Caller-resolved budgets shared by every recovery stage
///
/// Values are used as supplied and are never scaled by the coordinator
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryResourcePolicy {
    /// Maximum distinct candidate tasks accepted in this coordinator
    pub max_candidates: usize,
    /// Maximum queued candidate tasks waiting for work
    pub max_frontier: usize,
    /// Maximum input positions in one candidate batch
    pub max_inputs_per_candidate: usize,
    /// Maximum distinct evidence origins retained for one candidate
    pub max_origins_per_candidate: usize,
    /// Maximum bytes in one retained input position
    pub max_input_bytes_per_item: usize,
    /// Maximum bytes summed across one candidate input batch
    pub max_total_input_bytes_per_candidate: usize,
    /// Maximum number of expansion edges from a root candidate
    pub max_depth: usize,
    /// Maximum bytes one executor may retain from a candidate result
    pub max_output_bytes: usize,
    /// Maximum cumulative work bytes charged across all candidates
    pub max_work_bytes: usize,
    /// Maximum serialized task-identity bytes retained across candidates
    pub max_candidate_task_identity_bytes: usize,
    /// Maximum canonical recipe-identity bytes retained for transform proposals
    pub max_transform_proposal_identity_bytes: usize,
    /// Maximum unique transform-proposal report-node and recipe associations
    pub max_transform_proposal_associations: usize,
    /// Maximum distinct parent links retained across all candidates
    pub max_parent_links: usize,
    /// Maximum candidate visits and parent-edge examinations during cycle analysis
    pub max_lineage_work: usize,
    /// Maximum retained input-position and origin-node references across candidates
    pub max_context_aliases: usize,
    /// Maximum pending direct result links for late origins across candidates
    pub max_pending_origin_links: usize,
}

/// Result of checking a caller-reported resource request
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetCheck {
    /// The request fits within the selected policy
    WithinBudget,
    /// The request exceeds one selected policy value
    Exhausted {
        resource: super::RecoveryResource,
        limit: usize,
        used: usize,
        requested: usize,
    },
}
