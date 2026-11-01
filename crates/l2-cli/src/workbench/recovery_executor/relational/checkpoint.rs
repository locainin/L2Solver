//! Persist one relational candidate without publishing partial cohorts

pub(super) mod prepared;

use super::{Executor, PreparedRelationalCohort, RecoveryCandidateId, RecoveryError};
use l2_workbench::job::MemoryLease;

mod live;
pub(in crate::workbench::recovery_executor) use live::prepare;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::workbench::recovery_executor) struct RelationalProgress {
    pub(in crate::workbench::recovery_executor) candidate_id: RecoveryCandidateId,
    pub(super) next_context: usize,
    pub(super) work_remaining: usize,
    pub(super) prepared: Vec<PreparedRelationalCohort>,
    pub(super) active: Option<ActiveSearch>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ActiveSearch {
    #[serde(with = "l2_workbench::job::checkpoint_bytes")]
    pub(super) cursor: Vec<u8>,
    #[serde(with = "l2_workbench::job::checkpoint_bytes")]
    pub(super) gate: Vec<u8>,
    #[serde(with = "l2_workbench::job::checkpoint_bytes")]
    pub(super) history: Vec<u8>,
    pub(super) candidates_examined: usize,
    // Encoded buffers keep their live allocation charges outside the saved representation
    #[serde(skip)]
    pub(super) _memory: Vec<MemoryLease>,
}

impl RelationalProgress {
    pub(in crate::workbench::recovery_executor) fn validate(
        &self,
        executor: &Executor<'_>,
    ) -> Result<(), RecoveryError> {
        let contexts = executor
            .relational_discoveries
            .get(&self.candidate_id)
            .ok_or(RecoveryError::InvalidCheckpoint)?;
        if self.next_context != self.prepared.len()
            || self.next_context >= contexts.len()
            || self.work_remaining > executor.coordinator.remaining_work_bytes()
            || self
                .prepared
                .last()
                .is_some_and(|last| last.work_bytes_remaining != self.work_remaining)
            || self
                .active
                .as_ref()
                .is_none_or(|active| active.cursor.is_empty() || active.gate.is_empty())
        {
            return Err(RecoveryError::InvalidCheckpoint);
        }
        Ok(())
    }
}
