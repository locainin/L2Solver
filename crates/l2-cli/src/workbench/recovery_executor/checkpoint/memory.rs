//! Admit owned checkpoint metadata before rebuilding executor state

use super::{RecoveryError, RecoveryExecutionError, operational};
use l2_workbench::job::{
    JsonMemoryAdmission, JsonMemoryError, MemoryBudget, MemoryClass, admit_json,
};

pub(super) fn admit(
    bytes: &[u8],
    memory: Option<&MemoryBudget>,
) -> Result<Option<JsonMemoryAdmission>, RecoveryExecutionError> {
    memory
        .map(|memory| admit_json(bytes, memory, MemoryClass::Executor))
        .transpose()
        .map_err(|error| match error {
            JsonMemoryError::Memory(error) => operational(error),
            JsonMemoryError::InvalidJson { .. } | JsonMemoryError::SizeOverflow => {
                RecoveryError::InvalidCheckpoint.into()
            }
        })
}
