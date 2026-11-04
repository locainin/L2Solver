//! Admit Case-derived executor index entries before allocating them

use super::{ContextualDecodingViewKey, RecoveryError, RecoveryExecutionError, RecoveryStage};
use l2_workbench::job::{MemoryBudget, MemoryClass, MemoryLease};
use std::collections::BTreeSet;

// Allow the live hash table and its replacement during a growth operation
const HASH_BUCKETS_PER_ENTRY: usize = 8;
const HASH_CONTROL_BYTES_PER_ENTRY: usize = 16;

pub(super) fn new(
    memory: Option<&MemoryBudget>,
) -> Result<Option<MemoryLease>, RecoveryExecutionError> {
    memory
        .map(|memory| memory.try_reserve(MemoryClass::Executor, 0))
        .transpose()
        .map_err(operational)
}

pub(super) fn decoding_output(
    memory: &mut Option<MemoryLease>,
) -> Result<(), RecoveryExecutionError> {
    admit(memory, hash_entry::<u64, u64>()?)
}

pub(super) fn contextual_view(
    memory: &mut Option<MemoryLease>,
) -> Result<(), RecoveryExecutionError> {
    admit(memory, hash_entry::<ContextualDecodingViewKey, u64>()?)
}

pub(super) fn validated_range(
    memory: &mut Option<MemoryLease>,
    new_receipt: bool,
) -> Result<(), RecoveryExecutionError> {
    // One full BTree node per edge also bounds sparse trees with different receipt IDs
    let tree =
        l2_workbench::btree_node_bytes::<u64, ()>().ok_or(RecoveryError::AllocationFailed)?;
    let bytes = if new_receipt {
        hash_entry::<u64, BTreeSet<u64>>()?
            .checked_add(tree)
            .ok_or(RecoveryError::AllocationFailed)?
    } else {
        tree
    };
    admit(memory, bytes)
}

fn hash_entry<K, V>() -> Result<usize, RecoveryExecutionError> {
    size_of::<(K, V)>()
        .checked_add(1)
        .and_then(|bytes| bytes.checked_mul(HASH_BUCKETS_PER_ENTRY))
        .and_then(|bytes| bytes.checked_add(HASH_CONTROL_BYTES_PER_ENTRY))
        .ok_or_else(|| RecoveryError::AllocationFailed.into())
}

fn admit(memory: &mut Option<MemoryLease>, bytes: usize) -> Result<(), RecoveryExecutionError> {
    let Some(memory) = memory else {
        return Ok(());
    };
    let requested = u64::try_from(bytes)
        .ok()
        .and_then(|bytes| memory.bytes().checked_add(bytes))
        .ok_or(RecoveryError::AllocationFailed)?;
    memory.try_resize(requested).map_err(operational)
}

fn operational(error: l2_workbench::job::MemoryError) -> RecoveryExecutionError {
    RecoveryExecutionError::Operational {
        stage: RecoveryStage::StructuralValidation,
        source: Box::new(error),
    }
}
