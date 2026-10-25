use super::{Case, CaseResourceLimits};
use crate::evidence::model::Source;
use std::{collections::HashMap, panic};

#[derive(Debug)]
pub(super) struct CaseCheckpoint {
    schema_version: u32,
    collection_complete: bool,
    resource_limits: CaseResourceLimits,
    source_count: usize,
    source_snapshots: HashMap<usize, Source>,
    blob_count: usize,
    node_count: usize,
    edge_count: usize,
    limitation_count: usize,
    blob_bytes: usize,
    details_bytes: usize,
    range_count: usize,
}

impl CaseCheckpoint {
    fn capture(case: &Case) -> Self {
        Self {
            schema_version: case.schema_version,
            collection_complete: case.collection_complete,
            resource_limits: case.resource_limits,
            source_count: case.sources.len(),
            source_snapshots: HashMap::new(),
            blob_count: case.blobs.len(),
            node_count: case.nodes.len(),
            edge_count: case.edges.len(),
            limitation_count: case.limitations.len(),
            blob_bytes: case.blob_bytes,
            details_bytes: case.details_bytes,
            range_count: case.range_count,
        }
    }

    fn restore(self, case: &mut Case) {
        // Remove blobs added after the checkpoint and their index entries
        for blob in case.blobs.drain(self.blob_count..) {
            case.blob_index.remove(&blob.id);
        }
        // Restore metadata for existing rows that were changed in this scope
        for (index, source) in self.source_snapshots {
            if let Some(retained) = case.sources.get_mut(index) {
                *retained = source;
            }
        }
        // Remove appended sources and their index entries
        for source in case.sources.drain(self.source_count..) {
            case.source_index.remove(&source.id);
        }

        // Drop appended graph records and limitations by their old lengths
        case.nodes.truncate(self.node_count);
        case.truncate_edges(self.edge_count);
        case.limitations.truncate(self.limitation_count);

        // Restore values that must agree with the retained records
        case.schema_version = self.schema_version;
        case.collection_complete = self.collection_complete;
        case.resource_limits = self.resource_limits;
        case.blob_bytes = self.blob_bytes;
        case.details_bytes = self.details_bytes;
        case.range_count = self.range_count;
    }
}

impl Case {
    pub(super) fn snapshot_source_mutation(&mut self, index: usize) {
        let Some(source) = self.sources.get(index) else {
            return;
        };

        for checkpoint in &mut self.transaction_checkpoints {
            if index < checkpoint.source_count {
                checkpoint
                    .source_snapshots
                    .entry(index)
                    .or_insert_with(|| source.clone());
            }
        }
    }

    /// Apply multiple evidence changes as one append-only transaction
    ///
    /// Successful closures keep their changes. A returned `Err` removes records
    /// added by Case mutation methods and restores counters, indexes, source
    /// metadata, resource limits, and collection completeness. Existing source
    /// rows are copied only when a mutation first changes them in each transaction
    /// scope. Existing blob bytes are never cloned. Nested transactions each roll
    /// back to their own starting point
    ///
    /// Only a returned `Err` triggers rollback. A panic can unwind with the Case
    /// partially modified
    ///
    /// # Errors
    /// Returns the closure error after restoring the checkpoint
    pub fn transaction<T, E>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<T, E> {
        let checkpoint = CaseCheckpoint::capture(self);
        self.transaction_checkpoints.push(checkpoint);

        // Clean up the internal scope even when a closure unwinds
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| operation(self)));
        match result {
            Ok(Ok(value)) => {
                self.transaction_checkpoints.pop();
                Ok(value)
            }
            Ok(Err(error)) => {
                if let Some(checkpoint) = self.transaction_checkpoints.pop() {
                    checkpoint.restore(self);
                }
                Err(error)
            }
            Err(payload) => {
                self.transaction_checkpoints.pop();
                panic::resume_unwind(payload)
            }
        }
    }
}

#[cfg(test)]
#[path = "../../tests/evidence/transaction_internal.rs"]
mod internal_tests;
