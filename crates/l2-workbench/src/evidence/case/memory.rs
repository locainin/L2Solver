//! Logical charges for retained Case allocations
//!
//! Vector charges use observed capacity. Hash indexes include spare buckets,
//! alignment, and control bytes for the current Rust hash-table layout
//! JSON objects use a conservative model of the current `serde_json` `BTreeMap` nodes
//! Neither model promises allocator overhead or future Rust layouts

#[cfg(test)]
#[path = "../../../tests/evidence/case_memory_internal.rs"]
mod tests;

use super::{Case, Edge, EvidenceError, SourceRange};
use crate::job::{MemoryBudget, MemoryClass, MemoryLease};
use serde_json::Value;
use std::{
    collections::HashMap,
    hash::Hash,
    mem::{align_of, size_of},
};

// Rust 1.96 uses hashbrown 0.16.1, whose supported control groups are at most 16 bytes
// Review the allocation model when changing the toolchain or hash-table implementation
const HASH_CONTROL_GROUP_BYTES: usize = 16;

#[derive(Debug)]
pub(super) struct CaseMemory {
    pub(super) blobs: MemoryLease,
    graph: MemoryLease,
}

impl CaseMemory {
    pub(super) fn new(budget: &MemoryBudget) -> Result<Self, EvidenceError> {
        let blobs = budget
            .try_reserve(MemoryClass::Case, 0)
            .map_err(EvidenceError::Memory)?;
        let graph = budget
            .try_reserve(MemoryClass::Case, 0)
            .map_err(EvidenceError::Memory)?;
        Ok(Self { blobs, graph })
    }

    pub(super) fn try_duplicate(&self) -> Result<Self, EvidenceError> {
        Ok(Self {
            blobs: self.blobs.try_duplicate().map_err(EvidenceError::Memory)?,
            graph: self.graph.try_duplicate().map_err(EvidenceError::Memory)?,
        })
    }

    pub(super) fn try_scratch(&self, bytes: u64) -> Result<MemoryLease, EvidenceError> {
        self.graph.try_sibling(bytes).map_err(EvidenceError::Memory)
    }

    pub(super) const fn graph_bytes(&self) -> u64 {
        self.graph.bytes()
    }

    pub(super) fn reserve_graph(&mut self, bytes: usize) -> Result<(), EvidenceError> {
        let bytes = to_bytes(bytes)?;
        let requested = self.graph.bytes().checked_add(bytes).ok_or_else(overflow)?;
        self.graph
            .try_resize(requested)
            .map_err(EvidenceError::Memory)
    }

    pub(super) fn set_graph(&mut self, bytes: usize) -> Result<(), EvidenceError> {
        self.graph
            .try_resize(to_bytes(bytes)?)
            .map_err(EvidenceError::Memory)
    }

    pub(super) fn release_graph(&mut self, bytes: usize) -> Result<(), EvidenceError> {
        let remaining = self
            .graph
            .bytes()
            .checked_sub(to_bytes(bytes)?)
            .ok_or_else(overflow)?;
        self.graph
            .try_resize(remaining)
            .map_err(EvidenceError::Memory)
    }

    pub(super) fn restore_graph(&mut self, bytes: u64) {
        let _ = self.graph.try_resize(bytes);
    }
}

const fn overflow() -> EvidenceError {
    EvidenceError::ArithmeticOverflow {
        field: "Case memory bytes",
    }
}

fn to_bytes(bytes: usize) -> Result<u64, EvidenceError> {
    u64::try_from(bytes).map_err(|_| overflow())
}

fn array_bytes<T>(capacity: usize) -> Result<usize, EvidenceError> {
    capacity.checked_mul(size_of::<T>()).ok_or_else(overflow)
}

fn add(total: usize, amount: usize) -> Result<usize, EvidenceError> {
    total.checked_add(amount).ok_or_else(overflow)
}

/// Grow a Case vector while both old and new backing buffers remain charged
pub(super) fn grow_vec<T>(
    memory: &mut Option<CaseMemory>,
    values: &mut Vec<T>,
) -> Result<(), EvidenceError> {
    let Some(memory) = memory else {
        return Ok(());
    };
    let required = values.len().checked_add(1).ok_or_else(overflow)?;
    grow_vec_lease(&mut memory.graph, values, required)
}

pub(super) fn grow_vec_lease<T>(
    lease: &mut MemoryLease,
    values: &mut Vec<T>,
    required: usize,
) -> Result<(), EvidenceError> {
    if required <= values.capacity() {
        return Ok(());
    }
    let old_bytes = array_bytes::<T>(values.capacity())?;
    let wanted = values.capacity().saturating_mul(2).max(4).max(required);
    let proposed = array_bytes::<T>(wanted)?;
    let mut pending = lease
        .try_sibling(to_bytes(proposed)?)
        .map_err(EvidenceError::Memory)?;
    let mut grown = Vec::new();
    grown
        .try_reserve_exact(wanted)
        .map_err(|_| EvidenceError::AllocationFailed {
            field: "Case graph vector",
        })?;
    let actual = array_bytes::<T>(grown.capacity())?;
    pending
        .try_resize(to_bytes(actual)?)
        .map_err(EvidenceError::Memory)?;
    // Move records only after the replacement capacity has a live charge
    grown.append(values);
    *values = grown;
    lease.absorb(pending);
    lease
        .try_resize(lease.bytes() - to_bytes(old_bytes)?)
        .map_err(EvidenceError::Memory)
}

/// Grow an index without changing it when admission or allocation fails
pub(super) fn grow_map<K: Eq + Hash, V>(
    memory: &mut Option<CaseMemory>,
    values: &mut HashMap<K, V>,
) -> Result<(), EvidenceError> {
    grow_map_for(memory, values, 1)
}

pub(super) fn grow_map_for<K: Eq + Hash, V>(
    memory: &mut Option<CaseMemory>,
    values: &mut HashMap<K, V>,
    additional: usize,
) -> Result<(), EvidenceError> {
    let Some(memory) = memory else {
        return Ok(());
    };
    let required = values.len().checked_add(additional).ok_or_else(overflow)?;
    if required <= values.capacity() {
        return Ok(());
    }
    let old_bytes = map_bytes::<K, V>(values.capacity())?;
    let wanted = values.capacity().saturating_mul(2).max(4).max(required);
    let proposed = map_bytes::<K, V>(wanted)?;
    let mut pending = memory
        .graph
        .try_sibling(to_bytes(proposed)?)
        .map_err(EvidenceError::Memory)?;
    let mut grown = HashMap::new();
    grown
        .try_reserve(wanted)
        .map_err(|_| EvidenceError::AllocationFailed {
            field: "Case graph index",
        })?;
    let actual = map_bytes::<K, V>(grown.capacity())?;
    pending
        .try_resize(to_bytes(actual)?)
        .map_err(EvidenceError::Memory)?;
    // The requested capacity can accept all existing entries and the planned additions
    grown.extend(values.drain());
    *values = grown;
    memory.graph.absorb(pending);
    memory
        .graph
        .try_resize(memory.graph.bytes() - to_bytes(old_bytes)?)
        .map_err(EvidenceError::Memory)
}

pub(super) fn map_bytes<K, V>(capacity: usize) -> Result<usize, EvidenceError> {
    if capacity == 0 {
        return Ok(0);
    }
    let entry = size_of::<(K, V)>();
    // Usable capacity excludes the buckets kept empty to terminate failed lookups
    // Small entries also need enough buckets to cover the aligned control group
    let buckets = if capacity < 15 {
        let minimum = match entry {
            0..=1 => 16,
            2..=3 => 8,
            _ => 4,
        };
        capacity
            .checked_add(1)
            .and_then(usize::checked_next_power_of_two)
            .ok_or_else(overflow)?
            .max(minimum)
    } else {
        capacity
            .checked_mul(8)
            .map(|value| value / 7)
            .and_then(usize::checked_next_power_of_two)
            .ok_or_else(overflow)?
    };
    // hashbrown::raw::TableLayout places the control array after aligned bucket storage
    let alignment = align_of::<(K, V)>().max(HASH_CONTROL_GROUP_BYTES);
    let bucket_bytes = buckets.checked_mul(entry).ok_or_else(overflow)?;
    let control_offset = add(bucket_bytes, alignment - 1)? & !(alignment - 1);
    add(add(control_offset, buckets)?, HASH_CONTROL_GROUP_BYTES)
}

pub(super) fn source_payload(source: &super::Source) -> Result<usize, EvidenceError> {
    let mut bytes = source.id.capacity();
    bytes = add(bytes, source.label.capacity())?;
    bytes = add(bytes, source.kind.capacity())?;
    bytes = add(bytes, source.blob.as_ref().map_or(0, String::capacity))?;
    bytes = add(bytes, array_bytes::<String>(source.aliases.capacity())?)?;
    for alias in &source.aliases {
        bytes = add(bytes, alias.capacity())?;
    }
    Ok(bytes)
}

pub(super) fn node_payload(
    kind: &str,
    blob: Option<&str>,
    ranges: &[SourceRange],
    range_capacity: usize,
    details: &Value,
) -> Result<usize, EvidenceError> {
    let mut bytes = add(kind.len(), blob.map_or(0, str::len))?;
    bytes = add(bytes, array_bytes::<SourceRange>(range_capacity)?)?;
    for range in ranges {
        bytes = add(bytes, range.source.capacity())?;
    }
    add(bytes, value_bytes(details)?)
}

pub(super) fn edge_payload(edge: &Edge) -> Result<usize, EvidenceError> {
    add(edge.relation.capacity(), edge.reason.capacity())
}

pub(super) fn value_bytes(value: &Value) -> Result<usize, EvidenceError> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(0),
        Value::String(text) => Ok(text.capacity()),
        Value::Array(values) => {
            let mut bytes = array_bytes::<Value>(values.capacity())?;
            for value in values {
                bytes = add(bytes, value_bytes(value)?)?;
            }
            Ok(bytes)
        }
        Value::Object(fields) => {
            let mut bytes = json_object_nodes(fields.len())?;
            for (key, value) in fields {
                bytes = add(add(bytes, key.capacity())?, value_bytes(value)?)?;
            }
            Ok(bytes)
        }
    }
}

fn json_object_nodes(entries: usize) -> Result<usize, EvidenceError> {
    // The v1 model follows serde_json's BTreeMap and Rust 1.96 node layout
    // This model must be reviewed when serde_json map features or the Rust toolchain change
    // Rust 1.96 uses 11 key/value slots per node without the preserve_order feature
    // Each non-root node has at least 5 entries after rebalancing
    let nodes = if entries < 11 {
        1
    } else {
        (entries - 1) / 5 + 1
    };
    // Charge every node as an internal node with 12 child pointers and a padded header
    // An emptied map can retain a root node after its final entry is removed
    let slots = 11_usize
        .checked_mul(size_of::<(String, Value)>())
        .ok_or_else(overflow)?;
    let header_and_children = 14_usize
        .checked_mul(size_of::<usize>())
        .ok_or_else(overflow)?;
    nodes
        .checked_mul(add(slots, header_and_children)?)
        .ok_or_else(overflow)
}

pub(super) fn graph_bytes(case: &Case) -> Result<usize, EvidenceError> {
    let mut bytes = array_bytes::<super::Source>(case.sources.capacity())?;
    bytes = add(
        bytes,
        map_bytes::<String, usize>(case.source_index.capacity())?,
    )?;
    for source in &case.sources {
        bytes = add(bytes, source_payload(source)?)?;
    }
    for key in case.source_index.keys() {
        bytes = add(bytes, key.capacity())?;
    }
    bytes = add(bytes, array_bytes::<super::Blob>(case.blobs.capacity())?)?;
    bytes = add(
        bytes,
        map_bytes::<String, usize>(case.blob_index.capacity())?,
    )?;
    for blob in &case.blobs {
        bytes = add(bytes, blob.id.capacity())?;
    }
    for key in case.blob_index.keys() {
        bytes = add(bytes, key.capacity())?;
    }
    bytes = add(bytes, array_bytes::<super::Node>(case.nodes.capacity())?)?;
    bytes = add(bytes, array_bytes::<super::Edge>(case.edges.capacity())?)?;
    bytes = add(
        bytes,
        array_bytes::<super::EdgeLinks>(case.edge_links.capacity())?,
    )?;
    bytes = add(
        bytes,
        map_bytes::<super::EdgeIndexKey, usize>(case.edge_index.capacity())?,
    )?;
    for node in &case.nodes {
        bytes = add(
            bytes,
            node_payload(
                &node.kind,
                node.blob.as_deref(),
                &node.ranges,
                node.ranges.capacity(),
                &node.details,
            )?,
        )?;
    }
    for edge in &case.edges {
        bytes = add(bytes, edge_payload(edge)?)?;
    }
    bytes = add(bytes, array_bytes::<String>(case.limitations.capacity())?)?;
    for limitation in &case.limitations {
        bytes = add(bytes, limitation.capacity())?;
    }
    bytes = add(
        bytes,
        array_bytes::<super::transaction::CaseCheckpoint>(case.transaction_checkpoints.capacity())?,
    )?;
    for checkpoint in &case.transaction_checkpoints {
        bytes = add(bytes, checkpoint.memory_bytes()?)?;
    }
    Ok(bytes)
}

impl Case {
    pub(super) fn prepare_blob_graph(&mut self) -> Result<(), EvidenceError> {
        grow_vec(&mut self.memory, &mut self.blobs)?;
        grow_map(&mut self.memory, &mut self.blob_index)
    }

    pub(super) fn reserve_blob_graph(&mut self, id: &str) -> Result<Option<u64>, EvidenceError> {
        let Some(memory) = &mut self.memory else {
            return Ok(None);
        };
        let bytes = id
            .len()
            .checked_mul(2)
            .ok_or(EvidenceError::ArithmeticOverflow {
                field: "Case memory bytes",
            })?;
        let before = memory.graph_bytes();
        memory.reserve_graph(bytes)?;
        Ok(Some(before))
    }

    pub(super) fn restore_graph_memory(&mut self, bytes: Option<u64>) {
        if let (Some(memory), Some(bytes)) = (&mut self.memory, bytes) {
            memory.restore_graph(bytes);
        }
    }

    pub(super) fn reserve_blob_memory(&mut self, bytes: usize) -> Result<(), EvidenceError> {
        let Some(memory) = &mut self.memory else {
            return Ok(());
        };
        let bytes = u64::try_from(bytes)
            .ok()
            .and_then(|bytes| memory.blobs.bytes().checked_add(bytes))
            .ok_or(EvidenceError::ArithmeticOverflow {
                field: "Case memory bytes",
            })?;
        memory
            .blobs
            .try_resize(bytes)
            .map_err(EvidenceError::Memory)?;
        Ok(())
    }

    pub(super) fn copy_admitted_blob(&mut self, bytes: &[u8]) -> Result<Vec<u8>, EvidenceError> {
        self.reserve_blob_memory(bytes.len())?;
        match super::copy_blob_bytes(bytes) {
            Ok(retained) => {
                // The allocator may grant more capacity than the requested byte count
                let extra = retained.capacity() - bytes.len();
                if let Err(error) = self.reserve_blob_memory(extra) {
                    drop(retained);
                    self.release_blob_memory(bytes.len());
                    return Err(error);
                }
                Ok(retained)
            }
            Err(error) => {
                self.release_blob_memory(bytes.len());
                Err(error)
            }
        }
    }

    pub(super) fn release_blob_memory(&mut self, bytes: usize) {
        if let (Some(memory), Ok(bytes)) = (&mut self.memory, u64::try_from(bytes)) {
            // A poisoned shared budget cannot admit more work and is left unusable
            let _ = memory.blobs.try_resize(memory.blobs.bytes() - bytes);
        }
    }

    pub(super) fn admit_node_memory(
        &mut self,
        kind: &str,
        blob: Option<&str>,
        ranges: &[SourceRange],
        range_capacity: usize,
        details: &Value,
    ) -> Result<Option<u64>, EvidenceError> {
        if self.memory.is_none() {
            return Ok(None);
        }
        let payload = node_payload(kind, blob, ranges, range_capacity, details)?;
        grow_vec(&mut self.memory, &mut self.nodes)?;
        let Some(memory) = &mut self.memory else {
            return Ok(None);
        };
        let before = memory.graph_bytes();
        memory.reserve_graph(payload)?;
        Ok(Some(before))
    }
}
