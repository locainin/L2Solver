use super::{
    EvidenceError, EvidenceStatus, bounded,
    model::{Blob, Edge, Node, Source, SourceRange},
};
use crate::{job::MemoryBudget, serialization::CountWriter, sha256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{HashMap, hash_map::RandomState},
    hash::BuildHasher,
    sync::Arc,
};

#[cfg(test)]
#[path = "../../tests/evidence/case_index.rs"]
mod index_tests;
#[path = "mapping.rs"]
mod mapping;
#[path = "case/memory.rs"]
pub(super) mod memory;
#[path = "case/prefix.rs"]
mod prefix;
#[path = "case/snapshot/mod.rs"]
mod snapshot;
#[path = "transaction.rs"]
mod transaction;
#[path = "case/validation.rs"]
mod validation;

pub use mapping::{CheckedByteMappingCursor, clip_byte_mappings, clip_byte_mappings_with_memory};
pub use prefix::CasePrefixBinding;
pub use snapshot::{CaseSnapshotLimits, CaseSnapshotUsage};

/// Current serialized evidence schema version
pub const SCHEMA_VERSION: u32 = 1;
/// Maximum number of distinct source content hashes
pub const MAX_SOURCES: usize = 256;
/// Maximum bytes in a source basename, measured as UTF-8
pub const MAX_SOURCE_LABEL_BYTES: usize = 256;
/// Maximum alternate basenames retained for one source hash
pub const MAX_SOURCE_ALIASES: usize = 256;
/// Legacy default used by commands that require an explicit per-operation byte budget
///
/// Cases have no aggregate blob ceiling unless `Case::with_blob_limit` selects one
pub const MAX_BLOB_TOTAL_BYTES: usize = 16 * 1024 * 1024;
/// Maximum distinct blobs before evidence references are considered
pub const MAX_BLOBS: usize = MAX_NODES + MAX_SOURCES;
/// Maximum number of observation and derivation nodes
pub const MAX_NODES: usize = 65_536;
/// Maximum number of directed evidence relationships
pub const MAX_EDGES: usize = 131_072;
/// Maximum encoded JSON details for one node
pub const MAX_NODE_DETAILS_BYTES: usize = 4 * 1024;
/// Maximum UTF-8 bytes in a retained evidence-node kind
pub const MAX_NODE_KIND_BYTES: usize = 64;
/// Maximum encoded JSON details across all nodes
pub const MAX_TOTAL_DETAILS_BYTES: usize = 16 * 1024 * 1024;
/// Maximum source ranges retained by one node
pub const MAX_NODE_RANGES: usize = 1_024;
/// Maximum source ranges retained by one case
pub const MAX_TOTAL_SOURCE_RANGES: usize = 131_072;
/// Maximum bytes in a relationship name
pub const MAX_RELATION_BYTES: usize = 64;
/// Maximum bytes in a relationship reason
pub const MAX_REASON_BYTES: usize = 512;
/// Maximum limitation statements in one case
pub const MAX_LIMITATIONS: usize = 128;
/// Maximum bytes in one limitation statement
pub const MAX_LIMITATION_BYTES: usize = 1024;
/// Maximum encoded JSON document accepted or emitted by the case model
///
/// This is a default stream and journal budget, not a case-validity ceiling
pub const MAX_CASE_JSON_BYTES: usize = 64 * 1024 * 1024;

/// Caller-selected aggregate retention policy stored with a case
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseResourceLimits {
    /// Optional maximum distinct blob bytes retained by this case
    pub blob_bytes: Option<usize>,
}

impl CaseResourceLimits {
    const fn is_unlimited(&self) -> bool {
        self.blob_bytes.is_none()
    }
}

/// Exact retained evidence totals returned from the Case's validated counters
///
/// These values match the retained records after successful Case mutations.
/// `Case::validate` independently recomputes the totals and rejects inconsistent counters
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CaseResourceUsage {
    /// Bytes in distinct retained blobs, counting each deduplicated blob once
    pub blob_bytes: usize,
    /// Compact JSON encoded byte length of all retained node details
    pub details_bytes: usize,
    /// Number of source ranges retained across all nodes
    pub source_ranges: usize,
}

/// A validated, content-addressed evidence graph with bounded retained data
#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub(super) schema_version: u32,
    pub(super) collection_complete: bool,
    #[serde(skip_serializing_if = "CaseResourceLimits::is_unlimited")]
    pub(super) resource_limits: CaseResourceLimits,
    pub(super) sources: Vec<Source>,
    pub(super) blobs: Vec<Blob>,
    pub(super) nodes: Vec<Node>,
    pub(super) edges: Vec<Edge>,
    pub(super) limitations: Vec<String>,
    #[serde(skip)]
    pub(super) blob_bytes: usize,
    #[serde(skip)]
    pub(super) details_bytes: usize,
    #[serde(skip)]
    blob_index: HashMap<String, usize>,
    #[serde(skip)]
    edge_index: HashMap<EdgeIndexKey, usize>,
    #[serde(skip)]
    edge_links: Vec<EdgeLinks>,
    #[serde(skip)]
    edge_hash: RandomState,
    #[serde(skip)]
    source_index: HashMap<String, usize>,
    #[serde(skip)]
    range_count: usize,
    // A stable token lets recovery work stay tied to this exact graph
    #[serde(skip)]
    identity: Arc<()>,
    #[serde(skip)]
    transaction_checkpoints: Vec<transaction::CaseCheckpoint>,
    #[serde(skip)]
    memory: Option<memory::CaseMemory>,
}

impl PartialEq for Case {
    fn eq(&self, other: &Self) -> bool {
        self.schema_version == other.schema_version
            && self.collection_complete == other.collection_complete
            && self.resource_limits == other.resource_limits
            && self.sources == other.sources
            && self.blobs == other.blobs
            && self.nodes == other.nodes
            && self.edges == other.edges
            && self.limitations == other.limitations
            && self.blob_bytes == other.blob_bytes
            && self.details_bytes == other.details_bytes
            && self.blob_index == other.blob_index
            && self.source_index == other.source_index
            && self.range_count == other.range_count
    }
}

impl Eq for Case {}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct EdgeIndexKey {
    from: u64,
    to: u64,
    relation_hash: u64,
    reason_hash: u64,
    status: u8,
    exact: bool,
}

// Position plus one preserves zero as the end of each collision chain
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EdgeLinks {
    coarse: usize,
    exact: usize,
}

/// Opaque identity token for one exact retained Case instance
#[derive(Clone, Debug)]
pub struct CaseIdentity(Arc<()>);

impl CaseIdentity {
    /// Return whether this token identifies the supplied Case instance
    #[must_use]
    pub fn identifies(&self, case: &Case) -> bool {
        Arc::ptr_eq(&self.0, &case.identity)
    }
}

impl Case {
    /// Make an independent Case copy, reserving a separate charge when memory admission is active
    ///
    /// # Errors
    /// Returns an admission error when the copy cannot fit in the shared budget
    pub fn try_clone(&self) -> Result<Self, EvidenceError> {
        // A cloned graph can diverge and must have its own live charge
        let memory = self
            .memory
            .as_ref()
            .map(memory::CaseMemory::try_duplicate)
            .transpose()?;
        let mut copy = Self {
            schema_version: self.schema_version,
            collection_complete: self.collection_complete,
            resource_limits: self.resource_limits,
            sources: self.sources.clone(),
            blobs: self.blobs.clone(),
            nodes: self.nodes.clone(),
            edges: self.edges.clone(),
            limitations: self.limitations.clone(),
            blob_bytes: self.blob_bytes,
            details_bytes: self.details_bytes,
            blob_index: self.blob_index.clone(),
            edge_index: self.edge_index.clone(),
            edge_links: self.edge_links.clone(),
            edge_hash: self.edge_hash.clone(),
            source_index: self.source_index.clone(),
            range_count: self.range_count,
            identity: Arc::new(()),
            transaction_checkpoints: Vec::new(),
            memory,
        };
        let graph_bytes = copy
            .memory
            .as_ref()
            .map(|_| memory::graph_bytes(&copy))
            .transpose()?;
        if let Some(memory) = &mut copy.memory {
            let bytes = copy
                .blobs
                .iter()
                .try_fold(0_u64, |total, blob| {
                    u64::try_from(blob.bytes.capacity())
                        .ok()
                        .and_then(|value| total.checked_add(value))
                })
                .ok_or(EvidenceError::ArithmeticOverflow {
                    field: "Case memory bytes",
                })?;
            memory
                .blobs
                .try_resize(bytes)
                .map_err(EvidenceError::Memory)?;
            if let Some(graph_bytes) = graph_bytes {
                memory.set_graph(graph_bytes)?;
            }
        }
        Ok(copy)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseWire {
    schema_version: u32,
    collection_complete: bool,
    #[serde(default)]
    resource_limits: CaseResourceLimits,
    #[serde(deserialize_with = "deserialize_sources")]
    sources: Vec<Source>,
    #[serde(deserialize_with = "deserialize_blobs")]
    blobs: Vec<Blob>,
    #[serde(deserialize_with = "deserialize_nodes")]
    nodes: Vec<Node>,
    #[serde(deserialize_with = "deserialize_edges")]
    edges: Vec<Edge>,
    #[serde(deserialize_with = "deserialize_limitations")]
    limitations: Vec<String>,
}

#[derive(Clone, Copy)]
struct NodePlan {
    id: u64,
    total_details_bytes: usize,
    total_ranges: usize,
}

impl Case {
    /// Create an empty case using the current schema
    #[must_use]
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            collection_complete: true,
            resource_limits: CaseResourceLimits::default(),
            sources: Vec::new(),
            blobs: Vec::new(),
            nodes: Vec::new(),
            edges: Vec::new(),
            limitations: Vec::new(),
            blob_bytes: 0,
            details_bytes: 0,
            blob_index: HashMap::new(),
            edge_index: HashMap::new(),
            edge_links: Vec::new(),
            edge_hash: RandomState::new(),
            source_index: HashMap::new(),
            range_count: 0,
            identity: Arc::new(()),
            transaction_checkpoints: Vec::new(),
            memory: None,
        }
    }

    /// Create an empty Case that charges retained blobs and logical graph storage
    ///
    /// # Errors
    /// Returns an error if the shared budget cannot create a Case lease
    pub fn with_memory_budget(budget: &MemoryBudget) -> Result<Self, EvidenceError> {
        let mut case = Self::new();
        case.memory = Some(memory::CaseMemory::new(budget)?);
        Ok(case)
    }

    /// Create an empty case with an explicit aggregate blob-retention budget
    ///
    /// The limit is an analyst-selected policy and is persisted in case JSON
    ///
    /// # Errors
    /// Returns an error when the supplied byte budget is zero
    pub fn with_blob_limit(maximum: usize) -> Result<Self, EvidenceError> {
        if maximum == 0 {
            return Err(EvidenceError::InvalidResourceLimit {
                field: "blob bytes",
            });
        }
        let mut case = Self::new();
        case.resource_limits.blob_bytes = Some(maximum);
        Ok(case)
    }

    /// Create a Case with both a blob-retention policy and shared live-memory admission
    ///
    /// # Errors
    /// Returns an error for a zero blob limit or a failed shared-memory lease
    pub fn with_blob_limit_and_memory_budget(
        maximum: usize,
        budget: &MemoryBudget,
    ) -> Result<Self, EvidenceError> {
        let mut case = Self::with_blob_limit(maximum)?;
        case.memory = Some(memory::CaseMemory::new(budget)?);
        Ok(case)
    }

    /// Return the optional caller-selected aggregate blob-retention budget
    #[must_use]
    pub const fn blob_byte_limit(&self) -> Option<usize> {
        self.resource_limits.blob_bytes
    }

    /// Return this Case's current retained allocation charge, when admission is enabled
    ///
    /// This excludes scratch allocations, other Cases, allocator overhead, and process RSS
    #[must_use]
    pub fn charged_memory_bytes(&self) -> Option<u64> {
        self.memory
            .as_ref()
            .map(|memory| memory.graph_bytes() + memory.blobs.bytes())
    }

    /// Return a read-only snapshot of retained blob, node-detail, and source-range usage
    ///
    /// This reads the counters maintained by successful Case mutations in constant time.
    /// It does not scan records or serialize node details. `Case::validate` recomputes and
    /// checks these totals against the retained records
    #[must_use]
    pub const fn resource_usage(&self) -> CaseResourceUsage {
        CaseResourceUsage {
            blob_bytes: self.blob_bytes,
            details_bytes: self.details_bytes,
            source_ranges: self.range_count,
        }
    }

    /// Return the case schema version
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Return whether all collection and retention work recorded in this case completed
    #[must_use]
    pub const fn collection_complete(&self) -> bool {
        self.collection_complete
    }

    /// Return source identities in their stable insertion order
    #[must_use]
    pub fn sources(&self) -> &[Source] {
        &self.sources
    }

    /// Return deduplicated retained blobs
    #[must_use]
    pub fn blobs(&self) -> &[Blob] {
        &self.blobs
    }

    /// Return observation nodes in their canonical identifier order
    #[must_use]
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// Return evidence edges in their stable insertion order
    #[must_use]
    pub fn edges(&self) -> &[Edge] {
        &self.edges
    }

    /// Return an opaque token used to bind retained work to this exact case instance
    #[must_use]
    pub fn identity(&self) -> CaseIdentity {
        CaseIdentity(Arc::clone(&self.identity))
    }

    /// Return case-level scope and interpretation limits
    #[must_use]
    pub fn limitations(&self) -> &[String] {
        &self.limitations
    }

    /// Add one bounded content-addressed byte blob, deduplicating exact repeats
    ///
    /// # Errors
    /// Returns an error when the aggregate byte or blob-count limit is exceeded
    pub fn add_blob(&mut self, bytes: &[u8]) -> Result<String, EvidenceError> {
        let (id, should_add, next_size) = self.preflight_blob(bytes)?;
        if should_add {
            self.prepare_blob_graph()?;
            let prior_graph = self.reserve_blob_graph(&id)?;
            let retained = match self.copy_admitted_blob(bytes) {
                Ok(retained) => retained,
                Err(error) => {
                    self.restore_graph_memory(prior_graph);
                    return Err(error);
                }
            };
            self.commit_blob(id.clone(), retained, next_size);
        }
        Ok(id)
    }

    fn preflight_blob(&self, bytes: &[u8]) -> Result<(String, bool, usize), EvidenceError> {
        let id = format!("sha256:{}", sha256(bytes));
        if let Some(existing) = self.blob(&id) {
            if existing.bytes != bytes {
                return Err(EvidenceError::HashCollision);
            }
            return Ok((id, false, self.blob_bytes));
        }
        let next_size =
            self.blob_bytes
                .checked_add(bytes.len())
                .ok_or(EvidenceError::ArithmeticOverflow {
                    field: "blob bytes",
                })?;
        if self.blobs.len() >= MAX_BLOBS {
            return Err(EvidenceError::QuotaExceeded {
                field: "blobs",
                maximum: MAX_BLOBS,
            });
        }
        if self
            .resource_limits
            .blob_bytes
            .is_some_and(|maximum| next_size > maximum)
        {
            return Err(EvidenceError::QuotaExceeded {
                field: "blob bytes",
                maximum: self.resource_limits.blob_bytes.unwrap_or(usize::MAX),
            });
        }
        Ok((id, true, next_size))
    }

    fn commit_blob(&mut self, id: String, bytes: Vec<u8>, next_size: usize) {
        let index = self.blobs.len();
        self.blobs.push(Blob {
            id: id.clone(),
            bytes,
        });
        self.blob_index.insert(id, index);
        self.blob_bytes = next_size;
    }

    /// Add a source identity for a known full-source hash
    ///
    /// Identical hashes share one source record and retain other basenames as aliases
    ///
    /// # Errors
    /// Returns an error for invalid metadata, dangling blobs, conflicting duplicates,
    /// or a source-count or alias-count limit
    pub fn add_source(
        &mut self,
        label: &str,
        kind: &str,
        length: u64,
        sha256_hex: &str,
        blob: Option<&str>,
    ) -> Result<String, EvidenceError> {
        validate_label(label)?;
        validate_text(kind, 64, "source kind")?;
        let id = source_id(sha256_hex)?;
        if let Some(blob_id) = blob {
            let retained = self
                .blob(blob_id)
                .ok_or(EvidenceError::MissingReference { kind: "blob" })?;
            if blob_id != id || u64::try_from(retained.bytes.len()).ok() != Some(length) {
                return Err(EvidenceError::SourceMetadataConflict);
            }
        }
        if let Some(index) = self.source_index.get(&id).copied() {
            self.merge_source(index, label, kind, length, blob)?;
            return Ok(id);
        }
        if self.sources.len() >= MAX_SOURCES {
            return Err(EvidenceError::QuotaExceeded {
                field: "sources",
                maximum: MAX_SOURCES,
            });
        }
        memory::grow_vec(&mut self.memory, &mut self.sources)?;
        memory::grow_map(&mut self.memory, &mut self.source_index)?;
        if let Some(memory) = &mut self.memory {
            let bytes = id
                .len()
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_add(label.len()))
                .and_then(|bytes| bytes.checked_add(kind.len()))
                .and_then(|bytes| bytes.checked_add(blob.map_or(0, str::len)))
                .ok_or(EvidenceError::ArithmeticOverflow {
                    field: "Case memory bytes",
                })?;
            memory.reserve_graph(bytes)?;
        }
        let index = self.sources.len();
        self.sources.push(Source {
            id: id.clone(),
            label: label.to_owned(),
            aliases: Vec::new(),
            kind: kind.to_owned(),
            length,
            blob: blob.map(str::to_owned),
        });
        self.source_index.insert(id.clone(), index);
        Ok(id)
    }

    fn merge_source(
        &mut self,
        index: usize,
        label: &str,
        kind: &str,
        length: u64,
        blob_value: Option<&str>,
    ) -> Result<(), EvidenceError> {
        let existing = self
            .sources
            .get(index)
            .ok_or(EvidenceError::SourceMetadataConflict)?;
        if existing.kind != kind || existing.length != length {
            return Err(EvidenceError::SourceMetadataConflict);
        }
        if let Some(existing_blob) = &existing.blob
            && blob_value.is_some_and(|candidate| candidate != existing_blob)
        {
            return Err(EvidenceError::SourceMetadataConflict);
        }
        let needs_alias =
            existing.label != label && !existing.aliases.iter().any(|alias| alias == label);
        if needs_alias && existing.aliases.len() == MAX_SOURCE_ALIASES {
            return Err(EvidenceError::QuotaExceeded {
                field: "source aliases",
                maximum: MAX_SOURCE_ALIASES,
            });
        }
        let attaches_blob = existing.blob.is_none() && blob_value.is_some();
        if needs_alias || attaches_blob {
            self.snapshot_source_mutation(index)?;
        }
        if needs_alias {
            let existing = self
                .sources
                .get_mut(index)
                .ok_or(EvidenceError::SourceMetadataConflict)?;
            memory::grow_vec(&mut self.memory, &mut existing.aliases)?;
        }
        if let Some(memory) = &mut self.memory {
            let alias_bytes = if needs_alias { label.len() } else { 0 };
            let blob_bytes = if attaches_blob {
                blob_value.map_or(0, str::len)
            } else {
                0
            };
            memory.reserve_graph(alias_bytes.checked_add(blob_bytes).ok_or(
                EvidenceError::ArithmeticOverflow {
                    field: "Case memory bytes",
                },
            )?)?;
        }
        let existing = self
            .sources
            .get_mut(index)
            .ok_or(EvidenceError::SourceMetadataConflict)?;
        if existing.blob.is_none() {
            existing.blob = blob_value.map(str::to_owned);
        }
        if needs_alias {
            existing.aliases.push(label.to_owned());
            existing.aliases.sort_unstable();
        }
        Ok(())
    }

    /// Bind one source to the basename used by the current request
    ///
    /// Prior aliases are cleared while content identity and source ranges remain unchanged
    ///
    /// # Errors
    /// Returns an error when the source identity or basename is invalid or the source is absent
    pub fn rebind_source_label(
        &mut self,
        source_id: &str,
        label: &str,
    ) -> Result<(), EvidenceError> {
        validate_content_id(source_id)?;
        validate_label(label)?;
        let index = self
            .source_index
            .get(source_id)
            .copied()
            .ok_or(EvidenceError::MissingReference { kind: "source" })?;
        let source = self
            .sources
            .get(index)
            .ok_or(EvidenceError::SourceMetadataConflict)?;
        if source.label != label || !source.aliases.is_empty() {
            self.snapshot_source_mutation(index)?;
        }
        if self.memory.is_some() {
            let source = self
                .sources
                .get(index)
                .ok_or(EvidenceError::SourceMetadataConflict)?;
            let changed = source.label != label;
            let old_label = if changed { source.label.capacity() } else { 0 };
            let released = source
                .aliases
                .iter()
                .try_fold(old_label, |total, alias| {
                    total.checked_add(alias.capacity())
                })
                .ok_or(EvidenceError::ArithmeticOverflow {
                    field: "Case memory bytes",
                })?;
            let prior = self.memory.as_ref().map(memory::CaseMemory::graph_bytes);
            if changed {
                if let Some(memory) = &mut self.memory {
                    memory.reserve_graph(label.len())?;
                }
                let replacement = label.to_owned();
                let extra = replacement.capacity() - label.len();
                if let Some(memory) = &mut self.memory
                    && let Err(error) = memory.reserve_graph(extra)
                {
                    self.restore_graph_memory(prior);
                    return Err(error);
                }
                let source = self
                    .sources
                    .get_mut(index)
                    .ok_or(EvidenceError::SourceMetadataConflict)?;
                source.label = replacement;
            }
            let source = self
                .sources
                .get_mut(index)
                .ok_or(EvidenceError::SourceMetadataConflict)?;
            source.aliases.clear();
            if let Some(memory) = &mut self.memory {
                memory.release_graph(released)?;
            }
            return Ok(());
        }
        let source = self
            .sources
            .get_mut(index)
            .ok_or(EvidenceError::SourceMetadataConflict)?;
        if source.label != label {
            label.clone_into(&mut source.label);
        }
        source.aliases.clear();
        Ok(())
    }

    /// Add one observation with checked source, blob, and detail references
    ///
    /// # Errors
    /// Returns an error when a reference, range, string, or node quota is invalid
    pub fn add_node(
        &mut self,
        kind: &str,
        blob: Option<&str>,
        ranges: Vec<SourceRange>,
        details: Value,
    ) -> Result<u64, EvidenceError> {
        let plan = self.plan_node(kind, blob, None, &ranges, &details)?;
        self.admit_node_memory(kind, blob, &ranges, ranges.capacity(), &details)?;
        Ok(self.commit_node(kind, blob, ranges, details, plan))
    }

    pub(super) fn validate_node(
        &self,
        kind: &str,
        blob: Option<&str>,
        uncommitted_blob: Option<&str>,
        ranges: &[SourceRange],
        details: &Value,
    ) -> Result<(), EvidenceError> {
        self.plan_node(kind, blob, uncommitted_blob, ranges, details)
            .map(|_| ())
    }

    pub(super) fn replace_node_details(
        &mut self,
        id: u64,
        details: Value,
    ) -> Result<(), EvidenceError> {
        let index = id
            .checked_sub(1)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(EvidenceError::InvalidNodeId)?;
        let previous = self.nodes.get(index).ok_or(EvidenceError::InvalidNodeId)?;
        let previous_length = encoded_details_length(&previous.details)?;
        let next_length = encoded_details_length(&details)?;
        if next_length > MAX_NODE_DETAILS_BYTES {
            return Err(EvidenceError::NodeDetailsTooLarge {
                length: next_length,
                maximum: MAX_NODE_DETAILS_BYTES,
            });
        }
        let total_length = self
            .details_bytes
            .checked_sub(previous_length)
            .and_then(|length| length.checked_add(next_length))
            .ok_or(EvidenceError::TotalDetailsTooLarge {
                length: usize::MAX,
                maximum: MAX_TOTAL_DETAILS_BYTES,
            })?;
        if total_length > MAX_TOTAL_DETAILS_BYTES {
            return Err(EvidenceError::TotalDetailsTooLarge {
                length: total_length,
                maximum: MAX_TOTAL_DETAILS_BYTES,
            });
        }
        let graph_change = if self.memory.is_some() {
            Some((
                memory::value_bytes(&previous.details)?,
                memory::value_bytes(&details)?,
            ))
        } else {
            None
        };
        if let (Some(memory), Some((before, after))) = (&mut self.memory, graph_change)
            && after > before
        {
            memory.reserve_graph(after - before)?;
        }
        let node = self
            .nodes
            .get_mut(index)
            .ok_or(EvidenceError::InvalidNodeId)?;
        node.details = details;
        self.details_bytes = total_length;
        if let (Some(memory), Some((before, after))) = (&mut self.memory, graph_change)
            && before > after
        {
            let released =
                u64::try_from(before - after).map_err(|_| EvidenceError::ArithmeticOverflow {
                    field: "Case memory bytes",
                })?;
            memory.restore_graph(memory.graph_bytes() - released);
        }
        Ok(())
    }

    pub(super) fn validate_limitations(&self, planned: &[String]) -> Result<(), EvidenceError> {
        let mut additional = 0_usize;
        for (index, limitation) in planned.iter().enumerate() {
            validate_text(limitation, MAX_LIMITATION_BYTES, "limitation")?;
            if self.limitations.iter().any(|saved| saved == limitation)
                || planned
                    .iter()
                    .take(index)
                    .any(|previous| previous == limitation)
            {
                continue;
            }
            additional = additional
                .checked_add(1)
                .ok_or(EvidenceError::ArithmeticOverflow {
                    field: "limitations",
                })?;
        }
        let total = self.limitations.len().checked_add(additional).ok_or(
            EvidenceError::ArithmeticOverflow {
                field: "limitations",
            },
        )?;
        if total > MAX_LIMITATIONS {
            return Err(EvidenceError::QuotaExceeded {
                field: "limitations",
                maximum: MAX_LIMITATIONS,
            });
        }
        Ok(())
    }

    /// Add one byte blob and its observation atomically under all case quotas
    ///
    /// # Errors
    /// Returns an error when the blob, node, range, reference, or details limits fail
    pub fn add_bytes_node(
        &mut self,
        kind: &str,
        bytes: &[u8],
        ranges: Vec<SourceRange>,
        details: Value,
    ) -> Result<u64, EvidenceError> {
        let (blob_id, should_add, next_blob_bytes) = self.preflight_blob(bytes)?;
        let plan = self.plan_node(kind, Some(&blob_id), Some(&blob_id), &ranges, &details)?;
        if should_add {
            self.prepare_blob_graph()?;
        }
        let prior_graph =
            self.admit_node_memory(kind, Some(&blob_id), &ranges, ranges.capacity(), &details)?;
        if should_add {
            if let Err(error) = self.reserve_blob_graph(&blob_id) {
                self.restore_graph_memory(prior_graph);
                return Err(error);
            }
            let retained = match self.copy_admitted_blob(bytes) {
                Ok(retained) => retained,
                Err(error) => {
                    self.restore_graph_memory(prior_graph);
                    return Err(error);
                }
            };
            self.commit_blob(blob_id.clone(), retained, next_blob_bytes);
        }
        Ok(self.commit_node(kind, Some(&blob_id), ranges, details, plan))
    }

    fn plan_node(
        &self,
        kind: &str,
        blob: Option<&str>,
        uncommitted_blob: Option<&str>,
        ranges: &[SourceRange],
        details: &Value,
    ) -> Result<NodePlan, EvidenceError> {
        validate_text(kind, MAX_NODE_KIND_BYTES, "node kind")?;
        if self.nodes.len() >= MAX_NODES {
            return Err(EvidenceError::QuotaExceeded {
                field: "nodes",
                maximum: MAX_NODES,
            });
        }
        if let Some(blob_id) = blob
            && !self.blob_index.contains_key(blob_id)
            && uncommitted_blob != Some(blob_id)
        {
            return Err(EvidenceError::MissingReference { kind: "blob" });
        }
        if ranges.len() > MAX_NODE_RANGES {
            return Err(EvidenceError::QuotaExceeded {
                field: "node source ranges",
                maximum: MAX_NODE_RANGES,
            });
        }
        let total_ranges = self.range_count.checked_add(ranges.len()).ok_or(
            EvidenceError::ArithmeticOverflow {
                field: "source ranges",
            },
        )?;
        if total_ranges > MAX_TOTAL_SOURCE_RANGES {
            return Err(EvidenceError::QuotaExceeded {
                field: "source ranges",
                maximum: MAX_TOTAL_SOURCE_RANGES,
            });
        }
        for range in ranges {
            self.validate_range(range)?;
        }
        let details_bytes = encoded_details_length(details)?;
        let total_details_bytes = self.details_bytes.checked_add(details_bytes).ok_or(
            EvidenceError::TotalDetailsTooLarge {
                length: usize::MAX,
                maximum: MAX_TOTAL_DETAILS_BYTES,
            },
        )?;
        if total_details_bytes > MAX_TOTAL_DETAILS_BYTES {
            return Err(EvidenceError::TotalDetailsTooLarge {
                length: total_details_bytes,
                maximum: MAX_TOTAL_DETAILS_BYTES,
            });
        }
        let id = u64::try_from(self.nodes.len())
            .ok()
            .and_then(|count| count.checked_add(1))
            .ok_or(EvidenceError::ArithmeticOverflow { field: "nodes" })?;
        Ok(NodePlan {
            id,
            total_details_bytes,
            total_ranges,
        })
    }

    fn commit_node(
        &mut self,
        kind: &str,
        blob: Option<&str>,
        ranges: Vec<SourceRange>,
        details: Value,
        plan: NodePlan,
    ) -> u64 {
        self.nodes.push(Node {
            id: plan.id,
            kind: kind.to_owned(),
            blob: blob.map(str::to_owned),
            ranges,
            details,
        });
        self.details_bytes = plan.total_details_bytes;
        self.range_count = plan.total_ranges;
        plan.id
    }

    /// Add an evidence relation between existing graph nodes
    ///
    /// # Errors
    /// Returns an error when an endpoint, string, or edge quota is invalid
    pub fn add_edge(&mut self, edge: Edge) -> Result<(), EvidenceError> {
        if self.edges.len() == MAX_EDGES {
            return Err(EvidenceError::QuotaExceeded {
                field: "edges",
                maximum: MAX_EDGES,
            });
        }
        if !self.has_node(edge.from) || !self.has_node(edge.to) {
            return Err(EvidenceError::MissingReference { kind: "node" });
        }
        validate_text(&edge.relation, MAX_RELATION_BYTES, "edge relation")?;
        validate_text(&edge.reason, MAX_REASON_BYTES, "edge reason")?;
        let coarse_key = edge_index_key(&self.edge_hash, &edge, false);
        let exact_key = edge_index_key(&self.edge_hash, &edge, true);
        if self.memory.is_some() {
            let new_index_entries = usize::from(!self.edge_index.contains_key(&coarse_key))
                + usize::from(!self.edge_index.contains_key(&exact_key));
            let payload = memory::edge_payload(&edge)?;
            memory::grow_vec(&mut self.memory, &mut self.edges)?;
            memory::grow_vec(&mut self.memory, &mut self.edge_links)?;
            memory::grow_map_for(&mut self.memory, &mut self.edge_index, new_index_entries)?;
            if let Some(memory) = &mut self.memory {
                memory.reserve_graph(payload)?;
            }
        }
        let position = self.edges.len();
        let links = EdgeLinks {
            coarse: self
                .edge_index
                .get(&coarse_key)
                .map_or(0, |index| index + 1),
            exact: self.edge_index.get(&exact_key).map_or(0, |index| index + 1),
        };
        self.edges.push(edge);
        self.edge_links.push(links);
        // Prior positions let rollback restore both lookup paths without cloning edge text
        self.edge_index.insert(coarse_key, position);
        self.edge_index.insert(exact_key, position);
        Ok(())
    }

    /// Add a bounded case-level limitation statement, deduplicating exact repeats
    ///
    /// # Errors
    /// Returns an error when the text or limitation-count limit is exceeded
    pub fn add_limitation(&mut self, limitation: &str) -> Result<(), EvidenceError> {
        validate_text(limitation, MAX_LIMITATION_BYTES, "limitation")?;
        if self.limitations.iter().any(|item| item == limitation) {
            return Ok(());
        }
        if self.limitations.len() == MAX_LIMITATIONS {
            return Err(EvidenceError::QuotaExceeded {
                field: "limitations",
                maximum: MAX_LIMITATIONS,
            });
        }
        memory::grow_vec(&mut self.memory, &mut self.limitations)?;
        if let Some(memory) = &mut self.memory {
            memory.reserve_graph(limitation.len())?;
        }
        self.limitations.push(limitation.to_owned());
        Ok(())
    }

    /// Mark collection incomplete after recording a validated reason
    ///
    /// Completeness only moves from true to false. Adding the reason first keeps
    /// the state unchanged if its text or the limitation budget is invalid
    ///
    /// # Errors
    /// Returns an error when the reason is invalid or no limitation slot remains
    pub fn mark_incomplete(&mut self, reason: &str) -> Result<(), EvidenceError> {
        self.add_limitation(reason)?;
        self.collection_complete = false;
        Ok(())
    }

    /// Validate all serialized values, source hashes, graph references, and byte bounds
    ///
    /// # Errors
    /// Returns an error when any source, node, edge, hash, or quota invariant is broken
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(EvidenceError::UnsupportedSchema {
                found: self.schema_version,
                expected: SCHEMA_VERSION,
            });
        }
        if self.resource_limits.blob_bytes == Some(0) {
            return Err(EvidenceError::InvalidResourceLimit {
                field: "blob bytes",
            });
        }
        for (count, maximum, field) in [
            (self.sources.len(), MAX_SOURCES, "sources"),
            (self.blobs.len(), MAX_BLOBS, "blobs"),
            (self.nodes.len(), MAX_NODES, "nodes"),
            (self.edges.len(), MAX_EDGES, "edges"),
            (self.limitations.len(), MAX_LIMITATIONS, "limitations"),
        ] {
            if count > maximum {
                return Err(EvidenceError::QuotaExceeded { field, maximum });
            }
        }
        if self.blob_index.len() != self.blobs.len()
            || self.source_index.len() != self.sources.len()
        {
            return Err(EvidenceError::HashMismatch);
        }
        let mut referenced_blobs =
            validation::BlobReferences::new(self.blobs.len(), self.memory.as_ref())?;
        self.validate_blobs()?;
        self.validate_sources(&mut referenced_blobs)?;
        self.validate_nodes(&mut referenced_blobs)?;
        self.validate_edges()?;
        for limitation in &self.limitations {
            validate_text(limitation, MAX_LIMITATION_BYTES, "limitation")?;
        }
        if referenced_blobs.len() != self.blobs.len() {
            return Err(EvidenceError::OrphanBlob);
        }
        Ok(())
    }

    fn validate_blobs(&self) -> Result<(), EvidenceError> {
        let mut total_bytes = 0_usize;
        for (index, blob) in self.blobs.iter().enumerate() {
            validate_content_id(&blob.id)?;
            if !blob
                .id
                .strip_prefix("sha256:")
                .is_some_and(|digest| crate::hashing::sha256_matches(&blob.bytes, digest))
                || self.blob_index.get(&blob.id) != Some(&index)
            {
                return Err(EvidenceError::HashMismatch);
            }
            total_bytes = total_bytes.checked_add(blob.bytes.len()).ok_or(
                EvidenceError::ArithmeticOverflow {
                    field: "blob bytes",
                },
            )?;
        }
        if total_bytes != self.blob_bytes {
            return Err(EvidenceError::InconsistentResourceCount {
                field: "blob bytes",
            });
        }
        if self
            .resource_limits
            .blob_bytes
            .is_some_and(|maximum| total_bytes > maximum)
        {
            return Err(EvidenceError::QuotaExceeded {
                field: "blob bytes",
                maximum: self.resource_limits.blob_bytes.unwrap_or(usize::MAX),
            });
        }
        Ok(())
    }

    fn validate_sources(
        &self,
        referenced_blobs: &mut validation::BlobReferences,
    ) -> Result<(), EvidenceError> {
        for (index, source) in self.sources.iter().enumerate() {
            validate_content_id(&source.id)?;
            validate_label(&source.label)?;
            validate_text(&source.kind, 64, "source kind")?;
            if self.source_index.get(&source.id) != Some(&index)
                || source.aliases.len() > MAX_SOURCE_ALIASES
            {
                return Err(EvidenceError::QuotaExceeded {
                    field: "source aliases or identities",
                    maximum: MAX_SOURCE_ALIASES,
                });
            }
            for (alias_index, alias) in source.aliases.iter().enumerate() {
                validate_label(alias)?;
                if alias == &source.label
                    || source
                        .aliases
                        .iter()
                        .take(alias_index)
                        .any(|previous| previous == alias)
                {
                    return Err(EvidenceError::InvalidText {
                        field: "duplicate source alias",
                    });
                }
            }
            if let Some(blob_id) = &source.blob {
                let blob_index = self
                    .blob_index
                    .get(blob_id)
                    .copied()
                    .ok_or(EvidenceError::MissingReference { kind: "blob" })?;
                let blob = self
                    .blobs
                    .get(blob_index)
                    .ok_or(EvidenceError::MissingReference { kind: "blob" })?;
                if source.id != *blob_id
                    || u64::try_from(blob.bytes.len()).ok() != Some(source.length)
                {
                    return Err(EvidenceError::SourceMetadataConflict);
                }
                referenced_blobs.insert(blob_index)?;
            }
        }
        Ok(())
    }

    fn validate_nodes(
        &self,
        referenced_blobs: &mut validation::BlobReferences,
    ) -> Result<(), EvidenceError> {
        let mut total_details = 0_usize;
        let mut total_ranges = 0_usize;
        for (index, node) in self.nodes.iter().enumerate() {
            let expected_id = u64::try_from(index)
                .ok()
                .and_then(|count| count.checked_add(1))
                .ok_or(EvidenceError::InvalidNodeId)?;
            if node.id != expected_id {
                return Err(EvidenceError::InvalidNodeId);
            }
            validate_text(&node.kind, MAX_NODE_KIND_BYTES, "node kind")?;
            if let Some(blob_id) = &node.blob {
                let blob_index = self
                    .blob_index
                    .get(blob_id)
                    .copied()
                    .ok_or(EvidenceError::MissingReference { kind: "blob" })?;
                referenced_blobs.insert(blob_index)?;
            }
            if node.ranges.len() > MAX_NODE_RANGES {
                return Err(EvidenceError::QuotaExceeded {
                    field: "node source ranges",
                    maximum: MAX_NODE_RANGES,
                });
            }
            total_ranges = total_ranges.checked_add(node.ranges.len()).ok_or(
                EvidenceError::ArithmeticOverflow {
                    field: "source ranges",
                },
            )?;
            if total_ranges > MAX_TOTAL_SOURCE_RANGES {
                return Err(EvidenceError::QuotaExceeded {
                    field: "source ranges",
                    maximum: MAX_TOTAL_SOURCE_RANGES,
                });
            }
            for range in &node.ranges {
                self.validate_range(range)?;
            }
            total_details = total_details
                .checked_add(encoded_details_length(&node.details)?)
                .ok_or(EvidenceError::TotalDetailsTooLarge {
                    length: usize::MAX,
                    maximum: MAX_TOTAL_DETAILS_BYTES,
                })?;
        }
        if total_details > MAX_TOTAL_DETAILS_BYTES || total_details != self.details_bytes {
            return Err(EvidenceError::TotalDetailsTooLarge {
                length: total_details,
                maximum: MAX_TOTAL_DETAILS_BYTES,
            });
        }
        if total_ranges != self.range_count {
            return Err(EvidenceError::InconsistentResourceCount {
                field: "source ranges",
            });
        }
        Ok(())
    }

    fn validate_edges(&self) -> Result<(), EvidenceError> {
        for edge in &self.edges {
            if !self.has_node(edge.from) || !self.has_node(edge.to) {
                return Err(EvidenceError::MissingReference { kind: "node" });
            }
            validate_text(&edge.relation, MAX_RELATION_BYTES, "edge relation")?;
            validate_text(&edge.reason, MAX_REASON_BYTES, "edge reason")?;
        }
        Ok(())
    }

    /// Decode and validate a JSON evidence case already bounded by its reader
    ///
    /// # Errors
    /// Returns an error for invalid JSON or invalid evidence
    pub fn from_json(bytes: &[u8]) -> Result<Self, EvidenceError> {
        super::preflight::check_details(bytes)?;
        let wire: CaseWire =
            serde_json::from_slice(bytes).map_err(|_| EvidenceError::InvalidJson)?;
        let blob_bytes = total_blob_bytes(&wire.blobs)?;
        let details_bytes = total_details_bytes(&wire.nodes)?;
        let mut case = Self {
            schema_version: wire.schema_version,
            collection_complete: wire.collection_complete,
            resource_limits: wire.resource_limits,
            sources: wire.sources,
            blobs: wire.blobs,
            nodes: wire.nodes,
            edges: wire.edges,
            limitations: wire.limitations,
            blob_bytes,
            details_bytes,
            blob_index: HashMap::new(),
            edge_index: HashMap::new(),
            edge_links: Vec::new(),
            edge_hash: RandomState::new(),
            source_index: HashMap::new(),
            range_count: 0,
            identity: Arc::new(()),
            transaction_checkpoints: Vec::new(),
            memory: None,
        };
        case.rebuild_indexes()?;
        case.validate()?;
        Ok(case)
    }

    /// Encode a validated case after a fallible exact-size reservation
    ///
    /// # Errors
    /// Returns an error for invalid case data, size overflow, or allocation failure
    pub fn to_json(&self) -> Result<Vec<u8>, EvidenceError> {
        self.validate()?;
        let mut counter = CountWriter::new(usize::MAX);
        serde_json::to_writer(&mut counter, self).map_err(|_| EvidenceError::InvalidJson)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(counter.written()).map_err(|_| {
            EvidenceError::AllocationFailed {
                field: "encoded case JSON",
            }
        })?;
        self.write_validated_json(&mut bytes)?;
        Ok(bytes)
    }

    /// Stream one validated case to a JSON writer without allocating an encoded copy
    ///
    /// # Errors
    /// Returns an error for invalid case data, serialization failure, or output failure
    pub fn write_json(&self, output: &mut impl std::io::Write) -> Result<(), EvidenceError> {
        self.validate()?;
        self.write_validated_json(output)
    }

    fn write_validated_json(&self, output: &mut impl std::io::Write) -> Result<(), EvidenceError> {
        serde_json::to_writer(output, self).map_err(|error| {
            if error.is_io() {
                EvidenceError::WriteFailed
            } else {
                EvidenceError::InvalidJson
            }
        })
    }

    fn has_node(&self, id: u64) -> bool {
        self.node(id).is_some()
    }

    /// Return one retained evidence node by its stable Case-local identifier
    ///
    /// Node identifiers are sequential, so lookup does not scan the evidence graph
    #[must_use]
    pub fn node(&self, id: u64) -> Option<&Node> {
        id.checked_sub(1)
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| self.nodes.get(index))
            .filter(|node| node.id == id)
    }

    /// Return one retained blob by its stable content identifier
    #[must_use]
    pub fn blob(&self, id: &str) -> Option<&Blob> {
        self.blob_index
            .get(id)
            .and_then(|index| self.blobs.get(*index))
    }

    pub(super) fn blob_position(&self, id: &str) -> Option<usize> {
        self.blob_index.get(id).copied()
    }

    /// Check whether a relation with these endpoints and status is retained
    ///
    /// The original relation text is checked after the indexed hash lookup
    #[must_use]
    pub fn has_edge(&self, from: u64, to: u64, relation: &str, status: EvidenceStatus) -> bool {
        self.find_edge(from, to, relation, status, None)
    }

    /// Check whether an edge with exactly these fields is retained in the Case
    ///
    /// Hash collisions are checked against the original edge text
    #[must_use]
    pub fn contains_exact_edge(
        &self,
        from: u64,
        to: u64,
        relation: &str,
        status: EvidenceStatus,
        reason: &str,
    ) -> bool {
        self.find_edge(from, to, relation, status, Some(reason))
    }

    fn find_edge(
        &self,
        from: u64,
        to: u64,
        relation: &str,
        status: EvidenceStatus,
        reason: Option<&str>,
    ) -> bool {
        // Hashes narrow the search; original edge fields decide equality
        let key = edge_lookup_key(&self.edge_hash, from, to, relation, status, reason);
        let mut position = self.edge_index.get(&key).copied();
        while let Some(index) = position {
            let Some(edge) = self.edges.get(index) else {
                return false;
            };
            if edge.relation == relation && reason.is_none_or(|reason| edge.reason == reason) {
                return true;
            }
            let Some(links) = self.edge_links.get(index) else {
                return false;
            };
            position = if reason.is_some() {
                links.exact.checked_sub(1)
            } else {
                links.coarse.checked_sub(1)
            };
        }
        false
    }

    pub(super) fn truncate_edges(&mut self, length: usize) {
        while self.edges.len() > length {
            let Some(edge) = self.edges.pop() else {
                break;
            };
            let Some(links) = self.edge_links.pop() else {
                break;
            };
            let coarse_key = edge_index_key(&self.edge_hash, &edge, false);
            let exact_key = edge_index_key(&self.edge_hash, &edge, true);
            restore_edge_head(&mut self.edge_index, coarse_key, links.coarse);
            restore_edge_head(&mut self.edge_index, exact_key, links.exact);
        }
    }

    pub(super) fn source(&self, id: &str) -> Option<&Source> {
        self.source_index
            .get(id)
            .and_then(|index| self.sources.get(*index))
    }

    pub(super) const fn remaining_range_capacity(&self) -> usize {
        MAX_TOTAL_SOURCE_RANGES.saturating_sub(self.range_count)
    }

    fn rebuild_indexes(&mut self) -> Result<(), EvidenceError> {
        if self.blobs.len() > MAX_BLOBS || self.sources.len() > MAX_SOURCES {
            return Err(EvidenceError::QuotaExceeded {
                field: "source or blob records",
                maximum: MAX_BLOBS,
            });
        }
        let range_count = self.nodes.iter().try_fold(0_usize, |total, node| {
            let count =
                total
                    .checked_add(node.ranges.len())
                    .ok_or(EvidenceError::ArithmeticOverflow {
                        field: "source ranges",
                    })?;
            if count > MAX_TOTAL_SOURCE_RANGES {
                return Err(EvidenceError::QuotaExceeded {
                    field: "source ranges",
                    maximum: MAX_TOTAL_SOURCE_RANGES,
                });
            }
            Ok(count)
        })?;
        let mut blob_index = HashMap::with_capacity(self.blobs.len());
        for (index, blob) in self.blobs.iter().enumerate() {
            if blob_index.insert(blob.id.clone(), index).is_some() {
                return Err(EvidenceError::HashMismatch);
            }
        }
        let mut source_index = HashMap::with_capacity(self.sources.len());
        for (index, source) in self.sources.iter().enumerate() {
            if source_index.insert(source.id.clone(), index).is_some() {
                return Err(EvidenceError::HashMismatch);
            }
        }
        let mut edge_index = HashMap::with_capacity(self.edges.len() * 2);
        let mut edge_links = Vec::with_capacity(self.edges.len());
        for (position, edge) in self.edges.iter().enumerate() {
            let coarse_key = edge_index_key(&self.edge_hash, edge, false);
            let exact_key = edge_index_key(&self.edge_hash, edge, true);
            edge_links.push(EdgeLinks {
                coarse: edge_index.get(&coarse_key).map_or(0, |index| index + 1),
                exact: edge_index.get(&exact_key).map_or(0, |index| index + 1),
            });
            edge_index.insert(coarse_key, position);
            edge_index.insert(exact_key, position);
        }
        self.blob_index = blob_index;
        self.edge_index = edge_index;
        self.edge_links = edge_links;
        self.source_index = source_index;
        self.range_count = range_count;
        Ok(())
    }

    fn validate_range(&self, range: &SourceRange) -> Result<(), EvidenceError> {
        let source = self
            .source(&range.source)
            .ok_or(EvidenceError::MissingReference { kind: "source" })?;
        if range.length == 0
            || range.packet == Some(0)
            || range
                .offset
                .checked_add(range.length)
                .is_none_or(|end| end > source.length)
        {
            return Err(EvidenceError::InvalidSourceRange);
        }
        Ok(())
    }
}

fn edge_index_key(hash: &RandomState, edge: &Edge, exact: bool) -> EdgeIndexKey {
    edge_lookup_key(
        hash,
        edge.from,
        edge.to,
        &edge.relation,
        edge.status,
        exact.then_some(edge.reason.as_str()),
    )
}

fn edge_lookup_key(
    hash: &RandomState,
    from: u64,
    to: u64,
    relation: &str,
    status: EvidenceStatus,
    reason: Option<&str>,
) -> EdgeIndexKey {
    EdgeIndexKey {
        from,
        to,
        relation_hash: hash.hash_one(relation),
        reason_hash: reason.map_or(0, |reason| hash.hash_one(reason)),
        status: status_index(status),
        exact: reason.is_some(),
    }
}

fn restore_edge_head(index: &mut HashMap<EdgeIndexKey, usize>, key: EdgeIndexKey, previous: usize) {
    if let Some(position) = previous.checked_sub(1) {
        index.insert(key, position);
    } else {
        index.remove(&key);
    }
}

const fn status_index(status: EvidenceStatus) -> u8 {
    match status {
        EvidenceStatus::Observed => 0,
        EvidenceStatus::Hypothesis => 1,
        EvidenceStatus::ConstraintSatisfied => 2,
        EvidenceStatus::ConstraintFailed => 3,
        EvidenceStatus::Unresolved => 4,
    }
}

impl Default for Case {
    fn default() -> Self {
        Self::new()
    }
}

fn source_id(sha256_hex: &str) -> Result<String, EvidenceError> {
    if !crate::hashing::is_sha256_digest(sha256_hex) {
        return Err(EvidenceError::InvalidDigest);
    }
    Ok(format!("sha256:{sha256_hex}"))
}

fn copy_blob_bytes(bytes: &[u8]) -> Result<Vec<u8>, EvidenceError> {
    let mut retained = Vec::new();
    retained
        .try_reserve_exact(bytes.len())
        .map_err(|_| EvidenceError::AllocationFailed {
            field: "blob bytes",
        })?;
    retained.extend_from_slice(bytes);
    Ok(retained)
}

fn deserialize_sources<'de, D>(deserializer: D) -> Result<Vec<Source>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded::deserialize_vec::<D, Source, MAX_SOURCES>(deserializer)
}

fn deserialize_blobs<'de, D>(deserializer: D) -> Result<Vec<Blob>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded::deserialize_vec::<D, Blob, MAX_BLOBS>(deserializer)
}

fn deserialize_nodes<'de, D>(deserializer: D) -> Result<Vec<Node>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded::deserialize_vec::<D, Node, MAX_NODES>(deserializer)
}

fn deserialize_edges<'de, D>(deserializer: D) -> Result<Vec<Edge>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded::deserialize_vec::<D, Edge, MAX_EDGES>(deserializer)
}

fn deserialize_limitations<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bounded::deserialize_vec::<D, String, MAX_LIMITATIONS>(deserializer)
}

pub(super) fn validate_content_id(id: &str) -> Result<(), EvidenceError> {
    let digest = id
        .strip_prefix("sha256:")
        .ok_or(EvidenceError::InvalidDigest)?;
    if crate::hashing::is_sha256_digest(digest) {
        Ok(())
    } else {
        Err(EvidenceError::InvalidDigest)
    }
}

pub(super) fn validate_label(label: &str) -> Result<(), EvidenceError> {
    validate_text(label, MAX_SOURCE_LABEL_BYTES, "source label")?;
    if matches!(label, "." | "..") || label.contains('/') || label.contains('\\') {
        return Err(EvidenceError::InvalidText {
            field: "source basename",
        });
    }
    Ok(())
}

pub(super) fn validate_import_source_label(label: &str, kind: &str) -> Result<(), EvidenceError> {
    validate_label(label)?;
    validate_text(kind, 64, "source kind")
}

pub(super) fn validate_text(
    value: &str,
    maximum: usize,
    field: &'static str,
) -> Result<(), EvidenceError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(EvidenceError::InvalidText { field });
    }
    Ok(())
}

pub(super) fn encoded_details_length(details: &Value) -> Result<usize, EvidenceError> {
    let mut writer = CountWriter::new(MAX_NODE_DETAILS_BYTES);
    if serde_json::to_writer(&mut writer, details).is_err() {
        if writer.exceeded() {
            return Err(EvidenceError::NodeDetailsTooLarge {
                length: MAX_NODE_DETAILS_BYTES.saturating_add(1),
                maximum: MAX_NODE_DETAILS_BYTES,
            });
        }
        return Err(EvidenceError::InvalidJson);
    }
    Ok(writer.written())
}

fn total_blob_bytes(blobs: &[Blob]) -> Result<usize, EvidenceError> {
    blobs.iter().try_fold(0_usize, |total, blob| {
        total
            .checked_add(blob.bytes.len())
            .ok_or(EvidenceError::ArithmeticOverflow {
                field: "blob bytes",
            })
    })
}

fn total_details_bytes(nodes: &[Node]) -> Result<usize, EvidenceError> {
    nodes.iter().try_fold(0_usize, |total, node| {
        let node_bytes = encoded_details_length(&node.details)?;
        total
            .checked_add(node_bytes)
            .ok_or(EvidenceError::TotalDetailsTooLarge {
                length: usize::MAX,
                maximum: MAX_TOTAL_DETAILS_BYTES,
            })
    })
}
