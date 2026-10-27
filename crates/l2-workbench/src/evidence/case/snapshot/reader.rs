//! Bounded snapshot decoding and canonical Case validation

use super::super::super::model::{Blob, Edge, Node, Source};
use super::super::super::{FLOW_SELECTION_KIND, receipt_verification};
use super::super::{
    Case, EvidenceError, MAX_BLOBS, MAX_EDGES, MAX_LIMITATION_BYTES, MAX_LIMITATIONS,
    MAX_NODE_DETAILS_BYTES, MAX_NODE_KIND_BYTES, MAX_NODES, MAX_REASON_BYTES, MAX_RELATION_BYTES,
    MAX_SOURCES, MAX_TOTAL_DETAILS_BYTES, MAX_TOTAL_SOURCE_RANGES, SCHEMA_VERSION,
    validate_content_id, validate_import_source_label, validate_label, validate_text,
};
use super::{
    CaseSnapshotLimits, CaseSnapshotUsage,
    format::{
        MAX_SNAPSHOT_RECORD_BYTES, RangeCount, RawEdge, RawLimitation, RawNode, RawSnapshotRecord,
        RawSource, SNAPSHOT_BUFFER_CAPACITY, SNAPSHOT_FORMAT_VERSION, SnapshotBlob, SnapshotHeader,
    },
    io::{CountingReader, case_too_large, read_error},
};
use crate::job::{MemoryBudget, MemoryClass, MemoryLease};
use flate2::bufread::GzDecoder;
use serde_json::value::RawValue;
use std::io::{BufRead, BufReader, Read};

impl Case {
    /// Read an exact Case snapshot and report measured storage usage from the same pass
    ///
    /// The supplied decoded-byte bound is independent of the compressed package bound and is
    /// applied before blob allocations or owned graph records are created.
    ///
    /// # Errors
    /// Returns an error for malformed or oversized snapshots, invalid Case data, or I/O failure
    pub fn from_snapshot<G, B>(
        graph: G,
        blob_pack: B,
        limits: CaseSnapshotLimits,
    ) -> Result<(Self, CaseSnapshotUsage), EvidenceError>
    where
        G: Read,
        B: Read,
    {
        Self::from_snapshot_inner(graph, blob_pack, limits, None)
    }

    /// Restore a snapshot while charging the retained Case to one shared budget
    ///
    /// Reader and record buffers are charged while live. The caller must separately account
    /// for JSON decoding scratch and allocations inside the compression library
    ///
    /// # Errors
    /// Returns an admission error, invalid snapshot, allocation, or I/O failure
    pub fn from_snapshot_with_memory<G, B>(
        graph: G,
        blob_pack: B,
        limits: CaseSnapshotLimits,
        budget: &MemoryBudget,
    ) -> Result<(Self, CaseSnapshotUsage), EvidenceError>
    where
        G: Read,
        B: Read,
    {
        Self::from_snapshot_inner(graph, blob_pack, limits, Some(budget))
    }

    fn from_snapshot_inner<G, B>(
        graph: G,
        blob_pack: B,
        limits: CaseSnapshotLimits,
        budget: Option<&MemoryBudget>,
    ) -> Result<(Self, CaseSnapshotUsage), EvidenceError>
    where
        G: Read,
        B: Read,
    {
        let mut buffers = reserve_snapshot_buffers(budget)?;
        let mut compressed_graph = BufReader::with_capacity(
            SNAPSHOT_BUFFER_CAPACITY,
            CountingReader::new(
                graph,
                limits.maximum_storage_bytes,
                limits.maximum_storage_bytes.saturating_add(1),
                limits.maximum_storage_bytes,
            ),
        );
        let compressed_capacity = compressed_graph.capacity();
        adjust_snapshot_buffers(&mut buffers, compressed_capacity, SNAPSHOT_BUFFER_CAPACITY)?;
        let (case, graph_storage_limit, graph_decoded_bytes, blob_pack_bytes) = {
            let mut reader = SnapshotGraphReader::new(
                &mut compressed_graph,
                limits.maximum_decoded_bytes,
                budget,
            );
            adjust_snapshot_buffers(&mut buffers, compressed_capacity, reader.reader.capacity())?;
            let header = reader.read_header()?;
            let counts = validate_header(&header, limits)?;
            let blob_pack_bytes = header.blob_pack_bytes;
            let graph_storage_limit = limits.maximum_storage_bytes - header.blob_pack_bytes;
            let graph_decoded_limit = limits.maximum_decoded_bytes - header.blob_pack_bytes;
            reader.set_limits(
                graph_decoded_limit,
                graph_storage_limit,
                limits.maximum_storage_bytes,
            )?;

            let mut case = if let Some(budget) = budget {
                Self::with_memory_budget(budget)?
            } else {
                Self::new()
            };
            case.schema_version = header.schema_version;
            case.collection_complete = header.collection_complete;
            case.resource_limits = header.resource_limits;
            reader.read_sources(&mut case, counts.sources)?;
            reader.read_blobs(&mut case, blob_pack, counts.blobs, &header, limits)?;
            // Node references can resolve only after both content indexes are available
            if case.memory.is_none() {
                case.rebuild_indexes()?;
            }
            reader.read_nodes(&mut case, counts.nodes)?;
            reader.read_edges(&mut case, counts.edges)?;
            reader.read_limitations(&mut case, counts.limitations)?;
            let decoded_bytes = reader.finish()?;
            if decoded_bytes > graph_decoded_limit {
                return Err(case_too_large(decoded_bytes, graph_decoded_limit));
            }
            (case, graph_storage_limit, decoded_bytes, blob_pack_bytes)
        };

        if !compressed_graph
            .fill_buf()
            .map_err(|error| read_error(&error))?
            .is_empty()
        {
            return Err(EvidenceError::InvalidJson);
        }
        let graph_bytes = compressed_graph.get_ref().read_bytes;
        if graph_bytes > graph_storage_limit {
            return Err(case_too_large(
                limits.maximum_storage_bytes.saturating_add(1),
                limits.maximum_storage_bytes,
            ));
        }
        // Check blob digests once after the entire restored graph is available
        case.validate()?;
        Ok((
            case,
            CaseSnapshotUsage {
                graph_bytes,
                graph_decoded_bytes,
                blob_pack_bytes,
            },
        ))
    }
}

fn reserve_snapshot_buffers(
    budget: Option<&MemoryBudget>,
) -> Result<Option<MemoryLease>, EvidenceError> {
    // Both buffered readers live until the complete graph has been decoded
    let bytes = u64::try_from(SNAPSHOT_BUFFER_CAPACITY * 2).map_err(|_| {
        EvidenceError::ArithmeticOverflow {
            field: "snapshot reader buffers",
        }
    })?;
    budget
        .map(|budget| budget.try_reserve(MemoryClass::Cache, bytes))
        .transpose()
        .map_err(EvidenceError::Memory)
}

fn adjust_snapshot_buffers(
    memory: &mut Option<MemoryLease>,
    first: usize,
    second: usize,
) -> Result<(), EvidenceError> {
    let Some(memory) = memory else {
        return Ok(());
    };
    let bytes = first
        .checked_add(second)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(EvidenceError::ArithmeticOverflow {
            field: "snapshot reader buffers",
        })?;
    memory.try_resize(bytes).map_err(EvidenceError::Memory)
}

struct SnapshotGraphReader<'a, G: Read> {
    reader: BufReader<GzDecoder<&'a mut BufReader<CountingReader<G>>>>,
    decoded_bytes: u64,
    maximum_decoded_bytes: u64,
    budget: Option<&'a MemoryBudget>,
}

impl<'a, G: Read> SnapshotGraphReader<'a, G> {
    fn new(
        compressed_graph: &'a mut BufReader<CountingReader<G>>,
        maximum_decoded_bytes: u64,
        budget: Option<&'a MemoryBudget>,
    ) -> Self {
        Self {
            reader: BufReader::with_capacity(
                SNAPSHOT_BUFFER_CAPACITY,
                GzDecoder::new(compressed_graph),
            ),
            decoded_bytes: 0,
            maximum_decoded_bytes,
            budget,
        }
    }

    fn read_header(&mut self) -> Result<SnapshotHeader, EvidenceError> {
        let line = self.required_record()?;
        match decode_raw_record(line.as_ref())? {
            RawSnapshotRecord::Header(raw) => {
                serde_json::from_str(raw.get()).map_err(|_| EvidenceError::InvalidJson)
            }
            _ => Err(EvidenceError::InvalidJson),
        }
    }

    fn set_limits(
        &mut self,
        maximum_decoded_bytes: u64,
        maximum_graph_storage_bytes: u64,
        maximum_total_storage_bytes: u64,
    ) -> Result<(), EvidenceError> {
        self.maximum_decoded_bytes = maximum_decoded_bytes;
        let graph_input = &mut **self.reader.get_mut().get_mut();
        let buffered_bytes = u64::try_from(
            graph_input
                .fill_buf()
                .map_err(|error| read_error(&error))?
                .len(),
        )
        .map_err(|_| EvidenceError::ArithmeticOverflow {
            field: "snapshot compressed buffer",
        })?;
        let maximum_fetched = maximum_graph_storage_bytes
            .checked_add(buffered_bytes)
            .ok_or(EvidenceError::ArithmeticOverflow {
                field: "snapshot graph storage limit",
            })?;
        if graph_input.get_mut().set_maximum(maximum_fetched) {
            return Ok(());
        }
        Err(case_too_large(
            maximum_total_storage_bytes.saturating_add(1),
            maximum_total_storage_bytes,
        ))
    }

    fn next_line(&mut self) -> Result<Option<SnapshotLine>, EvidenceError> {
        read_record_line(
            &mut self.reader,
            &mut self.decoded_bytes,
            self.maximum_decoded_bytes,
            self.budget,
        )
    }

    fn required_record(&mut self) -> Result<SnapshotLine, EvidenceError> {
        self.next_line()?.ok_or(EvidenceError::InvalidJson)
    }

    fn read_sources(&mut self, case: &mut Case, count: usize) -> Result<(), EvidenceError> {
        for _ in 0..count {
            let line = self.required_record()?;
            let RawSnapshotRecord::Source(raw) = decode_raw_record(line.as_ref())? else {
                return Err(EvidenceError::InvalidJson);
            };
            preflight_source(raw)?;
            let source = serde_json::from_str::<Source>(raw.get())
                .map_err(|_| EvidenceError::InvalidJson)?;
            if case.memory.is_some() {
                super::super::memory::grow_vec(&mut case.memory, &mut case.sources)?;
                super::super::memory::grow_map(&mut case.memory, &mut case.source_index)?;
                let payload = super::super::memory::source_payload(&source)?
                    .checked_add(source.id.len())
                    .ok_or(EvidenceError::ArithmeticOverflow {
                        field: "Case memory bytes",
                    })?;
                if let Some(memory) = &mut case.memory {
                    memory.reserve_graph(payload)?;
                }
                let key = source.id.clone();
                if let Some(memory) = &mut case.memory {
                    memory.reserve_graph(key.capacity() - source.id.len())?;
                }
                let index = case.sources.len();
                if case.source_index.insert(key, index).is_some() {
                    return Err(EvidenceError::HashMismatch);
                }
                case.sources.push(source);
                continue;
            }
            case.sources
                .try_reserve(1)
                .map_err(|_| EvidenceError::AllocationFailed {
                    field: "snapshot sources",
                })?;
            case.sources.push(source);
        }
        Ok(())
    }

    fn read_blobs<B: Read>(
        &mut self,
        case: &mut Case,
        blob_pack: B,
        count: usize,
        header: &SnapshotHeader,
        limits: CaseSnapshotLimits,
    ) -> Result<(), EvidenceError> {
        let mut pack_reader = CountingReader::new(
            blob_pack,
            header.blob_pack_bytes,
            header.blob_pack_bytes.saturating_add(1),
            header.blob_pack_bytes,
        );
        let mut pack_offset = 0_u64;
        for _ in 0..count {
            let line = self.required_record()?;
            let RawSnapshotRecord::Blob(raw) = decode_raw_record(line.as_ref())? else {
                return Err(EvidenceError::InvalidJson);
            };
            let descriptor = serde_json::from_str::<SnapshotBlob>(raw.get())
                .map_err(|_| EvidenceError::InvalidJson)?;
            validate_content_id(&descriptor.id)?;
            // Contiguous ranges prevent bytes from being skipped or assigned twice
            if descriptor.offset != pack_offset {
                return Err(EvidenceError::InvalidJson);
            }
            let next_offset = pack_offset.checked_add(descriptor.length).ok_or(
                EvidenceError::ArithmeticOverflow {
                    field: "snapshot blob offset",
                },
            )?;
            if next_offset > header.blob_pack_bytes {
                return Err(EvidenceError::InvalidJson);
            }
            let length =
                usize::try_from(descriptor.length).map_err(|_| EvidenceError::QuotaExceeded {
                    field: "snapshot blob bytes",
                    maximum: usize::try_from(limits.maximum_decoded_bytes).unwrap_or(usize::MAX),
                })?;
            let next_blob_total =
                case.blob_bytes
                    .checked_add(length)
                    .ok_or(EvidenceError::ArithmeticOverflow {
                        field: "snapshot blob bytes",
                    })?;
            read_snapshot_blob(
                case,
                &mut pack_reader,
                descriptor.id,
                length,
                next_blob_total,
            )?;
            pack_offset = next_offset;
        }
        if pack_offset != header.blob_pack_bytes {
            return Err(EvidenceError::InvalidJson);
        }
        ensure_reader_eof(&mut pack_reader)?;
        if pack_reader.read_bytes != header.blob_pack_bytes {
            return Err(EvidenceError::InvalidJson);
        }
        Ok(())
    }

    fn read_nodes(&mut self, case: &mut Case, count: usize) -> Result<(), EvidenceError> {
        let mut accounting = NodeReadAccounting::default();
        for index in 0..count {
            let line = self.required_record()?;
            let RawSnapshotRecord::Node(raw) = decode_raw_record(line.as_ref())? else {
                return Err(EvidenceError::InvalidJson);
            };
            let preflight = serde_json::from_str::<RawNode>(raw.get())
                .map_err(|_| EvidenceError::InvalidJson)?;
            accounting.observe(&preflight, index)?;
            let node =
                serde_json::from_str::<Node>(raw.get()).map_err(|_| EvidenceError::InvalidJson)?;
            let plan = case.plan_node(
                &node.kind,
                node.blob.as_deref(),
                None,
                &node.ranges,
                &node.details,
            )?;
            if plan.id != node.id {
                return Err(EvidenceError::InvalidNodeId);
            }
            if case.memory.is_some() {
                case.admit_node_memory(
                    &node.kind,
                    node.blob.as_deref(),
                    &node.ranges,
                    node.ranges.capacity(),
                    &node.details,
                )?;
            } else {
                case.nodes
                    .try_reserve(1)
                    .map_err(|_| EvidenceError::AllocationFailed {
                        field: "snapshot nodes",
                    })?;
            }
            case.commit_node(
                &node.kind,
                node.blob.as_deref(),
                node.ranges,
                node.details,
                plan,
            );
        }
        Ok(())
    }

    fn read_edges(&mut self, case: &mut Case, count: usize) -> Result<(), EvidenceError> {
        for _ in 0..count {
            let line = self.required_record()?;
            let RawSnapshotRecord::Edge(raw) = decode_raw_record(line.as_ref())? else {
                return Err(EvidenceError::InvalidJson);
            };
            preflight_edge(raw)?;
            let edge =
                serde_json::from_str::<Edge>(raw.get()).map_err(|_| EvidenceError::InvalidJson)?;
            if case.memory.is_none() {
                case.edges
                    .try_reserve(1)
                    .map_err(|_| EvidenceError::AllocationFailed {
                        field: "snapshot edges",
                    })?;
            }
            case.add_edge(edge)?;
        }
        Ok(())
    }

    fn read_limitations(&mut self, case: &mut Case, count: usize) -> Result<(), EvidenceError> {
        for _ in 0..count {
            let line = self.required_record()?;
            let RawSnapshotRecord::Limitation(raw) = decode_raw_record(line.as_ref())? else {
                return Err(EvidenceError::InvalidJson);
            };
            let RawLimitation(limitation) = serde_json::from_str::<RawLimitation>(raw.get())
                .map_err(|_| EvidenceError::InvalidJson)?;
            validate_text(limitation.as_str(), MAX_LIMITATION_BYTES, "limitation")?;
            if case.memory.is_some() {
                super::super::memory::grow_vec(&mut case.memory, &mut case.limitations)?;
                if let Some(memory) = &mut case.memory {
                    memory.reserve_graph(limitation.as_str().len())?;
                }
                let value = limitation.into_string();
                if let Some(memory) = &mut case.memory {
                    memory.reserve_graph(value.capacity() - value.len())?;
                }
                case.limitations.push(value);
                continue;
            }
            case.limitations
                .try_reserve(1)
                .map_err(|_| EvidenceError::AllocationFailed {
                    field: "snapshot limitations",
                })?;
            case.limitations.push(limitation.into_string());
        }
        Ok(())
    }

    fn finish(mut self) -> Result<u64, EvidenceError> {
        if self.next_line()?.is_some() {
            return Err(EvidenceError::InvalidJson);
        }
        let decoded_bytes = self.decoded_bytes;
        drop(self.reader.into_inner());
        Ok(decoded_bytes)
    }
}

fn read_snapshot_blob(
    case: &mut Case,
    reader: &mut impl Read,
    id: String,
    length: usize,
    next_total: usize,
) -> Result<(), EvidenceError> {
    if case.memory.is_some() {
        case.prepare_blob_graph()?;
        case.reserve_blob_graph(&id)?;
        if let Some(memory) = &mut case.memory {
            memory.reserve_graph(id.capacity() - id.len())?;
        }
        case.reserve_blob_memory(length)?;
    } else {
        case.blobs
            .try_reserve(1)
            .map_err(|_| EvidenceError::AllocationFailed {
                field: "snapshot blobs",
            })?;
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| EvidenceError::AllocationFailed {
            field: "snapshot blob bytes",
        })?;
    if case.memory.is_some() {
        case.reserve_blob_memory(bytes.capacity() - length)?;
    }
    bytes.resize(length, 0);
    reader
        .read_exact(&mut bytes)
        .map_err(|_| EvidenceError::InvalidJson)?;
    if case.memory.is_some() {
        if case.blob_index.contains_key(&id) {
            return Err(EvidenceError::HashMismatch);
        }
        case.commit_blob(id, bytes, next_total);
    } else {
        case.blobs.push(Blob { id, bytes });
        case.blob_bytes = next_total;
    }
    Ok(())
}
#[derive(Default)]
struct NodeReadAccounting {
    ranges: usize,
    detail_bytes: usize,
}

impl NodeReadAccounting {
    fn observe(&mut self, node: &RawNode<'_>, index: usize) -> Result<(), EvidenceError> {
        let expected_id = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(EvidenceError::InvalidNodeId)?;
        if node.id != expected_id {
            return Err(EvidenceError::InvalidNodeId);
        }
        validate_text(node.kind.as_str(), MAX_NODE_KIND_BYTES, "node kind")?;
        if let Some(blob_id) = node.blob.as_ref() {
            validate_content_id(blob_id.as_str())?;
        }
        let RangeCount(ranges) =
            serde_json::from_str(node.ranges.get()).map_err(|_| EvidenceError::InvalidJson)?;
        self.ranges = self
            .ranges
            .checked_add(ranges)
            .ok_or(EvidenceError::ArithmeticOverflow {
                field: "snapshot source ranges",
            })?;
        if self.ranges > MAX_TOTAL_SOURCE_RANGES {
            return Err(EvidenceError::QuotaExceeded {
                field: "source ranges",
                maximum: MAX_TOTAL_SOURCE_RANGES,
            });
        }
        let raw_details_bytes = node.details.get().len();
        if raw_details_bytes > MAX_NODE_DETAILS_BYTES {
            return Err(EvidenceError::NodeDetailsTooLarge {
                length: raw_details_bytes,
                maximum: MAX_NODE_DETAILS_BYTES,
            });
        }
        self.detail_bytes = self.detail_bytes.checked_add(raw_details_bytes).ok_or(
            EvidenceError::TotalDetailsTooLarge {
                length: usize::MAX,
                maximum: MAX_TOTAL_DETAILS_BYTES,
            },
        )?;
        if self.detail_bytes > MAX_TOTAL_DETAILS_BYTES {
            return Err(EvidenceError::TotalDetailsTooLarge {
                length: self.detail_bytes,
                maximum: MAX_TOTAL_DETAILS_BYTES,
            });
        }
        if node.kind.as_str() == FLOW_SELECTION_KIND
            && !receipt_verification::raw_flow_selection_details_are_valid(node.details)
        {
            return Err(EvidenceError::InvalidJson);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct SnapshotCounts {
    sources: usize,
    blobs: usize,
    nodes: usize,
    edges: usize,
    limitations: usize,
}

fn validate_header(
    header: &SnapshotHeader,
    limits: CaseSnapshotLimits,
) -> Result<SnapshotCounts, EvidenceError> {
    if header.format_version != SNAPSHOT_FORMAT_VERSION {
        return Err(EvidenceError::InvalidJson);
    }
    if header.schema_version != SCHEMA_VERSION {
        return Err(EvidenceError::UnsupportedSchema {
            found: header.schema_version,
            expected: SCHEMA_VERSION,
        });
    }
    if header.resource_limits.blob_bytes == Some(0) {
        return Err(EvidenceError::InvalidResourceLimit {
            field: "blob bytes",
        });
    }
    let sources = checked_count(header.source_count, MAX_SOURCES, "sources")?;
    let blobs = checked_count(header.blob_count, MAX_BLOBS, "blobs")?;
    let nodes = checked_count(header.node_count, MAX_NODES, "nodes")?;
    let edges = checked_count(header.edge_count, MAX_EDGES, "edges")?;
    let limitations = checked_count(header.limitation_count, MAX_LIMITATIONS, "limitations")?;
    if header.blob_pack_bytes > limits.maximum_storage_bytes {
        return Err(case_too_large(
            header.blob_pack_bytes,
            limits.maximum_storage_bytes,
        ));
    }
    if header.blob_pack_bytes > limits.maximum_decoded_bytes {
        return Err(case_too_large(
            header.blob_pack_bytes,
            limits.maximum_decoded_bytes,
        ));
    }
    if header
        .resource_limits
        .blob_bytes
        .is_some_and(|maximum| u64::try_from(maximum).unwrap_or(u64::MAX) < header.blob_pack_bytes)
    {
        return Err(EvidenceError::QuotaExceeded {
            field: "blob bytes",
            maximum: header.resource_limits.blob_bytes.unwrap_or(usize::MAX),
        });
    }
    Ok(SnapshotCounts {
        sources,
        blobs,
        nodes,
        edges,
        limitations,
    })
}

fn checked_count(value: u64, maximum: usize, field: &'static str) -> Result<usize, EvidenceError> {
    if value > u64::try_from(maximum).unwrap_or(u64::MAX) {
        return Err(EvidenceError::QuotaExceeded { field, maximum });
    }
    usize::try_from(value).map_err(|_| EvidenceError::QuotaExceeded { field, maximum })
}

fn preflight_source(raw: &RawValue) -> Result<(), EvidenceError> {
    let source =
        serde_json::from_str::<RawSource>(raw.get()).map_err(|_| EvidenceError::InvalidJson)?;
    validate_content_id(source.id.as_str())?;
    validate_import_source_label(source.label.as_str(), source.kind.as_str())?;
    for alias in source.aliases {
        validate_label(alias.as_str())?;
    }
    if let Some(blob) = source.blob {
        validate_content_id(blob.as_str())?;
    }
    Ok(())
}

fn preflight_edge(raw: &RawValue) -> Result<(), EvidenceError> {
    let edge =
        serde_json::from_str::<RawEdge>(raw.get()).map_err(|_| EvidenceError::InvalidJson)?;
    validate_text(edge.relation.as_str(), MAX_RELATION_BYTES, "relationship")?;
    validate_text(
        edge.reason.as_str(),
        MAX_REASON_BYTES,
        "relationship reason",
    )?;
    Ok(())
}

fn decode_raw_record(line: &[u8]) -> Result<RawSnapshotRecord<'_>, EvidenceError> {
    serde_json::from_slice(line).map_err(|_| EvidenceError::InvalidJson)
}
struct SnapshotLine {
    bytes: Vec<u8>,
    _memory: Option<MemoryLease>,
}

impl AsRef<[u8]> for SnapshotLine {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

fn read_record_line<R: BufRead>(
    reader: &mut R,
    decoded_bytes: &mut u64,
    maximum_decoded_bytes: u64,
    budget: Option<&MemoryBudget>,
) -> Result<Option<SnapshotLine>, EvidenceError> {
    let mut line = Vec::new();
    let mut memory = budget
        .map(|budget| budget.try_reserve(MemoryClass::Cache, 0))
        .transpose()
        .map_err(EvidenceError::Memory)?;
    loop {
        let available = reader.fill_buf().map_err(|error| read_error(&error))?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            return Err(EvidenceError::InvalidJson);
        }
        let part_length = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        let next_decoded = decoded_bytes
            .checked_add(u64::try_from(part_length).map_err(|_| {
                EvidenceError::ArithmeticOverflow {
                    field: "snapshot graph bytes",
                }
            })?)
            .ok_or(EvidenceError::ArithmeticOverflow {
                field: "snapshot graph bytes",
            })?;
        if next_decoded > maximum_decoded_bytes {
            return Err(case_too_large(next_decoded, maximum_decoded_bytes));
        }
        let last_index = part_length
            .checked_sub(1)
            .ok_or(EvidenceError::InvalidJson)?;
        let complete = available.get(last_index).copied() == Some(b'\n');
        let line_part_length = part_length - usize::from(complete);
        let next_line_length =
            line.len()
                .checked_add(line_part_length)
                .ok_or(EvidenceError::ArithmeticOverflow {
                    field: "snapshot graph record",
                })?;
        if next_line_length > MAX_SNAPSHOT_RECORD_BYTES {
            return Err(case_too_large(
                u64::try_from(next_line_length).unwrap_or(u64::MAX),
                u64::try_from(MAX_SNAPSHOT_RECORD_BYTES).unwrap_or(u64::MAX),
            ));
        }
        if let Some(memory) = &mut memory {
            super::super::memory::grow_vec_lease(memory, &mut line, next_line_length)?;
        } else {
            line.try_reserve(line_part_length)
                .map_err(|_| EvidenceError::AllocationFailed {
                    field: "snapshot graph record",
                })?;
        }
        let line_part = available
            .get(..line_part_length)
            .ok_or(EvidenceError::InvalidJson)?;
        line.extend_from_slice(line_part);
        reader.consume(part_length);
        *decoded_bytes = next_decoded;
        if complete {
            return Ok(Some(SnapshotLine {
                bytes: line,
                _memory: memory,
            }));
        }
    }
}

fn ensure_reader_eof<R: Read>(reader: &mut R) -> Result<(), EvidenceError> {
    let mut extra = [0_u8; 1];
    match reader.read(&mut extra) {
        Ok(0) => Ok(()),
        _ => Err(EvidenceError::InvalidJson),
    }
}
