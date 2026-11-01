use super::Case;
use crate::evidence::{ByteMapping, Edge, EvidenceError, EvidenceStatus};
use crate::job::MemoryLease;
use serde_json::{Value, json};
use std::ops::Range;

/// Clip source mappings to one half-open output byte range
///
/// # Errors
/// Returns an error for invalid range arithmetic or a mapping that cannot be represented
pub fn clip_byte_mappings(
    mappings: &[ByteMapping],
    output_range: Range<usize>,
) -> Result<Vec<ByteMapping>, EvidenceError> {
    clip_byte_mappings_inner(mappings, output_range, None)
}

/// Clip mappings while admitting their output vector and source names
///
/// Keep the shared lease until the returned mappings and moved data are dropped
///
/// # Errors
/// Returns an error for invalid ranges, allocation failure, or refused memory admission
pub fn clip_byte_mappings_with_memory(
    mappings: &[ByteMapping],
    output_range: Range<usize>,
    memory: &mut MemoryLease,
) -> Result<Vec<ByteMapping>, EvidenceError> {
    let before = memory.bytes();
    let result = clip_byte_mappings_inner(mappings, output_range, Some(&mut *memory));
    if result.is_err() {
        // The partial output has dropped before its charge is released
        memory.try_resize(before).map_err(EvidenceError::Memory)?;
    }
    result
}

fn clip_byte_mappings_inner(
    mappings: &[ByteMapping],
    output_range: Range<usize>,
    mut memory: Option<&mut MemoryLease>,
) -> Result<Vec<ByteMapping>, EvidenceError> {
    if output_range.start > output_range.end {
        return Err(EvidenceError::InvalidSourceRange);
    }
    let mut clipped = Vec::new();
    for mapping in mappings {
        let mapping_end = checked_mapping_end(mapping)?;
        if let Some(mapping) =
            clip_mapping(mapping, mapping_end, &output_range, memory.as_deref_mut())?
        {
            if let Some(lease) = memory.as_deref_mut() {
                crate::allocation::reserve_one_with_memory(&mut clipped, lease).map_err(
                    |error| match error {
                        crate::allocation::VectorAllocationError::Memory(error) => {
                            EvidenceError::Memory(error)
                        }
                        crate::allocation::VectorAllocationError::Allocation => {
                            EvidenceError::AllocationFailed {
                                field: "clipped byte mappings",
                            }
                        }
                    },
                )?;
            } else {
                clipped
                    .try_reserve(1)
                    .map_err(|_| EvidenceError::AllocationFailed {
                        field: "clipped byte mappings",
                    })?;
            }
            clipped.push(mapping);
        }
    }
    Ok(clipped)
}

/// Incrementally clip disjoint ordered mappings across monotonically increasing ranges
///
/// `None` from [`Self::new`] means mappings are out of order or overlap in output
/// space, so callers should use [`clip_byte_mappings`] for each requested range
pub struct CheckedByteMappingCursor<'a> {
    mappings: &'a [ByteMapping],
    ends: Vec<usize>,
    next_mapping: usize,
    previous_range: Option<Range<usize>>,
    usable: bool,
}

impl<'a> CheckedByteMappingCursor<'a> {
    /// Create a cursor after checking every output and source interval
    ///
    /// Returns `Ok(None)` when mappings are unsorted or overlap in output space
    ///
    /// # Errors
    /// Returns an error for invalid mapping arithmetic or failed allocation
    pub fn new(mappings: &'a [ByteMapping]) -> Result<Option<Self>, EvidenceError> {
        let mut ends = Vec::new();
        ends.try_reserve_exact(mappings.len())
            .map_err(|_| EvidenceError::AllocationFailed {
                field: "mapping cursor ends",
            })?;

        let mut ordered = true;
        let mut previous_offset = None;
        let mut previous_end = None;
        for mapping in mappings {
            let end = checked_mapping_end(mapping)?;
            ends.push(end);
            if previous_offset.is_some_and(|offset| mapping.offset < offset) {
                ordered = false;
            }
            if previous_end.is_some_and(|end| end > mapping.offset) {
                ordered = false;
            }
            previous_offset = Some(mapping.offset);
            previous_end = Some(end);
        }
        if !ordered {
            return Ok(None);
        }

        Ok(Some(Self {
            mappings,
            ends,
            next_mapping: 0,
            previous_range: None,
            usable: true,
        }))
    }

    /// Clip the next output range while preserving original mapping order
    ///
    /// Returns `Ok(None)` after a non-monotonic query, allowing the caller to
    /// continue safely with [`clip_byte_mappings`]
    ///
    /// # Errors
    /// Returns an error for invalid range arithmetic or failed output allocation
    pub fn clip_range(
        &mut self,
        output_range: Range<usize>,
    ) -> Result<Option<Vec<ByteMapping>>, EvidenceError> {
        if output_range.start > output_range.end {
            return Err(EvidenceError::InvalidSourceRange);
        }
        if !self.usable {
            return Ok(None);
        }
        if self.previous_range.as_ref().is_some_and(|previous| {
            output_range.start < previous.start || output_range.end < previous.end
        }) {
            self.usable = false;
            return Ok(None);
        }

        let mut clipped = Vec::new();
        while self.next_mapping < self.mappings.len() {
            let index = self.next_mapping;
            let mapping = self
                .mappings
                .get(index)
                .ok_or(EvidenceError::InvalidSourceRange)?;
            if mapping.offset >= output_range.end {
                break;
            }
            let end = self
                .ends
                .get(index)
                .copied()
                .ok_or(EvidenceError::InvalidSourceRange)?;
            if end <= output_range.start {
                self.advance_mapping();
                continue;
            }
            if let Some(mapping) = clip_mapping(mapping, end, &output_range, None)? {
                clipped
                    .try_reserve(1)
                    .map_err(|_| EvidenceError::AllocationFailed {
                        field: "clipped byte mappings",
                    })?;
                clipped.push(mapping);
            }
            if end <= output_range.end {
                self.advance_mapping();
            } else {
                break;
            }
        }
        self.previous_range = Some(output_range);
        Ok(Some(clipped))
    }

    const fn advance_mapping(&mut self) {
        // The caller advances only while the cursor is within the mapping slice
        self.next_mapping += 1;
    }
}

fn checked_mapping_end(mapping: &ByteMapping) -> Result<usize, EvidenceError> {
    let mapping_length =
        usize::try_from(mapping.range.length).map_err(|_| EvidenceError::InvalidSourceRange)?;
    let mapping_end = mapping
        .offset
        .checked_add(mapping_length)
        .ok_or(EvidenceError::InvalidSourceRange)?;
    mapping
        .range
        .offset
        .checked_add(mapping.range.length)
        .ok_or(EvidenceError::InvalidSourceRange)?;
    Ok(mapping_end)
}

fn clip_mapping(
    mapping: &ByteMapping,
    mapping_end: usize,
    output_range: &Range<usize>,
    memory: Option<&mut MemoryLease>,
) -> Result<Option<ByteMapping>, EvidenceError> {
    let first = mapping.offset.max(output_range.start);
    let last = mapping_end.min(output_range.end);
    if first >= last {
        return Ok(None);
    }
    Ok(Some(ByteMapping {
        offset: first - output_range.start,
        range: crate::evidence::SourceRange {
            source: copy_mapping_source(&mapping.range.source, memory)?,
            packet: mapping.range.packet,
            offset: mapping
                .range
                .offset
                .checked_add(
                    u64::try_from(first - mapping.offset)
                        .map_err(|_| EvidenceError::InvalidSourceRange)?,
                )
                .ok_or(EvidenceError::InvalidSourceRange)?,
            length: u64::try_from(last - first).map_err(|_| EvidenceError::InvalidSourceRange)?,
        },
    }))
}

fn copy_mapping_source(
    source: &str,
    memory: Option<&mut MemoryLease>,
) -> Result<String, EvidenceError> {
    let Some(memory) = memory else {
        return Ok(source.to_owned());
    };
    let requested = u64::try_from(source.len()).map_err(|_| EvidenceError::ArithmeticOverflow {
        field: "clipped mapping source bytes",
    })?;
    let mut pending = memory
        .try_sibling(requested)
        .map_err(EvidenceError::Memory)?;
    let mut copy = String::new();
    copy.try_reserve_exact(source.len())
        .map_err(|_| EvidenceError::AllocationFailed {
            field: "clipped mapping source",
        })?;
    pending
        .try_resize(u64::try_from(copy.capacity()).map_err(|_| {
            EvidenceError::ArithmeticOverflow {
                field: "clipped mapping source bytes",
            }
        })?)
        .map_err(EvidenceError::Memory)?;
    copy.push_str(source);
    memory.absorb(pending);
    Ok(copy)
}

struct Checkpoint {
    blobs: usize,
    nodes: usize,
    edges: usize,
    blob_bytes: usize,
    details_bytes: usize,
    ranges: usize,
}

impl Case {
    /// Add literal bytes and any required output-offset receipt as one graph change
    ///
    /// # Errors
    /// Rejects invalid mappings and restores the prior graph if any case quota fails
    pub fn add_mapped_bytes_node(
        &mut self,
        kind: &str,
        bytes: &[u8],
        mappings: &[ByteMapping],
        details: Value,
    ) -> Result<u64, EvidenceError> {
        for mapping in mappings {
            if mapping.offset > bytes.len()
                || usize::try_from(mapping.range.length)
                    .map_or(true, |length| length > bytes.len() - mapping.offset)
            {
                return Err(EvidenceError::InvalidSourceRange);
            }
        }
        let checkpoint = Checkpoint {
            blobs: self.blobs.len(),
            nodes: self.nodes.len(),
            edges: self.edges.len(),
            blob_bytes: self.blob_bytes,
            details_bytes: self.details_bytes,
            ranges: self.range_count,
        };
        let result = self.insert_mapped_bytes(kind, bytes, mappings, details);
        if result.is_err() {
            // Remove only this attempted addition, without cloning retained capture bytes
            for blob in self.blobs.drain(checkpoint.blobs..) {
                self.blob_index.remove(&blob.id);
            }
            self.nodes.truncate(checkpoint.nodes);
            self.truncate_edges(checkpoint.edges);
            self.blob_bytes = checkpoint.blob_bytes;
            self.details_bytes = checkpoint.details_bytes;
            self.range_count = checkpoint.ranges;
        }
        result
    }

    fn insert_mapped_bytes(
        &mut self,
        kind: &str,
        bytes: &[u8],
        mappings: &[ByteMapping],
        details: Value,
    ) -> Result<u64, EvidenceError> {
        let ranges = mappings
            .iter()
            .map(|mapping| mapping.range.clone())
            .collect();
        let id = self.add_bytes_node(kind, bytes, ranges, details)?;
        let needs_receipt = !mappings.is_empty()
            && (mappings.len() != 1
                || mappings.first().is_some_and(|mapping| {
                    mapping.offset != 0
                        || usize::try_from(mapping.range.length).ok() != Some(bytes.len())
                }));
        if needs_receipt {
            let bytes = serde_json::to_vec(mappings).map_err(|_| EvidenceError::InvalidJson)?;
            let receipt = self.add_bytes_node(
                "byte_mapping_receipt",
                &bytes,
                Vec::new(),
                json!({"output_node":id,"representation":"json_blob"}),
            )?;
            self.add_edge(Edge {
                from: id,
                to: receipt,
                relation: "mapped_by".to_owned(),
                status: EvidenceStatus::Observed,
                reason: "Each receipt entry maps an output byte interval to an exact source file interval".to_owned(),
            })?;
        }
        Ok(id)
    }
}
