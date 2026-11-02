//! Admit and resolve source-packet mappings for provisional XOR outputs

use super::super::case_scan::case_scan_work_bounds;
use super::{
    Executor, MAX_PACKET_MAPPINGS, MAX_PROJECTED_BYTES, PacketProjection, RecoveryCandidateId,
    RecoveryError, RecoveryExecutionError, RecoveryStage, RecoveryTask, XorStage,
    packet_projections,
};
use l2_workbench::{
    carrier::discovery::mapped_node_with_supporting_mappings,
    evidence::Case,
    job::{MemoryClass, MemoryError, MemoryLease},
};

pub(super) struct ProjectionSet {
    pub(super) values: Vec<PacketProjection>,
    pub(super) total_bytes: usize,
    // Projected ranges remain live while their temporary allocation is charged
    _memory: Option<MemoryLease>,
}

impl Executor<'_> {
    pub(super) fn xor_projections(
        &mut self,
        candidate: RecoveryCandidateId,
        input_node: u64,
        input_length: usize,
    ) -> Result<XorStage<ProjectionSet>, RecoveryExecutionError> {
        let range_count = self
            .case
            .node(input_node)
            .ok_or(RecoveryError::InvariantFailure)?
            .ranges
            .len();
        if range_count > MAX_PACKET_MAPPINGS {
            self.omit_xor_input(
                input_node,
                "xor_mapping_limit",
                range_count - MAX_PACKET_MAPPINGS,
            );
            return Ok(XorStage::Skipped);
        }
        let memory = match self.xor_mapping_admission(candidate, input_node, range_count)? {
            XorStage::Ready(memory) => memory,
            XorStage::Skipped => return Ok(XorStage::Skipped),
            XorStage::Exhausted => return Ok(XorStage::Exhausted),
        };
        // The resolver checks complete coverage and keeps identical retransmissions
        let Ok(mapped) = mapped_node_with_supporting_mappings(self.case, input_node) else {
            self.omit_xor_input(input_node, "xor_mapping_unavailable", 1);
            return Ok(XorStage::Skipped);
        };
        if mapped.mappings.len() > MAX_PACKET_MAPPINGS {
            self.omit_xor_input(
                input_node,
                "xor_mapping_limit",
                mapped.mappings.len() - MAX_PACKET_MAPPINGS,
            );
            return Ok(XorStage::Skipped);
        }
        let (mut projections, omitted) = packet_projections(&mapped.mappings, input_length);
        if omitted != 0 {
            self.omit_xor_input(input_node, "xor_packet_mapping_incomplete", omitted);
        }
        let (keep, total_bytes) = projection_prefix(&projections);
        if keep < projections.len() {
            self.omit_xor_input(
                input_node,
                "xor_packet_output_limit",
                projections.len() - keep,
            );
            projections.truncate(keep);
        }
        if projections.is_empty() {
            return Ok(XorStage::Skipped);
        }
        Ok(XorStage::Ready(ProjectionSet {
            values: projections,
            total_bytes,
            _memory: memory,
        }))
    }
    fn xor_mapping_admission(
        &mut self,
        candidate: RecoveryCandidateId,
        input_node: u64,
        range_count: usize,
    ) -> Result<XorStage<Option<MemoryLease>>, RecoveryExecutionError> {
        let graph_work = case_scan_work_bounds(self.case)?.framing;
        if !self.charge_work(
            candidate,
            &RecoveryTask::TransformDiscovery,
            &[input_node],
            graph_work,
        )? {
            return Ok(XorStage::Exhausted);
        }
        let receipt_bytes = mapping_receipt_bytes(self.case, input_node);
        if receipt_bytes > MAX_PACKET_MAPPINGS * 1024 {
            self.omit_xor_input(input_node, "xor_mapping_receipt_limit", 1);
            return Ok(XorStage::Skipped);
        }
        // Cover receipt parsing, comparisons, and packet grouping before allocating
        let mapping_work = receipt_bytes
            .checked_mul(8)
            .and_then(|work| {
                range_count
                    .checked_mul(range_count)
                    .and_then(|pairs| pairs.checked_mul(256))
                    .and_then(|comparisons| work.checked_add(comparisons))
            })
            .ok_or(RecoveryError::InvariantFailure)?;
        if !self.charge_work(
            candidate,
            &RecoveryTask::TransformDiscovery,
            &[input_node],
            mapping_work,
        )? {
            return Ok(XorStage::Exhausted);
        }
        let heap_bytes = mapping_heap_bound(self.case, range_count, receipt_bytes)?;
        let memory = if let Some(budget) = &self.memory {
            let requested =
                u64::try_from(heap_bytes).map_err(|_| RecoveryError::InvariantFailure)?;
            match budget.try_reserve(MemoryClass::Executor, requested) {
                Ok(lease) => Some(lease),
                Err(MemoryError::Limit { .. } | MemoryError::Pressure { .. }) => {
                    self.omit_xor_input(input_node, "xor_mapping_memory_limit", 1);
                    return Ok(XorStage::Skipped);
                }
                Err(source) => {
                    return Err(RecoveryExecutionError::Operational {
                        stage: RecoveryStage::TransformDiscovery,
                        source: Box::new(source),
                    });
                }
            }
        } else {
            None
        };
        Ok(XorStage::Ready(memory))
    }
}

fn mapping_receipt_bytes(case: &Case, input_node: u64) -> usize {
    case.edges()
        .iter()
        .filter(|edge| edge.from == input_node && edge.relation == "mapped_by")
        .filter_map(|edge| {
            case.node(edge.to)
                .and_then(|node| node.blob.as_deref())
                .and_then(|id| case.blob(id))
                .map(|blob| blob.bytes.len())
        })
        .max()
        .unwrap_or(0)
}

fn mapping_heap_bound(
    case: &Case,
    range_count: usize,
    receipt_bytes: usize,
) -> Result<usize, RecoveryExecutionError> {
    case.nodes()
        .len()
        .checked_mul(256)
        .and_then(|bytes| {
            case.edges()
                .len()
                .checked_mul(256)
                .and_then(|edges| bytes.checked_add(edges))
        })
        .and_then(|bytes| {
            case.blobs()
                .len()
                .checked_mul(128)
                .and_then(|blobs| bytes.checked_add(blobs))
        })
        .and_then(|bytes| {
            range_count
                .checked_mul(1024)
                .and_then(|ranges| bytes.checked_add(ranges))
        })
        .and_then(|bytes| {
            receipt_bytes
                .checked_mul(8)
                .and_then(|receipt| bytes.checked_add(receipt))
        })
        .ok_or_else(|| RecoveryError::InvariantFailure.into())
}

fn projection_prefix(projections: &[PacketProjection]) -> (usize, usize) {
    let mut total = 0_usize;
    let mut keep = 0;
    for projection in projections {
        let length = projection.end - projection.start;
        let Some(next) = total.checked_add(length) else {
            break;
        };
        if next > MAX_PROJECTED_BYTES {
            break;
        }
        total = next;
        keep += 1;
    }
    (keep, total)
}
