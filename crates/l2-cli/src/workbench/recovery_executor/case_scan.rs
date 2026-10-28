use super::RecoveryExecutionError;
use l2_workbench::evidence::{
    Case, CaseIdentity, MAX_EDGES, MAX_NODE_KIND_BYTES, MAX_NODES, MAX_REASON_BYTES,
    MAX_RELATION_BYTES,
};
use std::sync::Arc;

pub(super) const CONTENT_ID_BYTES: usize = "sha256:".len() + 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CaseScanWorkBounds {
    pub(super) framing: usize,
    pub(super) record: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CaseScanShape {
    nodes: usize,
    edges: usize,
    blobs: usize,
    sources: usize,
    details_bytes: usize,
    blob_bytes: usize,
    source_ranges: usize,
}

pub(super) const INDEX_RADIX_PASSES: usize = CONTENT_ID_BYTES + std::mem::size_of::<u64>() + 2;
pub(super) const INDEX_VALIDATED_RANGE_KEY_VALUE_BYTES: usize = 2 * std::mem::size_of::<u64>();
const INDEX_RADIX_BUCKETS: usize = 256;

impl CaseScanShape {
    pub(super) fn from_case(case: &Case) -> Self {
        let usage = case.resource_usage();
        Self {
            nodes: case.nodes().len(),
            edges: case.edges().len(),
            blobs: case.blobs().len(),
            sources: case.sources().len(),
            details_bytes: usage.details_bytes,
            blob_bytes: usage.blob_bytes,
            source_ranges: usage.source_ranges,
        }
    }

    pub(super) fn framing_bound(self) -> Result<usize, RecoveryExecutionError> {
        let detail_work = checked_product(self.details_bytes, 2, "framing details")?;
        let node_work = checked_product(
            self.nodes,
            MAX_NODE_KIND_BYTES + std::mem::size_of::<u64>(),
            "framing nodes",
        )?;
        let range_work = checked_product(
            self.source_ranges,
            CONTENT_ID_BYTES + 4 * std::mem::size_of::<u64>(),
            "framing source ranges",
        )?;
        let edge_work = checked_product(
            self.edges,
            MAX_RELATION_BYTES + MAX_REASON_BYTES + 3 * std::mem::size_of::<u64>(),
            "framing edges",
        )?;
        let blob_work = checked_product(
            self.blobs,
            CONTENT_ID_BYTES + std::mem::size_of::<usize>(),
            "framing blobs",
        )?;
        checked_sum(
            &[detail_work, node_work, range_work, edge_work, blob_work],
            "framing Case scan",
        )
    }

    pub(super) fn record_bound(self) -> Result<usize, RecoveryExecutionError> {
        let detail_work = checked_product(self.details_bytes, 2, "record details")?;
        let node_work = checked_product(
            self.nodes,
            MAX_NODE_KIND_BYTES + CONTENT_ID_BYTES + std::mem::size_of::<u64>(),
            "record nodes",
        )?;
        let range_work = checked_product(
            self.source_ranges,
            64 + 2 * CONTENT_ID_BYTES,
            "record source ranges",
        )?;
        let blob_id_work = checked_product(self.blobs, CONTENT_ID_BYTES, "record blob IDs")?;
        let source_id_work = checked_product(self.sources, CONTENT_ID_BYTES, "record source IDs")?;
        let edge_work = checked_product(
            self.edges,
            MAX_RELATION_BYTES + MAX_REASON_BYTES + 17,
            "record edges",
        )?;
        checked_sum(
            &[
                detail_work,
                node_work,
                range_work,
                blob_id_work,
                self.blob_bytes,
                source_id_work,
                edge_work,
            ],
            "record Case scan",
        )
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct CaseIndexScanLedger {
    maximum: usize,
    charged: usize,
}

impl CaseIndexScanLedger {
    pub(super) fn new() -> Result<Self, RecoveryExecutionError> {
        Ok(Self {
            maximum: case_index_work_limit()?,
            charged: 0,
        })
    }

    pub(super) const fn maximum(self) -> usize {
        self.maximum
    }

    pub(super) const fn charged(self) -> usize {
        self.charged
    }

    pub(super) fn remaining(self) -> Result<usize, RecoveryExecutionError> {
        self.maximum
            .checked_sub(self.charged)
            .ok_or_else(|| invalid_bound("Case index scan ledger"))
    }

    pub(super) fn charge(
        &mut self,
        requested: usize,
        actual: usize,
    ) -> Result<(), RecoveryExecutionError> {
        if actual > requested || requested > self.remaining()? {
            return Err(RecoveryExecutionError::InvalidPolicy(
                "Case index scan exceeded its admitted retained-index allowance".to_owned(),
            ));
        }
        self.charged = self
            .charged
            .checked_add(actual)
            .ok_or_else(|| invalid_bound("Case index scan ledger"))?;
        Ok(())
    }
}

pub(super) fn case_index_work_limit() -> Result<usize, RecoveryExecutionError> {
    let node_visit = MAX_NODE_KIND_BYTES
        .checked_add(CONTENT_ID_BYTES)
        .and_then(|work| work.checked_add(CONTENT_ID_BYTES))
        .and_then(|work| work.checked_add(2 * std::mem::size_of::<u64>()))
        .and_then(|work| work.checked_add(std::mem::size_of::<u64>()))
        .and_then(|work| work.checked_add(std::mem::size_of::<usize>()))
        .ok_or_else(|| invalid_bound("Case index node work"))?;
    let seed_visit = node_visit
        .checked_add(MAX_NODE_KIND_BYTES + 2)
        .ok_or_else(|| invalid_bound("Case seed enumeration work"))?;
    let seed_sort = seed_ordering_work_bound(MAX_NODES)?;
    let node_work = checked_product(
        MAX_NODES,
        node_visit
            .checked_add(seed_visit)
            .ok_or_else(|| invalid_bound("Case index nodes"))?,
        "Case index nodes",
    )?;
    let edge_work = checked_product(
        MAX_EDGES,
        MAX_RELATION_BYTES
            + MAX_REASON_BYTES
            + 17
            + MAX_NODE_KIND_BYTES
            + INDEX_VALIDATED_RANGE_KEY_VALUE_BYTES,
        "Case index edges",
    )?;
    checked_sum(&[node_work, edge_work, seed_sort], "Case index ledger")
}

pub(super) fn case_index_scan_bound(case: &Case) -> Result<usize, RecoveryExecutionError> {
    let node_work = checked_product(
        case.nodes().len(),
        MAX_NODE_KIND_BYTES
            + CONTENT_ID_BYTES
            + CONTENT_ID_BYTES
            + 2 * std::mem::size_of::<u64>()
            + std::mem::size_of::<u64>()
            + std::mem::size_of::<usize>(),
        "Case index nodes",
    )?;
    let edge_work = checked_product(
        case.edges().len(),
        MAX_RELATION_BYTES
            + MAX_REASON_BYTES
            + 17
            + MAX_NODE_KIND_BYTES
            + INDEX_VALIDATED_RANGE_KEY_VALUE_BYTES,
        "Case index edges",
    )?;
    let seed_visit = checked_product(
        case.nodes().len(),
        2 * MAX_NODE_KIND_BYTES + CONTENT_ID_BYTES + std::mem::size_of::<u64>() + 2,
        "Case seed enumeration",
    )?;
    let seed_sort = seed_ordering_work_bound(case.nodes().len())?;
    checked_sum(
        &[node_work, edge_work, seed_visit, seed_sort],
        "initial Case index scan",
    )
}

pub(super) fn case_index_suffix_scan_bound(
    previous_nodes: usize,
    previous_edges: usize,
    case: &Case,
) -> Result<usize, RecoveryExecutionError> {
    let nodes = case
        .nodes()
        .len()
        .checked_sub(previous_nodes)
        .ok_or_else(|| invalid_bound("Case index node high-water mark"))?;
    let edges = case
        .edges()
        .len()
        .checked_sub(previous_edges)
        .ok_or_else(|| invalid_bound("Case index edge high-water mark"))?;
    let node_work = checked_product(
        nodes,
        MAX_NODE_KIND_BYTES
            + CONTENT_ID_BYTES
            + CONTENT_ID_BYTES
            + 2 * std::mem::size_of::<u64>()
            + std::mem::size_of::<u64>()
            + std::mem::size_of::<usize>(),
        "Case index suffix nodes",
    )?;
    let edge_work = checked_product(
        edges,
        MAX_RELATION_BYTES
            + MAX_REASON_BYTES
            + 17
            + MAX_NODE_KIND_BYTES
            + INDEX_VALIDATED_RANGE_KEY_VALUE_BYTES,
        "Case index suffix edges",
    )?;
    checked_sum(&[node_work, edge_work], "Case index suffix scan")
}

fn seed_ordering_work_bound(seeds: usize) -> Result<usize, RecoveryExecutionError> {
    let passes = INDEX_RADIX_PASSES;
    let item_work = checked_product(
        seeds,
        passes
            .checked_mul(2)
            .ok_or_else(|| invalid_bound("Case seed ordering items"))?,
        "Case seed ordering items",
    )?;
    let bucket_work = checked_product(passes, INDEX_RADIX_BUCKETS, "Case seed ordering buckets")?;
    checked_sum(&[item_work, bucket_work], "Case seed ordering")
}

pub(super) fn case_scan_work_bounds(
    case: &Case,
) -> Result<CaseScanWorkBounds, RecoveryExecutionError> {
    let shape = CaseScanShape::from_case(case);
    Ok(CaseScanWorkBounds {
        framing: shape.framing_bound()?,
        record: shape.record_bound()?,
    })
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum ScanAdmission<T> {
    Scanned { value: T, work: usize },
    Exhausted { requested: usize },
}

pub(super) fn preflight_scan<T>(
    requested: usize,
    remaining: usize,
    scan: impl FnOnce() -> Result<(T, usize), RecoveryExecutionError>,
) -> Result<ScanAdmission<T>, RecoveryExecutionError> {
    if requested > remaining {
        return Ok(ScanAdmission::Exhausted { requested });
    }

    let (value, work) = scan()?;
    if work > requested {
        return Err(RecoveryExecutionError::InvalidPolicy(format!(
            "measured Case scan work {work} exceeded its preflight bound {requested}"
        )));
    }
    Ok(ScanAdmission::Scanned { value, work })
}

pub(super) struct RecordDiscoverySnapshot {
    pub(super) plan: Arc<super::record_discovery::RecordDiscoveryPlan>,
    case_identity: CaseIdentity,
    node_high_water_mark: usize,
    edge_high_water_mark: usize,
}

impl RecordDiscoverySnapshot {
    pub(super) fn new(
        case: &Case,
        plan: Arc<super::record_discovery::RecordDiscoveryPlan>,
    ) -> Self {
        Self {
            plan,
            case_identity: case.identity(),
            node_high_water_mark: case.nodes().len(),
            edge_high_water_mark: case.edges().len(),
        }
    }

    pub(super) fn scan_work(&self) -> usize {
        super::record_discovery::scan_work(&self.plan)
    }

    pub(super) fn node_suffix_scan_bound(
        &self,
        case: &Case,
    ) -> Result<usize, RecoveryExecutionError> {
        if !self.case_identity.identifies(case)
            || case.nodes().len() < self.node_high_water_mark
            || case.edges().len() < self.edge_high_water_mark
        {
            return Ok(0);
        }
        let node_count = case.nodes().len() - self.node_high_water_mark;
        let edge_count = case.edges().len().saturating_sub(self.edge_high_water_mark);
        checked_sum(
            &[
                checked_product(
                    node_count,
                    MAX_NODE_KIND_BYTES + std::mem::size_of::<u64>(),
                    "record plan suffix nodes",
                )?,
                checked_product(
                    edge_count,
                    MAX_RELATION_BYTES + MAX_REASON_BYTES + 17 + 2 * MAX_NODE_KIND_BYTES,
                    "record plan suffix edges",
                )?,
            ],
            "record plan Case suffix",
        )
    }

    pub(super) fn inspect_case_suffix(
        &self,
        case: &Case,
    ) -> Result<(bool, usize), RecoveryExecutionError> {
        if !self.case_identity.identifies(case)
            || case.nodes().len() < self.node_high_water_mark
            || case.edges().len() < self.edge_high_water_mark
        {
            return Ok((false, 0));
        }
        let mut work = 0_usize;
        for node in case
            .nodes()
            .get(self.node_high_water_mark..)
            .unwrap_or_default()
        {
            work = work
                .checked_add(node.kind.len())
                .and_then(|total| total.checked_add(std::mem::size_of::<u64>()))
                .ok_or_else(|| invalid_bound("record plan suffix inspection"))?;
            if node.kind == "custom_protocol_frame" {
                return Ok((false, work));
            }
        }
        for edge in case
            .edges()
            .get(self.edge_high_water_mark..)
            .unwrap_or_default()
        {
            let from_kind = case.node(edge.from).map_or("", |node| node.kind.as_str());
            let to_kind = case.node(edge.to).map_or("", |node| node.kind.as_str());
            work = work
                .checked_add(edge.relation.len())
                .and_then(|total| total.checked_add(edge.reason.len()))
                .and_then(|total| total.checked_add(17))
                .and_then(|total| total.checked_add(from_kind.len()))
                .and_then(|total| total.checked_add(to_kind.len()))
                .ok_or_else(|| invalid_bound("record plan suffix inspection"))?;
            if relation_can_change_record_eligibility(edge.relation.as_str(), from_kind, to_kind) {
                return Ok((false, work));
            }
        }
        Ok((true, work))
    }
}

fn relation_can_change_record_eligibility(relation: &str, from_kind: &str, to_kind: &str) -> bool {
    match relation {
        "contains" => is_tcp_context_kind(from_kind) || is_tcp_context_kind(to_kind),
        "materialized" => to_kind == "custom_protocol_frame",
        "framing_rule_selected_from" | "framing_tested_by" => {
            is_framing_evidence_kind(from_kind) || is_framing_evidence_kind(to_kind)
        }
        _ => false,
    }
}

fn is_tcp_context_kind(kind: &str) -> bool {
    matches!(kind, "tcp_episode" | "tcp_direction" | "tcp_byte_run")
}

fn is_framing_evidence_kind(kind: &str) -> bool {
    matches!(
        kind,
        "custom_protocol_frame"
            | "custom_protocol_framing_receipt"
            | "recovery_framing_discovery_report"
    )
}

fn checked_product(
    count: usize,
    per_item: usize,
    field: &'static str,
) -> Result<usize, RecoveryExecutionError> {
    count
        .checked_mul(per_item)
        .ok_or_else(|| invalid_bound(field))
}

fn checked_sum(values: &[usize], field: &'static str) -> Result<usize, RecoveryExecutionError> {
    values
        .iter()
        .try_fold(0_usize, |total, value| total.checked_add(*value))
        .ok_or_else(|| invalid_bound(field))
}

fn invalid_bound(field: &'static str) -> RecoveryExecutionError {
    RecoveryExecutionError::InvalidPolicy(format!(
        "{field} work bound exceeds this platform's address space"
    ))
}

#[cfg(test)]
#[path = "../../../tests/workbench/recovery_case_scan_enforcement.rs"]
mod scan_enforcement_tests;
