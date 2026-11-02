//! Retain provisional decoded bytes and their source-linked receipts

use super::super::{checkpoint, evidence::add_transaction_edge};
use super::{PacketProjection, RecoveryError, RecoveryExecutionError, RecoveryStage};
use l2_workbench::{
    derivation::{self, DerivationStatus},
    evidence::{Case, Edge, EvidenceError, EvidenceStatus},
    job::{MemoryBudget, MemoryError, MemoryLease},
    recovery::xor::{XOR_PROPOSAL_FORMAT_VERSION, XorEvidence, XorProposalReport},
};
use serde::{Serialize, Serializer, ser::SerializeSeq};
use serde_json::json;

pub(super) struct EncodedReport {
    pub(super) bytes: Vec<u8>,
    // Keep the capacity admission until the encoded bytes have been dropped
    _memory: Option<MemoryLease>,
}

#[derive(Serialize)]
struct VisibleReport<'a> {
    omitted_candidates: usize,
    proposals: ProposalSequence<'a>,
    sample_truncated: bool,
    search_truncated: bool,
    version: u16,
}

struct ProposalSequence<'a>(&'a XorProposalReport);

impl Serialize for ProposalSequence<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut proposals = serializer.serialize_seq(Some(self.0.proposals.len()))?;
        for proposal in &self.0.proposals {
            proposals.serialize_element(&VisibleProposal {
                evidence: &proposal.evidence,
            })?;
        }
        proposals.end()
    }
}

#[derive(Serialize)]
struct VisibleProposal<'a> {
    evidence: &'a XorEvidence,
}

pub(super) fn serialized_report(
    report: &XorProposalReport,
    memory: &MemoryBudget,
    max_bytes: usize,
) -> Result<EncodedReport, RecoveryExecutionError> {
    // Proposal position identifies the transient recipe without exposing its key
    let value = VisibleReport {
        omitted_candidates: report.omitted_candidates,
        proposals: ProposalSequence(report),
        sample_truncated: report.sample_truncated,
        search_truncated: report.search_truncated,
        version: XOR_PROPOSAL_FORMAT_VERSION,
    };
    let (bytes, retained) = checkpoint::encode(&value, max_bytes, Some(memory))?;
    Ok(EncodedReport {
        bytes,
        _memory: retained,
    })
}

pub(super) fn is_memory_limit(error: &RecoveryExecutionError) -> bool {
    let limited = |error: &MemoryError| {
        matches!(
            error,
            MemoryError::Limit { .. } | MemoryError::Pressure { .. }
        )
    };
    if let RecoveryExecutionError::Evidence(EvidenceError::Memory(source)) = error {
        return limited(source);
    }
    let RecoveryExecutionError::Operational { source, .. } = error else {
        return false;
    };
    source.downcast_ref::<MemoryError>().is_some_and(limited)
        || source.downcast_ref::<derivation::AdmittedDerivationError>().is_some_and(|error| {
            matches!(error, derivation::AdmittedDerivationError::Memory(memory) if limited(memory))
        })
        || source.downcast_ref::<derivation::NormalizationError>().is_some_and(|error| {
            matches!(error, derivation::NormalizationError::Memory(memory) if limited(memory))
        })
}

pub(super) fn retain_xor_messages(
    case: &mut Case,
    input_node: u64,
    projections: &[PacketProjection],
    report: &XorProposalReport,
    report_bytes: &[u8],
    limits: derivation::DerivationLimits,
    lease: &mut l2_workbench::job::MemoryLease,
) -> Result<(), RecoveryExecutionError> {
    let report_node = case.add_bytes_node(
        "recovery_xor_proposal_report", report_bytes, Vec::new(),
        json!({"representation":"json_blob","version":XOR_PROPOSAL_FORMAT_VERSION,"input_node_id":input_node,"proposal_count":report.proposals.len(),"search_truncated":report.search_truncated,"sample_truncated":report.sample_truncated,"omitted_candidates":report.omitted_candidates}),
    )?;
    add_transaction_edge(
        case,
        Edge {
            from: report_node,
            to: input_node,
            relation: "tested_input".to_owned(),
            status: EvidenceStatus::Hypothesis,
            reason: "Text structure supports provisional XOR hypotheses for this source run"
                .to_owned(),
        },
    )?;
    for (proposal_index, proposal) in report.proposals.iter().enumerate() {
        let before_output = lease.bytes();
        let input = case
            .node(input_node)
            .and_then(|node| node.blob.as_deref())
            .and_then(|id| case.blob(id))
            .ok_or(RecoveryError::InvariantFailure)?;
        let output = derivation::run_with_memory(&input.bytes, &proposal.recipe, limits, lease)
            .map_err(|source| RecoveryExecutionError::Operational {
                stage: RecoveryStage::Transform,
                source: Box::new(source),
            })?;
        if output.status != DerivationStatus::Completed {
            return Err(RecoveryError::InvariantFailure.into());
        }
        let context = ObservationContext {
            input_node,
            report_node,
            proposal_index,
        };
        for projection in projections {
            let raw = output
                .output
                .get(projection.start..projection.end)
                .ok_or(RecoveryError::InvariantFailure)?;
            retain_observation(case, &context, projection, raw, lease)?;
        }
        drop(output);
        resize_lease(lease, before_output)?;
    }
    Ok(())
}

struct ObservationContext {
    input_node: u64,
    report_node: u64,
    proposal_index: usize,
}

fn retain_observation(
    case: &mut Case,
    context: &ObservationContext,
    projection: &PacketProjection,
    raw: &[u8],
    lease: &mut l2_workbench::job::MemoryLease,
) -> Result<(), RecoveryExecutionError> {
    let before = lease.bytes();
    let normalized = derivation::normalize_message_with_memory(raw, lease).map_err(|source| {
        RecoveryExecutionError::Operational {
            stage: RecoveryStage::Transform,
            source: Box::new(source),
        }
    })?;
    let raw_node = case.add_bytes_node("recovered_message", raw, projection.ranges.clone(), json!({
        "source_run_node_id":context.input_node, "proposal_report_node_id":context.report_node,
        "proposal_index":context.proposal_index,"stream_start":projection.start,"stream_end":projection.end,
        "boundary_basis":"source_packet_range", "message_boundary_established":false,
        "interpretation":"provisional XOR hypothesis"
    }))?;
    for (target, relation, reason) in [
        (
            context.report_node,
            "proposed_by",
            "The report records the candidate used for these packet-supported bytes",
        ),
        (
            context.input_node,
            "derived_from",
            "The decoded range comes from this run under a provisional XOR hypothesis",
        ),
    ] {
        add_transaction_edge(
            case,
            Edge {
                from: raw_node,
                to: target,
                relation: relation.to_owned(),
                status: EvidenceStatus::Hypothesis,
                reason: reason.to_owned(),
            },
        )?;
    }
    let normalized_node = case.add_bytes_node(
        "normalized_message",
        &normalized,
        projection.ranges.clone(),
        json!({
            "raw_node_id":raw_node,"operations":["remove_carriage_returns","decode_html_entities"],
            "boundary_basis":"source_packet_range","message_boundary_established":false,
            "interpretation":"provisional XOR hypothesis"
        }),
    )?;
    add_transaction_edge(case, Edge { from: normalized_node, to: raw_node, relation: "derived_from".to_owned(),
        status: EvidenceStatus::Observed, reason: "Carriage returns and supported HTML references were normalized from these raw bytes".to_owned() })?;
    retain_message_bytes(case, raw, &normalized, raw_node, normalized_node, lease)?;
    // Release the temporary output charge only after its buffer is gone
    drop(normalized);
    resize_lease(lease, before)
}

fn retain_message_bytes(
    case: &mut Case,
    raw: &[u8],
    normalized: &[u8],
    raw_node: u64,
    normalized_node: u64,
    lease: &mut l2_workbench::job::MemoryLease,
) -> Result<(), RecoveryExecutionError> {
    let before = lease.bytes();
    let receipt_bytes = serialize_message_bytes(raw, normalized, lease)?;
    let bytes_node = case.add_bytes_node("recovered_message_bytes", &receipt_bytes, Vec::new(), json!({
        "representation":"json_blob", "raw_node_id":raw_node, "normalized_node_id":normalized_node
    }))?;
    for target in [raw_node, normalized_node] {
        add_transaction_edge(
            case,
            Edge {
                from: bytes_node,
                to: target,
                relation: "represents".to_owned(),
                status: EvidenceStatus::Observed,
                reason: "This bounded receipt retains the exact bytes of the linked observation"
                    .to_owned(),
            },
        )?;
    }
    drop(receipt_bytes);
    resize_lease(lease, before)
}

#[derive(serde::Serialize)]
struct MessageBytes<'a> {
    raw_bytes: &'a [u8],
    normalized_bytes: &'a [u8],
}

fn resize_lease(
    lease: &mut l2_workbench::job::MemoryLease,
    bytes: u64,
) -> Result<(), RecoveryExecutionError> {
    lease
        .try_resize(bytes)
        .map_err(|source| RecoveryExecutionError::Operational {
            stage: RecoveryStage::Transform,
            source: Box::new(source),
        })
}

pub(super) fn serialize_message_bytes(
    raw: &[u8],
    normalized: &[u8],
    lease: &mut l2_workbench::job::MemoryLease,
) -> Result<Vec<u8>, RecoveryExecutionError> {
    // Each JSON byte takes at most three digits and one comma
    let capacity = raw
        .len()
        .checked_add(normalized.len())
        .and_then(|length| length.checked_mul(4))
        .and_then(|length| length.checked_add(128))
        .ok_or(RecoveryError::InvariantFailure)?;
    let before = lease.bytes();
    let requested = u64::try_from(capacity).map_err(|_| RecoveryError::InvariantFailure)?;
    resize_lease(
        lease,
        before
            .checked_add(requested)
            .ok_or(RecoveryError::InvariantFailure)?,
    )?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|source| RecoveryExecutionError::Operational {
            stage: RecoveryStage::Transform,
            source: Box::new(source),
        })?;
    let actual = u64::try_from(bytes.capacity()).map_err(|_| RecoveryError::InvariantFailure)?;
    resize_lease(
        lease,
        before
            .checked_add(actual)
            .ok_or(RecoveryError::InvariantFailure)?,
    )?;
    serde_json::to_writer(
        &mut bytes,
        &MessageBytes {
            raw_bytes: raw,
            normalized_bytes: normalized,
        },
    )
    .map_err(|source| RecoveryExecutionError::Operational {
        stage: RecoveryStage::Transform,
        source: Box::new(source),
    })?;
    if bytes.len() > capacity {
        return Err(RecoveryError::InvariantFailure.into());
    }
    Ok(bytes)
}
