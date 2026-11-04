//! Discover provisional decoded observations and preserve their source packets

mod mapping;
mod projection;
mod publication;

use mapping::ProjectionSet;
use projection::{PacketProjection, packet_projections};
#[cfg(test)]
use publication::serialize_message_bytes;
use publication::{EncodedReport, is_memory_limit, retain_xor_messages, serialized_report};

#[cfg(test)]
#[path = "../../../tests/workbench/recovery_xor_messages.rs"]
mod tests;

use super::{
    Executor, RecoveryCandidateId, RecoveryError, RecoveryExecutionError, RecoveryOmission,
    RecoveryStage, RecoveryTask,
};
use super::{checkpoint, evidence::case_evidence_quota};
use l2_workbench::{
    derivation,
    job::{MemoryBudget, MemoryClass, MemoryError, MemoryLease},
    recovery::xor::{
        XorProposalError, XorProposalReport, propose_xor_with_memory, xor_proposal_scan_work_bound,
    },
};

// Bound speculative output independently of other recovery lanes
pub(super) const MAX_XOR_INPUT_BYTES: usize = 64 * 1024;
pub(super) const MAX_PACKET_MAPPINGS: usize = 256;
pub(super) const MAX_PROJECTED_BYTES: usize = 256 * 1024;
// Copy, hash, transform, and hash the whole input once per hypothesis
pub(super) const XOR_INPUT_WORK_FACTOR: usize = 4;
// Cover byte receipts plus hashing and retaining the two source-linked outputs
pub(super) const XOR_PUBLICATION_WORK_FACTOR: usize = 28;
// Limit report output separately from admitted buffer capacity
const MAX_XOR_REPORT_BYTES: usize = 64 * 1024;

enum XorStage<T> {
    Ready(T),
    Skipped,
    Exhausted,
}

pub(super) enum XorDiscoveryOutcome {
    Retained,
    Skipped,
    Exhausted,
}

#[derive(Clone, Copy)]
struct XorRun {
    candidate: RecoveryCandidateId,
    input_node: u64,
    input_length: usize,
}

struct XorAnalysis {
    // Drop the proposal allocations before their admission
    report: XorProposalReport,
    lease: MemoryLease,
    memory: MemoryBudget,
}

impl Executor<'_> {
    /// Keep inferred keys local to this scheduler step and out of checkpoints
    pub(super) fn discover_xor_messages(
        &mut self,
        candidate: RecoveryCandidateId,
        input_node: u64,
        input_length: usize,
    ) -> Result<XorDiscoveryOutcome, RecoveryExecutionError> {
        let run = XorRun {
            candidate,
            input_node,
            input_length,
        };
        let mut analysis = match self.assess_xor_input(run)? {
            XorStage::Ready(value) => value,
            XorStage::Skipped => return Ok(XorDiscoveryOutcome::Skipped),
            XorStage::Exhausted => return Ok(XorDiscoveryOutcome::Exhausted),
        };
        let projections = match self.xor_projections(candidate, input_node, input_length)? {
            XorStage::Ready(value) => value,
            XorStage::Skipped => return Ok(XorDiscoveryOutcome::Skipped),
            XorStage::Exhausted => return Ok(XorDiscoveryOutcome::Exhausted),
        };
        match self.publish_xor(
            run,
            &analysis.report,
            &projections,
            &mut analysis.lease,
            &analysis.memory,
        )? {
            XorStage::Ready(()) => Ok(XorDiscoveryOutcome::Retained),
            XorStage::Skipped => Ok(XorDiscoveryOutcome::Skipped),
            XorStage::Exhausted => Ok(XorDiscoveryOutcome::Exhausted),
        }
    }

    fn assess_xor_input(
        &mut self,
        run: XorRun,
    ) -> Result<XorStage<XorAnalysis>, RecoveryExecutionError> {
        if !self.xor_input_eligible(run)? {
            return Ok(XorStage::Skipped);
        }
        let memory = self
            .memory
            .clone()
            .unwrap_or_else(|| MemoryBudget::new(u64::MAX));
        let mut lease = match memory.try_reserve(MemoryClass::Executor, 0) {
            Ok(lease) => lease,
            Err(MemoryError::Limit { .. } | MemoryError::Pressure { .. }) => {
                self.omit_xor_input(run.input_node, "xor_memory_limit", 1);
                return Ok(XorStage::Skipped);
            }
            Err(source) => {
                return Err(RecoveryExecutionError::Operational {
                    stage: RecoveryStage::TransformDiscovery,
                    source: Box::new(source),
                });
            }
        };
        let scan_work = xor_proposal_scan_work_bound(run.input_length)
            .ok_or(RecoveryError::InvariantFailure)?;
        if !self.charge_work(
            run.candidate,
            &RecoveryTask::TransformDiscovery,
            &[run.input_node],
            scan_work,
        )? {
            return Ok(XorStage::Exhausted);
        }
        let max_candidates = self
            .policy
            .transform_exploration
            .proposal_budget
            .max_candidates;
        let input = self.node_bytes(run.input_node)?;
        let report = match propose_xor_with_memory(input, max_candidates, &mut lease) {
            Ok(report) => report,
            Err(XorProposalError::Memory(
                MemoryError::Limit { .. } | MemoryError::Pressure { .. },
            )) => {
                self.omit_xor_input(run.input_node, "xor_memory_limit", 1);
                return Ok(XorStage::Skipped);
            }
            Err(source) => {
                return Err(RecoveryExecutionError::Operational {
                    stage: RecoveryStage::TransformDiscovery,
                    source: Box::new(source),
                });
            }
        };
        if report.omitted_candidates != 0 || report.sample_truncated || report.search_truncated {
            self.omissions.push(RecoveryOmission::XorSearchLimit {
                input_node_id: run.input_node,
                omitted_candidates: report.omitted_candidates,
                search_truncated: report.search_truncated,
                sample_truncated: report.sample_truncated,
            });
        }
        if report.proposals.is_empty() {
            return Ok(XorStage::Skipped);
        }
        Ok(XorStage::Ready(XorAnalysis {
            report,
            lease,
            memory,
        }))
    }

    fn xor_input_eligible(&mut self, run: XorRun) -> Result<bool, RecoveryExecutionError> {
        let node = self
            .case
            .node(run.input_node)
            .ok_or(RecoveryError::UnknownEvidenceNode {
                node_id: run.input_node,
            })?;
        if node.kind != "tcp_byte_run"
            || node
                .details
                .get("generation_ambiguous")
                .and_then(serde_json::Value::as_bool)
                == Some(true)
            || self
                .policy
                .framing_discovery_plan
                .as_ref()
                .is_some_and(|plan| {
                    plan.native_http_message_ranges(run.input_node)
                        .is_some_and(|ranges| !ranges.is_empty())
                })
            || xor_proposal_scan_work_bound(run.input_length)
                .ok_or(RecoveryError::InvariantFailure)?
                == 0
        {
            return Ok(false);
        }
        if run.input_length > MAX_XOR_INPUT_BYTES {
            self.omit_xor_input(run.input_node, "xor_input_limit", 1);
            return Ok(false);
        }
        let limits = self.policy.derivation_limits;
        if run.input_length > limits.max_input_bytes
            || run.input_length > limits.max_output_bytes
            || run.input_length > limits.max_intermediate_bytes
            || run
                .input_length
                .checked_mul(2)
                .is_none_or(|work| work > limits.max_work_bytes)
        {
            self.omit_xor_input(run.input_node, "xor_derivation_limit", 1);
            return Ok(false);
        }
        Ok(true)
    }

    fn publish_xor(
        &mut self,
        run: XorRun,
        report: &XorProposalReport,
        projections: &ProjectionSet,
        lease: &mut MemoryLease,
        memory: &MemoryBudget,
    ) -> Result<XorStage<()>, RecoveryExecutionError> {
        let execution_work = run
            .input_length
            .checked_mul(XOR_INPUT_WORK_FACTOR)
            .and_then(|work| {
                derivation::normalization_work_bound(projections.total_bytes)
                    .and_then(|normalization| work.checked_add(normalization))
            })
            .and_then(|work| {
                projections
                    .total_bytes
                    .checked_mul(XOR_PUBLICATION_WORK_FACTOR)
                    .and_then(|receipt| work.checked_add(receipt))
            })
            .and_then(|work| work.checked_mul(report.proposals.len()))
            .ok_or(RecoveryError::InvariantFailure)?;
        if !self.charge_work(
            run.candidate,
            &RecoveryTask::TransformDiscovery,
            &[run.input_node],
            execution_work,
        )? || !self.check_output(
            run.candidate,
            &RecoveryTask::TransformDiscovery,
            &[run.input_node],
            run.input_length,
        )? {
            return Ok(XorStage::Exhausted);
        }
        let encoded = match self.encode_xor_report(run.input_node, report, memory)? {
            XorStage::Ready(encoded) => encoded,
            XorStage::Skipped => return Ok(XorStage::Skipped),
            XorStage::Exhausted => return Ok(XorStage::Exhausted),
        };
        let limits = self.policy.derivation_limits;
        let result = self.case_transaction(|case| {
            retain_xor_messages(
                case,
                run.input_node,
                &projections.values,
                report,
                &encoded.bytes,
                limits,
                lease,
            )
        });
        match result {
            Ok(()) => Ok(XorStage::Ready(())),
            Err(error) => self.omit_xor_publication_error(run.input_node, error),
        }
    }

    fn encode_xor_report(
        &mut self,
        input_node: u64,
        report: &XorProposalReport,
        memory: &MemoryBudget,
    ) -> Result<XorStage<EncodedReport>, RecoveryExecutionError> {
        match serialized_report(report, memory, MAX_XOR_REPORT_BYTES) {
            Ok(encoded) => Ok(XorStage::Ready(encoded)),
            Err(error) if is_memory_limit(&error) => {
                self.omit_xor_input(input_node, "xor_report_memory_limit", 1);
                Ok(XorStage::Skipped)
            }
            Err(error) if checkpoint::unavailable_reason(&error).is_some() => {
                self.omit_xor_input(input_node, "xor_report_output_limit", 1);
                Ok(XorStage::Skipped)
            }
            Err(error) => Err(error),
        }
    }

    fn omit_xor_publication_error(
        &mut self,
        input_node: u64,
        error: RecoveryExecutionError,
    ) -> Result<XorStage<()>, RecoveryExecutionError> {
        if is_memory_limit(&error) {
            self.omit_xor_input(input_node, "xor_execution_memory_limit", 1);
            return Ok(XorStage::Skipped);
        }
        let RecoveryExecutionError::Evidence(source) = &error else {
            return Err(error);
        };
        let Some((resource, limit, used)) = case_evidence_quota(self.case, source) else {
            return Err(error);
        };
        self.omissions.push(RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::TransformDiscovery,
            input_node_ids: vec![input_node],
            resource,
            limit,
            used,
            requested: 1,
        });
        Ok(XorStage::Skipped)
    }

    fn omit_xor_input(&mut self, input_node: u64, reason: &'static str, count: usize) {
        self.omissions.push(RecoveryOmission::XorMessageOmission {
            input_node_id: input_node,
            omitted: count,
            reason: reason.into(),
        });
    }
}
