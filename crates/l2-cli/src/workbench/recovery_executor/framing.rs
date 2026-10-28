use super::super::framing_materialize::{self, FramingSelectionBasis, PreparedFraming};
use super::derived_discovery::MaterializedFrameRegistration;
use super::evidence::{add_transaction_edge, add_transaction_links};
use super::{
    DERIVED_REASON, Executor, RecoveryCandidateId, RecoveryExecutionError, RecoveryOmission,
    RecoveryStage, RecoveryTask,
};
use l2_workbench::{
    evidence::{EvidenceError, EvidenceStatus},
    protocol::FramingKind,
    recovery::{RecoveryResource, RecoveryResult},
};
use std::error::Error;

impl Executor<'_> {
    pub(super) fn run_framing(
        &mut self,
        candidate_id: RecoveryCandidateId,
        input_node: u64,
        origins: &[u64],
        rule: &FramingKind,
        basis: FramingSelectionBasis,
    ) -> Result<(), RecoveryExecutionError> {
        let input_kind = self.node_kind(input_node)?.to_owned();
        let derived_input =
            input_kind == "decoding_output" && self.derived_discovery.has_context(input_node);
        if input_kind != "tcp_byte_run" && !derived_input {
            return self.finish(candidate_id, RecoveryResult::Unsupported);
        }
        let Some(prepared) =
            self.prepare_framing(candidate_id, input_node, origins, rule, basis)?
        else {
            return Ok(());
        };
        let materialized = match self.commit_framing(candidate_id, origins, prepared) {
            Ok(materialized) => materialized,
            Err(RecoveryExecutionError::Evidence(EvidenceError::QuotaExceeded {
                field,
                maximum,
            })) => return self.finish_framing_quota(candidate_id, origins, rule, field, maximum),
            Err(error) => return Err(error),
        };
        if derived_input {
            self.derived_discovery.register_materialized_frames(
                self.case,
                MaterializedFrameRegistration {
                    input_node,
                    receipt_node: materialized.2,
                    frame_node_ids: &materialized.0,
                    rule,
                    parent: candidate_id,
                    discover_records: self.plan.discover_records,
                    maximum_contexts: self.policy.resources.max_context_aliases,
                },
            )?;
            self.omissions
                .extend(self.derived_discovery.take_omissions()?);
        }
        self.enqueue_framed_children(candidate_id, &materialized.0, materialized.1)
    }

    fn prepare_framing(
        &mut self,
        candidate_id: RecoveryCandidateId,
        input_node: u64,
        origins: &[u64],
        rule: &FramingKind,
        basis: FramingSelectionBasis,
    ) -> Result<Option<PreparedFraming>, RecoveryExecutionError> {
        let prepared =
            framing_materialize::prepare_recovery_with_basis(self.case, input_node, rule, basis)
                .map_err(|source| RecoveryExecutionError::Operational {
                    stage: RecoveryStage::MaterializeFraming,
                    source,
                })?;
        let task = RecoveryTask::MaterializeFraming(rule.clone());
        if !self.check_output(candidate_id, &task, origins, prepared.output_bytes())? {
            return Ok(None);
        }
        let materialization_work = self.node_bytes(input_node)?.len();
        if !self.charge_work(candidate_id, &task, origins, materialization_work)? {
            return Ok(None);
        }
        Ok(Some(prepared))
    }

    fn commit_framing(
        &mut self,
        candidate_id: RecoveryCandidateId,
        origins: &[u64],
        prepared: PreparedFraming,
    ) -> Result<(Vec<u64>, Option<u64>, u64), RecoveryExecutionError> {
        self.case_transaction_and_finish(candidate_id, |case| {
            let outcome = framing_materialize::commit_recovery(case, prepared)
                .map_err(framing_materialization_error)?;
            add_transaction_links(
                case,
                outcome.receipt_node,
                origins,
                "framing_execution",
                EvidenceStatus::Observed,
                "The receipt records the exact selected framing rule and its byte ranges",
            )?;
            let mut outputs = outcome.frame_nodes.clone();
            outputs.extend(outcome.tail_node);
            for frame_node in outputs {
                add_transaction_edge(
                    case,
                    l2_workbench::evidence::Edge {
                        from: frame_node,
                        to: outcome.receipt_node,
                        relation: "derived_from".to_owned(),
                        status: EvidenceStatus::Observed,
                        reason: DERIVED_REASON.to_owned(),
                    },
                )?;
            }
            let receipt_node = outcome.receipt_node;
            Ok((
                (outcome.frame_nodes, outcome.tail_node, receipt_node),
                RecoveryResult::Derived {
                    evidence_node_id: receipt_node,
                },
            ))
        })
    }

    fn finish_framing_quota(
        &mut self,
        candidate_id: RecoveryCandidateId,
        origins: &[u64],
        rule: &FramingKind,
        field: &'static str,
        maximum: usize,
    ) -> Result<(), RecoveryExecutionError> {
        let resource = match field {
            "edges" => RecoveryResource::EvidenceEdges,
            "nodes" => RecoveryResource::EvidenceNodes,
            _ => {
                return Err(RecoveryExecutionError::Evidence(
                    EvidenceError::QuotaExceeded { field, maximum },
                ));
            }
        };
        // Case rejects the next single item only after its resource reaches the ceiling
        let used = maximum;
        let requested = 1;
        self.omissions.push(RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::MaterializeFraming(rule.clone()),
            input_node_ids: origins.to_vec(),
            resource,
            limit: maximum,
            used,
            requested,
        });
        self.finish(
            candidate_id,
            RecoveryResult::ResourceExhausted {
                resource,
                limit: maximum,
                used,
                requested,
            },
        )
    }
}

fn framing_materialization_error(source: Box<dyn Error>) -> RecoveryExecutionError {
    match source.downcast::<EvidenceError>() {
        Ok(source) => RecoveryExecutionError::Evidence(*source),
        Err(source) => RecoveryExecutionError::Operational {
            stage: RecoveryStage::MaterializeFraming,
            source,
        },
    }
}
