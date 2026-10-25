use super::super::decode;
use super::evidence::{add_transaction_edge, add_transaction_links, case_evidence_quota};
use super::{
    DERIVED_REASON, Executor, RecoveryCandidateId, RecoveryExecutionError, RecoveryOmission,
    RecoveryStage, RecoveryTask,
};
use l2_workbench::{
    derivation::Recipe,
    evidence::{EvidenceError, EvidenceStatus},
    recovery::{RecoveryError, RecoveryResource, RecoveryResult},
};
use serde_json::json;

struct PreparedTransform {
    prepared: decode::service::PreparedRecipe,
    item: decode::service::PreparedItemSummary,
    origins: Vec<u64>,
}

struct TransformCommit {
    result_node: u64,
    output_node: Option<u64>,
}

impl Executor<'_> {
    pub(super) fn run_transform(
        &mut self,
        candidate_id: RecoveryCandidateId,
        input_node: u64,
        recipe: &Recipe,
    ) -> Result<(), RecoveryExecutionError> {
        let Some(prepared) = self.prepare_transform(candidate_id, input_node, recipe)? else {
            return Ok(());
        };
        self.commit_transform(candidate_id, input_node, recipe, prepared)
    }

    fn prepare_transform(
        &mut self,
        candidate_id: RecoveryCandidateId,
        input_node: u64,
        recipe: &Recipe,
    ) -> Result<Option<PreparedTransform>, RecoveryExecutionError> {
        let input_length = self.node_bytes(input_node)?.len();
        let mut batch_limits = self.policy.decode_batch_limits;
        let available_work = input_length
            .checked_add(self.coordinator.remaining_work_bytes())
            .ok_or_else(|| {
                RecoveryExecutionError::InvalidPolicy(
                    "transform work allowance overflowed".to_owned(),
                )
            })?;
        batch_limits.total_work_bytes = batch_limits.total_work_bytes.min(available_work);
        let global_work_limited = available_work < self.policy.decode_batch_limits.total_work_bytes;
        let prepared = decode::service::prepare_recipe(
            self.case,
            &[input_node],
            recipe,
            self.policy.derivation_limits,
            batch_limits,
        )
        .map_err(|source| RecoveryExecutionError::Operational {
            stage: RecoveryStage::Transform,
            source,
        })?;
        let item = prepared.item(0).ok_or(RecoveryError::InvariantFailure)?;
        let origins = self.transform_origins(candidate_id)?;
        let additional_work = item.work_bytes.saturating_sub(input_length);
        if !self.charge_work(
            candidate_id,
            &RecoveryTask::Transform(recipe.clone()),
            &origins,
            additional_work,
        )? {
            return Ok(None);
        }
        if self.handle_transform_work_limit(
            candidate_id,
            recipe,
            &origins,
            item,
            batch_limits.total_work_bytes,
            global_work_limited,
        )? {
            return Ok(None);
        }
        if self.handle_transform_output_limit(candidate_id, recipe, &origins, item)? {
            return Ok(None);
        }
        Ok(Some(PreparedTransform {
            prepared,
            item,
            origins,
        }))
    }

    fn transform_origins(
        &self,
        candidate_id: RecoveryCandidateId,
    ) -> Result<Vec<u64>, RecoveryExecutionError> {
        let candidate = self
            .coordinator
            .candidate(candidate_id)
            .ok_or(RecoveryError::UnknownCandidate { id: candidate_id })?;
        candidate
            .inputs()
            .first()
            .map(|input| input.origin_node_ids().to_vec())
            .ok_or_else(|| RecoveryError::InvariantFailure.into())
    }

    fn handle_transform_work_limit(
        &mut self,
        candidate_id: RecoveryCandidateId,
        recipe: &Recipe,
        origins: &[u64],
        item: decode::service::PreparedItemSummary,
        work_limit: usize,
        global_work_limited: bool,
    ) -> Result<bool, RecoveryExecutionError> {
        if !item.work_budget_exhausted {
            return Ok(false);
        }
        let task = RecoveryTask::Transform(recipe.clone());
        if global_work_limited {
            self.omissions.push(RecoveryOmission::ResourceExhausted {
                task,
                input_node_ids: origins.to_vec(),
                resource: RecoveryResource::WorkBytes,
                limit: self.policy.resources.max_work_bytes,
                used: self.coordinator.work_bytes_charged(),
                requested: self.policy.resources.max_work_bytes.saturating_add(1),
            });
        } else {
            self.omissions.push(RecoveryOmission::StageWorkLimit {
                task,
                input_node_ids: origins.to_vec(),
                limit: work_limit,
                work_bytes: item.work_bytes,
            });
        }
        self.finish(candidate_id, RecoveryResult::Omitted)?;
        Ok(true)
    }

    fn handle_transform_output_limit(
        &mut self,
        candidate_id: RecoveryCandidateId,
        recipe: &Recipe,
        origins: &[u64],
        item: decode::service::PreparedItemSummary,
    ) -> Result<bool, RecoveryExecutionError> {
        let Some(limit) = item.output_limit_exceeded else {
            return Ok(false);
        };
        let task = RecoveryTask::Transform(recipe.clone());
        let requested = limit.saturating_add(1);
        if limit == self.policy.resources.max_output_bytes {
            if self.check_output(candidate_id, &task, origins, requested)? {
                return Err(RecoveryError::InvariantFailure.into());
            }
        } else {
            self.omissions.push(RecoveryOmission::StageOutputLimit {
                task,
                input_node_ids: origins.to_vec(),
                limit,
                requested,
            });
            self.finish(candidate_id, RecoveryResult::Omitted)?;
        }
        Ok(true)
    }

    fn commit_transform(
        &mut self,
        candidate_id: RecoveryCandidateId,
        input_node: u64,
        recipe: &Recipe,
        prepared: PreparedTransform,
    ) -> Result<(), RecoveryExecutionError> {
        let PreparedTransform {
            prepared,
            item: summary,
            origins,
        } = prepared;
        let item_state = summary.state;
        let commit_result = self.case_transaction_and_finish(candidate_id, |case, identities| {
            let outcome =
                decode::service::commit_prepared_recipe(case, prepared).map_err(|source| {
                    RecoveryExecutionError::Operational {
                        stage: RecoveryStage::Transform,
                        source,
                    }
                })?;
            let item = outcome
                .created_nodes
                .first()
                .ok_or(RecoveryError::InvariantFailure)?;
            transform_result(
                case, identities, item, item_state, input_node, recipe, &origins,
            )
        });
        let commit = match commit_result {
            Ok(commit) => commit,
            Err(error) => {
                let quota = if self.is_speculative_transform(candidate_id, recipe) {
                    transform_case_quota(self.case, &error)
                } else {
                    None
                };
                let Some((resource, limit, used)) = quota else {
                    return Err(error);
                };
                return self.finish_transform_quota(
                    candidate_id,
                    recipe,
                    &origins,
                    resource,
                    limit,
                    used,
                );
            }
        };
        self.link_transform_proposals(candidate_id, commit.result_node)?;
        if let Some(output_node) = commit.output_node {
            let is_cohort_slot = self.transform_cohorts.iter().any(|cohort| {
                cohort
                    .slots
                    .iter()
                    .any(|slot| slot.candidate == candidate_id)
            });
            self.enqueue_derived_children_filtered(
                candidate_id,
                &[output_node],
                false,
                is_cohort_slot,
            )?;
        }
        Ok(())
    }

    fn is_speculative_transform(&self, candidate_id: RecoveryCandidateId, recipe: &Recipe) -> bool {
        self.transform_proposal_receipts.contains_key(&candidate_id)
            && !self.plan.recipes.contains(recipe)
    }

    fn finish_transform_quota(
        &mut self,
        candidate_id: RecoveryCandidateId,
        recipe: &Recipe,
        origins: &[u64],
        resource: RecoveryResource,
        limit: usize,
        used: usize,
    ) -> Result<(), RecoveryExecutionError> {
        let requested = 1;
        self.finish(
            candidate_id,
            RecoveryResult::ResourceExhausted {
                resource,
                limit,
                used,
                requested,
            },
        )?;
        self.omissions.push(RecoveryOmission::ResourceExhausted {
            task: RecoveryTask::Transform(recipe.clone()),
            input_node_ids: origins.to_vec(),
            resource,
            limit,
            used,
            requested,
        });
        Ok(())
    }
}

pub(super) fn transform_case_quota(
    case: &l2_workbench::evidence::Case,
    error: &RecoveryExecutionError,
) -> Option<(RecoveryResource, usize, usize)> {
    let evidence_error = match error {
        RecoveryExecutionError::Evidence(error) => error,
        RecoveryExecutionError::Operational {
            stage: RecoveryStage::Transform,
            source,
        } => source.downcast_ref::<EvidenceError>()?,
        _ => return None,
    };
    case_evidence_quota(case, evidence_error)
}

fn transform_result(
    case: &mut l2_workbench::evidence::Case,
    identities: &mut super::evidence::TransactionEdges<'_>,
    item: &decode::service::DecodeCreatedNodes,
    state: decode::service::DecodeItemState,
    input_node: u64,
    recipe: &Recipe,
    origins: &[u64],
) -> Result<(TransformCommit, RecoveryResult), RecoveryExecutionError> {
    match state {
        decode::service::DecodeItemState::Completed => {
            completed_transform(case, identities, item, recipe, origins)
        }
        decode::service::DecodeItemState::Rejected => {
            rejected_transform(case, identities, item.receipt_node, origins)
        }
        decode::service::DecodeItemState::Failed => {
            failed_transform(case, identities, item.receipt_node, input_node, origins)
        }
    }
}

fn completed_transform(
    case: &mut l2_workbench::evidence::Case,
    identities: &mut super::evidence::TransactionEdges<'_>,
    item: &decode::service::DecodeCreatedNodes,
    recipe: &Recipe,
    origins: &[u64],
) -> Result<(TransformCommit, RecoveryResult), RecoveryExecutionError> {
    let status = if recipe.constraints.is_empty() {
        EvidenceStatus::Observed
    } else {
        EvidenceStatus::ConstraintSatisfied
    };
    add_transaction_links(
        case,
        identities,
        item.receipt_node,
        origins,
        "decoding_result",
        status,
        DERIVED_REASON,
    )?;
    add_transaction_edge(
        case,
        identities,
        l2_workbench::evidence::Edge {
            from: item.output_node,
            to: item.receipt_node,
            relation: "derived_from".to_owned(),
            status: EvidenceStatus::Observed,
            reason: DERIVED_REASON.to_owned(),
        },
    )?;
    Ok((
        TransformCommit {
            result_node: item.receipt_node,
            output_node: Some(item.output_node),
        },
        RecoveryResult::Derived {
            evidence_node_id: item.receipt_node,
        },
    ))
}

fn rejected_transform(
    case: &mut l2_workbench::evidence::Case,
    identities: &mut super::evidence::TransactionEdges<'_>,
    receipt_node: u64,
    origins: &[u64],
) -> Result<(TransformCommit, RecoveryResult), RecoveryExecutionError> {
    add_transaction_links(
        case,
        identities,
        receipt_node,
        origins,
        "decoding_rejected",
        EvidenceStatus::ConstraintFailed,
        "The explicit recipe constraints rejected this exact output candidate",
    )?;
    Ok((
        TransformCommit {
            result_node: receipt_node,
            output_node: None,
        },
        RecoveryResult::Rejected {
            node_id: receipt_node,
        },
    ))
}

fn failed_transform(
    case: &mut l2_workbench::evidence::Case,
    identities: &mut super::evidence::TransactionEdges<'_>,
    receipt_node: u64,
    input_node: u64,
    origins: &[u64],
) -> Result<(TransformCommit, RecoveryResult), RecoveryExecutionError> {
    let details = json!({
        "input_node":input_node,
        "receipt_node":receipt_node,
        "reason":"explicit recipe step failed"
    });
    let issue_bytes =
        serde_json::to_vec(&details).map_err(|source| RecoveryExecutionError::Operational {
            stage: RecoveryStage::Transform,
            source: Box::new(source),
        })?;
    let issue = case.add_bytes_node(
        "recovery_transform_rejected",
        &issue_bytes,
        Vec::new(),
        details,
    )?;
    add_transaction_links(
        case,
        identities,
        issue,
        origins,
        "rejected_by_transform",
        EvidenceStatus::ConstraintFailed,
        "The exact recipe could not produce a completed byte result for this input",
    )?;
    Ok((
        TransformCommit {
            result_node: issue,
            output_node: None,
        },
        RecoveryResult::Rejected { node_id: issue },
    ))
}
