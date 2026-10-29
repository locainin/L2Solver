use super::super::records as record_service;
use super::evidence::{add_transaction_edge, add_transaction_links, case_evidence_quota};
use super::{
    DERIVED_REASON, Executor, RECORD_SCHEMA_SELECTED_FROM_REASON, RecoveryCandidateId,
    RecoveryExecutionError, RecoveryOmission, RecoveryStage, RecoveryTask,
};
use crate::arguments::RecordCountSource;
use l2_workbench::{
    evidence::{Case, Edge, EvidenceError, EvidenceStatus},
    protocol::{RecordError, RecordSchema},
    recovery::{RecoveryError, RecoveryResource, RecoveryResult},
};
use serde_json::json;
use std::error::Error;

pub(super) fn discovered_record_task_allowed(
    kind: &str,
    details: &serde_json::Value,
    task: &RecoveryTask,
) -> bool {
    if kind != "record_candidate" || !matches!(task, RecoveryTask::TransformDiscovery) {
        return true;
    }

    // One observed record cannot corroborate an inferred grouping relationship
    details
        .get("record_count")
        .and_then(serde_json::Value::as_u64)
        .is_some_and(|record_count| record_count > 1)
}

#[derive(Clone, Copy)]
struct RecordPrepareContext<'a> {
    candidate_id: RecoveryCandidateId,
    input_node_ids: &'a [u64],
    origins: &'a [u64],
    schema: &'a RecordSchema,
    remaining_work: usize,
    report_work_limited: bool,
}

struct RecordCommitArtifacts {
    recovery: record_service::service::RecoveryRecordServiceOutcome,
    children: Vec<u64>,
    derived: bool,
    receipt_node_id: u64,
}

impl Executor<'_> {
    pub(super) fn execute_record_candidate(
        &mut self,
        candidate_id: RecoveryCandidateId,
        candidate: &l2_workbench::recovery::RecoveryCandidate,
        schema: &RecordSchema,
    ) -> Result<(), RecoveryExecutionError> {
        let mut input_node_ids = Vec::new();
        let mut origin_node_ids = Vec::new();
        for input in candidate.inputs() {
            let input_node_id = input
                .origin_node_ids()
                .first()
                .copied()
                .ok_or(RecoveryError::InvariantFailure)?;
            input_node_ids.push(input_node_id);
            origin_node_ids.extend_from_slice(input.origin_node_ids());
        }
        let input_length = self
            .coordinator
            .input_blobs(self.case, candidate_id)?
            .iter()
            .try_fold(0_usize, |total, blob| total.checked_add(blob.bytes.len()))
            .ok_or_else(|| {
                RecoveryExecutionError::InvalidPolicy(
                    "record batch input length overflowed".to_owned(),
                )
            })?;
        let task = RecoveryTask::AssembleRecords(schema.clone());
        if !self.charge_work(candidate_id, &task, &origin_node_ids, input_length)? {
            return Ok(());
        }
        if input_length > self.policy.record_limits.max_input_bytes {
            let resource = RecoveryResource::TotalInputBytes;
            let limit = self.policy.record_limits.max_input_bytes;
            let requested = input_length;
            self.omissions.push(RecoveryOmission::ResourceExhausted {
                task,
                input_node_ids: origin_node_ids,
                resource,
                limit,
                used: 0,
                requested,
            });
            return self.finish(
                candidate_id,
                RecoveryResult::ResourceExhausted {
                    resource,
                    limit,
                    used: 0,
                    requested,
                },
            );
        }
        self.run_records(candidate_id, &input_node_ids, &origin_node_ids, schema)
    }

    fn run_records(
        &mut self,
        candidate_id: RecoveryCandidateId,
        input_node_ids: &[u64],
        origins: &[u64],
        schema: &RecordSchema,
    ) -> Result<(), RecoveryExecutionError> {
        let Some(prepared) = self.prepare_records(candidate_id, input_node_ids, origins, schema)?
        else {
            return Ok(());
        };
        let retained_output_bytes = prepared.retained_output_bytes().map_err(|source| {
            RecoveryExecutionError::Operational {
                stage: RecoveryStage::AssembleRecords,
                source: Box::new(source),
            }
        })?;
        let task = RecoveryTask::AssembleRecords(schema.clone());
        if !self.check_output(candidate_id, &task, origins, retained_output_bytes)? {
            return Ok(());
        }
        if !self.charge_work(candidate_id, &task, origins, retained_output_bytes)? {
            return Ok(());
        }
        self.commit_records(candidate_id, input_node_ids, origins, schema, prepared)
    }

    fn prepare_records(
        &mut self,
        candidate_id: RecoveryCandidateId,
        input_node_ids: &[u64],
        origins: &[u64],
        schema: &RecordSchema,
    ) -> Result<Option<record_service::service::PreparedRecordService>, RecoveryExecutionError>
    {
        let remaining_work = self.coordinator.remaining_work_bytes();
        if remaining_work == 0 {
            let resource = RecoveryResource::WorkBytes;
            let limit = self.policy.resources.max_work_bytes;
            let used = self.coordinator.work_bytes_charged();
            self.omissions.push(RecoveryOmission::ResourceExhausted {
                task: RecoveryTask::AssembleRecords(schema.clone()),
                input_node_ids: origins.to_vec(),
                resource,
                limit,
                used,
                requested: 1,
            });
            self.finish(
                candidate_id,
                RecoveryResult::ResourceExhausted {
                    resource,
                    limit,
                    used,
                    requested: 1,
                },
            )?;
            return Ok(None);
        }
        let mut record_limits = self.policy.record_limits;
        let report_work_limited = remaining_work < record_limits.max_report_bytes;
        record_limits.max_report_bytes = record_limits.max_report_bytes.min(remaining_work);
        let prepared = record_service::service::prepare_recovery(
            self.case,
            &record_service::service::RecordServiceInput {
                selected_node_ids: input_node_ids,
                count_sources: None::<&[RecordCountSource]>,
                schema,
                limits: record_limits,
            },
        );
        match prepared {
            Ok(prepared) => Ok(Some(prepared)),
            Err(error) => self.handle_record_prepare_error(
                RecordPrepareContext {
                    candidate_id,
                    input_node_ids,
                    origins,
                    schema,
                    remaining_work,
                    report_work_limited,
                },
                error,
            ),
        }
    }

    fn handle_record_prepare_error(
        &mut self,
        context: RecordPrepareContext<'_>,
        error: Box<dyn Error>,
    ) -> Result<Option<record_service::service::PreparedRecordService>, RecoveryExecutionError>
    {
        let RecordPrepareContext {
            candidate_id,
            input_node_ids,
            origins,
            schema,
            remaining_work,
            report_work_limited,
        } = context;
        if report_work_limited
            && let Some(RecordError::ReportTooLarge { bytes, .. }) =
                error.downcast_ref::<RecordError>()
        {
            let requested = *bytes;
            if !self.charge_work(
                candidate_id,
                &RecoveryTask::AssembleRecords(schema.clone()),
                origins,
                remaining_work.min(requested),
            )? {
                return Ok(None);
            }
            let resource = RecoveryResource::WorkBytes;
            let limit = self.policy.resources.max_work_bytes;
            let used = self.coordinator.work_bytes_charged();
            let additional = requested.saturating_sub(remaining_work);
            self.omissions.push(RecoveryOmission::ResourceExhausted {
                task: RecoveryTask::AssembleRecords(schema.clone()),
                input_node_ids: origins.to_vec(),
                resource,
                limit,
                used,
                requested: additional,
            });
            self.finish(
                candidate_id,
                RecoveryResult::ResourceExhausted {
                    resource,
                    limit,
                    used,
                    requested: additional,
                },
            )?;
            return Ok(None);
        }
        if let Some(RecordError::OutputTooLarge { length, maximum }) =
            error.downcast_ref::<RecordError>()
            && *maximum == self.policy.resources.max_output_bytes
            && !self.check_output(
                candidate_id,
                &RecoveryTask::AssembleRecords(schema.clone()),
                origins,
                *length,
            )?
        {
            return Ok(None);
        }
        self.handle_record_error(candidate_id, input_node_ids, origins, error)?;
        Ok(None)
    }

    fn commit_records(
        &mut self,
        candidate_id: RecoveryCandidateId,
        input_node_ids: &[u64],
        origins: &[u64],
        schema: &RecordSchema,
        prepared: record_service::service::PreparedRecordService,
    ) -> Result<(), RecoveryExecutionError> {
        let parsed_record_count = prepared.parsed_record_count();
        let report_nodes = self
            .record_schema_report_links
            .get(&candidate_id)
            .map(|reports| reports.as_slice().to_vec())
            .unwrap_or_default();
        // Caller-supplied schemas keep the existing individual issue evidence
        let issues = if !report_nodes.is_empty() && !self.plan.record_schemas.contains(schema) {
            record_service::service::RecordGroupIssues::Receipt
        } else {
            record_service::service::RecordGroupIssues::Individual
        };
        let committed = match self.commit_record_artifacts(
            candidate_id,
            input_node_ids,
            origins,
            &report_nodes,
            prepared,
            issues,
        ) {
            Ok(committed) => committed,
            Err(RecoveryExecutionError::Evidence(evidence_error)) => {
                let Some((resource, limit, used)) = case_evidence_quota(self.case, &evidence_error)
                else {
                    return Err(RecoveryExecutionError::Evidence(evidence_error));
                };
                self.finish_record_quota(candidate_id, schema, origins, resource, limit, used)?;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if let Some(progress) = &self.job {
            progress.parsed_records_committed(parsed_record_count)?;
            progress.record_input_applications_committed(input_node_ids.len())?;
        }
        if let Some(links) = self.record_schema_report_links.get_mut(&candidate_id) {
            links.mark_linked(committed.receipt_node_id);
        }
        for rejected in committed.recovery.rejected_inputs {
            self.omissions.push(RecoveryOmission::RecordInputRejected {
                input_index: rejected.input_index,
                input_node_id: rejected.input_node_id,
                error: rejected.error,
            });
        }
        if committed.derived {
            if report_nodes.is_empty() {
                self.enqueue_derived_children(candidate_id, &committed.children, false)?;
            } else {
                self.enqueue_discovered_record_children(candidate_id, &committed.children)?;
            }
        }
        Ok(())
    }

    fn commit_record_artifacts(
        &mut self,
        candidate_id: RecoveryCandidateId,
        input_node_ids: &[u64],
        origins: &[u64],
        report_nodes: &[u64],
        prepared: record_service::service::PreparedRecordService,
        issues: record_service::service::RecordGroupIssues,
    ) -> Result<RecordCommitArtifacts, RecoveryExecutionError> {
        self.case_transaction_and_finish(candidate_id, |case| {
            let recovery_outcome = record_service::service::commit_recovery(case, prepared, issues)
                .map_err(map_record_commit_error)?;
            let outcome = &recovery_outcome.outcome;
            let rejected_inputs = &recovery_outcome.rejected_inputs;
            let receipt_node_id = outcome.receipt_node_id;
            add_transaction_links(
                case,
                receipt_node_id,
                origins,
                "record_assembly",
                EvidenceStatus::Observed,
                "The receipt records the exact supplied schema, input digest, and assembly result",
            )?;
            for report_node_id in report_nodes {
                add_transaction_edge(
                    case,
                    Edge {
                        from: *report_node_id,
                        to: receipt_node_id,
                        relation: "record_schema_selected_from".to_owned(),
                        status: EvidenceStatus::Unresolved,
                        reason: RECORD_SCHEMA_SELECTED_FROM_REASON.to_owned(),
                    },
                )?;
            }
            for rejected in rejected_inputs {
                let selected_input = input_node_ids
                    .get(rejected.input_index)
                    .copied()
                    .ok_or(RecoveryError::InvariantFailure)?;
                if selected_input != rejected.input_node_id {
                    return Err(RecoveryError::InvariantFailure.into());
                }
            }
            let derived =
                rejected_inputs.is_empty() || rejected_inputs.len() != input_node_ids.len();
            let children = if derived {
                record_children(case, &outcome.group_node_ids)
            } else {
                Vec::new()
            };
            for child in &children {
                super::evidence::add_transaction_edge(
                    case,
                    l2_workbench::evidence::Edge {
                        from: *child,
                        to: receipt_node_id,
                        relation: "derived_from".to_owned(),
                        status: EvidenceStatus::Observed,
                        reason: DERIVED_REASON.to_owned(),
                    },
                )?;
            }
            let result = if derived {
                RecoveryResult::Derived {
                    evidence_node_id: receipt_node_id,
                }
            } else {
                RecoveryResult::Rejected {
                    node_id: receipt_node_id,
                }
            };
            Ok((
                RecordCommitArtifacts {
                    recovery: recovery_outcome,
                    children,
                    derived,
                    receipt_node_id,
                },
                result,
            ))
        })
    }

    fn finish_record_quota(
        &mut self,
        candidate_id: RecoveryCandidateId,
        schema: &RecordSchema,
        origins: &[u64],
        resource: RecoveryResource,
        limit: usize,
        used: usize,
    ) -> Result<(), RecoveryExecutionError> {
        let task = RecoveryTask::AssembleRecords(schema.clone());
        self.omissions.push(RecoveryOmission::ResourceExhausted {
            task,
            input_node_ids: origins.to_vec(),
            resource,
            limit,
            used,
            requested: 1,
        });
        self.finish(
            candidate_id,
            RecoveryResult::ResourceExhausted {
                resource,
                limit,
                used,
                requested: 1,
            },
        )
    }

    fn handle_record_error(
        &mut self,
        candidate_id: RecoveryCandidateId,
        input_node_ids: &[u64],
        origins: &[u64],
        error: Box<dyn Error>,
    ) -> Result<(), RecoveryExecutionError> {
        let Some(record_error) = error.downcast_ref::<RecordError>().cloned() else {
            return Err(RecoveryExecutionError::Operational {
                stage: RecoveryStage::AssembleRecords,
                source: error,
            });
        };
        match record_error {
            RecordError::TruncatedPreamble { .. }
            | RecordError::TruncatedRecord { .. }
            | RecordError::InvalidRecordLength { .. }
            | RecordError::LengthOverflow { .. }
            | RecordError::TrailingBytes { .. } => {
                let details =
                    json!({"input_nodes":input_node_ids,"reason":format!("{record_error:?}")});
                let receipt_bytes = serde_json::to_vec(&details).map_err(|source| {
                    RecoveryExecutionError::Operational {
                        stage: RecoveryStage::AssembleRecords,
                        source: Box::new(source),
                    }
                })?;
                self.case_transaction_and_finish(candidate_id, |case| {
                    let issue = case.add_bytes_node(
                        "record_schema_rejected",
                        &receipt_bytes,
                        Vec::new(),
                        details,
                    )?;
                    add_transaction_links(
                        case,
                        issue,
                        origins,
                        "record_parse_rejected",
                        EvidenceStatus::ConstraintFailed,
                        "The strict record parser found bytes that contradict the exact supplied schema",
                    )?;
                    Ok(((), RecoveryResult::Rejected { node_id: issue }))
                })
            }
            RecordError::InputTooLarge { .. }
            | RecordError::IdentifierTooLarge { .. }
            | RecordError::TooManyRecords { .. }
            | RecordError::ReportTooLarge { .. }
            | RecordError::TooManyGroups { .. }
            | RecordError::OutputTooLarge { .. }
            | RecordError::AllocationFailed => {
                self.omissions.push(RecoveryOmission::RecordService {
                    input_node_ids: input_node_ids.to_vec(),
                    error: record_error,
                });
                self.finish(candidate_id, RecoveryResult::Omitted)
            }
            other => Err(RecoveryExecutionError::Operational {
                stage: RecoveryStage::AssembleRecords,
                source: Box::new(other),
            }),
        }
    }
}

fn map_record_commit_error(source: Box<dyn Error>) -> RecoveryExecutionError {
    match source.downcast::<EvidenceError>() {
        Ok(error) => RecoveryExecutionError::Evidence(*error),
        Err(source) => RecoveryExecutionError::Operational {
            stage: RecoveryStage::AssembleRecords,
            source,
        },
    }
}

fn record_children(case: &Case, group_node_ids: &[u64]) -> Vec<u64> {
    group_node_ids
        .iter()
        .copied()
        .filter(|node_id| {
            case.node(*node_id).is_some_and(|node| {
                matches!(node.kind.as_str(), "record_object" | "record_candidate")
            })
        })
        .collect()
}

#[cfg(test)]
#[path = "../../../tests/workbench/recovery_executor_records.rs"]
mod tests;
