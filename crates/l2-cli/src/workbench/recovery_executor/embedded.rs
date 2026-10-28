use super::evidence::{add_transaction_edge, add_transaction_links, case_evidence_quota};
use super::{
    DERIVED_REASON, Executor, RecoveryCandidateId, RecoveryExecutionError, RecoveryOmission,
    RecoveryStage, RecoveryTask,
};
use l2_workbench::{
    artifact::{
        EmbeddedCandidate, EmbeddedDiscoveryOmissions, EmbeddedDiscoveryReport, EmbeddedFormat,
        EmbeddedValidationEvidence, EmbeddedValidationFailure, FileRange,
        discover_embedded_objects_with_work,
    },
    evidence::EvidenceStatus,
    recovery::{RecoveryError, RecoveryResult},
};
use serde_json::{Value, json};

type EmbeddedOutput = (Vec<u8>, EmbeddedFormat, FileRange);

struct PreparedEmbedded {
    input_node: u64,
    report: EmbeddedDiscoveryReport,
    validated_count: usize,
    outputs: Vec<EmbeddedOutput>,
}

impl Executor<'_> {
    pub(super) fn run_embedded(
        &mut self,
        candidate_id: RecoveryCandidateId,
        origins: &[u64],
    ) -> Result<(), RecoveryExecutionError> {
        let Some(prepared) = self.prepare_embedded(candidate_id, origins)? else {
            return Ok(());
        };
        let committed = self.commit_embedded(
            candidate_id,
            prepared.input_node,
            origins,
            &prepared.report,
            prepared.validated_count,
            prepared.outputs,
        );
        let (result, children) = match committed {
            Ok(committed) => committed,
            Err(error) => {
                self.finish_embedded_case_quota(candidate_id, origins, error)?;
                return Ok(());
            }
        };
        if matches!(&result, RecoveryResult::Derived { .. }) {
            self.enqueue_derived_children(candidate_id, &children, false)
        } else {
            Ok(())
        }
    }

    fn prepare_embedded(
        &mut self,
        candidate_id: RecoveryCandidateId,
        origins: &[u64],
    ) -> Result<Option<PreparedEmbedded>, RecoveryExecutionError> {
        let input_node = origins
            .first()
            .copied()
            .ok_or(RecoveryError::InvariantFailure)?;
        let input_length = self
            .coordinator
            .input_blob(self.case, candidate_id)?
            .bytes
            .len();
        let report = self.discover_embedded(candidate_id)?;
        let parser_work = report
            .validation_input_bytes
            .checked_add(report.zip_work_bytes)
            .ok_or_else(|| {
                RecoveryExecutionError::InvalidPolicy(
                    "embedded parser work count overflowed".to_owned(),
                )
            })?;
        if !self.charge_work(
            candidate_id,
            &RecoveryTask::EmbeddedDiscovery,
            origins,
            parser_work,
        )? {
            return Ok(None);
        }
        if report.omissions != EmbeddedDiscoveryOmissions::default() {
            self.omissions.push(RecoveryOmission::EmbeddedDiscovery {
                input_node_id: input_node,
                omissions: report.omissions,
            });
        }
        let validated = validated_candidates(&report);
        let validated_count = validated.len();
        let retained_children = retained_embedded_candidates(&validated, input_length);
        if !retained_children.is_empty()
            && !self.check_output(
                candidate_id,
                &RecoveryTask::EmbeddedDiscovery,
                origins,
                requested_embedded_output(&retained_children)?,
            )?
        {
            return Ok(None);
        }
        if report.candidates.is_empty() && report.omissions == EmbeddedDiscoveryOmissions::default()
        {
            self.finish(candidate_id, RecoveryResult::Unsupported)?;
            return Ok(None);
        }

        let outputs = self.copy_embedded_outputs(candidate_id, &retained_children)?;
        Ok(Some(PreparedEmbedded {
            input_node,
            report,
            validated_count,
            outputs,
        }))
    }

    fn finish_embedded_case_quota(
        &mut self,
        candidate_id: RecoveryCandidateId,
        origins: &[u64],
        error: RecoveryExecutionError,
    ) -> Result<(), RecoveryExecutionError> {
        let RecoveryExecutionError::Evidence(evidence_error) = &error else {
            return Err(error);
        };
        let Some((resource, limit, used)) = case_evidence_quota(self.case, evidence_error) else {
            return Err(error);
        };
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
            task: RecoveryTask::EmbeddedDiscovery,
            input_node_ids: origins.to_vec(),
            resource,
            limit,
            used,
            requested,
        });
        Ok(())
    }

    fn discover_embedded(
        &self,
        candidate_id: RecoveryCandidateId,
    ) -> Result<EmbeddedDiscoveryReport, RecoveryExecutionError> {
        let limits = self.policy.embedded_limits;
        let report = {
            let input = self.coordinator.input_blob(self.case, candidate_id)?;
            discover_embedded_objects_with_work(
                &input.bytes,
                limits,
                self.coordinator.remaining_work_bytes(),
            )
        };
        report.map_err(|source| RecoveryExecutionError::Operational {
            stage: RecoveryStage::EmbeddedDiscovery,
            source: Box::new(source),
        })
    }

    fn copy_embedded_outputs(
        &self,
        candidate_id: RecoveryCandidateId,
        validated: &[&EmbeddedCandidate],
    ) -> Result<Vec<EmbeddedOutput>, RecoveryExecutionError> {
        let input = self.coordinator.input_blob(self.case, candidate_id)?;
        let mut outputs = Vec::new();
        outputs
            .try_reserve_exact(validated.len())
            .map_err(|source| RecoveryExecutionError::Operational {
                stage: RecoveryStage::EmbeddedDiscovery,
                source: Box::new(source),
            })?;
        for candidate in validated {
            let end = candidate
                .range
                .offset
                .checked_add(candidate.range.length)
                .ok_or(RecoveryError::InvariantFailure)?;
            let object_bytes = input
                .bytes
                .get(candidate.range.offset..end)
                .ok_or(RecoveryError::InvariantFailure)?;
            let mut output_bytes = Vec::new();
            output_bytes
                .try_reserve_exact(object_bytes.len())
                .map_err(|source| RecoveryExecutionError::Operational {
                    stage: RecoveryStage::EmbeddedDiscovery,
                    source: Box::new(source),
                })?;
            output_bytes.extend_from_slice(object_bytes);
            outputs.push((output_bytes, candidate.format, candidate.range));
        }
        Ok(outputs)
    }

    fn commit_embedded(
        &mut self,
        candidate_id: RecoveryCandidateId,
        input_node: u64,
        origins: &[u64],
        report: &EmbeddedDiscoveryReport,
        validated_count: usize,
        outputs: Vec<EmbeddedOutput>,
    ) -> Result<(RecoveryResult, Vec<u64>), RecoveryExecutionError> {
        let (receipt_bytes, receipt_details) =
            embedded_receipt(report, input_node, validated_count)?;
        self.case_transaction_and_finish(candidate_id, |case| {
            let receipt = case.add_bytes_node(
                "embedded_discovery_receipt",
                &receipt_bytes,
                Vec::new(),
                receipt_details,
            )?;
            let result = embedded_result(case, receipt, origins, report, validated_count)?;
            let children = retain_embedded_children(case, input_node, receipt, outputs)?;
            Ok(((result.clone(), children), result))
        })
    }
}

fn embedded_result(
    case: &mut l2_workbench::evidence::Case,
    receipt: u64,
    origins: &[u64],
    report: &EmbeddedDiscoveryReport,
    validated_count: usize,
) -> Result<RecoveryResult, RecoveryExecutionError> {
    if validated_count > 0 {
        add_transaction_links(
            case,
            receipt,
            origins,
            "embedded_scan",
            EvidenceStatus::Observed,
            "The retained receipt records marker locations and existing parser results",
        )?;
        Ok(RecoveryResult::Derived {
            evidence_node_id: receipt,
        })
    } else if report.candidates.is_empty()
        || report.omissions != EmbeddedDiscoveryOmissions::default()
    {
        add_transaction_links(
            case,
            receipt,
            origins,
            "embedded_scan_incomplete",
            EvidenceStatus::Unresolved,
            "The selected scan limits omitted part of the embedded-object search",
        )?;
        Ok(RecoveryResult::Omitted)
    } else {
        add_transaction_links(
            case,
            receipt,
            origins,
            "embedded_scan_rejected",
            EvidenceStatus::ConstraintFailed,
            "Every retained embedded marker candidate failed its existing structural parser",
        )?;
        Ok(RecoveryResult::Rejected { node_id: receipt })
    }
}

fn retain_embedded_children(
    case: &mut l2_workbench::evidence::Case,
    input_node: u64,
    receipt: u64,
    outputs: Vec<EmbeddedOutput>,
) -> Result<Vec<u64>, RecoveryExecutionError> {
    let mut children = Vec::new();
    children
        .try_reserve_exact(outputs.len())
        .map_err(|source| RecoveryExecutionError::Operational {
            stage: RecoveryStage::EmbeddedDiscovery,
            source: Box::new(source),
        })?;
    for (object_bytes, format, range) in outputs {
        let child = case.add_bytes_node(
            "embedded_artifact",
            &object_bytes,
            Vec::new(),
            json!({
                "input_node":input_node,
                "format":embedded_format(format),
                "range":range,
                "sha256":l2_workbench::sha256(&object_bytes)
            }),
        )?;
        add_transaction_edge(
            case,
            l2_workbench::evidence::Edge {
                from: child,
                to: receipt,
                relation: "derived_from".to_owned(),
                status: EvidenceStatus::Observed,
                reason: DERIVED_REASON.to_owned(),
            },
        )?;
        add_transaction_edge(
            case,
            l2_workbench::evidence::Edge {
                from: input_node,
                to: child,
                relation: "contains_embedded_candidate".to_owned(),
                status: EvidenceStatus::Observed,
                reason: "The existing format parser validated this exact interior byte range"
                    .to_owned(),
            },
        )?;
        children.push(child);
    }
    Ok(children)
}

fn validated_candidates(report: &EmbeddedDiscoveryReport) -> Vec<&EmbeddedCandidate> {
    report
        .candidates
        .iter()
        .filter(|candidate| candidate.validation.is_ok())
        .collect()
}

fn retained_embedded_candidates<'a>(
    validated: &[&'a EmbeddedCandidate],
    input_length: usize,
) -> Vec<&'a EmbeddedCandidate> {
    validated
        .iter()
        .copied()
        // The input node already represents a candidate spanning its full byte range
        .filter(|candidate| candidate.range.offset != 0 || candidate.range.length != input_length)
        .collect()
}

fn requested_embedded_output(
    validated: &[&EmbeddedCandidate],
) -> Result<usize, RecoveryExecutionError> {
    validated.iter().try_fold(0_usize, |total, candidate| {
        total.checked_add(candidate.range.length).ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy(
                "embedded output byte count overflowed".to_owned(),
            )
        })
    })
}

fn embedded_receipt(
    report: &EmbeddedDiscoveryReport,
    input_node: u64,
    validated_count: usize,
) -> Result<(Vec<u8>, Value), RecoveryExecutionError> {
    let candidate_summaries = report
        .candidates
        .iter()
        .map(embedded_candidate_summary)
        .collect::<Vec<_>>();
    let omissions = json!({
        "output_candidate_count":report.omissions.output_candidate_count,
        "unvalidated_candidate_count":report.omissions.unvalidated_candidate_count,
        "zip_entry_count_limited":report.omissions.zip_entry_count_limited,
        "unscanned_range":report.omissions.unscanned_range
    });
    let receipt_content = json!({
        "input_node":input_node,
        "scanned_range":report.scanned_range,
        "validation_attempt_count":report.validation_attempt_count,
        "validation_input_bytes":report.validation_input_bytes,
        "zip_work_bytes":report.zip_work_bytes,
        "candidates":candidate_summaries,
        "omissions":omissions
    });
    let receipt_bytes = serde_json::to_vec(&receipt_content).map_err(|source| {
        RecoveryExecutionError::Operational {
            stage: RecoveryStage::EmbeddedDiscovery,
            source: Box::new(source),
        }
    })?;
    let rejected_count = report
        .candidates
        .len()
        .checked_sub(validated_count)
        .and_then(|count| count.checked_sub(report.omissions.unvalidated_candidate_count))
        .ok_or(RecoveryError::InvariantFailure)?;
    let details = json!({
        "representation":"json_blob",
        "input_node":input_node,
        "candidate_count":report.candidates.len(),
        "validated_candidate_count":validated_count,
        "rejected_candidate_count":rejected_count,
        "omitted_candidate_count":report.omissions.unvalidated_candidate_count,
        "validation_attempt_count":report.validation_attempt_count,
        "validation_input_bytes":report.validation_input_bytes,
        "zip_work_bytes":report.zip_work_bytes,
        "omissions":omissions,
        "report_sha256":l2_workbench::sha256(&receipt_bytes)
    });
    Ok((receipt_bytes, details))
}

fn embedded_candidate_summary(candidate: &EmbeddedCandidate) -> Value {
    let validation = match &candidate.validation {
        Ok(EmbeddedValidationEvidence::Png {
            chunk_count,
            iend_range,
            trailing_range,
        }) => json!({
            "status":"validated",
            "chunk_count":chunk_count,
            "iend_range":iend_range,
            "trailing_range":trailing_range
        }),
        Ok(EmbeddedValidationEvidence::Zip {
            archive_sha256,
            entry_count,
            expanded_byte_count,
            expanded_work_byte_count,
            omitted_entry_count,
        }) => json!({
            "status":"validated",
            "archive_sha256":archive_sha256,
            "entry_count":entry_count,
            "expanded_byte_count":expanded_byte_count,
            "expanded_work_byte_count":expanded_work_byte_count,
            "omitted_entry_count":omitted_entry_count
        }),
        Err(EmbeddedValidationFailure::ZipEntryCountLimit { count, maximum }) => json!({
            "status":"omitted", "reason":"zip_entry_count_limit", "count":count, "maximum":maximum
        }),
        Err(EmbeddedValidationFailure::ValidationAttemptsExhausted) => {
            json!({"status":"omitted","reason":"validation_attempts_exhausted"})
        }
        Err(EmbeddedValidationFailure::ValidationWorkExhausted) => {
            json!({"status":"omitted","reason":"validation_work_exhausted"})
        }
        Err(EmbeddedValidationFailure::ScanBudgetExhausted) => {
            json!({"status":"omitted","reason":"scan_budget_exhausted"})
        }
        Err(reason) => json!({"status":"rejected","reason":format!("{reason:?}")}),
    };
    json!({
        "format":embedded_format(candidate.format),
        "offset":candidate.offset,
        "range":candidate.range,
        "validation":validation
    })
}

const fn embedded_format(format: EmbeddedFormat) -> &'static str {
    match format {
        EmbeddedFormat::Png => "png",
        EmbeddedFormat::Zip => "zip",
    }
}
