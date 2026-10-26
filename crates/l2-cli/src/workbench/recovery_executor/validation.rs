use super::evidence::{TransactionEdges, add_transaction_edge, add_transaction_links};
use super::format::{validation_boundary, validation_format};
use super::{
    Executor, RecoveryCandidateId, RecoveryExecutionError, RecoveryOmission, RecoveryTask,
};
use l2_workbench::artifact::zip::{ZipArtifactOmissionReason, ZipArtifactReport};
use l2_workbench::{
    artifact::{
        ArtifactBoundaryEvidence, ArtifactResourceOmissionReason, ArtifactStructure,
        ArtifactValidationFormat, ArtifactValidationOutcome, FileRange,
    },
    evidence::{Case, Edge, EvidenceStatus},
    recovery::{RecoveryError, RecoveryResult, RecoveryStage},
};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub(super) enum ValidationDecision {
    Validated {
        format: ArtifactValidationFormat,
        range: FileRange,
        boundary: ArtifactBoundaryEvidence,
    },
    BoundaryUnproven {
        format: ArtifactValidationFormat,
        input_range: FileRange,
    },
    Rejected {
        format: ArtifactValidationFormat,
        input_range: FileRange,
        reason: String,
    },
    Unsupported,
    Omitted {
        reason: ArtifactResourceOmissionReason,
    },
}

pub(super) struct ValidationAttempt {
    pub(super) decision: ValidationDecision,
    pub(super) zip_work_bytes: usize,
    pub(super) global_zip_work_request: Option<usize>,
}

#[derive(Clone, Copy)]
struct ValidatedArtifact {
    format: ArtifactValidationFormat,
    range: FileRange,
    boundary: ArtifactBoundaryEvidence,
    input_length: usize,
}

enum RetainedValidatedRange {
    OutputLimit,
    FullInput,
    ExactBytes(Vec<u8>),
}

struct ValidationReceipt {
    details: Value,
    bytes: Vec<u8>,
}

struct RetainedArtifactBytes {
    exact_bytes: Option<Vec<u8>>,
    blob_id: String,
}

struct RelationalRecordArtifact {
    report_node_id: u64,
    candidate_index: usize,
    parser_format: String,
    expected_session_orders: Vec<u64>,
    input_frame_node_ids: Vec<u64>,
    record_group_identifier_sha256: Option<String>,
}

struct RelationalFrameMetadata {
    report_node_id: u64,
    candidate_index: usize,
    parser_format: String,
    expected_session_orders: Vec<u64>,
    session_order: u64,
}

struct ValidatedEvidenceCommit<'a> {
    candidate_id: RecoveryCandidateId,
    origins: &'a [u64],
    input_node: u64,
    artifact: ValidatedArtifact,
    receipt: ValidationReceipt,
    exact_bytes: Option<Vec<u8>>,
    relational_record_artifact: Option<RelationalRecordArtifact>,
}

pub(super) fn classify_validation(
    outcome: ArtifactValidationOutcome<'_>,
    global_zip_work_limited: bool,
) -> Result<ValidationAttempt, RecoveryExecutionError> {
    let mut zip_work_bytes = 0;
    let mut global_zip_work_request = None;
    let decision = match outcome {
        ArtifactValidationOutcome::Validated {
            format,
            range,
            boundary,
            structure: ArtifactStructure::Zip(report),
        } => {
            zip_work_bytes = report.expanded_work_byte_count;
            if global_zip_work_limited {
                global_zip_work_request = zip_limited_request(&report)?;
            }
            ValidationDecision::Validated {
                format,
                range,
                boundary,
            }
        }
        ArtifactValidationOutcome::Validated {
            format,
            range,
            boundary,
            ..
        } => ValidationDecision::Validated {
            format,
            range,
            boundary,
        },
        ArtifactValidationOutcome::BoundaryUnproven {
            format,
            input_range,
            ..
        } => ValidationDecision::BoundaryUnproven {
            format,
            input_range,
        },
        ArtifactValidationOutcome::Rejected {
            format,
            input_range,
            reason,
        } => ValidationDecision::Rejected {
            format,
            input_range,
            reason: format!("{reason:?}"),
        },
        ArtifactValidationOutcome::Unsupported { .. } => ValidationDecision::Unsupported,
        ArtifactValidationOutcome::Omitted { reason, .. } => ValidationDecision::Omitted { reason },
    };
    Ok(ValidationAttempt {
        decision,
        zip_work_bytes,
        global_zip_work_request,
    })
}

fn zip_limited_request(
    report: &ZipArtifactReport,
) -> Result<Option<usize>, RecoveryExecutionError> {
    let mut requested = 0_usize;
    let mut limited = false;
    for entry in &report.entries {
        if entry.omission != Some(ZipArtifactOmissionReason::TotalExpandedByteLimit) {
            continue;
        }
        limited = true;
        let entry_work = usize::try_from(entry.metadata.expanded_size).map_err(|_| {
            RecoveryExecutionError::InvalidPolicy(
                "ZIP member work exceeds the platform's addressable range".to_owned(),
            )
        })?;
        requested = requested.checked_add(entry_work).ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy("ZIP member work count overflowed".to_owned())
        })?;
    }
    Ok(limited.then_some(requested))
}

fn relational_record_artifact(
    case: &Case,
    input_node_id: u64,
    format: ArtifactValidationFormat,
) -> Option<RelationalRecordArtifact> {
    let input = case.node(input_node_id)?;
    if !matches!(input.kind.as_str(), "record_candidate" | "record_object") {
        return None;
    }
    let frame_node_ids = relational_frame_node_ids(case, input_node_id)?;
    let first_id = *frame_node_ids.first()?;
    let first = relational_frame_metadata(case, first_id, format)?;
    let expected_set = unique_session_orders(&first.expected_session_orders)?;
    let mut observed_session_orders = BTreeSet::new();
    for frame_node_id in &frame_node_ids {
        let frame = relational_frame_metadata(case, *frame_node_id, format)?;
        if frame.report_node_id != first.report_node_id
            || frame.candidate_index != first.candidate_index
            || frame.parser_format != first.parser_format
            || frame.expected_session_orders != first.expected_session_orders
        {
            return None;
        }
        observed_session_orders.insert(frame.session_order);
    }
    if observed_session_orders != expected_set {
        return None;
    }
    Some(RelationalRecordArtifact {
        report_node_id: first.report_node_id,
        candidate_index: first.candidate_index,
        parser_format: first.parser_format,
        expected_session_orders: first.expected_session_orders,
        input_frame_node_ids: frame_node_ids,
        record_group_identifier_sha256: input
            .details
            .get("identifier_sha256")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

fn relational_frame_node_ids(case: &Case, input_node_id: u64) -> Option<Vec<u64>> {
    let mut frame_node_ids = case
        .edges()
        .iter()
        .filter(|edge| {
            edge.to == input_node_id
                && matches!(edge.relation.as_str(), "candidate_from" | "assembled_from")
        })
        .map(|edge| edge.from)
        .collect::<Vec<_>>();
    frame_node_ids.sort_unstable();
    frame_node_ids.dedup();
    (!frame_node_ids.is_empty()).then_some(frame_node_ids)
}

fn relational_frame_metadata(
    case: &Case,
    frame_node_id: u64,
    format: ArtifactValidationFormat,
) -> Option<RelationalFrameMetadata> {
    let frame = case.node(frame_node_id)?;
    if frame.kind != "relational_decoded_frame"
        || frame.details.get("relational_decoded_frame") != Some(&Value::Bool(true))
    {
        return None;
    }
    let parser_format = frame
        .details
        .get("relational_parser_format")
        .and_then(Value::as_str)?
        .to_owned();
    if parser_format != format!("{format:?}") {
        return None;
    }
    let expected_session_orders = frame
        .details
        .get("expected_session_orders")
        .and_then(Value::as_array)?
        .iter()
        .map(Value::as_u64)
        .collect::<Option<Vec<_>>>()?;
    Some(RelationalFrameMetadata {
        report_node_id: frame
            .details
            .get("relational_report_node_id")
            .and_then(Value::as_u64)?,
        candidate_index: usize::try_from(
            frame
                .details
                .get("relational_candidate_index")
                .and_then(Value::as_u64)?,
        )
        .ok()?,
        parser_format,
        expected_session_orders,
        session_order: frame.details.get("session_order").and_then(Value::as_u64)?,
    })
}

fn unique_session_orders(orders: &[u64]) -> Option<BTreeSet<u64>> {
    let unique = orders.iter().copied().collect::<BTreeSet<_>>();
    (unique.len() == orders.len() && !unique.is_empty()).then_some(unique)
}

impl Executor<'_> {
    pub(super) fn run_validation(
        &mut self,
        candidate_id: RecoveryCandidateId,
        origins: &[u64],
        input_node: u64,
        input_length: usize,
        decision: ValidationDecision,
    ) -> Result<(), RecoveryExecutionError> {
        match decision {
            ValidationDecision::Validated {
                format,
                range,
                boundary,
            } => self.finish_validated(
                candidate_id,
                origins,
                input_node,
                ValidatedArtifact {
                    format,
                    range,
                    boundary,
                    input_length,
                },
            ),
            ValidationDecision::BoundaryUnproven {
                format,
                input_range,
            } => self.finish_boundary_unproven(
                candidate_id,
                origins,
                input_node,
                format,
                input_range,
            ),
            ValidationDecision::Rejected {
                format,
                input_range,
                reason,
            } => self.finish_validation_rejected(
                candidate_id,
                origins,
                input_node,
                format,
                input_range,
                &reason,
            ),
            ValidationDecision::Unsupported => {
                self.finish(candidate_id, RecoveryResult::Unsupported)
            }
            ValidationDecision::Omitted { reason } => {
                self.omissions.push(RecoveryOmission::ArtifactValidation {
                    input_node_id: input_node,
                    reason,
                });
                self.finish(candidate_id, RecoveryResult::Omitted)
            }
        }
    }

    fn finish_validated(
        &mut self,
        candidate_id: RecoveryCandidateId,
        origins: &[u64],
        input_node: u64,
        artifact: ValidatedArtifact,
    ) -> Result<(), RecoveryExecutionError> {
        let relational_record_artifact = if self.case_index.has_relational_frames
            && artifact.range.offset == 0
            && artifact.range.length == artifact.input_length
        {
            relational_record_artifact(self.case, input_node, artifact.format)
        } else {
            None
        };
        if relational_record_artifact.is_some()
            && !self.check_output(
                candidate_id,
                &RecoveryTask::StructuralValidation,
                origins,
                artifact.input_length,
            )?
        {
            return Ok(());
        }
        let receipt = ValidationReceipt::new(input_node, artifact)?;
        let Some(retained) =
            self.retain_validated_artifact(candidate_id, origins, input_node, artifact)?
        else {
            return Ok(());
        };
        let expansion_node = self.commit_validated_evidence(ValidatedEvidenceCommit {
            candidate_id,
            origins,
            input_node,
            artifact,
            receipt,
            exact_bytes: retained.exact_bytes,
            relational_record_artifact,
        })?;
        self.validated_artifacts.insert(retained.blob_id);
        self.enqueue_validation_expansion(candidate_id, artifact.format, expansion_node)?;
        Ok(())
    }

    fn retain_validated_artifact(
        &mut self,
        candidate_id: RecoveryCandidateId,
        origins: &[u64],
        input_node: u64,
        artifact: ValidatedArtifact,
    ) -> Result<Option<RetainedArtifactBytes>, RecoveryExecutionError> {
        let exact_bytes = match self.validated_range_bytes(candidate_id, origins, artifact)? {
            RetainedValidatedRange::OutputLimit => return Ok(None),
            RetainedValidatedRange::FullInput => None,
            RetainedValidatedRange::ExactBytes(bytes) => Some(bytes),
        };
        let blob_id = match &exact_bytes {
            Some(bytes) => format!("sha256:{}", l2_workbench::sha256(bytes)),
            None => self.node_blob_id(input_node)?.to_owned(),
        };
        Ok(Some(RetainedArtifactBytes {
            exact_bytes,
            blob_id,
        }))
    }

    fn commit_validated_evidence(
        &mut self,
        commit: ValidatedEvidenceCommit<'_>,
    ) -> Result<u64, RecoveryExecutionError> {
        let ValidatedEvidenceCommit {
            candidate_id,
            origins,
            input_node,
            artifact,
            receipt,
            exact_bytes,
            relational_record_artifact,
        } = commit;
        self.case_transaction_and_finish(candidate_id, |case, identities| {
            // The full input gets a validated-range edge below, so omit its reciprocal link
            let validated_input = exact_bytes.is_none().then_some(input_node);
            let receipt_node =
                add_validation_receipt(case, identities, origins, validated_input, receipt)?;
            let expansion_node = add_validated_range(
                case,
                identities,
                input_node,
                receipt_node,
                artifact,
                exact_bytes,
            )?;
            if let Some(relational_artifact) = relational_record_artifact {
                let input_blob = case
                    .node(input_node)
                    .and_then(|node| node.blob.as_deref())
                    .and_then(|blob_id| case.blob(blob_id))
                    .ok_or(RecoveryError::InvariantFailure)?;
                let input_digest = input_blob
                    .id
                    .strip_prefix("sha256:")
                    .ok_or(RecoveryError::InvariantFailure)?;
                let details = json!({
                    "representation":"raw_bytes",
                    "report_node_id":relational_artifact.report_node_id,
                    "candidate_index":relational_artifact.candidate_index,
                    "parser_format":relational_artifact.parser_format,
                    "parser_scope":"after_cross_session_record_assembly",
                    "record_group_identifier_sha256":relational_artifact.record_group_identifier_sha256,
                    "input_record_candidate":input_node,
                    "input_frame_node_ids":relational_artifact.input_frame_node_ids,
                    "session_orders":relational_artifact.expected_session_orders,
                    "length":input_blob.bytes.len(),
                    "sha256":input_digest,
                    "terminal_sequence":"unknown",
                });
                // Validation adds an interpretation of these retained bytes, so reuse their identity
                let input_blob_id = input_blob.id.clone();
                let output_node = case.add_node(
                    "relational_transform_output",
                    Some(&input_blob_id),
                    Vec::new(),
                    details,
                )?;
                add_transaction_links(
                    case,
                    identities,
                    output_node,
                    &[input_node],
                    "validated_record_assembly",
                    EvidenceStatus::Observed,
                    "This exact parser-validated artifact is the output of cross-session record assembly",
                )?;
                add_transaction_edge(
                    case,
                    identities,
                    Edge {
                        from: relational_artifact.report_node_id,
                        to: output_node,
                        relation: "supports_relational_output".to_owned(),
                        status: EvidenceStatus::Hypothesis,
                        reason: "The frozen relational rule contributed decoded frame payloads to this parser-validated record assembly".to_owned(),
                    },
                )?;
            }
            Ok((
                expansion_node,
                RecoveryResult::ObservedValidation {
                    node_id: receipt_node,
                },
            ))
        })
    }

    fn enqueue_validation_expansion(
        &mut self,
        candidate_id: RecoveryCandidateId,
        format: ArtifactValidationFormat,
        expansion_node: u64,
    ) -> Result<(), RecoveryExecutionError> {
        if matches!(
            format,
            ArtifactValidationFormat::Der
                | ArtifactValidationFormat::Png
                | ArtifactValidationFormat::Zip
        ) {
            self.enqueue_validated_task(
                candidate_id,
                expansion_node,
                &RecoveryTask::RecursiveExpansion,
            )?;
        }
        Ok(())
    }

    fn validated_range_bytes(
        &mut self,
        candidate_id: RecoveryCandidateId,
        origins: &[u64],
        artifact: ValidatedArtifact,
    ) -> Result<RetainedValidatedRange, RecoveryExecutionError> {
        if artifact.range.offset == 0 && artifact.range.length == artifact.input_length {
            return Ok(RetainedValidatedRange::FullInput);
        }
        if !self.check_output(
            candidate_id,
            &RecoveryTask::StructuralValidation,
            origins,
            artifact.range.length,
        )? {
            return Ok(RetainedValidatedRange::OutputLimit);
        }
        let end = artifact
            .range
            .offset
            .checked_add(artifact.range.length)
            .ok_or(RecoveryError::InvariantFailure)?;
        let input = self.coordinator.input_blob(self.case, candidate_id)?;
        let source_bytes = input
            .bytes
            .get(artifact.range.offset..end)
            .ok_or(RecoveryError::InvariantFailure)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(source_bytes.len())
            .map_err(|source| RecoveryExecutionError::Operational {
                stage: RecoveryStage::StructuralValidation,
                source: Box::new(source),
            })?;
        bytes.extend_from_slice(source_bytes);
        Ok(RetainedValidatedRange::ExactBytes(bytes))
    }

    fn finish_boundary_unproven(
        &mut self,
        candidate_id: RecoveryCandidateId,
        origins: &[u64],
        input_node: u64,
        format: ArtifactValidationFormat,
        input_range: FileRange,
    ) -> Result<(), RecoveryExecutionError> {
        let details = json!({
            "input_node":input_node,
            "status":"boundary_unproven",
            "format":validation_format(format),
            "range":input_range
        });
        let receipt_bytes =
            serde_json::to_vec(&details).map_err(|source| RecoveryExecutionError::Operational {
                stage: RecoveryStage::StructuralValidation,
                source: Box::new(source),
            })?;
        self.case_transaction_and_finish(candidate_id, |case, identities| {
            let receipt = case.add_bytes_node(
                "artifact_validation_receipt",
                &receipt_bytes,
                Vec::new(),
                details,
            )?;
            add_transaction_links(
                case,
                identities,
                receipt,
                origins,
                "validation_hypothesis",
                EvidenceStatus::Hypothesis,
                "The parser inspected the selected executable structures but did not establish a whole-file boundary",
            )?;
            Ok(((), RecoveryResult::Hypothesis { node_id: receipt }))
        })
    }

    fn finish_validation_rejected(
        &mut self,
        candidate_id: RecoveryCandidateId,
        origins: &[u64],
        input_node: u64,
        format: ArtifactValidationFormat,
        input_range: FileRange,
        reason: &str,
    ) -> Result<(), RecoveryExecutionError> {
        let details = json!({
            "input_node":input_node,
            "status":"rejected",
            "format":validation_format(format),
            "range":input_range,
            "reason":reason
        });
        let receipt_bytes =
            serde_json::to_vec(&details).map_err(|source| RecoveryExecutionError::Operational {
                stage: RecoveryStage::StructuralValidation,
                source: Box::new(source),
            })?;
        self.case_transaction_and_finish(candidate_id, |case, identities| {
            let receipt = case.add_bytes_node(
                "artifact_validation_receipt",
                &receipt_bytes,
                Vec::new(),
                details,
            )?;
            add_transaction_links(
                case,
                identities,
                receipt,
                origins,
                "validation_rejected",
                EvidenceStatus::ConstraintFailed,
                "The existing structural parser rejected this exact candidate range",
            )?;
            Ok(((), RecoveryResult::Rejected { node_id: receipt }))
        })
    }
}

impl ValidationReceipt {
    fn new(input_node: u64, artifact: ValidatedArtifact) -> Result<Self, RecoveryExecutionError> {
        let details = json!({
            "input_node":input_node,
            "status":"validated",
            "format":validation_format(artifact.format),
            "range":artifact.range,
            "boundary":validation_boundary(artifact.boundary)
        });
        let bytes =
            serde_json::to_vec(&details).map_err(|source| RecoveryExecutionError::Operational {
                stage: RecoveryStage::StructuralValidation,
                source: Box::new(source),
            })?;
        Ok(Self { details, bytes })
    }
}

fn add_validation_receipt(
    case: &mut Case,
    identities: &mut TransactionEdges<'_>,
    origins: &[u64],
    validated_input: Option<u64>,
    receipt: ValidationReceipt,
) -> Result<u64, RecoveryExecutionError> {
    let receipt_node = case.add_bytes_node(
        "artifact_validation_receipt",
        &receipt.bytes,
        Vec::new(),
        receipt.details,
    )?;
    for origin in origins
        .iter()
        .copied()
        .filter(|origin| Some(*origin) != validated_input)
    {
        add_transaction_edge(
            case,
            identities,
            Edge {
                from: receipt_node,
                to: origin,
                relation: "validated_by".to_owned(),
                status: EvidenceStatus::Observed,
                reason: "The existing structural parser validated the exact recorded byte range"
                    .to_owned(),
            },
        )?;
    }
    Ok(receipt_node)
}

fn add_validated_range(
    case: &mut Case,
    identities: &mut TransactionEdges<'_>,
    input_node: u64,
    receipt_node: u64,
    artifact: ValidatedArtifact,
    exact_bytes: Option<Vec<u8>>,
) -> Result<u64, RecoveryExecutionError> {
    let expansion_node = match exact_bytes {
        Some(bytes) => add_exact_validated_artifact(
            case,
            identities,
            input_node,
            receipt_node,
            artifact,
            &bytes,
        )?,
        None => input_node,
    };
    add_transaction_edge(
        case,
        identities,
        Edge {
            from: expansion_node,
            to: receipt_node,
            relation: "validated_range".to_owned(),
            status: EvidenceStatus::Observed,
            reason: "These exact bytes passed structural validation".to_owned(),
        },
    )?;
    Ok(expansion_node)
}

fn add_exact_validated_artifact(
    case: &mut Case,
    identities: &mut TransactionEdges<'_>,
    input_node: u64,
    receipt_node: u64,
    artifact: ValidatedArtifact,
    bytes: &[u8],
) -> Result<u64, RecoveryExecutionError> {
    let format = validation_format(artifact.format);
    let exact_node = case.add_bytes_node(
        "validated_artifact",
        bytes,
        Vec::new(),
        json!({
            "source_node":input_node,
            "validation_node":receipt_node,
            "range":artifact.range,
            "format":format,
            "sha256":l2_workbench::sha256(bytes)
        }),
    )?;
    add_transaction_edge(
        case,
        identities,
        Edge {
            from: exact_node,
            to: receipt_node,
            relation: "derived_from".to_owned(),
            status: EvidenceStatus::Observed,
            reason: "The validated parser range identifies these exact artifact bytes".to_owned(),
        },
    )?;
    Ok(exact_node)
}
