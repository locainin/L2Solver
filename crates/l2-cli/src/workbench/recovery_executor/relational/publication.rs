use super::super::evidence::{TransactionEdges, add_transaction_edge, add_transaction_links};
use super::record_gate::AcceptedRecordSchema;
use super::{
    CommittedRelationalOutputs, DECODED_FRAME_KIND, DECODED_FRAME_REASON, OUTPUT_KIND,
    OUTPUT_REASON, PreparedRelationalCohort, REPORT_KIND, REPORT_VERSION, RecordCohortKey,
    RecordCohortOrigin, RecordFrameInput, RecoveryExecutionError, RecoveryResult, invalid_policy,
};
use l2_workbench::{
    evidence::{Case, Edge, EvidenceStatus},
    protocol::ByteRange,
    recovery::RecoveryError,
    sha256,
};
use serde_json::json;
use std::collections::BTreeMap;

// Write report, output, and frame evidence in the caller transaction
pub(super) fn publish_prepared_cohorts(
    case: &mut Case,
    identities: &mut TransactionEdges<'_>,
    prepared: &[PreparedRelationalCohort],
) -> Result<(CommittedRelationalOutputs, RecoveryResult), RecoveryExecutionError> {
    let mut report_nodes = Vec::new();
    let mut output_node_ids = Vec::new();
    let mut decoded_record_inputs = Vec::new();
    let mut accepted_record_schemas = Vec::new();
    report_nodes
        .try_reserve_exact(prepared.len())
        .map_err(|source| operational("relational report node allocation failed", source))?;
    decoded_record_inputs
        .try_reserve(prepared.len())
        .map_err(|source| operational("decoded record cohort allocation failed", source))?;
    let accepted_schema_count = prepared
        .iter()
        .try_fold(0_usize, |total, cohort| {
            total.checked_add(cohort.accepted_schemas.len())
        })
        .ok_or_else(|| invalid_policy("accepted schema request count overflowed"))?;
    accepted_record_schemas
        .try_reserve_exact(accepted_schema_count)
        .map_err(|source| operational("accepted record schema allocation failed", source))?;

    // Preserve cohort order so report edges match the admitted work order
    for cohort in prepared {
        let report_node = publish_report(case, identities, cohort)?;
        report_nodes.push(report_node);
        publish_outputs(case, identities, report_node, cohort, &mut output_node_ids)?;
        let record_inputs = publish_record_inputs(case, identities, report_node, cohort)?;
        decoded_record_inputs.extend(record_inputs.decoded_record_inputs);
        accepted_record_schemas.extend(record_inputs.accepted_record_schemas);
    }

    let result_node = report_nodes
        .first()
        .copied()
        .ok_or(RecoveryError::InvariantFailure)?;
    let result = if output_node_ids.is_empty() {
        RecoveryResult::Hypothesis {
            node_id: result_node,
        }
    } else {
        RecoveryResult::Derived {
            evidence_node_id: result_node,
        }
    };
    Ok((
        CommittedRelationalOutputs {
            output_node_ids,
            decoded_record_inputs,
            accepted_record_schemas,
        },
        result,
    ))
}

fn publish_report(
    case: &mut Case,
    identities: &mut TransactionEdges<'_>,
    cohort: &PreparedRelationalCohort,
) -> Result<u64, RecoveryExecutionError> {
    let details = json!({
        "representation":"json_blob",
        "report_schema_version":REPORT_VERSION,
        "source_id":cohort.context.key.source_id,
        "candidate_limit_remaining":cohort.candidate_limit_remaining,
        "locator_candidate_limit_remaining":cohort.locator_candidate_limit_remaining,
        "work_bytes_remaining":cohort.work_bytes_remaining,
        "search_exhaustive_within_plan":cohort.search_exhaustive_within_plan,
        "report_details_complete":cohort.report_details_complete,
        "source_eligibility_omissions":cohort.context.source_eligibility_omissions,
    });
    let report_node =
        case.add_bytes_node(REPORT_KIND, &cohort.report_bytes, Vec::new(), details)?;
    let mut cohort_origins = cohort.context.sample_node_ids.clone();
    cohort_origins.sort_unstable();
    cohort_origins.dedup();
    add_transaction_links(
        case,
        identities,
        report_node,
        &cohort_origins,
        "relational_transform_input",
        EvidenceStatus::Unresolved,
        super::INPUT_REASON,
    )?;
    Ok(report_node)
}

fn publish_outputs(
    case: &mut Case,
    identities: &mut TransactionEdges<'_>,
    report_node: u64,
    cohort: &PreparedRelationalCohort,
    output_node_ids: &mut Vec<u64>,
) -> Result<(), RecoveryExecutionError> {
    for output in &cohort.outputs {
        let details = json!({
            "representation":"raw_bytes",
            "report_node_id":report_node,
            "candidate_index":output.candidate_index,
            "session":output.value.session,
            "sessions":output.session_ids,
            "session_order":output.value.session_order,
            "session_orders":output.session_orders,
            "seed_sample":output.value.seed_sample,
            "seed_samples":output.seed_samples,
            "payload_samples":output.value.payload_samples,
            "parser_format":format!("{:?}", output.parser_format),
            "parser_scope":if output.session_ids.len() > 1 { "across_sessions" } else { "each_session" },
            "parser_validation_deferred":output.value.parser_validation_deferred,
            "length":output.value.bytes.len(),
            "sha256":output.sha256,
            "terminal_sequence":"unknown",
        });
        let output_node =
            case.add_bytes_node(OUTPUT_KIND, &output.value.bytes, Vec::new(), details)?;
        let mut parents = output.value.payload_samples.clone();
        parents.extend_from_slice(&output.seed_samples);
        parents.sort_unstable();
        parents.dedup();
        add_transaction_links(
            case,
            identities,
            output_node,
            &parents,
            "derived_from",
            EvidenceStatus::Hypothesis,
            OUTPUT_REASON,
        )?;
        add_transaction_edge(
            case,
            identities,
            Edge {
                from: report_node,
                to: output_node,
                relation: "supports_relational_output".to_owned(),
                status: EvidenceStatus::Hypothesis,
                reason: OUTPUT_REASON.to_owned(),
            },
        )?;
        output_node_ids.push(output_node);
    }
    Ok(())
}

type RecordInputGroups = Vec<(RecordCohortKey, Vec<RecordFrameInput>)>;
type AcceptedRecordSchemaInputs = Vec<(Vec<u64>, l2_workbench::protocol::RecordSchema, u64)>;

struct PublishedRecordInputs {
    decoded_record_inputs: RecordInputGroups,
    accepted_record_schemas: AcceptedRecordSchemaInputs,
}

struct PublishedFrameInputs {
    by_candidate: BTreeMap<usize, Vec<RecordFrameInput>>,
    accepted_members_seen: BTreeMap<usize, usize>,
}

fn publish_record_inputs(
    case: &mut Case,
    identities: &mut TransactionEdges<'_>,
    report_node: u64,
    cohort: &PreparedRelationalCohort,
) -> Result<PublishedRecordInputs, RecoveryExecutionError> {
    let mut accepted_by_candidate = BTreeMap::<usize, AcceptedRecordSchema>::new();
    for (candidate_index, accepted) in &cohort.accepted_schemas {
        if accepted_by_candidate
            .insert(*candidate_index, accepted.clone())
            .is_some()
        {
            return Err(RecoveryError::InvariantFailure.into());
        }
    }
    let published_frames = publish_decoded_record_frames(
        case,
        identities,
        report_node,
        &cohort.context.key.source_id,
        &cohort.decoded_frames,
        &accepted_by_candidate,
    )?;
    route_record_inputs(
        &cohort.context,
        report_node,
        accepted_by_candidate,
        published_frames,
    )
}

fn publish_decoded_record_frames(
    case: &mut Case,
    identities: &mut TransactionEdges<'_>,
    report_node: u64,
    source_id: &str,
    frames: &[super::DecodedFrameOutput],
    accepted_by_candidate: &BTreeMap<usize, AcceptedRecordSchema>,
) -> Result<PublishedFrameInputs, RecoveryExecutionError> {
    let mut by_candidate = BTreeMap::<usize, Vec<RecordFrameInput>>::new();
    let mut accepted_members_seen = BTreeMap::<usize, usize>::new();
    for frame in frames {
        let (decoded_node, blob_id) =
            publish_decoded_frame(case, identities, report_node, source_id, frame)?;
        let frame_inputs = by_candidate.entry(frame.candidate_index).or_default();
        frame_inputs
            .try_reserve(1)
            .map_err(|source| operational("decoded record input allocation failed", source))?;
        let frame_index = frame_inputs.len();
        if let Some(accepted) = accepted_by_candidate.get(&frame.candidate_index)
            && let Ok(identity_index) = accepted.frame_indices.binary_search(&frame_index)
        {
            let identity = accepted
                .frame_identities
                .get(identity_index)
                .ok_or(RecoveryError::InvariantFailure)?;
            let frame_blob = case.blob(&blob_id).ok_or(RecoveryError::InvariantFailure)?;
            let frame_bytes_sha256 = blob_id
                .strip_prefix("sha256:")
                .ok_or(RecoveryError::InvariantFailure)?;
            super::application::validate_accepted_frame_identity(
                identity,
                frame,
                frame_index,
                frame_blob.bytes.len(),
                frame_bytes_sha256,
            )?;
            let seen = accepted_members_seen
                .entry(frame.candidate_index)
                .or_default();
            *seen = seen.checked_add(1).ok_or(RecoveryError::InvariantFailure)?;
        }
        frame_inputs.push(RecordFrameInput {
            node_id: decoded_node,
            blob_id,
            receipt_node_id: report_node,
            session_node_id: frame.context.session,
            direction_node_id: frame.direction_node_id,
            episode_node_id: frame.episode_node_id,
            session_id: frame.session_order,
            frame_index,
            stream_range: ByteRange {
                start: 0,
                end: frame.bytes.len(),
            },
            stream_offset: frame.stream_offset,
            byte_length: frame.bytes.len(),
        });
    }
    Ok(PublishedFrameInputs {
        by_candidate,
        accepted_members_seen,
    })
}

fn route_record_inputs(
    context: &super::RelationalDiscoveryContext,
    report_node: u64,
    accepted_by_candidate: BTreeMap<usize, AcceptedRecordSchema>,
    mut published_frames: PublishedFrameInputs,
) -> Result<PublishedRecordInputs, RecoveryExecutionError> {
    let mut decoded_record_inputs = Vec::new();
    decoded_record_inputs
        .try_reserve(
            published_frames
                .by_candidate
                .len()
                .saturating_add(accepted_by_candidate.len()),
        )
        .map_err(|source| operational("decoded record cohort allocation failed", source))?;
    let mut accepted_record_schemas = Vec::new();
    accepted_record_schemas
        .try_reserve_exact(accepted_by_candidate.len())
        .map_err(|source| operational("accepted record schema allocation failed", source))?;
    for (candidate_index, accepted) in accepted_by_candidate {
        let frames = published_frames
            .by_candidate
            .remove(&candidate_index)
            .ok_or(RecoveryError::InvariantFailure)?;
        if published_frames
            .accepted_members_seen
            .get(&candidate_index)
            .copied()
            != Some(accepted.frame_indices.len())
        {
            return Err(RecoveryError::InvariantFailure.into());
        }
        let mut accepted_input_node_ids = Vec::new();
        accepted_input_node_ids
            .try_reserve_exact(accepted.frame_indices.len())
            .map_err(|source| operational("accepted schema input allocation failed", source))?;
        let mut remaining_inputs = Vec::new();
        remaining_inputs
            .try_reserve_exact(frames.len().saturating_sub(accepted.frame_indices.len()))
            .map_err(|source| operational("unassigned record input allocation failed", source))?;
        for (frame_index, frame_input) in frames.into_iter().enumerate() {
            if accepted.frame_indices.binary_search(&frame_index).is_ok() {
                accepted_input_node_ids.push(frame_input.node_id);
            } else {
                remaining_inputs.push(frame_input);
            }
        }
        if accepted_input_node_ids.len() != accepted.frame_indices.len() {
            return Err(RecoveryError::InvariantFailure.into());
        }
        accepted_record_schemas.push((accepted_input_node_ids, accepted.schema, report_node));
        if !remaining_inputs.is_empty() {
            decoded_record_inputs.push((
                relational_record_cohort_key(context, report_node, candidate_index),
                remaining_inputs,
            ));
        }
    }
    for (candidate_index, frames) in published_frames.by_candidate {
        decoded_record_inputs.push((
            relational_record_cohort_key(context, report_node, candidate_index),
            frames,
        ));
    }
    Ok(PublishedRecordInputs {
        decoded_record_inputs,
        accepted_record_schemas,
    })
}

fn relational_record_cohort_key(
    context: &super::RelationalDiscoveryContext,
    report_node: u64,
    candidate_index: usize,
) -> RecordCohortKey {
    RecordCohortKey {
        source_id: context.key.source_id.clone(),
        scope_json: context.key.scope_json.clone(),
        endpoints_json: context.key.endpoints_json.clone(),
        direction: context.key.direction,
        origin: RecordCohortOrigin::Relational {
            report_node,
            candidate_index,
        },
        framing_rule_json: context.key.framing_rule_json.clone(),
    }
}

fn publish_decoded_frame(
    case: &mut Case,
    identities: &mut TransactionEdges<'_>,
    report_node: u64,
    source_id: &str,
    frame: &super::DecodedFrameOutput,
) -> Result<(u64, String), RecoveryExecutionError> {
    let frame_details = json!({
        "representation":"raw_bytes",
        "relational_decoded_frame":true,
        "logical_source_id":source_id,
        "relational_report_node_id":report_node,
        "relational_candidate_index":frame.candidate_index,
        "relational_parser_format":format!("{:?}", frame.parser_format),
        "expected_session_orders":frame.expected_session_orders,
        "session_node_id":frame.context.session,
        "session_order":frame.session_order,
        "direction_node_id":frame.direction_node_id,
        "episode_node_id":frame.episode_node_id,
        "stream_offset":frame.stream_offset,
        "input_frame_node_id":frame.input_node_id,
        "seed_sample":frame.seed_sample,
        "payload_range":frame.payload_range,
        "length":frame.bytes.len(),
        "sha256":sha256(&frame.bytes),
    });
    let decoded_node =
        case.add_bytes_node(DECODED_FRAME_KIND, &frame.bytes, Vec::new(), frame_details)?;
    let mut parents = vec![frame.input_node_id, frame.seed_sample];
    parents.sort_unstable();
    parents.dedup();
    add_transaction_links(
        case,
        identities,
        decoded_node,
        &parents,
        "decoded_from",
        EvidenceStatus::Hypothesis,
        DECODED_FRAME_REASON,
    )?;
    add_transaction_edge(
        case,
        identities,
        Edge {
            from: report_node,
            to: decoded_node,
            relation: "supports_relational_frame".to_owned(),
            status: EvidenceStatus::Hypothesis,
            reason: DECODED_FRAME_REASON.to_owned(),
        },
    )?;
    let blob_id = case
        .node(decoded_node)
        .and_then(|node| node.blob.clone())
        .ok_or(RecoveryError::InvariantFailure)?;
    Ok((decoded_node, blob_id))
}

fn operational(
    context: &'static str,
    source: impl std::error::Error + Send + Sync + 'static,
) -> RecoveryExecutionError {
    super::operational(context, source)
}
