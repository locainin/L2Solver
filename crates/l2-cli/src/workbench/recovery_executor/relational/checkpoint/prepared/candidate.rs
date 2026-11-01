//! Replay every retained positive result before publishing a saved cohort

use super::super::super::{
    AppliedOutput, DecodedFrameOutput, aggregate_validator,
    application::{AggregateOutput, accepted_record_schema_json, concatenate_outputs},
    operational,
    record_gate::{
        AcceptedRecordSchema, SchemaCacheRestoreContext, StructuralEvidence,
        checkpoint::{accepted, replay, structural},
    },
    report,
};
use crate::workbench::recovery_executor::RecoveryExecutionError;
use l2_workbench::{
    artifact::{ArtifactValidationOutcome, PngChunk},
    job::MemoryClass,
    protocol::{
        RelationalFit, RelationalFitStatus, RelationalOutputMapping, RelationalSessionCheck,
        RelationalSessionId, RelationalTransformRule,
    },
    recovery::RecoveryError,
    sha256,
};

#[derive(Clone, Copy)]
pub(in crate::workbench::recovery_executor::relational) struct CandidateVerification<'a> {
    pub(in crate::workbench::recovery_executor::relational) candidate_index: usize,
    pub(in crate::workbench::recovery_executor::relational) rule: &'a RelationalTransformRule,
    pub(in crate::workbench::recovery_executor::relational) saved_outputs: &'a [AppliedOutput],
    pub(in crate::workbench::recovery_executor::relational) saved_frames:
        &'a [DecodedFrameOutput],
    pub(in crate::workbench::recovery_executor::relational) accepted_schema:
        Option<&'a AcceptedRecordSchema>,
    pub(in crate::workbench::recovery_executor::relational) structural_evidence:
        Option<&'a StructuralEvidence>,
    pub(in crate::workbench::recovery_executor::relational) reported: Option<&'a serde_json::Value>,
    pub(in crate::workbench::recovery_executor::relational) reported_evidence:
        Option<&'a serde_json::Value>,
    pub(in crate::workbench::recovery_executor::relational) reported_aggregate:
        Option<&'a serde_json::Value>,
}

pub(in crate::workbench::recovery_executor::relational) fn verify_candidate(
    saved: CandidateVerification<'_>,
    context: &mut SchemaCacheRestoreContext<'_, '_>,
) -> Result<(), RecoveryExecutionError> {
    let CandidateVerification {
        candidate_index,
        rule,
        saved_outputs,
        saved_frames,
        accepted_schema,
        reported,
        reported_evidence,
        reported_aggregate,
        ..
    } = saved;
    // The frozen rule runs against the current Case, never against saved decoded bytes
    let actual = replay::replay(rule, context)?;
    if let Some(reported) = reported {
        verify_reported_fits(reported, &actual.outputs, context)?;
    }
    let frames = saved_frames
        .iter()
        .filter(|frame| frame.candidate_index == candidate_index);
    if frames.clone().next().is_some()
        && (frames.clone().count() != actual.frames.len()
            || frames
                .zip(&actual.frames)
                .any(|(saved, replayed)| !same_frame(saved, replayed)))
    {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    let mut outputs = saved_outputs
        .iter()
        .filter(|output| output.candidate_index == candidate_index);
    let output = outputs.next();
    if outputs.next().is_some() {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    if reported.is_some()
        && ((output.is_some() && reported_aggregate.is_none())
            || (accepted_schema.is_some() && reported_evidence.is_none())
            || (saved_frames
                .iter()
                .any(|frame| frame.candidate_index == candidate_index)
                && reported_evidence.is_none()))
    {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    if output.is_some() || reported_aggregate.is_some() {
        verify_aggregate(output, reported_aggregate, rule, &actual.outputs, context)?;
    }
    if let Some(accepted) = accepted_schema {
        if saved_frames
            .iter()
            .all(|frame| frame.candidate_index != candidate_index)
            || accepted.artifact_format != rule.parser_format
        {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
        accepted::verify(
            accepted,
            &actual.frames,
            context.schema_limits.discovery.record_limits,
            context,
        )?;
    }
    verify_reported_evidence(saved, &actual.frames, context)?;
    Ok(())
}

fn verify_reported_fits(
    reported: &serde_json::Value,
    outputs: &[l2_workbench::protocol::RelationalAppliedOutput],
    context: &mut SchemaCacheRestoreContext<'_, '_>,
) -> Result<(), RecoveryExecutionError> {
    if reported.get("status") != Some(&serde_json::json!("awaiting_across_session_validation")) {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    let canonical = context.report;
    verify_fit(
        reported.get("discovery"),
        &canonical.discovery_sessions,
        outputs,
        context,
    )?;
    verify_fit(
        reported.get("heldout"),
        &canonical.heldout_sessions,
        outputs,
        context,
    )?;
    Ok(())
}

fn verify_reported_evidence(
    saved: CandidateVerification<'_>,
    frames: &[DecodedFrameOutput],
    context: &mut SchemaCacheRestoreContext<'_, '_>,
) -> Result<(), RecoveryExecutionError> {
    if let Some(evidence) = saved.reported_evidence {
        let structural_positive = evidence.get("structurally_supported")
            == Some(&serde_json::Value::Bool(true))
            || evidence.get("status").and_then(serde_json::Value::as_str)
                == Some("structurally_supported");
        if structural_positive {
            let witness = saved
                .structural_evidence
                .ok_or(RecoveryError::InvalidCheckpoint)?;
            structural::verify(witness, frames, context)?;
        } else if saved.structural_evidence.is_some() {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
        let schema_value = evidence
            .get("accepted_record_schema")
            .ok_or(RecoveryError::InvalidCheckpoint)?;
        if !schema_value.is_null() {
            verify_reported_schema(saved, schema_value, frames, context)?;
        } else if (evidence.get("artifact_validated") == Some(&serde_json::Value::Bool(true))
            || evidence.get("status").and_then(serde_json::Value::as_str)
                == Some("artifact_validated"))
            && saved.reported_aggregate.is_none()
        {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
    } else if saved.structural_evidence.is_some() {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    Ok(())
}

fn verify_reported_schema(
    saved: CandidateVerification<'_>,
    schema_value: &serde_json::Value,
    frames: &[DecodedFrameOutput],
    context: &mut SchemaCacheRestoreContext<'_, '_>,
) -> Result<(), RecoveryExecutionError> {
    // The report holds a complete receipt; the format is displayed as a debug name there
    let limit = (context.maximum_workspace_bytes / 128)
        .min(context.work.remaining_verification_work_bytes());
    let mut counter =
        crate::output::BoundedWriter::named(std::io::sink(), limit, "saved schema receipt");
    let write_result = serde_json::to_writer(&mut counter, schema_value);
    replay::charge(context, counter.written())?;
    write_result.map_err(|error| {
        operational("saved schema receipt exceeds verification workspace", error)
    })?;
    let _memory = context
        .memory
        .try_reserve(
            MemoryClass::Executor,
            u64::try_from(context.maximum_workspace_bytes)
                .map_err(|_| RecoveryError::InvalidCheckpoint)?,
        )
        .map_err(|error| operational("reported schema receipt admission failed", error))?;
    let mut encoded = schema_value.clone();
    let object = encoded
        .as_object_mut()
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    if object.get("artifact_format")
        != Some(&serde_json::json!(format!(
            "{:?}",
            saved.rule.parser_format
        )))
    {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    object.insert(
        "artifact_format".to_owned(),
        serde_json::to_value(saved.rule.parser_format)
            .map_err(|_| RecoveryError::InvalidCheckpoint)?,
    );
    let reported_schema: AcceptedRecordSchema =
        serde_json::from_value(encoded).map_err(|_| RecoveryError::InvalidCheckpoint)?;
    if accepted_record_schema_json(&reported_schema) != *schema_value
        || saved
            .accepted_schema
            .is_some_and(|saved| accepted_record_schema_json(saved) != *schema_value)
    {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    if saved.accepted_schema.is_none() {
        accepted::verify(
            &reported_schema,
            frames,
            context.schema_limits.discovery.record_limits,
            context,
        )?;
    }
    Ok(())
}

fn verify_fit(
    reported: Option<&serde_json::Value>,
    sessions: &[RelationalSessionId],
    outputs: &[l2_workbench::protocol::RelationalAppliedOutput],
    context: &mut SchemaCacheRestoreContext<'_, '_>,
) -> Result<(), RecoveryExecutionError> {
    let mut checks = Vec::new();
    checks
        .try_reserve_exact(sessions.len())
        .map_err(|error| operational("saved fit verification allocation failed", error))?;
    for session in sessions {
        let output = outputs
            .iter()
            .find(|output| output.session == *session)
            .ok_or(RecoveryError::InvalidCheckpoint)?;
        replay::charge(context, output.bytes.len())?;
        checks.push(RelationalSessionCheck {
            session: session.clone(),
            seed_sample: Some(output.seed_sample),
            payload_samples: output
                .payload_mappings
                .iter()
                .map(|mapping| mapping.sample)
                .collect(),
            status: RelationalFitStatus::TransformConstraintsSatisfied,
            output_length: Some(output.bytes.len()),
            output_sha256: Some(sha256(&output.bytes)),
            falsification: None,
        });
    }
    let fit = RelationalFit {
        status: RelationalFitStatus::TransformConstraintsSatisfied,
        supported_sessions: sessions.to_vec(),
        contradicted_sessions: Vec::new(),
        unresolved_sessions: Vec::new(),
        checks,
    };
    if reported != Some(&report::fit_json(&fit)) {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    Ok(())
}

fn same_frame(saved: &DecodedFrameOutput, actual: &DecodedFrameOutput) -> bool {
    saved.context == actual.context
        && saved.input_node_id == actual.input_node_id
        && saved.seed_sample == actual.seed_sample
        && saved.session_order == actual.session_order
        && saved.transformed_output_sha256 == actual.transformed_output_sha256
        && saved.direction_node_id == actual.direction_node_id
        && saved.episode_node_id == actual.episode_node_id
        && saved.stream_offset == actual.stream_offset
        && saved.parser_format == actual.parser_format
        && saved.expected_session_orders == actual.expected_session_orders
        && saved.payload_range == actual.payload_range
        && saved.preserved_header_end == actual.preserved_header_end
        && saved.bytes == actual.bytes
}

fn verify_aggregate(
    saved: Option<&AppliedOutput>,
    reported: Option<&serde_json::Value>,
    rule: &RelationalTransformRule,
    outputs: &[l2_workbench::protocol::RelationalAppliedOutput],
    context: &mut SchemaCacheRestoreContext<'_, '_>,
) -> Result<(), RecoveryExecutionError> {
    let first = outputs.first().ok_or(RecoveryError::InvalidCheckpoint)?;
    let length = aggregate_size(outputs, context)?;
    let _memory = context
        .memory
        .try_reserve(
            MemoryClass::Executor,
            u64::try_from(context.maximum_workspace_bytes)
                .map_err(|_| RecoveryError::InvalidCheckpoint)?,
        )
        .map_err(|error| operational("saved aggregate verification admission failed", error))?;
    // Join and check the same ordered mappings used by normal publication
    replay::charge(context, length)?;
    let aggregate = concatenate_outputs(outputs, length, context.job)?;
    let work_bytes = aggregate
        .session_work
        .checked_add(length)
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    replay::charge(context, length)?;
    let digest = sha256(&aggregate.bytes);
    if let Some(saved) = saved {
        verify_saved_aggregate(saved, rule, first, &aggregate, work_bytes, &digest)?;
    }
    // A matching byte string must still have one exact artifact boundary
    let mut policy = context.artifact_policy;
    policy.png_limits.max_chunks = policy
        .png_limits
        .max_chunks
        .min((context.maximum_workspace_bytes / 16) / size_of::<PngChunk<'_>>());
    let allowance = (context.maximum_workspace_bytes / 16)
        .min(context.work.remaining_verification_work_bytes());
    let validator = aggregate_validator(policy, length, allowance)?;
    let mut remaining = allowance;
    let outcome =
        validator.validate_as_with_zip_budget(rule.parser_format, &aggregate.bytes, &mut remaining);
    let expansion_work = allowance - remaining;
    replay::charge(context, expansion_work)?;
    if let Some(reported) = reported {
        verify_aggregate_report(
            reported,
            rule,
            &aggregate,
            &digest,
            length,
            expansion_work,
            &outcome,
        )?;
    }
    match outcome {
        ArtifactValidationOutcome::Validated { range, .. }
            if range.offset == 0 && range.length == length =>
        {
            Ok(())
        }
        ArtifactValidationOutcome::Omitted { reason, .. } => Err(operational(
            "saved aggregate parser was resource limited",
            std::io::Error::other(format!("{reason:?}")),
        )),
        _ => Err(RecoveryError::InvalidCheckpoint.into()),
    }
}

fn aggregate_size(
    outputs: &[l2_workbench::protocol::RelationalAppliedOutput],
    context: &SchemaCacheRestoreContext<'_, '_>,
) -> Result<usize, RecoveryExecutionError> {
    let (length, mappings) = outputs
        .iter()
        .try_fold((0_usize, 0_usize), |(bytes, maps), output| {
            Some((
                bytes.checked_add(output.bytes.len())?,
                maps.checked_add(output.payload_mappings.len())?,
            ))
        })
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    let needed = length
        .checked_add(
            mappings
                .checked_mul(8 * size_of::<RelationalOutputMapping>())
                .ok_or(RecoveryError::InvalidCheckpoint)?,
        )
        .and_then(|bytes| bytes.checked_add(outputs.len().checked_mul(size_of::<[usize; 8]>())?))
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    if length > context.relational_limits.max_total_bytes
        || needed > context.maximum_workspace_bytes / 16
    {
        return Err(operational(
            "saved aggregate exceeds verification workspace",
            RecoveryError::InvalidCheckpoint,
        ));
    }
    Ok(length)
}

fn verify_saved_aggregate(
    saved: &AppliedOutput,
    rule: &RelationalTransformRule,
    first: &l2_workbench::protocol::RelationalAppliedOutput,
    aggregate: &AggregateOutput,
    work_bytes: usize,
    digest: &str,
) -> Result<(), RecoveryExecutionError> {
    if saved.parser_format != rule.parser_format
        || saved.session_ids != aggregate.session_ids
        || saved.session_orders != aggregate.session_orders
        || saved.seed_samples != aggregate.seed_samples
        || saved.value.session != first.session
        || saved.value.session_order != first.session_order
        || saved.value.seed_sample != first.seed_sample
        || saved.value.payload_mappings != aggregate.payload_mappings
        || saved.value.bytes != aggregate.bytes
        || saved.value.parser_validation_deferred
        || saved.value.work_bytes != work_bytes
        || saved.sha256 != digest
    {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    Ok(())
}

fn verify_aggregate_report(
    reported: &serde_json::Value,
    rule: &RelationalTransformRule,
    aggregate: &AggregateOutput,
    digest: &str,
    length: usize,
    expansion_work: usize,
    outcome: &ArtifactValidationOutcome<'_>,
) -> Result<(), RecoveryExecutionError> {
    let parser_work = length
        .checked_add(expansion_work)
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    if reported.get("status") != Some(&serde_json::json!("validated_exact_range"))
        || reported.get("accepted") != Some(&serde_json::Value::Bool(true))
        || reported.get("parser_scope") != Some(&serde_json::json!("across_sessions"))
        || reported.get("parser_format")
            != Some(&serde_json::json!(format!("{:?}", rule.parser_format)))
        || reported.get("sessions") != Some(&serde_json::json!(aggregate.session_ids))
        || reported.get("length") != Some(&serde_json::json!(length))
        || reported.get("sha256") != Some(&serde_json::json!(digest))
        || reported.get("parser_work_bytes") != Some(&serde_json::json!(parser_work))
        || reported.get("result") != Some(&serde_json::json!(format!("{outcome:?}")))
    {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    Ok(())
}
