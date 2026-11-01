//! Check saved positive schema evidence against freshly replayed source bytes

use super::{replay, restore::SchemaCacheRestoreContext};
use crate::workbench::recovery_executor::{
    RecoveryExecutionError,
    relational::{
        DecodedFrameOutput, aggregate_validator, application::validate_accepted_record_schema,
        operational, record_gate::AcceptedRecordSchema,
    },
};
use l2_workbench::{
    artifact::{ArtifactValidationOutcome, PngChunk},
    job::MemoryClass,
    protocol::{
        RecordAssemblyInput, RecordInput, RecordLimits, RecordParseReport, RecordWorkBudget,
        assemble_record_groups_from_inputs,
    },
    recovery::RecoveryError,
};
use std::borrow::Cow;

pub(in crate::workbench::recovery_executor::relational) fn verify(
    accepted: &AcceptedRecordSchema,
    frames: &[DecodedFrameOutput],
    mut limits: RecordLimits,
    context: &mut SchemaCacheRestoreContext<'_, '_>,
) -> Result<(), RecoveryExecutionError> {
    if accepted.frame_indices.is_empty() || accepted.frame_indices.len() > frames.len() {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    // Parsing, assembly, and validation share one bounded temporary workspace
    let _memory = context
        .memory
        .try_reserve(
            MemoryClass::Executor,
            u64::try_from(context.maximum_workspace_bytes)
                .map_err(|_| RecoveryError::InvalidCheckpoint)?,
        )
        .map_err(|error| operational("schema checkpoint validation admission failed", error))?;
    let logical_workspace = context.maximum_workspace_bytes / 16;
    let frame_storage = accepted
        .frame_indices
        .len()
        .checked_mul(
            size_of::<RecordInput<'_>>()
                + size_of::<RecordParseReport>()
                + size_of::<RecordAssemblyInput<'_>>(),
        )
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    if logical_workspace == 0 || frame_storage > logical_workspace {
        return Err(operational(
            "schema checkpoint validation workspace is too small",
            RecoveryError::InvalidCheckpoint,
        ));
    }
    limits.max_report_bytes = limits.max_report_bytes.min(logical_workspace);
    limits.max_output_bytes = limits.max_output_bytes.min(logical_workspace);
    let inputs = collect_inputs(accepted, frames)?;
    let mut reports = Vec::new();
    reports
        .try_reserve_exact(inputs.len())
        .map_err(|error| operational("schema checkpoint report allocation failed", error))?;
    let mut work = RecordWorkBudget::new(context.work.remaining_verification_work_bytes());
    let mut metadata_bytes = 0_usize;
    let parsed = (|| {
        for input in &inputs {
            if let Some(job) = context.job {
                job.check_cancelled()?;
            }
            let mut parse_limits = limits;
            parse_limits.max_report_bytes = limits.max_report_bytes - metadata_bytes;
            let report = input
                .parse_with_work(&accepted.schema, parse_limits, &mut work)
                .map_err(|error| operational("saved record schema no longer parses", error))?;
            metadata_bytes += report.metadata_bytes();
            reports.push(report);
        }
        Ok::<_, RecoveryExecutionError>(())
    })();
    // Failed parsing still consumes verification work, without changing saved search charges
    replay::charge(context, work.consumed())?;
    parsed?;
    validate_accepted_record_schema(0, frames, accepted, |index, _| {
        let position = accepted
            .frame_indices
            .binary_search(&index)
            .map_err(|_| RecoveryError::InvalidCheckpoint)?;
        let report = reports
            .get(position)
            .ok_or(RecoveryError::InvalidCheckpoint)?;
        Ok(Cow::Borrowed(report.input_sha256()))
    })?;
    verify_assembly(
        accepted,
        &inputs,
        &reports,
        metadata_bytes,
        limits,
        logical_workspace,
        context,
    )
}

fn collect_inputs<'a>(
    accepted: &AcceptedRecordSchema,
    frames: &'a [DecodedFrameOutput],
) -> Result<Vec<RecordInput<'a>>, RecoveryExecutionError> {
    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(accepted.frame_indices.len())
        .map_err(|error| operational("schema checkpoint input allocation failed", error))?;
    for index in &accepted.frame_indices {
        let frame = frames.get(*index).ok_or(RecoveryError::InvalidCheckpoint)?;
        inputs.push(RecordInput::new(&frame.bytes));
    }
    Ok(inputs)
}

fn verify_assembly(
    accepted: &AcceptedRecordSchema,
    inputs: &[RecordInput<'_>],
    reports: &[RecordParseReport],
    metadata_bytes: usize,
    limits: RecordLimits,
    logical_workspace: usize,
    context: &mut SchemaCacheRestoreContext<'_, '_>,
) -> Result<(), RecoveryExecutionError> {
    let mut assembly_inputs = Vec::new();
    assembly_inputs
        .try_reserve_exact(inputs.len())
        .map_err(|error| operational("schema checkpoint assembly allocation failed", error))?;
    let mut input_bytes = 0_usize;
    for (input, report) in inputs.iter().zip(reports) {
        input_bytes = input_bytes
            .checked_add(input.bytes().len())
            .ok_or(RecoveryError::InvalidCheckpoint)?;
        assembly_inputs.push(
            RecordAssemblyInput::from_input(input, report)
                .map_err(|_| RecoveryError::InvalidCheckpoint)?,
        );
    }
    let assembly_work = input_bytes
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(metadata_bytes))
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    replay::charge(context, assembly_work)?;
    let assembled = assemble_record_groups_from_inputs(&assembly_inputs, limits)
        .map_err(|error| operational("saved record schema no longer assembles", error))?;
    let group = assembled
        .groups()
        .iter()
        .find(|group| group.receipt() == &accepted.artifact_receipt)
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    let bytes = group.candidate_bytes();
    replay::charge(context, bytes.len())?;
    if let Some(job) = context.job {
        job.check_cancelled()?;
    }
    // The same structural parser must establish the same complete object boundary again
    let mut policy = context.artifact_policy;
    policy.png_limits.max_chunks = policy
        .png_limits
        .max_chunks
        .min(logical_workspace / size_of::<PngChunk<'_>>());
    let expansion_allowance =
        logical_workspace.min(context.work.remaining_verification_work_bytes());
    let validator = aggregate_validator(policy, bytes.len(), expansion_allowance)?;
    let mut expansion_remaining = expansion_allowance;
    let outcome = validator.validate_as_with_zip_budget(
        accepted.artifact_format,
        bytes,
        &mut expansion_remaining,
    );
    replay::charge(context, expansion_allowance - expansion_remaining)?;
    match outcome {
        ArtifactValidationOutcome::Validated { range, .. }
            if range.offset == 0 && range.length == bytes.len() =>
        {
            Ok(())
        }
        ArtifactValidationOutcome::Omitted { reason, .. } => Err(operational(
            "saved artifact verification was resource limited",
            std::io::Error::other(format!("{reason:?}")),
        )),
        _ => Err(RecoveryError::InvalidCheckpoint.into()),
    }
}
