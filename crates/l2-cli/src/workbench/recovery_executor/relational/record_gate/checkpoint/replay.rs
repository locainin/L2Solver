//! Replay a cached plan's producing rule against its current source records

use super::restore::SchemaCacheRestoreContext;
use crate::workbench::recovery_executor::{
    RecoveryExecutionError,
    relational::{
        DecodedFrameOutput,
        application::{DecodedFrameContext, decoded_payload_frames},
        operational,
    },
};
use l2_workbench::{
    job::{MemoryClass, MemoryLease},
    protocol::{
        RelationalAppliedOutput, RelationalParserScope, RelationalRecordSample,
        RelationalTransformRule, apply_relational_transform_rule,
    },
    recovery::RecoveryError,
};

pub(in crate::workbench::recovery_executor::relational) struct ReplayedFrames {
    pub(in crate::workbench::recovery_executor::relational) frames: Vec<DecodedFrameOutput>,
    pub(in crate::workbench::recovery_executor::relational) outputs: Vec<RelationalAppliedOutput>,
    // The byte views and copied mappings are dropped before their admission
    _memory: MemoryLease,
}

pub(in crate::workbench::recovery_executor::relational) fn replay(
    rule: &RelationalTransformRule,
    context: &mut SchemaCacheRestoreContext<'_, '_>,
) -> Result<ReplayedFrames, RecoveryExecutionError> {
    if rule.parser_scope != RelationalParserScope::AcrossSessions {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    let session_count = context
        .report
        .discovery_sessions
        .len()
        .checked_add(context.report.heldout_sessions.len())
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    let scan_work = context
        .samples
        .len()
        .checked_mul(2 * size_of::<RelationalRecordSample<'_>>())
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    charge(context, scan_work)?;
    if let Some(job) = context.job {
        job.check_cancelled()?;
    }
    let admitted_bytes = replay_memory(context.samples, session_count)?;
    let memory = context
        .memory
        .try_reserve(MemoryClass::Executor, admitted_bytes)
        .map_err(|error| operational("schema checkpoint replay admission failed", error))?;
    let bounds = scan_samples(context, session_count)?;
    let outputs = replay_outputs(rule, context, &bounds)?;
    let frames = materialize_frames(rule, context, &bounds, &outputs)?;
    Ok(ReplayedFrames {
        frames,
        outputs,
        _memory: memory,
    })
}

struct ReplayBounds {
    session_count: usize,
    input_bytes: usize,
    context_bytes: usize,
    longest_context: usize,
}

fn scan_samples(
    context: &SchemaCacheRestoreContext<'_, '_>,
    session_count: usize,
) -> Result<ReplayBounds, RecoveryExecutionError> {
    let mut input_bytes = 0_usize;
    let mut context_bytes = 0_usize;
    let mut longest_context = 0_usize;
    for (index, sample) in context.samples.iter().enumerate() {
        if index.is_multiple_of(256)
            && let Some(job) = context.job
        {
            job.check_cancelled()?;
        }
        let strings = sample
            .context
            .source
            .len()
            .checked_add(sample.context.scope.len())
            .ok_or(RecoveryError::InvalidCheckpoint)?;
        input_bytes = input_bytes
            .checked_add(sample.bytes.len())
            .ok_or(RecoveryError::InvalidCheckpoint)?;
        context_bytes = context_bytes
            .checked_add(strings)
            .ok_or(RecoveryError::InvalidCheckpoint)?;
        longest_context = longest_context.max(strings);
    }
    Ok(ReplayBounds {
        session_count,
        input_bytes,
        context_bytes,
        longest_context,
    })
}

fn replay_outputs(
    rule: &RelationalTransformRule,
    context: &mut SchemaCacheRestoreContext<'_, '_>,
    bounds: &ReplayBounds,
) -> Result<Vec<RelationalAppliedOutput>, RecoveryExecutionError> {
    let mut outputs = Vec::new();
    outputs
        .try_reserve_exact(bounds.session_count)
        .map_err(|error| operational("schema checkpoint output allocation failed", error))?;
    for session in context
        .report
        .discovery_sessions
        .iter()
        .chain(&context.report.heldout_sessions)
    {
        if let Some(job) = context.job {
            job.check_cancelled()?;
        }
        let lookup = context
            .samples
            .len()
            .checked_mul(
                rule.seed_locator
                    .marker
                    .len()
                    .checked_add(rule.payload_locator.marker.len())
                    .and_then(|bytes| bytes.checked_add(4 * size_of::<usize>()))
                    .ok_or(RecoveryError::InvalidCheckpoint)?,
            )
            .and_then(|bytes| bytes.checked_add(bounds.context_bytes))
            .ok_or(RecoveryError::InvalidCheckpoint)?;
        charge(context, lookup)?;
        let mut samples = Vec::new();
        samples
            .try_reserve_exact(context.samples.len())
            .map_err(|error| operational("schema checkpoint input allocation failed", error))?;
        for sample in context.samples {
            if sample.context.source == session.source
                && sample.context.scope == session.scope
                && sample.context.session == session.session
            {
                samples.push(sample.clone());
            }
        }
        // The existing executor checks this exclusive allowance before transforming bytes
        let allowance = context.work.remaining_verification_work_bytes();
        let output =
            apply_relational_transform_rule(&samples, rule, context.relational_limits, allowance);
        // A failed transform does not report partial work, so consume its whole allowance
        let output = match output {
            Ok(output) => output,
            Err(error) => {
                charge(context, allowance)?;
                return Err(match error {
                    l2_workbench::protocol::RelationalTransformError::InvalidPlan(_)
                    | l2_workbench::protocol::RelationalTransformError::InvalidInput(_)
                    | l2_workbench::protocol::RelationalTransformError::RuleContradicted(_) => {
                        RecoveryError::InvalidCheckpoint.into()
                    }
                    error => error.into(),
                });
            }
        };
        charge(context, output.work_bytes)?;
        outputs.push(output);
    }
    outputs.sort_unstable_by_key(|output| output.session_order);
    Ok(outputs)
}

fn materialize_frames(
    rule: &RelationalTransformRule,
    context: &mut SchemaCacheRestoreContext<'_, '_>,
    bounds: &ReplayBounds,
    outputs: &[RelationalAppliedOutput],
) -> Result<Vec<DecodedFrameOutput>, RecoveryExecutionError> {
    let mut orders = Vec::new();
    orders
        .try_reserve_exact(outputs.len())
        .map_err(|error| operational("schema checkpoint order allocation failed", error))?;
    orders.extend(outputs.iter().map(|output| output.session_order));
    let frame_context = DecodedFrameContext {
        samples: context.samples,
        stored_samples: context.stored_samples,
        candidate_index: 0,
        expected_session_orders: &orders,
        raw_directional_run: context.raw_directional_run,
        job: context.job,
    };
    let mut frames = Vec::new();
    for output in outputs {
        if let Some(job) = context.job {
            job.check_cancelled()?;
        }
        let per_frame = context
            .samples
            .len()
            .checked_add(context.stored_samples.len())
            .and_then(|count| count.checked_mul(size_of::<u64>()))
            .and_then(|bytes| {
                bytes.checked_add(bounds.session_count.checked_mul(size_of::<u64>())?)
            })
            .and_then(|bytes| bytes.checked_add(bounds.longest_context.checked_mul(3)?))
            .ok_or(RecoveryError::InvalidCheckpoint)?;
        let materialization_work = output
            .payload_mappings
            .len()
            .checked_mul(per_frame)
            .and_then(|bytes| bytes.checked_add(bounds.input_bytes))
            .and_then(|bytes| bytes.checked_add(output.bytes.len().checked_mul(2)?))
            .ok_or(RecoveryError::InvalidCheckpoint)?;
        // Each mapped payload searches the source indexes and copies a full framed record
        charge(context, materialization_work)?;
        let digest = l2_workbench::sha256(&output.bytes);
        let mut decoded = decoded_payload_frames(&frame_context, output, rule, &digest)?;
        frames
            .try_reserve(decoded.len())
            .map_err(|error| operational("schema checkpoint frame allocation failed", error))?;
        frames.append(&mut decoded);
    }
    Ok(frames)
}

fn replay_memory(
    samples: &[RelationalRecordSample<'_>],
    sessions: usize,
) -> Result<u64, RecoveryExecutionError> {
    let bytes = samples
        .iter()
        .try_fold(0_usize, |total, sample| {
            total
                .checked_add(sample.bytes.len())?
                .checked_add(sample.context.source.len())?
                .checked_add(sample.context.scope.len())
        })
        .and_then(|bytes| bytes.checked_mul(8));
    let entries = samples.len().checked_mul(
        8 * (size_of::<RelationalRecordSample<'_>>()
            + size_of::<RelationalAppliedOutput>()
            + size_of::<DecodedFrameOutput>()),
    );
    bytes
        .zip(entries)
        .and_then(|(bytes, entries)| bytes.checked_add(entries))
        .and_then(|bytes| {
            bytes.checked_add(
                samples
                    .len()
                    .checked_mul(sessions)?
                    .checked_mul(4 * size_of::<u64>())?,
            )
        })
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(|| RecoveryError::InvalidCheckpoint.into())
}

pub(in crate::workbench::recovery_executor::relational) fn charge(
    context: &mut SchemaCacheRestoreContext<'_, '_>,
    bytes: usize,
) -> Result<(), RecoveryExecutionError> {
    if !context.work.try_charge_verification(bytes) {
        return Err(operational(
            "schema checkpoint verification work limit reached",
            l2_workbench::protocol::RelationalCursorError::<std::convert::Infallible>::RestoreWorkLimit,
        ));
    }
    Ok(())
}
