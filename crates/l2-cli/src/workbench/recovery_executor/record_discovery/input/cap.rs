use super::super::super::RecoveryExecutionError;
use super::{
    MAX_OMISSION_EXAMPLES, OmissionKind, RecordDiscoveryPlan, RecordFrameInput, invalid_work,
    operational,
};
use l2_workbench::{protocol::RecordSchemaProposalLimits, recovery::RecoveryError};

struct LearningPrefix {
    retained_by_session: Vec<usize>,
    messages: usize,
    bytes: usize,
}

struct OmissionBatch {
    reason: OmissionKind,
    count: usize,
    examples: Vec<u64>,
}

struct CappedCohort {
    retained_inputs: Vec<RecordFrameInput>,
    omitted_frames: usize,
    omission_batches: Vec<OmissionBatch>,
}

pub(super) fn cap_cohorts(
    plan: &mut RecordDiscoveryPlan,
    limits: RecordSchemaProposalLimits,
) -> Result<(), RecoveryExecutionError> {
    let cohorts = std::mem::take(&mut plan.cohorts);
    let maximum_messages = limits
        .discovery
        .max_messages
        .min(limits.discovery.record_limits.max_records);
    let maximum_bytes = limits.discovery.record_limits.max_input_bytes;
    for (key, inputs) in cohorts {
        cap_cohort(plan, &key, inputs, maximum_messages, maximum_bytes)?;
    }
    Ok(())
}

fn cap_cohort(
    plan: &mut RecordDiscoveryPlan,
    key: &super::RecordCohortKey,
    mut inputs: Vec<RecordFrameInput>,
    maximum_messages: usize,
    maximum_bytes: usize,
) -> Result<(), RecoveryExecutionError> {
    inputs.sort_by_key(|input| {
        (
            input.session_id,
            input.session_node_id,
            input.stream_offset,
            input.stream_range.start,
            input.frame_index,
            input.node_id,
        )
    });
    let session_ranges = cohort_session_ranges(&inputs)?;
    let prefix = learning_prefix(&inputs, &session_ranges, maximum_messages, maximum_bytes)?;
    let capped = collect_capped_inputs(
        &inputs,
        &session_ranges,
        &prefix,
        maximum_messages,
        maximum_bytes,
    )?;

    // Keep every validated frame for application while learning uses bounded prefixes
    plan.application_cohorts.insert(key.clone(), inputs);
    plan.cohorts.insert(key.clone(), capped.retained_inputs);
    if capped.omitted_frames > 0 {
        plan.cohort_omitted_frames
            .insert(key.clone(), capped.omitted_frames);
    }
    for batch in capped.omission_batches {
        plan.record_omissions(&key.source_id, batch.reason, batch.count, &batch.examples)?;
    }
    Ok(())
}

fn cohort_session_ranges(
    inputs: &[RecordFrameInput],
) -> Result<Vec<(usize, usize)>, RecoveryExecutionError> {
    let mut ranges = Vec::new();
    ranges
        .try_reserve(inputs.len())
        .map_err(|error| operational("record discovery session allocation failed", error))?;
    let mut session_start = 0_usize;
    for session in inputs.chunk_by(|left, right| left.session_node_id == right.session_node_id) {
        let session_end = session_start
            .checked_add(session.len())
            .ok_or_else(|| invalid_work("record discovery session range overflowed"))?;
        ranges.push((session_start, session_end));
        session_start = session_end;
    }
    Ok(ranges)
}

fn learning_prefix(
    inputs: &[RecordFrameInput],
    session_ranges: &[(usize, usize)],
    maximum_messages: usize,
    maximum_bytes: usize,
) -> Result<LearningPrefix, RecoveryExecutionError> {
    // Give each session one next frame per turn so long sessions cannot use the full budget first
    let mut next_sessions = std::collections::VecDeque::new();
    next_sessions
        .try_reserve(session_ranges.len())
        .map_err(|error| operational("record discovery scheduling allocation failed", error))?;
    next_sessions.extend(0..session_ranges.len());

    let mut prefix = LearningPrefix {
        retained_by_session: Vec::new(),
        messages: 0,
        bytes: 0,
    };
    prefix
        .retained_by_session
        .try_reserve_exact(session_ranges.len())
        .map_err(|error| operational("record discovery session allocation failed", error))?;
    prefix
        .retained_by_session
        .resize(session_ranges.len(), 0_usize);

    while prefix.messages < maximum_messages {
        let Some(session_index) = next_sessions.pop_front() else {
            break;
        };
        let (session_start, session_end) = session_ranges
            .get(session_index)
            .copied()
            .ok_or(RecoveryError::InvariantFailure)?;
        let retained_in_session = prefix
            .retained_by_session
            .get(session_index)
            .copied()
            .ok_or(RecoveryError::InvariantFailure)?;
        let input_index = session_start
            .checked_add(retained_in_session)
            .ok_or_else(|| invalid_work("record discovery session cursor overflowed"))?;
        if input_index >= session_end {
            continue;
        }

        let input = inputs
            .get(input_index)
            .ok_or(RecoveryError::InvariantFailure)?;
        let next_bytes = prefix
            .bytes
            .checked_add(input.byte_length)
            .ok_or_else(|| invalid_work("record discovery retained byte count overflowed"))?;
        if next_bytes > maximum_bytes {
            // A session stops at its first frame that cannot fit the shared byte cap
            continue;
        }

        let retained_count = prefix
            .retained_by_session
            .get_mut(session_index)
            .ok_or(RecoveryError::InvariantFailure)?;
        *retained_count = retained_count
            .checked_add(1)
            .ok_or_else(|| invalid_work("record discovery retained frame count overflowed"))?;
        prefix.messages = prefix
            .messages
            .checked_add(1)
            .ok_or_else(|| invalid_work("record discovery retained message count overflowed"))?;
        prefix.bytes = next_bytes;
        if input_index
            .checked_add(1)
            .is_some_and(|next_index| next_index < session_end)
        {
            next_sessions.push_back(session_index);
        }
    }
    Ok(prefix)
}

fn collect_capped_inputs(
    inputs: &[RecordFrameInput],
    session_ranges: &[(usize, usize)],
    prefix: &LearningPrefix,
    maximum_messages: usize,
    maximum_bytes: usize,
) -> Result<CappedCohort, RecoveryExecutionError> {
    let retained_count = prefix.messages.min(inputs.len());
    let mut retained_inputs = Vec::new();
    retained_inputs
        .try_reserve_exact(retained_count)
        .map_err(|error| operational("record discovery retained input allocation failed", error))?;
    let mut omission_batches = Vec::<OmissionBatch>::new();
    for (session_index, (session_start, session_end)) in session_ranges.iter().copied().enumerate()
    {
        let retained_in_session = prefix
            .retained_by_session
            .get(session_index)
            .copied()
            .ok_or(RecoveryError::InvariantFailure)?;
        let retained_end = session_start
            .checked_add(retained_in_session)
            .ok_or_else(|| invalid_work("record discovery retained range overflowed"))?;
        let retained_session = inputs
            .get(session_start..retained_end)
            .ok_or(RecoveryError::InvariantFailure)?;
        retained_inputs.extend(retained_session.iter().cloned());
        if retained_end == session_end {
            continue;
        }

        let first_omitted = inputs
            .get(retained_end)
            .ok_or(RecoveryError::InvariantFailure)?;
        let byte_blocked = prefix
            .bytes
            .checked_add(first_omitted.byte_length)
            .is_none_or(|total| total > maximum_bytes);
        let message_blocked = prefix.messages >= maximum_messages;
        let reason = omission_reason(message_blocked, byte_blocked)?;
        let omitted_count = session_end
            .checked_sub(retained_end)
            .ok_or(RecoveryError::InvariantFailure)?;
        record_omission_batch(
            &mut omission_batches,
            inputs,
            retained_end,
            session_end,
            reason,
            omitted_count,
        )?;
    }

    let omitted_frames = inputs
        .len()
        .checked_sub(retained_count)
        .ok_or(RecoveryError::InvariantFailure)?;
    Ok(CappedCohort {
        retained_inputs,
        omitted_frames,
        omission_batches,
    })
}

fn omission_reason(
    message_blocked: bool,
    byte_blocked: bool,
) -> Result<OmissionKind, RecoveryExecutionError> {
    match (message_blocked, byte_blocked) {
        (true, true) => Ok(OmissionKind::LearningPrefixMessageCountAndAggregateByteLimits),
        (true, false) => Ok(OmissionKind::LearningPrefixMessageCountLimit),
        (false, true) => Ok(OmissionKind::LearningPrefixAggregateByteLimit),
        (false, false) => Err(RecoveryError::InvariantFailure.into()),
    }
}

fn record_omission_batch(
    batches: &mut Vec<OmissionBatch>,
    inputs: &[RecordFrameInput],
    first_omitted: usize,
    session_end: usize,
    reason: OmissionKind,
    omitted_count: usize,
) -> Result<(), RecoveryExecutionError> {
    if let Some(batch) = batches.iter_mut().find(|batch| batch.reason == reason) {
        return append_omission_batch(batch, inputs, first_omitted, session_end, omitted_count);
    }
    batches
        .try_reserve(1)
        .map_err(|error| operational("record discovery omission allocation failed", error))?;
    let mut batch = OmissionBatch {
        reason,
        count: 0,
        examples: Vec::new(),
    };
    append_omission_batch(
        &mut batch,
        inputs,
        first_omitted,
        session_end,
        omitted_count,
    )?;
    batches.push(batch);
    Ok(())
}

fn append_omission_batch(
    batch: &mut OmissionBatch,
    inputs: &[RecordFrameInput],
    first_omitted: usize,
    session_end: usize,
    omitted_count: usize,
) -> Result<(), RecoveryExecutionError> {
    let omitted_inputs = inputs
        .get(first_omitted..session_end)
        .ok_or(RecoveryError::InvariantFailure)?;
    batch.count = batch
        .count
        .checked_add(omitted_count)
        .ok_or_else(|| invalid_work("record discovery omitted-frame count overflowed"))?;
    let examples_needed = MAX_OMISSION_EXAMPLES.saturating_sub(batch.examples.len());
    let example_count = examples_needed.min(omitted_count);
    batch
        .examples
        .try_reserve(example_count)
        .map_err(|error| operational("record discovery omission allocation failed", error))?;
    batch.examples.extend(
        omitted_inputs
            .iter()
            .take(examples_needed)
            .map(|input| input.node_id),
    );
    Ok(())
}
