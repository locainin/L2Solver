use super::super::super::RecoveryExecutionError;
use super::super::{DecodedFrameOutput, invalid_policy, operational};
use super::selection::{LearningSelection, select_learning_frames};
use super::{GateStatus, SchemaPlan};
use super::{record_job_work, total_input_bytes};
use l2_workbench::{
    job::{Counter, Job, Phase},
    protocol::{
        RecordSchemaDiscoveryReport, RecordSchemaDiscoverySpace, RecordSchemaProposalLimits,
        RecordSchemaProposalReport, RelationalSessionId, RelationalTransformReport,
        discover_record_schemas, propose_record_schema_space,
    },
};
use serde_json::{Value, json};
use std::collections::BTreeSet;

#[cfg(test)]
#[path = "../../../../../tests/workbench/record_gate_plan.rs"]
mod tests;

const MAX_GATE_SCHEMA_CHECKS: usize = 512;
const MAX_RETAINED_SCHEMA_HYPOTHESES: usize = 128;

struct LearningMessages<'a> {
    training: Vec<&'a [u8]>,
    heldout: Vec<&'a [u8]>,
    learning_bytes: usize,
    full_input_bytes: usize,
}

pub(super) fn build_schema_plan(
    frames: &[DecodedFrameOutput],
    report: &RelationalTransformReport,
    schema_limits: RecordSchemaProposalLimits,
    work_limit: usize,
    job: Option<&Job>,
) -> Result<SchemaPlan, RecoveryExecutionError> {
    let discovery = session_ids(&report.discovery_sessions);
    let heldout = session_ids(&report.heldout_sessions);
    if discovery.is_empty() || frames.is_empty() {
        return Ok(pending_plan(
            schema_limits,
            "no_decoded_discovery_frames",
            &json!({"schema_candidates_examined":0}),
        ));
    }

    let selection = select_learning_frames(
        frames,
        schema_limits.discovery.max_messages,
        &discovery,
        &heldout,
    )?;
    let messages = collect_learning_messages(frames, &selection, &discovery, &heldout)?;
    if messages.training.is_empty()
        || messages.learning_bytes == 0
        || messages.full_input_bytes > work_limit
    {
        return Ok(work_limited_plan(
            schema_limits,
            messages.learning_bytes,
            messages.full_input_bytes,
            work_limit,
        ));
    }

    let Some(limits) = prepare_schema_limits(schema_limits, frames, &messages, work_limit)? else {
        return Ok(work_limited_plan(
            schema_limits,
            messages.learning_bytes,
            messages.full_input_bytes,
            work_limit,
        ));
    };

    if let Some(job) = job {
        job.check_cancelled()?;
    }
    let proposal = match propose_record_schema_space(&messages.training, &messages.heldout, limits)
    {
        Ok(proposal) => proposal,
        Err(error) => {
            return Ok(pending_plan(
                limits,
                "record_schema_analysis_unavailable",
                &json!({"error":error.to_string()}),
            ));
        }
    };
    let Some(mut candidate_space) = proposal.candidate_space.clone() else {
        return Ok(no_candidate_plan(limits, &selection, &proposal));
    };
    add_preserved_header_offsets(&mut candidate_space, frames, limits)?;

    let discovery_report = match discover_record_schemas(
        &messages.training,
        &messages.heldout,
        &candidate_space,
        limits.discovery,
    ) {
        Ok(discovery_report) => discovery_report,
        Err(error) => {
            return Ok(pending_plan(
                limits,
                "record_schema_analysis_unavailable",
                &json!({
                    "error":error.to_string(),
                    "omitted_record_views":proposal.omitted_record_views,
                }),
            ));
        }
    };
    count_schema_candidates(job, discovery_report.examined_combinations)?;
    complete_plan(
        limits,
        &selection,
        &proposal,
        discovery_report,
        messages.learning_bytes,
        work_limit,
    )
}

fn collect_learning_messages<'a>(
    frames: &'a [DecodedFrameOutput],
    selection: &LearningSelection,
    discovery: &BTreeSet<u64>,
    heldout: &BTreeSet<u64>,
) -> Result<LearningMessages<'a>, RecoveryExecutionError> {
    let mut training = Vec::new();
    let mut heldout_messages = Vec::new();
    training
        .try_reserve_exact(selection.indices.len())
        .map_err(|source| operational("record gate training allocation failed", source))?;
    heldout_messages
        .try_reserve_exact(selection.indices.len())
        .map_err(|source| operational("record gate held-out allocation failed", source))?;
    let mut learning_bytes = 0_usize;
    for frame_index in &selection.indices {
        let frame = frames
            .get(*frame_index)
            .ok_or_else(|| invalid_policy("record gate selected a missing frame"))?;
        learning_bytes = learning_bytes
            .checked_add(frame.bytes.len())
            .ok_or_else(|| invalid_policy("record gate learning byte count overflowed"))?;
        if discovery.contains(&frame.context.session) {
            training.push(frame.bytes.as_slice());
        } else if heldout.contains(&frame.context.session) {
            heldout_messages.push(frame.bytes.as_slice());
        }
    }
    let full_input_bytes = total_input_bytes(frames)?;
    Ok(LearningMessages {
        training,
        heldout: heldout_messages,
        learning_bytes,
        full_input_bytes,
    })
}

fn work_limited_plan(
    limits: RecordSchemaProposalLimits,
    learning_bytes: usize,
    full_input_bytes: usize,
    work_limit: usize,
) -> SchemaPlan {
    pending_plan(
        limits,
        "record_schema_work_limit",
        &json!({
            "learning_bytes":learning_bytes,
            "full_input_bytes":full_input_bytes,
            "work_limit":work_limit,
        }),
    )
}

fn prepare_schema_limits(
    initial: RecordSchemaProposalLimits,
    frames: &[DecodedFrameOutput],
    messages: &LearningMessages<'_>,
    work_limit: usize,
) -> Result<Option<RecordSchemaProposalLimits>, RecoveryExecutionError> {
    let Some(mut limits) = bounded_schema_limits(initial, messages.learning_bytes, work_limit)
    else {
        return Ok(None);
    };
    // Keep clear-header candidates bounded by bytes that the transform cannot change
    limits = restrict_header_offsets(limits, frames)?;
    limits.discovery.max_survivors = limits
        .discovery
        .max_survivors
        .min(MAX_RETAINED_SCHEMA_HYPOTHESES);
    limit_record_input(&mut limits, messages.full_input_bytes);
    Ok(Some(limits))
}

fn bounded_schema_limits(
    mut limits: RecordSchemaProposalLimits,
    input_bytes: usize,
    work_limit: usize,
) -> Option<RecordSchemaProposalLimits> {
    let steps = work_limit.checked_div(input_bytes)?;
    if steps < 6 {
        return None;
    }
    // Divide the caller budget across the six independent proposal checks
    let per_domain_limit = steps.checked_div(6)?.clamp(1, MAX_GATE_SCHEMA_CHECKS);
    limits.max_field_checks_per_domain = limits.max_field_checks_per_domain.min(per_domain_limit);
    limits.max_pair_checks = limits.max_pair_checks.min(per_domain_limit);
    limits.max_length_checks = limits.max_length_checks.min(per_domain_limit);
    limits.discovery.max_candidates = limits.discovery.max_candidates.min(per_domain_limit);
    Some(limits)
}

fn restrict_header_offsets(
    mut limits: RecordSchemaProposalLimits,
    frames: &[DecodedFrameOutput],
) -> Result<RecordSchemaProposalLimits, RecoveryExecutionError> {
    if frames
        .iter()
        .all(|frame| frame.preserved_header_end.is_some())
    {
        let prefix_end = frames
            .iter()
            .filter_map(|frame| frame.preserved_header_end)
            .min()
            .ok_or_else(|| invalid_policy("record gate schema plan has no preserved headers"))?;
        limits.max_field_offset = limits.max_field_offset.min(prefix_end);
    }
    Ok(limits)
}

fn limit_record_input(limits: &mut RecordSchemaProposalLimits, full_input_bytes: usize) {
    limits.discovery.record_limits.max_input_bytes = limits
        .discovery
        .record_limits
        .max_input_bytes
        .min(full_input_bytes);
    limits.discovery.record_limits.max_output_bytes = limits
        .discovery
        .record_limits
        .max_output_bytes
        .min(full_input_bytes);
}

fn add_preserved_header_offsets(
    candidate_space: &mut RecordSchemaDiscoverySpace,
    frames: &[DecodedFrameOutput],
    limits: RecordSchemaProposalLimits,
) -> Result<(), RecoveryExecutionError> {
    for data_offset in frames
        .iter()
        .filter_map(|frame| frame.preserved_header_end)
        .filter(|offset| *offset <= limits.max_field_offset)
    {
        if !candidate_space.data_offsets.contains(&data_offset) {
            candidate_space
                .data_offsets
                .try_reserve(1)
                .map_err(|source| {
                    operational("record gate data offset allocation failed", source)
                })?;
            candidate_space.data_offsets.push(data_offset);
        }
    }
    candidate_space.data_offsets.sort_unstable();
    candidate_space.data_offsets.dedup();
    Ok(())
}

fn no_candidate_plan(
    limits: RecordSchemaProposalLimits,
    selection: &LearningSelection,
    proposal: &RecordSchemaProposalReport,
) -> SchemaPlan {
    let status = if proposal.search_exhaustive_within_plan {
        GateStatus::Contradicted
    } else {
        GateStatus::Pending
    };
    SchemaPlan {
        discovery_report: None,
        limits,
        discovery_work_bytes: 0,
        learning_message_count: proposal.training_message_count,
        heldout_message_count: proposal.held_out_message_count,
        omitted_learning_messages: selection.omitted_messages,
        learning_session_count: selection.session_count,
        proposal_search_exhaustive: proposal.search_exhaustive_within_plan,
        status,
        details: json!({
            "reason":"no_record_schema_candidates",
            "schema_candidates_examined":0,
            "omitted_record_views":proposal.omitted_record_views,
            "schema_search_exhaustive":proposal.search_exhaustive_within_plan,
        }),
    }
}

fn count_schema_candidates(
    job: Option<&Job>,
    candidates_examined: usize,
) -> Result<(), RecoveryExecutionError> {
    if let Some(job) = job {
        record_job_work(
            job,
            Phase::FramingRecordDiscovery,
            Counter::CandidatesExamined,
            u64::try_from(candidates_examined).unwrap_or(u64::MAX),
        )?;
    }
    Ok(())
}

fn complete_plan(
    limits: RecordSchemaProposalLimits,
    selection: &LearningSelection,
    proposal: &RecordSchemaProposalReport,
    discovery_report: RecordSchemaDiscoveryReport,
    learning_bytes: usize,
    work_limit: usize,
) -> Result<SchemaPlan, RecoveryExecutionError> {
    let analysis_steps = proposal
        .examined_field_checks
        .checked_add(proposal.examined_pair_checks)
        .and_then(|steps| steps.checked_add(proposal.examined_length_checks))
        .and_then(|steps| steps.checked_add(discovery_report.examined_combinations))
        .ok_or_else(|| invalid_policy("record gate schema work count overflowed"))?;
    let discovery_work_bytes = learning_bytes
        .checked_mul(analysis_steps)
        .ok_or_else(|| invalid_policy("record gate schema work overflowed"))?;
    let proposal_search_exhaustive = proposal.search_exhaustive_within_plan;
    let plan_status = if discovery_report.surviving.is_empty()
        && proposal_search_exhaustive
        && discovery_report.search_exhaustive_within_plan
    {
        GateStatus::Contradicted
    } else {
        GateStatus::Pending
    };
    let status = if discovery_work_bytes > work_limit {
        GateStatus::Pending
    } else {
        plan_status
    };
    let details = complete_plan_details(
        status,
        &discovery_report,
        discovery_work_bytes,
        work_limit,
        proposal,
    );
    Ok(SchemaPlan {
        discovery_report: Some(discovery_report),
        limits,
        discovery_work_bytes,
        learning_message_count: proposal.training_message_count,
        heldout_message_count: proposal.held_out_message_count,
        omitted_learning_messages: selection.omitted_messages,
        learning_session_count: selection.session_count,
        proposal_search_exhaustive,
        details,
        status,
    })
}

fn complete_plan_details(
    status: GateStatus,
    report: &RecordSchemaDiscoveryReport,
    discovery_work_bytes: usize,
    work_limit: usize,
    proposal: &RecordSchemaProposalReport,
) -> Value {
    json!({
        "reason":if status == GateStatus::Pending { "record_schema_work_limit" } else { status.as_str() },
        "schema_candidates_examined":report.examined_combinations,
        "schema_candidates_omitted":report.unexamined_combinations,
        "schema_survivors":report.surviving.len(),
        "omitted_record_views":proposal.omitted_record_views,
        "schema_search_exhaustive":proposal.search_exhaustive_within_plan
            && report.search_exhaustive_within_plan,
        "schema_work_bytes":discovery_work_bytes,
        "work_limit":work_limit,
    })
}

fn pending_plan(
    limits: RecordSchemaProposalLimits,
    reason: &'static str,
    details: &Value,
) -> SchemaPlan {
    SchemaPlan {
        discovery_report: None,
        limits,
        discovery_work_bytes: 0,
        learning_message_count: 0,
        heldout_message_count: 0,
        omitted_learning_messages: 0,
        learning_session_count: 0,
        proposal_search_exhaustive: false,
        status: GateStatus::Pending,
        details: json!({"reason":reason,"details":details}),
    }
}

fn session_ids(sessions: &[RelationalSessionId]) -> BTreeSet<u64> {
    sessions.iter().map(|session| session.session).collect()
}
