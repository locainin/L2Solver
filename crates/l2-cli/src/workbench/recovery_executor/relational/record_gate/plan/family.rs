use super::super::super::super::RecoveryExecutionError;
use super::super::super::{DecodedFrameOutput, invalid_policy, operational};
use super::super::SchemaAlternative;
use super::super::screen::SchemaObserverOptions;
use super::super::selection::LearningSelection;
use super::analysis::{AnalysisRequest, analyze_group};
use super::{LearningMessages, SchemaOffsetScope, prepare_schema_limits};
use l2_workbench::{
    job::Job,
    protocol::{
        DEFAULT_MAX_FAMILY_RANGES, DEFAULT_MAX_FAMILY_REPORT_BYTES, DEFAULT_MAX_FAMILY_SAMPLES,
        Direction, MAX_MESSAGE_BYTES, MessageFamilyLimits, MessageFamilyReport, MessageRole,
        MessageSample, RecordInput, RecordSchemaProposalLimits, discover_message_families,
    },
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;

const MAX_GATE_FAMILY_SELECTORS: usize = 8;
const MAX_GATE_FAMILY_VALUES: usize = 4;
const MAX_FAMILY_WIDTH: usize = 4;

pub(super) struct FamilyAnalysis {
    pub(super) alternatives: Vec<SchemaAlternative>,
    pub(super) details: Value,
    pub(super) work_bytes: usize,
    pub(super) observation_work_bytes: usize,
    pub(super) work_limited: bool,
    pub(super) has_unassigned_messages: bool,
    pub(super) complete: bool,
}

#[derive(Clone, Copy)]
pub(super) struct FamilyAnalysisRequest<'a> {
    pub(super) frames: &'a [DecodedFrameOutput],
    pub(super) inputs: &'a [RecordInput<'a>],
    pub(super) selection: &'a LearningSelection,
    pub(super) discovery_sessions: &'a BTreeSet<u64>,
    pub(super) base_limits: RecordSchemaProposalLimits,
    pub(super) work_limit: usize,
    pub(super) observer: Option<SchemaObserverOptions<'a>>,
    pub(super) offset_scope: SchemaOffsetScope,
    pub(super) job: Option<&'a Job>,
}

struct FamilyGroup {
    training_ids: BTreeSet<u64>,
    heldout_ids: BTreeSet<u64>,
    frames: Vec<usize>,
    details: Value,
    label: String,
}

struct FamilyGroupContext<'a> {
    frames: &'a [DecodedFrameOutput],
    inputs: &'a [RecordInput<'a>],
    base_limits: RecordSchemaProposalLimits,
    work_limit: usize,
    observer: Option<SchemaObserverOptions<'a>>,
    offset_scope: SchemaOffsetScope,
    omitted_learning_messages: usize,
    job: Option<&'a Job>,
}

pub(super) fn build_family_analysis(
    request: &FamilyAnalysisRequest<'_>,
) -> Result<FamilyAnalysis, RecoveryExecutionError> {
    if request.work_limit == 0 {
        return Ok(FamilyAnalysis {
            alternatives: Vec::new(),
            details: json!({"reason":"message_family_work_limit","work_limit":0}),
            work_bytes: 0,
            observation_work_bytes: 0,
            work_limited: true,
            has_unassigned_messages: true,
            complete: false,
        });
    }
    let messages = family_samples(request.frames, request.selection)?;
    let training_ids = training_sample_ids(&messages, request.discovery_sessions);
    let family_report = match discover_message_families(
        &messages,
        &training_ids,
        family_limits(request.base_limits, request.work_limit),
    ) {
        Ok(report) => report,
        Err(error) => {
            return Ok(unavailable_family_analysis(
                &error.to_string(),
                training_ids.len(),
            ));
        }
    };
    finish_family_analysis(request, &family_report, &messages, &training_ids)
}

fn finish_family_analysis(
    request: &FamilyAnalysisRequest<'_>,
    family_report: &MessageFamilyReport,
    messages: &[MessageSample<'_>],
    training_ids: &[u64],
) -> Result<FamilyAnalysis, RecoveryExecutionError> {
    let observation_work_bytes = family_report.observation_coverage.work_units;
    let group_work_limit = request
        .work_limit
        .checked_sub(observation_work_bytes)
        .ok_or_else(|| invalid_policy("family observation work exceeded its allowance"))?;
    let groups = family_groups(family_report, messages, request.selection)?;
    let family_observer = if request.selection.omitted_messages == 0 {
        request.observer
    } else {
        None
    };
    let group_context = FamilyGroupContext {
        frames: request.frames,
        inputs: request.inputs,
        base_limits: request.base_limits,
        work_limit: group_work_limit,
        observer: family_observer,
        offset_scope: request.offset_scope,
        omitted_learning_messages: request.selection.omitted_messages,
        job: request.job,
    };
    let group_analysis = analyze_family_groups(&groups, &group_context)?;
    let has_unassigned_messages = groups_has_unassigned(family_report);
    let work_bytes = observation_work_bytes
        .checked_add(group_analysis.work_bytes)
        .ok_or_else(|| invalid_policy("family work count overflowed"))?;
    let complete = request.selection.omitted_messages == 0
        && family_report.complete
        && group_analysis.complete;
    let details = json!({
        "family_analysis":family_report_details(family_report, messages, training_ids),
        "family_groups":group_analysis.details,
        "family_observation_work_bytes":observation_work_bytes,
        "family_schema_work_bytes":group_analysis.work_bytes,
        "family_work_bytes":work_bytes,
        "family_work_limit":request.work_limit,
        "family_search_complete":complete,
        "family_unassigned_messages":has_unassigned_messages,
        "selection_omitted_messages":request.selection.omitted_messages,
    });
    Ok(FamilyAnalysis {
        alternatives: group_analysis.alternatives,
        details,
        work_bytes,
        observation_work_bytes,
        work_limited: group_analysis.work_limited
            || family_report.observation_coverage.omitted_work_units > 0,
        has_unassigned_messages,
        complete,
    })
}

fn training_sample_ids(
    messages: &[MessageSample<'_>],
    discovery_sessions: &BTreeSet<u64>,
) -> Vec<u64> {
    messages
        .iter()
        .filter(|sample| {
            sample
                .context
                .as_ref()
                .is_some_and(|context| discovery_sessions.contains(&context.session))
        })
        .map(|sample| sample.sample)
        .collect()
}

fn family_limits(
    base_limits: RecordSchemaProposalLimits,
    work_limit: usize,
) -> MessageFamilyLimits {
    MessageFamilyLimits {
        max_samples: DEFAULT_MAX_FAMILY_SAMPLES,
        // The record-input allowance spans messages; this ceiling applies to one message
        max_message_bytes: base_limits
            .discovery
            .record_limits
            .max_input_bytes
            .min(MAX_MESSAGE_BYTES),
        max_total_bytes: base_limits
            .discovery
            .record_limits
            .max_input_bytes
            .min(l2_workbench::protocol::MAX_PROTOCOL_BYTES),
        max_selector_offset: base_limits.max_field_offset.min(15),
        max_selector_width: MAX_FAMILY_WIDTH,
        min_training_sessions_per_family: 2,
        max_candidate_ranges: DEFAULT_MAX_FAMILY_RANGES,
        max_selectors: MAX_GATE_FAMILY_SELECTORS,
        max_families_per_selector: MAX_GATE_FAMILY_VALUES,
        max_work_units: work_limit.min(1_000_000),
        max_report_bytes: DEFAULT_MAX_FAMILY_REPORT_BYTES / 2,
    }
}

fn unavailable_family_analysis(error: &str, training_count: usize) -> FamilyAnalysis {
    FamilyAnalysis {
        alternatives: Vec::new(),
        details: json!({
            "reason":"message_family_analysis_unavailable",
            "error":error,
            "training_samples":training_count,
        }),
        work_bytes: 0,
        observation_work_bytes: 0,
        work_limited: false,
        has_unassigned_messages: true,
        complete: false,
    }
}

struct FamilyGroupsAnalysis {
    alternatives: Vec<SchemaAlternative>,
    details: Vec<Value>,
    work_bytes: usize,
    work_limited: bool,
    complete: bool,
}

fn analyze_family_groups(
    groups: &[FamilyGroup],
    context: &FamilyGroupContext<'_>,
) -> Result<FamilyGroupsAnalysis, RecoveryExecutionError> {
    let per_group_budget = context
        .work_limit
        .checked_div(groups.len().max(1))
        .unwrap_or(0);
    let mut alternatives = Vec::new();
    let maximum_alternatives = groups.len().saturating_mul(2);
    alternatives
        .try_reserve_exact(maximum_alternatives)
        .map_err(|source| operational("family schema alternative allocation failed", source))?;
    let mut work_bytes = 0_usize;
    let mut work_limited = false;
    let mut group_details = Vec::new();
    group_details
        .try_reserve_exact(groups.len())
        .map_err(|source| operational("family schema report allocation failed", source))?;
    let mut complete = true;
    for group in groups {
        if let Some(job) = context.job {
            job.check_cancelled()?;
        }
        let group_analysis = analyze_family_group(group, context, per_group_budget)?;
        let next_work = work_bytes
            .checked_add(group_analysis.work_bytes)
            .ok_or_else(|| invalid_policy("family schema work count overflowed"))?;
        if next_work > context.work_limit {
            complete = false;
            work_limited = true;
            group_details.push(json!({
                "label":group.label,
                "reason":"record_schema_work_limit",
                "family":group.details,
                "requested_work_bytes":group_analysis.work_bytes,
                "remaining_work_bytes":context.work_limit.saturating_sub(work_bytes),
            }));
            break;
        }
        work_bytes = next_work;
        work_limited |= group_analysis.work_limited;
        complete &= group_analysis.complete;
        group_details.push(group_analysis.details);
        alternatives.extend(group_analysis.alternatives);
    }
    Ok(FamilyGroupsAnalysis {
        alternatives,
        details: group_details,
        work_bytes,
        work_limited,
        complete,
    })
}

struct FamilyGroupResult {
    alternatives: Vec<SchemaAlternative>,
    details: Value,
    work_bytes: usize,
    work_limited: bool,
    complete: bool,
}

fn analyze_family_group(
    group: &FamilyGroup,
    context: &FamilyGroupContext<'_>,
    work_limit: usize,
) -> Result<FamilyGroupResult, RecoveryExecutionError> {
    let FamilyGroupContext {
        frames,
        base_limits,
        observer,
        offset_scope,
        omitted_learning_messages,
        job,
        ..
    } = context;
    let messages = collect_group_messages(frames, group)?;
    let analysis_budget = if observer.is_some() {
        work_limit.checked_div(2).unwrap_or(0)
    } else {
        work_limit
    };
    let limits = prepare_schema_limits(
        *base_limits,
        frames,
        messages.training_indices.as_slice(),
        &messages,
        *offset_scope,
    )?;
    let frame_indices = frame_slice(group.frames.as_slice())?;
    let request = AnalysisRequest {
        label: &group.label,
        family_details: Some(&group.details),
        frame_indices: Some(frame_indices),
        messages: &messages,
        inputs: context.inputs,
        limits,
        work_limit,
        analysis_work_limit: analysis_budget,
        observer_work_limit: work_limit.saturating_sub(analysis_budget),
        observer: *observer,
        omitted_learning_messages: *omitted_learning_messages,
        job: *job,
    };
    let analysis = analyze_group(&request)?;
    Ok(FamilyGroupResult {
        alternatives: analysis.alternatives,
        details: analysis.details,
        work_bytes: analysis.work_bytes,
        work_limited: analysis.work_limited,
        complete: analysis.exhaustive,
    })
}

fn family_samples<'a>(
    frames: &'a [DecodedFrameOutput],
    selection: &LearningSelection,
) -> Result<Vec<MessageSample<'a>>, RecoveryExecutionError> {
    let mut samples = Vec::new();
    samples
        .try_reserve_exact(selection.indices.len())
        .map_err(|source| operational("family observation sample allocation failed", source))?;
    for index in &selection.indices {
        let frame = frames
            .get(*index)
            .ok_or_else(|| invalid_policy("family selector references a missing frame"))?;
        samples.push(MessageSample {
            sample: frame.input_node_id,
            role: MessageRole::Unclassified,
            bytes: &frame.bytes,
            context: Some(frame.context.clone()),
        });
    }
    Ok(samples)
}

fn family_groups(
    family_report: &l2_workbench::protocol::MessageFamilyReport,
    messages: &[MessageSample<'_>],
    selection: &LearningSelection,
) -> Result<Vec<FamilyGroup>, RecoveryExecutionError> {
    let mut groups = Vec::new();
    for (selector_index, selector) in family_report
        .selectors
        .iter()
        .take(MAX_GATE_FAMILY_SELECTORS)
        .enumerate()
    {
        if !selector.training_coverage_complete {
            continue;
        }
        for (family_index, family) in selector
            .families
            .iter()
            .take(MAX_GATE_FAMILY_VALUES)
            .enumerate()
        {
            let training_ids = family
                .training_samples
                .iter()
                .copied()
                .collect::<BTreeSet<_>>();
            let heldout_ids = family
                .heldout_samples
                .iter()
                .copied()
                .collect::<BTreeSet<_>>();
            let mut frame_indices = Vec::new();
            frame_indices
                .try_reserve_exact(training_ids.len().saturating_add(heldout_ids.len()))
                .map_err(|source| {
                    operational("family frame selection allocation failed", source)
                })?;
            for (position, sample) in messages.iter().enumerate() {
                if training_ids.contains(&sample.sample) || heldout_ids.contains(&sample.sample) {
                    frame_indices.push(
                        *selection
                            .indices
                            .get(position)
                            .ok_or_else(|| invalid_policy("family frame index is missing"))?,
                    );
                }
            }
            if training_ids.len() < 2 || frame_indices.len() < training_ids.len() {
                continue;
            }
            let range = selector.range;
            let family_value = hex(&family.value);
            let details = json!({
                "selector_range":{"start":range.start,"end":range.end},
                "selector_value_hex":family_value,
                "selector_training_support":family.training_samples,
                "selector_training_sessions":family.training_sessions,
                "selector_heldout_support":family.heldout_samples,
                "selector_heldout_sessions":family.heldout_sessions,
                "selector_cohort":{
                    "source":selector.cohort.source,
                    "scope":selector.cohort.scope,
                    "direction":direction_name(selector.cohort.direction),
                },
                "unassigned_samples":selector.unassigned.iter().map(|sample| json!({
                    "sample":sample.sample,
                    "reason":sample.reason.as_str(),
                })).collect::<Vec<_>>(),
                "omitted_families":selector.omitted_families,
            });
            groups.push(FamilyGroup {
                training_ids,
                heldout_ids,
                frames: frame_indices,
                details,
                label: format!("family_selector_{selector_index}_value_{family_index}"),
            });
        }
    }
    Ok(groups)
}

fn collect_group_messages<'a>(
    frames: &'a [DecodedFrameOutput],
    group: &FamilyGroup,
) -> Result<LearningMessages<'a>, RecoveryExecutionError> {
    let mut training = Vec::new();
    let mut heldout = Vec::new();
    let mut training_indices = Vec::new();
    let mut heldout_indices = Vec::new();
    let mut training_data_offsets = Vec::new();
    let mut training_sessions = BTreeSet::new();
    let input_bytes = total_frame_bytes(frames, &group.frames)?;
    training
        .try_reserve_exact(group.training_ids.len())
        .map_err(|source| operational("family training messages allocation failed", source))?;
    heldout
        .try_reserve_exact(group.heldout_ids.len())
        .map_err(|source| operational("family held-out messages allocation failed", source))?;
    training_indices
        .try_reserve_exact(group.training_ids.len())
        .map_err(|source| operational("family training index allocation failed", source))?;
    heldout_indices
        .try_reserve_exact(group.heldout_ids.len())
        .map_err(|source| operational("family held-out index allocation failed", source))?;
    training_data_offsets
        .try_reserve_exact(group.training_ids.len())
        .map_err(|source| operational("family offset allocation failed", source))?;
    let mut learning_bytes = 0_usize;
    let mut eligible_input_bytes = 0_usize;
    for index in &group.frames {
        let frame = frames
            .get(*index)
            .ok_or_else(|| invalid_policy("family group references a missing frame"))?;
        if group.training_ids.contains(&frame.input_node_id) {
            learning_bytes = learning_bytes
                .checked_add(frame.bytes.len())
                .ok_or_else(|| invalid_policy("family training byte count overflowed"))?;
            training.push(frame.bytes.as_slice());
            training_indices.push(*index);
            eligible_input_bytes = eligible_input_bytes
                .checked_add(frame.bytes.len())
                .ok_or_else(|| invalid_policy("family eligible input count overflowed"))?;
            training_sessions.insert(frame.context.session);
            if let Some(offset) = frame.preserved_header_end {
                training_data_offsets.push(offset);
            }
        } else if group.heldout_ids.contains(&frame.input_node_id) {
            heldout.push(frame.bytes.as_slice());
            heldout_indices.push(*index);
            eligible_input_bytes = eligible_input_bytes
                .checked_add(frame.bytes.len())
                .ok_or_else(|| invalid_policy("family eligible input count overflowed"))?;
        }
    }
    Ok(LearningMessages {
        training,
        heldout,
        all_training_indices: training_indices.clone(),
        all_heldout_indices: heldout_indices.clone(),
        training_indices,
        heldout_indices,
        training_data_offsets,
        learning_bytes,
        eligible_input_bytes,
        full_input_bytes: input_bytes,
        training_session_count: training_sessions.len(),
    })
}

fn total_frame_bytes(
    frames: &[DecodedFrameOutput],
    indices: &[usize],
) -> Result<usize, RecoveryExecutionError> {
    indices.iter().try_fold(0_usize, |total, index| {
        let length = frames
            .get(*index)
            .ok_or_else(|| invalid_policy("family byte count references a missing frame"))?
            .bytes
            .len();
        total
            .checked_add(length)
            .ok_or_else(|| invalid_policy("family byte count overflowed"))
    })
}

fn frame_slice(indices: &[usize]) -> Result<Arc<[usize]>, RecoveryExecutionError> {
    let mut retained = Vec::new();
    retained
        .try_reserve_exact(indices.len())
        .map_err(|source| operational("family frame index allocation failed", source))?;
    retained.extend_from_slice(indices);
    Ok(Arc::from(retained))
}

fn family_report_details(
    report: &l2_workbench::protocol::MessageFamilyReport,
    samples: &[MessageSample<'_>],
    training_samples: &[u64],
) -> Value {
    let assigned_samples = report
        .selectors
        .iter()
        .flat_map(|selector| &selector.families)
        .flat_map(|family| {
            family
                .training_samples
                .iter()
                .chain(&family.heldout_samples)
        })
        .copied()
        .collect::<BTreeSet<_>>();
    let unassigned_samples = samples
        .iter()
        .filter(|sample| !assigned_samples.contains(&sample.sample))
        .map(|sample| {
            json!({
                "sample":sample.sample,
                "partition":if training_samples.contains(&sample.sample) { "training" } else { "heldout" },
                "reason":"not_assigned_to_retained_family",
                "context":context_details(sample.context.as_ref()),
            })
        })
        .collect::<Vec<_>>();
    json!({
        "selectors_examined":report.selectors.len(),
        "selectors_omitted":report.omitted_selectors,
        "samples_seen":report.samples_seen,
        "training_samples":report.training_samples,
        "heldout_samples":report.heldout_samples,
        "candidate_ranges_omitted":report.omitted_candidate_ranges,
        "observation_complete":report.observation_coverage.complete,
        "family_analysis_complete":report.complete,
        "unassigned_samples":unassigned_samples,
        "selectors":report.selectors.iter().map(|selector| json!({
            "range":{"start":selector.range.start,"end":selector.range.end},
            "source":selector.cohort.source,
            "scope":selector.cohort.scope,
            "direction":direction_name(selector.cohort.direction),
            "families":selector.families.iter().map(|family| json!({
                "value_hex":hex(&family.value),
                "training_samples":family.training_samples,
                "training_sessions":family.training_sessions,
                "heldout_samples":family.heldout_samples,
                "heldout_sessions":family.heldout_sessions,
            })).collect::<Vec<_>>(),
            "unassigned":selector.unassigned.iter().map(|sample| json!({
                "sample":sample.sample,
                "value_hex":sample.value.as_deref().map(hex),
                "reason":sample.reason.as_str(),
                "context":samples.iter().find(|input| input.sample == sample.sample)
                    .map_or(Value::Null, |input| context_details(input.context.as_ref())),
            })).collect::<Vec<_>>(),
            "training_coverage_complete":selector.training_coverage_complete,
            "omitted_families":selector.omitted_families,
        })).collect::<Vec<_>>(),
    })
}

fn context_details(context: Option<&l2_workbench::protocol::MessageContext>) -> Value {
    context.map_or(Value::Null, |context| {
        json!({
            "source":context.source,
            "scope":context.scope,
            "session":context.session,
            "direction":direction_name(context.direction),
        })
    })
}

fn groups_has_unassigned(report: &l2_workbench::protocol::MessageFamilyReport) -> bool {
    (report.samples_seen > 0 && report.selectors.is_empty())
        || report.omitted_candidate_ranges > 0
        || report.omitted_selectors > 0
        || report.observation_coverage.omitted_samples > 0
        || report
            .selectors
            .iter()
            .any(|selector| !selector.unassigned.is_empty() || selector.omitted_families > 0)
}

const fn direction_name(direction: Direction) -> &'static str {
    match direction {
        Direction::FirstToSecond => "first_to_second",
        Direction::SecondToFirst => "second_to_first",
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}
