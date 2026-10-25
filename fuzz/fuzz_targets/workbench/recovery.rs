use l2_workbench::{
    artifact::{
        self, EmbeddedDiscoveryLimits, EmbeddedFormat, EmbeddedValidationEvidence, PngLimits,
    },
    evidence::{Case, Edge, EvidenceStatus},
    measurement::LengthMeaning,
    protocol::{
        self, BoundaryCandidate, BoundaryExtractionReport, ByteField, ByteOrder, ByteRunSample,
        Direction, FrameBoundary, FramingKind, IntegerField, MessageContext, ProtocolLimits,
        RecordCount, RecordDiscoveryLimits, RecordLengthMeaning, RecordLimits, RecordSchema,
        RecordSchemaDiscoverySpace, RecordSchemaProposalLimits,
    },
    recovery::{
        EnqueueOutcome, RecoveryCoordinator, RecoveryError, RecoveryResource,
        RecoveryResourcePolicy, RecoveryResult, RecoveryTask,
        proposals::transform_proposal_operations,
    },
};
use serde_json::json;

const MAX_RECOVERY_INPUT_BYTES: usize = 256;
const MAX_RECORD_INPUT_BYTES: usize = 272;
const MAX_RECORDS: usize = 8;
const MAX_CANDIDATES: usize = 8;
const MAX_FRAMES: usize = 8;

pub(super) fn exercise(input: &[u8]) {
    let input = input
        .get(..input.len().min(MAX_RECOVERY_INPUT_BYTES))
        .unwrap_or_default();

    // Keep each parser independent so one rejected input cannot skip later paths
    exercise_coordinator(input);
    exercise_framing(input);
    exercise_records(input);
    exercise_embedded(input);
}

pub(super) fn exercise_reconstructed_framing(
    reconstruction: &l2_workbench::reconstruction::ReconstructionReport,
) {
    let (run_count, total_bytes, maximum_run_bytes) = reconstruction_run_sizes(reconstruction);
    let limits = ProtocolLimits {
        max_samples: run_count.max(1).min(MAX_FRAMES),
        max_message_bytes: maximum_run_bytes.max(1),
        max_total_bytes: total_bytes.max(1),
        max_run_bytes: maximum_run_bytes.max(1),
        max_prefix_offset: 7,
        max_candidates: MAX_CANDIDATES,
        max_retained_frames: MAX_FRAMES,
        max_report_bytes: 4_096,
    };
    let Ok(report) = protocol::discover_reconstructed_framing_with_limits(
        "fuzz-recovery-source",
        reconstruction,
        limits,
    ) else {
        return;
    };
    let Ok(repeated) = protocol::discover_reconstructed_framing_with_limits(
        "fuzz-recovery-source",
        reconstruction,
        limits,
    ) else {
        return;
    };
    require(report.bootstrap == repeated.bootstrap);
    require(report.input_omissions == repeated.input_omissions);
    require(report.runs.len() == repeated.runs.len());
    for (first, second) in report.runs.iter().zip(&repeated.runs) {
        require(first.sample == second.sample);
        require(first.stream_index == second.stream_index);
        require(first.stream_offset == second.stream_offset);
        require(first.bytes == second.bytes);
        require(first.origins == second.origins);
    }

    let Some(bootstrap) = report.bootstrap.as_ref() else {
        require(report.runs.is_empty());
        return;
    };
    check_bootstrap_report(bootstrap, limits.max_samples);
    require_session_split(&report.runs, &report.streams, bootstrap);

    for run in &report.runs {
        let Some(stream) = report.streams.get(run.stream_index) else {
            fail();
        };
        require(stream.session_first_packet > 0);
        require(stream.context.session == u64::from(stream.session_first_packet));
        if let Some(materialized) = report.framing_for_run(run.sample) {
            check_boundary_candidates(&materialized.boundaries, run.bytes);
            for candidate in &materialized.boundaries.candidates {
                check_reconstructed_candidate(run, candidate);
            }
        }
    }
    require(report.input_omissions.omitted_runs <= run_count);
    require(
        report
            .runs
            .len()
            .saturating_add(report.input_omissions.omitted_runs)
            <= run_count,
    );
    if !report.reconstruction.complete || report.input_omissions.omitted_runs > 0 {
        require(report.is_partial());
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CoordinatorObservation {
    queued: EnqueueOutcome,
    merged: EnqueueOutcome,
    cycle: EnqueueOutcome,
    candidates_after_merge: usize,
    candidates_after_cycle: usize,
    origins_after_merge: usize,
    charged_work: usize,
    rejected_other_case: bool,
    contextual_first: EnqueueOutcome,
    contextual_repeat: EnqueueOutcome,
    contextual_alias: EnqueueOutcome,
    contextual_candidate_count: usize,
}

fn exercise_coordinator(input: &[u8]) {
    let first = coordinator_observation(input);
    let second = coordinator_observation(input);
    require(first == second);
}

fn coordinator_observation(input: &[u8]) -> CoordinatorObservation {
    let mut case = Case::new();
    let bytes = input.get(..input.len().min(64)).unwrap_or_default();
    let first_node = add_bytes_node(&mut case, "recovery_input", bytes);
    let alias_node = add_bytes_node(&mut case, "recovery_input", bytes);
    let policy = recovery_policy(bytes.len());
    let mut coordinator = RecoveryCoordinator::new(policy);
    let task = RecoveryTask::StructuralValidation;
    let queued = match coordinator.enqueue(&case, first_node, task.clone()) {
        Ok(EnqueueOutcome::Queued(id)) => EnqueueOutcome::Queued(id),
        _ => fail(),
    };
    let candidate_id = match queued {
        EnqueueOutcome::Queued(id) => id,
        _ => fail(),
    };
    let merged = match coordinator.enqueue(&case, alias_node, task) {
        Ok(outcome @ EnqueueOutcome::Merged(id)) if id == candidate_id => outcome,
        _ => fail(),
    };
    require(coordinator.candidate_count() == 1);

    let Some(candidate) = coordinator.candidate(candidate_id) else {
        fail();
    };
    let Some(input) = candidate.inputs().first() else {
        fail();
    };
    require(input.origin_node_ids().contains(&first_node));
    require(input.origin_node_ids().contains(&alias_node));
    let origins_after_merge = input.origin_node_ids().len();
    let input_blob = match coordinator.input_blob(&case, candidate_id) {
        Ok(blob) => blob,
        Err(_) => fail(),
    };
    require(input_blob.bytes.as_slice() == bytes);

    match coordinator.pop_next() {
        Ok(Some(id)) if id == candidate_id => {}
        _ => fail(),
    }
    if coordinator
        .finish(&case, candidate_id, RecoveryResult::Unsupported)
        .is_err()
    {
        fail();
    }
    require(matches!(coordinator.pop_next(), Ok(None)));

    let mut other_case = Case::new();
    let other_node = add_bytes_node(&mut other_case, "recovery_input", bytes);
    let rejected_other_case = matches!(
        coordinator.enqueue(&other_case, other_node, RecoveryTask::StructuralValidation),
        Err(RecoveryError::DifferentCase)
    );
    require(rejected_other_case);

    let charged = match coordinator.charge_case_work(bytes.len()) {
        l2_workbench::recovery::BudgetCheck::WithinBudget => coordinator.work_bytes_charged(),
        l2_workbench::recovery::BudgetCheck::Exhausted { .. } => fail(),
    };
    require(charged <= policy.max_work_bytes);
    let Some(over_budget) = policy
        .max_work_bytes
        .checked_sub(charged)
        .and_then(|remaining| remaining.checked_add(1))
    else {
        fail();
    };
    match coordinator.charge_case_work(over_budget) {
        l2_workbench::recovery::BudgetCheck::Exhausted {
            resource,
            limit,
            used,
            requested,
        } => {
            require(resource == RecoveryResource::WorkBytes);
            require(limit == policy.max_work_bytes);
            require(used == charged);
            require(requested == over_budget);
        }
        l2_workbench::recovery::BudgetCheck::WithinBudget => fail(),
    }
    require(coordinator.work_bytes_charged() == charged);

    let (cycle, candidates_after_cycle) = exercise_cycle(bytes);
    let (contextual_first, contextual_repeat, contextual_alias, contextual_candidate_count) =
        exercise_context_identity(bytes);
    CoordinatorObservation {
        queued,
        merged,
        cycle,
        candidates_after_merge: coordinator.candidate_count(),
        candidates_after_cycle,
        origins_after_merge,
        charged_work: charged,
        rejected_other_case,
        contextual_first,
        contextual_repeat,
        contextual_alias,
        contextual_candidate_count,
    }
}

fn exercise_context_identity(
    bytes: &[u8],
) -> (EnqueueOutcome, EnqueueOutcome, EnqueueOutcome, usize) {
    let mut case = Case::new();
    let first_node = add_bytes_node(&mut case, "framing_origin", bytes);
    let alias_node = add_bytes_node(&mut case, "framing_origin", bytes);
    let mut coordinator = RecoveryCoordinator::new(recovery_policy(bytes.len()));
    let task = RecoveryTask::FramingDiscovery;
    let first = match coordinator.enqueue(&case, first_node, task.clone()) {
        Ok(outcome @ EnqueueOutcome::Queued(_)) => outcome,
        _ => fail(),
    };
    let first_id = match first {
        EnqueueOutcome::Queued(id) => id,
        _ => fail(),
    };
    let repeat = match coordinator.enqueue(&case, first_node, task.clone()) {
        Ok(outcome @ EnqueueOutcome::Merged(id)) if id == first_id => outcome,
        _ => fail(),
    };
    let alias = match coordinator.enqueue(&case, alias_node, task) {
        Ok(outcome @ EnqueueOutcome::Queued(id)) if id != first_id => outcome,
        _ => fail(),
    };
    require(coordinator.candidate_count() == 2);

    let Some(first_candidate) = coordinator.candidate(first_id) else {
        fail();
    };
    let Some(first_input) = first_candidate.inputs().first() else {
        fail();
    };
    require(first_input.origin_node_ids() == [first_node]);
    let alias_id = match alias {
        EnqueueOutcome::Queued(id) => id,
        _ => fail(),
    };
    let Some(alias_candidate) = coordinator.candidate(alias_id) else {
        fail();
    };
    let Some(alias_input) = alias_candidate.inputs().first() else {
        fail();
    };
    require(alias_input.origin_node_ids() == [alias_node]);
    (first, repeat, alias, coordinator.candidate_count())
}

fn exercise_cycle(bytes: &[u8]) -> (EnqueueOutcome, usize) {
    let mut case = Case::new();
    let input_node = add_bytes_node(&mut case, "recursive_input", bytes);
    let result_node = add_bytes_node(&mut case, "recursive_result", bytes);
    let child_node = add_bytes_node(&mut case, "recursive_child", bytes);
    add_derived_edge(&mut case, result_node, input_node);
    add_derived_edge(&mut case, child_node, result_node);

    let mut coordinator = RecoveryCoordinator::new(recovery_policy(bytes.len()));
    let task = RecoveryTask::RecursiveExpansion;
    let candidate_id = match coordinator.enqueue(&case, input_node, task.clone()) {
        Ok(EnqueueOutcome::Queued(id)) => id,
        _ => fail(),
    };
    match coordinator.pop_next() {
        Ok(Some(id)) if id == candidate_id => {}
        _ => fail(),
    }
    if coordinator
        .finish(
            &case,
            candidate_id,
            RecoveryResult::Derived {
                evidence_node_id: result_node,
            },
        )
        .is_err()
    {
        fail();
    }
    let cycle = match coordinator.enqueue_derived(candidate_id, &case, &[child_node], task) {
        Ok(
            outcome @ EnqueueOutcome::CycleSkipped {
                candidate_id: found,
            },
        ) if found == candidate_id => outcome,
        _ => fail(),
    };
    require(coordinator.candidate_count() == 1);
    (cycle, coordinator.candidate_count())
}

fn recovery_policy(input_length: usize) -> RecoveryResourcePolicy {
    let input_limit = input_length.max(1);
    let max_candidate_task_identity_bytes = [
        RecoveryTask::StructuralValidation,
        RecoveryTask::FramingDiscovery,
        RecoveryTask::RecursiveExpansion,
    ]
    .iter()
    .map(|task| serde_json::to_vec(task).map_or(0, |identity| identity.len()))
    .max()
    .unwrap_or_default()
    .saturating_mul(4);
    let max_proposal_identity_bytes = transform_proposal_operations()
        .map(RecoveryTask::transform)
        .map(|task| serde_json::to_vec(&task).map_or(0, |identity| identity.len()))
        .max()
        .unwrap_or_default()
        .saturating_mul(4);
    RecoveryResourcePolicy {
        max_candidates: 4,
        max_frontier: 4,
        max_inputs_per_candidate: 4,
        max_origins_per_candidate: 4,
        max_input_bytes_per_item: input_limit,
        max_total_input_bytes_per_candidate: input_limit.saturating_mul(2),
        max_depth: 3,
        max_output_bytes: input_limit,
        max_work_bytes: input_limit.saturating_mul(4).saturating_add(16),
        max_candidate_task_identity_bytes,
        max_transform_proposal_identity_bytes: max_proposal_identity_bytes,
        max_transform_proposal_associations: 4,
        max_parent_links: 8,
        max_lineage_work: 64,
        max_context_aliases: 16,
        max_pending_origin_links: 8,
    }
}

fn exercise_framing(input: &[u8]) {
    let framing = generated_framing(input);
    check_explicit_boundaries(input, &framing);
    let framings = [framing];

    let limits = protocol_limits(input.len(), 4);
    let run = ByteRunSample {
        sample: 1,
        context: None,
        bytes: input,
    };
    if let Ok(report) = protocol::extract_boundaries_with_limits(&run, &framings, limits) {
        let Ok(repeated) = protocol::extract_boundaries_with_limits(&run, &framings, limits) else {
            return;
        };
        require(report == repeated);
        check_boundary_candidates(&report, input);
        require(report.evaluated_candidates <= limits.max_candidates);
    }

    let run_width = input.len().div_ceil(4);
    let mut runs = Vec::new();
    for index in 0_usize..4 {
        let start = index.saturating_mul(run_width);
        let end = start.saturating_add(run_width).min(input.len());
        let bytes = input.get(start..end).unwrap_or_default();
        let session = if index < 2 { 1 } else { 2 };
        let direction = if index % 2 == 0 {
            Direction::FirstToSecond
        } else {
            Direction::SecondToFirst
        };
        let sample = match index {
            0 => 1,
            1 => 2,
            2 => 3,
            _ => 4,
        };
        runs.push(ByteRunSample {
            sample,
            context: Some(MessageContext {
                source: "fuzz-recovery-source".to_owned(),
                scope: "fuzz-recovery-scope".to_owned(),
                session,
                direction,
            }),
            bytes,
        });
    }

    let limits = protocol_limits(input.len(), runs.len());
    let Ok(first) = protocol::bootstrap_framing_with_execution_plan(&runs, limits) else {
        return;
    };
    let Ok(second) = protocol::bootstrap_framing_with_execution_plan(&runs, limits) else {
        return;
    };
    require(first == second);
    let report = &first.report;
    require(
        report
            .hypotheses
            .len()
            .saturating_add(report.omitted_hypothesis_details)
            == first.execution_plan.hypotheses.len(),
    );
    require(
        report
            .hypotheses
            .iter()
            .zip(&first.execution_plan.hypotheses)
            .all(|(retained, planned)| retained == planned),
    );
    check_bootstrap_report(report, runs.len());
    require_session_split_for_samples(&runs, &report.discovery_samples, &report.holdout_samples);
    for materialized in report.discovery.iter().chain(&report.holdout) {
        let Some(run) = runs
            .iter()
            .find(|run| run.sample == materialized.boundaries.sample)
        else {
            fail();
        };
        check_boundary_candidates(&materialized.boundaries, run.bytes);
    }
}

fn check_bootstrap_report(
    report: &l2_workbench::protocol::FramingBootstrapReport,
    maximum_runs: usize,
) {
    let runs = report.discovery.len().saturating_add(report.holdout.len());
    require(runs <= maximum_runs);
    let omitted_candidates = report
        .discovery
        .iter()
        .filter_map(|run| run.candidate_generation_omissions)
        .fold(0_usize, usize::saturating_add);
    require(report.omitted_candidates == omitted_candidates);
    let detail_runs = report.discovery.iter().chain(&report.holdout);
    let omitted_candidate_details = detail_runs
        .clone()
        .map(|run| run.boundaries.omitted_candidate_details)
        .fold(0_usize, usize::saturating_add);
    let omitted_alias_candidates = report
        .discovery
        .iter()
        .chain(&report.holdout)
        .map(|run| run.boundaries.omitted_alias_candidates)
        .fold(0_usize, usize::saturating_add);
    require(report.omitted_candidate_details == omitted_candidate_details);
    require(report.omitted_alias_candidates == omitted_alias_candidates);
    require(report.search_exhaustive_within_plan == (report.omitted_candidates == 0));
    require(
        report.report_details_complete
            == (report.omitted_hypothesis_details == 0
                && report.omitted_candidate_details == 0
                && report.omitted_alias_candidates == 0
                && report
                    .discovery
                    .iter()
                    .chain(&report.holdout)
                    .all(|run| run.boundaries.report_details_complete)),
    );
}

fn generated_framing(input: &[u8]) -> FramingKind {
    match byte_at(input, 0) % 3 {
        0 => FramingKind::Delimiter {
            byte: byte_at(input, 1),
        },
        1 => FramingKind::FixedSize {
            bytes: usize::from(byte_at(input, 1) % 16).saturating_add(1),
        },
        _ => {
            let width = match byte_at(input, 2) % 4 {
                0 => 1,
                1 => 2,
                2 => 4,
                _ => 8,
            };
            FramingKind::LengthPrefix {
                offset: usize::from(byte_at(input, 1) % 8),
                width,
                byte_order: if byte_at(input, 3) & 1 == 0 {
                    ByteOrder::BigEndian
                } else {
                    ByteOrder::LittleEndian
                },
                meaning: if byte_at(input, 4) & 1 == 0 {
                    LengthMeaning::WholeMessage
                } else {
                    LengthMeaning::BytesAfterField
                },
            }
        }
    }
}

fn check_explicit_boundaries(input: &[u8], framing: &FramingKind) {
    let mut cursor = 0;
    for boundary in protocol::frame_boundaries(input, framing) {
        let range = match boundary {
            FrameBoundary::Frame(range) => range,
            FrameBoundary::Tail { range, .. } => range,
        };
        require(range.start == cursor);
        require(range.start <= range.end);
        require(range.end <= input.len());
        cursor = range.end;
    }
    require(cursor == input.len());
}

fn check_boundary_candidates(report: &BoundaryExtractionReport, bytes: &[u8]) {
    require(report.candidates.len() <= report.evaluated_candidates);
    require(
        report
            .candidates
            .len()
            .checked_add(report.omitted_candidate_details)
            == Some(report.evaluated_candidates),
    );
    require(report.search_exhaustive_within_plan == (report.omitted_candidates == 0));
    require(
        report.report_details_complete
            == (report.omitted_candidate_details == 0
                && report.omitted_alias_candidates == 0
                && report
                    .candidates
                    .iter()
                    .all(|candidate| candidate.omitted_frames == 0)),
    );
    for candidate in &report.candidates {
        check_one_boundary_candidate(candidate, bytes);
    }
}

fn check_one_boundary_candidate(candidate: &BoundaryCandidate, bytes: &[u8]) {
    require(
        candidate
            .frames
            .len()
            .saturating_add(candidate.omitted_frames)
            == candidate.frame_count,
    );
    let mut cursor = 0;
    for range in &candidate.frames {
        require(range.start == cursor);
        require(range.start <= range.end);
        require(range.end <= bytes.len());
        cursor = range.end;
    }
    if let Some(trailing) = candidate.trailing {
        require(trailing.start <= trailing.end);
        require(trailing.end <= bytes.len());
        require(trailing.start >= cursor);
    }
}

fn require_session_split_for_samples(
    runs: &[ByteRunSample<'_>],
    discovery_samples: &[u64],
    holdout_samples: &[u64],
) {
    let mut seen = std::collections::HashSet::new();
    for sample in discovery_samples.iter().chain(holdout_samples) {
        require(seen.insert(*sample));
        require(runs.iter().any(|run| run.sample == *sample));
    }
    require(seen.len() == runs.len());
    for discovery in discovery_samples {
        let Some(discovery_session) = runs
            .iter()
            .find(|run| run.sample == *discovery)
            .and_then(|run| run.context.as_ref())
            .map(|context| context.session)
        else {
            fail();
        };
        for holdout in holdout_samples {
            let Some(holdout_session) = runs
                .iter()
                .find(|run| run.sample == *holdout)
                .and_then(|run| run.context.as_ref())
                .map(|context| context.session)
            else {
                fail();
            };
            require(discovery_session != holdout_session);
        }
    }
}

fn require_session_split(
    runs: &[l2_workbench::protocol::ReconstructedFramingRun<'_>],
    streams: &[l2_workbench::protocol::ReconstructedFramingStream<'_>],
    bootstrap: &l2_workbench::protocol::FramingBootstrapReport,
) {
    let mut seen = std::collections::HashSet::new();
    for sample in bootstrap
        .discovery_samples
        .iter()
        .chain(&bootstrap.holdout_samples)
    {
        require(seen.insert(*sample));
        require(runs.iter().any(|run| run.sample == *sample));
    }
    require(seen.len() == runs.len());
    for discovery in &bootstrap.discovery_samples {
        let Some(discovery_session) = reconstructed_session(runs, streams, *discovery) else {
            fail();
        };
        for holdout in &bootstrap.holdout_samples {
            let Some(holdout_session) = reconstructed_session(runs, streams, *holdout) else {
                fail();
            };
            require(discovery_session != holdout_session);
        }
    }
}

fn reconstructed_session(
    runs: &[l2_workbench::protocol::ReconstructedFramingRun<'_>],
    streams: &[l2_workbench::protocol::ReconstructedFramingStream<'_>],
    sample: u64,
) -> Option<u64> {
    let run = runs.iter().find(|run| run.sample == sample)?;
    streams
        .get(run.stream_index)
        .map(|stream| stream.context.session)
}

fn check_reconstructed_candidate(
    run: &l2_workbench::protocol::ReconstructedFramingRun<'_>,
    candidate: &BoundaryCandidate,
) {
    for range in candidate
        .frames
        .iter()
        .copied()
        .chain(candidate.trailing.into_iter())
    {
        let Ok(mapping) = run.map_range(range) else {
            fail();
        };
        require(mapping.run_range == range);
        let expected_start = run.stream_offset.checked_add(range.start);
        let expected_end = run.stream_offset.checked_add(range.end);
        require(Some(mapping.stream_range.start) == expected_start);
        require(Some(mapping.stream_range.end) == expected_end);
        for origin in &mapping.origins {
            require(origin.offset >= mapping.stream_range.start);
            let Some(origin_end) = origin.offset.checked_add(origin.length) else {
                fail();
            };
            require(origin_end <= mapping.stream_range.end);
        }
        let mut covered_to = mapping.stream_range.start;
        for origin in &mapping.origins {
            require(origin.offset <= covered_to);
            let Some(origin_end) = origin.offset.checked_add(origin.length) else {
                fail();
            };
            covered_to = covered_to.max(origin_end);
            if covered_to >= mapping.stream_range.end {
                break;
            }
        }
        require(covered_to >= mapping.stream_range.end);
    }
}

fn reconstruction_run_sizes(
    reconstruction: &l2_workbench::reconstruction::ReconstructionReport,
) -> (usize, usize, usize) {
    let mut run_count = 0_usize;
    let mut total_bytes = 0_usize;
    let mut maximum_run_bytes = 0_usize;
    for session in &reconstruction.sessions {
        for stream in &session.directions {
            for run in stream.runs() {
                run_count = run_count.saturating_add(1);
                total_bytes = total_bytes.saturating_add(run.bytes.len());
                maximum_run_bytes = maximum_run_bytes.max(run.bytes.len());
            }
        }
    }
    (run_count, total_bytes, maximum_run_bytes)
}

fn exercise_records(input: &[u8]) {
    let limits = record_limits(input.len());
    let (messages, stream, expected_payload) = generated_record_inputs(input);
    exercise_generated_record_proposal(&messages, limits);
    exercise_generated_record_discovery(&messages, limits);
    exercise_arbitrary_record_schema(input, limits);
    exercise_strict_record_assembly(&stream, &expected_payload, limits);
}

fn generated_record_inputs(input: &[u8]) -> ([Vec<u8>; 3], Vec<u8>, Vec<u8>) {
    let identifier = byte_at(input, 0);
    let mut messages = std::array::from_fn::<_, 3, _>(|_| Vec::new());
    let mut stream = Vec::new();
    let mut expected_payload = Vec::new();
    for (ordinal, message) in messages.iter_mut().enumerate() {
        let start = ordinal.saturating_mul(8);
        let desired_length = usize::from(byte_at(input, start) % 4);
        let payload = input
            .get(start..)
            .and_then(|tail| tail.get(..desired_length))
            .unwrap_or_default();
        let Ok(sequence) = u8::try_from(ordinal) else {
            fail();
        };
        let Ok(length) = u8::try_from(payload.len()) else {
            fail();
        };
        message.extend_from_slice(&[identifier, sequence, length]);
        message.extend_from_slice(payload);
        stream.extend_from_slice(message);
        expected_payload.extend_from_slice(payload);
    }
    (messages, stream, expected_payload)
}

fn exercise_generated_record_proposal(messages: &[Vec<u8>; 3], limits: RecordLimits) {
    let Some((first, rest)) = messages.split_first() else {
        return;
    };
    let Some((second, held_out_messages)) = rest.split_first() else {
        return;
    };
    let Some(held_out) = held_out_messages.first() else {
        return;
    };
    let training = [first.as_slice(), second.as_slice()];
    let held_out = [held_out.as_slice()];
    let proposal_limits = proposal_limits(limits);
    let Ok(first_report) =
        protocol::propose_record_schema_space(&training, &held_out, proposal_limits)
    else {
        return;
    };
    let Ok(second_report) =
        protocol::propose_record_schema_space(&training, &held_out, proposal_limits)
    else {
        return;
    };
    require(first_report == second_report);
    require(first_report.training_message_count == training.len());
    require(first_report.held_out_message_count == held_out.len());
    // Work limits cap examined work, not the size of omitted search domains
    require(
        first_report.examined_field_checks
            <= proposal_limits
                .max_field_checks_per_domain
                .saturating_mul(2),
    );
    require(first_report.examined_pair_checks <= proposal_limits.max_pair_checks);
    require(first_report.examined_length_checks <= proposal_limits.max_length_checks);
    require(
        first_report.omitted_schema_combinations
            == first_report
                .candidate_combinations
                .map(|count| count.saturating_sub(proposal_limits.discovery.max_candidates)),
    );
    require(
        first_report.search_exhaustive_within_plan
            == (first_report.omitted_field_checks == 0
                && first_report.omitted_pair_checks == 0
                && first_report.omitted_length_checks == 0
                && first_report.omitted_schema_combinations == Some(0)),
    );
    if let Some(space) = first_report.candidate_space.as_ref() {
        let discovery_limits = proposal_limits.discovery;
        if let Ok(discovery) =
            protocol::discover_record_schemas(&training, &held_out, space, discovery_limits)
        {
            check_record_discovery(&discovery, discovery_limits);
        }
    }
}

fn exercise_generated_record_discovery(messages: &[Vec<u8>; 3], limits: RecordLimits) {
    let Some((first, rest)) = messages.split_first() else {
        return;
    };
    let Some((second, held_out_messages)) = rest.split_first() else {
        return;
    };
    let Some(held_out) = held_out_messages.first() else {
        return;
    };
    let training = [first.as_slice(), second.as_slice()];
    let held_out = [held_out.as_slice()];
    let space = generated_discovery_space();
    let discovery_limits = RecordDiscoveryLimits {
        max_candidates: 8,
        max_messages: 3,
        max_survivors: 4,
        max_falsifications: 4,
        record_limits: limits,
    };
    let Ok(first_report) =
        protocol::discover_record_schemas(&training, &held_out, &space, discovery_limits)
    else {
        return;
    };
    let Ok(second_report) =
        protocol::discover_record_schemas(&training, &held_out, &space, discovery_limits)
    else {
        return;
    };
    require(first_report == second_report);
    check_record_discovery(&first_report, discovery_limits);
}

fn generated_discovery_space() -> RecordSchemaDiscoverySpace {
    RecordSchemaDiscoverySpace {
        records_offsets: vec![0],
        counts: vec![RecordCount::UntilEnd],
        identifier_fields: vec![ByteField {
            offset: 0,
            width: 1,
        }],
        sequence_fields: vec![IntegerField {
            offset: 1,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        }],
        length_fields: vec![IntegerField {
            offset: 2,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        }],
        data_offsets: vec![3],
        length_meanings: vec![RecordLengthMeaning::PayloadBytes],
        sequence_base: 0,
    }
}

fn check_record_discovery(
    report: &l2_workbench::protocol::RecordSchemaDiscoveryReport,
    limits: RecordDiscoveryLimits,
) {
    require(report.examined_combinations <= limits.max_candidates);
    require(report.surviving.len() <= limits.max_survivors);
    require(report.falsifications.len() <= limits.max_falsifications);
    require(report.omitted_survivors <= report.examined_combinations);
    require(report.falsified_count <= report.examined_combinations);
    require(report.falsifications.len() <= report.falsified_count);
    require(report.omitted_falsification_examples <= report.falsified_count);
    if let Some(total) = report.candidate_combinations {
        require(report.examined_combinations <= total);
        require(report.unexamined_combinations == total.checked_sub(report.examined_combinations));
    }
    require(report.search_exhaustive_within_plan == (report.unexamined_combinations == Some(0)));
    require(
        report.report_details_complete
            == (report.omitted_survivors == 0 && report.omitted_falsification_examples == 0),
    );
    for hypothesis in &report.surviving {
        require(hypothesis.training_message_count <= limits.max_messages);
        require(hypothesis.held_out_message_count <= limits.max_messages);
    }
}

fn exercise_arbitrary_record_schema(input: &[u8], limits: RecordLimits) {
    let width = match byte_at(input, 0) % 4 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let schema = RecordSchema {
        records_offset: usize::from(byte_at(input, 1) % 8),
        count: if byte_at(input, 2) & 1 == 0 {
            RecordCount::UntilEnd
        } else {
            RecordCount::Exact {
                records: u64::from(byte_at(input, 3) % 8),
            }
        },
        identifier: ByteField {
            offset: usize::from(byte_at(input, 4) % 8),
            width: usize::from(byte_at(input, 5) % 4).saturating_add(1),
        },
        sequence: IntegerField {
            offset: usize::from(byte_at(input, 6) % 8),
            width,
            byte_order: if byte_at(input, 7) & 1 == 0 {
                ByteOrder::BigEndian
            } else {
                ByteOrder::LittleEndian
            },
        },
        length: IntegerField {
            offset: usize::from(byte_at(input, 8) % 8),
            width,
            byte_order: if byte_at(input, 9) & 1 == 0 {
                ByteOrder::BigEndian
            } else {
                ByteOrder::LittleEndian
            },
        },
        data_offset: usize::from(byte_at(input, 10) % 16),
        length_meaning: match byte_at(input, 11) % 3 {
            0 => RecordLengthMeaning::PayloadBytes,
            1 => RecordLengthMeaning::WholeRecord,
            _ => RecordLengthMeaning::BytesAfterLengthField,
        },
        sequence_base: u64::from(byte_at(input, 12)),
        terminal_sequence: (byte_at(input, 13) & 1 == 0).then_some(u64::from(byte_at(input, 14))),
    };

    let Ok(first) = protocol::parse_records_with_limits(input, &schema, limits) else {
        return;
    };
    let Ok(second) = protocol::parse_records_with_limits(input, &schema, limits) else {
        return;
    };
    require(first == second);
    check_record_parse(input, &schema, &first);
    if let Ok(assembly) = protocol::assemble_record_groups(input, &first, limits) {
        let Ok(repeated) = protocol::assemble_record_groups(input, &first, limits) else {
            return;
        };
        require(assembly == repeated);
        check_record_assembly(&assembly.report(), &[input]);
    }
}

fn exercise_strict_record_assembly(stream: &[u8], expected_payload: &[u8], limits: RecordLimits) {
    let schema = RecordSchema {
        records_offset: 0,
        count: RecordCount::UntilEnd,
        identifier: ByteField {
            offset: 0,
            width: 1,
        },
        sequence: IntegerField {
            offset: 1,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        },
        length: IntegerField {
            offset: 2,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        },
        data_offset: 3,
        length_meaning: RecordLengthMeaning::PayloadBytes,
        sequence_base: 0,
        terminal_sequence: Some(2),
    };
    let Ok(parsed) = protocol::parse_records_with_limits(stream, &schema, limits) else {
        return;
    };
    check_record_parse(stream, &schema, &parsed);
    let Ok(assembly) = protocol::assemble_record_groups(stream, &parsed, limits) else {
        return;
    };
    let Ok(repeated) = protocol::assemble_record_groups(stream, &parsed, limits) else {
        return;
    };
    require(assembly == repeated);
    let report = assembly.report();
    check_record_assembly(&report, &[stream]);
    require(report.input_count == 1);
    require(report.output_bytes == expected_payload.len());
    let Some(group) = report.groups.first() else {
        fail();
    };
    require(group.receipt().complete);
    require(group.bytes() == Some(expected_payload));
}

fn check_record_parse(
    input: &[u8],
    schema: &RecordSchema,
    report: &l2_workbench::protocol::RecordParseReport,
) {
    require(report.schema() == schema);
    require(report.input_length() == input.len());
    require(report.input_sha256() == l2_workbench::sha256(input));
    require(report.records().len() <= MAX_RECORDS);
    let mut previous_end = schema.records_offset;
    for (index, record) in report.records().iter().enumerate() {
        require(record.index == index);
        require(record.record.start == previous_end);
        require(record.record.start <= record.record.end);
        require(record.record.end <= input.len());
        require(record.payload.start >= record.record.start);
        require(record.payload.start <= record.payload.end);
        require(record.payload.end <= record.record.end);
        require(record.identifier.len() <= schema.identifier.width);
        previous_end = record.record.end;
    }
    require(previous_end == input.len());
}

fn check_record_assembly(
    report: &l2_workbench::protocol::RecordAssemblyReport<'_>,
    sources: &[&[u8]],
) {
    require(report.input_count == sources.len());
    require(report.output_bytes <= MAX_RECORD_INPUT_BYTES);
    for group in report.groups {
        require(group.candidate_bytes().len() <= MAX_RECORD_INPUT_BYTES);
        for part in &group.receipt().parts {
            let Some(source) = sources.get(part.input_index) else {
                fail();
            };
            require(part.input.start <= part.input.end);
            require(part.input.end <= source.len());
            require(part.output.start <= part.output.end);
            require(part.output.end <= group.candidate_bytes().len());
            let source_payload = source.get(part.input.start..part.input.end);
            let output_payload = group
                .candidate_bytes()
                .get(part.output.start..part.output.end);
            require(source_payload == output_payload);
        }
    }
}

fn exercise_embedded(input: &[u8]) {
    let scan_limit = input.len().max(1);
    let png_input_limit = input.len().max(1);
    let zip_input_limit = input.len().max(1);
    let limits = EmbeddedDiscoveryLimits {
        max_scan_bytes: scan_limit,
        max_validation_attempts: 4,
        max_candidates: 4,
        png_limits: PngLimits {
            max_input_bytes: png_input_limit,
            max_chunks: 8,
        },
        zip_limits: artifact::zip::ZipArtifactLimits {
            max_archive_bytes: zip_input_limit,
            max_entries: 4,
            max_entry_expanded_bytes: 32,
            max_total_expanded_bytes: 64,
            max_depth: 1,
        },
        max_zip_operation_expanded_bytes: 64,
    };
    let work_limit = input.len().saturating_mul(4).saturating_add(16);
    let Ok(report) = artifact::discover_embedded_objects_with_work(input, limits, work_limit)
    else {
        return;
    };
    let Ok(repeated) = artifact::discover_embedded_objects_with_work(input, limits, work_limit)
    else {
        return;
    };
    require(report == repeated);

    require(report.scanned_range.offset == 0);
    require(report.scanned_range.length <= input.len());
    require(report.scanned_range.length <= limits.max_scan_bytes);
    require(report.candidates.len() <= limits.max_candidates);
    require(report.validation_attempt_count <= limits.max_validation_attempts);
    require(
        report
            .validation_input_bytes
            .saturating_add(report.zip_work_bytes)
            <= work_limit,
    );
    require(report.zip_work_bytes <= limits.max_zip_operation_expanded_bytes.min(work_limit));
    require(report.omissions.unvalidated_candidate_count <= report.candidates.len());
    require(report.omissions.output_candidate_count <= report.scanned_range.length);
    if let Some(unscanned) = report.omissions.unscanned_range {
        require(unscanned.offset == report.scanned_range.length);
        require(unscanned.length == input.len().saturating_sub(report.scanned_range.length));
    }

    let mut previous_offset = 0;
    for candidate in &report.candidates {
        require(candidate.offset >= previous_offset);
        previous_offset = candidate.offset;
        require(candidate.range.offset == candidate.offset);
        let Some(end) = candidate.range.offset.checked_add(candidate.range.length) else {
            fail();
        };
        require(end <= input.len());
        if let Ok(evidence) = &candidate.validation {
            check_embedded_evidence(candidate.format, candidate.range, evidence, input, limits);
        }
    }
}

fn check_embedded_evidence(
    format: EmbeddedFormat,
    range: l2_workbench::artifact::FileRange,
    evidence: &EmbeddedValidationEvidence,
    input: &[u8],
    limits: EmbeddedDiscoveryLimits,
) {
    let Some(end) = range.offset.checked_add(range.length) else {
        fail();
    };
    let Some(object) = input.get(range.offset..end) else {
        fail();
    };
    match (format, evidence) {
        (
            EmbeddedFormat::Png,
            EmbeddedValidationEvidence::Png {
                chunk_count,
                iend_range,
                trailing_range,
            },
        ) => {
            let png_limits = PngLimits {
                max_input_bytes: object.len().max(1),
                max_chunks: limits.png_limits.max_chunks,
            };
            let Ok(report) = artifact::parse_png(object, png_limits) else {
                fail();
            };
            require(report.chunks.len() == *chunk_count);
            let Some(iend_end) = iend_range.offset.checked_add(iend_range.length) else {
                fail();
            };
            require(iend_range.offset >= range.offset);
            require(iend_end == end);
            if let Some(trailing) = trailing_range {
                require(trailing.offset == end);
                require(trailing.offset.checked_add(trailing.length) == Some(input.len()));
            } else {
                require(end == input.len());
            }
        }
        (EmbeddedFormat::Zip, EmbeddedValidationEvidence::Zip { archive_sha256, .. }) => {
            require(*archive_sha256 == l2_workbench::sha256(object));
        }
        _ => fail(),
    }
}

fn record_limits(input_length: usize) -> RecordLimits {
    let input_limit = input_length
        .saturating_add(16)
        .clamp(16, MAX_RECORD_INPUT_BYTES);
    RecordLimits {
        max_input_bytes: input_limit,
        max_records: MAX_RECORDS,
        max_identifier_bytes: 4,
        max_report_bytes: 4_096,
        max_groups: 4,
        max_output_bytes: input_limit,
        max_issue_examples: 4,
    }
}

fn proposal_limits(record_limits: RecordLimits) -> RecordSchemaProposalLimits {
    RecordSchemaProposalLimits {
        discovery: RecordDiscoveryLimits {
            max_candidates: 8,
            max_messages: 3,
            max_survivors: 4,
            max_falsifications: 4,
            record_limits,
        },
        max_field_offset: 8,
        max_field_checks_per_domain: 32,
        max_pair_checks: 32,
        max_length_checks: 32,
    }
}

fn protocol_limits(input_length: usize, sample_count: usize) -> ProtocolLimits {
    let input_limit = input_length.max(1);
    ProtocolLimits {
        max_samples: sample_count.max(1).min(MAX_FRAMES),
        max_message_bytes: input_limit,
        max_total_bytes: input_limit,
        max_run_bytes: input_limit,
        max_prefix_offset: 7,
        max_candidates: MAX_CANDIDATES,
        max_retained_frames: MAX_FRAMES,
        max_report_bytes: 4_096,
    }
}

fn add_bytes_node(case: &mut Case, kind: &str, bytes: &[u8]) -> u64 {
    match case.add_bytes_node(kind, bytes, Vec::new(), json!({})) {
        Ok(node) => node,
        Err(_) => fail(),
    }
}

fn add_derived_edge(case: &mut Case, output: u64, input: u64) {
    let edge = Edge {
        from: output,
        to: input,
        relation: "derived_from".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "The output retains the exact input relation used by the fuzz scenario".to_owned(),
    };
    if case.add_edge(edge).is_err() {
        fail();
    }
}

fn byte_at(bytes: &[u8], offset: usize) -> u8 {
    bytes.get(offset).copied().unwrap_or_default()
}

fn require(condition: bool) {
    if !condition {
        fail();
    }
}

fn fail() -> ! {
    std::process::abort()
}
