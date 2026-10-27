use super::super::policy_for_profile;
use super::super::record_discovery_tests::build_session_relative_fixture;
use super::search::CandidateGate;
use super::{GateAssessment, MAX_RETAINED_RELATIONAL_APPLICATIONS, StoredSample};
use crate::arguments::RecoveryProfile;
use l2_workbench::{
    artifact::{ArtifactValidationFormat, ArtifactValidationPolicy},
    derivation::{CounterByteOrder, CounterWidth, SeedCounterOrder},
    evidence::Case,
    job::{Job, Phase},
    protocol::{
        ByteOrder, Direction, MessageContext, RelationalByteRangeLocator,
        RelationalCandidateEvaluation, RelationalCandidateEvaluationReport,
        RelationalCoordinateBasis, RelationalCounterReset, RelationalOperationTemplate,
        RelationalParserScope, RelationalRecordSample, RelationalSha256CounterXor,
        RelationalTransformEvaluationOptions, RelationalTransformLimits, RelationalTransformPlan,
        RelationalTransformRule, apply_relational_transform_rule,
        infer_relational_transform_candidates_with_evaluator,
    },
};
use serde_json::Value;
use std::{collections::BTreeMap, error::Error};

type TestResult = Result<(), Box<dyn Error>>;
type EvaluationReport = RelationalCandidateEvaluationReport<GateAssessment>;

struct OwnedSample {
    sample: u64,
    context: MessageContext,
    session_order: u64,
    bytes: Vec<u8>,
}

struct FixtureSession<'a> {
    context: MessageContext,
    session_order: u64,
    direction_node_id: u64,
    bytes: &'a [u8],
}

struct FirstGateScreen {
    remaining_before: usize,
    work_used: usize,
}

struct CandidateSearchResult {
    evaluation: EvaluationReport,
    first_gate_screen: FirstGateScreen,
}

#[test]
fn deep_profile_reserves_the_same_normal_admission_before_its_wider_domain() -> TestResult {
    let fixture = build_session_relative_fixture()?;
    let normal = policy_for_profile(&fixture.case, RecoveryProfile::Normal, 64 * 1024 * 1024)?;
    let deep = policy_for_profile(&fixture.case, RecoveryProfile::Deep, 64 * 1024 * 1024)?;
    assert_eq!(
        deep.relational_transform_plan, normal.relational_transform_plan,
        "deep recovery must first use the same cohort, search, and work limits as normal"
    );
    let extra = deep
        .relational_incremental_plan
        .ok_or("deep recovery omitted its wider second domain")?;
    assert!(extra.limits.max_sessions > normal.relational_transform_plan.limits.max_sessions);
    assert!(
        extra.limits.max_records_per_session
            > normal
                .relational_transform_plan
                .limits
                .max_records_per_session
    );
    assert!(
        extra.limits.max_locator_candidates
            > normal
                .relational_transform_plan
                .limits
                .max_locator_candidates
    );
    assert!(extra.limits.max_candidates > normal.relational_transform_plan.limits.max_candidates);
    Ok(())
}

#[test]
fn insufficient_coordinator_work_reports_an_omission_without_charging_unread_input() -> TestResult {
    let mut case = Case::new();
    let first = case.add_bytes_node("frame", b"first", Vec::new(), serde_json::json!({}))?;
    let second = case.add_bytes_node("frame", b"second", Vec::new(), serde_json::json!({}))?;
    let plan = super::super::RecoveryPlan::default();
    let policy = policy_for_profile(&case, RecoveryProfile::Normal, 64 * 1024 * 1024)?;
    let executor = super::super::test_support::build_executor(&mut case, &plan, &policy)?;
    let samples = [(first, 1_u64), (second, 2_u64)].map(|(node_id, session)| StoredSample {
        node_id,
        context: MessageContext {
            source: "source".to_owned(),
            scope: "scope".to_owned(),
            session,
            direction: Direction::FirstToSecond,
        },
        session_order: session,
        direction_node_id: session,
        episode_node_id: session,
        stream_offset: 0,
    });
    let context = super::RelationalDiscoveryContext {
        lane: super::RelationalLane::Incremental,
        key: super::RelationalCohortKey {
            source_id: "source".to_owned(),
            scope_json: "scope".to_owned(),
            endpoints_json: "{}".to_owned(),
            direction: Direction::FirstToSecond,
            framing_rule_json: "framed".to_owned(),
            schema_json: "{}".to_owned(),
        },
        sample_node_ids: vec![first, second],
        samples: samples.to_vec(),
        sessions_available: 2,
        omitted_sessions: 0,
        omitted_samples: 0,
        source_eligibility_omissions: 0,
        input_coverage_complete: true,
    };
    let mut work_remaining = 1;
    let result = super::search::prepare_cohort(
        &executor,
        context,
        &policy.relational_transform_plan,
        &mut work_remaining,
        None,
    )?;
    assert_eq!(result.reason, Some("coordinator_work_limit"));
    assert_eq!(work_remaining, 1);
    assert!(result.outputs.is_empty());
    Ok(())
}

#[test]
fn screening_work_is_bounded_and_the_equivalent_rule_is_retained() -> TestResult {
    let fixture = build_session_relative_fixture()?;
    let (owned_samples, stored_samples) = fixture_samples(&fixture.case, &fixture.episode_nodes)?;
    let samples = relational_samples(&owned_samples);
    let policy = policy_for_profile(&fixture.case, RecoveryProfile::Normal, 64 * 1024 * 1024)?;
    let mut plan = policy.relational_transform_plan;
    plan.limits.max_work_bytes = 32 * 1024 * 1024;

    let expected_rule = expected_session_relative_rule();
    assert_eq!(
        replay_expected_rule(&samples, &expected_rule, plan.limits)?,
        4
    );
    let search = search_candidates(
        &samples,
        &stored_samples,
        policy.record_schema_proposal_limits,
        policy.artifact_validation_policy,
        &plan,
    )?;

    let first_screen = search.first_gate_screen;
    assert!(
        first_screen.work_used > 0,
        "the first candidate did not screen records"
    );
    let first_screen_limit = first_screen.remaining_before / MAX_RETAINED_RELATIONAL_APPLICATIONS;
    assert!(
        first_screen.work_used <= first_screen_limit,
        "the first record gate exceeded the allocation for its scope"
    );
    assert!(
        search.evaluation.report.work_bytes <= plan.limits.max_work_bytes,
        "screening exceeded the existing cohort search budget"
    );

    let retained_index = search
        .evaluation
        .report
        .candidates
        .iter()
        .position(|candidate| equivalent_rule(&candidate.rule, &expected_rule, &samples))
        .ok_or_else(|| {
            format!(
                "equivalent rule missing: candidates={}, work_bytes={}, first_work={}/{}",
                search.evaluation.report.candidates_examined,
                search.evaluation.report.work_bytes,
                first_screen.work_used,
                first_screen.remaining_before,
            )
        })?;
    let retained_status = search
        .evaluation
        .evaluations
        .get(retained_index)
        .map(|item| item.assessment.status.as_str());
    assert_eq!(
        retained_status,
        Some("artifact_validated"),
        "the retained equivalent rule must pass exact artifact validation"
    );
    Ok(())
}

fn relational_samples(owned: &[OwnedSample]) -> Vec<RelationalRecordSample<'_>> {
    owned
        .iter()
        .map(|sample| RelationalRecordSample {
            sample: sample.sample,
            context: sample.context.clone(),
            session_order: sample.session_order,
            bytes: &sample.bytes,
        })
        .collect()
}

fn replay_expected_rule(
    samples: &[RelationalRecordSample<'_>],
    rule: &RelationalTransformRule,
    limits: RelationalTransformLimits,
) -> Result<usize, Box<dyn Error>> {
    let mut sessions = BTreeMap::<u64, Vec<RelationalRecordSample<'_>>>::new();
    for sample in samples {
        sessions
            .entry(sample.context.session)
            .or_default()
            .push(sample.clone());
    }
    for session_samples in sessions.values() {
        let output =
            apply_relational_transform_rule(session_samples, rule, limits, limits.max_work_bytes)?;
        assert!(
            !output.bytes.is_empty(),
            "the expected rule replay produced no bytes"
        );
    }
    Ok(sessions.len())
}

fn search_candidates(
    samples: &[RelationalRecordSample<'_>],
    stored_samples: &[StoredSample],
    schema_limits: l2_workbench::protocol::RecordSchemaProposalLimits,
    artifact_policy: ArtifactValidationPolicy,
    plan: &RelationalTransformPlan,
) -> Result<CandidateSearchResult, Box<dyn Error>> {
    let job = Job::new("session-relative candidate search budget regression");
    job.start(Phase::TransformDiscovery, None)?;
    let mut gate = CandidateGate::new(
        samples,
        stored_samples,
        false,
        schema_limits,
        artifact_policy,
        Some(&job),
    );
    let mut first_screen = None;
    let evaluation = infer_relational_transform_candidates_with_evaluator(
        samples,
        plan,
        Some(&job),
        RelationalTransformEvaluationOptions {
            max_retained_output_bytes: plan.limits.max_total_bytes,
        },
        |context, candidate, discovery_outputs, heldout_outputs| {
            let result = gate.evaluate(context, candidate, discovery_outputs, heldout_outputs)?;
            if first_screen.is_none() {
                first_screen = Some(FirstGateScreen {
                    remaining_before: context.work_bytes_remaining,
                    work_used: result.work_bytes,
                });
            }
            Ok::<
                RelationalCandidateEvaluation<GateAssessment>,
                crate::workbench::recovery_executor::RecoveryExecutionError,
            >(result)
        },
    )?;
    let first_gate_screen =
        first_screen.ok_or("candidate search did not invoke its record gate")?;
    Ok(CandidateSearchResult {
        evaluation,
        first_gate_screen,
    })
}

fn equivalent_rule(
    candidate: &RelationalTransformRule,
    expected: &RelationalTransformRule,
    samples: &[RelationalRecordSample<'_>],
) -> bool {
    candidate.operation == expected.operation
        && candidate.counter_reset == expected.counter_reset
        && candidate.parser_scope == expected.parser_scope
        && candidate.parser_format == expected.parser_format
        && selects_expected_ranges(candidate, samples)
}

fn selects_expected_ranges(
    rule: &RelationalTransformRule,
    samples: &[RelationalRecordSample<'_>],
) -> bool {
    let sessions = samples
        .iter()
        .map(|sample| sample.context.session)
        .collect::<std::collections::BTreeSet<_>>();
    sessions.len() == 4
        && sessions.iter().all(|session| {
            let session_samples = samples
                .iter()
                .filter(|sample| sample.context.session == *session);
            let mut seed_ranges = Vec::new();
            let mut payload_ranges = Vec::new();
            for sample in session_samples {
                if locator_marker_matches(sample, &rule.seed_locator)
                    && let Some(range) = selected_range(sample, &rule.seed_locator)
                {
                    seed_ranges.push(range);
                }
                if locator_marker_matches(sample, &rule.payload_locator)
                    && let Some(range) = selected_range(sample, &rule.payload_locator)
                {
                    payload_ranges.push((range, sample.bytes.len()));
                }
            }
            seed_ranges.as_slice() == [(10, 18)]
                && payload_ranges.len() == 2
                && payload_ranges
                    .iter()
                    .all(|((start, end), message_length)| *start == 10 && *end == *message_length)
        })
}

fn locator_marker_matches(
    sample: &RelationalRecordSample<'_>,
    locator: &RelationalByteRangeLocator,
) -> bool {
    if locator.coordinate_basis != RelationalCoordinateBasis::MessageStartV1
        || locator.direction != sample.context.direction
    {
        return false;
    }
    locator
        .marker_offset
        .checked_add(locator.marker.len())
        .and_then(|end| sample.bytes.get(locator.marker_offset..end))
        == Some(locator.marker.as_slice())
}

fn selected_range(
    sample: &RelationalRecordSample<'_>,
    locator: &RelationalByteRangeLocator,
) -> Option<(usize, usize)> {
    let bytes = sample.bytes;
    let start = locator.value_offset;
    let end = match locator.value_length {
        Some(length) => start.checked_add(length)?,
        None => bytes.len(),
    };
    if start >= end || end > bytes.len() {
        return None;
    }
    if let Some(field) = locator.declared_length {
        let field_end = field.offset.checked_add(field.width.byte_length())?;
        let observed = decode_length(bytes.get(field.offset..field_end)?, field.byte_order)?;
        if observed != u64::try_from(end.checked_sub(start)?).ok()? {
            return None;
        }
    }
    Some((start, end))
}

fn decode_length(bytes: &[u8], order: ByteOrder) -> Option<u64> {
    let mut value = 0_u64;
    match order {
        ByteOrder::BigEndian => {
            for byte in bytes {
                value = value.checked_mul(256)?.checked_add(u64::from(*byte))?;
            }
        }
        ByteOrder::LittleEndian => {
            for byte in bytes.iter().rev() {
                value = value.checked_mul(256)?.checked_add(u64::from(*byte))?;
            }
        }
    }
    Some(value)
}

pub(super) fn expected_session_relative_rule() -> RelationalTransformRule {
    RelationalTransformRule {
        seed_locator: locator(vec![0x1a, 0x73], Some(8)),
        payload_locator: locator(vec![0xb2, 0x39], None),
        operation: RelationalOperationTemplate::Sha256CounterXor(RelationalSha256CounterXor {
            initial_counter: 0,
            counter_width: CounterWidth::OneByte,
            counter_byte_order: CounterByteOrder::BigEndian,
            seed_order: SeedCounterOrder::SeedThenCounter,
        }),
        counter_reset: RelationalCounterReset::PerRecord,
        parser_scope: RelationalParserScope::AcrossSessions,
        parser_format: ArtifactValidationFormat::Png,
    }
}

fn locator(marker: Vec<u8>, value_length: Option<usize>) -> RelationalByteRangeLocator {
    RelationalByteRangeLocator {
        coordinate_basis: RelationalCoordinateBasis::MessageStartV1,
        direction: Direction::FirstToSecond,
        marker_offset: 3,
        marker,
        value_offset: 10,
        value_length,
        declared_length: None,
    }
}

fn fixture_samples(
    case: &Case,
    episode_ids: &[u64],
) -> Result<(Vec<OwnedSample>, Vec<StoredSample>), Box<dyn Error>> {
    let source = case
        .sources()
        .first()
        .ok_or("fixture has no source")?
        .id
        .clone();
    let mut owned = Vec::new();
    let mut stored = Vec::new();
    let mut next_sample = 1_u64;
    for episode_id in episode_ids {
        let session = fixture_session(case, &source, *episode_id)?;
        append_session_samples(&session, &mut next_sample, &mut owned, &mut stored)?;
    }
    Ok((owned, stored))
}

fn fixture_session<'a>(
    case: &'a Case,
    source: &str,
    episode_id: u64,
) -> Result<FixtureSession<'a>, Box<dyn Error>> {
    let episode = case.node(episode_id).ok_or("fixture episode is missing")?;
    let scope = episode
        .details
        .get("scope")
        .ok_or("fixture scope is missing")?;
    let session_order = episode
        .details
        .get("first_packet")
        .and_then(Value::as_u64)
        .ok_or("fixture episode order is missing")?;
    let direction_node_id = child_node_id(case, episode_id, "tcp_direction")?;
    let run_id = child_node_id(case, direction_node_id, "tcp_byte_run")?;
    let run = case.node(run_id).ok_or("fixture byte run is missing")?;
    let blob_id = run.blob.as_deref().ok_or("fixture byte run has no blob")?;
    let bytes = &case
        .blob(blob_id)
        .ok_or("fixture byte-run blob is missing")?
        .bytes;
    Ok(FixtureSession {
        context: MessageContext {
            source: source.to_owned(),
            scope: serde_json::to_string(scope)?,
            session: episode_id,
            direction: Direction::FirstToSecond,
        },
        session_order,
        direction_node_id,
        bytes,
    })
}

fn child_node_id(case: &Case, parent: u64, kind: &str) -> Result<u64, Box<dyn Error>> {
    case.edges()
        .iter()
        .filter(|edge| edge.from == parent && edge.relation == "contains")
        .find_map(|edge| {
            case.node(edge.to)
                .filter(|node| node.kind == kind)
                .map(|node| node.id)
        })
        .ok_or_else(|| format!("fixture {kind} child is missing").into())
}

fn append_session_samples(
    session: &FixtureSession<'_>,
    next_sample: &mut u64,
    owned: &mut Vec<OwnedSample>,
    stored: &mut Vec<StoredSample>,
) -> TestResult {
    let mut stream_offset = 0_usize;
    while stream_offset < session.bytes.len() {
        let frame_end = framed_end(session.bytes, stream_offset)?;
        let frame = session
            .bytes
            .get(stream_offset..frame_end)
            .ok_or("fixture frame is out of bounds")?
            .to_vec();
        append_frame_sample(frame, stream_offset, session, next_sample, owned, stored)?;
        stream_offset = frame_end;
    }
    Ok(())
}

fn framed_end(bytes: &[u8], start: usize) -> Result<usize, Box<dyn Error>> {
    let prefix_end = start.checked_add(2).ok_or("fixture prefix overflow")?;
    let prefix = bytes
        .get(start..prefix_end)
        .ok_or("fixture prefix is truncated")?;
    let body_length = u16::from_be_bytes([
        *prefix.first().ok_or("fixture prefix is empty")?,
        *prefix.get(1).ok_or("fixture prefix is incomplete")?,
    ]);
    prefix_end
        .checked_add(usize::from(body_length))
        .ok_or_else(|| "fixture frame end overflow".into())
}

fn append_frame_sample(
    bytes: Vec<u8>,
    stream_offset: usize,
    session: &FixtureSession<'_>,
    next_sample: &mut u64,
    owned: &mut Vec<OwnedSample>,
    stored: &mut Vec<StoredSample>,
) -> TestResult {
    let sample_id = *next_sample;
    *next_sample = next_sample
        .checked_add(1)
        .ok_or("fixture sample id overflow")?;
    owned.push(OwnedSample {
        sample: sample_id,
        context: session.context.clone(),
        session_order: session.session_order,
        bytes,
    });
    stored.push(StoredSample {
        node_id: sample_id,
        context: session.context.clone(),
        session_order: session.session_order,
        direction_node_id: session.direction_node_id,
        episode_node_id: session.context.session,
        stream_offset,
    });
    Ok(())
}
