use super::application::{AppliedCandidates, CandidateApplication};
use super::record_gate::{GateStatus, SchemaOffsetScope};
use super::search::CandidateGate;
use super::{RelationalCohortKey, RelationalDiscoveryContext, StoredSample};
use l2_workbench::{
    artifact::{ArtifactValidationFormat, ArtifactValidationPolicy},
    derivation::{CounterByteOrder, CounterWidth, SeedCounterOrder},
    protocol::{
        ByteRange, Direction, HoldoutBasis, MessageContext, RecordSchemaProposalLimits,
        RelationalAppliedOutput, RelationalByteRangeLocator, RelationalCandidateOutputs,
        RelationalCounterReset, RelationalFit, RelationalFitStatus, RelationalOperationTemplate,
        RelationalOutputMapping, RelationalParserScope, RelationalRecordSample,
        RelationalRetainedEvaluation, RelationalSessionCheck, RelationalSessionId,
        RelationalSha256CounterXor, RelationalTransformCandidate,
        RelationalTransformEvaluationContext, RelationalTransformLimits, RelationalTransformPlan,
        RelationalTransformReport, RelationalTransformRule, RelationalTransformStatus,
    },
    sha256,
};
use serde_json::Value;
use std::error::Error;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const APPLICATION_WORK_LIMIT: usize = 64 * 1024 * 1024;

struct InputFrame {
    sample_id: u64,
    context: MessageContext,
    session_order: u64,
    stream_offset: usize,
    sequence: u8,
    fragment: Vec<u8>,
    source_bytes: Vec<u8>,
}

#[test]
fn cold_body_dependent_candidate_runs_deferred_application_and_charges_work() -> TestResult {
    let fixture =
        crate::workbench::recovery_executor::record_discovery_tests::build_session_relative_fixture()?;
    let (applied, report_work) = apply_body_dependent_candidate(&fixture.plaintext)?;

    assert_application_fallback(&applied, report_work, &fixture.plaintext)
}

fn apply_body_dependent_candidate(plaintext: &[u8]) -> TestResult<(AppliedCandidates, usize)> {
    let input_frames = input_frames(plaintext)?;
    let (samples, stored_samples) = samples_for(&input_frames);
    let sessions = session_ids();
    let discovery_sessions = sessions
        .get(..2)
        .ok_or("discovery session split is missing")?;
    let heldout_sessions = sessions
        .get(2..)
        .ok_or("held-out session split is missing")?;
    let outputs = outputs_for(&input_frames, &sessions)?;
    let candidate = candidate_for_outputs(nested_record_rule(), &outputs);
    let mut gate = CandidateGate::new(
        &samples,
        &stored_samples,
        false,
        RecordSchemaProposalLimits::default(),
        ArtifactValidationPolicy::default(),
        None,
    );
    let primary = gate.evaluate(
        &RelationalTransformEvaluationContext {
            discovery_sessions,
            heldout_sessions,
            work_bytes_remaining: APPLICATION_WORK_LIMIT,
        },
        &candidate,
        &session_outputs(&outputs, discovery_sessions),
        &session_outputs(&outputs, heldout_sessions),
    )?;
    assert_ne!(primary.assessment.status, GateStatus::ArtifactValidated);
    assert_eq!(
        primary.assessment.assessment_scope,
        Some(SchemaOffsetScope::PreservedHeader)
    );
    assert!(primary.assessment.needs_full_inference());
    let report = transform_report(candidate, &sessions, primary.work_bytes)?;
    let context = application_context(&stored_samples);
    let search_plan = RelationalTransformPlan {
        limits: RelationalTransformLimits::default(),
        parser_scope: RelationalParserScope::AcrossSessions,
        ..RelationalTransformPlan::default()
    };
    let retained = RelationalRetainedEvaluation {
        assessment: primary.assessment,
        outputs: Some(RelationalCandidateOutputs {
            discovery: session_outputs(&outputs, discovery_sessions),
            heldout: session_outputs(&outputs, heldout_sessions),
        }),
    };

    let applied = CandidateApplication::new(
        &context,
        &samples,
        &search_plan,
        ArtifactValidationPolicy::default(),
        APPLICATION_WORK_LIMIT,
        &report,
        None,
    )?
    .apply(&report, vec![retained], &gate)?;

    Ok((applied, report.work_bytes))
}

fn assert_application_fallback(
    applied: &AppliedCandidates,
    report_work: usize,
    plaintext: &[u8],
) -> TestResult {
    let evidence = applied
        .application_evidence_checks
        .first()
        .ok_or("application evidence was not retained")?;
    let fallback_attempted = evidence
        .pointer("/details/full_inference_fallback/attempted")
        .and_then(Value::as_bool);
    let fallback_work = evidence
        .pointer("/details/full_inference_fallback/work_bytes")
        .and_then(Value::as_u64)
        .and_then(|work| usize::try_from(work).ok())
        .ok_or("fallback work accounting is missing")?;
    let aggregate_work = applied
        .aggregate_parser_checks
        .first()
        .and_then(|check| check.get("parser_work_bytes"))
        .and_then(Value::as_u64)
        .and_then(|work| usize::try_from(work).ok())
        .ok_or("direct aggregate parser work was not accounted")?;
    let application_work = applied
        .used_work
        .checked_sub(report_work)
        .ok_or("application work exceeds its total work")?;

    assert_eq!(fallback_attempted, Some(true));
    assert!(fallback_work > 0);
    assert_eq!(
        application_work,
        fallback_work.saturating_add(aggregate_work)
    );
    assert_eq!(applied.accepted_schemas.len(), 1);
    assert_eq!(applied.applied_rules, 1);
    assert!(applied.used_work <= APPLICATION_WORK_LIMIT);
    let accepted_schema = applied
        .accepted_schemas
        .first()
        .ok_or("accepted schema was not retained")?;
    assert_eq!(
        accepted_schema.1.artifact_receipt.output_sha256.as_deref(),
        Some(sha256(plaintext).as_str())
    );
    Ok(())
}

fn samples_for(frames: &[InputFrame]) -> (Vec<RelationalRecordSample<'_>>, Vec<StoredSample>) {
    let samples = frames
        .iter()
        .map(|frame| RelationalRecordSample {
            sample: frame.sample_id,
            context: frame.context.clone(),
            session_order: frame.session_order,
            bytes: &frame.source_bytes,
        })
        .collect();
    let stored_samples = frames
        .iter()
        .map(|frame| StoredSample {
            node_id: frame.sample_id,
            context: frame.context.clone(),
            session_order: frame.session_order,
            direction_node_id: 50,
            episode_node_id: frame.context.session,
            stream_offset: frame.stream_offset,
        })
        .collect();
    (samples, stored_samples)
}

fn input_frames(plaintext: &[u8]) -> TestResult<Vec<InputFrame>> {
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(8)
        .map_err(|source| format!("application fixture frame allocation failed: {source}"))?;
    for sequence in 0..8_usize {
        let start = plaintext
            .len()
            .checked_mul(sequence)
            .and_then(|offset| offset.checked_div(8))
            .ok_or("fixture fragment start overflowed")?;
        let end = plaintext
            .len()
            .checked_mul(sequence.saturating_add(1))
            .and_then(|offset| offset.checked_div(8))
            .ok_or("fixture fragment end overflowed")?;
        let fragment = plaintext
            .get(start..end)
            .filter(|fragment| !fragment.is_empty())
            .ok_or("fixture PNG fragment is empty")?
            .to_vec();
        let sequence = u8::try_from(sequence)?;
        let session = u64::from(sequence % 4).saturating_add(1);
        let source_body = record_body(sequence, &fragment)?;
        let mut source_bytes = vec![
            0x49,
            7_u8.saturating_sub(sequence),
            u8::try_from(source_body.len())?,
        ];
        source_bytes.extend_from_slice(&source_body);
        frames.push(InputFrame {
            sample_id: u64::from(sequence).saturating_add(1),
            context: message_context(session),
            session_order: session,
            stream_offset: usize::from(sequence / 4)
                .checked_mul(1024)
                .ok_or("fixture stream offset overflowed")?,
            sequence,
            fragment,
            source_bytes,
        });
    }
    Ok(frames)
}

fn record_body(sequence: u8, fragment: &[u8]) -> TestResult<Vec<u8>> {
    let total_length = fragment
        .len()
        .checked_add(3)
        .ok_or("fixture record body length overflowed")?;
    let mut body = Vec::new();
    body.try_reserve_exact(total_length)
        .map_err(|source| format!("application fixture body allocation failed: {source}"))?;
    body.extend_from_slice(&[0x44, sequence, u8::try_from(fragment.len())?]);
    body.extend_from_slice(fragment);
    Ok(body)
}

fn outputs_for(
    frames: &[InputFrame],
    sessions: &[RelationalSessionId],
) -> TestResult<Vec<RelationalAppliedOutput>> {
    let mut outputs = Vec::new();
    outputs
        .try_reserve_exact(sessions.len())
        .map_err(|source| format!("application fixture output allocation failed: {source}"))?;
    for session in sessions {
        let mut bytes = Vec::new();
        let mut payload_mappings = Vec::new();
        for frame in frames
            .iter()
            .filter(|frame| frame.context.session == session.session)
        {
            let body = record_body(frame.sequence, &frame.fragment)?;
            let start = bytes.len();
            bytes.extend_from_slice(&body);
            payload_mappings.push(RelationalOutputMapping {
                sample: frame.sample_id,
                source_range: ByteRange {
                    start: 3,
                    end: frame.source_bytes.len(),
                },
                output_range: ByteRange {
                    start,
                    end: bytes.len(),
                },
            });
        }
        let seed_sample = payload_mappings
            .first()
            .map(|mapping| mapping.sample)
            .ok_or("fixture session has no payload sample")?;
        outputs.push(RelationalAppliedOutput {
            session: session.clone(),
            session_order: session.session,
            seed_sample,
            payload_mappings,
            bytes,
            parser_validation_deferred: true,
            work_bytes: 0,
        });
    }
    Ok(outputs)
}

fn candidate_for_outputs(
    rule: RelationalTransformRule,
    outputs: &[RelationalAppliedOutput],
) -> RelationalTransformCandidate {
    let checks = outputs
        .iter()
        .map(|output| RelationalSessionCheck {
            session: output.session.clone(),
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
        })
        .collect::<Vec<_>>();
    let discovery_checks = checks
        .iter()
        .filter(|check| check.session.session <= 2)
        .cloned()
        .collect();
    let heldout_checks = checks
        .into_iter()
        .filter(|check| check.session.session > 2)
        .collect();
    RelationalTransformCandidate {
        rule,
        discovery: fit(discovery_checks),
        heldout: fit(heldout_checks),
        status: RelationalTransformStatus::AwaitingAcrossSessionValidation,
    }
}

fn fit(checks: Vec<RelationalSessionCheck>) -> RelationalFit {
    RelationalFit {
        status: RelationalFitStatus::TransformConstraintsSatisfied,
        supported_sessions: checks.iter().map(|check| check.session.clone()).collect(),
        contradicted_sessions: Vec::new(),
        unresolved_sessions: Vec::new(),
        checks,
    }
}

fn nested_record_rule() -> RelationalTransformRule {
    let locator = RelationalByteRangeLocator {
        direction: Direction::FirstToSecond,
        marker_offset: 0,
        marker: vec![0x49],
        value_offset: 3,
        value_length: None,
        declared_length: None,
    };
    RelationalTransformRule {
        seed_locator: locator.clone(),
        payload_locator: locator,
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

fn transform_report(
    candidate: RelationalTransformCandidate,
    sessions: &[RelationalSessionId],
    work_bytes: usize,
) -> TestResult<RelationalTransformReport> {
    let discovery_sessions = sessions
        .get(..2)
        .ok_or("discovery sessions are missing")?
        .to_vec();
    let heldout_sessions = sessions
        .get(2..)
        .ok_or("held-out sessions are missing")?
        .to_vec();
    Ok(RelationalTransformReport {
        split_basis: HoldoutBasis::CompleteSessions,
        discovery_sessions,
        heldout_sessions,
        candidates: vec![candidate],
        candidates_examined: 1,
        equivalent_candidate_aliases: 0,
        omitted_candidates: 0,
        omitted_candidates_exact: true,
        candidate_limit_remaining: 0,
        locator_candidates_examined: 1,
        locator_candidate_limit_remaining: 0,
        work_bytes,
        work_bytes_remaining: APPLICATION_WORK_LIMIT.saturating_sub(work_bytes),
        search_exhaustive_within_plan: false,
        search_limits: Vec::new(),
        search_limit: None,
    })
}

fn application_context(samples: &[StoredSample]) -> RelationalDiscoveryContext {
    RelationalDiscoveryContext {
        key: RelationalCohortKey {
            source_id: "sha256:test-source".to_owned(),
            scope_json: "{}".to_owned(),
            endpoints_json: "{}".to_owned(),
            direction: Direction::FirstToSecond,
            framing_rule_json: "framed".to_owned(),
            schema_json: "{}".to_owned(),
        },
        sample_node_ids: samples.iter().map(|sample| sample.node_id).collect(),
        samples: samples.to_vec(),
        sessions_available: 4,
        omitted_sessions: 0,
        omitted_samples: 0,
        source_eligibility_omissions: 0,
        input_coverage_complete: true,
    }
}

fn session_outputs(
    outputs: &[RelationalAppliedOutput],
    sessions: &[RelationalSessionId],
) -> Vec<RelationalAppliedOutput> {
    outputs
        .iter()
        .filter(|output| {
            sessions
                .iter()
                .any(|session| session.session == output.session.session)
        })
        .cloned()
        .collect()
}

fn session_ids() -> Vec<RelationalSessionId> {
    (1..=4)
        .map(|session| RelationalSessionId {
            source: "source".to_owned(),
            scope: "{}".to_owned(),
            session,
        })
        .collect()
}

fn message_context(session: u64) -> MessageContext {
    MessageContext {
        source: "source".to_owned(),
        scope: "{}".to_owned(),
        session,
        direction: Direction::FirstToSecond,
    }
}
