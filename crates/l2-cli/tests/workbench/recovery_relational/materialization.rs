use super::StoredSample;
use super::application::{
    DecodedFrameContext, decoded_payload_frames, should_retain_rule,
    validate_accepted_record_schema,
};
use super::record_gate::{GateStatus, SchemaCandidateOptions, SchemaPlanCache};
use super::search::CandidateGate;
use l2_workbench::{
    artifact::{ArtifactValidationFormat, ArtifactValidationPolicy},
    derivation::{CounterByteOrder, CounterWidth, SeedCounterOrder},
    evidence::{Case, EvidenceStatus},
    protocol::{
        ByteRange, Direction, HoldoutBasis, MessageContext, RecordSchemaProposalLimits,
        RelationalAppliedOutput, RelationalByteRangeLocator, RelationalCandidateEvaluation,
        RelationalCoordinateBasis, RelationalCounterReset, RelationalFit, RelationalFitStatus,
        RelationalOperationTemplate, RelationalOutputMapping, RelationalParserScope,
        RelationalRecordSample, RelationalSessionCheck, RelationalSessionId,
        RelationalSha256CounterXor, RelationalTransformCandidate,
        RelationalTransformEvaluationContext, RelationalTransformLimits, RelationalTransformReport,
        RelationalTransformRule, RelationalTransformStatus, apply_relational_transform_rule,
    },
    recovery::RecoveryTask,
    sha256,
};
use serde_json::Value;
use std::error::Error;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[test]
fn exact_artifact_validation_can_survive_incomplete_search_coverage() {
    assert!(should_retain_rule(GateStatus::ArtifactValidated, false));
}

#[test]
fn structural_support_requires_complete_search_coverage() {
    assert!(!should_retain_rule(
        GateStatus::StructurallySupported,
        false,
    ));
    assert!(should_retain_rule(GateStatus::StructurallySupported, true,));
}

#[test]
fn unresolved_and_contradicted_rules_are_not_retained() {
    assert!(!should_retain_rule(GateStatus::Pending, true));
    assert!(!should_retain_rule(GateStatus::Contradicted, true));
}

#[test]
fn decoded_frames_use_the_exact_applied_source_mapping() -> TestResult {
    let session = session(1);
    let context = message_context(&session);
    let mappings = vec![RelationalOutputMapping {
        sample: 101,
        source_range: ByteRange { start: 3, end: 10 },
        output_range: ByteRange { start: 0, end: 7 },
    }];
    let frames = decode_mapping_case(&session, &context, mappings)?;
    let frame = frames
        .first()
        .ok_or("decoded mapping did not produce a frame")?;
    assert_eq!(frame.input_node_id, 101);
    assert_eq!(frame.bytes, b"hdrPLAINTXtail");
    assert_eq!(frame.payload_range, ByteRange { start: 3, end: 10 });
    assert_eq!(frame.preserved_header_end, Some(3));
    assert_eq!(frame.stream_offset, 500);
    assert_eq!(frame.transformed_output_sha256, sha256(b"PLAINTX"));
    Ok(())
}

#[test]
fn decoded_frames_reject_invalid_output_mappings() {
    let session = session(1);
    let context = message_context(&session);
    for (label, mappings) in invalid_output_mapping_cases() {
        assert!(
            decode_mapping_case(&session, &context, mappings).is_err(),
            "decoded output should reject {label}"
        );
    }
}

fn invalid_output_mapping_cases() -> [(&'static str, Vec<RelationalOutputMapping>); 6] {
    [
        (
            "output gap",
            vec![
                RelationalOutputMapping {
                    sample: 101,
                    source_range: ByteRange { start: 3, end: 6 },
                    output_range: ByteRange { start: 0, end: 3 },
                },
                RelationalOutputMapping {
                    sample: 102,
                    source_range: ByteRange { start: 3, end: 6 },
                    output_range: ByteRange { start: 4, end: 7 },
                },
            ],
        ),
        (
            "output overlap",
            vec![
                RelationalOutputMapping {
                    sample: 101,
                    source_range: ByteRange { start: 3, end: 7 },
                    output_range: ByteRange { start: 0, end: 4 },
                },
                RelationalOutputMapping {
                    sample: 102,
                    source_range: ByteRange { start: 3, end: 7 },
                    output_range: ByteRange { start: 3, end: 7 },
                },
            ],
        ),
        (
            "reversed source range",
            vec![RelationalOutputMapping {
                sample: 101,
                source_range: ByteRange { start: 10, end: 3 },
                output_range: ByteRange { start: 0, end: 7 },
            }],
        ),
        (
            "output range past transformed bytes",
            vec![RelationalOutputMapping {
                sample: 101,
                source_range: ByteRange { start: 3, end: 11 },
                output_range: ByteRange { start: 0, end: 8 },
            }],
        ),
        (
            "source range past input bytes",
            vec![
                RelationalOutputMapping {
                    sample: 101,
                    source_range: ByteRange { start: 3, end: 5 },
                    output_range: ByteRange { start: 0, end: 2 },
                },
                RelationalOutputMapping {
                    sample: 102,
                    source_range: ByteRange { start: 12, end: 17 },
                    output_range: ByteRange { start: 2, end: 7 },
                },
            ],
        ),
        (
            "duplicate sample identity",
            vec![
                RelationalOutputMapping {
                    sample: 101,
                    source_range: ByteRange { start: 3, end: 6 },
                    output_range: ByteRange { start: 0, end: 3 },
                },
                RelationalOutputMapping {
                    sample: 101,
                    source_range: ByteRange { start: 6, end: 10 },
                    output_range: ByteRange { start: 3, end: 7 },
                },
            ],
        ),
    ]
}

#[test]
fn decoded_frames_reject_mappings_from_another_source_scope_or_session() {
    let session = session(1);
    let original_context = message_context(&session);
    let cases = [
        ("source", "other-source", "scope", 1),
        ("scope", "source", "other-scope", 1),
        ("session", "source", "scope", 2),
    ];

    for (label, source, scope, session_id) in cases {
        let sample_context = MessageContext {
            source: source.to_owned(),
            scope: scope.to_owned(),
            session: session_id,
            direction: original_context.direction,
        };
        let mapping = RelationalOutputMapping {
            sample: 101,
            source_range: ByteRange { start: 3, end: 10 },
            output_range: ByteRange { start: 0, end: 7 },
        };
        assert!(
            decode_mapping_case(&session, &sample_context, vec![mapping]).is_err(),
            "decoded output should reject a different {label}"
        );
    }
}

fn decode_mapping_case(
    session: &RelationalSessionId,
    sample_context: &MessageContext,
    mappings: Vec<RelationalOutputMapping>,
) -> TestResult<Vec<super::DecodedFrameOutput>> {
    let mut sample_ids = Vec::new();
    for mapping in &mappings {
        if !sample_ids.contains(&mapping.sample) {
            sample_ids.push(mapping.sample);
        }
    }
    let samples = sample_ids
        .iter()
        .map(|sample| RelationalRecordSample {
            sample: *sample,
            context: sample_context.clone(),
            session_order: 1,
            bytes: b"hdrSOURCE!tail",
        })
        .collect::<Vec<_>>();
    let stored_samples = sample_ids
        .iter()
        .map(|sample| StoredSample {
            node_id: *sample,
            context: sample_context.clone(),
            session_order: 1,
            direction_node_id: 20,
            episode_node_id: session.session,
            stream_offset: 500,
        })
        .collect::<Vec<_>>();
    let expected_session_orders = [1];
    let context = DecodedFrameContext {
        samples: &samples,
        stored_samples: &stored_samples,
        candidate_index: 0,
        expected_session_orders: &expected_session_orders,
        raw_directional_run: false,
    };
    let applied = RelationalAppliedOutput {
        session: session.clone(),
        session_order: 1,
        seed_sample: 102,
        payload_mappings: mappings,
        bytes: b"PLAINTX".to_vec(),
        parser_validation_deferred: true,
        work_bytes: 0,
    };
    let mut rule = frozen_session_relative_rule();
    // The applied mapping remains authoritative when the rule uses another coordinate basis
    rule.payload_locator.value_offset = 1;
    let digest = sha256(&applied.bytes);
    Ok(decoded_payload_frames(&context, &applied, &rule, &digest)?)
}

#[test]
fn evaluator_cache_does_not_reuse_a_plan_for_changed_transformed_bytes() -> TestResult {
    let sessions = [session(1), session(2), session(3)];
    let context = RelationalTransformEvaluationContext {
        discovery_sessions: &sessions[..2],
        heldout_sessions: &sessions[2..],
        work_bytes_remaining: 1,
    };
    let sample_ids = [101, 102, 103];
    let samples = sample_ids
        .iter()
        .zip(&sessions)
        .map(|(sample, session)| RelationalRecordSample {
            sample: *sample,
            context: message_context(session),
            session_order: session.session,
            bytes: b"HEADxxxxx",
        })
        .collect::<Vec<_>>();
    let stored_samples = sample_ids
        .iter()
        .zip(&sessions)
        .map(|(sample, session)| StoredSample {
            node_id: *sample,
            context: message_context(session),
            session_order: session.session,
            direction_node_id: 20,
            episode_node_id: session.session,
            stream_offset: 0,
        })
        .collect::<Vec<_>>();
    let mut gate = CandidateGate::new(
        &samples,
        &stored_samples,
        false,
        RecordSchemaProposalLimits::default(),
        ArtifactValidationPolicy::default(),
        None,
    );

    let (first_candidate, first_outputs) = candidate_with_outputs(b"alpha", &sessions);
    let first = evaluate_partitioned_candidate(
        &mut gate,
        &context,
        &first_candidate,
        &first_outputs,
        "first",
    )?;
    assert_eq!(
        first.assessment.details.get("schema_plan_cache_hit"),
        Some(&Value::Bool(false))
    );
    assert_eq!(first.assessment.status, GateStatus::Pending);

    let (repeated_candidate, repeated_outputs) = candidate_with_outputs(b"alpha", &sessions);
    let repeated = evaluate_partitioned_candidate(
        &mut gate,
        &context,
        &repeated_candidate,
        &repeated_outputs,
        "repeated",
    )?;
    assert_eq!(repeated.assessment.status, GateStatus::Pending);
    assert_eq!(
        repeated.assessment.details.get("schema_plan_cache_hit"),
        Some(&Value::Bool(true)),
        "an identical frozen input should retain its exact cache-hit fact"
    );

    let (second_candidate, second_outputs) = candidate_with_outputs(b"bravo", &sessions);
    let second = evaluate_partitioned_candidate(
        &mut gate,
        &context,
        &second_candidate,
        &second_outputs,
        "second",
    )?;

    assert_eq!(
        second.assessment.details.get("schema_plan_cache_hit"),
        Some(&Value::Bool(false)),
        "evaluator outputs share candidate index zero, so cache identity must bind transformed bytes"
    );
    assert_eq!(second.assessment.status, GateStatus::Pending);
    Ok(())
}

fn evaluate_partitioned_candidate(
    gate: &mut CandidateGate<'_>,
    context: &RelationalTransformEvaluationContext<'_>,
    candidate: &RelationalTransformCandidate,
    outputs: &[RelationalAppliedOutput],
    label: &str,
) -> TestResult<RelationalCandidateEvaluation<super::GateAssessment>> {
    let discovery = outputs
        .get(..2)
        .ok_or_else(|| format!("{label} discovery output partition is missing"))?;
    let heldout = outputs
        .get(2..)
        .ok_or_else(|| format!("{label} held-out output partition is missing"))?;
    Ok(gate.evaluate(context, candidate, discovery, heldout)?)
}

#[test]
fn frozen_session_relative_rule_replays_through_the_existing_record_gate() -> TestResult {
    let fixture =
        crate::workbench::recovery_executor::record_discovery_tests::build_session_relative_fixture()?;
    let samples_owned = session_relative_messages(&fixture.case, &fixture.episode_nodes)?;
    assert_eq!(samples_owned.len(), 12);

    let samples = samples_owned
        .iter()
        .map(|sample| RelationalRecordSample {
            sample: sample.sample,
            context: sample.context.clone(),
            session_order: sample.session_order,
            bytes: &sample.bytes,
        })
        .collect::<Vec<_>>();
    let stored_samples = samples_owned
        .iter()
        .map(|sample| StoredSample {
            node_id: sample.sample,
            context: sample.context.clone(),
            session_order: sample.session_order,
            direction_node_id: sample.direction_node_id,
            episode_node_id: sample.episode_node_id,
            stream_offset: sample.stream_offset,
        })
        .collect::<Vec<_>>();
    let sessions = session_ids(&samples_owned);
    assert_eq!(sessions.len(), 4);
    let work_limit = RelationalTransformLimits::default().max_work_bytes;
    let rule = frozen_session_relative_rule();
    let mut frames = replay_frozen_frames(&samples, &stored_samples, &sessions, &rule, work_limit)?;
    assert_eq!(frames.len(), 8);
    assert_replayed_frames_match_fixture(&frames, &samples_owned, &fixture.plaintext)?;

    let report = frozen_session_relative_report(&sessions, work_limit)?;
    let accepted_schema =
        assert_gate_accepts_frozen_schema(&mut frames, &report, work_limit, &fixture.plaintext)?;
    assert_frozen_schema_is_used_for_final_assembly(
        fixture.case,
        &frames,
        &accepted_schema,
        7,
        &fixture.plaintext,
    )?;
    assert_schema_report_cap_preserves_artifact(&frames, &report, work_limit)?;
    Ok(())
}

fn frozen_session_relative_rule() -> RelationalTransformRule {
    RelationalTransformRule {
        seed_locator: RelationalByteRangeLocator {
            coordinate_basis: RelationalCoordinateBasis::MessageStartV1,
            direction: Direction::FirstToSecond,
            marker_offset: 3,
            marker: vec![0x1a, 0x73],
            value_offset: 10,
            value_length: Some(8),
            declared_length: None,
        },
        payload_locator: RelationalByteRangeLocator {
            coordinate_basis: RelationalCoordinateBasis::MessageStartV1,
            direction: Direction::FirstToSecond,
            marker_offset: 3,
            marker: vec![0xb2, 0x39],
            value_offset: 10,
            value_length: None,
            declared_length: None,
        },
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

fn replay_frozen_frames(
    samples: &[RelationalRecordSample<'_>],
    stored_samples: &[StoredSample],
    sessions: &[RelationalSessionId],
    rule: &RelationalTransformRule,
    work_limit: usize,
) -> TestResult<Vec<super::DecodedFrameOutput>> {
    let mut outputs = Vec::new();
    for session in sessions {
        let session_samples = samples
            .iter()
            .filter(|sample| sample.context.session == session.session)
            .cloned()
            .collect::<Vec<_>>();
        outputs.push(apply_relational_transform_rule(
            &session_samples,
            rule,
            RelationalTransformLimits::default(),
            work_limit,
        )?);
    }
    assert_eq!(outputs.len(), 4);
    let session_orders = outputs
        .iter()
        .map(|output| output.session_order)
        .collect::<Vec<_>>();
    let frame_context = DecodedFrameContext {
        samples,
        stored_samples,
        candidate_index: 0,
        expected_session_orders: &session_orders,
        raw_directional_run: false,
    };
    let mut frames = Vec::new();
    for output in &outputs {
        let output_sha = sha256(&output.bytes);
        frames.extend(decoded_payload_frames(
            &frame_context,
            output,
            rule,
            &output_sha,
        )?);
    }
    assert_eq!(frames.len(), 8);
    for frame in &frames {
        let input = stored_samples
            .iter()
            .find(|sample| sample.node_id == frame.input_node_id)
            .ok_or("replayed frame input identity is missing")?;
        assert_eq!(frame.session_order, input.session_order);
        assert_eq!(frame.stream_offset, input.stream_offset);
    }
    Ok(frames)
}

fn frozen_session_relative_report(
    sessions: &[RelationalSessionId],
    work_limit: usize,
) -> TestResult<RelationalTransformReport> {
    let discovery_sessions = sessions
        .get(..2)
        .ok_or("discovery session partition is missing")?
        .to_vec();
    let heldout_sessions = sessions
        .get(2..)
        .ok_or("held-out session partition is missing")?
        .to_vec();
    Ok(RelationalTransformReport {
        split_basis: HoldoutBasis::CompleteSessions,
        discovery_sessions,
        heldout_sessions,
        candidates: Vec::new(),
        equivalent_candidate_aliases: 0,
        candidates_examined: 0,
        omitted_candidates: 0,
        omitted_candidates_exact: true,
        candidate_limit_remaining: 0,
        locator_candidates_examined: 0,
        locator_candidate_limit_remaining: 0,
        prefix_probe_hypotheses_examined: 0,
        prefix_probes_examined: 0,
        prefix_probe_cache_reuses: 0,
        prefix_probe_candidates_with_novelty: 0,
        prefix_probe_work_bytes: 0,
        prefix_probe_complete: true,
        work_bytes: 0,
        work_bytes_remaining: work_limit,
        search_exhaustive_within_plan: true,
        search_limits: Vec::new(),
        search_limit: None,
    })
}

fn assert_gate_accepts_frozen_schema(
    frames: &mut [super::DecodedFrameOutput],
    report: &RelationalTransformReport,
    work_limit: usize,
    plaintext: &[u8],
) -> TestResult<super::record_gate::AcceptedRecordSchema> {
    let mut cache = SchemaPlanCache::default();
    let gate = cache.screen_candidate(
        frames,
        report,
        SchemaCandidateOptions {
            parser_format: ArtifactValidationFormat::Png,
            schema_limits: RecordSchemaProposalLimits::default(),
            artifact_policy: ArtifactValidationPolicy::default(),
            work_limit,
            job: None,
        },
    )?;
    assert!(gate.work_bytes <= work_limit);
    assert_eq!(
        gate.status,
        GateStatus::ArtifactValidated,
        "gate={:?}",
        gate.details
    );
    assert!(
        gate.details
            .get("exact_artifact_matches")
            .and_then(Value::as_u64)
            .is_some_and(|matches| matches > 0)
    );
    let accepted = gate
        .accepted_schema
        .ok_or("exact artifact gate omitted the accepted record schema")?;
    assert_eq!(
        accepted.frame_indices,
        (0..frames.len()).collect::<Vec<_>>(),
        "the accepted schema must preserve the complete ordered application set"
    );
    assert_eq!(accepted.frame_identities.len(), frames.len());
    for (frame_index, (identity, frame)) in accepted
        .frame_identities
        .iter()
        .zip(frames.iter())
        .enumerate()
    {
        assert_eq!(identity.frame_index, frame_index);
        assert_eq!(identity.input_node_id, frame.input_node_id);
        assert_eq!(identity.context, frame.context);
        assert_eq!(identity.session_order, frame.session_order);
        assert_eq!(identity.stream_offset, frame.stream_offset);
        assert_eq!(identity.frame_byte_length, frame.bytes.len());
        assert_eq!(identity.frame_bytes_sha256, sha256(&frame.bytes));
    }
    assert_eq!(
        accepted.artifact_receipt.output_sha256.as_deref(),
        Some(l2_workbench::sha256(plaintext).as_str())
    );
    assert_eq!(
        accepted.artifact_receipt.output_length,
        Some(plaintext.len())
    );
    assert_accepted_schema_uses_byte_identity(frames, &accepted)?;
    Ok(accepted)
}

fn assert_accepted_schema_uses_byte_identity(
    frames: &mut [super::DecodedFrameOutput],
    accepted: &super::record_gate::AcceptedRecordSchema,
) -> TestResult {
    // Gate evaluation uses index zero; final application assigns the retained candidate index
    for frame in frames.iter_mut() {
        frame.candidate_index = 7;
    }
    assert!(
        validate_accepted_record_schema(7, frames, accepted).is_ok(),
        "the exact accepted bytes remain valid when the retained candidate index changes"
    );
    let original_bytes = frames
        .first()
        .ok_or("accepted schema has no frame to mutate")?
        .bytes
        .clone();
    *frames
        .first_mut()
        .and_then(|frame| frame.bytes.first_mut())
        .ok_or("accepted schema frame is empty")? ^= 1;
    assert!(
        validate_accepted_record_schema(7, frames, accepted).is_err(),
        "changed decoded bytes must invalidate the accepted schema identity"
    );
    frames
        .first_mut()
        .ok_or("accepted schema frame is missing")?
        .bytes = original_bytes;
    Ok(())
}

fn assert_schema_report_cap_preserves_artifact(
    frames: &[super::DecodedFrameOutput],
    report: &RelationalTransformReport,
    work_limit: usize,
) -> TestResult {
    let mut small_report_cap = RecordSchemaProposalLimits::default();
    small_report_cap.discovery.max_survivors = 4;
    let mut cache = SchemaPlanCache::default();
    let gate = cache.screen_candidate(
        frames,
        report,
        SchemaCandidateOptions {
            parser_format: ArtifactValidationFormat::Png,
            schema_limits: small_report_cap,
            artifact_policy: ArtifactValidationPolicy::default(),
            work_limit,
            job: None,
        },
    )?;
    assert_eq!(
        gate.status,
        GateStatus::ArtifactValidated,
        "gate={:?}",
        gate.details
    );
    assert!(gate.work_bytes <= work_limit);
    assert!(
        gate.details
            .get("exact_artifact_matches")
            .and_then(Value::as_u64)
            .is_some_and(|matches| matches > 0),
        "a low schema-detail cap must not hide a valid exact artifact: {:?}",
        gate.details
    );
    Ok(())
}

fn assert_frozen_schema_is_used_for_final_assembly(
    mut case: Case,
    frames: &[super::DecodedFrameOutput],
    accepted: &super::record_gate::AcceptedRecordSchema,
    candidate_index: usize,
    expected_artifact: &[u8],
) -> TestResult<()> {
    let report_node_id = add_handoff_report(&mut case)?;
    let frame_node_ids =
        add_handoff_frames(&mut case, report_node_id, frames, accepted, candidate_index)?;
    execute_frozen_schema_assembly(&mut case, report_node_id, &frame_node_ids, accepted)?;
    assert_final_handoff_receipt(
        &case,
        report_node_id,
        &frame_node_ids,
        accepted,
        expected_artifact,
    )
}

fn add_handoff_report(case: &mut Case) -> TestResult<u64> {
    Ok(case.add_bytes_node(
        "recovery_relational_transform_report",
        b"accepted schema fixture",
        Vec::new(),
        serde_json::json!({"fixture":"accepted schema handoff"}),
    )?)
}

fn add_handoff_frames(
    case: &mut Case,
    report_node_id: u64,
    frames: &[super::DecodedFrameOutput],
    accepted: &super::record_gate::AcceptedRecordSchema,
    candidate_index: usize,
) -> TestResult<Vec<u64>> {
    let mut frame_node_ids = Vec::new();
    for (frame_index, frame) in frames.iter().enumerate() {
        let identity = accepted
            .frame_identities
            .get(frame_index)
            .ok_or("accepted frame identity is missing")?;
        assert_eq!(identity.frame_index, frame_index);
        assert_eq!(identity.input_node_id, frame.input_node_id);
        assert_eq!(identity.context, frame.context);
        assert_eq!(identity.session_order, frame.session_order);
        assert_eq!(identity.stream_offset, frame.stream_offset);
        assert_eq!(identity.frame_byte_length, frame.bytes.len());
        assert_eq!(identity.frame_bytes_sha256, sha256(&frame.bytes));
        assert_eq!(frame.candidate_index, candidate_index);

        let frame_node_id = case.add_bytes_node(
            super::DECODED_FRAME_KIND,
            &frame.bytes,
            Vec::new(),
            serde_json::json!({
                "representation":"raw_bytes",
                "relational_decoded_frame":true,
                "logical_source_id":frame.context.source,
                "relational_report_node_id":report_node_id,
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
            }),
        )?;
        case.add_edge(l2_workbench::evidence::Edge {
            from: report_node_id,
            to: frame_node_id,
            relation: "supports_relational_frame".to_owned(),
            status: EvidenceStatus::Hypothesis,
            reason: "The accepted frozen schema applies to this exact decoded frame".to_owned(),
        })?;
        frame_node_ids.push(frame_node_id);
    }
    Ok(frame_node_ids)
}

fn execute_frozen_schema_assembly(
    case: &mut Case,
    report_node_id: u64,
    frame_node_ids: &[u64],
    accepted: &super::record_gate::AcceptedRecordSchema,
) -> TestResult {
    let plan = super::super::RecoveryPlan {
        discover_records: true,
        ..super::super::RecoveryPlan::default()
    };
    let policy = super::super::normal_policy(case)?;
    let mut executor = super::super::test_support::build_executor(case, &plan, &policy)?;
    executor.defer_record_schema_group(vec![(
        frame_node_ids.to_vec(),
        accepted.schema.clone(),
        report_node_id,
    )])?;
    assert!(executor.flush_pending_record_assemblies()?);

    let candidate_id = executor
        .coordinator
        .pop_next()?
        .ok_or("the frozen schema did not reach the assembly queue")?;
    let candidate = executor
        .coordinator
        .candidate(candidate_id)
        .ok_or("the frozen schema assembly candidate is missing")?;
    assert_eq!(
        candidate.task(),
        &RecoveryTask::AssembleRecords(accepted.schema.clone()),
        "the scheduler must carry the exact accepted schema without re-inference"
    );
    let candidate_inputs = candidate
        .inputs()
        .iter()
        .map(|input| {
            input.origin_node_ids().first().copied().ok_or_else(|| {
                Box::<dyn Error>::from("frozen schema candidate input has no frame identity")
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(candidate_inputs, frame_node_ids);
    executor.execute_candidate(candidate_id)?;
    let _outcome = super::super::finish_executor(executor)?;
    Ok(())
}

fn assert_final_handoff_receipt(
    case: &Case,
    report_node_id: u64,
    frame_node_ids: &[u64],
    accepted: &super::record_gate::AcceptedRecordSchema,
    expected_artifact: &[u8],
) -> TestResult {
    let selected_receipts = case
        .edges()
        .iter()
        .filter(|edge| {
            edge.from == report_node_id && edge.relation == "record_schema_selected_from"
        })
        .map(|edge| edge.to)
        .collect::<Vec<_>>();
    assert_eq!(selected_receipts.len(), 1);
    let receipt_node_id = selected_receipts
        .first()
        .copied()
        .ok_or("the accepted schema receipt link is missing")?;
    let receipt_node = case
        .node(receipt_node_id)
        .filter(|node| node.kind == "record_parse_receipt")
        .ok_or("the accepted schema did not produce a parse receipt")?;
    let receipt_blob_id = receipt_node
        .blob
        .as_deref()
        .ok_or("the final parse receipt has no serialized report")?;
    let receipt_blob = case
        .blob(receipt_blob_id)
        .ok_or("the final parse receipt bytes are missing")?;
    let receipt: Value = serde_json::from_slice(&receipt_blob.bytes)?;
    assert_receipt_input_identity(case, &receipt, frame_node_ids, accepted)?;
    assert_receipt_artifact(case, &receipt, expected_artifact)?;
    assert_record_assembly_links(case, receipt_node_id, frame_node_ids);
    Ok(())
}

fn assert_receipt_input_identity(
    case: &Case,
    receipt: &Value,
    frame_node_ids: &[u64],
    accepted: &super::record_gate::AcceptedRecordSchema,
) -> TestResult {
    let schema_value = serde_json::to_value(&accepted.schema)?;
    let input_receipts = receipt
        .get("inputs")
        .and_then(Value::as_array)
        .ok_or("the final parse receipt omitted its ordered inputs")?;
    assert_eq!(input_receipts.len(), frame_node_ids.len());
    for (input_index, (input, frame_node_id)) in
        input_receipts.iter().zip(frame_node_ids.iter()).enumerate()
    {
        assert_eq!(
            input.get("input_node").and_then(Value::as_u64),
            Some(*frame_node_id)
        );
        assert_eq!(input.pointer("/parse/schema"), Some(&schema_value));
        let frame_node = case
            .node(*frame_node_id)
            .ok_or("final parse input frame is missing")?;
        let frame_bytes = frame_node
            .blob
            .as_deref()
            .and_then(|blob_id| case.blob(blob_id))
            .ok_or("final parse input frame bytes are missing")?;
        assert_eq!(
            input.pointer("/parse/input_sha256").and_then(Value::as_str),
            Some(l2_workbench::sha256(&frame_bytes.bytes).as_str()),
            "receipt input {input_index} must bind the exact selected frame bytes"
        );
    }
    Ok(())
}

fn assert_receipt_artifact(case: &Case, receipt: &Value, expected_artifact: &[u8]) -> TestResult {
    let artifact_sha256 = l2_workbench::sha256(expected_artifact);
    let groups = receipt
        .pointer("/assembly/groups")
        .and_then(Value::as_array)
        .ok_or("the final assembly receipt omitted its groups")?;
    assert!(groups.iter().any(|group| {
        group.get("output_sha256").and_then(Value::as_str) == Some(artifact_sha256.as_str())
            && group.get("output_length").and_then(Value::as_u64)
                == u64::try_from(expected_artifact.len()).ok()
    }));
    assert!(
        case.nodes().iter().any(|node| {
            matches!(node.kind.as_str(), "record_candidate" | "record_object")
                && node
                    .blob
                    .as_deref()
                    .and_then(|blob_id| case.blob(blob_id))
                    .is_some_and(|blob| blob.bytes == expected_artifact)
        }),
        "the exact parser-validated bytes should be retained as a record candidate when no terminal sequence is supplied"
    );
    Ok(())
}

fn assert_record_assembly_links(case: &Case, receipt_node_id: u64, frame_node_ids: &[u64]) {
    for frame_node_id in frame_node_ids {
        assert!(case.edges().iter().any(|edge| {
            edge.from == receipt_node_id
                && edge.to == *frame_node_id
                && edge.relation == "record_assembly"
        }));
    }
}

fn assert_replayed_frames_match_fixture(
    frames: &[super::DecodedFrameOutput],
    inputs: &[ReplayMessage],
    plaintext: &[u8],
) -> TestResult {
    let mut input_payload_lengths = std::collections::BTreeMap::new();
    for input in inputs {
        if input.bytes.get(3..5) != Some(&[0xb2, 0x39]) {
            continue;
        }
        let sequence = u16::from_be_bytes(
            input
                .bytes
                .get(5..7)
                .ok_or("fixture payload sequence is missing")?
                .try_into()?,
        );
        input_payload_lengths.insert(
            sequence,
            input
                .bytes
                .len()
                .checked_sub(10)
                .ok_or("fixture payload header exceeds its record")?,
        );
    }

    let boundaries = [
        0,
        plaintext.len() / 5,
        plaintext.len() * 2 / 5,
        plaintext.len() * 3 / 5,
        plaintext.len(),
    ];
    let mut decoded_fragments = Vec::new();
    for frame in frames {
        let sequence = u16::from_be_bytes(
            frame
                .bytes
                .get(5..7)
                .ok_or("replayed frame sequence is missing")?
                .try_into()?,
        );
        let artifact_part = usize::from(sequence / 2);
        let part_start = *boundaries
            .get(artifact_part)
            .ok_or("replayed frame artifact part is invalid")?;
        let fragment_start = if sequence.is_multiple_of(2) {
            part_start
        } else {
            part_start
                .checked_add(
                    *input_payload_lengths
                        .get(&(sequence - 1))
                        .ok_or("first payload fragment length is missing")?,
                )
                .ok_or("replayed fragment start overflowed")?
        };
        let fragment_length = *input_payload_lengths
            .get(&sequence)
            .ok_or("replayed payload length is missing")?;
        let fragment_end = fragment_start
            .checked_add(fragment_length)
            .ok_or("replayed fragment end overflowed")?;
        let expected = plaintext
            .get(fragment_start..fragment_end)
            .ok_or("expected plaintext fragment is outside the artifact")?;
        let actual = frame
            .bytes
            .get(10..)
            .ok_or("replayed frame payload is missing")?;
        assert_eq!(actual, expected, "sequence {sequence} decoded incorrectly");
        decoded_fragments.push((sequence, actual.to_vec()));
    }
    decoded_fragments.sort_unstable_by_key(|(sequence, _)| *sequence);
    let mut reassembled = Vec::new();
    for (_, fragment) in decoded_fragments {
        reassembled.extend_from_slice(&fragment);
    }
    assert_eq!(reassembled, plaintext);
    Ok(())
}

struct ReplayMessage {
    sample: u64,
    context: MessageContext,
    session_order: u64,
    direction_node_id: u64,
    episode_node_id: u64,
    stream_offset: usize,
    bytes: Vec<u8>,
}

fn session_relative_messages(
    case: &Case,
    episodes: &[u64],
) -> Result<Vec<ReplayMessage>, Box<dyn Error>> {
    let mut samples = Vec::new();
    for (session_order, episode_node_id) in episodes.iter().copied().enumerate() {
        let direction_node_id = case
            .edges()
            .iter()
            .find(|edge| edge.from == episode_node_id && edge.relation == "contains")
            .map(|edge| edge.to)
            .ok_or("fixture session direction is missing")?;
        let run_node_id = case
            .edges()
            .iter()
            .find(|edge| edge.from == direction_node_id && edge.relation == "contains")
            .map(|edge| edge.to)
            .ok_or("fixture session run is missing")?;
        let run = case
            .node(run_node_id)
            .ok_or("fixture session run node is missing")?;
        let blob_id = run.blob.as_deref().ok_or("fixture run has no bytes")?;
        let wire = &case
            .blob(blob_id)
            .ok_or("fixture run blob is missing")?
            .bytes;
        let source = run
            .ranges
            .first()
            .map(|range| range.source.clone())
            .ok_or("fixture run has no source identity")?;
        let scope = serde_json::to_string(
            run_context_scope(case, episode_node_id).ok_or("fixture session scope is missing")?,
        )?;
        let context = MessageContext {
            source,
            scope,
            session: episode_node_id,
            direction: Direction::FirstToSecond,
        };
        let session_order = u64::try_from(session_order)
            .ok()
            .and_then(|order| order.checked_add(1))
            .ok_or("fixture session order overflowed")?;
        let mut stream_offset = 0_usize;
        while stream_offset < wire.len() {
            let prefix_end = stream_offset
                .checked_add(2)
                .ok_or("fixture record prefix overflowed")?;
            let prefix = wire
                .get(stream_offset..prefix_end)
                .ok_or("fixture record prefix is truncated")?;
            let body_length = usize::from(u16::from_be_bytes(prefix.try_into()?));
            let record_end = prefix_end
                .checked_add(body_length)
                .ok_or("fixture record length overflowed")?;
            let bytes = wire
                .get(stream_offset..record_end)
                .ok_or("fixture record is truncated")?
                .to_vec();
            let sample = u64::try_from(samples.len())?
                .checked_add(1)
                .ok_or("fixture sample identity overflowed")?;
            samples.push(ReplayMessage {
                sample,
                context: context.clone(),
                session_order,
                direction_node_id,
                episode_node_id,
                stream_offset,
                bytes,
            });
            stream_offset = record_end;
        }
    }
    Ok(samples)
}

fn run_context_scope(case: &Case, episode_node_id: u64) -> Option<&Value> {
    case.node(episode_node_id)?.details.get("scope")
}

fn session_ids(samples: &[ReplayMessage]) -> Vec<RelationalSessionId> {
    let mut sessions = Vec::new();
    for sample in samples {
        if sessions
            .last()
            .is_some_and(|session: &RelationalSessionId| session.session == sample.context.session)
        {
            continue;
        }
        sessions.push(RelationalSessionId {
            source: sample.context.source.clone(),
            scope: sample.context.scope.clone(),
            session: sample.context.session,
        });
    }
    sessions
}

fn candidate_with_outputs(
    bytes: &[u8],
    sessions: &[RelationalSessionId; 3],
) -> (RelationalTransformCandidate, Vec<RelationalAppliedOutput>) {
    let outputs = sessions
        .iter()
        .enumerate()
        .map(|(index, session)| {
            let sample = 101 + u64::try_from(index).unwrap_or_default();
            RelationalAppliedOutput {
                session: session.clone(),
                session_order: session.session,
                seed_sample: sample.saturating_add(100),
                payload_mappings: vec![RelationalOutputMapping {
                    sample,
                    source_range: ByteRange { start: 4, end: 9 },
                    output_range: ByteRange {
                        start: 0,
                        end: bytes.len(),
                    },
                }],
                bytes: bytes.to_vec(),
                parser_validation_deferred: true,
                work_bytes: 0,
            }
        })
        .collect::<Vec<_>>();
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
    let candidate = RelationalTransformCandidate {
        rule: RelationalTransformRule {
            seed_locator: locator(0),
            payload_locator: locator(4),
            operation: RelationalOperationTemplate::Sha256CounterXor(RelationalSha256CounterXor {
                initial_counter: 0,
                counter_width: CounterWidth::OneByte,
                counter_byte_order: CounterByteOrder::BigEndian,
                seed_order: SeedCounterOrder::SeedThenCounter,
            }),
            counter_reset: RelationalCounterReset::Continuous,
            parser_scope: RelationalParserScope::AcrossSessions,
            parser_format: ArtifactValidationFormat::Png,
        },
        discovery: fit(checks.iter().take(2).cloned().collect()),
        heldout: fit(checks.iter().skip(2).cloned().collect()),
        status: RelationalTransformStatus::AwaitingAcrossSessionValidation,
    };
    (candidate, outputs)
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

fn locator(value_offset: usize) -> RelationalByteRangeLocator {
    RelationalByteRangeLocator {
        coordinate_basis: RelationalCoordinateBasis::MessageStartV1,
        direction: Direction::FirstToSecond,
        marker_offset: 0,
        marker: vec![0x4d],
        value_offset,
        value_length: None,
        declared_length: None,
    }
}

fn session(session: u64) -> RelationalSessionId {
    RelationalSessionId {
        source: "source".to_owned(),
        scope: "scope".to_owned(),
        session,
    }
}

fn message_context(session: &RelationalSessionId) -> MessageContext {
    MessageContext {
        source: session.source.clone(),
        scope: session.scope.clone(),
        session: session.session,
        direction: Direction::FirstToSecond,
    }
}
