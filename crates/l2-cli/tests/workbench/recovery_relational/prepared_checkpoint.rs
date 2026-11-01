use super::{
    AppliedOutput, DecodedFrameOutput, RelationalLane,
    checkpoint::{
        ActiveSearch, RelationalProgress,
        prepared::{CandidateVerification, validate_prepared, verify_candidate},
    },
    gate_checkpoint_tests::Fixture,
    materialization_tests::replay_frozen_frames,
    record_gate::{
        AcceptedRecordSchema, SchemaCacheRestoreContext, SchemaCandidateOptions, SchemaPlanCache,
    },
    scheduler_tests::{add_cohort_views, simple_cohort},
    search,
};
use crate::workbench::recovery_executor::{Executor, RecoveryPlan, normal_policy, test_support};
use l2_workbench::{
    artifact::{ArtifactValidationFormat, ArtifactValidationPolicy},
    job::MemoryBudget,
    protocol::{
        RecordSchemaProposalLimits, RelationalRestoreBudget, RelationalTransformLimits,
        RelationalTransformRule, apply_relational_transform_rule,
    },
    sha256,
};
use std::error::Error;

const WORK_LIMIT: usize = 64 * 1024 * 1024;
const WORKSPACE: usize = 64 * 1024 * 1024;
const CHECKPOINT_LIMIT: usize = 4 * 1024 * 1024;
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn candidate() -> TestResult<(Fixture, Vec<DecodedFrameOutput>, AcceptedRecordSchema)> {
    let fixture = Fixture::new()?;
    let samples = fixture.samples();
    let stored = fixture.stored();
    let frames = replay_frozen_frames(
        &samples,
        &stored,
        &fixture.sessions,
        &fixture.correct,
        WORK_LIMIT,
    )?;
    let mut cache = SchemaPlanCache::default();
    let accepted = cache
        .screen_candidate(
            &frames,
            &fixture.report,
            SchemaCandidateOptions {
                parser_format: ArtifactValidationFormat::Png,
                schema_limits: RecordSchemaProposalLimits::default(),
                artifact_policy: ArtifactValidationPolicy::default(),
                work_limit: WORK_LIMIT,
                job: None,
                producer_rule: Some(&fixture.correct),
                structural_admission: None,
            },
        )?
        .accepted_schema
        .ok_or("fixture did not produce a verified record schema")?;
    Ok((fixture, frames, accepted))
}

fn check_candidate(
    fixture: &Fixture,
    rule: &RelationalTransformRule,
    outputs: &[AppliedOutput],
    frames: &[DecodedFrameOutput],
    accepted: Option<&AcceptedRecordSchema>,
    work_limit: usize,
) -> Result<(), super::super::RecoveryExecutionError> {
    let samples = fixture.samples();
    let stored = fixture.stored();
    let memory = MemoryBudget::new(256 * 1024 * 1024);
    let mut work = RelationalRestoreBudget::new(work_limit, 100_000);
    let mut context = SchemaCacheRestoreContext {
        raw_directional_run: false,
        samples: &samples,
        stored_samples: &stored,
        report: &fixture.report,
        relational_limits: RelationalTransformLimits::default(),
        schema_limits: RecordSchemaProposalLimits::default(),
        artifact_policy: ArtifactValidationPolicy::default(),
        maximum_checkpoint_bytes: CHECKPOINT_LIMIT,
        maximum_workspace_bytes: WORKSPACE,
        memory: &memory,
        work: &mut work,
        job: None,
    };
    verify_candidate(
        CandidateVerification {
            candidate_index: 0,
            rule,
            saved_outputs: outputs,
            saved_frames: frames,
            accepted_schema: accepted,
            structural_evidence: None,
            reported: None,
            reported_evidence: None,
            reported_aggregate: None,
        },
        &mut context,
    )
}

fn reported_candidate<'a>(
    rule: &'a RelationalTransformRule,
    evidence: &'a serde_json::Value,
    structural: Option<&'a super::record_gate::StructuralEvidence>,
) -> CandidateVerification<'a> {
    CandidateVerification {
        candidate_index: 0,
        rule,
        saved_outputs: &[],
        saved_frames: &[],
        accepted_schema: None,
        structural_evidence: structural,
        reported: None,
        reported_evidence: Some(evidence),
        reported_aggregate: None,
    }
}

#[test]
fn prepared_candidate_replays_frames_and_validates_the_accepted_schema() -> TestResult {
    let (fixture, frames, accepted) = candidate()?;
    check_candidate(
        &fixture,
        &fixture.correct,
        &[],
        &frames,
        Some(&accepted),
        WORK_LIMIT,
    )?;
    Ok(())
}

#[test]
fn prepared_candidate_rejects_changed_output_and_source_provenance() -> TestResult {
    let (fixture, mut frames, accepted) = candidate()?;
    *frames
        .first_mut()
        .and_then(|frame| frame.bytes.first_mut())
        .ok_or("missing decoded frame bytes")? ^= 1;
    assert!(matches!(
        check_candidate(
            &fixture,
            &fixture.correct,
            &[],
            &frames,
            Some(&accepted),
            WORK_LIMIT
        ),
        Err(super::super::RecoveryExecutionError::Coordinator(
            l2_workbench::recovery::RecoveryError::InvalidCheckpoint
        ))
    ));
    *frames
        .first_mut()
        .and_then(|frame| frame.bytes.first_mut())
        .ok_or("missing decoded frame bytes")? ^= 1;
    let first = frames.first_mut().ok_or("missing decoded frame")?;
    first.direction_node_id = first
        .direction_node_id
        .checked_add(1)
        .ok_or("direction identity overflow")?;
    assert!(matches!(
        check_candidate(
            &fixture,
            &fixture.correct,
            &[],
            &frames,
            Some(&accepted),
            WORK_LIMIT
        ),
        Err(super::super::RecoveryExecutionError::Coordinator(
            l2_workbench::recovery::RecoveryError::InvalidCheckpoint
        ))
    ));
    Ok(())
}

#[test]
fn prepared_candidate_rejects_changed_source_and_forged_schema_receipt() -> TestResult {
    let (mut fixture, frames, mut accepted) = candidate()?;
    *fixture
        .messages
        .first_mut()
        .and_then(|sample| sample.bytes.get_mut(10))
        .ok_or("missing source sample byte")? ^= 1;
    assert!(
        check_candidate(
            &fixture,
            &fixture.correct,
            &[],
            &frames,
            Some(&accepted),
            WORK_LIMIT
        )
        .is_err()
    );
    *fixture
        .messages
        .first_mut()
        .and_then(|sample| sample.bytes.get_mut(10))
        .ok_or("missing source sample byte")? ^= 1;
    accepted.artifact_receipt.output_sha256 = Some("0".repeat(64));
    assert!(
        check_candidate(
            &fixture,
            &fixture.correct,
            &[],
            &frames,
            Some(&accepted),
            WORK_LIMIT
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn prepared_candidate_rejects_a_forged_aggregate_output() -> TestResult {
    let (fixture, frames, accepted) = candidate()?;
    let samples = fixture.samples();
    let session = fixture.sessions.first().ok_or("missing session")?;
    let selected = samples
        .iter()
        .filter(|sample| sample.context.session == session.session)
        .cloned()
        .collect::<Vec<_>>();
    let output = apply_relational_transform_rule(
        &selected,
        &fixture.correct,
        RelationalTransformLimits::default(),
        WORK_LIMIT,
    )?;
    let saved = AppliedOutput {
        candidate_index: 0,
        sha256: sha256(&output.bytes),
        parser_format: ArtifactValidationFormat::Png,
        session_ids: vec![output.session.session],
        session_orders: vec![output.session_order],
        seed_samples: vec![output.seed_sample],
        value: output,
    };
    assert!(
        check_candidate(
            &fixture,
            &fixture.correct,
            &[saved],
            &frames,
            Some(&accepted),
            WORK_LIMIT
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn prepared_candidate_accepts_a_real_across_session_aggregate() -> TestResult {
    let mut fixture = Fixture::new()?;
    let mut rule = fixture.correct.clone();
    rule.parser_format = ArtifactValidationFormat::Der;
    let outputs = session_outputs(&fixture, &rule)?;
    let total = outputs
        .iter()
        .try_fold(0_usize, |sum, output| sum.checked_add(output.bytes.len()))
        .ok_or("aggregate length overflow")?;
    let target = der_target(total)?;
    retarget_payloads(&mut fixture, &outputs, &target)?;
    let replayed = session_outputs(&fixture, &rule)?;
    let mut saved = saved_aggregate(&replayed, target)?;
    check_candidate(
        &fixture,
        &rule,
        std::slice::from_ref(&saved),
        &[],
        None,
        WORK_LIMIT,
    )?;
    *saved.value.bytes.last_mut().ok_or("empty aggregate")? ^= 1;
    assert!(check_candidate(&fixture, &rule, &[saved], &[], None, WORK_LIMIT).is_err());
    Ok(())
}

fn session_outputs(
    fixture: &Fixture,
    rule: &RelationalTransformRule,
) -> TestResult<Vec<l2_workbench::protocol::RelationalAppliedOutput>> {
    let samples = fixture.samples();
    let mut outputs = Vec::new();
    for session in fixture
        .report
        .discovery_sessions
        .iter()
        .chain(&fixture.report.heldout_sessions)
    {
        let selected = samples
            .iter()
            .filter(|sample| {
                sample.context.source == session.source
                    && sample.context.scope == session.scope
                    && sample.context.session == session.session
            })
            .cloned()
            .collect::<Vec<_>>();
        outputs.push(apply_relational_transform_rule(
            &selected,
            rule,
            RelationalTransformLimits::default(),
            WORK_LIMIT,
        )?);
    }
    outputs.sort_unstable_by_key(|output| output.session_order);
    Ok(outputs)
}

fn der_target(total: usize) -> TestResult<Vec<u8>> {
    let mut target = vec![0_u8; total];
    *target.first_mut().ok_or("missing DER tag")? = 0x04;
    if total <= 129 {
        *target.get_mut(1).ok_or("missing DER length")? =
            u8::try_from(total.checked_sub(2).ok_or("short DER")?)?;
    } else if (131..=258).contains(&total) {
        *target.get_mut(1).ok_or("missing DER length")? = 0x81;
        *target.get_mut(2).ok_or("missing DER length")? = u8::try_from(total - 3)?;
    } else {
        let length = u16::try_from(total.checked_sub(4).ok_or("short DER")?)?.to_be_bytes();
        if total == 130 {
            return Err("fixture size cannot encode a canonical DER octet string".into());
        }
        *target.get_mut(1).ok_or("missing DER length")? = 0x82;
        target
            .get_mut(2..4)
            .ok_or("missing DER length")?
            .copy_from_slice(&length);
    }
    Ok(target)
}

fn retarget_payloads(
    fixture: &mut Fixture,
    outputs: &[l2_workbench::protocol::RelationalAppliedOutput],
    target: &[u8],
) -> TestResult {
    let mut offset = 0_usize;
    for output in outputs {
        for mapping in &output.payload_mappings {
            let message = fixture
                .messages
                .iter_mut()
                .find(|message| message.sample == mapping.sample)
                .ok_or("mapped source missing")?;
            let source = message
                .bytes
                .get_mut(mapping.source_range.start..mapping.source_range.end)
                .ok_or("source range missing")?;
            let decoded = output
                .bytes
                .get(mapping.output_range.start..mapping.output_range.end)
                .ok_or("output range missing")?;
            let start = offset
                .checked_add(mapping.output_range.start)
                .ok_or("target range overflow")?;
            let end = offset
                .checked_add(mapping.output_range.end)
                .ok_or("target range overflow")?;
            let desired = target.get(start..end).ok_or("target range missing")?;
            for ((byte, previous), desired) in source.iter_mut().zip(decoded).zip(desired) {
                *byte ^= previous ^ desired;
            }
        }
        offset = offset
            .checked_add(output.bytes.len())
            .ok_or("aggregate offset overflow")?;
    }
    Ok(())
}

fn saved_aggregate(
    replayed: &[l2_workbench::protocol::RelationalAppliedOutput],
    target: Vec<u8>,
) -> TestResult<AppliedOutput> {
    let total = target.len();
    let first = replayed.first().ok_or("missing session output")?;
    let mut mappings = Vec::new();
    let mut offset = 0_usize;
    let mut work_bytes = 0_usize;
    for output in replayed {
        for mapping in &output.payload_mappings {
            let mut mapping = mapping.clone();
            mapping.output_range.start = mapping
                .output_range
                .start
                .checked_add(offset)
                .ok_or("mapping overflow")?;
            mapping.output_range.end = mapping
                .output_range
                .end
                .checked_add(offset)
                .ok_or("mapping overflow")?;
            mappings.push(mapping);
        }
        offset = offset
            .checked_add(output.bytes.len())
            .ok_or("aggregate offset overflow")?;
        work_bytes = work_bytes
            .checked_add(output.work_bytes)
            .ok_or("aggregate work overflow")?;
    }
    let saved = AppliedOutput {
        candidate_index: 0,
        sha256: sha256(&target),
        parser_format: ArtifactValidationFormat::Der,
        session_ids: replayed
            .iter()
            .map(|output| output.session.session)
            .collect(),
        session_orders: replayed.iter().map(|output| output.session_order).collect(),
        seed_samples: replayed.iter().map(|output| output.seed_sample).collect(),
        value: l2_workbench::protocol::RelationalAppliedOutput {
            session: first.session.clone(),
            session_order: first.session_order,
            seed_sample: first.seed_sample,
            payload_mappings: mappings,
            bytes: target,
            parser_validation_deferred: false,
            work_bytes: work_bytes
                .checked_add(total)
                .ok_or("aggregate work overflow")?,
        },
    };
    Ok(saved)
}

#[test]
fn prepared_candidate_stops_when_verification_work_is_unavailable() -> TestResult {
    let (fixture, frames, accepted) = candidate()?;
    assert!(check_candidate(&fixture, &fixture.correct, &[], &frames, Some(&accepted), 0).is_err());
    Ok(())
}

#[test]
fn each_session_rule_is_incompatible_with_resumable_cohort_replay() -> TestResult {
    let (fixture, frames, accepted) = candidate()?;
    let mut rule = fixture.correct.clone();
    rule.parser_scope = l2_workbench::protocol::RelationalParserScope::EachSession;
    assert!(check_candidate(&fixture, &rule, &[], &frames, Some(&accepted), WORK_LIMIT).is_err());
    Ok(())
}

#[test]
fn evicted_positive_schema_is_replayed_from_its_report_receipt() -> TestResult {
    let (fixture, _, accepted) = candidate()?;
    let samples = fixture.samples();
    let stored = fixture.stored();
    let memory = MemoryBudget::new(256 * 1024 * 1024);
    let mut work = RelationalRestoreBudget::new(WORK_LIMIT, 100_000);
    let mut context = SchemaCacheRestoreContext {
        raw_directional_run: false,
        samples: &samples,
        stored_samples: &stored,
        report: &fixture.report,
        relational_limits: RelationalTransformLimits::default(),
        schema_limits: RecordSchemaProposalLimits::default(),
        artifact_policy: ArtifactValidationPolicy::default(),
        maximum_checkpoint_bytes: CHECKPOINT_LIMIT,
        maximum_workspace_bytes: WORKSPACE,
        memory: &memory,
        work: &mut work,
        job: None,
    };
    let mut positive = serde_json::json!({
        "candidate_index":0,
        "artifact_validated":true,
        "structurally_supported":false,
        "accepted_record_schema":super::application::accepted_record_schema_json(&accepted),
    });
    verify_candidate(
        reported_candidate(&fixture.correct, &positive, None),
        &mut context,
    )?;
    let structural_without_witness = serde_json::json!({
        "candidate_index":0,
        "artifact_validated":false,
        "structurally_supported":true,
        "accepted_record_schema":null,
    });
    assert!(
        verify_candidate(
            reported_candidate(&fixture.correct, &structural_without_witness, None),
            &mut context
        )
        .is_err()
    );
    let forged_witness: super::record_gate::StructuralEvidence =
        serde_json::from_value(serde_json::json!({"witnesses":[], "family_selectors":[]}))?;
    assert!(
        verify_candidate(
            reported_candidate(
                &fixture.correct,
                &structural_without_witness,
                Some(&forged_witness)
            ),
            &mut context
        )
        .is_err()
    );
    *positive
        .pointer_mut("/accepted_record_schema/artifact_receipt/output_sha256")
        .ok_or("missing artifact digest")? = serde_json::json!("0".repeat(64));
    assert!(
        verify_candidate(
            reported_candidate(&fixture.correct, &positive, None),
            &mut context
        )
        .is_err()
    );
    Ok(())
}

fn with_prepared(
    check: impl FnOnce(&mut Executor<'_>, &mut RelationalProgress) -> TestResult,
) -> TestResult {
    let mut case = l2_workbench::evidence::Case::new();
    let (first_key, first_samples) = simple_cohort(&mut case, 1)?;
    let (second_key, second_samples) = simple_cohort(&mut case, 2)?;
    let plan = RecoveryPlan::default();
    let mut policy = normal_policy(&case)?;
    policy.relational_transform_plan.parser_scope =
        l2_workbench::protocol::RelationalParserScope::AcrossSessions;
    policy.relational_transform_plan.limits.max_candidates = 4;
    policy
        .relational_transform_plan
        .limits
        .max_locator_candidates = 16;
    policy.relational_transform_plan.limits.max_work_bytes = 8_192;
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    add_cohort_views(&mut executor, first_key, &first_samples, &first_samples);
    add_cohort_views(&mut executor, second_key, &second_samples, &second_samples);
    assert!(executor.flush_relational_cohorts(RelationalLane::Normal)?);
    let candidate_id = executor
        .coordinator
        .peek_next_id()
        .ok_or("candidate missing")?;
    let first = executor
        .relational_discoveries
        .get(&candidate_id)
        .and_then(|items| items.first())
        .ok_or("first context missing")?
        .clone();
    let second = executor
        .relational_discoveries
        .values()
        .flatten()
        .find(|context| context != &&first)
        .ok_or("second context missing")?
        .clone();
    executor
        .relational_discoveries
        .insert(candidate_id, vec![first.clone(), second]);
    let (_, base_plan) = executor.relational_task_plan(candidate_id)?;
    let mut remaining = executor.coordinator.remaining_work_bytes();
    let cohort = search::prepare_cohort(&executor, first, &base_plan, &mut remaining, None)?;
    let mut progress = RelationalProgress {
        candidate_id,
        next_context: 1,
        work_remaining: remaining,
        prepared: vec![cohort],
        // The active cursor is checked by the scheduler; this fixture checks prior cohorts
        active: Some(ActiveSearch {
            cursor: vec![1],
            gate: vec![1],
            history: Vec::new(),
            candidates_examined: 0,
            _memory: Vec::new(),
        }),
    };
    check(&mut executor, &mut progress)
}

fn check_prepared(
    executor: &Executor<'_>,
    progress: &RelationalProgress,
    work_bytes: usize,
) -> Result<(), super::super::RecoveryExecutionError> {
    let memory = MemoryBudget::new(256 * 1024 * 1024);
    let mut work = RelationalRestoreBudget::new(work_bytes, 100_000);
    validate_prepared(
        executor,
        progress,
        &memory,
        &mut work,
        CHECKPOINT_LIMIT,
        WORKSPACE,
    )
}

fn first_prepared_mut(
    progress: &mut RelationalProgress,
) -> TestResult<&mut super::PreparedRelationalCohort> {
    progress
        .prepared
        .first_mut()
        .ok_or_else(|| "missing prepared cohort".into())
}

#[test]
fn completed_cohort_with_unchanged_work_and_report_is_accepted() -> TestResult {
    with_prepared(|executor, progress| {
        check_prepared(executor, progress, WORK_LIMIT)?;
        Ok(())
    })
}

#[test]
fn completed_cohort_rejects_corrupt_report_and_forged_remaining_work() -> TestResult {
    with_prepared(|executor, progress| {
        let report = std::mem::replace(
            &mut first_prepared_mut(progress)?.report_bytes,
            b"{broken".to_vec(),
        );
        assert!(matches!(
            check_prepared(executor, progress, WORK_LIMIT),
            Err(super::super::RecoveryExecutionError::Coordinator(
                l2_workbench::recovery::RecoveryError::InvalidCheckpoint
            ))
        ));
        first_prepared_mut(progress)?.report_bytes = report;
        first_prepared_mut(progress)?.work_bytes_remaining = usize::MAX;
        assert!(check_prepared(executor, progress, WORK_LIMIT).is_err());
        Ok(())
    })
}

#[test]
fn completed_cohort_rejects_forged_uniqueness_and_prefix_work_claims() -> TestResult {
    with_prepared(|executor, progress| {
        let original = first_prepared_mut(progress)?.report_bytes.clone();
        let mut report: serde_json::Value = serde_json::from_slice(&original)?;
        *report
            .pointer_mut("/output_application/uniqueness_established")
            .ok_or("missing uniqueness field")? = serde_json::json!(true);
        first_prepared_mut(progress)?.report_bytes = serde_json::to_vec(&report)?;
        assert!(check_prepared(executor, progress, WORK_LIMIT).is_err());
        report = serde_json::from_slice(&original)?;
        *report
            .pointer_mut("/prefix_probe_work_bytes")
            .ok_or("missing prefix work")? = serde_json::json!(u64::MAX);
        first_prepared_mut(progress)?.report_bytes = serde_json::to_vec(&report)?;
        assert!(check_prepared(executor, progress, WORK_LIMIT).is_err());
        report = serde_json::from_slice(&original)?;
        *report
            .pointer_mut("/output_application/supported_rules")
            .ok_or("missing supported count")? = serde_json::json!(u64::MAX);
        first_prepared_mut(progress)?.report_bytes = serde_json::to_vec(&report)?;
        assert!(check_prepared(executor, progress, WORK_LIMIT).is_err());
        report = serde_json::from_slice(&original)?;
        report
            .get_mut("aggregate_parser_checks")
            .and_then(serde_json::Value::as_array_mut)
            .ok_or("missing aggregate parser checks")?
            .push(serde_json::json!({"accepted":false,"parser_work_bytes":u64::MAX}));
        first_prepared_mut(progress)?.report_bytes = serde_json::to_vec(&report)?;
        assert!(check_prepared(executor, progress, WORK_LIMIT).is_err());
        report = serde_json::from_slice(&original)?;
        report
            .get_mut("application_evidence_checks")
            .and_then(serde_json::Value::as_array_mut)
            .ok_or("missing application checks")?
            .push(serde_json::json!({
                "candidate_index":0,"status":"pending","artifact_validated":"true",
                "structurally_supported":false,"accepted_record_schema":null
            }));
        first_prepared_mut(progress)?.report_bytes = serde_json::to_vec(&report)?;
        assert!(check_prepared(executor, progress, WORK_LIMIT).is_err());
        report = serde_json::from_slice(&original)?;
        report
            .as_object_mut()
            .ok_or("report is not an object")?
            .insert(
                "all_candidates_independently_verified".to_owned(),
                serde_json::json!(true),
            );
        first_prepared_mut(progress)?.report_bytes = serde_json::to_vec(&report)?;
        assert!(check_prepared(executor, progress, WORK_LIMIT).is_err());
        report = serde_json::from_slice(&original)?;
        *report
            .get_mut("search_limits")
            .ok_or("missing search limits")? = serde_json::json!(["forged_limit"]);
        first_prepared_mut(progress)?.report_bytes = serde_json::to_vec(&report)?;
        assert!(check_prepared(executor, progress, WORK_LIMIT).is_err());
        Ok(())
    })
}

#[test]
fn completed_cohort_rejects_conflicting_duplicate_report_keys() -> TestResult {
    with_prepared(|executor, progress| {
        let report = std::str::from_utf8(&first_prepared_mut(progress)?.report_bytes)?;
        let duplicate = report.replacen(
            "\"uniqueness_established\":false",
            "\"uniqueness_established\":true,\"uniqueness_established\":false",
            1,
        );
        assert_ne!(duplicate, report);
        first_prepared_mut(progress)?.report_bytes = duplicate.into_bytes();
        assert!(check_prepared(executor, progress, WORK_LIMIT).is_err());
        Ok(())
    })
}

#[test]
fn completed_cohort_rejects_a_swapped_discovery_and_holdout_partition() -> TestResult {
    with_prepared(|executor, progress| {
        let mut report: serde_json::Value =
            serde_json::from_slice(&first_prepared_mut(progress)?.report_bytes)?;
        let discovery = report
            .get("discovery_sessions")
            .cloned()
            .ok_or("missing discovery sessions")?;
        let heldout = report
            .get("heldout_sessions")
            .cloned()
            .ok_or("missing heldout sessions")?;
        let fields = report.as_object_mut().ok_or("report is not an object")?;
        fields.insert("discovery_sessions".to_owned(), heldout);
        fields.insert("heldout_sessions".to_owned(), discovery);
        first_prepared_mut(progress)?.report_bytes = serde_json::to_vec(&report)?;
        assert!(check_prepared(executor, progress, WORK_LIMIT).is_err());
        Ok(())
    })
}

#[test]
fn completed_cohort_rejects_unavailable_verification_work() -> TestResult {
    with_prepared(|executor, progress| {
        assert!(check_prepared(executor, progress, 0).is_err());
        Ok(())
    })
}

#[test]
fn completed_cohort_rejects_a_missing_active_checkpoint_boundary() -> TestResult {
    with_prepared(|executor, progress| {
        progress.active = None;
        assert!(check_prepared(executor, progress, WORK_LIMIT).is_err());
        Ok(())
    })
}

#[test]
fn live_restore_checks_completed_report_before_active_cursor() -> TestResult {
    use crate::{
        arguments::RecoveryOptions,
        workbench::recovery_executor::{
            execution_state::{SchedulerCursor, SchedulerPhase},
            resume::RecoveryResume,
        },
    };
    use l2_workbench::job::cache::{Cache, SourceIdentity, StageKey};

    with_prepared(|executor, progress| {
        let correct_report = std::mem::replace(
            &mut first_prepared_mut(progress)?.report_bytes,
            b"{broken".to_vec(),
        );
        let candidate_id = progress.candidate_id;
        let saved = std::mem::replace(
            progress,
            RelationalProgress {
                candidate_id,
                next_context: 0,
                work_remaining: 0,
                prepared: Vec::new(),
                active: None,
            },
        );
        let mut cursor = SchedulerCursor::default();
        cursor.phase = SchedulerPhase::Running;
        cursor.begun_relational = Some(candidate_id);
        cursor.active_relational = Some(saved);
        cursor.restoration_pending = true;
        let directory = tempfile::tempdir()?;
        let options = RecoveryOptions {
            memory_limit: 256 * 1024 * 1024,
            ..RecoveryOptions::default()
        };
        let cache = Cache::open_at(
            directory.path().join("cache"),
            directory.path().join("state"),
            options.cache_max_bytes,
        )?;
        let source = SourceIdentity::from_sha256("c".repeat(64))?;
        let key = StageKey::new(
            "prepared_order",
            1,
            "prepared_order",
            &serde_json::json!({}),
            &source,
            &[],
        )?;
        let mut lease = cache.lease(&key)?;
        let memory = MemoryBudget::new(256 * 1024 * 1024);
        let mut resume = RecoveryResume::new(&mut lease, &options, Some(&memory));
        let first = super::checkpoint::prepare(executor, candidate_id, &mut cursor, &mut resume);
        assert!(matches!(
            first,
            Err(super::super::RecoveryExecutionError::Coordinator(
                l2_workbench::recovery::RecoveryError::InvalidCheckpoint
            ))
        ));
        let progress = cursor
            .active_relational
            .as_mut()
            .ok_or("failed restore consumed progress")?;
        first_prepared_mut(progress)?.report_bytes = correct_report;
        let second = super::checkpoint::prepare(executor, candidate_id, &mut cursor, &mut resume);
        assert!(matches!(
            second,
            Err(super::super::RecoveryExecutionError::Operational { .. })
        ));
        Ok(())
    })
}

#[test]
fn completed_cohort_without_history_rejects_a_published_rule() -> TestResult {
    with_prepared(|executor, progress| {
        let fixture = Fixture::new()?;
        first_prepared_mut(progress)?
            .published_rules
            .push(fixture.correct);
        assert!(check_prepared(executor, progress, WORK_LIMIT).is_err());
        Ok(())
    })
}

#[test]
fn completed_cohort_rejects_a_report_workspace_that_cannot_hold_its_projection() -> TestResult {
    with_prepared(|executor, progress| {
        let memory = MemoryBudget::new(256 * 1024 * 1024);
        let mut work = RelationalRestoreBudget::new(WORK_LIMIT, 100_000);
        assert!(
            validate_prepared(executor, progress, &memory, &mut work, CHECKPOINT_LIMIT, 1).is_err()
        );
        Ok(())
    })
}
