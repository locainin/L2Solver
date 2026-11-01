use super::{
    ArtifactValidationFormat, RelationalCandidateEvaluation, RelationalParserScope,
    RelationalTransformEvaluationOptions, TestResult, borrow_samples, search_plan,
    synthetic_sessions,
};
use l2_workbench::{
    job::{Counter, Job, Phase},
    protocol::{
        RelationalCandidateOutputs, RelationalReplayHistory, RelationalSearchCursor,
        RelationalSearchStep, RelationalTransformCandidate,
        infer_relational_transform_candidates_with_evaluator_and_history,
        step_relational_transform_candidates_with_evaluator_and_history,
    },
};
use sha2::{Digest, Sha256};
use std::convert::Infallible;

const CHECKPOINT_LIMIT: usize = 4 * 1024 * 1024;
const SCOPE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn evaluate(candidate: &RelationalTransformCandidate) -> RelationalCandidateEvaluation<usize> {
    RelationalCandidateEvaluation {
        priority: u8::from(!candidate.discovery.supported_sessions.is_empty()),
        work_bytes: 1,
        assessment: candidate.discovery.checks.len(),
    }
}

fn decode_assessment(
    _: &RelationalTransformCandidate,
    _: Option<&RelationalCandidateOutputs>,
    value: serde_json::Value,
) -> Result<usize, serde_json::Error> {
    serde_json::from_value(value)
}

fn rehash(mut envelope: serde_json::Value) -> TestResult<Vec<u8>> {
    let payload = serde_json::to_vec(&envelope["payload"])?;
    envelope["digest"] = serde_json::to_value(<[u8; 32]>::from(Sha256::digest(&payload)))?;
    Ok(serde_json::to_vec(&envelope)?)
}

#[test]
fn resumes_after_completed_candidates_with_identical_report_and_charges() -> TestResult<()> {
    let records = synthetic_sessions(false)?;
    let samples = borrow_samples(&records)?;
    let mut plan = search_plan();
    plan.parser_scope = RelationalParserScope::AcrossSessions;
    plan.parser_formats = vec![ArtifactValidationFormat::Der];
    plan.limits.max_candidates = 120;
    plan.limits.max_retained_candidates = 6;
    let options = RelationalTransformEvaluationOptions {
        max_retained_output_bytes: 8 * 1024,
    };
    let baseline_job = Job::new("uninterrupted cursor comparison").work_scope(SCOPE)?;
    let mut baseline_history = RelationalReplayHistory::new(256 * 1024);
    let mut baseline_rules = Vec::new();
    let baseline = infer_relational_transform_candidates_with_evaluator_and_history(
        &samples,
        &plan,
        Some(&baseline_job),
        options,
        Some(&mut baseline_history),
        |_, candidate, _, _| {
            baseline_rules.push(candidate.rule.clone());
            Ok::<_, Infallible>(evaluate(candidate))
        },
    )?;

    let resumed_job = Job::new("resumed cursor comparison").work_scope(SCOPE)?;
    let mut history = RelationalReplayHistory::new(256 * 1024);
    let mut observed_rules = Vec::new();
    let mut cursor = None;
    let mut previous_count = 0;
    let mut pauses = 0;
    let resumed = loop {
        let step = step_relational_transform_candidates_with_evaluator_and_history(
            &samples,
            &plan,
            Some(&resumed_job),
            options,
            Some(&mut history),
            cursor,
            7,
            |_, candidate, _, _| {
                observed_rules.push(candidate.rule.clone());
                Ok::<_, Infallible>(evaluate(candidate))
            },
        )?;
        match step {
            RelationalSearchStep::Complete(report) => break report,
            RelationalSearchStep::Paused(saved) => {
                assert!(saved.candidates_examined() > previous_count);
                previous_count = saved.candidates_examined();
                pauses += 1;
                let bytes = saved
                    .encode_checkpoint(CHECKPOINT_LIMIT, |value| serde_json::to_value(value))?;
                let history_bytes = serde_json::to_vec(&history)?;
                let work = resumed_job.work_snapshot()?;
                drop(saved);
                history = serde_json::from_slice(&history_bytes)?;
                resumed_job.restore_work(work)?;
                cursor = Some(RelationalSearchCursor::decode_checkpoint(
                    &bytes,
                    CHECKPOINT_LIMIT,
                    decode_assessment,
                )?);
            }
        }
    };
    assert!(pauses > 1);
    assert!(previous_count > 16);
    assert!(!baseline.evaluations.is_empty());
    assert_eq!(resumed, baseline);
    assert_eq!(observed_rules, baseline_rules);
    let expected_work = baseline_job.work_snapshot()?;
    let actual_work = resumed_job.work_snapshot()?;
    for counter in [Counter::CandidatesExamined, Counter::CandidatesRejected] {
        assert_eq!(actual_work.counter(counter), expected_work.counter(counter));
    }
    assert_eq!(
        actual_work.phase_work(Phase::TransformDiscovery),
        expected_work.phase_work(Phase::TransformDiscovery)
    );
    Ok(())
}

#[test]
fn rejects_incompatible_corrupt_and_oversized_checkpoints() -> TestResult<()> {
    let records = synthetic_sessions(false)?;
    let samples = borrow_samples(&records)?;
    let mut plan = search_plan();
    plan.parser_scope = RelationalParserScope::AcrossSessions;
    plan.limits.max_candidates = 120;
    let options = RelationalTransformEvaluationOptions::default();
    let step = step_relational_transform_candidates_with_evaluator_and_history(
        &samples,
        &plan,
        None,
        options,
        None,
        None,
        7,
        |_, candidate, _, _| Ok::<_, Infallible>(evaluate(candidate)),
    )?;
    let RelationalSearchStep::Paused(cursor) = step else {
        return Err("fixture did not reach a checkpoint boundary".into());
    };
    assert!(
        cursor
            .encode_checkpoint(8, |value| serde_json::to_value(value))
            .is_err()
    );
    let bytes = cursor.encode_checkpoint(CHECKPOINT_LIMIT, |value| serde_json::to_value(value))?;
    assert!(RelationalSearchCursor::decode_checkpoint(&bytes, 8, decode_assessment).is_err());
    let mut damaged = bytes.clone();
    let index = damaged.len() / 2;
    damaged[index] ^= 1;
    assert!(
        RelationalSearchCursor::decode_checkpoint(&damaged, CHECKPOINT_LIMIT, decode_assessment)
            .is_err()
    );

    // A syntactically valid envelope can still carry impossible search accounting
    let mut changed: serde_json::Value = serde_json::from_slice(&bytes)?;
    changed["payload"]["search"]["candidates_examined"] =
        serde_json::json!(plan.limits.max_candidates + 1);
    let changed = rehash(changed)?;
    let restored =
        RelationalSearchCursor::decode_checkpoint(&changed, CHECKPOINT_LIMIT, decode_assessment)?;
    let mut calls = 0_usize;
    assert!(
        step_relational_transform_candidates_with_evaluator_and_history(
            &samples,
            &plan,
            None,
            options,
            None,
            Some(restored),
            7,
            |_, candidate, _, _| {
                calls += 1;
                Ok::<_, Infallible>(evaluate(candidate))
            },
        )
        .is_err()
    );
    assert_eq!(calls, 0);

    let mut changed: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert!(!changed["payload"]["position"]["current"].is_null());
    let index = changed["payload"]["position"]["current"]["parameters"]["candidate_index"]
        .as_u64()
        .ok_or("missing parameter index")?;
    changed["payload"]["position"]["current"]["parameters"]["candidate_index"] =
        serde_json::json!(index + 1);
    let changed = rehash(changed)?;
    let restored =
        RelationalSearchCursor::decode_checkpoint(&changed, CHECKPOINT_LIMIT, decode_assessment)?;
    let mut calls = 0_usize;
    assert!(
        step_relational_transform_candidates_with_evaluator_and_history(
            &samples,
            &plan,
            None,
            options,
            None,
            Some(restored),
            7,
            |_, candidate, _, _| {
                calls += 1;
                Ok::<_, Infallible>(evaluate(candidate))
            },
        )
        .is_err()
    );
    assert_eq!(calls, 0);

    let restored =
        RelationalSearchCursor::decode_checkpoint(&bytes, CHECKPOINT_LIMIT, decode_assessment)?;
    let mut wrong_history = RelationalReplayHistory::new(256 * 1024);
    assert!(
        step_relational_transform_candidates_with_evaluator_and_history(
            &samples,
            &plan,
            None,
            options,
            Some(&mut wrong_history),
            Some(restored),
            7,
            |_, candidate, _, _| Ok::<_, Infallible>(evaluate(candidate)),
        )
        .is_err()
    );

    let mut changed_plan = plan.clone();
    changed_plan.limits.max_work_bytes -= 1;
    let restored =
        RelationalSearchCursor::decode_checkpoint(&bytes, CHECKPOINT_LIMIT, decode_assessment)?;
    assert!(
        step_relational_transform_candidates_with_evaluator_and_history(
            &samples,
            &changed_plan,
            None,
            options,
            None,
            Some(restored),
            7,
            |_, candidate, _, _| Ok::<_, Infallible>(evaluate(candidate)),
        )
        .is_err()
    );
    let mut changed_samples = samples.clone();
    changed_samples[0].session_order += 1;
    let restored =
        RelationalSearchCursor::decode_checkpoint(&bytes, CHECKPOINT_LIMIT, decode_assessment)?;
    assert!(
        step_relational_transform_candidates_with_evaluator_and_history(
            &changed_samples,
            &plan,
            None,
            options,
            None,
            Some(restored),
            7,
            |_, candidate, _, _| Ok::<_, Infallible>(evaluate(candidate)),
        )
        .is_err()
    );

    let mut unsupported = plan;
    unsupported.parser_scope = RelationalParserScope::EachSession;
    assert!(
        step_relational_transform_candidates_with_evaluator_and_history(
            &samples,
            &unsupported,
            None,
            options,
            None,
            None,
            7,
            |_, candidate, _, _| Ok::<_, Infallible>(evaluate(candidate)),
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn restored_output_provenance_must_reference_exact_input_ranges() -> TestResult<()> {
    let records = synthetic_sessions(false)?;
    let samples = borrow_samples(&records)?;
    let mut plan = search_plan();
    plan.parser_scope = RelationalParserScope::AcrossSessions;
    plan.limits.max_candidates = 120;
    let options = RelationalTransformEvaluationOptions {
        max_retained_output_bytes: 8 * 1024,
    };
    let step = step_relational_transform_candidates_with_evaluator_and_history(
        &samples,
        &plan,
        None,
        options,
        None,
        None,
        32,
        |_, candidate, _, _| Ok::<_, Infallible>(evaluate(candidate)),
    )?;
    let RelationalSearchStep::Paused(saved) = step else {
        return Err("fixture did not reach a checkpoint boundary".into());
    };
    let bytes = saved.encode_checkpoint(CHECKPOINT_LIMIT, |value| serde_json::to_value(value))?;
    let mut envelope: serde_json::Value = serde_json::from_slice(&bytes)?;
    let candidates = envelope["payload"]["search"]["candidates"]
        .as_array_mut()
        .ok_or("missing candidates")?;
    let output = candidates
        .iter_mut()
        .find_map(|candidate| {
            candidate["outputs"]["discovery"]
                .as_array_mut()
                .and_then(|outputs| outputs.first_mut())
        })
        .ok_or("fixture has no retained discovery output")?;
    output["payload_mappings"][0]["source_range"]["end"] = serde_json::json!(usize::MAX);
    let changed = rehash(envelope)?;
    let restored =
        RelationalSearchCursor::decode_checkpoint(&changed, CHECKPOINT_LIMIT, decode_assessment)?;
    let mut calls = 0;
    assert!(
        step_relational_transform_candidates_with_evaluator_and_history(
            &samples,
            &plan,
            None,
            options,
            None,
            Some(restored),
            7,
            |_, candidate, _, _| {
                calls += 1;
                Ok::<_, Infallible>(evaluate(candidate))
            },
        )
        .is_err()
    );
    assert_eq!(calls, 0);
    Ok(())
}
