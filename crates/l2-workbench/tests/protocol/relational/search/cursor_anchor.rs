use super::{
    CounterWidth, RelationalCandidateEvaluation, RelationalParserScope,
    RelationalTransformEvaluationOptions, TestResult, anchored_search_plan,
    anchored_session_records, samples_from_records,
};
use l2_workbench::{
    job::MemoryBudget,
    protocol::{
        RelationalCursorError, RelationalRestoreBudget, RelationalSearchSession,
        RelationalSearchStep, infer_relational_transform_candidates_with_evaluator_and_history,
    },
};
use std::convert::Infallible;

#[test]
fn resuming_preserves_anchor_ranking_prefix_work_and_candidate_order() -> TestResult<()> {
    let records = anchored_session_records(9, 4, 4, false, false, CounterWidth::OneByte)?;
    let samples = samples_from_records(&records, 201)?;
    let mut plan = anchored_search_plan();
    plan.parser_scope = RelationalParserScope::AcrossSessions;
    plan.limits.max_candidates = 256;
    plan.limits.max_retained_candidates = 8;
    let options = RelationalTransformEvaluationOptions {
        max_retained_output_bytes: 16 * 1024,
    };
    let mut baseline_calls = Vec::new();
    let baseline = infer_relational_transform_candidates_with_evaluator_and_history(
        &samples,
        &plan,
        None,
        options,
        None,
        |_, candidate, _, _| {
            baseline_calls.push(candidate.rule.clone());
            Ok::<_, Infallible>(RelationalCandidateEvaluation {
                priority: 1,
                work_bytes: 0,
                assessment: 7_u8,
            })
        },
    )?;
    assert!(baseline.report.prefix_probes_examined > 0);
    assert!(baseline.report.prefix_probe_work_bytes > 0);

    let mut observed_calls = Vec::new();
    let mut cursor = None;
    let mut pauses = 0;
    let mut session = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
    let mut restored_memory = None;
    let actual = loop {
        match session.step(cursor, 11, |_, candidate, _, _| {
            observed_calls.push(candidate.rule.clone());
            Ok::<_, Infallible>(RelationalCandidateEvaluation {
                priority: 1,
                work_bytes: 0,
                assessment: 7_u8,
            })
        })? {
            RelationalSearchStep::Complete(report) => break report,
            RelationalSearchStep::Paused(saved) => {
                pauses += 1;
                if pauses == 1 {
                    let encode_memory = MemoryBudget::new(64 * 1024 * 1024);
                    let (bytes, _encoded_lease) = session.encode_checkpoint(
                        &saved,
                        4 * 1024 * 1024,
                        &encode_memory,
                        |value, writer| serde_json::to_writer(writer, value),
                    )?;
                    drop(saved);
                    drop(session);
                    session = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
                    let memory = MemoryBudget::new(64 * 1024 * 1024);
                    let (restored, lease) = session.restore_checkpoint(
                        &bytes,
                        4 * 1024 * 1024,
                        &memory,
                        &mut RelationalRestoreBudget::new(usize::MAX, usize::MAX),
                        |_, _, value, _| {
                            serde_json::from_value::<u8>(value)
                                .map_err(RelationalCursorError::Assessment)
                        },
                    )?;
                    restored_memory = Some(lease);
                    cursor = Some(restored);
                } else {
                    cursor = Some(saved);
                }
            }
        }
    };
    assert!(pauses > 1);
    assert_eq!(actual, baseline);
    assert_eq!(observed_calls, baseline_calls);
    assert!(restored_memory.is_some());
    Ok(())
}

#[test]
fn anchored_search_handles_a_locator_limit_with_no_absolute_payloads() -> TestResult<()> {
    let records = anchored_session_records(9, 4, 4, false, false, CounterWidth::OneByte)?;
    let samples = samples_from_records(&records, 201)?;
    let mut plan = anchored_search_plan();
    plan.parser_scope = RelationalParserScope::AcrossSessions;
    plan.limits.max_locator_candidates = 1;
    plan.limits.max_candidates = 256;
    let report = infer_relational_transform_candidates_with_evaluator_and_history(
        &samples,
        &plan,
        None,
        RelationalTransformEvaluationOptions::default(),
        None,
        |_, _, _, _| {
            Ok::<_, Infallible>(RelationalCandidateEvaluation {
                priority: 0,
                work_bytes: 0,
                assessment: (),
            })
        },
    )?;
    assert!(report.report.prefix_probe_hypotheses_examined > 0);
    assert!(!report.report.search_exhaustive_within_plan);
    Ok(())
}
