use super::{
    CounterWidth, RelationalCandidateEvaluation, RelationalParserScope,
    RelationalTransformEvaluationOptions, TestResult, anchored_search_plan,
    anchored_session_records, samples_from_records,
};
use l2_workbench::protocol::{
    RelationalSearchCursor, RelationalSearchStep,
    infer_relational_transform_candidates_with_evaluator_and_history,
    step_relational_transform_candidates_with_evaluator_and_history,
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
    let actual = loop {
        match step_relational_transform_candidates_with_evaluator_and_history(
            &samples,
            &plan,
            None,
            options,
            None,
            cursor,
            11,
            |_, candidate, _, _| {
                observed_calls.push(candidate.rule.clone());
                Ok::<_, Infallible>(RelationalCandidateEvaluation {
                    priority: 1,
                    work_bytes: 0,
                    assessment: 7_u8,
                })
            },
        )? {
            RelationalSearchStep::Complete(report) => break report,
            RelationalSearchStep::Paused(saved) => {
                pauses += 1;
                let bytes = saved
                    .encode_checkpoint(4 * 1024 * 1024, |value| serde_json::to_value(value))?;
                cursor = Some(RelationalSearchCursor::decode_checkpoint(
                    &bytes,
                    4 * 1024 * 1024,
                    |_, _, value| serde_json::from_value::<u8>(value),
                )?);
            }
        }
    };
    assert!(pauses > 1);
    assert_eq!(actual, baseline);
    assert_eq!(observed_calls, baseline_calls);
    Ok(())
}
