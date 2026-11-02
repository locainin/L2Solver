use super::{
    CHECKPOINT_LIMIT, Infallible, Job, RelationalParserScope, RelationalRestoreBudget,
    RelationalSearchSession, RelationalSearchStep, RelationalTransformEvaluationOptions, SCOPE,
    TestResult, borrow_samples, decode_assessment, evaluate,
    infer_relational_transform_candidates_with_evaluator_and_history, search_plan,
    synthetic_sessions,
};
use l2_workbench::{
    derivation::{CounterByteOrder, CounterWidth, SeedCounterOrder},
    job::{MemoryBudget, MemoryLease},
    protocol::{
        RelationalCandidateEvaluationReport, RelationalCounterReset, RelationalRecordSample,
        RelationalTransformPlan, RelationalTransformRule,
    },
};

type SlicedResult = (
    RelationalCandidateEvaluationReport<usize>,
    Vec<RelationalTransformRule>,
    MemoryLease,
);

fn absolute_plan() -> RelationalTransformPlan {
    let mut plan = search_plan();
    plan.parser_scope = RelationalParserScope::AcrossSessions;
    plan.counter_widths = vec![CounterWidth::OneByte];
    plan.counter_byte_orders = vec![CounterByteOrder::BigEndian];
    plan.seed_orders = vec![SeedCounterOrder::SeedThenCounter];
    plan.initial_counters = vec![0];
    plan.counter_resets = vec![RelationalCounterReset::Continuous];
    plan.limits.max_locator_candidates = 256;
    plan.limits.max_candidates = 2_000;
    plan.limits.max_retained_candidates = 6;
    plan
}

fn sliced_after_absolute_restart(
    samples: &[RelationalRecordSample<'_>],
    plan: &RelationalTransformPlan,
    options: RelationalTransformEvaluationOptions,
    job: &Job,
) -> TestResult<SlicedResult> {
    let mut session = RelationalSearchSession::new(samples, plan, Some(job), options, None)?;
    let mut cursor = None;
    let mut calls = Vec::new();
    let mut restored_memory = None;
    for _ in 0..10_000 {
        let step = session.step(cursor, 23, |_, candidate, _, _| {
            calls.push(candidate.rule.clone());
            Ok::<_, Infallible>(evaluate(candidate))
        })?;
        let saved = match step {
            RelationalSearchStep::Complete(report) => {
                return Ok((
                    report,
                    calls,
                    restored_memory.ok_or("absolute restart was not reached")?,
                ));
            }
            RelationalSearchStep::Paused(saved) => saved,
        };
        if restored_memory.is_some() {
            cursor = Some(saved);
            continue;
        }
        let memory = MemoryBudget::new(64 * 1024 * 1024);
        let (bytes, _encoded_lease) =
            session.encode_checkpoint(&saved, CHECKPOINT_LIMIT, &memory, |value, writer| {
                serde_json::to_writer(writer, value)
            })?;
        let envelope: serde_json::Value = serde_json::from_slice(&bytes)?;
        let at_absolute = envelope
            .pointer("/payload/position/stage/stage")
            .and_then(serde_json::Value::as_str)
            == Some("absolute")
            && envelope
                .pointer("/payload/position/stage/schedule/pairs_returned")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|count| count > 2);
        if !at_absolute {
            cursor = Some(saved);
            continue;
        }
        let saved_work = job.work_snapshot()?;
        drop(saved);
        drop(session);
        job.restore_work(saved_work)?;
        session = RelationalSearchSession::new(samples, plan, Some(job), options, None)?;
        let mut restore_work = RelationalRestoreBudget::new(plan.limits.max_work_bytes, 100_000);
        let (saved, lease) = session.restore_checkpoint(
            &bytes,
            CHECKPOINT_LIMIT,
            &memory,
            &mut restore_work,
            decode_assessment,
        )?;
        assert!(restore_work.schedule_steps() > 2);
        restored_memory = Some(lease);
        cursor = Some(saved);
    }
    Err("absolute-stage search did not make bounded progress".into())
}

#[test]
fn absolute_stage_restart_preserves_complete_report_order_and_work() -> TestResult<()> {
    let records = synthetic_sessions(false)?;
    let samples = borrow_samples(&records)?;
    let plan = absolute_plan();
    let options = RelationalTransformEvaluationOptions {
        max_retained_output_bytes: 8 * 1024,
    };
    let baseline_job = Job::new("whole absolute search").work_scope(SCOPE)?;
    let mut baseline_calls = Vec::new();
    let baseline = infer_relational_transform_candidates_with_evaluator_and_history(
        &samples,
        &plan,
        Some(&baseline_job),
        options,
        None,
        |_, candidate, _, _| {
            baseline_calls.push(candidate.rule.clone());
            Ok::<_, Infallible>(evaluate(candidate))
        },
    )?;
    let resumed_job = Job::new("restarted absolute search").work_scope(SCOPE)?;
    let (resumed, calls, _lease) =
        sliced_after_absolute_restart(&samples, &plan, options, &resumed_job)?;
    assert_ne!(baseline.evaluations.len(), 0);
    assert_eq!(resumed, baseline);
    assert_eq!(calls, baseline_calls);
    assert_eq!(resumed_job.work_snapshot()?, baseline_job.work_snapshot()?);
    Ok(())
}
