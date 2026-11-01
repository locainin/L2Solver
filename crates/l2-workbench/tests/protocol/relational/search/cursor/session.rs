use super::{
    CHECKPOINT_LIMIT, Infallible, Job, RelationalParserScope, RelationalReplayHistory,
    RelationalSearchStep, RelationalTransformEvaluationOptions, SCOPE, TestResult, borrow_samples,
    decode_assessment, evaluate, infer_relational_transform_candidates_with_evaluator_and_history,
    search_plan, synthetic_sessions,
};
use l2_workbench::{
    artifact::ArtifactValidationFormat,
    derivation::{CounterByteOrder, CounterWidth, SeedCounterOrder},
    job::{MemoryBudget, MemoryClass, admit_json},
    protocol::{
        Direction, RelationalCandidateEvaluationReport, RelationalCounterReset,
        RelationalCursorError, RelationalRecordSample, RelationalSearchSession,
        RelationalTransformPlan, RelationalTransformRule,
    },
};

fn baseline_report(
    samples: &[RelationalRecordSample<'_>],
    plan: &RelationalTransformPlan,
    options: RelationalTransformEvaluationOptions,
    job: &Job,
) -> TestResult<(
    RelationalCandidateEvaluationReport<usize>,
    Vec<RelationalTransformRule>,
)> {
    let mut history = RelationalReplayHistory::new(256 * 1024);
    let mut calls = Vec::new();
    let report = infer_relational_transform_candidates_with_evaluator_and_history(
        samples,
        plan,
        Some(job),
        options,
        Some(&mut history),
        |_, candidate, _, _| {
            calls.push(candidate.rule.clone());
            Ok::<_, Infallible>(evaluate(candidate))
        },
    )?;
    Ok((report, calls))
}

fn retained_candidates_plan() -> RelationalTransformPlan {
    let mut plan = search_plan();
    plan.parser_scope = RelationalParserScope::AcrossSessions;
    plan.limits.max_candidates = 160;
    plan.limits.max_retained_candidates = 6;
    plan
}

#[test]
fn live_slices_reuse_preparation_and_restart_preserves_the_same_search() -> TestResult<()> {
    let records = synthetic_sessions(false)?;
    let samples = borrow_samples(&records)?;
    let plan = retained_candidates_plan();
    let options = RelationalTransformEvaluationOptions {
        max_retained_output_bytes: 8 * 1024,
    };
    let baseline_job = Job::new("whole search").work_scope(SCOPE)?;
    let (baseline, baseline_calls) = baseline_report(&samples, &plan, options, &baseline_job)?;

    let resumed_job = Job::new("sliced search").work_scope(SCOPE)?;
    let mut history = RelationalReplayHistory::new(256 * 1024);
    let mut session = RelationalSearchSession::new(
        &samples,
        &plan,
        Some(&resumed_job),
        options,
        Some(&mut history),
    )?;
    let mut cursor = None;
    let mut calls = Vec::new();
    let mut pauses = 0_usize;
    let mut previous_count = 0_usize;
    let mut restored_memory = None;
    let actual = loop {
        let step = session.step(cursor, 7, |_, candidate, _, _| {
            calls.push(candidate.rule.clone());
            Ok::<_, Infallible>(evaluate(candidate))
        })?;
        match step {
            RelationalSearchStep::Complete(report) => break report,
            RelationalSearchStep::Paused(saved) => {
                pauses += 1;
                assert!(pauses < 10_000, "cursor did not make bounded progress");
                assert!(saved.candidates_examined() >= previous_count);
                previous_count = saved.candidates_examined();
                if pauses == 2 {
                    assert!(saved.candidates_examined() > 0);
                    // A restart restores one committed cursor and its matching history and work
                    let encode_memory = MemoryBudget::new(64 * 1024 * 1024);
                    let (bytes, _encoded_lease) = session.encode_checkpoint(
                        &saved,
                        CHECKPOINT_LIMIT,
                        &encode_memory,
                        |value, writer| serde_json::to_writer(writer, value),
                    )?;
                    let history_bytes =
                        serde_json::to_vec(session.history().ok_or("missing history")?)?;
                    let work = resumed_job.work_snapshot()?;
                    drop(saved);
                    drop(session);
                    history = serde_json::from_slice(&history_bytes)?;
                    resumed_job.restore_work(work)?;
                    session = RelationalSearchSession::new(
                        &samples,
                        &plan,
                        Some(&resumed_job),
                        options,
                        Some(&mut history),
                    )?;
                    let memory = MemoryBudget::new(64 * 1024 * 1024);
                    let (restored, lease) = session.restore_checkpoint(
                        &bytes,
                        CHECKPOINT_LIMIT,
                        &memory,
                        decode_assessment,
                    )?;
                    // Keep the restored-state allowance until all returned evidence is consumed
                    restored_memory = Some(lease);
                    cursor = Some(restored);
                } else {
                    // Normal slices retain the already prepared indexes and locators
                    cursor = Some(saved);
                }
            }
        }
    };
    assert!(pauses > 2);
    assert!(previous_count > 16);
    assert!(!baseline.evaluations.is_empty());
    assert_eq!(actual, baseline);
    assert_eq!(calls, baseline_calls);
    assert_eq!(resumed_job.work_snapshot()?, baseline_job.work_snapshot()?);
    assert!(restored_memory.is_some());
    Ok(())
}

#[test]
fn decoded_metadata_is_admitted_before_assessment_conversion() -> TestResult<()> {
    let records = synthetic_sessions(false)?;
    let samples = borrow_samples(&records)?;
    let plan = retained_candidates_plan();
    let options = RelationalTransformEvaluationOptions::default();
    let mut session = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
    let step = session.step(None, 32, |_, candidate, _, _| {
        Ok::<_, Infallible>(evaluate(candidate))
    })?;
    let RelationalSearchStep::Paused(cursor) = step else {
        return Err("fixture did not reach a checkpoint boundary".into());
    };
    let encode_memory = MemoryBudget::new(64 * 1024 * 1024);
    let (bytes, _encoded_lease) =
        session.encode_checkpoint(&cursor, CHECKPOINT_LIMIT, &encode_memory, |_, writer| {
            serde_json::to_writer(writer, [0_u8; 4096].as_slice())
        })?;
    drop(cursor);
    drop(session);
    let mut session = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
    // Scratch space fits, but the many values do not fit the parsed-data allowance
    let limit = u64::try_from(bytes.len())?
        .checked_mul(4)
        .ok_or("limit overflow")?;
    let memory = MemoryBudget::new(limit);
    let mut decoded = 0;
    let result = session.restore_checkpoint(&bytes, CHECKPOINT_LIMIT, &memory, |_, _, value| {
        decoded += 1;
        serde_json::from_value::<usize>(value)
    });
    assert!(matches!(result, Err(RelationalCursorError::Memory(_))));
    assert_eq!(decoded, 0);
    assert_eq!(memory.snapshot()?.used(MemoryClass::Executor), 0);
    Ok(())
}

#[test]
fn restored_dimensions_need_separate_admission_before_assessment_conversion() -> TestResult<()> {
    let records = synthetic_sessions(false)?;
    let samples = borrow_samples(&records)?;
    let mut plan = search_plan();
    plan.parser_scope = RelationalParserScope::AcrossSessions;
    plan.limits.max_candidates = 160;
    let options = RelationalTransformEvaluationOptions {
        max_retained_output_bytes: 8 * 1024,
    };
    let mut source = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
    let step = source.step(None, 32, |_, candidate, _, _| {
        Ok::<_, Infallible>(evaluate(candidate))
    })?;
    let RelationalSearchStep::Paused(cursor) = step else {
        return Err("fixture did not pause".into());
    };
    let encode_memory = MemoryBudget::new(64 * 1024 * 1024);
    let (bytes, _encoded_lease) = source.encode_checkpoint(
        &cursor,
        CHECKPOINT_LIMIT,
        &encode_memory,
        |value, writer| serde_json::to_writer(writer, value),
    )?;
    let probe = MemoryBudget::new(512 * 1024 * 1024);
    let admission = admit_json(&bytes, &probe, MemoryClass::Executor)?;
    let json_allowance = probe.snapshot()?.used(MemoryClass::Executor);
    drop(admission);
    let memory = MemoryBudget::new(json_allowance);
    let mut restored_session = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
    let mut decoded = 0;
    let result = restored_session.restore_checkpoint(
        &bytes,
        CHECKPOINT_LIMIT,
        &memory,
        |candidate, outputs, value| {
            decoded += 1;
            decode_assessment(candidate, outputs, value)
        },
    );
    assert!(matches!(result, Err(RelationalCursorError::Memory(_))));
    assert_eq!(decoded, 0);
    assert_eq!(memory.snapshot()?.used(MemoryClass::Executor), 0);
    Ok(())
}

#[test]
fn a_live_session_cannot_restore_a_second_cursor() -> TestResult<()> {
    let records = synthetic_sessions(false)?;
    let samples = borrow_samples(&records)?;
    let mut plan = search_plan();
    plan.parser_scope = RelationalParserScope::AcrossSessions;
    plan.limits.max_candidates = 160;
    let options = RelationalTransformEvaluationOptions::default();
    let mut session = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
    let step = session.step(None, 7, |_, candidate, _, _| {
        Ok::<_, Infallible>(evaluate(candidate))
    })?;
    let RelationalSearchStep::Paused(cursor) = step else {
        return Err("fixture did not reach a checkpoint boundary".into());
    };
    let encode_memory = MemoryBudget::new(64 * 1024 * 1024);
    let (bytes, encoded_lease) = session.encode_checkpoint(
        &cursor,
        CHECKPOINT_LIMIT,
        &encode_memory,
        |value, writer| serde_json::to_writer(writer, value),
    )?;
    let memory = MemoryBudget::new(64 * 1024 * 1024);
    let restored = session.restore_checkpoint(&bytes, CHECKPOINT_LIMIT, &memory, decode_assessment);
    assert!(matches!(
        restored,
        Err(RelationalCursorError::InvalidCheckpoint)
    ));
    assert_eq!(memory.snapshot()?.used(MemoryClass::Executor), 0);
    assert_eq!(
        encode_memory.snapshot()?.used(MemoryClass::Executor),
        encoded_lease.bytes()
    );
    drop(bytes);
    drop(encoded_lease);
    assert_eq!(encode_memory.snapshot()?.used(MemoryClass::Executor), 0);
    Ok(())
}

#[test]
fn a_live_cursor_cannot_be_used_by_another_session() -> TestResult<()> {
    let records = synthetic_sessions(false)?;
    let samples = borrow_samples(&records)?;
    let mut plan = search_plan();
    plan.parser_scope = RelationalParserScope::AcrossSessions;
    plan.limits.max_candidates = 160;
    let options = RelationalTransformEvaluationOptions::default();
    let mut first = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
    let step = first.step(None, 7, |_, candidate, _, _| {
        Ok::<_, Infallible>(evaluate(candidate))
    })?;
    let RelationalSearchStep::Paused(cursor) = step else {
        return Err("fixture did not reach a checkpoint boundary".into());
    };
    let mut other = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
    let mut calls = 0;
    assert!(
        other
            .step(Some(cursor), 7, |_, candidate, _, _| {
                calls += 1;
                Ok::<_, Infallible>(evaluate(candidate))
            })
            .is_err()
    );
    assert_eq!(calls, 0);
    Ok(())
}

#[test]
fn zero_step_budget_leaves_a_fresh_session_available() -> TestResult<()> {
    let records = synthetic_sessions(false)?;
    let samples = borrow_samples(&records)?;
    let mut plan = search_plan();
    plan.parser_scope = RelationalParserScope::AcrossSessions;
    plan.limits.max_candidates = 160;
    let mut session = RelationalSearchSession::new(
        &samples,
        &plan,
        None,
        RelationalTransformEvaluationOptions::default(),
        None,
    )?;
    assert!(
        session
            .step::<usize, Infallible, _>(None, 0, |_, candidate, _, _| Ok(evaluate(candidate)))
            .is_err()
    );
    assert!(matches!(
        session.step(None, 7, |_, candidate, _, _| Ok::<_, Infallible>(evaluate(
            candidate
        )))?,
        RelationalSearchStep::Paused(_)
    ));
    Ok(())
}

#[test]
fn session_creation_stops_for_a_cancelled_job() -> TestResult<()> {
    let records = synthetic_sessions(false)?;
    let samples = borrow_samples(&records)?;
    let mut plan = search_plan();
    plan.parser_scope = RelationalParserScope::AcrossSessions;
    let job = Job::new("cancelled search preparation");
    job.request_cancel();
    assert!(
        RelationalSearchSession::new(
            &samples,
            &plan,
            Some(&job),
            RelationalTransformEvaluationOptions::default(),
            None,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn history_reuse_pauses_after_bounded_traversal_even_without_a_new_transform() -> TestResult<()> {
    let mut records = Vec::new();
    for session in 1_u32..=4 {
        records.push((session, Direction::FirstToSecond, vec![0x31]));
        records.push((session, Direction::SecondToFirst, vec![0x82; 512]));
        records.push((session, Direction::SecondToFirst, vec![0x82; 512]));
    }
    let samples = borrow_samples(&records)?;
    let mut plan = search_plan();
    plan.parser_scope = RelationalParserScope::AcrossSessions;
    plan.limits.max_candidates = 256;
    plan.limits.max_locator_candidates = 64;
    plan.limits.max_seed_bytes = 1;
    plan.limits.max_record_bytes = 1024;
    plan.counter_widths = vec![CounterWidth::OneByte];
    plan.counter_byte_orders = vec![CounterByteOrder::BigEndian, CounterByteOrder::LittleEndian];
    plan.seed_orders = vec![
        SeedCounterOrder::SeedThenCounter,
        SeedCounterOrder::CounterThenSeed,
    ];
    plan.initial_counters = vec![254, 255];
    plan.counter_resets = vec![
        RelationalCounterReset::Continuous,
        RelationalCounterReset::PerRecord,
    ];
    plan.parser_formats = vec![ArtifactValidationFormat::Der, ArtifactValidationFormat::Png];
    let options = RelationalTransformEvaluationOptions::default();
    let mut history = RelationalReplayHistory::new(1024 * 1024);
    let baseline = infer_relational_transform_candidates_with_evaluator_and_history(
        &samples,
        &plan,
        None,
        options,
        Some(&mut history),
        |_, candidate, _, _| Ok::<_, Infallible>(evaluate(candidate)),
    )?;
    assert!(baseline.report.candidates_examined > 16);
    assert!(baseline.evaluations.is_empty());
    let mut session =
        RelationalSearchSession::new(&samples, &plan, None, options, Some(&mut history))?;
    let mut calls = 0;
    let step = session.step(None, 7, |_, candidate, _, _| {
        calls += 1;
        Ok::<_, Infallible>(evaluate(candidate))
    })?;
    let RelationalSearchStep::Paused(cursor) = step else {
        return Err("history traversal did not yield".into());
    };
    assert_eq!(cursor.candidates_examined(), 0);
    assert_eq!(calls, 0);
    Ok(())
}
