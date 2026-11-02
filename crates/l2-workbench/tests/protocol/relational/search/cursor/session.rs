use super::{
    CHECKPOINT_LIMIT, Infallible, Job, RelationalCandidateEvaluation, RelationalParserScope,
    RelationalReplayHistory, RelationalRestoreBudget, RelationalSearchStep,
    RelationalTransformEvaluationOptions, SCOPE, TestResult, borrow_samples, decode_assessment,
    evaluate, infer_relational_transform_candidates_with_evaluator_and_history, rehash,
    search_plan, synthetic_sessions,
};
use l2_workbench::{
    artifact::ArtifactValidationFormat,
    derivation::{CounterByteOrder, CounterWidth, SeedCounterOrder},
    job::{MemoryBudget, MemoryClass, admit_json},
    protocol::{
        Direction, RelationalCandidateEvaluationReport, RelationalCounterReset,
        RelationalCursorError, RelationalRecordSample, RelationalSearchSession,
        RelationalSessionId, RelationalTransformPlan, RelationalTransformRule,
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

#[derive(Debug, Eq, PartialEq)]
enum Assessment {
    PartialGate,
    Invalid,
    Equivalent,
    Other(usize),
}

#[test]
fn paused_cursor_borrows_every_retained_assessment_in_candidate_order() -> TestResult<()> {
    let records = synthetic_sessions(false)?;
    let samples = borrow_samples(&records)?;
    let plan = retained_candidates_plan();
    let mut session = RelationalSearchSession::new(
        &samples,
        &plan,
        None,
        RelationalTransformEvaluationOptions::default(),
        None,
    )?;
    let mut calls = 0_usize;
    let mut paused = None;
    for _ in 0..128 {
        let step = session.step(paused.take(), 1, |_, _, _, _| {
            let ordinal = calls;
            calls += 1;
            let assessment = match ordinal {
                0 => Assessment::PartialGate,
                1 => Assessment::Invalid,
                2 | 3 => Assessment::Equivalent,
                _ => Assessment::Other(ordinal),
            };
            Ok::<_, Infallible>(RelationalCandidateEvaluation {
                priority: u8::from(ordinal < 6),
                work_bytes: 0,
                assessment,
            })
        })?;
        let RelationalSearchStep::Paused(cursor) = step else {
            return Err("fixture completed before exercising retained assessments".into());
        };
        paused = Some(cursor);
        if calls >= 9 {
            break;
        }
    }
    assert!(calls >= 9, "fixture did not exercise the retention limit");
    let cursor = paused.ok_or("fixture did not produce a paused cursor")?;
    let retained = cursor.assessments().collect::<Vec<_>>();
    assert_eq!(
        retained,
        [
            &Assessment::PartialGate,
            &Assessment::Invalid,
            &Assessment::Equivalent,
            &Assessment::Equivalent,
            &Assessment::Other(4),
            &Assessment::Other(5),
        ]
    );
    let first_equivalent = retained
        .get(2)
        .ok_or("first equivalent assessment missing")?;
    let second_equivalent = retained
        .get(3)
        .ok_or("second equivalent assessment missing")?;
    assert!(!std::ptr::eq(*first_equivalent, *second_equivalent));
    Ok(())
}

#[test]
fn cursor_partition_survives_rejected_step_and_restore() -> TestResult<()> {
    let records = synthetic_sessions(false)?;
    let samples = borrow_samples(&records)?;
    let plan = retained_candidates_plan();
    let options = RelationalTransformEvaluationOptions::default();
    let mut session = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
    // A rejected slice leaves preparation available for a later attempt
    assert!(
        session
            .step(None, 0, |_, candidate, _, _| {
                Ok::<_, Infallible>(evaluate(candidate))
            })
            .is_err()
    );
    let mut calls = 0;
    let mut expected = None;
    let RelationalSearchStep::Paused(cursor) =
        session.step(None, 1, |context, candidate, _, _| {
            calls += 1;
            assert_eq!(
                context
                    .discovery_sessions
                    .iter()
                    .map(|id| id.session)
                    .collect::<Vec<_>>(),
                [1, 2]
            );
            assert_eq!(
                context
                    .heldout_sessions
                    .iter()
                    .map(|id| id.session)
                    .collect::<Vec<_>>(),
                [3, 4]
            );
            let partition = (
                context.discovery_sessions.to_vec(),
                context.heldout_sessions.to_vec(),
            );
            if let Some(expected) = &expected {
                assert_eq!(&partition, expected);
            } else {
                expected = Some(partition);
            }
            Ok::<_, Infallible>(evaluate(candidate))
        })?
    else {
        return Err("fixture did not pause".into());
    };
    assert!(calls > 0, "fixture did not evaluate a candidate");
    let expected = expected.ok_or("fixture did not supply a partition")?;
    let (discovery, heldout) = cursor.session_partition();
    assert_eq!(discovery, expected.0.as_slice());
    assert_eq!(heldout, expected.1.as_slice());

    let memory = MemoryBudget::new(64 * 1024 * 1024);
    let (bytes, _encoded_lease) =
        session.encode_checkpoint(&cursor, CHECKPOINT_LIMIT, &memory, |value, writer| {
            serde_json::to_writer(writer, value)
        })?;
    drop(cursor);
    drop(session);

    assert_partition_after_restore(&samples, &plan, options, &bytes, &memory, &expected)?;
    Ok(())
}

fn assert_partition_after_restore(
    samples: &[RelationalRecordSample<'_>],
    plan: &RelationalTransformPlan,
    options: RelationalTransformEvaluationOptions,
    bytes: &[u8],
    memory: &MemoryBudget,
    expected: &(Vec<RelationalSessionId>, Vec<RelationalSessionId>),
) -> TestResult<()> {
    let mut restored = RelationalSearchSession::new(samples, plan, None, options, None)?;
    let mut invalid: serde_json::Value = serde_json::from_slice(bytes)?;
    *invalid
        .pointer_mut("/payload/search/work_bytes")
        .ok_or("missing saved work")? = serde_json::json!(plan.limits.max_work_bytes + 1);
    assert!(
        restored
            .restore_checkpoint(
                &rehash(invalid)?,
                CHECKPOINT_LIMIT,
                memory,
                &mut RelationalRestoreBudget::new(usize::MAX, usize::MAX),
                decode_assessment
            )
            .is_err()
    );
    let (cursor, _restored_lease) = restored.restore_checkpoint(
        bytes,
        CHECKPOINT_LIMIT,
        memory,
        &mut RelationalRestoreBudget::new(usize::MAX, usize::MAX),
        decode_assessment,
    )?;
    let (discovery, heldout) = cursor.session_partition();
    assert_eq!(discovery, expected.0.as_slice());
    assert_eq!(heldout, expected.1.as_slice());
    Ok(())
}

#[test]
fn restored_assessments_receive_the_validated_session_partition_and_remaining_work()
-> TestResult<()> {
    let records = synthetic_sessions(false)?;
    let samples = borrow_samples(&records)?;
    let plan = retained_candidates_plan();
    let options = RelationalTransformEvaluationOptions::default();
    let mut original = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
    let RelationalSearchStep::Paused(cursor) = original.step(None, 32, |_, candidate, _, _| {
        Ok::<_, Infallible>(evaluate(candidate))
    })?
    else {
        return Err("fixture did not pause".into());
    };
    let memory = MemoryBudget::new(64 * 1024 * 1024);
    let (bytes, _encoded_lease) =
        original.encode_checkpoint(&cursor, CHECKPOINT_LIMIT, &memory, |value, writer| {
            serde_json::to_writer(writer, value)
        })?;
    let document: serde_json::Value = serde_json::from_slice(&bytes)?;
    let saved_work = usize::try_from(
        document
            .pointer("/payload/search/work_bytes")
            .and_then(serde_json::Value::as_u64)
            .ok_or("missing saved search work")?,
    )?;
    drop(cursor);
    drop(original);

    let mut restored = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
    let mut calls = 0;
    let mut decoded = Vec::new();
    let (cursor, _lease) = restored.restore_checkpoint(
        &bytes,
        CHECKPOINT_LIMIT,
        &memory,
        &mut RelationalRestoreBudget::new(usize::MAX, usize::MAX),
        |context, candidate, outputs, value, work| {
            calls += 1;
            let discovery = context
                .discovery_sessions
                .iter()
                .map(|session| session.session)
                .collect::<Vec<_>>();
            let heldout = context
                .heldout_sessions
                .iter()
                .map(|session| session.session)
                .collect::<Vec<_>>();
            assert_eq!(discovery, [1, 2]);
            assert_eq!(heldout, [3, 4]);
            assert!(
                context
                    .discovery_sessions
                    .iter()
                    .chain(context.heldout_sessions)
                    .all(|session| session.source == "synthetic-source"
                        && session.scope == "synthetic-scope")
            );
            assert_eq!(
                context.work_bytes_remaining,
                plan.limits.max_work_bytes - saved_work
            );
            let assessment = decode_assessment(context, candidate, outputs, value, work)?;
            decoded.push(assessment);
            Ok(assessment)
        },
    )?;
    assert!(calls > 0, "fixture had no retained assessments");
    assert_eq!(cursor.assessments().copied().collect::<Vec<_>>(), decoded);
    Ok(())
}

#[test]
fn restored_empty_cursor_exposes_the_validated_session_partition() -> TestResult<()> {
    let mut records = synthetic_sessions(false)?;
    for (_, _, bytes) in &mut records {
        // Short decoys would fit in the final counter block
        bytes.resize(64, 0x77);
    }
    let samples = borrow_samples(&records)?;
    let mut plan = retained_candidates_plan();
    // A one-byte counter starting at its maximum cannot process these long sessions
    plan.counter_widths = vec![CounterWidth::OneByte];
    plan.initial_counters = vec![u64::from(u8::MAX)];
    plan.counter_resets = vec![RelationalCounterReset::Continuous];
    plan.limits.max_locator_offset = 1;
    let options = RelationalTransformEvaluationOptions::default();
    let mut original = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
    let mut evaluated = 0;
    let RelationalSearchStep::Paused(cursor) = original.step(None, 1, |_, candidate, _, _| {
        evaluated += 1;
        Ok::<_, Infallible>(evaluate(candidate))
    })?
    else {
        return Err("empty fixture did not pause".into());
    };
    assert_eq!(evaluated, 0);
    assert_eq!(cursor.assessments().count(), 0);
    let memory = MemoryBudget::new(64 * 1024 * 1024);
    let (bytes, _encoded_lease) =
        original.encode_checkpoint(&cursor, CHECKPOINT_LIMIT, &memory, |value, writer| {
            serde_json::to_writer(writer, value)
        })?;
    let envelope: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        envelope
            .pointer("/payload/search/candidates")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    drop(cursor);
    drop(original);

    let mut restored = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
    let mut decoded = 0;
    let (cursor, _lease) = restored.restore_checkpoint(
        &bytes,
        CHECKPOINT_LIMIT,
        &memory,
        &mut RelationalRestoreBudget::new(usize::MAX, usize::MAX),
        |context, candidate, outputs, value, work| {
            decoded += 1;
            decode_assessment(context, candidate, outputs, value, work)
        },
    )?;
    assert_eq!(decoded, 0);
    assert_eq!(cursor.assessments().count(), 0);
    let (discovery, heldout) = cursor.session_partition();
    assert_eq!(
        discovery
            .iter()
            .map(|session| session.session)
            .collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(
        heldout
            .iter()
            .map(|session| session.session)
            .collect::<Vec<_>>(),
        [3, 4]
    );
    assert!(
        discovery
            .iter()
            .chain(heldout)
            .all(|session| session.source == "synthetic-source"
                && session.scope == "synthetic-scope")
    );
    Ok(())
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
                        &mut RelationalRestoreBudget::new(usize::MAX, usize::MAX),
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
    assert!(pauses > 2 && previous_count > 16);
    assert_ne!(baseline.evaluations.len(), 0);
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
    let result = session.restore_checkpoint(
        &bytes,
        CHECKPOINT_LIMIT,
        &memory,
        &mut RelationalRestoreBudget::new(usize::MAX, usize::MAX),
        |_, _, _, value, _| {
            decoded += 1;
            serde_json::from_value::<usize>(value).map_err(RelationalCursorError::Assessment)
        },
    );
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
        &mut RelationalRestoreBudget::new(usize::MAX, usize::MAX),
        |context, candidate, outputs, value, work| {
            decoded += 1;
            decode_assessment(context, candidate, outputs, value, work)
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
    let restored = session.restore_checkpoint(
        &bytes,
        CHECKPOINT_LIMIT,
        &memory,
        &mut RelationalRestoreBudget::new(usize::MAX, usize::MAX),
        decode_assessment,
    );
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
    assert_eq!(baseline.evaluations.len(), 0);
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
