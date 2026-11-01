use super::{
    CHECKPOINT_LIMIT, CheckpointFixture, Infallible, Job, RelationalCursorError,
    RelationalParserScope, RelationalRestoreBudget, RelationalSearchSession, RelationalSearchStep,
    RelationalTransformEvaluationOptions, TestResult, assert_resume_rejected, borrow_samples,
    checkpoint_fixture, decode_assessment, evaluate, rehash, search_plan, synthetic_sessions,
};
use l2_workbench::job::{JsonMemoryError, MemoryBudget};
use l2_workbench::protocol::{Direction, RelationalCounterReset};
use sha2::{Digest, Sha256};

#[test]
fn malformed_json_is_corruption_and_real_admission_denial_is_memory_pressure() -> TestResult<()> {
    let records = synthetic_sessions(false)?;
    let samples = borrow_samples(&records)?;
    let mut plan = search_plan();
    plan.parser_scope = RelationalParserScope::AcrossSessions;
    let options = RelationalTransformEvaluationOptions::default();
    let mut session = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
    let ample = MemoryBudget::new(64 * 1024 * 1024);
    assert!(matches!(
        session.restore_checkpoint(
            b"{",
            CHECKPOINT_LIMIT,
            &ample,
            &mut RelationalRestoreBudget::new(usize::MAX, usize::MAX),
            decode_assessment
        ),
        Err(RelationalCursorError::InvalidCheckpoint)
    ));
    let denied = MemoryBudget::new(0);
    assert!(matches!(
        session.restore_checkpoint(
            b"{}",
            CHECKPOINT_LIMIT,
            &denied,
            &mut RelationalRestoreBudget::new(usize::MAX, usize::MAX),
            decode_assessment
        ),
        Err(RelationalCursorError::Memory(JsonMemoryError::Memory(_)))
    ));
    Ok(())
}

fn absolute_checkpoint_fixture() -> TestResult<CheckpointFixture> {
    let records = synthetic_sessions(false)?;
    let samples = borrow_samples(&records)?;
    let mut plan = search_plan();
    plan.parser_scope = RelationalParserScope::AcrossSessions;
    plan.limits.max_retained_candidates = 6;
    let options = RelationalTransformEvaluationOptions::default();
    let memory = MemoryBudget::new(64 * 1024 * 1024);
    let mut session = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
    let mut cursor = None;
    let mut absolute = None;
    for _ in 0..1_000 {
        let RelationalSearchStep::Paused(saved) =
            session.step(cursor, 128, |_, candidate, _, _| {
                Ok::<_, Infallible>(evaluate(candidate))
            })?
        else {
            return Err("fixture completed before the absolute scheduler was reached".into());
        };
        let (bytes, lease) =
            session.encode_checkpoint(&saved, CHECKPOINT_LIMIT, &memory, |value, writer| {
                serde_json::to_writer(writer, value)
            })?;
        let envelope: serde_json::Value = serde_json::from_slice(&bytes)?;
        if envelope
            .pointer("/payload/position/stage/stage")
            .and_then(serde_json::Value::as_str)
            == Some("absolute")
            && envelope
                .pointer("/payload/position/stage/schedule/pairs_returned")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|count| count > 2)
            && envelope
                .pointer("/payload/position/stage/schedule/initial_pair_cursor")
                .and_then(serde_json::Value::as_u64)
                == Some(2)
        {
            absolute = Some((bytes, lease));
            break;
        }
        cursor = Some(saved);
    }
    let (bytes, lease) = absolute.ok_or("no absolute-stage boundary")?;
    drop(session);
    drop(samples);
    Ok((records, plan, options, bytes, lease))
}

#[test]
fn missing_absolute_scheduler_rows_cannot_claim_exhaustive_completion() -> TestResult<()> {
    let (records, plan, options, bytes, _lease) = absolute_checkpoint_fixture()?;
    let samples = borrow_samples(&records)?;
    let memory = MemoryBudget::new(64 * 1024 * 1024);
    let mut envelope: serde_json::Value = serde_json::from_slice(&bytes)?;
    let mut denied_session = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
    let mut denied = RelationalRestoreBudget::new(usize::MAX, 0);
    assert!(matches!(
        denied_session.restore_checkpoint(
            &bytes,
            CHECKPOINT_LIMIT,
            &memory,
            &mut denied,
            decode_assessment
        ),
        Err(RelationalCursorError::RestoreWorkLimit)
    ));
    assert_eq!(denied.schedule_steps(), 0);
    let mut valid = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
    let mut allowed = RelationalRestoreBudget::new(usize::MAX, 100_000);
    let (_cursor, _restored_lease) = valid.restore_checkpoint(
        &bytes,
        CHECKPOINT_LIMIT,
        &memory,
        &mut allowed,
        decode_assessment,
    )?;
    assert!(allowed.schedule_steps() > 0);
    let mut wrong_rotation = envelope.clone();
    let rotation = wrong_rotation
        .pointer_mut("/payload/position/stage/schedule/stream_cursor")
        .ok_or("missing stream cursor")?;
    *rotation = serde_json::json!((rotation.as_u64().ok_or("invalid stream cursor")? + 1) % 7);
    assert_resume_rejected(&samples, &plan, options, None, &rehash(wrong_rotation)?)?;
    let schedule = envelope
        .pointer_mut("/payload/position/stage/schedule")
        .ok_or("missing saved schedule")?;
    let mut removed = 0;
    for name in ["header", "aligned", "fallback"] {
        let entries = schedule
            .get_mut(name)
            .and_then(serde_json::Value::as_array_mut)
            .ok_or("missing scheduler heap")?;
        removed += entries.len();
        entries.clear();
    }
    assert!(removed > 0, "fixture has no pending scheduler work");
    *schedule
        .get_mut("initial_pair_cursor")
        .ok_or("missing initial cursor")? = serde_json::json!(2);
    *envelope
        .pointer_mut("/payload/position/current")
        .ok_or("missing current pair")? = serde_json::Value::Null;
    assert_resume_rejected(&samples, &plan, options, None, &rehash(envelope)?)
}

#[test]
fn changed_output_with_matching_hash_is_not_a_valid_rule_result() -> TestResult<()> {
    let records = synthetic_sessions(false)?;
    let samples = borrow_samples(&records)?;
    let mut plan = search_plan();
    plan.parser_scope = RelationalParserScope::AcrossSessions;
    plan.limits.max_candidates = 120;
    let options = RelationalTransformEvaluationOptions {
        max_retained_output_bytes: 8 * 1024,
    };
    let memory = MemoryBudget::new(64 * 1024 * 1024);
    let mut session = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
    let RelationalSearchStep::Paused(saved) = session.step(None, 32, |_, candidate, _, _| {
        Ok::<_, Infallible>(evaluate(candidate))
    })?
    else {
        return Err("fixture did not pause".into());
    };
    let (bytes, _lease) =
        session.encode_checkpoint(&saved, CHECKPOINT_LIMIT, &memory, |value, writer| {
            serde_json::to_writer(writer, value)
        })?;
    drop(saved);
    drop(session);
    let mut envelope: serde_json::Value = serde_json::from_slice(&bytes)?;
    let candidates = envelope
        .pointer_mut("/payload/search/candidates")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("missing candidates")?;
    let candidate = candidates
        .iter_mut()
        .find(|candidate| candidate.pointer("/outputs/discovery/0/bytes/0").is_some())
        .ok_or("fixture has no retained output")?;
    let output = candidate
        .pointer_mut("/outputs/discovery/0")
        .ok_or("missing output")?;
    let session_id = output
        .get("session")
        .ok_or("missing output session")?
        .clone();
    let payload = output
        .get_mut("bytes")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("missing output bytes")?;
    let byte = payload.first_mut().ok_or("empty output")?;
    *byte = serde_json::json!(byte.as_u64().ok_or("bad output byte")? ^ 1);
    let bytes = payload
        .iter()
        .map(|value| u8::try_from(value.as_u64().ok_or("bad output byte")?).map_err(Into::into))
        .collect::<TestResult<Vec<u8>>>()?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let checks = candidate
        .pointer_mut("/candidate/discovery/checks")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("missing checks")?;
    let check = checks
        .iter_mut()
        .find(|check| check.get("session") == Some(&session_id))
        .ok_or("missing output check")?;
    *check.get_mut("output_sha256").ok_or("missing digest")? = serde_json::json!(digest);
    let changed = rehash(envelope)?;
    assert_resume_rejected(&samples, &plan, options, None, &changed)?;
    let mut restored = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
    let mut work = RelationalRestoreBudget::new(usize::MAX, 100_000);
    let result = restored.restore_checkpoint(
        &changed,
        CHECKPOINT_LIMIT,
        &memory,
        &mut work,
        decode_assessment,
    );
    assert!(matches!(
        result,
        Err(RelationalCursorError::InvalidCheckpoint)
    ));
    assert!(work.verification_work_bytes() > 0);
    Ok(())
}

#[test]
fn cancellation_stops_restored_assessment_conversion_between_candidates() -> TestResult<()> {
    let (records, plan, options, bytes, _lease) = checkpoint_fixture()?;
    let samples = borrow_samples(&records)?;
    let job = Job::new("cancel restored assessments");
    let mut session = RelationalSearchSession::new(&samples, &plan, Some(&job), options, None)?;
    let memory = MemoryBudget::new(64 * 1024 * 1024);
    let mut decoded = 0;
    let result = session.restore_checkpoint(
        &bytes,
        CHECKPOINT_LIMIT,
        &memory,
        &mut RelationalRestoreBudget::new(usize::MAX, usize::MAX),
        |candidate, outputs, value, work| {
            decoded += 1;
            job.request_cancel();
            decode_assessment(candidate, outputs, value, work)
        },
    );
    assert!(matches!(result, Err(RelationalCursorError::Search(_))));
    assert_eq!(decoded, 1);
    Ok(())
}

#[test]
fn cancellation_stops_checkpoint_encoding_between_assessments() -> TestResult<()> {
    let records = synthetic_sessions(false)?;
    let samples = borrow_samples(&records)?;
    let mut plan = search_plan();
    plan.parser_scope = RelationalParserScope::AcrossSessions;
    plan.limits.max_candidates = 160;
    let job = Job::new("cancel checkpoint encoding");
    let mut session = RelationalSearchSession::new(
        &samples,
        &plan,
        Some(&job),
        RelationalTransformEvaluationOptions::default(),
        None,
    )?;
    let RelationalSearchStep::Paused(cursor) = session.step(None, 32, |_, candidate, _, _| {
        Ok::<_, Infallible>(evaluate(candidate))
    })?
    else {
        return Err("fixture did not pause".into());
    };
    let memory = MemoryBudget::new(64 * 1024 * 1024);
    let mut encoded = 0;
    let result = session.encode_checkpoint(&cursor, CHECKPOINT_LIMIT, &memory, |value, writer| {
        encoded += 1;
        job.request_cancel();
        serde_json::to_writer(writer, value)
    });
    assert!(matches!(result, Err(RelationalCursorError::Search(_))));
    assert_eq!(encoded, 1);
    Ok(())
}

#[test]
fn valid_output_replays_across_record_and_chunk_boundaries_in_both_reset_modes() -> TestResult<()> {
    let mut records = Vec::new();
    for session in 1_u8..=4 {
        records.push((
            u32::from(session),
            Direction::FirstToSecond,
            vec![0x31, session, session.wrapping_mul(3)],
        ));
        for length in [17, 4_096, 19] {
            let mut bytes = vec![0x82];
            bytes.extend(
                (0_u8..=u8::MAX)
                    .cycle()
                    .take(length)
                    .map(|byte| byte.wrapping_add(session)),
            );
            records.push((u32::from(session), Direction::SecondToFirst, bytes));
        }
    }
    let samples = borrow_samples(&records)?;
    for reset in [
        RelationalCounterReset::Continuous,
        RelationalCounterReset::PerRecord,
    ] {
        let mut plan = search_plan();
        plan.parser_scope = RelationalParserScope::AcrossSessions;
        plan.counter_resets = vec![reset];
        plan.limits.max_seed_bytes = 2;
        plan.limits.max_locator_offset = 2;
        plan.limits.max_locator_candidates = 32;
        plan.limits.max_candidates = 120;
        plan.limits.max_record_bytes = 5_000;
        plan.limits.max_total_bytes = 32 * 1024;
        let options = RelationalTransformEvaluationOptions {
            max_retained_output_bytes: 32 * 1024,
        };
        let memory = MemoryBudget::new(64 * 1024 * 1024);
        let mut session = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
        let RelationalSearchStep::Paused(saved) =
            session.step(None, 32, |_, candidate, _, _| {
                Ok::<_, Infallible>(evaluate(candidate))
            })?
        else {
            return Err("fixture did not pause".into());
        };
        let (bytes, _lease) =
            session.encode_checkpoint(&saved, CHECKPOINT_LIMIT, &memory, |value, writer| {
                serde_json::to_writer(writer, value)
            })?;
        let envelope: serde_json::Value = serde_json::from_slice(&bytes)?;
        let candidates = envelope
            .pointer("/payload/search/candidates")
            .and_then(serde_json::Value::as_array)
            .ok_or("missing candidates")?;
        assert!(
            candidates.iter().any(|candidate| {
                candidate
                    .pointer("/outputs/discovery/0/bytes")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|bytes| bytes.len() > 4_096)
            }),
            "fixture did not retain a multi-chunk output"
        );
        drop(saved);
        drop(session);
        let mut restored = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
        let (_cursor, _restored_lease) = restored.restore_checkpoint(
            &bytes,
            CHECKPOINT_LIMIT,
            &memory,
            &mut RelationalRestoreBudget::new(usize::MAX, usize::MAX),
            decode_assessment,
        )?;
    }
    Ok(())
}
