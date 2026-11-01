use super::{
    CHECKPOINT_LIMIT, Infallible, RelationalCursorError, RelationalParserScope,
    RelationalSearchSession, RelationalSearchStep, RelationalTransformEvaluationOptions,
    TestResult, borrow_samples, checkpoint_fixture, decode_assessment, evaluate, search_plan,
    synthetic_sessions,
};
use l2_workbench::{
    job::{MemoryBudget, MemoryClass, MemoryError},
    protocol::RelationalRestoreBudget,
};

#[test]
fn preparation_allowance_is_checked_before_reserving_live_session_memory() -> TestResult<()> {
    let records = synthetic_sessions(false)?;
    let samples = borrow_samples(&records)?;
    let mut plan = search_plan();
    plan.parser_scope = RelationalParserScope::AcrossSessions;
    let required = RelationalSearchSession::preparation_memory_bytes(&samples, &plan)
        .ok_or("preparation bound overflowed")?;
    assert!(required > 0);
    let denied = MemoryBudget::new(required - 1);
    assert!(matches!(
        denied.try_reserve(MemoryClass::Executor, required),
        Err(MemoryError::Limit { .. })
    ));
    let memory = MemoryBudget::new(required);
    let lease = memory.try_reserve(MemoryClass::Executor, required)?;
    let session = RelationalSearchSession::new(
        &samples,
        &plan,
        None,
        RelationalTransformEvaluationOptions::default(),
        None,
    )?;
    assert_eq!(memory.snapshot()?.used(MemoryClass::Executor), required);
    drop(session);
    drop(lease);
    assert_eq!(memory.snapshot()?.used(MemoryClass::Executor), 0);
    plan.limits.max_locator_candidates = usize::MAX;
    assert!(RelationalSearchSession::preparation_memory_bytes(&samples, &plan).is_none());
    Ok(())
}

#[test]
fn retained_output_restore_has_a_separate_bounded_work_meter() -> TestResult<()> {
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
    let RelationalSearchStep::Paused(cursor) = session.step(None, 32, |_, candidate, _, _| {
        Ok::<_, Infallible>(evaluate(candidate))
    })?
    else {
        return Err("fixture did not pause".into());
    };
    let (bytes, _encoded_lease) =
        session.encode_checkpoint(&cursor, CHECKPOINT_LIMIT, &memory, |value, writer| {
            serde_json::to_writer(writer, value)
        })?;
    drop(cursor);
    drop(session);
    let mut denied = RelationalRestoreBudget::new(0, 100_000);
    let mut restored = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
    let result = restored.restore_checkpoint(
        &bytes,
        CHECKPOINT_LIMIT,
        &memory,
        &mut denied,
        decode_assessment,
    );
    assert!(matches!(
        result,
        Err(RelationalCursorError::RestoreWorkLimit)
    ));
    assert_eq!(denied.verification_work_bytes(), 0);
    let mut allowed = RelationalRestoreBudget::new(plan.limits.max_work_bytes, 100_000);
    let (_cursor, _lease) = restored.restore_checkpoint(
        &bytes,
        CHECKPOINT_LIMIT,
        &memory,
        &mut allowed,
        decode_assessment,
    )?;
    assert!(allowed.verification_work_bytes() > 0);
    assert!(allowed.verification_work_bytes() <= plan.limits.max_work_bytes);
    Ok(())
}

#[test]
fn assessment_decoder_shares_the_same_restore_work_allowance() -> TestResult<()> {
    let (records, plan, options, bytes, _lease) = checkpoint_fixture()?;
    let samples = borrow_samples(&records)?;
    let mut session = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
    let memory = MemoryBudget::new(64 * 1024 * 1024);
    let mut work = RelationalRestoreBudget::new(1, 100_000);
    let mut calls = 0;
    let result = session.restore_checkpoint(
        &bytes,
        CHECKPOINT_LIMIT,
        &memory,
        &mut work,
        |_, _, value, budget| {
            calls += 1;
            if !budget.try_charge_verification(1) || !budget.try_charge_verification(1) {
                return Err(RelationalCursorError::RestoreWorkLimit);
            }
            serde_json::from_value::<usize>(value).map_err(RelationalCursorError::Assessment)
        },
    );
    assert!(matches!(
        result,
        Err(RelationalCursorError::RestoreWorkLimit)
    ));
    assert_eq!(calls, 1);
    assert_eq!(work.verification_work_bytes(), 1);
    assert_eq!(work.remaining_verification_work_bytes(), 0);
    Ok(())
}
