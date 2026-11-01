use super::{
    Job, RelationalCursorError, RelationalParserScope, RelationalReplayHistory,
    RelationalRestoreBudget, RelationalSearchSession, RelationalSearchStep,
    RelationalTransformEvaluationOptions, TestResult, borrow_samples, checkpoint_fixture, evaluate,
    search_plan,
};
use l2_workbench::{
    artifact::ArtifactValidationFormat,
    derivation::{CounterByteOrder, CounterWidth, SeedCounterOrder},
    protocol::{
        Direction, RelationalCounterReset, RelationalOperationTemplate, RelationalTransformRule,
    },
};
use std::convert::Infallible;

fn candidate_rule(bytes: &[u8]) -> TestResult<RelationalTransformRule> {
    let checkpoint: serde_json::Value = serde_json::from_slice(bytes)?;
    let rule = checkpoint
        .pointer("/payload/search/candidates/0/candidate/rule")
        .ok_or("fixture has no candidate rule")?
        .clone();
    Ok(serde_json::from_value(rule)?)
}

#[test]
fn history_hits_can_reach_valid_parameters_past_the_ranking_window() -> TestResult<()> {
    let mut records = Vec::new();
    for session in 1_u8..=4 {
        for (direction, marker) in [
            (Direction::FirstToSecond, 0x31),
            (Direction::SecondToFirst, 0x82),
        ] {
            let mut bytes = vec![marker, session];
            bytes.resize(64, 0x77);
            records.push((u32::from(session), direction, bytes));
        }
    }
    let samples = borrow_samples(&records)?;
    let mut plan = search_plan();
    plan.parser_scope = RelationalParserScope::AcrossSessions;
    plan.limits.max_candidates = 1;
    plan.limits.max_locator_candidates = 2;
    plan.limits.max_locator_offset = 1;
    plan.limits.max_seed_bytes = 1;
    plan.counter_widths = vec![CounterWidth::OneByte];
    plan.counter_byte_orders = vec![CounterByteOrder::BigEndian];
    plan.seed_orders = vec![SeedCounterOrder::SeedThenCounter];
    plan.counter_resets = vec![RelationalCounterReset::Continuous];
    plan.initial_counters = vec![255, 0];
    let options = RelationalTransformEvaluationOptions::default();
    let mut history = RelationalReplayHistory::new(256 * 1024);
    let mut retained = None;

    // The first parameter exhausts its counter; later runs reuse those exact rejections
    for _ in 0..16 {
        let mut session =
            RelationalSearchSession::new(&samples, &plan, None, options, Some(&mut history))?;
        let mut cursor = None;
        for _ in 0..128 {
            let step = session.step(cursor, 16, |_, candidate, _, _| {
                retained = Some(candidate.rule.clone());
                Ok::<_, Infallible>(evaluate(candidate))
            })?;
            match step {
                RelationalSearchStep::Complete(_) => break,
                RelationalSearchStep::Paused(saved) if retained.is_none() => cursor = Some(saved),
                RelationalSearchStep::Paused(_) => break,
            }
        }
        drop(session);
        if retained.is_some() {
            break;
        }
    }
    let rule = retained.ok_or("history reuse never reached the later parameter")?;
    let RelationalOperationTemplate::Sha256CounterXor(operation) = rule.operation;
    assert_eq!(operation.initial_counter, 0);
    assert!(history.is_complete());
    let session = RelationalSearchSession::new(&samples, &plan, None, options, None)?;
    let mut work = RelationalRestoreBudget::new(1024, 0);
    session.validate_producer_parameters(&rule, &mut work)?;
    assert!(work.verification_work_bytes() > 0);
    Ok(())
}

#[test]
fn allowed_parameters_beyond_the_ranking_window_are_accepted() -> TestResult<()> {
    let (records, mut plan, _, bytes, _lease) = checkpoint_fixture()?;
    let samples = borrow_samples(&records)?;
    let mut rule = candidate_rule(&bytes)?;
    plan.limits.max_candidates = 1;
    plan.counter_widths = vec![CounterWidth::EightBytes];
    plan.counter_byte_orders = vec![CounterByteOrder::BigEndian];
    plan.seed_orders = vec![SeedCounterOrder::SeedThenCounter];
    plan.counter_resets = vec![RelationalCounterReset::Continuous];
    plan.initial_counters = vec![0, 1];
    let RelationalOperationTemplate::Sha256CounterXor(ref mut operation) = rule.operation;
    operation.counter_width = CounterWidth::EightBytes;
    operation.counter_byte_order = CounterByteOrder::BigEndian;
    operation.seed_order = SeedCounterOrder::SeedThenCounter;
    operation.initial_counter = 1;
    rule.counter_reset = RelationalCounterReset::Continuous;
    let session = RelationalSearchSession::new(
        &samples,
        &plan,
        None,
        RelationalTransformEvaluationOptions::default(),
        None,
    )?;
    let mut work = RelationalRestoreBudget::new(1024, 0);
    session.validate_producer_parameters(&rule, &mut work)?;
    assert!(work.verification_work_bytes() > 0);
    Ok(())
}

#[test]
fn incompatible_parameters_are_rejected_and_consume_verification_work() -> TestResult<()> {
    let (records, mut plan, _, bytes, _lease) = checkpoint_fixture()?;
    let samples = borrow_samples(&records)?;
    let rule = candidate_rule(&bytes)?;
    plan.counter_widths = vec![CounterWidth::OneByte];
    plan.counter_byte_orders = vec![CounterByteOrder::BigEndian, CounterByteOrder::LittleEndian];
    plan.seed_orders = vec![SeedCounterOrder::SeedThenCounter];
    plan.counter_resets = vec![RelationalCounterReset::Continuous];
    plan.initial_counters = vec![0, 256];
    plan.parser_formats = vec![ArtifactValidationFormat::Der];
    let mut valid = rule;
    let RelationalOperationTemplate::Sha256CounterXor(ref mut operation) = valid.operation;
    operation.counter_width = CounterWidth::OneByte;
    operation.counter_byte_order = CounterByteOrder::BigEndian;
    operation.seed_order = SeedCounterOrder::SeedThenCounter;
    operation.initial_counter = 0;
    valid.counter_reset = RelationalCounterReset::Continuous;
    valid.parser_format = ArtifactValidationFormat::Der;
    let session = RelationalSearchSession::new(
        &samples,
        &plan,
        None,
        RelationalTransformEvaluationOptions::default(),
        None,
    )?;
    let mut work = RelationalRestoreBudget::new(10_000, 0);
    session.validate_producer_parameters(&valid, &mut work)?;

    let mut incompatible = Vec::new();
    let mut wrong = valid.clone();
    wrong.parser_scope = RelationalParserScope::EachSession;
    incompatible.push(wrong);
    let mut wrong = valid.clone();
    wrong.parser_format = ArtifactValidationFormat::Png;
    incompatible.push(wrong);
    let mut wrong = valid.clone();
    wrong.counter_reset = RelationalCounterReset::PerRecord;
    incompatible.push(wrong);
    let mut wrong = valid.clone();
    let RelationalOperationTemplate::Sha256CounterXor(ref mut operation) = wrong.operation;
    operation.counter_width = CounterWidth::TwoBytes;
    incompatible.push(wrong);
    let mut wrong = valid.clone();
    let RelationalOperationTemplate::Sha256CounterXor(ref mut operation) = wrong.operation;
    operation.counter_byte_order = CounterByteOrder::LittleEndian;
    incompatible.push(wrong);
    let mut wrong = valid.clone();
    let RelationalOperationTemplate::Sha256CounterXor(ref mut operation) = wrong.operation;
    operation.seed_order = SeedCounterOrder::CounterThenSeed;
    incompatible.push(wrong);
    let mut wrong = valid.clone();
    let RelationalOperationTemplate::Sha256CounterXor(ref mut operation) = wrong.operation;
    operation.initial_counter = 1;
    incompatible.push(wrong);
    let mut wrong = valid;
    let RelationalOperationTemplate::Sha256CounterXor(ref mut operation) = wrong.operation;
    operation.initial_counter = 256;
    incompatible.push(wrong);
    for rule in incompatible {
        let before = work.verification_work_bytes();
        assert!(matches!(
            session.validate_producer_parameters(&rule, &mut work),
            Err(RelationalCursorError::InvalidCheckpoint)
        ));
        assert!(work.verification_work_bytes() > before);
    }
    Ok(())
}

#[test]
fn parameter_validation_respects_work_and_cancellation_before_scanning() -> TestResult<()> {
    let (records, plan, options, bytes, _lease) = checkpoint_fixture()?;
    let samples = borrow_samples(&records)?;
    let rule = candidate_rule(&bytes)?;
    let job = Job::new("parameter validation");
    let session = RelationalSearchSession::new(&samples, &plan, Some(&job), options, None)?;
    let mut denied = RelationalRestoreBudget::new(0, 0);
    assert!(matches!(
        session.validate_producer_parameters(&rule, &mut denied),
        Err(RelationalCursorError::RestoreWorkLimit)
    ));
    assert_eq!(denied.verification_work_bytes(), 0);
    job.request_cancel();
    let mut cancelled = RelationalRestoreBudget::new(10_000, 0);
    assert!(matches!(
        session.validate_producer_parameters(&rule, &mut cancelled),
        Err(RelationalCursorError::Search(_))
    ));
    assert_eq!(cancelled.verification_work_bytes(), 0);
    Ok(())
}
