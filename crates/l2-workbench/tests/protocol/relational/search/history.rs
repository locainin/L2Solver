use super::{
    ArtifactValidationFormat, CounterByteOrder, CounterWidth, RelationalCandidateEvaluation,
    RelationalCounterReset, RelationalOperationTemplate, RelationalParserScope,
    RelationalTransformEvaluationOptions, RelationalTransformPlan, RelationalTransformStatus,
    SeedCounterOrder, TestResult, borrow_samples, same_message_plan, same_message_sessions,
    search_plan, synthetic_sessions,
};
use l2_workbench::protocol::{
    RelationalCandidateEvaluationReport, RelationalRecordSample, RelationalReplayHistory,
    RelationalTransformRule, infer_relational_transform_candidates_with_evaluator_and_history,
};
use std::convert::Infallible;

#[path = "history/checkpoint_validation.rs"]
mod checkpoint_validation;

fn search(
    samples: &[RelationalRecordSample<'_>],
    plan: &RelationalTransformPlan,
    history: Option<&mut RelationalReplayHistory>,
) -> TestResult<(
    RelationalCandidateEvaluationReport<()>,
    Vec<RelationalTransformRule>,
)> {
    let mut evaluated = Vec::new();
    let report = infer_relational_transform_candidates_with_evaluator_and_history(
        samples,
        plan,
        None,
        RelationalTransformEvaluationOptions::default(),
        history,
        |_, candidate, _, _| {
            evaluated.push(candidate.rule.clone());
            Ok::<_, Infallible>(RelationalCandidateEvaluation {
                priority: 1,
                work_bytes: 0,
                assessment: (),
            })
        },
    )?;
    Ok((report, evaluated))
}

fn checkpoint_history() -> TestResult<(RelationalReplayHistory, RelationalTransformRule)> {
    let records = same_message_sessions()?;
    let samples = borrow_samples(&records)?;
    let mut plan = same_message_plan();
    plan.limits.max_candidates = 2_048;
    let mut history = RelationalReplayHistory::new(1024 * 1024);
    let (first, _) = search(&samples, &plan, Some(&mut history))?;
    let published = first
        .report
        .candidates
        .iter()
        .find(|candidate| {
            candidate.status == RelationalTransformStatus::HeldoutConstraintsSatisfied
        })
        .ok_or("checkpoint fixture has no fully supported rule")?
        .rule
        .clone();
    assert!(history.register_published_rule(&published));
    Ok((history, published))
}

#[test]
fn saved_history_rebuilds_lookup_and_preserves_conclusive_replay_results() -> TestResult<()> {
    let (history, published) = checkpoint_history()?;
    let storage = history.storage_bytes();
    let complete = history.is_complete();
    let encoded = serde_json::to_vec(&history)?;
    drop(history);
    let mut restored: RelationalReplayHistory = serde_json::from_slice(&encoded)?;
    assert_eq!(restored.storage_bytes(), storage);
    assert_eq!(restored.is_complete(), complete);

    let records = same_message_sessions()?;
    let samples = borrow_samples(&records)?;
    let mut plan = same_message_plan();
    plan.limits.max_candidates = 2_048;
    let (report, evaluated) = search(&samples, &plan, Some(&mut restored))?;
    assert!(report.history_reused_rejections > 0);
    assert!(report.history_reused_published > 0);
    assert!(!evaluated.contains(&published));
    Ok(())
}

#[test]
fn saved_history_rejects_changed_versions_capacities_and_repeated_rules() -> TestResult<()> {
    let (history, _) = checkpoint_history()?;
    let original = serde_json::to_value(&history)?;
    for (field, value) in [
        ("version", serde_json::json!(999)),
        ("max_bytes", serde_json::json!(0)),
        ("entry_capacity", serde_json::json!(usize::MAX)),
    ] {
        let mut changed = original.clone();
        *changed.get_mut(field).ok_or("missing history field")? = value;
        assert!(serde_json::from_value::<RelationalReplayHistory>(changed).is_err());
    }
    let mut repeated = original;
    let entries = repeated
        .get_mut("entries")
        .ok_or("missing history entries")?
        .as_array_mut()
        .ok_or("missing history entries")?;
    entries.push(entries.first().ok_or("history has no saved rule")?.clone());
    let count = entries.len();
    *repeated
        .get_mut("entry_capacity")
        .ok_or("missing history capacity")? = serde_json::json!(count);
    *repeated
        .get_mut("max_bytes")
        .ok_or("missing history byte limit")? = serde_json::json!(2 * 1024 * 1024);
    assert!(serde_json::from_value::<RelationalReplayHistory>(repeated).is_err());
    Ok(())
}

#[test]
fn widened_search_reuses_completed_rejections_without_counting_them_as_attempts() -> TestResult<()>
{
    let records = same_message_sessions()?;
    let samples = borrow_samples(&records)?;
    let mut normal = same_message_plan();
    normal.limits.max_candidates = 128;
    let mut deep = normal.clone();
    deep.limits.max_candidates = 2_048;
    deep.limits.max_seed_bytes += 1;
    deep.limits.max_sessions += 1;
    deep.limits.max_records_per_session += 1;
    let mut history = RelationalReplayHistory::new(1024 * 1024);

    let (first, _) = search(&samples, &normal, Some(&mut history))?;
    let (continued, _) = search(&samples, &deep, Some(&mut history))?;
    let (fresh, _) = search(&samples, &deep, None)?;

    assert!(first.report.candidates_examined > 0);
    assert!(continued.history_reused_rejections > 0);
    assert_eq!(continued.history_reused_published, 0);
    assert_eq!(continued.history_recording_omissions, 0);
    assert!(history.is_complete());
    assert!(continued.report.candidates_examined < fresh.report.candidates_examined);
    assert_eq!(
        continued.report.candidate_limit_remaining,
        deep.limits.max_candidates - continued.report.candidates_examined
    );
    assert_eq!(
        continued.report.candidates_examined + continued.history_reused_rejections,
        fresh.report.candidates_examined,
        "cached rejections must cover candidates without claiming new replay attempts"
    );
    assert_eq!(
        continued.report.search_exhaustive_within_plan,
        fresh.report.search_exhaustive_within_plan
    );
    Ok(())
}

#[test]
fn only_exactly_published_rules_are_skipped_and_unpublished_support_is_retried() -> TestResult<()> {
    let records = same_message_sessions()?;
    let samples = borrow_samples(&records)?;
    let mut plan = same_message_plan();
    plan.limits.max_candidates = 2_048;
    let mut history = RelationalReplayHistory::new(1024 * 1024);
    let (first, _) = search(&samples, &plan, Some(&mut history))?;
    let valid = first
        .report
        .candidates
        .iter()
        .find(|candidate| {
            candidate.status == RelationalTransformStatus::HeldoutConstraintsSatisfied
        })
        .ok_or("expected a fully supported frozen rule")?
        .rule
        .clone();

    // Distinct locator bytes and each transform parameter must stay distinct
    let mut variants = Vec::new();
    let mut variant = valid.clone();
    variant.seed_locator.marker.push(0xff);
    variants.push(variant);
    let mut variant = valid.clone();
    variant.payload_locator.marker.push(0xff);
    variants.push(variant);
    let mut variant = valid.clone();
    variant.seed_locator.value_offset += 1;
    variants.push(variant);
    let mut variant = valid.clone();
    let RelationalOperationTemplate::Sha256CounterXor(mut operation) = variant.operation;
    operation.initial_counter += 1;
    variant.operation = RelationalOperationTemplate::Sha256CounterXor(operation);
    variants.push(variant);
    let mut variant = valid.clone();
    let RelationalOperationTemplate::Sha256CounterXor(mut operation) = variant.operation;
    operation.counter_width = CounterWidth::TwoBytes;
    operation.counter_byte_order = CounterByteOrder::LittleEndian;
    operation.seed_order = SeedCounterOrder::CounterThenSeed;
    variant.operation = RelationalOperationTemplate::Sha256CounterXor(operation);
    variants.push(variant);
    let mut variant = valid.clone();
    variant.counter_reset = RelationalCounterReset::PerRecord;
    variant.parser_scope = RelationalParserScope::AcrossSessions;
    variant.parser_format = ArtifactValidationFormat::Png;
    variants.push(variant);
    for variant in &variants {
        assert!(history.register_published_rule(variant));
    }

    let (unpublished, unpublished_evaluated) = search(&samples, &plan, Some(&mut history))?;
    assert!(unpublished_evaluated.contains(&valid));

    assert!(history.register_published_rule(&valid));
    let (published, published_evaluated) = search(&samples, &plan, Some(&mut history))?;
    assert_eq!(
        published.history_reused_published,
        unpublished.history_reused_published + 1
    );
    assert!(!published_evaluated.contains(&valid));
    assert_eq!(
        published.report.candidates_examined + 1,
        unpublished.report.candidates_examined
    );
    Ok(())
}

#[test]
fn heldout_contradictions_are_reused_after_a_completed_replay() -> TestResult<()> {
    let records = synthetic_sessions(true)?;
    let samples = borrow_samples(&records)?;
    let plan = search_plan();
    let mut history = RelationalReplayHistory::new(16 * 1024 * 1024);
    let (first, _) = search(&samples, &plan, Some(&mut history))?;
    let rejected = first
        .report
        .candidates
        .iter()
        .find(|candidate| {
            candidate.status == RelationalTransformStatus::ContradictedByHeldoutSession
        })
        .ok_or("expected a held-out contradiction")?
        .rule
        .clone();

    let (second, evaluated) = search(&samples, &plan, Some(&mut history))?;
    assert!(second.history_reused_rejections > 0);
    assert!(!evaluated.contains(&rejected));
    Ok(())
}

#[test]
fn work_limited_candidates_are_retried_after_the_budget_increases() -> TestResult<()> {
    let records = same_message_sessions()?;
    let samples = borrow_samples(&records)?;
    let mut limited = same_message_plan();
    limited.limits.max_work_bytes = 1;
    let mut history = RelationalReplayHistory::new(1024 * 1024);
    let (first, _) = search(&samples, &limited, Some(&mut history))?;
    let (retry, _) = search(&samples, &limited, Some(&mut history))?;
    assert!(first.report.candidates_examined > 0);
    assert_eq!(retry.history_reused_rejections, 0);
    assert_eq!(
        retry.report.candidates_examined,
        first.report.candidates_examined
    );

    let (widened, _) = search(&samples, &same_message_plan(), Some(&mut history))?;
    assert_eq!(widened.history_reused_rejections, 0);
    assert_eq!(
        widened.report.candidates_examined,
        retry.report.candidates_examined
    );
    assert!(widened.report.work_bytes > retry.report.work_bytes);
    assert!(widened.report.candidates.iter().any(|candidate| {
        candidate.status == RelationalTransformStatus::HeldoutConstraintsSatisfied
    }));
    Ok(())
}

#[test]
fn mixed_contradiction_and_unresolved_sessions_are_replayed() -> TestResult<()> {
    let mut records = same_message_sessions()?;
    let mut extra_one = records.first().ok_or("missing first session")?.clone();
    extra_one.0 = 5;
    let mut extra_two = records.get(1).ok_or("missing second session")?.clone();
    extra_two.0 = 6;
    records.extend([extra_one, extra_two]);
    let (_, _, second_bytes) = records.get_mut(1).ok_or("missing discovery session")?;
    *second_bytes.get_mut(4).ok_or("missing ciphertext")? ^= 0xff;
    let samples = borrow_samples(&records)?;
    let mut full_plan = same_message_plan();
    full_plan.limits.max_sessions = 6;

    // Find a budget that completes two discovery sessions but leaves a third unresolved
    let mut target = None;
    for budget in [300, 400, 500, 600, 800, 1_000] {
        let mut limited = full_plan.clone();
        limited.limits.max_work_bytes = budget;
        let mut history = RelationalReplayHistory::new(1024 * 1024);
        let (report, _) = search(&samples, &limited, Some(&mut history))?;
        if let Some(candidate) = report.report.candidates.iter().find(|candidate| {
            candidate.status == RelationalTransformStatus::DiscoveryContradicted
                && !candidate.discovery.unresolved_sessions.is_empty()
                && !candidate.discovery.contradicted_sessions.is_empty()
        }) {
            target = Some((candidate.rule.clone(), history));
            break;
        }
    }
    let (rule, mut history) = target.ok_or("no mixed contradiction and unresolved fit found")?;
    let (_, evaluated) = search(&samples, &full_plan, Some(&mut history))?;
    assert!(evaluated.contains(&rule), "the unresolved rule was skipped");
    Ok(())
}

#[test]
fn full_history_declines_entries_without_suppressing_future_attempts() -> TestResult<()> {
    let records = same_message_sessions()?;
    let samples = borrow_samples(&records)?;
    let plan = same_message_plan();
    let mut history = RelationalReplayHistory::new(0);
    let (first, _) = search(&samples, &plan, Some(&mut history))?;
    let (second, _) = search(&samples, &plan, Some(&mut history))?;
    assert!(first.history_recording_omissions > 0);
    assert!(!history.is_complete());
    assert_eq!(second.history_reused_rejections, 0);
    assert_eq!(
        second.report.candidates_examined,
        first.report.candidates_examined
    );
    if let Some(candidate) = first.report.candidates.first() {
        assert!(!history.register_published_rule(&candidate.rule));
    }
    Ok(())
}

#[test]
fn partially_full_history_respects_its_byte_bound_and_replays_unrecorded_rules() -> TestResult<()> {
    let records = same_message_sessions()?;
    let samples = borrow_samples(&records)?;
    let plan = same_message_plan();
    let mut history = RelationalReplayHistory::new(1_024);
    let (first, _) = search(&samples, &plan, Some(&mut history))?;
    assert!(first.history_recording_omissions > 0);
    assert!(!history.is_complete());
    assert!(history.storage_bytes() <= 1_024);

    let (second, _) = search(&samples, &plan, Some(&mut history))?;
    assert!(second.history_reused_rejections > 0);
    assert!(second.history_recording_omissions > 0);
    assert_eq!(
        second.report.candidates_examined + second.history_reused_rejections,
        first.report.candidates_examined
    );
    assert!(history.storage_bytes() <= 1_024);

    if let Some(candidate) = first.report.candidates.first() {
        let mut oversized = candidate.rule.clone();
        oversized.seed_locator.marker = vec![0; 2_048];
        assert!(!history.register_published_rule(&oversized));
        assert!(history.storage_bytes() <= 1_024);
    }
    Ok(())
}

#[test]
fn a_distinct_cohort_history_does_not_reuse_another_cohorts_results() -> TestResult<()> {
    let records = same_message_sessions()?;
    let samples = borrow_samples(&records)?;
    let plan = same_message_plan();
    let mut first_history = RelationalReplayHistory::new(1024 * 1024);
    let (first, _) = search(&samples, &plan, Some(&mut first_history))?;
    assert!(first.report.candidates_examined > 0);

    let mut changed_records = same_message_sessions()?;
    if let Some((_, _, bytes)) = changed_records.last_mut()
        && let Some(byte) = bytes.last_mut()
    {
        *byte ^= 1;
    }
    let changed_samples = borrow_samples(&changed_records)?;
    let mut changed_history = RelationalReplayHistory::new(1024 * 1024);
    let (changed, _) = search(&changed_samples, &plan, Some(&mut changed_history))?;
    let (cold, _) = search(&changed_samples, &plan, None)?;
    assert_eq!(changed.history_reused_rejections, 0);
    assert_eq!(changed.history_reused_published, 0);
    assert_eq!(
        changed.report.candidates_examined,
        cold.report.candidates_examined
    );
    Ok(())
}

#[test]
fn entry_growth_leaves_room_for_marker_bytes_under_the_storage_bound() -> TestResult<()> {
    let records = same_message_sessions()?;
    let samples = borrow_samples(&records)?;
    let (report, _) = search(&samples, &same_message_plan(), None)?;
    let mut rule = report
        .report
        .candidates
        .first()
        .ok_or("missing rule")?
        .rule
        .clone();
    let RelationalOperationTemplate::Sha256CounterXor(mut operation) = rule.operation;
    operation.counter_width = CounterWidth::EightBytes;
    let capacity = 128 * 1024;
    let mut history = RelationalReplayHistory::new(capacity);
    let mut stored = 0;
    loop {
        operation.initial_counter = stored;
        rule.operation = RelationalOperationTemplate::Sha256CounterXor(operation);
        if !history.register_published_rule(&rule) {
            break;
        }
        stored += 1;
    }
    let approximate_entry_bytes = std::mem::size_of::<RelationalTransformRule>()
        + 2 * std::mem::size_of::<usize>()
        + rule.seed_locator.marker.len()
        + rule.payload_locator.marker.len();
    let expected_minimum = capacity / approximate_entry_bytes * 9 / 10;
    assert!(stored >= u64::try_from(expected_minimum)?);
    assert!(history.storage_bytes() <= capacity);
    Ok(())
}

#[test]
fn storage_limit_can_grow_and_cannot_shrink_below_allocated_bytes() -> TestResult<()> {
    let records = same_message_sessions()?;
    let samples = borrow_samples(&records)?;
    let (report, _) = search(&samples, &same_message_plan(), None)?;
    let mut rule = report
        .report
        .candidates
        .first()
        .ok_or("missing rule")?
        .rule
        .clone();
    let RelationalOperationTemplate::Sha256CounterXor(mut operation) = rule.operation;
    operation.counter_width = CounterWidth::EightBytes;
    let mut history = RelationalReplayHistory::new(0);
    assert!(history.set_max_bytes(4_096));
    assert!(history.register_published_rule(&rule));
    let used = history.storage_bytes();
    assert!(used > 0);
    assert!(!history.set_max_bytes(used - 1));

    operation.initial_counter += 1;
    rule.operation = RelationalOperationTemplate::Sha256CounterXor(operation);
    assert!(history.register_published_rule(&rule));
    assert!(history.set_max_bytes(history.storage_bytes()));
    operation.initial_counter += 1;
    rule.operation = RelationalOperationTemplate::Sha256CounterXor(operation);
    assert!(!history.register_published_rule(&rule));
    assert!(!history.is_complete());

    assert!(history.set_max_bytes(8_192));
    assert!(history.register_published_rule(&rule));
    assert!(!history.is_complete());
    assert!(history.storage_bytes() <= 8_192);
    Ok(())
}
