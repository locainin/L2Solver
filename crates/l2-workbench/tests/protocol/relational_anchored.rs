use l2_workbench::{
    artifact::ArtifactValidationFormat,
    derivation::{
        CounterByteOrder, CounterWidth, DerivationLimits, Operation, Recipe, SeedCounterOrder,
        run_with_limits,
    },
    protocol::{
        ByteOrder, Direction, MessageContext, RelationalByteRangeLocator,
        RelationalCandidateEvaluation, RelationalCoordinateBasis, RelationalCounterReset,
        RelationalFitStatus, RelationalLengthField, RelationalOperationTemplate,
        RelationalParserScope, RelationalRecordSample, RelationalSha256CounterXor,
        RelationalTransformEvaluationOptions, RelationalTransformLimits, RelationalTransformPlan,
        RelationalTransformRule, apply_relational_transform_rule,
        infer_relational_transform_candidates,
        infer_relational_transform_candidates_with_evaluator,
    },
};
use std::error::Error;

type TestResult<T> = Result<T, Box<dyn Error>>;

#[path = "relational/search/cursor_anchor.rs"]
mod cursor_anchor;

#[test]
fn anchored_payload_replay_uses_the_same_samples_seed_end_and_keeps_absolute_source_ranges()
-> TestResult<()> {
    let seed = [0x13, 0x27, 0x3b, 0x4f];
    let plaintext = (0_u8..64)
        .map(|byte| byte.wrapping_mul(3))
        .collect::<Vec<_>>();
    let sample_bytes = source_run(seed, &plaintext)?;
    let context = context(7);
    let sample = RelationalRecordSample {
        sample: 101,
        context: context.clone(),
        session_order: 4,
        bytes: &sample_bytes,
    };
    let rule = anchored_rule();

    let applied = apply_relational_transform_rule(
        std::slice::from_ref(&sample),
        &rule,
        RelationalTransformLimits::default(),
        1_000,
    )?;

    assert_eq!(applied.session, session_id(&context));
    assert_eq!(applied.seed_sample, 101);
    assert_eq!(applied.bytes, plaintext);
    let mapping = applied
        .payload_mappings
        .first()
        .ok_or("the anchored payload mapping was not retained")?;
    assert_eq!(mapping.sample, 101);
    assert_eq!(mapping.source_range.start, 9 + seed.len() + 12);
    assert_eq!(mapping.source_range.end, sample_bytes.len());
    assert_eq!(mapping.output_range.start, 0);
    assert_eq!(mapping.output_range.end, plaintext.len());
    assert!(applied.parser_validation_deferred);
    Ok(())
}

#[test]
fn anchored_replay_rechecks_seed_length_and_relative_payload_marker_for_each_session()
-> TestResult<()> {
    let seed = [0x18, 0x2c, 0x40, 0x54];
    let plaintext = vec![0x5a; 48];
    let rule = anchored_rule();
    let limits = RelationalTransformLimits::default();

    let mut changed_seed_length = source_run(seed, &plaintext)?;
    let seed_length = changed_seed_length
        .get_mut(8)
        .ok_or("the synthetic seed length field is missing")?;
    *seed_length = seed_length.saturating_add(1);
    let context = context(8);
    let sample = RelationalRecordSample {
        sample: 102,
        context: context.clone(),
        session_order: 5,
        bytes: &changed_seed_length,
    };
    assert!(
        apply_relational_transform_rule(std::slice::from_ref(&sample), &rule, limits, 1_000)
            .is_err()
    );

    let mut changed_marker = source_run(seed, &plaintext)?;
    let marker = changed_marker
        .get_mut(9 + seed.len() + 7)
        .ok_or("the relative payload marker is missing")?;
    *marker ^= 0xff;
    let sample = RelationalRecordSample {
        sample: 103,
        context,
        session_order: 5,
        bytes: &changed_marker,
    };
    assert!(
        apply_relational_transform_rule(std::slice::from_ref(&sample), &rule, limits, 1_000)
            .is_err()
    );
    Ok(())
}

#[test]
fn anchored_payload_marker_must_be_in_the_seed_bearing_sample() -> TestResult<()> {
    let seed = [0x22, 0x36, 0x4a, 0x5e];
    let plaintext = vec![0x6b; 48];
    let mut seed_bytes = source_run(seed, &plaintext)?;
    let marker_start = 9 + seed.len() + 7;
    let marker_end = marker_start + 2;
    let marker = seed_bytes
        .get_mut(marker_start..marker_end)
        .ok_or("the relative payload marker is missing")?;
    marker.fill(0);
    let separated_payload = [0x57, 0x19].to_vec();
    let context = context(9);
    let samples = [
        RelationalRecordSample {
            sample: 104,
            context: context.clone(),
            session_order: 6,
            bytes: &seed_bytes,
        },
        RelationalRecordSample {
            sample: 105,
            context,
            session_order: 6,
            bytes: &separated_payload,
        },
    ];

    assert!(
        apply_relational_transform_rule(
            &samples,
            &anchored_rule(),
            RelationalTransformLimits::default(),
            1_000,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn seed_relative_coordinates_require_a_declared_fixed_message_relative_seed() -> TestResult<()> {
    let seed = [0x31, 0x45, 0x59, 0x6d];
    let plaintext = vec![0x72; 48];
    let bytes = source_run(seed, &plaintext)?;
    let context = context(10);
    let sample = RelationalRecordSample {
        sample: 106,
        context,
        session_order: 7,
        bytes: &bytes,
    };
    let limits = RelationalTransformLimits::default();

    let mut invalid_seed_basis = anchored_rule();
    invalid_seed_basis.seed_locator.coordinate_basis = RelationalCoordinateBasis::SeedRangeEndV1;
    assert!(
        apply_relational_transform_rule(
            std::slice::from_ref(&sample),
            &invalid_seed_basis,
            limits,
            1_000,
        )
        .is_err()
    );

    let mut missing_declared_length = anchored_rule();
    missing_declared_length.seed_locator.declared_length = None;
    assert!(
        apply_relational_transform_rule(
            std::slice::from_ref(&sample),
            &missing_declared_length,
            limits,
            1_000,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn anchored_locator_is_learned_from_training_and_held_out_marker_changes_contradict_it()
-> TestResult<()> {
    let supported = infer_anchored_sessions(false)?;
    let candidate = supported
        .candidates
        .iter()
        .find(|candidate| is_expected_anchored_rule(candidate))
        .ok_or("the stable seed-relative payload rule was not retained")?;
    assert_eq!(
        candidate.discovery.status,
        RelationalFitStatus::ConstraintsSatisfied
    );
    assert_eq!(
        candidate.heldout.status,
        RelationalFitStatus::ConstraintsSatisfied
    );

    let contradicted = infer_anchored_sessions(true)?;
    let candidate = contradicted
        .candidates
        .iter()
        .find(|candidate| is_expected_anchored_rule(candidate))
        .ok_or("the training rule was lost when held-out markers changed")?;
    assert_eq!(
        candidate.discovery.status,
        RelationalFitStatus::ConstraintsSatisfied
    );
    assert_eq!(candidate.heldout.status, RelationalFitStatus::Contradicted);
    assert_eq!(
        contradicted.prefix_probe_hypotheses_examined, supported.prefix_probe_hypotheses_examined,
        "held-out marker changes altered training probe eligibility"
    );
    assert_eq!(
        contradicted.prefix_probe_work_bytes, supported.prefix_probe_work_bytes,
        "held-out marker changes altered training probe work"
    );
    assert_eq!(
        contradicted.prefix_probe_candidates_with_novelty,
        supported.prefix_probe_candidates_with_novelty,
        "held-out marker changes altered training-only ranking"
    );
    assert_eq!(contradicted.discovery_sessions.len(), 2);
    assert_eq!(contradicted.heldout_sessions.len(), 2);
    Ok(())
}

#[test]
fn prefix_score_alias_reuse_keeps_each_heldout_selector_check() -> TestResult<()> {
    let mut plan = anchored_search_plan();
    // Keep the valid one-byte family after an unrelated width family
    plan.counter_widths = vec![CounterWidth::TwoBytes, CounterWidth::OneByte];
    let report = infer_anchored_sessions_with_plan(true, &plan)?;
    let full_marker = report
        .candidates
        .iter()
        .find(|candidate| is_expected_anchored_rule(candidate))
        .ok_or("the full-marker rule was not retained")?;
    let short_marker = report
        .candidates
        .iter()
        .find(|candidate| is_short_marker_alias(candidate, &full_marker.rule))
        .ok_or("the equivalent short-marker rule was not retained")?;

    assert_eq!(
        full_marker.discovery.status,
        RelationalFitStatus::ConstraintsSatisfied
    );
    assert_eq!(
        full_marker.heldout.status,
        RelationalFitStatus::Contradicted
    );
    assert_eq!(
        short_marker.discovery.status,
        RelationalFitStatus::ConstraintsSatisfied
    );
    assert_eq!(
        short_marker.heldout.status,
        RelationalFitStatus::ConstraintsSatisfied,
        "the short marker remains present in held-out messages"
    );
    assert!(
        report.prefix_probe_cache_reuses > 0,
        "equivalent training ranges did not reuse a prefix score"
    );
    Ok(())
}

#[test]
fn capacity_rejected_prefix_hypotheses_do_not_count_as_transform_attempts() -> TestResult<()> {
    let plaintext = [0x55; 64];
    let mut records = Vec::new();
    for session in 1_u8..=4 {
        let seed = [session, session + 1, session + 2, session + 3];
        records.push((u64::from(session), source_run(seed, &plaintext)?));
    }
    let samples = samples_from_records(&records, 501)?;
    let mut plan = anchored_search_plan();
    plan.limits.max_seed_bytes = 4;
    plan.initial_counters = vec![u64::from(u8::MAX)];
    let latest_payload_start = plan.limits.max_locator_offset * 2 + plan.limits.max_seed_bytes;
    assert!(
        samples
            .iter()
            .all(|sample| sample.bytes.len().saturating_sub(latest_payload_start) > 32),
        "every admitted seed-relative payload must exceed the last counter block"
    );

    let report = infer_relational_transform_candidates(&samples, &plan)?;

    assert!(
        report.prefix_probe_hypotheses_examined > 0,
        "the fixture must reach anchored prefix hypotheses"
    );
    assert_eq!(
        report.prefix_probes_examined, 0,
        "one remaining counter block cannot cover any selected full payload"
    );
    assert_eq!(report.prefix_probe_cache_reuses, 0);
    assert!(report.work_bytes <= plan.limits.max_work_bytes);
    Ok(())
}

fn is_short_marker_alias(
    candidate: &l2_workbench::protocol::RelationalTransformCandidate,
    full_marker_rule: &RelationalTransformRule,
) -> bool {
    candidate.rule.seed_locator == full_marker_rule.seed_locator
        && candidate.rule.operation == full_marker_rule.operation
        && candidate.rule.counter_reset == full_marker_rule.counter_reset
        && candidate.rule.payload_locator.coordinate_basis
            == full_marker_rule.payload_locator.coordinate_basis
        && candidate.rule.payload_locator.direction == full_marker_rule.payload_locator.direction
        && candidate.rule.payload_locator.marker_offset == 8
        && candidate.rule.payload_locator.marker == [0x19]
        && candidate.rule.payload_locator.value_offset == 12
        && candidate.rule.payload_locator.value_length
            == full_marker_rule.payload_locator.value_length
        && candidate.rule.payload_locator.declared_length
            == full_marker_rule.payload_locator.declared_length
}

#[test]
fn bounded_search_ranks_a_new_decoded_prefix_before_the_absolute_locator_domain() -> TestResult<()>
{
    let mut plan = anchored_search_plan();
    plan.limits.max_candidates = 1_024;
    let work_limit = plan.limits.max_work_bytes;
    let report = infer_anchored_sessions_with_plan(false, &plan)?;
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| is_expected_anchored_rule(candidate))
        .ok_or("the bounded search did not retain the supported anchored rule")?;

    assert_eq!(
        candidate.status,
        l2_workbench::protocol::RelationalTransformStatus::HeldoutConstraintsSatisfied
    );
    assert!(report.candidates_examined <= 1_024);
    assert!(report.prefix_probe_hypotheses_examined <= 1_024_usize.div_ceil(3));
    assert!(report.prefix_probe_hypotheses_examined > 0);
    assert!(report.prefix_probes_examined > 0);
    assert!(report.prefix_probe_candidates_with_novelty > 0);
    assert!(report.prefix_probe_work_bytes <= report.work_bytes);
    assert!(report.work_bytes <= work_limit);
    Ok(())
}

#[test]
fn widened_search_still_retains_a_supported_seed_relative_candidate() -> TestResult<()> {
    let mut narrow_plan = anchored_search_plan();
    narrow_plan.counter_widths = vec![CounterWidth::FourBytes];
    assert_narrow_profile_replays_candidate(&narrow_plan)?;
    let wide_plan = widened_anchored_plan();

    let wide_records = anchored_session_records(9, 24, 17, true, false, CounterWidth::FourBytes)?;
    let wide_fixture = samples_from_records(&wide_records, 201)?;
    assert_wide_profile_replays_candidate(&wide_fixture, &wide_plan)
}

fn assert_narrow_profile_replays_candidate(plan: &RelationalTransformPlan) -> TestResult<()> {
    let report = infer_anchored_sessions_with_seed_shape(
        false,
        plan,
        9,
        24,
        17,
        true,
        CounterWidth::FourBytes,
    )?;
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| {
            is_expected_anchored_rule_for_width(candidate, 9, 24, CounterWidth::FourBytes)
        })
        .ok_or_else(|| {
            std::io::Error::other(format!(
                "the narrow profile did not retain its supported anchored rule: candidates={}, locators={}, hypotheses={}, probes={}, novelty={}, work={}, limit={:?}",
                report.candidates_examined,
                report.locator_candidates_examined,
                report.prefix_probe_hypotheses_examined,
                report.prefix_probes_examined,
                report.prefix_probe_candidates_with_novelty,
                report.work_bytes,
                report.search_limit,
            ))
        })?;
    assert_eq!(
        candidate.status,
        l2_workbench::protocol::RelationalTransformStatus::HeldoutConstraintsSatisfied
    );
    Ok(())
}

fn widened_anchored_plan() -> RelationalTransformPlan {
    let mut plan = anchored_search_plan();
    let defaults = RelationalTransformPlan::default();
    plan.limits.max_marker_bytes = 4;
    plan.limits.max_marker_offset = 16;
    plan.limits.max_locator_offset = 16;
    plan.limits.max_seed_bytes = 64;
    plan.limits.max_locator_candidates = 32_768;
    plan.limits.max_candidates = 262_144;
    plan.limits.max_retained_candidates = 128;
    plan.limits.max_work_bytes = 256 * 1024 * 1024;
    plan.counter_widths.clone_from(&defaults.counter_widths);
    plan.counter_byte_orders
        .clone_from(&defaults.counter_byte_orders);
    plan.seed_orders.clone_from(&defaults.seed_orders);
    plan.initial_counters.clone_from(&defaults.initial_counters);
    plan.counter_resets.clone_from(&defaults.counter_resets);
    plan
}

fn assert_wide_profile_replays_candidate(
    samples: &[RelationalRecordSample<'_>],
    plan: &RelationalTransformPlan,
) -> TestResult<()> {
    let mut exact_candidate_reached = false;
    let wide_evaluation = infer_relational_transform_candidates_with_evaluator(
        samples,
        plan,
        None,
        RelationalTransformEvaluationOptions::default(),
        |_, candidate, discovery_outputs, heldout_outputs| {
            let matches_target =
                is_expected_anchored_rule_for_width(candidate, 9, 24, CounterWidth::FourBytes);
            let exact_bytes = matches_target
                && discovery_outputs.len() + heldout_outputs.len() == 17
                && discovery_outputs
                    .iter()
                    .chain(heldout_outputs)
                    .all(expected_der_output);
            let exact_acceptance = exact_bytes
                && candidate.status
                    == l2_workbench::protocol::RelationalTransformStatus::HeldoutConstraintsSatisfied;
            exact_candidate_reached |= exact_acceptance;
            Ok::<_, std::convert::Infallible>(RelationalCandidateEvaluation {
                priority: u8::from(exact_acceptance) * 3,
                work_bytes: 0,
                assessment: exact_acceptance,
            })
        },
    )?;
    let wide_report = &wide_evaluation.report;
    assert!(
        exact_candidate_reached,
        "the widened search did not replay the exact seed-relative candidate: candidates={}, locators={}, hypotheses={}, probes={}, novelty={}, probe_work={}, work={}, complete={}, exhaustive={}, limit={:?}",
        wide_report.candidates_examined,
        wide_report.locator_candidates_examined,
        wide_report.prefix_probe_hypotheses_examined,
        wide_report.prefix_probes_examined,
        wide_report.prefix_probe_candidates_with_novelty,
        wide_report.prefix_probe_work_bytes,
        wide_report.work_bytes,
        wide_report.prefix_probe_complete,
        wide_report.search_exhaustive_within_plan,
        wide_report.search_limit,
    );
    assert!(
        wide_report.prefix_probe_hypotheses_examined > 0,
        "the widened case did not reach anchor scoring: locators={}, candidates={}, limit={:?}",
        wide_report.locator_candidates_examined,
        wide_report.candidates_examined,
        wide_report.search_limit,
    );
    let supported = wide_report.candidates.iter().find(|candidate| {
        is_expected_anchored_rule_for_width(candidate, 9, 24, CounterWidth::FourBytes)
    });

    assert!(
        supported.is_some(),
        "the widened evaluator did not retain its independently supported exact rule: candidates={}, locators={}, hypotheses={}, probes={}, novelty={}, work={}, limit={:?}",
        wide_report.candidates_examined,
        wide_report.locator_candidates_examined,
        wide_report.prefix_probe_hypotheses_examined,
        wide_report.prefix_probes_examined,
        wide_report.prefix_probe_candidates_with_novelty,
        wide_report.work_bytes,
        wide_report.search_limit,
    );
    assert!(wide_report.candidates_examined <= plan.limits.max_candidates);
    assert!(wide_report.work_bytes <= plan.limits.max_work_bytes);
    Ok(())
}

fn expected_der_output(output: &l2_workbench::protocol::RelationalAppliedOutput) -> bool {
    let Ok(session) = u8::try_from(output.session.session) else {
        return false;
    };
    output.bytes.as_slice() == [0x04, 0x03, session, 0x11, 0x22]
}

#[test]
fn fully_observed_short_seed_tails_do_not_make_locator_search_incomplete() -> TestResult<()> {
    let mut records = Vec::new();
    for session in 1_u8..=4 {
        let seed = [
            session,
            session.wrapping_add(1),
            session.wrapping_add(2),
            session.wrapping_add(3),
        ];
        let mut bytes = vec![0_u8; 9 + seed.len()];
        bytes
            .get_mut(0..2)
            .ok_or("the seed marker range is missing")?
            .copy_from_slice(&[0xd2, 0x4c]);
        *bytes
            .get_mut(8)
            .ok_or("the declared seed length is missing")? = u8::try_from(seed.len())?;
        bytes
            .get_mut(9..)
            .ok_or("the seed range is missing")?
            .copy_from_slice(&seed);
        records.push((u64::from(session), bytes));
    }
    let samples = records
        .iter()
        .enumerate()
        .map(|(index, (session, bytes))| {
            Ok(RelationalRecordSample {
                sample: 301_u64
                    .checked_add(u64::try_from(index)?)
                    .ok_or("the sample identity overflowed")?,
                context: context(*session),
                session_order: *session,
                bytes,
            })
        })
        .collect::<TestResult<Vec<_>>>()?;

    // Keep the search domain focused on this fixture's one known header location
    let mut plan = anchored_search_plan();
    plan.limits.max_marker_offset = 0;
    let report = infer_relational_transform_candidates(&samples, &plan)?;

    assert!(
        report.search_exhaustive_within_plan,
        "short-tail search was incomplete: limit={:?}, limits={:?}, candidates={}, candidate_remaining={}, locators={}, locator_remaining={}, work={}, work_remaining={}, probe_hypotheses={}, probes={}, probe_reuses={}, probe_work={}, probe_complete={}",
        report.search_limit,
        report.search_limits,
        report.candidates_examined,
        report.candidate_limit_remaining,
        report.locator_candidates_examined,
        report.locator_candidate_limit_remaining,
        report.work_bytes,
        report.work_bytes_remaining,
        report.prefix_probe_hypotheses_examined,
        report.prefix_probes_examined,
        report.prefix_probe_cache_reuses,
        report.prefix_probe_work_bytes,
        report.prefix_probe_complete,
    );
    assert!(
        report.locator_candidates_examined > 0,
        "the short-tail fixture did not produce any locator candidates"
    );
    assert!(
        report.prefix_probe_complete,
        "complete short-tail inputs were marked as incomplete probe coverage"
    );
    assert_eq!(report.search_limit, None);
    Ok(())
}

#[test]
fn large_locator_offsets_are_bounded_by_fully_observed_seed_tails() -> TestResult<()> {
    let mut records = Vec::new();
    for session in 1_u8..=4 {
        let seed = [
            session,
            session.wrapping_add(1),
            session.wrapping_add(2),
            session.wrapping_add(3),
        ];
        let mut bytes = vec![0_u8; 13];
        bytes
            .get_mut(0..2)
            .ok_or("seed marker range is missing")?
            .copy_from_slice(&[0xd2, 0x4c]);
        *bytes.get_mut(8).ok_or("declared seed length is missing")? = u8::try_from(seed.len())?;
        bytes
            .get_mut(9..13)
            .ok_or("seed range is missing")?
            .copy_from_slice(&seed);
        bytes.extend_from_slice(&[0x91, 0x42]);
        records.push((u64::from(session), bytes));
    }
    let samples = records
        .iter()
        .enumerate()
        .map(|(index, (session, bytes))| {
            Ok(RelationalRecordSample {
                sample: 351_u64
                    .checked_add(u64::try_from(index)?)
                    .ok_or("sample identity overflowed")?,
                context: context(*session),
                session_order: *session,
                bytes,
            })
        })
        .collect::<TestResult<Vec<_>>>()?;

    let mut plan = anchored_search_plan();
    plan.limits.max_seed_bytes = 4;
    plan.limits.max_marker_offset = 0;
    plan.limits.max_locator_offset = 2_000_000;
    let report = infer_relational_transform_candidates(&samples, &plan)?;

    assert!(
        report.prefix_probe_complete,
        "fully observed short tails were marked incomplete for a larger configured offset"
    );
    assert!(report.locator_candidates_examined > 0);
    Ok(())
}

#[test]
fn anchor_observation_preserves_work_for_the_first_two_absolute_attempts() -> TestResult<()> {
    let sample_length = 100_usize;
    let mut plan = anchored_search_plan();
    plan.limits.max_seed_bytes = 1;
    plan.limits.max_marker_bytes = 1;
    plan.limits.max_work_bytes = 100_000;

    let mut records = Vec::new();
    for session in 1_u64..=4 {
        records.push((session, vec![1_u8; sample_length]));
    }
    let samples = records
        .iter()
        .enumerate()
        .map(|(index, (session, bytes))| {
            Ok(RelationalRecordSample {
                sample: 451_u64
                    .checked_add(u64::try_from(index)?)
                    .ok_or("sample identity overflowed")?,
                context: context(*session),
                session_order: *session,
                bytes,
            })
        })
        .collect::<TestResult<Vec<_>>>()?;

    let report = infer_relational_transform_candidates(&samples, &plan)?;

    assert!(
        report.candidates_examined >= 2,
        "anchor preparation consumed the absolute-attempt reserve: limit={:?}, candidates={}, work={}, remaining={}",
        report.search_limits,
        report.candidates_examined,
        report.work_bytes,
        report.work_bytes_remaining,
    );
    assert!(report.work_bytes <= plan.limits.max_work_bytes);
    Ok(())
}

#[test]
fn repeated_ciphertext_prefixes_do_not_count_as_new_evidence_or_reject_the_rule() -> TestResult<()>
{
    let seed = [0x41, 0x52, 0x63, 0x74];
    let plaintext = [0x04, 0x03, 0x02, 0x11, 0x22];
    let bytes = source_run(seed, &plaintext)?;
    let records = (1_u64..=4)
        .map(|session| (session, bytes.clone()))
        .collect::<Vec<_>>();
    let samples = records
        .iter()
        .enumerate()
        .map(|(index, (session, bytes))| {
            Ok(RelationalRecordSample {
                sample: 401_u64
                    .checked_add(u64::try_from(index)?)
                    .ok_or("the sample identity overflowed")?,
                context: context(*session),
                session_order: *session,
                bytes,
            })
        })
        .collect::<TestResult<Vec<_>>>()?;

    // Focus on the fixture's four-byte seed and one-byte-short marker domain
    let mut plan = anchored_search_plan();
    plan.limits.max_seed_bytes = 4;
    plan.limits.max_marker_offset = 7;
    plan.limits.max_locator_offset = 12;
    let report = infer_relational_transform_candidates(&samples, &plan)?;
    assert_eq!(report.prefix_probe_candidates_with_novelty, 0);
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| is_expected_anchored_rule(candidate))
        .ok_or_else(|| {
            std::io::Error::other(format!(
                "the expected rule was not retained: limit={:?}, limits={:?}, candidates={}, candidate_remaining={}, locators={}, locator_remaining={}, probes={}, novelty={}, probe_complete={}",
                report.search_limit,
                report.search_limits,
                report.candidates_examined,
                report.candidate_limit_remaining,
                report.locator_candidates_examined,
                report.locator_candidate_limit_remaining,
                report.prefix_probes_examined,
                report.prefix_probe_candidates_with_novelty,
                report.prefix_probe_complete,
            ))
        })?;

    assert_eq!(
        candidate.status,
        l2_workbench::protocol::RelationalTransformStatus::HeldoutConstraintsSatisfied
    );
    assert!(report.prefix_probes_examined > 0);
    assert!(
        report.search_exhaustive_within_plan,
        "zero novelty left the focused rule search incomplete: limit={:?}, candidates={}, candidate_remaining={}, locators={}, locator_remaining={}",
        report.search_limit,
        report.candidates_examined,
        report.candidate_limit_remaining,
        report.locator_candidates_examined,
        report.locator_candidate_limit_remaining,
    );
    Ok(())
}

fn infer_anchored_sessions(
    change_heldout_markers: bool,
) -> TestResult<l2_workbench::protocol::RelationalTransformReport> {
    infer_anchored_sessions_with_plan(change_heldout_markers, &anchored_search_plan())
}

fn infer_anchored_sessions_with_plan(
    change_heldout_markers: bool,
    plan: &RelationalTransformPlan,
) -> TestResult<l2_workbench::protocol::RelationalTransformReport> {
    infer_anchored_sessions_with_seed_shape(
        change_heldout_markers,
        plan,
        9,
        4,
        4,
        false,
        CounterWidth::OneByte,
    )
}

fn infer_anchored_sessions_with_seed_shape(
    change_heldout_markers: bool,
    plan: &RelationalTransformPlan,
    seed_value_offset: usize,
    seed_length: usize,
    session_count: u8,
    stable_prefix: bool,
    counter_width: CounterWidth,
) -> TestResult<l2_workbench::protocol::RelationalTransformReport> {
    let records = anchored_session_records(
        seed_value_offset,
        seed_length,
        session_count,
        stable_prefix,
        change_heldout_markers,
        counter_width,
    )?;
    let samples = samples_from_records(&records, 201)?;
    infer_relational_transform_candidates(&samples, plan).map_err(Into::into)
}

fn anchored_session_records(
    seed_value_offset: usize,
    seed_length: usize,
    session_count: u8,
    stable_prefix: bool,
    change_heldout_markers: bool,
    counter_width: CounterWidth,
) -> TestResult<Vec<(u64, Vec<u8>)>> {
    let mut records = Vec::new();
    for session in 1_u8..=session_count {
        let mut seed = Vec::with_capacity(seed_length);
        for index in 0..seed_length {
            let index_byte = u8::try_from(index)?;
            seed.push(
                session
                    .wrapping_mul(index_byte.wrapping_add(3))
                    .wrapping_add(index_byte),
            );
        }
        let plaintext = [0x04, 0x03, session, 0x11, 0x22];
        let mut bytes = source_run_with_seed(&seed, &plaintext, seed_value_offset, counter_width)?;
        if stable_prefix {
            for (offset, byte) in bytes.iter_mut().enumerate().take(8).skip(2) {
                *byte = 0x40_u8.wrapping_add(u8::try_from(offset)?);
            }
        }
        if change_heldout_markers && session > 2 {
            let marker = bytes
                .get_mut(seed_value_offset + seed.len() + 7)
                .ok_or("the held-out relative marker is missing")?;
            *marker ^= 0xff;
        }
        records.push((u64::from(session), bytes));
    }
    Ok(records)
}

fn samples_from_records(
    records: &[(u64, Vec<u8>)],
    first_sample: u64,
) -> TestResult<Vec<RelationalRecordSample<'_>>> {
    let samples = records
        .iter()
        .enumerate()
        .map(|(index, (session, bytes))| {
            Ok(RelationalRecordSample {
                sample: first_sample
                    .checked_add(u64::try_from(index)?)
                    .ok_or("the synthetic sample identity overflowed")?,
                context: context(*session),
                session_order: *session,
                bytes,
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    Ok(samples)
}

fn anchored_search_plan() -> RelationalTransformPlan {
    let limits = RelationalTransformLimits {
        max_locator_offset: 16,
        max_marker_offset: 8,
        max_locator_candidates: 8_192,
        max_candidates: 65_536,
        max_retained_candidates: 128,
        max_work_bytes: 64 * 1024 * 1024,
        ..RelationalTransformLimits::default()
    };
    RelationalTransformPlan {
        limits,
        parser_scope: RelationalParserScope::EachSession,
        parser_formats: vec![ArtifactValidationFormat::Der],
        counter_widths: vec![CounterWidth::OneByte],
        counter_byte_orders: vec![CounterByteOrder::BigEndian],
        seed_orders: vec![SeedCounterOrder::SeedThenCounter],
        initial_counters: vec![1],
        counter_resets: vec![RelationalCounterReset::Continuous],
    }
}

fn is_expected_anchored_rule(
    candidate: &l2_workbench::protocol::RelationalTransformCandidate,
) -> bool {
    is_expected_anchored_rule_for_width(candidate, 9, 4, CounterWidth::OneByte)
}

fn is_expected_anchored_rule_for_width(
    candidate: &l2_workbench::protocol::RelationalTransformCandidate,
    seed_value_offset: usize,
    seed_length: usize,
    counter_width: CounterWidth,
) -> bool {
    candidate.rule.seed_locator.coordinate_basis == RelationalCoordinateBasis::MessageStartV1
        && candidate.rule.seed_locator.value_offset == seed_value_offset
        && candidate.rule.seed_locator.value_length == Some(seed_length)
        && candidate.rule.seed_locator.declared_length
            == Some(RelationalLengthField {
                offset: 8,
                width: CounterWidth::OneByte,
                byte_order: ByteOrder::BigEndian,
            })
        && candidate.rule.payload_locator.coordinate_basis
            == RelationalCoordinateBasis::SeedRangeEndV1
        && candidate.rule.payload_locator.marker_offset == 7
        && candidate.rule.payload_locator.marker == [0x57, 0x19]
        && candidate.rule.payload_locator.value_offset == 12
        && matches!(
            candidate.rule.operation,
            RelationalOperationTemplate::Sha256CounterXor(operation)
                if operation.initial_counter == 1
                    && operation.counter_width == counter_width
                    && operation.counter_byte_order == CounterByteOrder::BigEndian
                    && operation.seed_order == SeedCounterOrder::SeedThenCounter
        )
        && candidate.rule.counter_reset == RelationalCounterReset::Continuous
}

fn anchored_rule() -> RelationalTransformRule {
    RelationalTransformRule {
        seed_locator: RelationalByteRangeLocator {
            coordinate_basis: RelationalCoordinateBasis::MessageStartV1,
            direction: Direction::FirstToSecond,
            marker_offset: 0,
            marker: vec![0xd2, 0x4c],
            value_offset: 9,
            value_length: Some(4),
            declared_length: Some(RelationalLengthField {
                offset: 8,
                width: CounterWidth::OneByte,
                byte_order: ByteOrder::BigEndian,
            }),
        },
        payload_locator: RelationalByteRangeLocator {
            coordinate_basis: RelationalCoordinateBasis::SeedRangeEndV1,
            direction: Direction::FirstToSecond,
            marker_offset: 7,
            marker: vec![0x57, 0x19],
            value_offset: 12,
            value_length: None,
            declared_length: None,
        },
        operation: RelationalOperationTemplate::Sha256CounterXor(RelationalSha256CounterXor {
            initial_counter: 1,
            counter_width: CounterWidth::OneByte,
            counter_byte_order: CounterByteOrder::BigEndian,
            seed_order: SeedCounterOrder::SeedThenCounter,
        }),
        counter_reset: RelationalCounterReset::Continuous,
        parser_scope: RelationalParserScope::AcrossSessions,
        parser_format: ArtifactValidationFormat::Png,
    }
}

fn source_run(seed: [u8; 4], plaintext: &[u8]) -> TestResult<Vec<u8>> {
    source_run_with_seed(&seed, plaintext, 9, CounterWidth::OneByte)
}

fn source_run_with_seed(
    seed: &[u8],
    plaintext: &[u8],
    seed_value_offset: usize,
    counter_width: CounterWidth,
) -> TestResult<Vec<u8>> {
    let recipe = Recipe {
        steps: vec![Operation::Sha256CounterXor {
            seed: seed.to_vec().into(),
            initial_counter: 1,
            counter_width,
            counter_byte_order: CounterByteOrder::BigEndian,
            seed_order: SeedCounterOrder::SeedThenCounter,
        }],
        constraints: Vec::new(),
    };
    let encrypted = run_with_limits(plaintext, &recipe, DerivationLimits::default())?.output;
    let mut bytes = vec![0u8; 9];
    bytes
        .get_mut(0..2)
        .ok_or("the synthetic seed marker is missing")?
        .copy_from_slice(&[0xd2, 0x4c]);
    for (offset, byte) in bytes.iter_mut().enumerate().take(8).skip(2) {
        let seed_byte = seed
            .get((offset - 2) % seed.len())
            .copied()
            .ok_or("the synthetic header seed byte is missing")?;
        *byte = seed_byte.wrapping_add(u8::try_from(offset)?);
    }
    *bytes
        .get_mut(8)
        .ok_or("the synthetic seed length field is missing")? = u8::try_from(seed.len())?;
    bytes.resize(seed_value_offset + seed.len(), 0);
    bytes
        .get_mut(seed_value_offset..seed_value_offset + seed.len())
        .ok_or("the synthetic seed range is missing")?
        .copy_from_slice(seed);
    let seed_end = seed_value_offset + seed.len();
    bytes.resize(seed_end + 12, 0);
    for offset in 0..12 {
        if (7..9).contains(&offset) {
            continue;
        }
        let position = seed_end
            .checked_add(offset)
            .ok_or("the synthetic header offset overflowed")?;
        let byte = bytes
            .get_mut(position)
            .ok_or("the synthetic clear header is incomplete")?;
        let seed_byte = seed
            .get(offset % seed.len())
            .copied()
            .ok_or("the synthetic payload seed byte is missing")?;
        *byte = seed_byte.wrapping_add(u8::try_from(offset)?);
    }
    bytes
        .get_mut(seed_end + 7..seed_end + 9)
        .ok_or("the synthetic payload marker is missing")?
        .copy_from_slice(&[0x57, 0x19]);
    bytes.extend_from_slice(&encrypted);
    Ok(bytes)
}

fn context(session: u64) -> MessageContext {
    MessageContext {
        source: "synthetic-source".to_owned(),
        scope: "synthetic-scope".to_owned(),
        session,
        direction: Direction::FirstToSecond,
    }
}

fn session_id(context: &MessageContext) -> l2_workbench::protocol::RelationalSessionId {
    l2_workbench::protocol::RelationalSessionId {
        source: context.source.clone(),
        scope: context.scope.clone(),
        session: context.session,
    }
}
