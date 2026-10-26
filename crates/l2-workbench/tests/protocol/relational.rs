use l2_workbench::{
    artifact::{ArtifactValidationFormat, ArtifactValidationOutcome, ArtifactValidator},
    derivation::{CounterByteOrder, CounterWidth, SeedCounterOrder},
    job::{Counter, Job},
    protocol::{
        ByteOrder, ByteRange, Direction, MessageContext, RelationalCandidateEvaluation,
        RelationalCounterReset, RelationalFalsification, RelationalFitStatus,
        RelationalLengthField, RelationalOperationTemplate, RelationalParserScope,
        RelationalRecordSample, RelationalTransformEvaluationOptions, RelationalTransformLimits,
        RelationalTransformPlan, RelationalTransformStatus, apply_relational_transform_rule,
        infer_relational_transform_candidates,
        infer_relational_transform_candidates_with_evaluator,
        infer_relational_transform_candidates_with_job,
    },
};
use std::error::Error;

const SEED_MARKER: u8 = 0x31;
const PAYLOAD_MARKER: u8 = 0x82;
const DECOY_MARKER: u8 = 0xee;
const SEED_LENGTH: usize = 8;
type OwnedRecord = (u32, Direction, Vec<u8>);
type TestResult<T> = Result<T, Box<dyn Error>>;

#[test]
fn learns_session_relative_seed_and_payload_ranges_across_frozen_sessions()
-> Result<(), Box<dyn Error>> {
    let records = synthetic_sessions(false)?;
    let samples = borrow_samples(&records)?;
    let report = infer_relational_transform_candidates(&samples, &search_plan())?;

    let candidate = report
        .candidates
        .iter()
        .find(|candidate| {
            candidate.rule.seed_locator.marker == [SEED_MARKER]
                && candidate.rule.seed_locator.value_offset == 1
                && candidate.rule.seed_locator.value_length == Some(SEED_LENGTH)
                && candidate.rule.payload_locator.marker == [PAYLOAD_MARKER]
                && candidate.rule.payload_locator.value_offset == 1
                && candidate.rule.counter_reset == RelationalCounterReset::PerRecord
        })
        .ok_or("no relational rule located each session's own seed and payload bytes")?;

    assert_eq!(report.discovery_sessions.len(), 2);
    assert_eq!(report.heldout_sessions.len(), 2);
    assert_eq!(
        candidate.discovery.supported_sessions,
        report.discovery_sessions
    );
    assert_eq!(
        candidate.heldout.supported_sessions,
        report.heldout_sessions
    );
    assert_eq!(
        candidate.discovery.status,
        RelationalFitStatus::ConstraintsSatisfied
    );
    assert_eq!(
        candidate.heldout.status,
        RelationalFitStatus::ConstraintsSatisfied
    );
    assert_eq!(
        candidate.status,
        RelationalTransformStatus::HeldoutConstraintsSatisfied
    );
    let RelationalOperationTemplate::Sha256CounterXor(operation) = candidate.rule.operation;
    assert_eq!(operation.counter_width, CounterWidth::EightBytes);
    assert_eq!(operation.counter_byte_order, CounterByteOrder::LittleEndian);
    assert_eq!(operation.seed_order, SeedCounterOrder::CounterThenSeed);
    assert_eq!(operation.initial_counter, 3);
    assert_eq!(
        report.candidate_limit_remaining,
        search_plan().limits.max_candidates - report.candidates_examined
    );
    Ok(())
}

#[test]
fn retains_exact_heldout_parser_contradictions() -> Result<(), Box<dyn Error>> {
    let records = synthetic_sessions(true)?;
    let samples = borrow_samples(&records)?;
    let report = infer_relational_transform_candidates(&samples, &search_plan())?;
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| {
            candidate.rule.seed_locator.marker == [SEED_MARKER]
                && candidate.rule.seed_locator.value_offset == 1
                && candidate.rule.seed_locator.value_length == Some(SEED_LENGTH)
                && candidate.rule.payload_locator.marker == [PAYLOAD_MARKER]
                && candidate.rule.payload_locator.value_offset == 1
                && candidate.rule.counter_reset == RelationalCounterReset::PerRecord
        })
        .ok_or("the discovery rule was not retained for held-out evaluation")?;

    assert_eq!(
        candidate.discovery.status,
        RelationalFitStatus::ConstraintsSatisfied
    );
    assert_eq!(candidate.heldout.status, RelationalFitStatus::Contradicted);
    assert_eq!(
        candidate.status,
        RelationalTransformStatus::ContradictedByHeldoutSession
    );
    assert!(candidate.heldout.checks.iter().any(|check| {
        check.status == RelationalFitStatus::Contradicted
            && check.session.session == 4
            && check.falsification.is_some()
    }));
    assert_eq!(
        candidate.heldout.checks.len(),
        report.heldout_sessions.len()
    );
    Ok(())
}

#[test]
fn retains_a_single_session_hypothesis_without_claiming_heldout_support()
-> Result<(), Box<dyn Error>> {
    let records = synthetic_sessions(false)?;
    let single_session_records = records
        .into_iter()
        .filter(|(session, _, _)| *session == 1)
        .collect::<Vec<_>>();
    let samples = borrow_samples(&single_session_records)?;
    let report = infer_relational_transform_candidates(&samples, &search_plan())?;

    assert_eq!(report.discovery_sessions.len(), 1);
    assert!(report.heldout_sessions.is_empty());
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| {
            candidate.rule.seed_locator.marker == [SEED_MARKER]
                && candidate.rule.payload_locator.marker == [PAYLOAD_MARKER]
                && candidate.rule.counter_reset == RelationalCounterReset::PerRecord
        })
        .ok_or("single-session evidence did not retain its parser-checked hypothesis")?;

    assert_eq!(
        candidate.discovery.status,
        RelationalFitStatus::ConstraintsSatisfied
    );
    assert_eq!(candidate.heldout.status, RelationalFitStatus::NotEvaluated);
    assert!(candidate.heldout.checks.is_empty());
    assert_eq!(
        candidate.status,
        RelationalTransformStatus::DiscoveryOnlyHypothesis
    );
    Ok(())
}

#[test]
fn reports_candidate_limit_exhaustion_without_claiming_complete_discovery()
-> Result<(), Box<dyn Error>> {
    let records = synthetic_sessions(false)?;
    let samples = borrow_samples(&records)?;
    let mut plan = search_plan();
    plan.limits.max_candidates = 1;
    let report = infer_relational_transform_candidates(&samples, &plan)?;

    assert_eq!(report.candidates_examined, 1);
    assert_eq!(report.candidate_limit_remaining, 0);
    assert!(!report.search_exhaustive_within_plan);
    assert!(report.omitted_candidates > 0);
    Ok(())
}

#[test]
fn replays_a_frozen_rule_with_the_selected_sessions_own_seed() -> Result<(), Box<dyn Error>> {
    let records = synthetic_sessions(false)?;
    let samples = borrow_samples(&records)?;
    let plan = search_plan();
    let report = infer_relational_transform_candidates(&samples, &plan)?;
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| {
            candidate.rule.seed_locator.marker == [SEED_MARKER]
                && candidate.rule.payload_locator.marker == [PAYLOAD_MARKER]
                && candidate.rule.counter_reset == RelationalCounterReset::PerRecord
                && candidate.status == RelationalTransformStatus::HeldoutConstraintsSatisfied
        })
        .ok_or("a held-out-supported relational rule was not retained")?;
    let session_samples = samples
        .iter()
        .filter(|sample| sample.context.session == 1)
        .cloned()
        .collect::<Vec<_>>();

    let applied = apply_relational_transform_rule(
        &session_samples,
        &candidate.rule,
        plan.limits,
        plan.limits.max_work_bytes,
    )?;

    assert_eq!(applied.session.session, 1);
    assert_eq!(applied.bytes, der_sample(1));
    assert!(applied.work_bytes >= applied.bytes.len());
    Ok(())
}

#[test]
fn discovers_disjoint_seed_and_payload_ranges_in_one_message() -> Result<(), Box<dyn Error>> {
    let records = same_message_sessions()?;
    let samples = borrow_samples(&records)?;
    let plan = same_message_plan();
    let report = infer_relational_transform_candidates(&samples, &plan)?;
    let candidate = report
        .candidates
        .iter()
        .find(|candidate| {
            candidate.rule.seed_locator.marker == [SEED_MARKER]
                && candidate.rule.seed_locator.value_offset == 1
                && candidate.rule.seed_locator.value_length == Some(2)
                && candidate.rule.payload_locator.marker == [PAYLOAD_MARKER]
                && candidate.rule.payload_locator.marker_offset == 3
                && candidate.rule.payload_locator.value_offset == 4
                && candidate.rule.counter_reset == RelationalCounterReset::Continuous
                && candidate.status == RelationalTransformStatus::HeldoutConstraintsSatisfied
        })
        .ok_or("same-message evidence did not retain the disjoint seed and payload rule")?;

    assert_eq!(report.discovery_sessions.len(), 2);
    assert_eq!(report.heldout_sessions.len(), 2);
    assert_eq!(
        candidate.discovery.supported_sessions,
        report.discovery_sessions
    );
    assert_eq!(
        candidate.heldout.supported_sessions,
        report.heldout_sessions
    );
    assert!(report.candidates.iter().all(|candidate| {
        candidate_ranges_are_disjoint(
            &candidate.rule,
            samples.first().map_or(0, |s| s.bytes.len()),
        )
    }));

    let session_samples = samples
        .iter()
        .filter(|sample| sample.context.session == 1)
        .cloned()
        .collect::<Vec<_>>();
    let applied = apply_relational_transform_rule(
        &session_samples,
        &candidate.rule,
        plan.limits,
        plan.limits.max_work_bytes,
    )?;
    assert_eq!(applied.bytes, der_sample(1));
    assert_eq!(applied.session.session, 1);
    assert_eq!(
        applied.payload_ranges,
        [ByteRange {
            start: 0,
            end: applied.bytes.len(),
        }]
    );
    Ok(())
}

#[test]
fn one_byte_counter_order_aliases_do_not_consume_candidate_or_work_budgets() -> TestResult<()> {
    let records = same_message_sessions()?;
    let samples = borrow_samples(&records)?;
    let mut single_order_plan = same_message_plan();
    single_order_plan.limits.max_locator_candidates = 8;
    single_order_plan.limits.max_candidates = 512;
    single_order_plan.limits.max_retained_candidates = 8;
    single_order_plan.limits.max_work_bytes = 64 * 1024 * 1024;

    let complete_single_order_report =
        infer_relational_transform_candidates(&samples, &single_order_plan)?;
    let exact_candidate_limit = complete_single_order_report.candidates_examined;
    single_order_plan.limits.max_candidates = exact_candidate_limit;

    let mut both_orders_plan = single_order_plan.clone();
    both_orders_plan
        .counter_byte_orders
        .push(CounterByteOrder::LittleEndian);

    let single_order_report = infer_relational_transform_candidates(&samples, &single_order_plan)?;
    let both_orders_report = infer_relational_transform_candidates(&samples, &both_orders_plan)?;

    assert!(single_order_report.candidates_examined > 0);
    assert_eq!(
        single_order_report.candidates_examined,
        exact_candidate_limit
    );
    assert_eq!(
        both_orders_report.candidates_examined,
        single_order_report.candidates_examined
    );
    assert_eq!(
        both_orders_report.work_bytes,
        single_order_report.work_bytes
    );
    assert_eq!(
        both_orders_report.candidate_limit_remaining,
        single_order_report.candidate_limit_remaining
    );
    assert_eq!(both_orders_report.candidate_limit_remaining, 0);
    assert_eq!(
        both_orders_report.candidates,
        single_order_report.candidates
    );
    assert!(both_orders_report.candidates.len() <= both_orders_plan.limits.max_retained_candidates);
    assert_eq!(
        both_orders_report.omitted_candidates,
        single_order_report.omitted_candidates
    );
    assert_eq!(
        both_orders_report.omitted_candidates_exact,
        single_order_report.omitted_candidates_exact
    );
    assert_eq!(
        both_orders_report.equivalent_candidate_aliases,
        single_order_report.candidates_examined
    );
    assert_eq!(single_order_report.equivalent_candidate_aliases, 0);
    assert_eq!(
        both_orders_report.search_exhaustive_within_plan,
        single_order_report.search_exhaustive_within_plan
    );
    assert_eq!(
        both_orders_report.search_limits,
        single_order_report.search_limits
    );
    assert!(
        !both_orders_report
            .search_limits
            .contains(&l2_workbench::protocol::RelationalSearchLimit::CandidateCount)
    );
    Ok(())
}

#[test]
fn one_payload_per_session_does_not_collapse_counter_reset_strategies() -> TestResult<()> {
    let records = same_message_sessions()?;
    let samples = borrow_samples(&records)?;
    let mut continuous_plan = same_message_plan();
    continuous_plan.limits.max_locator_candidates = 8;
    continuous_plan.limits.max_candidates = 512;
    continuous_plan.limits.max_retained_candidates = 32;
    continuous_plan.limits.max_work_bytes = 64 * 1024 * 1024;

    let mut both_resets_plan = continuous_plan.clone();
    both_resets_plan
        .counter_resets
        .push(RelationalCounterReset::PerRecord);

    let continuous_report = infer_relational_transform_candidates(&samples, &continuous_plan)?;
    let both_resets_report = infer_relational_transform_candidates(&samples, &both_resets_plan)?;

    assert!(continuous_report.candidates_examined > 0);
    assert_eq!(
        both_resets_report.candidates_examined,
        continuous_report.candidates_examined * 2
    );
    assert_eq!(
        both_resets_report.work_bytes,
        continuous_report.work_bytes * 2
    );
    assert!(
        both_resets_report.candidates.iter().any(|candidate| {
            candidate.rule.counter_reset == RelationalCounterReset::Continuous
        })
    );
    assert!(
        both_resets_report
            .candidates
            .iter()
            .any(|candidate| { candidate.rule.counter_reset == RelationalCounterReset::PerRecord })
    );
    assert_eq!(both_resets_report.equivalent_candidate_aliases, 0);
    Ok(())
}

#[test]
fn prioritizes_length_prefixed_seed_over_high_variance_ranges_under_candidate_budget()
-> TestResult<()> {
    let records = length_prefixed_seed_sessions(
        SeedLengthEncoding {
            width: CounterWidth::OneByte,
            byte_order: ByteOrder::BigEndian,
        },
        None,
    )?;
    let samples = borrow_samples(&records)?;
    let plan = length_prefixed_seed_plan();
    let report = infer_relational_transform_candidates(&samples, &plan)?;
    assert_eq!(report.candidates_examined, 1);
    let candidate = report
        .candidates
        .first()
        .ok_or("the bounded search did not retain its first candidate")?;
    assert_eq!(candidate.rule.seed_locator.value_offset, 2);
    assert_eq!(candidate.rule.seed_locator.value_length, Some(SEED_LENGTH));
    assert_eq!(
        candidate.rule.seed_locator.declared_length,
        Some(RelationalLengthField {
            offset: 1,
            width: CounterWidth::OneByte,
            byte_order: ByteOrder::BigEndian,
        })
    );
    assert_eq!(candidate.rule.payload_locator.value_offset, 1);
    assert_eq!(
        candidate.status,
        RelationalTransformStatus::HeldoutConstraintsSatisfied
    );
    Ok(())
}

#[test]
fn frozen_seed_length_field_rejects_changed_and_truncated_heldout_prefixes() -> TestResult<()> {
    for mutation in [
        HeldoutPrefixMutation::Changed,
        HeldoutPrefixMutation::Truncated,
    ] {
        let encoding = SeedLengthEncoding {
            width: CounterWidth::OneByte,
            byte_order: ByteOrder::BigEndian,
        };
        let records = length_prefixed_seed_sessions(encoding, Some(mutation))?;
        let samples = borrow_samples(&records)?;
        let plan = length_prefixed_seed_plan();
        let report = infer_relational_transform_candidates(&samples, &plan)?;
        let candidate = report
            .candidates
            .first()
            .ok_or("the bounded search did not retain its first candidate")?;

        assert_eq!(candidate.rule.seed_locator.value_offset, 2);
        assert!(candidate.rule.seed_locator.declared_length.is_some());
        assert_eq!(
            candidate.discovery.status,
            RelationalFitStatus::ConstraintsSatisfied
        );
        assert_eq!(candidate.heldout.status, RelationalFitStatus::Contradicted);
        assert_eq!(
            candidate.status,
            RelationalTransformStatus::ContradictedByHeldoutSession
        );
        let heldout_check = candidate
            .heldout
            .checks
            .iter()
            .find(|check| check.session.session == 4)
            .ok_or("the mutated held-out session was not checked")?;
        assert_eq!(
            heldout_check.falsification,
            Some(RelationalFalsification::SeedLengthMismatch {
                expected: SEED_LENGTH,
                observed: match mutation {
                    HeldoutPrefixMutation::Changed => Some(u64::try_from(SEED_LENGTH - 1)?),
                    HeldoutPrefixMutation::Truncated => None,
                },
            })
        );

        let heldout_samples = samples
            .iter()
            .filter(|sample| sample.context.session == 4)
            .cloned()
            .collect::<Vec<_>>();
        assert!(
            apply_relational_transform_rule(
                &heldout_samples,
                &candidate.rule,
                plan.limits,
                plan.limits.max_work_bytes,
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn recognizes_length_fields_across_supported_widths_and_byte_orders() -> TestResult<()> {
    for encoding in [
        SeedLengthEncoding {
            width: CounterWidth::OneByte,
            byte_order: ByteOrder::BigEndian,
        },
        SeedLengthEncoding {
            width: CounterWidth::TwoBytes,
            byte_order: ByteOrder::BigEndian,
        },
        SeedLengthEncoding {
            width: CounterWidth::TwoBytes,
            byte_order: ByteOrder::LittleEndian,
        },
        SeedLengthEncoding {
            width: CounterWidth::FourBytes,
            byte_order: ByteOrder::BigEndian,
        },
        SeedLengthEncoding {
            width: CounterWidth::FourBytes,
            byte_order: ByteOrder::LittleEndian,
        },
        SeedLengthEncoding {
            width: CounterWidth::EightBytes,
            byte_order: ByteOrder::BigEndian,
        },
        SeedLengthEncoding {
            width: CounterWidth::EightBytes,
            byte_order: ByteOrder::LittleEndian,
        },
    ] {
        let records = length_prefixed_seed_sessions(encoding, None)?;
        let samples = borrow_samples(&records)?;
        let plan = length_prefixed_seed_plan();
        let report = infer_relational_transform_candidates(&samples, &plan)?;
        let candidate = report
            .candidates
            .first()
            .ok_or("the bounded search did not retain its first candidate")?;
        assert_eq!(
            candidate.rule.seed_locator.value_offset,
            1 + encoding.width.byte_length()
        );
        assert_eq!(
            candidate.rule.seed_locator.declared_length,
            Some(RelationalLengthField {
                offset: 1,
                width: encoding.width,
                byte_order: encoding.byte_order,
            })
        );
        assert_eq!(
            candidate.status,
            RelationalTransformStatus::HeldoutConstraintsSatisfied
        );
    }
    Ok(())
}

#[test]
fn bounded_seed_locator_retention_keeps_later_declared_length_evidence() -> TestResult<()> {
    let encoding = SeedLengthEncoding {
        width: CounterWidth::TwoBytes,
        byte_order: ByteOrder::BigEndian,
    };
    let records = length_prefixed_seed_sessions(encoding, None)?;
    let samples = borrow_samples(&records)?;
    let mut plan = length_prefixed_seed_plan();
    plan.limits.max_locator_candidates = 8;
    plan.limits.max_candidates = 4096;
    plan.limits.max_retained_candidates = 128;

    let report = infer_relational_transform_candidates(&samples, &plan)?;

    let candidate = report
        .candidates
        .iter()
        .find(|candidate| {
            candidate.rule.seed_locator.marker == [SEED_MARKER]
                && candidate.rule.seed_locator.value_offset == 3
                && candidate.rule.seed_locator.value_length == Some(SEED_LENGTH)
                && candidate.rule.seed_locator.declared_length
                    == Some(RelationalLengthField {
                        offset: 1,
                        width: CounterWidth::TwoBytes,
                        byte_order: ByteOrder::BigEndian,
                    })
                && candidate.rule.payload_locator.marker == [PAYLOAD_MARKER]
                && candidate.rule.payload_locator.value_offset == 1
        })
        .ok_or("bounded retention discarded the later length-backed seed locator")?;

    assert_eq!(
        candidate.status,
        RelationalTransformStatus::HeldoutConstraintsSatisfied
    );
    assert!(!report.search_exhaustive_within_plan);
    assert!(
        report
            .search_limits
            .contains(&l2_workbench::protocol::RelationalSearchLimit::LocatorCount)
    );
    Ok(())
}

#[test]
fn bounded_pair_schedule_reaches_later_seed_before_exhausting_earlier_rows() -> TestResult<()> {
    let records = fair_pair_schedule_sessions()?;
    let samples = borrow_samples(&records)?;
    let plan = RelationalTransformPlan {
        limits: RelationalTransformLimits {
            max_cohorts: 1,
            max_sessions: 4,
            max_records_per_session: 17,
            max_record_bytes: 128,
            max_total_bytes: 1024,
            max_marker_bytes: 1,
            max_marker_offset: 0,
            max_seed_bytes: 1,
            max_locator_offset: 62,
            max_locator_candidates: 256,
            max_candidates: 1026,
            max_retained_candidates: 64,
            max_work_bytes: 16 * 1024 * 1024,
        },
        parser_scope: RelationalParserScope::EachSession,
        parser_formats: vec![ArtifactValidationFormat::Der],
        counter_widths: vec![CounterWidth::OneByte],
        counter_byte_orders: vec![CounterByteOrder::BigEndian],
        seed_orders: vec![
            SeedCounterOrder::CounterThenSeed,
            SeedCounterOrder::SeedThenCounter,
        ],
        initial_counters: vec![0],
        counter_resets: vec![RelationalCounterReset::PerRecord],
    };

    let report = infer_relational_transform_candidates(&samples, &plan)?;
    let target = report
        .candidates
        .iter()
        .find(|candidate| {
            candidate.rule.seed_locator.marker == [0x2f]
                && candidate.rule.seed_locator.value_offset == 1
                && candidate.rule.seed_locator.value_length == Some(1)
                && candidate.rule.payload_locator.marker == [PAYLOAD_MARKER]
                && candidate.rule.payload_locator.value_offset == 1
        })
        .ok_or_else(|| {
            format!(
                "the bounded schedule did not reach the later seed/payload pair: examined {}, retained {}, limits {:?}, locators {}",
                report.candidates_examined,
                report.candidates.len(),
                report.search_limits,
                report.locator_candidates_examined
            )
        })?;

    assert_eq!(
        target.status,
        RelationalTransformStatus::HeldoutConstraintsSatisfied
    );
    assert_eq!(report.candidates_examined, plan.limits.max_candidates);
    assert!(!report.search_exhaustive_within_plan);
    assert!(!report.omitted_candidates_exact);
    assert!(
        report
            .search_limits
            .contains(&l2_workbench::protocol::RelationalSearchLimit::CandidateCount)
    );
    Ok(())
}

#[test]
fn sparse_relative_start_cue_reaches_seed_51_payload_129_within_pair_budget() -> TestResult<()> {
    let records = sparse_aligned_rank_pair_schedule_sessions()?;
    let samples = borrow_samples(&records)?;
    let mut plan = ranked_pair_schedule_plan(1_170, 53);
    plan.limits.max_locator_offset = 130;
    plan.limits.max_locator_candidates = 512;
    plan.limits.max_record_bytes = 256;
    plan.limits.max_total_bytes = 4_096;

    let report = infer_relational_transform_candidates(&samples, &plan)?;
    let target = report
        .candidates
        .iter()
        .find(|candidate| {
            candidate.rule.seed_locator.marker == [0x43]
                && candidate.rule.seed_locator.value_offset == 130
                && candidate.rule.seed_locator.value_length == Some(1)
                && candidate.rule.payload_locator.marker == [0x82]
                && candidate.rule.payload_locator.value_offset == 130
        })
        .ok_or_else(|| {
            format!(
                "the sparse cue did not reach the rank-51/rank-129 pair: examined {}, retained {}, limits {:?}",
                report.candidates_examined,
                report.candidates.len(),
                report.search_limits
            )
        })?;

    assert_eq!(
        target.status,
        RelationalTransformStatus::HeldoutConstraintsSatisfied
    );
    assert_eq!(report.candidates_examined, plan.limits.max_candidates);
    assert!(!report.search_exhaustive_within_plan);
    assert!(
        report
            .search_limits
            .contains(&l2_workbench::protocol::RelationalSearchLimit::CandidateCount)
    );
    Ok(())
}

#[test]
fn unaligned_late_locator_pair_remains_reachable_through_fallback() -> TestResult<()> {
    let records = ranked_pair_schedule_sessions(0x40, 0x4b, 0x92, 7)?;
    let samples = borrow_samples(&records)?;
    let plan = ranked_pair_schedule_plan(1_500, 13);

    let report = infer_relational_transform_candidates(&samples, &plan)?;
    let target = report
        .candidates
        .iter()
        .find(|candidate| {
            candidate.rule.seed_locator.marker == [0x4b]
                && candidate.rule.seed_locator.value_offset == 6
                && candidate.rule.seed_locator.value_length == Some(1)
                && candidate.rule.payload_locator.marker == [0x92]
                && candidate.rule.payload_locator.value_offset == 7
        })
        .ok_or_else(|| {
            format!(
                "the unaligned late-ranked pair was lost: examined {}, retained {}, limits {:?}",
                report.candidates_examined,
                report.candidates.len(),
                report.search_limits
            )
        })?;

    assert_eq!(
        target.status,
        RelationalTransformStatus::HeldoutConstraintsSatisfied
    );
    assert_eq!(report.candidates_examined, plan.limits.max_candidates);
    assert!(!report.search_exhaustive_within_plan);
    assert!(!report.omitted_candidates_exact);
    Ok(())
}

#[test]
fn retention_keeps_later_structural_rule_across_payload_starts_and_configurations() -> TestResult<()>
{
    let records = relational_retention_sessions()?;
    let samples = borrow_samples(&records)?;
    let plan = relational_retention_plan();
    let report = infer_relational_transform_candidates(&samples, &plan)?;

    assert!(report.search_exhaustive_within_plan);
    assert!(report.omitted_candidates_exact);
    assert!(report.omitted_candidates > 0);
    assert_eq!(report.candidates.len(), plan.limits.max_retained_candidates);
    assert_eq!(
        report.candidate_limit_remaining,
        plan.limits.max_candidates - report.candidates_examined
    );
    assert!(
        report
            .search_limits
            .contains(&l2_workbench::protocol::RelationalSearchLimit::RetainedCandidates)
    );

    let mut locator_pairs = Vec::new();
    for candidate in &report.candidates {
        if !locator_pairs.iter().any(|(seed, payload)| {
            *seed == candidate.rule.seed_locator && *payload == candidate.rule.payload_locator
        }) {
            locator_pairs.push((
                candidate.rule.seed_locator.clone(),
                candidate.rule.payload_locator.clone(),
            ));
        }
    }
    assert_eq!(locator_pairs.len(), 8);
    for (seed, payload) in &locator_pairs {
        let pair_candidates = report
            .candidates
            .iter()
            .filter(|candidate| {
                candidate.rule.seed_locator == *seed && candidate.rule.payload_locator == *payload
            })
            .collect::<Vec<_>>();
        assert_eq!(pair_candidates.len(), 2);
        let first = pair_candidates
            .first()
            .ok_or("the retained locator pair has no first configuration")?;
        let second = pair_candidates
            .get(1)
            .ok_or("the retained locator pair has no second configuration")?;
        assert!(
            first.rule.operation != second.rule.operation
                || first.rule.counter_reset != second.rule.counter_reset
        );
    }

    let target = report
        .candidates
        .iter()
        .find(|candidate| is_target_retention_rule(candidate, 10))
        .ok_or("the later structurally valid payload rule was omitted")?;
    let earlier_wrong_start = report
        .candidates
        .iter()
        .find(|candidate| is_target_retention_rule(candidate, 9))
        .ok_or("the earlier deferred-transform rule was not retained")?;
    assert_eq!(
        target.status,
        RelationalTransformStatus::AwaitingAcrossSessionValidation
    );
    assert_eq!(
        earlier_wrong_start.status,
        RelationalTransformStatus::AwaitingAcrossSessionValidation
    );

    let target_output = aggregate_rule_output(&samples, &target.rule, plan.limits)?;
    let wrong_output = aggregate_rule_output(&samples, &earlier_wrong_start.rule, plan.limits)?;
    assert!(validates_exact_der(&target_output));
    assert!(!validates_exact_der(&wrong_output));
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetentionGateAssessment {
    ArtifactValidated,
    Unresolved,
}

#[derive(Default)]
struct RetentionEvaluatorState {
    first_unresolved_rule: Option<l2_workbench::protocol::RelationalTransformRule>,
    validated_after_unresolved: bool,
}

fn evaluate_retention_candidate(
    context: &l2_workbench::protocol::RelationalTransformEvaluationContext<'_>,
    candidate: &l2_workbench::protocol::RelationalTransformCandidate,
    discovery_outputs: &[l2_workbench::protocol::RelationalAppliedOutput],
    heldout_outputs: &[l2_workbench::protocol::RelationalAppliedOutput],
    state: &mut RetentionEvaluatorState,
) -> Result<RelationalCandidateEvaluation<RetentionGateAssessment>, std::io::Error> {
    let all_outputs = ordered_outputs(discovery_outputs, heldout_outputs);
    assert!(
        all_outputs
            .iter()
            .all(|output| payload_output_ranges_are_valid(output))
    );
    let expected_sessions = context.discovery_sessions.len() + context.heldout_sessions.len();
    let is_complete = all_outputs.len() == expected_sessions
        && matches!(
            candidate.status,
            RelationalTransformStatus::AwaitingAcrossSessionValidation
        );
    let output_valid = aggregate_outputs(&all_outputs)
        .map(|bytes| validates_exact_der(&bytes))
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let assessment = if is_complete && output_valid {
        state.validated_after_unresolved |= state.first_unresolved_rule.is_some();
        RetentionGateAssessment::ArtifactValidated
    } else {
        if state.first_unresolved_rule.is_none() && is_target_retention_rule(candidate, 9) {
            state.first_unresolved_rule = Some(candidate.rule.clone());
        }
        RetentionGateAssessment::Unresolved
    };
    Ok(RelationalCandidateEvaluation {
        priority: match assessment {
            RetentionGateAssessment::ArtifactValidated => 3,
            RetentionGateAssessment::Unresolved => 1,
        },
        work_bytes: 0,
        assessment,
    })
}

#[test]
fn evaluator_priority_retains_later_valid_rule_and_keeps_deferred_rules_unresolved()
-> TestResult<()> {
    let records = relational_retention_sessions()?;
    let samples = borrow_samples(&records)?;
    let mut plan = relational_retention_plan();
    plan.limits.max_retained_candidates = 3;
    plan.counter_resets = vec![RelationalCounterReset::Continuous];
    plan.counter_byte_orders = vec![CounterByteOrder::BigEndian];
    let options = RelationalTransformEvaluationOptions {
        max_retained_output_bytes: plan.limits.max_total_bytes,
    };
    let mut evaluator_state = RetentionEvaluatorState::default();
    let evaluated = infer_relational_transform_candidates_with_evaluator(
        &samples,
        &plan,
        None,
        options,
        |context, candidate, discovery_outputs, heldout_outputs| {
            evaluate_retention_candidate(
                context,
                candidate,
                discovery_outputs,
                heldout_outputs,
                &mut evaluator_state,
            )
        },
    )?;

    assert_priority_evaluation(&evaluated, &plan, options, &evaluator_state)
}

fn assert_priority_evaluation(
    evaluated: &l2_workbench::protocol::RelationalCandidateEvaluationReport<
        RetentionGateAssessment,
    >,
    plan: &RelationalTransformPlan,
    options: RelationalTransformEvaluationOptions,
    evaluator_state: &RetentionEvaluatorState,
) -> TestResult<()> {
    let report = &evaluated.report;
    assert!(report.search_exhaustive_within_plan);
    assert!(report.omitted_candidates_exact);
    assert!(report.omitted_candidates > 0);
    assert_eq!(report.candidates.len(), plan.limits.max_retained_candidates);
    assert_eq!(evaluated.evaluations.len(), report.candidates.len());
    assert!(evaluator_state.validated_after_unresolved);
    assert!(evaluated.output_capture_complete);
    assert!(evaluated.output_bytes_retained <= options.max_retained_output_bytes);

    let target_index = report
        .candidates
        .iter()
        .position(|candidate| is_target_retention_rule(candidate, 10))
        .ok_or("the later exact artifact rule was omitted")?;
    let target = report
        .candidates
        .get(target_index)
        .ok_or("the retained exact artifact rule disappeared")?;
    let target_evaluation = evaluated
        .evaluations
        .get(target_index)
        .ok_or("the exact artifact rule has no aligned evaluation")?;
    assert_eq!(
        target_evaluation.assessment,
        RetentionGateAssessment::ArtifactValidated
    );
    assert_eq!(
        target.status,
        RelationalTransformStatus::AwaitingAcrossSessionValidation
    );
    let captured = target_evaluation
        .outputs
        .as_ref()
        .ok_or("the bounded retained-output capture omitted the winning rule")?;
    let captured_outputs = ordered_outputs(&captured.discovery, &captured.heldout);
    assert!(validates_exact_der(&aggregate_outputs(&captured_outputs)?));

    let unresolved_rule = evaluator_state
        .first_unresolved_rule
        .as_ref()
        .ok_or("the evaluator never observed a deferred rule")?;
    let unresolved_index = report
        .candidates
        .iter()
        .position(|candidate| candidate.rule == *unresolved_rule)
        .ok_or("the earlier deferred rule was not retained")?;
    let unresolved = report
        .candidates
        .get(unresolved_index)
        .ok_or("the earlier deferred rule disappeared")?;
    let unresolved_evaluation = evaluated
        .evaluations
        .get(unresolved_index)
        .ok_or("the earlier deferred rule has no aligned evaluation")?;
    assert_eq!(
        unresolved.status,
        RelationalTransformStatus::AwaitingAcrossSessionValidation
    );
    assert_eq!(
        unresolved_evaluation.assessment,
        RetentionGateAssessment::Unresolved
    );
    Ok(())
}

#[test]
fn evaluator_output_capture_respects_its_global_byte_budget() -> TestResult<()> {
    let records = relational_retention_sessions()?;
    let samples = borrow_samples(&records)?;
    let mut plan = relational_retention_plan();
    plan.limits.max_retained_candidates = 2;
    let evaluated = infer_relational_transform_candidates_with_evaluator(
        &samples,
        &plan,
        None,
        RelationalTransformEvaluationOptions {
            max_retained_output_bytes: 1,
        },
        |_, _, _, _| {
            Ok::<_, std::io::Error>(RelationalCandidateEvaluation {
                priority: 1,
                work_bytes: 0,
                assessment: RetentionGateAssessment::Unresolved,
            })
        },
    )?;

    assert_eq!(evaluated.report.candidates.len(), 2);
    assert_eq!(evaluated.evaluations.len(), 2);
    assert!(evaluated.output_bytes_retained <= 1);
    assert!(!evaluated.output_capture_complete);
    assert!(evaluated.output_capture_omissions > 0);
    assert!(
        evaluated
            .evaluations
            .iter()
            .all(|evaluation| evaluation.outputs.is_none())
    );
    Ok(())
}

#[test]
fn positive_residual_work_insufficient_for_fit_prevents_exhaustive_negative() -> TestResult<()> {
    let records = same_message_sessions()?;
    let samples = borrow_samples(&records)?;
    let mut plan = same_message_plan();
    plan.limits.max_work_bytes = 1;
    plan.limits.max_candidates = 4_096;
    let job = Job::new("budget-limited relational search");

    let report = infer_relational_transform_candidates_with_job(&samples, &plan, Some(&job))?;

    assert!(report.candidates_examined > 0);
    assert_eq!(report.work_bytes_remaining, 1);
    assert!(!report.search_exhaustive_within_plan);
    assert!(!report.omitted_candidates_exact);
    assert!(
        report
            .search_limits
            .contains(&l2_workbench::protocol::RelationalSearchLimit::WorkBytes)
    );
    assert!(
        !report
            .search_limits
            .contains(&l2_workbench::protocol::RelationalSearchLimit::CandidateCount)
    );
    assert_eq!(
        job.snapshot()?.counters.get(&Counter::CandidatesRejected),
        Some(&0)
    );
    Ok(())
}

#[test]
fn evaluator_work_must_fit_the_remaining_shared_search_budget() -> TestResult<()> {
    let records = relational_retention_sessions()?;
    let samples = borrow_samples(&records)?;
    let plan = relational_retention_plan();
    let mut callback_seen = false;
    let result = infer_relational_transform_candidates_with_evaluator(
        &samples,
        &plan,
        None,
        RelationalTransformEvaluationOptions::default(),
        |context, _, _, _| {
            callback_seen = true;
            Ok::<_, std::io::Error>(RelationalCandidateEvaluation {
                priority: 0,
                work_bytes: context.work_bytes_remaining.saturating_add(1),
                assessment: (),
            })
        },
    );

    assert!(callback_seen);
    assert!(matches!(
        result,
        Err(l2_workbench::protocol::RelationalEvaluationError::EvaluatorWorkLimit {
            requested,
            remaining,
        }) if remaining > 0 && requested == remaining.saturating_add(1)
    ));
    Ok(())
}

fn ordered_outputs<'a>(
    discovery: &'a [l2_workbench::protocol::RelationalAppliedOutput],
    heldout: &'a [l2_workbench::protocol::RelationalAppliedOutput],
) -> Vec<&'a l2_workbench::protocol::RelationalAppliedOutput> {
    let mut outputs = discovery.iter().chain(heldout).collect::<Vec<_>>();
    outputs.sort_unstable_by_key(|output| output.session_order);
    outputs
}

fn aggregate_outputs(
    outputs: &[&l2_workbench::protocol::RelationalAppliedOutput],
) -> TestResult<Vec<u8>> {
    let length = outputs
        .iter()
        .try_fold(0_usize, |total, output| {
            total.checked_add(output.bytes.len())
        })
        .ok_or("evaluated output length overflowed")?;
    let mut aggregate = Vec::with_capacity(length);
    for output in outputs {
        aggregate.extend_from_slice(&output.bytes);
    }
    Ok(aggregate)
}

fn payload_output_ranges_are_valid(
    output: &l2_workbench::protocol::RelationalAppliedOutput,
) -> bool {
    if output.payload_samples.len() != output.payload_ranges.len() {
        return false;
    }
    let mut expected_start = 0_usize;
    for range in &output.payload_ranges {
        if range.start != expected_start
            || range.end < range.start
            || output.bytes.get(range.start..range.end).is_none()
        {
            return false;
        }
        expected_start = range.end;
    }
    expected_start == output.bytes.len()
}

#[test]
fn candidate_limit_preserves_known_retention_omissions() -> TestResult<()> {
    let records = relational_retention_sessions()?;
    let samples = borrow_samples(&records)?;
    let mut plan = relational_retention_plan();
    plan.limits.max_candidates = 4;
    plan.limits.max_retained_candidates = 1;
    let report = infer_relational_transform_candidates(&samples, &plan)?;

    assert_eq!(report.candidates_examined, 4);
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(report.candidate_limit_remaining, 0);
    assert!(!report.search_exhaustive_within_plan);
    assert!(!report.omitted_candidates_exact);
    assert_eq!(report.omitted_candidates, 4);
    assert_eq!(
        report.search_limit,
        Some(l2_workbench::protocol::RelationalSearchLimit::RetainedCandidates)
    );
    assert!(
        report
            .search_limits
            .contains(&l2_workbench::protocol::RelationalSearchLimit::CandidateCount)
    );
    Ok(())
}

#[test]
fn incomplete_locator_search_does_not_become_exact_after_retention_omissions() -> TestResult<()> {
    let records = relational_retention_sessions()?;
    let samples = borrow_samples(&records)?;
    let mut plan = relational_retention_plan();
    plan.limits.max_locator_candidates = 8;
    plan.limits.max_candidates = 128;
    plan.limits.max_retained_candidates = 1;
    let report = infer_relational_transform_candidates(&samples, &plan)?;

    assert!(!report.search_exhaustive_within_plan);
    assert!(!report.omitted_candidates_exact);
    assert!(
        report
            .search_limits
            .contains(&l2_workbench::protocol::RelationalSearchLimit::LocatorCount)
    );
    assert!(
        report
            .search_limits
            .contains(&l2_workbench::protocol::RelationalSearchLimit::RetainedCandidates)
    );
    Ok(())
}

#[test]
fn does_not_retain_a_same_message_rule_with_overlapping_seed_and_payload_ranges()
-> Result<(), Box<dyn Error>> {
    let records = overlapping_same_message_sessions();
    let samples = borrow_samples(&records)?;
    let mut plan = same_message_plan();
    plan.parser_scope = RelationalParserScope::AcrossSessions;
    plan.limits.max_marker_offset = 2;
    plan.limits.max_locator_offset = 3;
    plan.limits.max_seed_bytes = 2;
    plan.limits.max_candidates = 128;
    let report = infer_relational_transform_candidates(&samples, &plan)?;

    assert!(report.candidates_examined > 0);
    assert!(report.candidates.iter().all(|candidate| {
        candidate_ranges_are_disjoint(
            &candidate.rule,
            samples.first().map_or(0, |s| s.bytes.len()),
        )
    }));
    assert!(!report.candidates.iter().any(|candidate| {
        candidate.rule.seed_locator.marker == [SEED_MARKER]
            && candidate.rule.seed_locator.marker_offset == 0
            && candidate.rule.seed_locator.value_offset == 1
            && candidate.rule.seed_locator.value_length == Some(2)
            && candidate.rule.payload_locator.marker == [PAYLOAD_MARKER]
            && candidate.rule.payload_locator.marker_offset == 2
            && candidate.rule.payload_locator.value_offset == 1
    }));
    Ok(())
}

fn candidate_ranges_are_disjoint(
    rule: &l2_workbench::protocol::RelationalTransformRule,
    sample_length: usize,
) -> bool {
    let Some(seed_length) = rule.seed_locator.value_length else {
        return false;
    };
    let Some(seed_end) = rule.seed_locator.value_offset.checked_add(seed_length) else {
        return false;
    };
    let payload_end = rule
        .payload_locator
        .value_length
        .and_then(|length| rule.payload_locator.value_offset.checked_add(length))
        .unwrap_or(sample_length);
    seed_end <= rule.payload_locator.value_offset || payload_end <= rule.seed_locator.value_offset
}

fn same_message_plan() -> RelationalTransformPlan {
    RelationalTransformPlan {
        limits: RelationalTransformLimits {
            max_cohorts: 4,
            max_sessions: 4,
            max_records_per_session: 2,
            max_record_bytes: 128,
            max_total_bytes: 1024,
            max_marker_bytes: 1,
            max_marker_offset: 3,
            max_seed_bytes: 2,
            max_locator_offset: 4,
            max_locator_candidates: 32,
            max_candidates: 256,
            max_retained_candidates: 256,
            max_work_bytes: 1024 * 1024,
        },
        parser_scope: RelationalParserScope::EachSession,
        parser_formats: vec![l2_workbench::artifact::ArtifactValidationFormat::Der],
        counter_widths: vec![CounterWidth::OneByte],
        counter_byte_orders: vec![CounterByteOrder::BigEndian],
        seed_orders: vec![SeedCounterOrder::SeedThenCounter],
        initial_counters: vec![0],
        counter_resets: vec![RelationalCounterReset::Continuous],
    }
}

fn length_prefixed_seed_plan() -> RelationalTransformPlan {
    RelationalTransformPlan {
        limits: RelationalTransformLimits {
            max_cohorts: 4,
            max_sessions: 4,
            max_records_per_session: 2,
            max_record_bytes: 128,
            max_total_bytes: 1024,
            max_marker_bytes: 1,
            max_marker_offset: 0,
            max_seed_bytes: SEED_LENGTH,
            max_locator_offset: 18,
            max_locator_candidates: 2048,
            max_candidates: 1,
            max_retained_candidates: 4,
            max_work_bytes: 1024 * 1024,
        },
        parser_scope: RelationalParserScope::EachSession,
        parser_formats: vec![l2_workbench::artifact::ArtifactValidationFormat::Der],
        counter_widths: vec![CounterWidth::OneByte],
        counter_byte_orders: vec![CounterByteOrder::BigEndian],
        seed_orders: vec![SeedCounterOrder::SeedThenCounter],
        initial_counters: vec![0],
        counter_resets: vec![RelationalCounterReset::Continuous],
    }
}

fn relational_retention_plan() -> RelationalTransformPlan {
    RelationalTransformPlan {
        limits: RelationalTransformLimits {
            max_cohorts: 4,
            max_sessions: 4,
            max_records_per_session: 1,
            max_record_bytes: 128,
            max_total_bytes: 1024,
            max_marker_bytes: 1,
            max_marker_offset: 0,
            max_seed_bytes: SEED_LENGTH,
            max_locator_offset: 10,
            max_locator_candidates: 2048,
            max_candidates: 30_000,
            max_retained_candidates: 16,
            max_work_bytes: 32 * 1024 * 1024,
        },
        parser_scope: RelationalParserScope::AcrossSessions,
        parser_formats: vec![ArtifactValidationFormat::Der],
        counter_widths: vec![CounterWidth::OneByte, CounterWidth::TwoBytes],
        counter_byte_orders: vec![CounterByteOrder::BigEndian, CounterByteOrder::LittleEndian],
        seed_orders: vec![
            SeedCounterOrder::SeedThenCounter,
            SeedCounterOrder::CounterThenSeed,
        ],
        initial_counters: vec![0],
        counter_resets: vec![
            RelationalCounterReset::Continuous,
            RelationalCounterReset::PerRecord,
        ],
    }
}

fn relational_retention_sessions() -> TestResult<Vec<OwnedRecord>> {
    let plaintext = der_sample(1);
    let chunk_boundaries = [15_usize, 30, 45, plaintext.len()];
    let mut records = Vec::new();
    let mut chunk_start = 0_usize;
    for session_number in 1_u8..=4 {
        let chunk_end = chunk_boundaries
            .get(usize::from(session_number - 1))
            .copied()
            .ok_or("the synthetic session chunk boundary is missing")?;
        let chunk = plaintext
            .get(chunk_start..chunk_end)
            .ok_or("the synthetic session chunk range is invalid")?;
        chunk_start = chunk_end;

        let seed = (0_u8..u8::try_from(SEED_LENGTH)?)
            .map(|index| {
                session_number
                    .wrapping_mul(31)
                    .wrapping_add(index.wrapping_mul(23))
            })
            .collect::<Vec<_>>();
        let ciphertext = encrypt_continuous(chunk, &seed)?;
        let mut message = vec![u8::try_from(SEED_LENGTH)?];
        message.extend_from_slice(&seed);
        message.push(DECOY_MARKER);
        message.extend_from_slice(&ciphertext);
        records.push((u32::from(session_number), Direction::FirstToSecond, message));
    }
    Ok(records)
}

fn is_target_retention_rule(
    candidate: &l2_workbench::protocol::RelationalTransformCandidate,
    payload_offset: usize,
) -> bool {
    let RelationalOperationTemplate::Sha256CounterXor(operation) = candidate.rule.operation;
    candidate.rule.seed_locator.value_offset == 1
        && candidate.rule.seed_locator.value_length == Some(SEED_LENGTH)
        && candidate.rule.seed_locator.declared_length.is_some()
        && candidate.rule.payload_locator.value_offset == payload_offset
        && candidate.rule.counter_reset == RelationalCounterReset::Continuous
        && operation.initial_counter == 0
        && operation.counter_width == CounterWidth::OneByte
        && operation.counter_byte_order == CounterByteOrder::BigEndian
        && operation.seed_order == SeedCounterOrder::SeedThenCounter
}

fn aggregate_rule_output(
    samples: &[RelationalRecordSample<'_>],
    rule: &l2_workbench::protocol::RelationalTransformRule,
    limits: RelationalTransformLimits,
) -> TestResult<Vec<u8>> {
    let mut outputs = Vec::new();
    for session in 1..=4 {
        let session_samples = samples
            .iter()
            .filter(|sample| sample.context.session == session)
            .cloned()
            .collect::<Vec<_>>();
        let output =
            apply_relational_transform_rule(&session_samples, rule, limits, limits.max_work_bytes)?;
        outputs.push((output.session_order, output.bytes));
    }
    outputs.sort_unstable_by_key(|(session_order, _)| *session_order);
    let output_length = outputs
        .iter()
        .try_fold(0_usize, |total, (_, bytes)| total.checked_add(bytes.len()))
        .ok_or("the synthetic aggregate output length overflowed")?;
    let mut aggregate = Vec::with_capacity(output_length);
    for (_, bytes) in outputs {
        aggregate.extend_from_slice(&bytes);
    }
    Ok(aggregate)
}

fn validates_exact_der(bytes: &[u8]) -> bool {
    matches!(
        ArtifactValidator::default().validate_as(ArtifactValidationFormat::Der, bytes),
        ArtifactValidationOutcome::Validated { range, .. }
            if range.offset == 0 && range.length == bytes.len()
    )
}

fn length_prefixed_seed_sessions(
    encoding: SeedLengthEncoding,
    heldout_mutation: Option<HeldoutPrefixMutation>,
) -> TestResult<Vec<OwnedRecord>> {
    let mut records = Vec::new();
    for session_number in 1_u8..=4 {
        let session = u32::from(session_number);
        let seed = (0_u8..u8::try_from(SEED_LENGTH)?)
            .map(|index| {
                session_number
                    .wrapping_mul(37)
                    .wrapping_add(index.wrapping_mul(19))
            })
            .collect::<Vec<_>>();
        let mut seed_message = vec![SEED_MARKER];
        seed_message.extend(encode_seed_length(SEED_LENGTH, encoding)?);
        seed_message.extend_from_slice(&seed);
        seed_message.extend(session_noise(session_number));

        let plaintext = der_sample(session_number);
        let ciphertext = encrypt_continuous(&plaintext, &seed)?;
        let payload = tagged(PAYLOAD_MARKER, &ciphertext);
        if session_number == 4 {
            match heldout_mutation {
                Some(HeldoutPrefixMutation::Changed) => {
                    let changed = encode_seed_length(SEED_LENGTH - 1, encoding)?;
                    let prefix_end = 1 + encoding.width.byte_length();
                    if let Some(prefix) = seed_message.get_mut(1..prefix_end) {
                        prefix.copy_from_slice(&changed);
                    }
                }
                Some(HeldoutPrefixMutation::Truncated) => seed_message.truncate(1),
                None => {}
            }
        }
        records.push((session, Direction::FirstToSecond, seed_message));
        records.push((session, Direction::SecondToFirst, payload));
    }
    Ok(records)
}

#[derive(Clone, Copy)]
enum HeldoutPrefixMutation {
    Changed,
    Truncated,
}

#[derive(Clone, Copy)]
struct SeedLengthEncoding {
    width: CounterWidth,
    byte_order: ByteOrder,
}

fn encode_seed_length(length: usize, encoding: SeedLengthEncoding) -> TestResult<Vec<u8>> {
    let length = u64::try_from(length)?;
    let bytes = match encoding.byte_order {
        ByteOrder::BigEndian => length.to_be_bytes(),
        ByteOrder::LittleEndian => length.to_le_bytes(),
    };
    let width = encoding.width.byte_length();
    let encoded = match encoding.byte_order {
        ByteOrder::BigEndian => bytes.get(8 - width..),
        ByteOrder::LittleEndian => bytes.get(..width),
    }
    .ok_or("seed length encoding has an invalid width")?;
    Ok(encoded.to_vec())
}

fn session_noise(session: u8) -> Vec<u8> {
    let mut state = u32::from(session).wrapping_mul(0x9e37_79b9);
    (0..16)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            u8::try_from((state & 0xff) | 0x20).unwrap_or(0x20)
        })
        .collect()
}

fn same_message_sessions() -> TestResult<Vec<OwnedRecord>> {
    let mut records = Vec::new();
    for session_number in 1_u8..=4 {
        let session = u32::from(session_number);
        let seed = [
            session_number.wrapping_mul(17).wrapping_add(3),
            session_number.wrapping_mul(29).wrapping_add(11),
        ];
        let ciphertext = encrypt_continuous(&der_sample(session_number), &seed)?;
        let mut message = Vec::with_capacity(4 + ciphertext.len());
        message.push(SEED_MARKER);
        message.extend_from_slice(&seed);
        message.push(PAYLOAD_MARKER);
        message.extend_from_slice(&ciphertext);
        records.push((session, Direction::FirstToSecond, message));
    }
    Ok(records)
}

fn overlapping_same_message_sessions() -> Vec<OwnedRecord> {
    (1_u8..=4)
        .map(|session| {
            (
                u32::from(session),
                Direction::FirstToSecond,
                vec![SEED_MARKER, session, PAYLOAD_MARKER, 0x41, 0x42],
            )
        })
        .collect()
}

fn search_plan() -> RelationalTransformPlan {
    RelationalTransformPlan {
        limits: RelationalTransformLimits {
            max_cohorts: 8,
            max_sessions: 8,
            max_records_per_session: 16,
            max_record_bytes: 256,
            max_total_bytes: 16 * 1024,
            max_marker_bytes: 1,
            max_marker_offset: 0,
            max_seed_bytes: SEED_LENGTH,
            max_locator_offset: 4,
            max_locator_candidates: 2_000,
            max_candidates: 20_000,
            max_retained_candidates: 256,
            max_work_bytes: 32 * 1024 * 1024,
        },
        parser_scope: l2_workbench::protocol::RelationalParserScope::EachSession,
        parser_formats: vec![l2_workbench::artifact::ArtifactValidationFormat::Der],
        counter_widths: vec![
            CounterWidth::OneByte,
            CounterWidth::TwoBytes,
            CounterWidth::EightBytes,
        ],
        counter_byte_orders: vec![CounterByteOrder::BigEndian, CounterByteOrder::LittleEndian],
        seed_orders: vec![
            SeedCounterOrder::SeedThenCounter,
            SeedCounterOrder::CounterThenSeed,
        ],
        initial_counters: vec![0, 1, 3],
        counter_resets: vec![
            RelationalCounterReset::Continuous,
            RelationalCounterReset::PerRecord,
        ],
    }
}

fn synthetic_sessions(corrupt_last_heldout: bool) -> TestResult<Vec<OwnedRecord>> {
    let mut owned = Vec::<OwnedRecord>::new();
    for session_number in 1_u8..=4 {
        let session = u32::from(session_number);
        let mut seed = Vec::with_capacity(SEED_LENGTH);
        for index in 0..SEED_LENGTH {
            let index = u8::try_from(index)?;
            seed.push(
                session_number
                    .wrapping_mul(17)
                    .wrapping_add(index.wrapping_mul(29)),
            );
        }
        let plaintext = der_sample(session_number);
        let split = match session {
            1 => [19, 43],
            2 => [7, 37],
            3 => [31, 52],
            _ => [13, 46],
        };
        let ciphertext = encrypt_per_record(&plaintext, &seed, split)?;
        let mut chunks = vec![
            ciphertext
                .get(..split[0])
                .ok_or("first payload split is invalid")?
                .to_vec(),
            ciphertext
                .get(split[0]..split[1])
                .ok_or("second payload split is invalid")?
                .to_vec(),
            ciphertext
                .get(split[1]..)
                .ok_or("last payload split is invalid")?
                .to_vec(),
        ];
        if corrupt_last_heldout
            && session == 4
            && let Some(byte) = chunks.first_mut().and_then(|chunk| chunk.first_mut())
        {
            *byte ^= 0x04;
        }

        let seed_record = tagged(SEED_MARKER, &seed);
        let mut payload_records = chunks
            .into_iter()
            .map(|chunk| tagged(PAYLOAD_MARKER, &chunk));
        let first_payload = payload_records
            .next()
            .ok_or("first payload record is missing")?;
        let second_payload = payload_records
            .next()
            .ok_or("second payload record is missing")?;
        let third_payload = payload_records
            .next()
            .ok_or("third payload record is missing")?;
        let decoy = tagged(DECOY_MARKER, &[session_number, 0x55, 0xaa]);
        let first_to_second = Direction::FirstToSecond;
        let second_to_first = Direction::SecondToFirst;
        if session % 2 == 0 {
            owned.push((session, first_to_second, seed_record));
            owned.push((session, second_to_first, first_payload));
            owned.push((session, first_to_second, decoy));
        } else {
            owned.push((session, second_to_first, first_payload));
            owned.push((session, first_to_second, decoy));
            owned.push((session, first_to_second, seed_record));
        }
        owned.push((session, second_to_first, second_payload));
        owned.push((session, second_to_first, third_payload));
    }
    Ok(owned)
}

fn borrow_samples(records: &[OwnedRecord]) -> TestResult<Vec<RelationalRecordSample<'_>>> {
    records
        .iter()
        .enumerate()
        .map(|(index, (session, direction, bytes))| {
            Ok(RelationalRecordSample {
                sample: u64::try_from(index + 1)?,
                context: MessageContext {
                    source: "synthetic-source".to_owned(),
                    scope: "synthetic-scope".to_owned(),
                    session: u64::from(*session),
                    direction: *direction,
                },
                session_order: u64::from(*session),
                bytes,
            })
        })
        .collect()
}

fn fair_pair_schedule_sessions() -> TestResult<Vec<OwnedRecord>> {
    let mut records = Vec::new();
    for session_number in 1_u8..=4 {
        let session = u32::from(session_number);
        let target_seed = 0x2f_u8.wrapping_add(session_number);
        for marker in 0x20_u8..=0x2f {
            let seed = marker.wrapping_add(session_number);
            let message = vec![marker, seed];
            records.push((session, Direction::FirstToSecond, message));
        }
        let plaintext = der_sample(session_number);
        let ciphertext = encrypt_pair_schedule_target(&plaintext, target_seed)?;
        records.push((
            session,
            Direction::SecondToFirst,
            tagged(PAYLOAD_MARKER, &ciphertext),
        ));
    }
    Ok(records)
}

fn ranked_pair_schedule_sessions(
    first_seed_marker: u8,
    target_seed_marker: u8,
    payload_marker: u8,
    payload_value_offset: usize,
) -> TestResult<Vec<OwnedRecord>> {
    let payload_padding_length = payload_value_offset
        .checked_sub(1)
        .ok_or("the payload value offset must follow its marker")?;
    let mut records = Vec::new();
    for session_number in 1_u8..=4 {
        let session = u32::from(session_number);
        let target_seed = target_seed_marker.wrapping_add(session_number);
        for marker in first_seed_marker..=target_seed_marker {
            let message = if marker == target_seed_marker {
                vec![marker, 0x55, 0x55, 0x55, 0x55, 0x55, target_seed]
            } else {
                vec![marker, marker.wrapping_add(session_number)]
            };
            records.push((session, Direction::FirstToSecond, message));
        }
        let plaintext = der_sample(session_number);
        let ciphertext = encrypt_pair_schedule_target(&plaintext, target_seed)?;
        let mut payload = Vec::with_capacity(payload_value_offset + ciphertext.len());
        payload.push(payload_marker);
        payload.extend(std::iter::repeat_n(0x55, payload_padding_length));
        payload.extend_from_slice(&ciphertext);
        records.push((session, Direction::SecondToFirst, payload));
    }
    Ok(records)
}

fn sparse_aligned_rank_pair_schedule_sessions() -> TestResult<Vec<OwnedRecord>> {
    let mut records = Vec::new();
    for session_number in 1_u8..=4 {
        let session = u32::from(session_number);
        let target_seed = 0x43_u8.wrapping_add(session_number);
        for marker in 0x10_u8..=0x42 {
            records.push((
                session,
                Direction::FirstToSecond,
                vec![marker, marker.wrapping_add(session_number)],
            ));
        }

        let mut seed_message = vec![0x55; 131];
        if let Some(marker) = seed_message.first_mut() {
            *marker = 0x43;
        }
        if let Some(seed) = seed_message.get_mut(130) {
            *seed = target_seed;
        }
        records.push((session, Direction::FirstToSecond, seed_message));

        let plaintext = der_sample(session_number);
        let ciphertext = encrypt_pair_schedule_target(&plaintext, target_seed)?;
        let mut payload_message = vec![0x55; 130 + ciphertext.len()];
        if let Some(marker) = payload_message.first_mut() {
            *marker = 0x82;
        }
        if let Some(payload) = payload_message.get_mut(130..) {
            payload.copy_from_slice(&ciphertext);
        }
        records.push((session, Direction::SecondToFirst, payload_message));
    }
    Ok(records)
}

fn ranked_pair_schedule_plan(
    max_candidates: usize,
    records_per_session: usize,
) -> RelationalTransformPlan {
    RelationalTransformPlan {
        limits: RelationalTransformLimits {
            max_cohorts: 1,
            max_sessions: 4,
            max_records_per_session: records_per_session,
            max_record_bytes: 128,
            max_total_bytes: 2_048,
            max_marker_bytes: 1,
            max_marker_offset: 0,
            max_seed_bytes: 1,
            max_locator_offset: 10,
            max_locator_candidates: 256,
            max_candidates,
            max_retained_candidates: 512,
            max_work_bytes: 16 * 1024 * 1024,
        },
        parser_scope: RelationalParserScope::EachSession,
        parser_formats: vec![ArtifactValidationFormat::Der],
        counter_widths: vec![CounterWidth::OneByte],
        counter_byte_orders: vec![CounterByteOrder::BigEndian],
        seed_orders: vec![
            SeedCounterOrder::CounterThenSeed,
            SeedCounterOrder::SeedThenCounter,
        ],
        initial_counters: vec![0],
        counter_resets: vec![RelationalCounterReset::PerRecord],
    }
}

fn encrypt_pair_schedule_target(bytes: &[u8], seed: u8) -> TestResult<Vec<u8>> {
    use l2_workbench::derivation::{OperandRef, Operation, Recipe, run};

    let report = run(
        bytes,
        &Recipe {
            steps: vec![Operation::Sha256CounterXor {
                seed: OperandRef::from(vec![seed]),
                initial_counter: 0,
                counter_width: CounterWidth::OneByte,
                counter_byte_order: CounterByteOrder::BigEndian,
                seed_order: SeedCounterOrder::SeedThenCounter,
            }],
            constraints: Vec::new(),
        },
    )?;
    Ok(report.output)
}

fn tagged(marker: u8, body: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(body.len() + 1);
    record.push(marker);
    record.extend_from_slice(body);
    record
}

fn der_sample(session: u8) -> Vec<u8> {
    let mut bytes = vec![0x04, 60];
    bytes.extend((0_u8..60).map(|index| session.wrapping_add(index.wrapping_mul(13))));
    bytes
}

fn encrypt_per_record(
    bytes: &[u8],
    seed: &[u8],
    splits: [usize; 2],
) -> Result<Vec<u8>, Box<dyn Error>> {
    use l2_workbench::derivation::{OperandRef, Operation, Recipe, run};

    let mut output = Vec::new();
    for chunk in [
        bytes
            .get(..splits[0])
            .ok_or("first payload split is invalid")?,
        bytes
            .get(splits[0]..splits[1])
            .ok_or("second payload split is invalid")?,
        bytes
            .get(splits[1]..)
            .ok_or("last payload split is invalid")?,
    ] {
        let report = run(
            chunk,
            &Recipe {
                steps: vec![Operation::Sha256CounterXor {
                    seed: OperandRef::from(seed.to_vec()),
                    initial_counter: 3,
                    counter_width: CounterWidth::EightBytes,
                    counter_byte_order: CounterByteOrder::LittleEndian,
                    seed_order: SeedCounterOrder::CounterThenSeed,
                }],
                constraints: Vec::new(),
            },
        )?;
        output.extend_from_slice(&report.output);
    }
    Ok(output)
}

fn encrypt_continuous(bytes: &[u8], seed: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    use l2_workbench::derivation::{OperandRef, Operation, Recipe, run};

    let report = run(
        bytes,
        &Recipe {
            steps: vec![Operation::Sha256CounterXor {
                seed: OperandRef::from(seed.to_vec()),
                initial_counter: 0,
                counter_width: CounterWidth::OneByte,
                counter_byte_order: CounterByteOrder::BigEndian,
                seed_order: SeedCounterOrder::SeedThenCounter,
            }],
            constraints: Vec::new(),
        },
    )?;
    Ok(report.output)
}
