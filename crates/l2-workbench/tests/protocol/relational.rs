use l2_workbench::{
    artifact::{ArtifactValidationFormat, ArtifactValidationOutcome, ArtifactValidator},
    derivation::{CounterByteOrder, CounterWidth, SeedCounterOrder},
    protocol::{
        ByteOrder, Direction, MessageContext, RelationalCounterReset, RelationalFalsification,
        RelationalFitStatus, RelationalLengthField, RelationalOperationTemplate,
        RelationalParserScope, RelationalRecordSample, RelationalTransformLimits,
        RelationalTransformPlan, RelationalTransformStatus, apply_relational_transform_rule,
        infer_relational_transform_candidates,
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
        RelationalTransformStatus::TransformSupportedAcrossSessions
    );
    assert_eq!(
        earlier_wrong_start.status,
        RelationalTransformStatus::TransformSupportedAcrossSessions
    );

    let target_output = aggregate_rule_output(&samples, &target.rule, plan.limits)?;
    let wrong_output = aggregate_rule_output(&samples, &earlier_wrong_start.rule, plan.limits)?;
    assert!(validates_exact_der(&target_output));
    assert!(!validates_exact_der(&wrong_output));
    Ok(())
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
