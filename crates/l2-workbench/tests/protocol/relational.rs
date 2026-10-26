use l2_workbench::{
    derivation::{CounterByteOrder, CounterWidth, SeedCounterOrder},
    protocol::{
        Direction, MessageContext, RelationalCounterReset, RelationalFitStatus,
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
    assert_eq!(
        candidate.rule.operation.sha256_counter_xor().counter_width,
        CounterWidth::EightBytes
    );
    assert_eq!(
        candidate
            .rule
            .operation
            .sha256_counter_xor()
            .counter_byte_order,
        CounterByteOrder::LittleEndian
    );
    assert_eq!(
        candidate.rule.operation.sha256_counter_xor().seed_order,
        SeedCounterOrder::CounterThenSeed
    );
    assert_eq!(
        candidate
            .rule
            .operation
            .sha256_counter_xor()
            .initial_counter,
        3
    );
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
