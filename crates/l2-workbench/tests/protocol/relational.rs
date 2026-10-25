use l2_workbench::{
    derivation::{CounterByteOrder, CounterWidth, SeedCounterOrder},
    protocol::{
        Direction, MessageContext, RelationalCounterReset, RelationalFitStatus,
        RelationalRecordSample, RelationalTransformLimits, RelationalTransformPlan,
        RelationalTransformStatus, apply_relational_transform_rule,
        infer_relational_transform_candidates,
    },
};
use std::error::Error;

const SEED_MARKER: u8 = 0x31;
const PAYLOAD_MARKER: u8 = 0x82;
const DECOY_MARKER: u8 = 0xee;
const SEED_LENGTH: usize = 8;

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
        candidate.rule.operation.sha256_counter_xor().counter_byte_order,
        CounterByteOrder::LittleEndian
    );
    assert_eq!(
        candidate.rule.operation.sha256_counter_xor().seed_order,
        SeedCounterOrder::CounterThenSeed
    );
    assert_eq!(candidate.rule.operation.sha256_counter_xor().initial_counter, 3);
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

fn synthetic_sessions(
    corrupt_last_heldout: bool,
) -> Result<Vec<(u32, Direction, Vec<u8>)>, Box<dyn Error>> {
    let mut owned = Vec::<(u32, Direction, Vec<u8>)>::new();
    for session in 1..=4 {
        let seed = (0..SEED_LENGTH)
            .map(|index| {
                (session as u8)
                    .wrapping_mul(17)
                    .wrapping_add(index as u8 * 29)
            })
            .collect::<Vec<_>>();
        let plaintext = der_sample(session as u8);
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
        if corrupt_last_heldout && session == 4 {
            if let Some(byte) = chunks.first_mut().and_then(|chunk| chunk.first_mut()) {
                *byte ^= 0x04;
            }
        }

        let seed_record = tagged(SEED_MARKER, &seed);
        let payload_records = chunks
            .into_iter()
            .map(|chunk| tagged(PAYLOAD_MARKER, &chunk))
            .collect::<Vec<_>>();
        let decoy = tagged(DECOY_MARKER, &[session as u8, 0x55, 0xaa]);
        let first_to_second = Direction::FirstToSecond;
        let second_to_first = Direction::SecondToFirst;
        if session % 2 == 0 {
            owned.push((session, first_to_second, seed_record));
            owned.push((session, second_to_first, payload_records[0].clone()));
            owned.push((session, first_to_second, decoy));
            owned.push((session, second_to_first, payload_records[1].clone()));
            owned.push((session, second_to_first, payload_records[2].clone()));
        } else {
            owned.push((session, second_to_first, payload_records[0].clone()));
            owned.push((session, first_to_second, decoy));
            owned.push((session, first_to_second, seed_record));
            owned.push((session, second_to_first, payload_records[1].clone()));
            owned.push((session, second_to_first, payload_records[2].clone()));
        }
    }
    Ok(owned)
}

fn borrow_samples<'a>(
    records: &'a [(u32, Direction, Vec<u8>)],
) -> Result<Vec<RelationalRecordSample<'a>>, Box<dyn Error>> {
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
    bytes.extend((0..60).map(|index| session.wrapping_add((index as u8).wrapping_mul(13))));
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
