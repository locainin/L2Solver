use super::support::{fail, require};
#[path = "relational_ranges.rs"]
mod ranges;
use l2_workbench::{
    artifact::ArtifactValidationFormat,
    derivation::{
        CounterByteOrder, CounterWidth, DerivationStatus, OperandRef, Operation, Recipe,
        SeedCounterOrder, run,
    },
    protocol::{
        ByteOrder, Direction, MessageContext, RelationalCounterReset, RelationalFalsification,
        RelationalFitStatus, RelationalLengthField, RelationalOperationTemplate,
        RelationalParserScope, RelationalRecordSample, RelationalSha256CounterXor,
        RelationalTransformCandidate, RelationalTransformLimits, RelationalTransformPlan,
        RelationalTransformReport, RelationalTransformStatus, apply_relational_transform_rule,
        infer_relational_transform_candidates,
    },
};
use ranges::candidate_ranges_are_valid;

const MAX_SESSIONS: usize = 4;
const MAX_SEED_LENGTH: usize = 3;
const MAX_CONTENT_LENGTH: u8 = 32;
const MAX_SEARCH_CANDIDATES: usize = 1_024;
const MAX_SEARCH_WORK_BYTES: usize = 1024 * 1024;
const MAX_LOCATOR_MARKER_OFFSET: usize = 16;

type OwnedRecord = (u64, u64, Direction, Vec<u8>);
type BorrowedSamples<'a> = Vec<RelationalRecordSample<'a>>;

struct Scenario {
    records: Vec<OwnedRecord>,
    expected: Vec<(u64, Vec<u8>)>,
    session_count: usize,
    reversed_order: bool,
    plan: RelationalTransformPlan,
    operation: RelationalSha256CounterXor,
    seed_marker: u8,
    seed_marker_offset: usize,
    payload_marker: u8,
    payload_marker_offset: usize,
    seed_value_offset: usize,
    seed_length_field: RelationalLengthField,
    seed_length: usize,
    corrupt_session: Option<u64>,
    corruption: Option<HeldoutCorruption>,
}

#[derive(Clone, Copy)]
enum HeldoutCorruption {
    Payload,
    DeclaredSeedLength,
}

pub fn exercise(input: &[u8]) {
    let Some(scenario) = make_scenario(input) else {
        return;
    };
    let Some(samples) = borrow_samples(&scenario.records) else {
        return;
    };
    let Ok(report) = infer_relational_transform_candidates(&samples, &scenario.plan) else {
        fail();
    };
    check_report(&samples, &scenario.plan, &report);
    if check_known_hypothesis(&scenario, &report) {
        replay_known_hypothesis(&samples, &scenario, &report);
    }
    exercise_tighter_limits(input, &samples, &scenario.plan);
}

fn make_scenario(input: &[u8]) -> Option<Scenario> {
    let session_count = 3 + usize::from(byte_at(input, 2) % 2);
    let seed_length = usize::from(byte_at(input, 3) % u8::try_from(MAX_SEED_LENGTH).ok()?) + 1;
    let seed_marker_offset = usize::from(byte_at(input, 18) % 4);
    let seed_length_field = RelationalLengthField {
        offset: seed_marker_offset.checked_add(1)?,
        width: generated_length_width(input),
        byte_order: if byte_at(input, 17) & 1 == 0 {
            ByteOrder::BigEndian
        } else {
            ByteOrder::LittleEndian
        },
    };
    let seed_value_offset = seed_length_field
        .offset
        .checked_add(seed_length_field.width.byte_length())?;
    let seed_marker = byte_at(input, 0);
    let payload_marker = distinct_marker(seed_marker, byte_at(input, 1));
    let payload_marker_offset = seed_value_offset.checked_add(seed_length)?;
    let payload_value_offset = payload_marker_offset.checked_add(1)?;
    let marker_offset_limit = payload_marker_offset;
    let locator_offset_limit = payload_value_offset;
    let reversed_order = byte_at(input, 8) & 1 != 0;
    let discovery_count = session_count.div_ceil(2);
    let corruption = match byte_at(input, 9) % 3 {
        0 => None,
        1 => Some(HeldoutCorruption::Payload),
        _ => Some(HeldoutCorruption::DeclaredSeedLength),
    };
    let corrupt_session = if corruption.is_some() {
        let heldout_ordinal = if reversed_order {
            session_count.checked_sub(discovery_count)?
        } else {
            discovery_count.checked_add(1)?
        };
        Some(u64::try_from(heldout_ordinal).ok()?)
    } else {
        None
    };
    let operation = generated_operation(input);
    let limits = RelationalTransformLimits {
        max_cohorts: 1,
        max_sessions: MAX_SESSIONS,
        max_records_per_session: 1,
        max_record_bytes: 128,
        max_total_bytes: 512,
        max_marker_bytes: 1,
        max_marker_offset: marker_offset_limit.min(MAX_LOCATOR_MARKER_OFFSET),
        max_seed_bytes: seed_length,
        max_locator_offset: locator_offset_limit,
        max_locator_candidates: 128,
        max_candidates: MAX_SEARCH_CANDIDATES,
        max_retained_candidates: MAX_SEARCH_CANDIDATES,
        max_work_bytes: MAX_SEARCH_WORK_BYTES,
    };
    let plan = scenario_plan(operation, limits);

    let mut scenario = Scenario {
        records: Vec::new(),
        expected: Vec::new(),
        session_count,
        reversed_order,
        plan,
        operation,
        seed_marker,
        seed_marker_offset,
        payload_marker,
        payload_marker_offset,
        seed_value_offset,
        seed_length_field,
        seed_length,
        corrupt_session,
        corruption,
    };
    populate_records(input, &mut scenario)?;
    Some(scenario)
}

fn scenario_plan(
    operation: RelationalSha256CounterXor,
    limits: RelationalTransformLimits,
) -> RelationalTransformPlan {
    RelationalTransformPlan {
        limits,
        parser_scope: RelationalParserScope::EachSession,
        parser_formats: vec![ArtifactValidationFormat::Der],
        counter_widths: vec![operation.counter_width],
        counter_byte_orders: vec![operation.counter_byte_order],
        seed_orders: vec![operation.seed_order],
        initial_counters: vec![operation.initial_counter],
        counter_resets: vec![RelationalCounterReset::Continuous],
    }
}

fn populate_records(input: &[u8], scenario: &mut Scenario) -> Option<()> {
    let session_count_u64 = u64::try_from(scenario.session_count).ok()?;
    let content_length = byte_at(input, 10) % MAX_CONTENT_LENGTH + 1;
    let payload_value_offset = scenario.payload_marker_offset.checked_add(1)?;
    let direction = if byte_at(input, 19) & 1 == 0 {
        Direction::FirstToSecond
    } else {
        Direction::SecondToFirst
    };
    for session_number in 1..=scenario.session_count {
        let session = u64::try_from(session_number).ok()?;
        let session_byte = u8::try_from(session_number).ok()?;
        let order = capture_order(session, session_count_u64, scenario.reversed_order)?;
        let seed = generated_seed(
            input,
            session_byte,
            scenario.seed_length,
            scenario.seed_marker,
            scenario.payload_marker,
        )?;
        let plaintext = generated_object(input, session_byte, content_length);
        let ciphertext = encrypt(&plaintext, &seed, scenario.operation)?;

        let mut message = Vec::new();
        message
            .try_reserve_exact(payload_value_offset.checked_add(ciphertext.len())?)
            .ok()?;
        message.resize(scenario.seed_marker_offset, byte_at(input, 20));
        message.push(scenario.seed_marker);
        message.extend(encode_length(
            scenario.seed_length,
            scenario.seed_length_field,
        )?);
        message.extend_from_slice(&seed);
        message.push(scenario.payload_marker);
        message.extend_from_slice(&ciphertext);
        if Some(session) == scenario.corrupt_session {
            match scenario.corruption {
                Some(HeldoutCorruption::Payload) => {
                    let first_ciphertext_byte =
                        message.get_mut(payload_value_offset..)?.first_mut()?;
                    *first_ciphertext_byte ^= 1;
                }
                Some(HeldoutCorruption::DeclaredSeedLength) => {
                    let changed = encode_length(
                        scenario.seed_length.checked_add(1)?,
                        scenario.seed_length_field,
                    )?;
                    let field_end = scenario
                        .seed_length_field
                        .offset
                        .checked_add(scenario.seed_length_field.width.byte_length())?;
                    message
                        .get_mut(scenario.seed_length_field.offset..field_end)?
                        .copy_from_slice(&changed);
                }
                None => {}
            }
        }
        scenario.records.push((session, order, direction, message));
        scenario.expected.push((session, plaintext));
    }
    Some(())
}

fn generated_length_width(input: &[u8]) -> CounterWidth {
    match byte_at(input, 16) % 4 {
        0 => CounterWidth::OneByte,
        1 => CounterWidth::TwoBytes,
        2 => CounterWidth::FourBytes,
        _ => CounterWidth::EightBytes,
    }
}

fn encode_length(length: usize, field: RelationalLengthField) -> Option<Vec<u8>> {
    let length = u64::try_from(length).ok()?;
    let bytes = match field.byte_order {
        ByteOrder::BigEndian => length.to_be_bytes(),
        ByteOrder::LittleEndian => length.to_le_bytes(),
    };
    let width = field.width.byte_length();
    let encoded = match field.byte_order {
        ByteOrder::BigEndian => bytes.get(8_usize.checked_sub(width)?..),
        ByteOrder::LittleEndian => bytes.get(..width),
    }?;
    Some(encoded.to_vec())
}

const fn distinct_marker(first: u8, requested: u8) -> u8 {
    if first == requested {
        requested.wrapping_add(1)
    } else {
        requested
    }
}

fn generated_operation(input: &[u8]) -> RelationalSha256CounterXor {
    RelationalSha256CounterXor {
        initial_counter: u64::from(byte_at(input, 7) % 4),
        counter_width: if byte_at(input, 4) & 1 == 0 {
            CounterWidth::OneByte
        } else {
            CounterWidth::TwoBytes
        },
        counter_byte_order: if byte_at(input, 5) & 1 == 0 {
            CounterByteOrder::BigEndian
        } else {
            CounterByteOrder::LittleEndian
        },
        seed_order: if byte_at(input, 6) & 1 == 0 {
            SeedCounterOrder::SeedThenCounter
        } else {
            SeedCounterOrder::CounterThenSeed
        },
    }
}

fn capture_order(session: u64, maximum: u64, reverse: bool) -> Option<u64> {
    if reverse {
        maximum.checked_add(1)?.checked_sub(session)
    } else {
        Some(session)
    }
}

fn generated_seed(
    input: &[u8],
    session: u8,
    length: usize,
    seed_marker: u8,
    payload_marker: u8,
) -> Option<Vec<u8>> {
    let mut seed = Vec::new();
    seed.try_reserve_exact(length).ok()?;
    for index in 0..length {
        let index_byte = u8::try_from(index).ok()?;
        let mut byte = byte_at(input, 11_usize.checked_add(index)?)
            .wrapping_add(session.wrapping_mul(19))
            .wrapping_add(index_byte);
        while byte == seed_marker || byte == payload_marker {
            byte = byte.wrapping_add(1);
        }
        seed.push(byte);
    }
    Some(seed)
}

fn generated_object(input: &[u8], session: u8, content_length: u8) -> Vec<u8> {
    let mut object = Vec::with_capacity(2 + usize::from(content_length));
    object.push(0x04);
    object.push(content_length);
    for index in 0..content_length {
        let source_offset = 32_usize.saturating_add(usize::from(index));
        object.push(
            byte_at(input, source_offset)
                .wrapping_add(session.wrapping_mul(37))
                .wrapping_add(index),
        );
    }
    object
}

fn encrypt(
    plaintext: &[u8],
    seed: &[u8],
    parameters: RelationalSha256CounterXor,
) -> Option<Vec<u8>> {
    let report = run(
        plaintext,
        &Recipe {
            steps: vec![Operation::Sha256CounterXor {
                seed: OperandRef::from(seed.to_vec()),
                initial_counter: parameters.initial_counter,
                counter_width: parameters.counter_width,
                counter_byte_order: parameters.counter_byte_order,
                seed_order: parameters.seed_order,
            }],
            constraints: Vec::new(),
        },
    )
    .ok()?;
    (report.status == DerivationStatus::Completed).then_some(report.output)
}

fn borrow_samples(records: &[OwnedRecord]) -> Option<BorrowedSamples<'_>> {
    records
        .iter()
        .enumerate()
        .map(|(index, (session, order, direction, bytes))| {
            Some(RelationalRecordSample {
                sample: u64::try_from(index.checked_add(1)?).ok()?,
                context: MessageContext {
                    source: "bounded-fuzz-source".to_owned(),
                    scope: "bounded-fuzz-scope".to_owned(),
                    session: *session,
                    direction: *direction,
                },
                session_order: *order,
                bytes,
            })
        })
        .collect()
}

fn check_report(
    samples: &[RelationalRecordSample<'_>],
    plan: &RelationalTransformPlan,
    report: &RelationalTransformReport,
) {
    let limits = plan.limits;
    require(report.candidates_examined <= limits.max_candidates);
    require(
        report.candidate_limit_remaining
            == limits
                .max_candidates
                .saturating_sub(report.candidates_examined),
    );
    require(report.candidates.len() <= limits.max_retained_candidates);
    require(report.candidates.len() <= report.candidates_examined);
    let accounted_candidates = report
        .candidates
        .len()
        .saturating_add(report.omitted_candidates);
    let possible_unexamined_omission = usize::from(!report.omitted_candidates_exact);
    require(
        accounted_candidates
            <= report
                .candidates_examined
                .saturating_add(possible_unexamined_omission),
    );
    if report.omitted_candidates_exact {
        require(accounted_candidates <= report.candidates_examined);
    }
    if report.search_exhaustive_within_plan {
        require(report.omitted_candidates_exact);
    } else {
        require(!report.omitted_candidates_exact);
    }
    require(report.locator_candidates_examined <= limits.max_locator_candidates.saturating_mul(2));
    require(report.work_bytes <= limits.max_work_bytes);
    require(report.work_bytes_remaining == limits.max_work_bytes.saturating_sub(report.work_bytes));
    check_session_partition(samples, report);
    for candidate in &report.candidates {
        check_candidate(samples, candidate, report);
    }
}

fn check_session_partition(
    samples: &[RelationalRecordSample<'_>],
    report: &RelationalTransformReport,
) {
    let mut retained_sessions = Vec::new();
    for session in report
        .discovery_sessions
        .iter()
        .chain(&report.heldout_sessions)
    {
        require(!retained_sessions.contains(session));
        retained_sessions.push(session.clone());
        require(
            samples
                .iter()
                .any(|sample| sample.context.session == session.session),
        );
    }
    require(retained_sessions.len() == samples.len());
    for discovery in &report.discovery_sessions {
        require(
            report
                .heldout_sessions
                .iter()
                .all(|heldout| heldout != discovery),
        );
    }
}

fn check_candidate(
    samples: &[RelationalRecordSample<'_>],
    candidate: &RelationalTransformCandidate,
    report: &RelationalTransformReport,
) {
    require(candidate.discovery.checks.len() <= report.discovery_sessions.len());
    require(candidate.heldout.checks.len() <= report.heldout_sessions.len());
    require(
        candidate
            .discovery
            .checks
            .iter()
            .all(|check| report.discovery_sessions.contains(&check.session)),
    );
    require(
        candidate
            .heldout
            .checks
            .iter()
            .all(|check| report.heldout_sessions.contains(&check.session)),
    );
    for check in candidate
        .discovery
        .checks
        .iter()
        .chain(&candidate.heldout.checks)
    {
        let session_input_bytes = samples
            .iter()
            .filter(|sample| sample.context.session == check.session.session)
            .map(|sample| sample.bytes.len())
            .sum::<usize>();
        require(session_input_bytes > 0);
        require(
            check
                .output_length
                .is_none_or(|length| length <= session_input_bytes),
        );
        require(
            check
                .output_sha256
                .as_ref()
                .is_none_or(|digest| digest.len() == 64),
        );
    }
    require(candidate_ranges_are_valid(samples, &candidate.rule));
    require(
        candidate
            .rule
            .seed_locator
            .declared_length
            .is_none_or(|field| {
                field
                    .offset
                    .checked_add(field.width.byte_length())
                    .is_some()
            }),
    );
}

fn check_known_hypothesis(scenario: &Scenario, report: &RelationalTransformReport) -> bool {
    if !report.search_exhaustive_within_plan
        || !report.omitted_candidates_exact
        || report.omitted_candidates > 0
    {
        return false;
    }
    let Some(candidate) = report
        .candidates
        .iter()
        .find(|candidate| matches_expected_rule(candidate, scenario))
    else {
        fail();
    };
    require(candidate.discovery.supported_sessions.len() == report.discovery_sessions.len());
    let expected_status = if scenario.corrupt_session.is_some() {
        RelationalTransformStatus::ContradictedByHeldoutSession
    } else {
        RelationalTransformStatus::HeldoutConstraintsSatisfied
    };
    require(candidate.status == expected_status);
    require(candidate.discovery.status == RelationalFitStatus::ConstraintsSatisfied);
    if scenario.corrupt_session.is_some() {
        let Some(corrupt_session) = scenario.corrupt_session else {
            fail();
        };
        require(candidate.heldout.status == RelationalFitStatus::Contradicted);
        let Some(heldout_check) = candidate.heldout.checks.iter().find(|check| {
            check.session.session == corrupt_session
                && check.status == RelationalFitStatus::Contradicted
        }) else {
            fail();
        };
        match scenario.corruption {
            Some(HeldoutCorruption::DeclaredSeedLength) => {
                let Some(observed_length) = scenario.seed_length.checked_add(1) else {
                    fail();
                };
                require(
                    heldout_check.falsification
                        == Some(RelationalFalsification::SeedLengthMismatch {
                            expected: scenario.seed_length,
                            observed: u64::try_from(observed_length).ok(),
                        }),
                );
            }
            Some(HeldoutCorruption::Payload) => require(heldout_check.falsification.is_some()),
            None => fail(),
        }
    } else {
        require(candidate.heldout.status == RelationalFitStatus::ConstraintsSatisfied);
    }
    true
}

fn replay_known_hypothesis(
    samples: &[RelationalRecordSample<'_>],
    scenario: &Scenario,
    report: &RelationalTransformReport,
) {
    let Some(candidate) = report
        .candidates
        .iter()
        .find(|candidate| matches_expected_rule(candidate, scenario))
    else {
        fail();
    };
    for (session, expected) in &scenario.expected {
        let session_samples = samples
            .iter()
            .filter(|sample| sample.context.session == *session)
            .cloned()
            .collect::<Vec<_>>();
        let result = apply_relational_transform_rule(
            &session_samples,
            &candidate.rule,
            scenario.plan.limits,
            scenario.plan.limits.max_work_bytes,
        );
        if Some(*session) == scenario.corrupt_session {
            require(result.is_err());
            continue;
        }
        let Ok(applied) = result else {
            fail();
        };
        require(applied.bytes.as_slice() == expected.as_slice());
        require(!applied.parser_validation_deferred);
        require(applied.work_bytes <= scenario.plan.limits.max_work_bytes);
        require(applied.session.session == *session);
    }
}

fn matches_expected_rule(candidate: &RelationalTransformCandidate, scenario: &Scenario) -> bool {
    candidate.rule.seed_locator.marker == [scenario.seed_marker]
        && candidate.rule.seed_locator.marker_offset == scenario.seed_marker_offset
        && candidate.rule.seed_locator.value_offset == scenario.seed_value_offset
        && candidate.rule.seed_locator.value_length == Some(scenario.seed_length)
        && declared_length_matches(
            candidate.rule.seed_locator.declared_length,
            scenario.seed_length_field,
        )
        && candidate.rule.payload_locator.marker == [scenario.payload_marker]
        && candidate.rule.payload_locator.marker_offset == scenario.payload_marker_offset
        && candidate.rule.payload_locator.value_offset
            == scenario.payload_marker_offset.saturating_add(1)
        && operation_matches(candidate, scenario.operation)
}

fn operation_matches(
    candidate: &RelationalTransformCandidate,
    expected: RelationalSha256CounterXor,
) -> bool {
    matches!(
        candidate.rule.operation,
        RelationalOperationTemplate::Sha256CounterXor(actual) if actual == expected
    )
}

fn declared_length_matches(
    actual: Option<RelationalLengthField>,
    expected: RelationalLengthField,
) -> bool {
    actual.is_some_and(|actual| {
        actual.offset == expected.offset
            && actual.width == expected.width
            && (actual.width == CounterWidth::OneByte || actual.byte_order == expected.byte_order)
    })
}

fn exercise_tighter_limits(
    input: &[u8],
    samples: &[RelationalRecordSample<'_>],
    plan: &RelationalTransformPlan,
) {
    let mut constrained = plan.clone();
    constrained.limits.max_locator_candidates = usize::from(byte_at(input, 12) % 16) + 1;
    constrained.limits.max_candidates = usize::from(byte_at(input, 13) % 24) + 1;
    constrained.limits.max_retained_candidates = usize::from(byte_at(input, 14) % 8) + 1;
    constrained.limits.max_work_bytes = usize::from(byte_at(input, 15)) % 4096 + 1;
    let Ok(report) = infer_relational_transform_candidates(samples, &constrained) else {
        return;
    };
    check_report(samples, &constrained, &report);
}

fn byte_at(input: &[u8], offset: usize) -> u8 {
    input.get(offset).copied().unwrap_or_default()
}
