use super::{
    PrefixAdmission, PrefixPreparation, RelationalByteRangeLocator, RelationalCoordinateBasis,
    RelationalCounterReset, RelationalLengthField, RelationalOperationTemplate,
    RelationalParserScope, RelationalRecordSample, RelationalSha256CounterXor,
    RelationalTransformLimits, RelationalTransformRule, group_sessions, prepare_candidate_prefix,
    transform_prepared_prefix,
};
use crate::artifact::ArtifactValidationFormat;
use crate::derivation::{CounterByteOrder, CounterWidth, SeedCounterOrder};
use crate::protocol::relational::search::probe::{
    PrefixProbeOutcome, score_prepared_candidate_prefix,
};
use crate::protocol::{ByteOrder, Direction, MessageContext};
use std::error::Error;

#[test]
fn positive_insufficient_work_never_starts_a_prefix_transform() -> Result<(), Box<dyn Error>> {
    let mut bytes = vec![0xd2, 2, 0x11, 0x22, 0x57];
    bytes.extend([0x33; 64]);
    let samples = [RelationalRecordSample {
        sample: 1,
        context: MessageContext {
            source: String::from("synthetic"),
            scope: String::from("stream"),
            session: 1,
            direction: Direction::FirstToSecond,
        },
        session_order: 1,
        bytes: &bytes,
    }];
    let limits = RelationalTransformLimits::default();
    let groups = group_sessions(&samples, limits, &mut || Ok(()))?;
    let rule = rule();
    let PrefixPreparation::Ready(prepared) =
        prepare_candidate_prefix(&samples, &groups, &rule, limits, 32)?
    else {
        return Err("the synthetic prefix should satisfy its selectors".into());
    };

    assert!(matches!(
        prepared.within_work_limit(66)?,
        PrefixAdmission::WorkLimited
    ));

    let PrefixPreparation::Ready(prepared) =
        prepare_candidate_prefix(&samples, &groups, &rule, limits, 32)?
    else {
        return Err("the synthetic prefix should satisfy its selectors".into());
    };
    let PrefixAdmission::Ready(ready) = prepared.within_work_limit(67)? else {
        return Err("the exact transform allowance should admit the prefix".into());
    };
    let output = transform_prepared_prefix(&samples, ready)?;
    assert_eq!(output.work_bytes, 67);
    assert_eq!(output.messages.len(), 1);
    Ok(())
}

#[test]
fn prefix_preparation_distinguishes_contradictions_from_unusable_probes()
-> Result<(), Box<dyn Error>> {
    let contradiction_bytes = [0xc2, 2, 0x11, 0x22, 0x57, 0x33];
    let samples = [sample(1, &contradiction_bytes)];
    let limits = RelationalTransformLimits::default();
    let groups = group_sessions(&samples, limits, &mut || Ok(()))?;
    assert!(matches!(
        prepare_candidate_prefix(&samples, &groups, &rule(), limits, 32)?,
        PrefixPreparation::Contradicted
    ));

    let seed = [0xd2, 2, 0x11, 0x22];
    let payload_a = [0x57, 0x33];
    let payload_b = [0x57, 0x44];
    let samples = [
        sample(1, &seed),
        sample(2, &payload_a),
        sample(3, &payload_b),
    ];
    let groups = group_sessions(&samples, limits, &mut || Ok(()))?;
    let mut multi_payload_rule = rule();
    multi_payload_rule.payload_locator.coordinate_basis = RelationalCoordinateBasis::MessageStartV1;
    assert!(matches!(
        prepare_candidate_prefix(&samples, &groups, &multi_payload_rule, limits, 32)?,
        PrefixPreparation::NotApplicable
    ));

    let mut exhausted = vec![0xd2, 2, 0x11, 0x22, 0x57];
    exhausted.extend(vec![0x33; 32 * 255 + 1]);
    let samples = [sample(1, &exhausted)];
    let groups = group_sessions(&samples, limits, &mut || Ok(()))?;
    assert!(matches!(
        prepare_candidate_prefix(&samples, &groups, &rule(), limits, 32)?,
        PrefixPreparation::Contradicted
    ));
    Ok(())
}

#[test]
fn unfinished_prefix_observation_reports_the_transform_work_already_spent()
-> Result<(), Box<dyn Error>> {
    let mut bytes = vec![0xd2, 2, 0x11, 0x22, 0x57];
    bytes.extend([0x33; 64]);
    let samples = [sample(1, &bytes)];
    let limits = RelationalTransformLimits::default();
    let groups = group_sessions(&samples, limits, &mut || Ok(()))?;
    let PrefixPreparation::Ready(prepared) =
        prepare_candidate_prefix(&samples, &groups, &rule(), limits, 32)?
    else {
        return Err("the synthetic prefix should satisfy its selectors".into());
    };
    let PrefixAdmission::Ready(ready) = prepared.within_work_limit(67)? else {
        return Err("the transform should fit the allowance".into());
    };
    assert_eq!(
        score_prepared_candidate_prefix(&samples, ready, limits, 67)?,
        PrefixProbeOutcome::WorkLimited { work_bytes: 67 }
    );
    Ok(())
}

fn sample(sample: u64, bytes: &[u8]) -> RelationalRecordSample<'_> {
    RelationalRecordSample {
        sample,
        context: MessageContext {
            source: String::from("synthetic"),
            scope: String::from("stream"),
            session: 1,
            direction: Direction::FirstToSecond,
        },
        session_order: 1,
        bytes,
    }
}

fn rule() -> RelationalTransformRule {
    RelationalTransformRule {
        seed_locator: RelationalByteRangeLocator {
            coordinate_basis: RelationalCoordinateBasis::MessageStartV1,
            direction: Direction::FirstToSecond,
            marker_offset: 0,
            marker: vec![0xd2],
            value_offset: 2,
            value_length: Some(2),
            declared_length: Some(RelationalLengthField {
                offset: 1,
                width: CounterWidth::OneByte,
                byte_order: ByteOrder::BigEndian,
            }),
        },
        payload_locator: RelationalByteRangeLocator {
            coordinate_basis: RelationalCoordinateBasis::SeedRangeEndV1,
            direction: Direction::FirstToSecond,
            marker_offset: 0,
            marker: vec![0x57],
            value_offset: 1,
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
        parser_scope: RelationalParserScope::EachSession,
        parser_format: ArtifactValidationFormat::Der,
    }
}
