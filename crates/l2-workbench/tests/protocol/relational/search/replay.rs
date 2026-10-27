use super::{
    RelationalByteRangeLocator, RelationalCoordinateBasis, RelationalCounterReset,
    RelationalLengthField, RelationalOperationTemplate, RelationalParserScope,
    RelationalRecordSample, RelationalSha256CounterXor, RelationalTransformLimits,
    RelationalTransformRule, group_sessions, prepare_candidate_prefix, transform_prepared_prefix,
};
use crate::artifact::ArtifactValidationFormat;
use crate::derivation::{CounterByteOrder, CounterWidth, SeedCounterOrder};
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
    let groups = group_sessions(&samples, limits)?;
    let rule = rule();
    let prepared = prepare_candidate_prefix(&samples, &groups, &rule, limits, 32)?
        .ok_or("the synthetic prefix should satisfy its selectors")?;

    assert!(prepared.within_work_limit(66)?.is_none());

    let prepared = prepare_candidate_prefix(&samples, &groups, &rule, limits, 32)?
        .ok_or("the synthetic prefix should satisfy its selectors")?;
    let ready = prepared
        .within_work_limit(67)?
        .ok_or("the exact transform allowance should admit the prefix")?;
    let output = transform_prepared_prefix(&samples, ready)?
        .ok_or("the admitted prefix should transform")?;
    assert_eq!(output.work_bytes, 67);
    assert_eq!(output.messages.len(), 1);
    Ok(())
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
