#[path = "../fuzz_targets/workbench/relational_ranges.rs"]
mod relational_ranges;

use l2_workbench::{
    artifact::ArtifactValidationFormat,
    derivation::{CounterByteOrder, CounterWidth, SeedCounterOrder},
    protocol::{
        ByteOrder, Direction, MessageContext, RelationalByteRangeLocator,
        RelationalCoordinateBasis, RelationalCounterReset, RelationalLengthField,
        RelationalOperationTemplate, RelationalParserScope, RelationalRecordSample,
        RelationalSha256CounterXor, RelationalTransformRule,
    },
};

#[test]
fn seed_relative_payload_offsets_start_at_the_matched_seed_end() {
    let bytes = [0x04, 0x03, 0x01, 0x14, 0x04, 0x5e, 0xed, 0xec];
    let sample = RelationalRecordSample {
        sample: 1,
        context: MessageContext {
            source: "fixture".to_owned(),
            scope: "session".to_owned(),
            session: 1,
            direction: Direction::FirstToSecond,
        },
        session_order: 1,
        bytes: &bytes,
    };
    let seed = RelationalByteRangeLocator {
        coordinate_basis: RelationalCoordinateBasis::MessageStartV1,
        direction: Direction::FirstToSecond,
        marker_offset: 2,
        marker: vec![0x01],
        value_offset: 3,
        value_length: Some(1),
        declared_length: Some(RelationalLengthField {
            offset: 2,
            width: CounterWidth::OneByte,
            byte_order: ByteOrder::BigEndian,
        }),
    };
    let payload = RelationalByteRangeLocator {
        coordinate_basis: RelationalCoordinateBasis::SeedRangeEndV1,
        direction: Direction::FirstToSecond,
        marker_offset: 0,
        marker: vec![0x04],
        value_offset: 2,
        value_length: None,
        declared_length: None,
    };

    let seed_range =
        relational_ranges::value_range(&sample, &seed, 0).expect("seed range resolves");
    assert_eq!(seed_range, 3..4);
    assert!(relational_ranges::locator_matches(&sample, &seed, 0));

    let payload_range = relational_ranges::value_range(&sample, &payload, seed_range.end)
        .expect("payload range resolves from the seed end");
    assert_eq!(payload_range, 6..8);
    assert!(relational_ranges::locator_matches(
        &sample,
        &payload,
        seed_range.end
    ));

    let rule = RelationalTransformRule {
        seed_locator: seed,
        payload_locator: payload,
        operation: RelationalOperationTemplate::Sha256CounterXor(RelationalSha256CounterXor {
            initial_counter: 0,
            counter_width: CounterWidth::OneByte,
            counter_byte_order: CounterByteOrder::BigEndian,
            seed_order: SeedCounterOrder::SeedThenCounter,
        }),
        counter_reset: RelationalCounterReset::Continuous,
        parser_scope: RelationalParserScope::EachSession,
        parser_format: ArtifactValidationFormat::Der,
    };
    assert!(relational_ranges::candidate_ranges_are_valid(
        &[sample],
        &rule
    ));
}
