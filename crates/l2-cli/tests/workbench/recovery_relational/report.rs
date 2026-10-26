use super::candidate_json;
use l2_workbench::{
    artifact::ArtifactValidationFormat,
    derivation::{CounterByteOrder, CounterWidth, SeedCounterOrder},
    protocol::{
        Direction, RelationalByteRangeLocator, RelationalCoordinateBasis, RelationalCounterReset,
        RelationalFit, RelationalFitStatus, RelationalOperationTemplate, RelationalParserScope,
        RelationalSha256CounterXor, RelationalTransformCandidate, RelationalTransformRule,
        RelationalTransformStatus,
    },
};
use serde_json::json;

#[test]
fn candidate_summary_preserves_seed_relative_basis_without_raw_marker_bytes() {
    let candidate = RelationalTransformCandidate {
        rule: RelationalTransformRule {
            seed_locator: locator(RelationalCoordinateBasis::MessageStartV1, 6, vec![0xAA]),
            payload_locator: locator(
                RelationalCoordinateBasis::SeedRangeEndV1,
                11,
                vec![0xBB, 0xCC],
            ),
            operation: RelationalOperationTemplate::Sha256CounterXor(RelationalSha256CounterXor {
                initial_counter: 1,
                counter_width: CounterWidth::TwoBytes,
                counter_byte_order: CounterByteOrder::LittleEndian,
                seed_order: SeedCounterOrder::CounterThenSeed,
            }),
            counter_reset: RelationalCounterReset::Continuous,
            parser_scope: RelationalParserScope::AcrossSessions,
            parser_format: ArtifactValidationFormat::Zip,
        },
        discovery: empty_fit(),
        heldout: empty_fit(),
        status: RelationalTransformStatus::DiscoveryOnlyHypothesis,
    };

    let summary = candidate_json(&candidate);

    assert_eq!(
        summary.pointer("/rule/seed_locator/coordinate_basis"),
        Some(&json!("message_start_v1"))
    );
    assert_eq!(
        summary.pointer("/rule/payload_locator/coordinate_basis"),
        Some(&json!("seed_range_end_v1"))
    );
    assert_eq!(
        summary.pointer("/rule/payload_locator/value_offset"),
        Some(&json!(11))
    );
    assert_eq!(
        summary.pointer("/rule/payload_locator/marker_length"),
        Some(&json!(2))
    );
    assert!(summary.pointer("/rule/payload_locator/marker").is_none());
}

fn locator(
    coordinate_basis: RelationalCoordinateBasis,
    value_offset: usize,
    marker: Vec<u8>,
) -> RelationalByteRangeLocator {
    RelationalByteRangeLocator {
        coordinate_basis,
        direction: Direction::FirstToSecond,
        marker_offset: 3,
        marker,
        value_offset,
        value_length: None,
        declared_length: None,
    }
}

fn empty_fit() -> RelationalFit {
    RelationalFit {
        status: RelationalFitStatus::NotEvaluated,
        supported_sessions: Vec::new(),
        contradicted_sessions: Vec::new(),
        unresolved_sessions: Vec::new(),
        checks: Vec::new(),
    }
}
