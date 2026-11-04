use super::analyze::observe_regions;
use super::model::{
    ObservationInput, ObservationLimits, ObservationPlan, ObservationProvenance, SampleRange,
};
use super::{ObservationReport, observe};
use crate::protocol::{ByteRange, Direction, MessageContext, MessageRole, MessageSample};
use std::error::Error;

#[test]
fn region_only_pass_preserves_exact_values_and_derived_source_ranges() -> TestResult {
    let messages = [
        (1_u64, [0x10, 0x20, 0xaa, 0xbb, 0x30]),
        (2_u64, [0x40, 0x50, 0xaa, 0xbb, 0x60]),
    ];
    let identities = [String::from("derived-one"), String::from("derived-two")];
    let inputs = messages
        .iter()
        .zip(&identities)
        .map(|((session, bytes), identity)| ObservationInput {
            message: MessageSample {
                sample: *session,
                role: MessageRole::Unclassified,
                bytes,
                context: Some(context(*session)),
            },
            provenance: ObservationProvenance::Derived {
                identity,
                range: ByteRange {
                    start: 0,
                    end: bytes.len(),
                },
            },
        })
        .collect::<Vec<_>>();
    let plan = observation_plan(&messages, ObservationLimits::default());

    let full = observe(&inputs, &plan)?;
    let regions = observe_regions(&inputs, &plan)?;

    assert_eq!(region_values(&regions), region_values(&full));
    assert!(regions.coverage.complete);
    assert_eq!(regions.coverage.input_bytes_retained, 10);
    assert_eq!(regions.integer_interpretations.len(), 0);
    assert_eq!(regions.partial_constraints.len(), 0);
    assert_eq!(regions.byte_observations.len(), messages.len());
    for (index, byte_fact) in regions.byte_observations.iter().enumerate() {
        assert!(byte_fact.origin_complete);
        assert_eq!(byte_fact.range, ByteRange { start: 2, end: 4 });
        let source_identity = identities.get(index).ok_or("derived identity is missing")?;
        assert!(matches!(
            byte_fact.origins.first(),
            Some(super::model::ObservationOrigin::Derived { identity, range })
                if identity == source_identity && *range == byte_fact.range
        ));
    }
    Ok(())
}

#[test]
fn region_only_pass_keeps_sample_and_work_omissions_visible() -> TestResult {
    let first = [0x11, 0x22, 0xaa, 0xbb];
    let second = [0x33, 0x44, 0xaa, 0xbb];
    let identities = ["first", "second"];
    let inputs = [
        derived_input(1, &first, identities[0]),
        derived_input(2, &second, identities[1]),
    ];
    let plan = ObservationPlan {
        region_ranges: vec![
            SampleRange {
                sample: 1,
                range: ByteRange { start: 2, end: 4 },
            },
            SampleRange {
                sample: 2,
                range: ByteRange { start: 2, end: 4 },
            },
        ],
        limits: ObservationLimits {
            max_samples: 1,
            max_prefix_offset: 0,
            max_hypotheses: 0,
            max_work_units: 1,
            ..ObservationLimits::default()
        },
    };

    let report = observe_regions(&inputs, &plan)?;

    assert_eq!(report.coverage.samples_seen, 2);
    assert_eq!(report.coverage.samples_retained, 1);
    assert_eq!(report.coverage.omitted_samples, 1);
    assert!(report.coverage.work_units <= plan.limits.max_work_units);
    assert!(!report.coverage.complete);
    assert!(report.coverage.omitted_byte_observations > 0);
    let requested = report
        .regions
        .first()
        .ok_or("the bounded region receipt is missing")?;
    assert!(requested.coverage.omitted_occurrences > 0);
    Ok(())
}

type TestResult = Result<(), Box<dyn Error>>;

fn derived_input<'a>(sample: u64, bytes: &'a [u8], identity: &'a str) -> ObservationInput<'a> {
    ObservationInput {
        message: MessageSample {
            sample,
            role: MessageRole::Unclassified,
            bytes,
            context: Some(context(sample)),
        },
        provenance: ObservationProvenance::Derived {
            identity,
            range: ByteRange {
                start: 0,
                end: bytes.len(),
            },
        },
    }
}

fn context(session: u64) -> MessageContext {
    MessageContext {
        source: String::from("scope-source"),
        scope: String::from("tcp-stream"),
        session,
        direction: Direction::FirstToSecond,
    }
}

fn observation_plan(messages: &[(u64, [u8; 5])], limits: ObservationLimits) -> ObservationPlan {
    ObservationPlan {
        region_ranges: messages
            .iter()
            .map(|(sample, _)| SampleRange {
                sample: *sample,
                range: ByteRange { start: 2, end: 4 },
            })
            .collect(),
        limits: ObservationLimits {
            max_prefix_offset: 24,
            ..limits
        },
    }
}

fn region_values(report: &ObservationReport) -> Vec<(ByteRange, Vec<Vec<u8>>, usize, usize)> {
    report
        .regions
        .iter()
        .map(|region| {
            (
                region.range,
                region
                    .values
                    .iter()
                    .map(|value| value.bytes.clone())
                    .collect(),
                region.coverage.requested_occurrences,
                region.coverage.observed_occurrences,
            )
        })
        .collect()
}
