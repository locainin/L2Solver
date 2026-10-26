use l2_workbench::evidence::{ByteMapping, EvidenceStatus, SourceRange};
use l2_workbench::measurement::{ByteOrder, LengthMeaning};
use l2_workbench::protocol::observation::{
    ConstraintOutcome, ObservationInput, ObservationLimits, ObservationOrigin, ObservationPlan,
    ObservationProvenance, SampleRange, observe,
};
use l2_workbench::protocol::{
    ByteRange, Direction, FramingKind, MessageContext, MessageRole, MessageSample,
};
use std::error::Error;

#[test]
fn one_unsequenced_message_supports_a_length_hypothesis() -> Result<(), Box<dyn Error>> {
    let bytes = [4_u8, 0xaa, 0xbb, 0xcc];
    let inputs = [literal_input(7, &bytes, None)];

    let report = observe(&inputs, &ObservationPlan::default())?;
    let constraint = report
        .partial_constraints
        .iter()
        .find(|constraint| {
            constraint.hypothesis
                == length_hypothesis(0, 1, ByteOrder::BigEndian, LengthMeaning::WholeMessage)
        })
        .ok_or("one-byte whole-message hypothesis is missing")?;

    assert_eq!(constraint.sample, 7);
    assert_eq!(constraint.expected, Some(4));
    assert_eq!(constraint.observed, Some(4));
    assert_eq!(constraint.outcome, ConstraintOutcome::Supported);
    assert_eq!(constraint.semantic_status, EvidenceStatus::Hypothesis);
    assert_eq!(report.coverage.omitted_samples, 0);
    Ok(())
}

#[test]
fn contradictory_length_values_remain_visible_per_sample() -> Result<(), Box<dyn Error>> {
    let first = [4_u8, 0xaa, 0xbb, 0xcc];
    let second = [5_u8, 0x11, 0x22, 0x33];
    let inputs = [
        literal_input(1, &first, None),
        literal_input(2, &second, None),
    ];

    let report = observe(&inputs, &ObservationPlan::default())?;
    let outcomes = report
        .partial_constraints
        .iter()
        .filter(|constraint| {
            constraint.hypothesis
                == length_hypothesis(0, 1, ByteOrder::BigEndian, LengthMeaning::WholeMessage)
        })
        .map(|constraint| (constraint.sample, constraint.outcome))
        .collect::<Vec<_>>();

    assert_eq!(
        outcomes,
        [
            (1, ConstraintOutcome::Supported),
            (2, ConstraintOutcome::Contradicted),
        ]
    );
    Ok(())
}

#[test]
fn truncated_length_fields_are_untestable_not_contradicted() -> Result<(), Box<dyn Error>> {
    let bytes = [0x10_u8];
    let inputs = [literal_input(3, &bytes, None)];

    let report = observe(&inputs, &ObservationPlan::default())?;
    let constraint = report
        .partial_constraints
        .iter()
        .find(|constraint| {
            constraint.hypothesis
                == length_hypothesis(1, 2, ByteOrder::BigEndian, LengthMeaning::WholeMessage)
        })
        .ok_or("truncated two-byte length hypothesis is missing")?;

    assert_eq!(constraint.outcome, ConstraintOutcome::Untestable);
    assert_eq!(constraint.expected, None);
    assert_eq!(constraint.observed, None);
    assert_eq!(constraint.semantic_status, EvidenceStatus::Hypothesis);
    Ok(())
}

#[test]
fn sample_limit_reports_omissions_instead_of_a_complete_negative() -> Result<(), Box<dyn Error>> {
    let first = [4_u8, 0xaa, 0xbb, 0xcc];
    let second = [4_u8, 0x11, 0x22, 0x33];
    let inputs = [
        literal_input(1, &first, None),
        literal_input(2, &second, None),
    ];
    let plan = ObservationPlan {
        limits: ObservationLimits {
            max_samples: 1,
            ..ObservationLimits::default()
        },
        ..ObservationPlan::default()
    };

    let report = observe(&inputs, &plan)?;

    assert_eq!(report.coverage.samples_seen, 2);
    assert_eq!(report.coverage.samples_retained, 1);
    assert_eq!(report.coverage.omitted_samples, 1);
    assert!(!report.coverage.complete);
    let first_constraint = report
        .partial_constraints
        .first()
        .ok_or("first retained partial constraint is missing")?;
    assert_eq!(first_constraint.sample, 1);
    Ok(())
}

#[test]
fn copied_byte_ranges_consume_work_proportional_to_their_width() -> Result<(), Box<dyn Error>> {
    let bytes = [4_u8, 0xaa, 0xbb, 0xcc];
    let inputs = [literal_input(1, &bytes, None)];
    let plan = ObservationPlan {
        region_ranges: vec![SampleRange {
            sample: 1,
            range: range(0, 4),
        }],
        limits: ObservationLimits {
            max_prefix_offset: 0,
            max_hypotheses: 1,
            max_work_units: 2,
            ..ObservationLimits::default()
        },
    };

    let report = observe(&inputs, &plan)?;

    assert_eq!(report.coverage.work_units, 2);
    assert_eq!(report.byte_observations.len(), 1);
    assert!(report.coverage.omitted_byte_observations > 0);
    assert!(!report.coverage.complete);
    Ok(())
}

#[test]
fn copied_origin_identities_consume_work_and_can_be_omitted() -> Result<(), Box<dyn Error>> {
    let bytes = [4_u8];
    let mappings = [ByteMapping {
        offset: 0,
        range: SourceRange {
            source: "capture-name".to_owned(),
            packet: Some(1),
            offset: 100,
            length: 1,
        },
    }];
    let input = ObservationInput {
        message: MessageSample {
            sample: 1,
            role: MessageRole::Unclassified,
            bytes: &bytes,
            context: None,
        },
        provenance: ObservationProvenance::Literal {
            mappings: &mappings,
        },
    };
    let plan = ObservationPlan {
        limits: ObservationLimits {
            max_prefix_offset: 0,
            max_hypotheses: 1,
            max_work_units: 2,
            ..ObservationLimits::default()
        },
        ..ObservationPlan::default()
    };

    let report = observe(&[input], &plan)?;
    let byte_fact = report
        .byte_observations
        .first()
        .ok_or("the raw byte fact should fit the work budget")?;

    assert!(byte_fact.origins.is_empty());
    assert!(!byte_fact.origin_complete);
    assert!(report.coverage.omitted_origins > 0);
    Ok(())
}

#[test]
fn copied_region_values_consume_work_and_preserve_omission_counts() -> Result<(), Box<dyn Error>> {
    let bytes = [0x10_u8, 0x20];
    let inputs = [literal_input(1, &bytes, Some(context("capture-a", 1)))];
    let plan = ObservationPlan {
        region_ranges: vec![SampleRange {
            sample: 1,
            range: range(0, 1),
        }],
        limits: ObservationLimits {
            max_prefix_offset: 0,
            max_hypotheses: 0,
            max_work_units: 2,
            ..ObservationLimits::default()
        },
    };

    let report = observe(&inputs, &plan)?;
    let region = report
        .regions
        .first()
        .ok_or("the requested comparison region should be retained")?;

    assert!(region.values.is_empty());
    assert_eq!(region.coverage.omitted_occurrences, 1);
    assert_eq!(report.coverage.omitted_region_values, 1);
    assert!(!report.coverage.complete);
    Ok(())
}

#[test]
fn alternate_values_keep_separate_sample_occurrences() -> Result<(), Box<dyn Error>> {
    let first = [0x10_u8, 0x20];
    let second = [0x11_u8, 0x30];
    let inputs = [
        literal_input(1, &first, Some(context("capture-a", 1))),
        literal_input(2, &second, Some(context("capture-a", 2))),
    ];
    let plan = ObservationPlan {
        region_ranges: vec![
            SampleRange {
                sample: 1,
                range: range(0, 1),
            },
            SampleRange {
                sample: 2,
                range: range(0, 1),
            },
        ],
        limits: ObservationLimits {
            max_prefix_offset: 0,
            max_hypotheses: 0,
            ..ObservationLimits::default()
        },
    };

    let report = observe(&inputs, &plan)?;
    let region = report
        .regions
        .first()
        .ok_or("the requested comparison region should be retained")?;

    assert_eq!(region.values.len(), 2);
    assert_eq!(region.coverage.observed_occurrences, 2);
    assert_eq!(
        region.values.first().map(|value| value.bytes.as_slice()),
        Some([0x10].as_slice())
    );
    assert_eq!(
        region.values.get(1).map(|value| value.bytes.as_slice()),
        Some([0x11].as_slice())
    );
    Ok(())
}

#[test]
fn duplicate_identifiers_in_the_considered_window_are_rejected() {
    let first = [4_u8, 0xaa, 0xbb, 0xcc];
    let oversized = [4_u8, 0x11, 0x22, 0x33, 0x44];
    let inputs = [
        literal_input(9, &first, None),
        literal_input(9, &oversized, None),
    ];
    let plan = ObservationPlan {
        limits: ObservationLimits {
            max_message_bytes: 4,
            ..ObservationLimits::default()
        },
        ..ObservationPlan::default()
    };

    let result = observe(&inputs, &plan);

    assert!(matches!(
        result,
        Err(l2_workbench::protocol::observation::ObservationError::DuplicateSample { sample: 9 })
    ));
}

#[test]
fn cohorts_merge_sessions_but_keep_source_and_full_occurrence_context() -> Result<(), Box<dyn Error>>
{
    let bytes = [0x10_u8, 0x20, 0x30];
    let inputs = [
        literal_input(1, &bytes, Some(context("capture-a", 10))),
        literal_input(2, &bytes, Some(context("capture-a", 11))),
        literal_input(3, &bytes, Some(context("capture-b", 10))),
    ];
    let plan = ObservationPlan {
        region_ranges: vec![
            SampleRange {
                sample: 1,
                range: range(0, 2),
            },
            SampleRange {
                sample: 2,
                range: range(0, 2),
            },
            SampleRange {
                sample: 3,
                range: range(0, 2),
            },
        ],
        ..ObservationPlan::default()
    };

    let report = observe(&inputs, &plan)?;
    let capture_a = report
        .regions
        .iter()
        .find(|region| region.cohort.source == "capture-a")
        .ok_or("first source cohort is missing")?;
    let capture_b = report
        .regions
        .iter()
        .find(|region| region.cohort.source == "capture-b")
        .ok_or("second source cohort is missing")?;
    let repeated = capture_a
        .values
        .iter()
        .find(|value| value.bytes == [0x10, 0x20])
        .ok_or("repeated first-source value is missing")?;
    let singleton = capture_b
        .values
        .iter()
        .find(|value| value.bytes == [0x10, 0x20])
        .ok_or("second-source singleton is missing")?;

    assert_eq!(capture_a.cohort.direction, Direction::FirstToSecond);
    assert_eq!(capture_a.range, range(0, 2));
    assert_eq!(repeated.observation_indices.len(), 2);
    assert_eq!(singleton.observation_indices.len(), 1);
    let first_index = *repeated
        .observation_indices
        .first()
        .ok_or("first repeated observation index is missing")?;
    let second_index = *repeated
        .observation_indices
        .get(1)
        .ok_or("second repeated observation index is missing")?;
    let first_observation = report
        .byte_observations
        .get(first_index)
        .ok_or("first repeated byte observation is missing")?;
    assert_eq!(first_observation.sample, 1);
    assert_eq!(
        first_observation.context.as_ref().map(|c| c.session),
        Some(10)
    );
    let second_observation = report
        .byte_observations
        .get(second_index)
        .ok_or("second repeated byte observation is missing")?;
    assert_eq!(second_observation.sample, 2);
    assert_eq!(
        second_observation.context.as_ref().map(|c| c.session),
        Some(11)
    );
    assert_eq!(report.coverage.unscoped_region_occurrences, 0);
    Ok(())
}

#[test]
fn literal_and_derived_origins_keep_their_distinct_coordinate_systems() -> Result<(), Box<dyn Error>>
{
    let bytes = [1_u8, 2, 3, 4];
    let literal_mappings = [ByteMapping {
        offset: 0,
        range: SourceRange {
            source: "capture".to_owned(),
            packet: Some(3),
            offset: 100,
            length: u64::try_from(bytes.len())?,
        },
    }];
    let literal = ObservationInput {
        message: MessageSample {
            sample: 1,
            role: MessageRole::Unclassified,
            bytes: &bytes,
            context: None,
        },
        provenance: ObservationProvenance::Literal {
            mappings: &literal_mappings,
        },
    };
    let derived = ObservationInput {
        message: MessageSample {
            sample: 2,
            role: MessageRole::Unclassified,
            bytes: &bytes,
            context: None,
        },
        provenance: ObservationProvenance::Derived {
            identity: "decoded-view-v1",
            range: range(40, 44),
        },
    };
    let plan = ObservationPlan {
        region_ranges: vec![
            SampleRange {
                sample: 1,
                range: range(2, 4),
            },
            SampleRange {
                sample: 2,
                range: range(2, 4),
            },
        ],
        ..ObservationPlan::default()
    };

    let report = observe(&[literal, derived], &plan)?;
    let literal_fact = report
        .byte_observations
        .iter()
        .find(|fact| fact.sample == 1 && fact.range == range(2, 4))
        .ok_or("literal range observation is missing")?;
    let derived_fact = report
        .byte_observations
        .iter()
        .find(|fact| fact.sample == 2 && fact.range == range(2, 4))
        .ok_or("derived range observation is missing")?;

    assert_eq!(
        literal_fact.origins,
        [ObservationOrigin::Literal(SourceRange {
            source: "capture".to_owned(),
            packet: Some(3),
            offset: 102,
            length: 2,
        })]
    );
    assert_eq!(
        derived_fact.origins,
        [ObservationOrigin::Derived {
            identity: "decoded-view-v1".to_owned(),
            range: range(42, 44),
        }]
    );
    assert!(literal_fact.origin_complete);
    assert!(derived_fact.origin_complete);
    Ok(())
}

#[test]
fn length_hypotheses_use_canonical_offset_width_and_meaning_order() -> Result<(), Box<dyn Error>> {
    let bytes = [0_u8; 8];
    let inputs = [literal_input(1, &bytes, None)];

    let report = observe(&inputs, &ObservationPlan::default())?;
    let first = report
        .partial_constraints
        .first()
        .ok_or("first canonical length hypothesis is missing")?;
    let second = report
        .partial_constraints
        .get(1)
        .ok_or("second canonical length hypothesis is missing")?;
    let third = report
        .partial_constraints
        .get(2)
        .ok_or("third canonical length hypothesis is missing")?;

    assert_eq!(
        first.hypothesis,
        length_hypothesis(0, 1, ByteOrder::BigEndian, LengthMeaning::WholeMessage)
    );
    assert_eq!(
        second.hypothesis,
        length_hypothesis(0, 1, ByteOrder::BigEndian, LengthMeaning::BytesAfterField)
    );
    assert_eq!(
        third.hypothesis,
        length_hypothesis(0, 2, ByteOrder::BigEndian, LengthMeaning::WholeMessage)
    );
    Ok(())
}

fn literal_input(
    sample: u64,
    bytes: &[u8],
    context: Option<MessageContext>,
) -> ObservationInput<'_> {
    ObservationInput {
        message: MessageSample {
            sample,
            role: MessageRole::Unclassified,
            bytes,
            context,
        },
        provenance: ObservationProvenance::Literal { mappings: &[] },
    }
}

fn context(source: &str, session: u64) -> MessageContext {
    MessageContext {
        source: source.to_owned(),
        scope: "tcp".to_owned(),
        session,
        direction: Direction::FirstToSecond,
    }
}

fn range(start: usize, end: usize) -> ByteRange {
    ByteRange { start, end }
}

fn length_hypothesis(
    offset: usize,
    width: usize,
    byte_order: ByteOrder,
    meaning: LengthMeaning,
) -> FramingKind {
    FramingKind::LengthPrefix {
        offset,
        width,
        byte_order,
        meaning,
    }
}
