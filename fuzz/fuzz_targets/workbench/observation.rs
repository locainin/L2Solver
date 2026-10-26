use l2_workbench::evidence::{ByteMapping, EvidenceStatus, SourceRange};
use l2_workbench::measurement::{ByteOrder, LengthMeaning};
use l2_workbench::protocol::observation::{
    ConstraintOutcome, ObservationCoverage, ObservationInput, ObservationLimits, ObservationOrigin,
    ObservationPlan, ObservationProvenance, SampleRange, observe,
};
use l2_workbench::protocol::{
    ByteRange, Direction, FramingKind, MessageContext, MessageFamilyLimits, MessageRole,
    MessageSample, discover_message_families,
};

const SUPPORTED_SAMPLE_ID: u64 = 1;
const CONTRADICTED_SAMPLE_ID: u64 = 2;
const UNTESTABLE_SAMPLE_ID: u64 = 3;
const DERIVED_SAMPLE_ID: u64 = 4;
const OBSERVATION_SAMPLE_IDS: [u64; 8] = [
    SUPPORTED_SAMPLE_ID,
    CONTRADICTED_SAMPLE_ID,
    UNTESTABLE_SAMPLE_ID,
    DERIVED_SAMPLE_ID,
    5,
    6,
    7,
    8,
];
const FAMILY_SAMPLE_IDS: [u64; 8] = [101, 102, 103, 104, 105, 106, 107, 108];

pub(super) fn exercise(input: &[u8]) {
    let bounded = input.get(..input.len().min(32)).unwrap_or_default();
    exercise_observation(bounded);

    // Keep training and held-out samples explicit so unseen bytes cannot seed a family
    exercise_message_families(bounded);
}

fn exercise_observation(input: &[u8]) {
    let source = format!("capture-{:02x}", byte_at(input, 0));
    let other_source = format!("capture-{:02x}-other", byte_at(input, 1));
    let scope = format!("scope-{:02x}", byte_at(input, 2));
    let other_scope = format!("scope-{:02x}-other", byte_at(input, 3));

    // Fixed message lengths make supported, contradicted, and short-field cases reproducible
    let messages = vec![
        message_with_first(8, 8, input, 0),
        message_with_first(7, 8, input, 1),
        Vec::new(),
        message_with_first(byte_at(input, 4), 8, input, 2),
        message_with_first(8, 8, input, 3),
        message_with_first(8, 8, input, 4),
        message_with_first(8, 8, input, 5),
        message_with_first(8, 8, input, 6),
    ];

    // Session IDs differ while source, scope, and direction define comparison cohorts
    let contexts = vec![
        Some(message_context(
            &source,
            &scope,
            10,
            Direction::FirstToSecond,
        )),
        Some(message_context(
            &source,
            &scope,
            11,
            Direction::FirstToSecond,
        )),
        Some(message_context(
            &source,
            &scope,
            12,
            Direction::FirstToSecond,
        )),
        Some(message_context(
            &other_source,
            &scope,
            13,
            Direction::FirstToSecond,
        )),
        Some(message_context(
            &source,
            &other_scope,
            14,
            Direction::FirstToSecond,
        )),
        Some(message_context(
            &source,
            &scope,
            15,
            Direction::SecondToFirst,
        )),
        Some(message_context(
            &source,
            &scope,
            16,
            Direction::FirstToSecond,
        )),
        None,
    ];

    // Mappings include complete, absent, gapped, overlapping, and derived origins
    let mappings = vec![
        complete_mappings(&source, 1, 8),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        gapped_mappings(&source, 5),
        overlapping_mappings(&source, 6),
        complete_mappings(&source, 7, 8),
        Vec::new(),
    ];

    let derived_start = usize::from(byte_at(input, 5));
    let mut observations = Vec::with_capacity(messages.len());
    for (index, bytes) in messages.iter().enumerate() {
        let sample = OBSERVATION_SAMPLE_IDS
            .get(index)
            .copied()
            .unwrap_or_else(|| fail());
        let context = contexts.get(index).cloned().flatten();
        let message = MessageSample {
            sample,
            role: message_role(byte_at(input, index)),
            bytes,
            context,
        };

        // The empty message keeps literal provenance because byte ranges must be nonempty
        // Sample four uses a nonzero base to verify derived coordinate translation
        let provenance = match index {
            3 => ObservationProvenance::Derived {
                identity: "derived-view-v1",
                range: ByteRange {
                    start: derived_start,
                    end: derived_start + bytes.len(),
                },
            },
            _ => ObservationProvenance::Literal {
                mappings: mappings
                    .get(index)
                    .map_or(&[], |entries| entries.as_slice()),
            },
        };
        observations.push(ObservationInput {
            message,
            provenance,
        });
    }

    // Run normal, limited, and invalid range plans through the public analyzer
    exercise_observation_report(input, &observations);
    exercise_observation_limits(&observations);
    exercise_hostile_ranges(&observations);
}

fn exercise_observation_report(input: &[u8], observations: &[ObservationInput<'_>]) {
    let mut region_ranges = Vec::with_capacity(16);
    for sample in OBSERVATION_SAMPLE_IDS {
        // One-byte windows also request a safe but unavailable range from the empty message
        region_ranges.push(SampleRange {
            sample,
            range: ByteRange { start: 0, end: 1 },
        });
    }
    region_ranges.push(SampleRange {
        sample: SUPPORTED_SAMPLE_ID,
        range: ByteRange { start: 1, end: 3 },
    });
    region_ranges.push(SampleRange {
        sample: CONTRADICTED_SAMPLE_ID,
        range: ByteRange { start: 1, end: 3 },
    });
    region_ranges.push(SampleRange {
        sample: 5,
        range: ByteRange { start: 0, end: 5 },
    });
    region_ranges.push(SampleRange {
        sample: 6,
        range: ByteRange { start: 0, end: 8 },
    });
    let plan = ObservationPlan {
        region_ranges,
        ..ObservationPlan::default()
    };

    let report = match observe(observations, &plan) {
        Ok(report) => report,
        Err(_) => fail(),
    };
    assert_omissions_clear_incompleteness(&report.coverage);

    // The first byte is a length hypothesis in two complete messages and one empty message
    let supported = length_constraint(&report, SUPPORTED_SAMPLE_ID);
    require(supported.outcome == ConstraintOutcome::Supported);
    require(supported.expected == Some(8));
    require(supported.observed == Some(8));
    require(supported.semantic_status == EvidenceStatus::Hypothesis);

    let contradicted = length_constraint(&report, CONTRADICTED_SAMPLE_ID);
    require(contradicted.outcome == ConstraintOutcome::Contradicted);
    require(contradicted.expected == Some(8));
    require(contradicted.observed == Some(7));
    require(contradicted.semantic_status == EvidenceStatus::Hypothesis);

    let untestable = length_constraint(&report, UNTESTABLE_SAMPLE_ID);
    require(untestable.outcome == ConstraintOutcome::Untestable);
    require(untestable.observed.is_none());
    require(untestable.semantic_status == EvidenceStatus::Hypothesis);

    // Every retained semantic constraint stays a hypothesis with a consistent per-sample result
    for constraint in &report.partial_constraints {
        require(matches!(
            &constraint.hypothesis,
            FramingKind::LengthPrefix { .. }
        ));
        require(constraint.semantic_status == EvidenceStatus::Hypothesis);
        match constraint.outcome {
            ConstraintOutcome::Supported => {
                require(constraint.expected.is_some());
                require(constraint.expected == constraint.observed);
            }
            ConstraintOutcome::Contradicted => {
                require(constraint.expected.is_some());
                require(constraint.observed.is_some());
                require(constraint.expected != constraint.observed);
            }
            ConstraintOutcome::Untestable => require(constraint.observed.is_none()),
        }
    }

    // Missing provenance keeps raw facts visible without claiming a complete origin
    let missing_origin = report
        .byte_observations
        .iter()
        .find(|fact| {
            fact.sample == CONTRADICTED_SAMPLE_ID && fact.range == (ByteRange { start: 0, end: 1 })
        })
        .unwrap_or_else(|| fail());
    require(missing_origin.origins.is_empty());
    require(!missing_origin.origin_complete);

    // Derived ranges are relative to the input and keep their separate identity
    let derived = report
        .byte_observations
        .iter()
        .find(|fact| {
            fact.sample == DERIVED_SAMPLE_ID && fact.range == (ByteRange { start: 0, end: 1 })
        })
        .unwrap_or_else(|| fail());
    require(derived.origin_complete);
    require(matches!(
        derived.origins.first(),
        Some(ObservationOrigin::Derived { identity, range })
            if identity == "derived-view-v1"
                && range.start == usize::from(byte_at(input, 5))
                && range.end == usize::from(byte_at(input, 5)) + 1
    ));

    // A split literal mapping covers its selected bytes without merging source cohorts
    let literal = report
        .byte_observations
        .iter()
        .find(|fact| {
            fact.sample == SUPPORTED_SAMPLE_ID && fact.range == (ByteRange { start: 0, end: 1 })
        })
        .unwrap_or_else(|| fail());
    require(literal.origin_complete);
    require(!literal.origins.is_empty());

    // Gaps and overlapping source mappings cannot claim a complete literal origin
    let gapped = byte_observation(&report, 5, ByteRange { start: 0, end: 5 });
    let overlapping = byte_observation(&report, 6, ByteRange { start: 0, end: 8 });
    require(!gapped.origin_complete);
    require(!overlapping.origin_complete);

    // Region values point back to facts with the same exact range and full cohort
    for region in &report.regions {
        for value in &region.values {
            for observation_index in &value.observation_indices {
                let Some(fact) = report.byte_observations.get(*observation_index) else {
                    fail();
                };
                let Some(context) = fact.context.as_ref() else {
                    fail();
                };
                require(fact.range == region.range);
                require(fact.bytes == value.bytes);
                require(context.source == region.cohort.source);
                require(context.scope == region.cohort.scope);
                require(context.direction == region.cohort.direction);
            }
        }
    }
    require(report.coverage.untestable_region_occurrences > 0);
    require(report.coverage.unscoped_region_occurrences > 0);
}

fn exercise_observation_limits(observations: &[ObservationInput<'_>]) {
    // Restrict several budgets together so omission accounting must stay visible
    let limits = ObservationLimits {
        max_samples: 2,
        max_message_bytes: 8,
        max_total_bytes: 8,
        max_work_units: 64,
        max_byte_observations: 1,
        max_constraints: 1,
        max_region_ranges: 1,
        max_region_width: 1,
        max_region_values: 1,
        max_region_occurrences: 1,
        max_origin_ranges_per_observation: 1,
        max_report_bytes: 1_024,
        max_mappings_per_input: 1,
        ..ObservationLimits::default()
    };
    let plan = ObservationPlan {
        region_ranges: OBSERVATION_SAMPLE_IDS
            .iter()
            .map(|sample| SampleRange {
                sample: *sample,
                range: ByteRange { start: 0, end: 1 },
            })
            .collect(),
        limits,
    };
    let report = match observe(observations, &plan) {
        Ok(report) => report,
        Err(_) => fail(),
    };
    require(!report.coverage.complete);
    require(report.coverage.omitted_samples > 0);
    require(report.coverage.omitted_region_ranges > 0);
    assert_omissions_clear_incompleteness(&report.coverage);

    // A zero sample ceiling yields an explicit incomplete report
    let invalid_limits = ObservationLimits {
        max_samples: 0,
        ..ObservationLimits::default()
    };
    let zero_sample_report = match observe(
        observations,
        &ObservationPlan {
            limits: invalid_limits,
            ..ObservationPlan::default()
        },
    ) {
        Ok(report) => report,
        Err(_) => fail(),
    };
    require(zero_sample_report.coverage.samples_retained == 0);
    require(zero_sample_report.coverage.omitted_samples == observations.len());
    require(!zero_sample_report.coverage.complete);
}

fn exercise_hostile_ranges(observations: &[ObservationInput<'_>]) {
    // Reversed coordinates are rejected without slicing or panicking
    let reversed = ObservationPlan {
        region_ranges: vec![SampleRange {
            sample: SUPPORTED_SAMPLE_ID,
            range: ByteRange {
                start: usize::MAX,
                end: 0,
            },
        }],
        ..ObservationPlan::default()
    };
    require(observe(observations, &reversed).is_err());

    // Huge valid endpoints are retained as omitted evidence under the configured width cap
    let oversized = ObservationPlan {
        region_ranges: vec![SampleRange {
            sample: SUPPORTED_SAMPLE_ID,
            range: ByteRange {
                start: 0,
                end: usize::MAX,
            },
        }],
        ..ObservationPlan::default()
    };
    let report = match observe(observations, &oversized) {
        Ok(report) => report,
        Err(_) => fail(),
    };
    require(!report.coverage.complete);
    require(report.coverage.omitted_region_occurrences > 0);
}

fn exercise_message_families(input: &[u8]) {
    let first_value = byte_at(input, 0);
    let second_value = first_value.wrapping_add(1);
    let heldout_value = first_value.wrapping_add(2);
    let source = format!("family-source-{:02x}", byte_at(input, 2));
    let scope = format!("family-scope-{:02x}", byte_at(input, 3));
    let other_source = format!("family-other-{:02x}", byte_at(input, 4));

    // Two values recur in distinct training sessions; holdout includes one seen and one unseen value
    let message_bytes = vec![
        message_with_first(first_value, message_length(input, 0), input, 7),
        message_with_first(first_value, message_length(input, 1), input, 8),
        message_with_first(second_value, message_length(input, 2), input, 9),
        message_with_first(second_value, message_length(input, 3), input, 10),
        message_with_first(first_value, message_length(input, 4), input, 11),
        message_with_first(heldout_value, message_length(input, 5), input, 12),
        message_with_first(first_value, message_length(input, 6), input, 13),
        message_with_first(first_value, message_length(input, 7), input, 14),
    ];
    let mut samples = Vec::with_capacity(message_bytes.len());
    for (index, bytes) in message_bytes.iter().enumerate() {
        let sample = FAMILY_SAMPLE_IDS
            .get(index)
            .copied()
            .unwrap_or_else(|| fail());
        let session = 100 + u64::try_from(index).unwrap_or_else(|_| fail());
        let context = match index {
            6 => message_context(&other_source, &scope, session, Direction::FirstToSecond),
            7 => message_context(&source, &scope, session, Direction::SecondToFirst),
            _ => message_context(&source, &scope, session, Direction::FirstToSecond),
        };
        samples.push(MessageSample {
            sample,
            role: message_role(byte_at(input, index + 8)),
            bytes,
            context: Some(context),
        });
    }

    let limits = MessageFamilyLimits {
        max_samples: 16,
        max_message_bytes: 16,
        max_total_bytes: 128,
        max_selector_offset: 0,
        max_selector_width: 1,
        max_candidate_ranges: 16,
        max_selectors: 8,
        max_families_per_selector: 4,
        max_work_units: 8_192,
        max_report_bytes: 65_536,
        ..MessageFamilyLimits::default()
    };
    let report = match discover_message_families(&samples, &[101, 102, 103, 104], limits) {
        Ok(report) => report,
        Err(_) => fail(),
    };
    require(report.samples_seen == samples.len());
    require(report.training_samples == 4);
    require(report.heldout_samples == 4);

    let main_selector = report
        .selectors
        .iter()
        .find(|selector| {
            selector.range == (ByteRange { start: 0, end: 1 })
                && selector.cohort.source == source
                && selector.cohort.scope == scope
                && selector.cohort.direction == Direction::FirstToSecond
        })
        .unwrap_or_else(|| fail());
    let mut retained_first = false;
    let mut retained_second = false;
    for family in &main_selector.families {
        require(family.value.len() == 1);
        let Some(value) = family.value.first().copied() else {
            fail();
        };
        require(value != heldout_value);
        retained_first |= value == first_value;
        retained_second |= value == second_value;
        require(family.training_sessions.len() >= 2);
        require(
            family
                .training_samples
                .iter()
                .all(|sample| [101, 102, 103, 104].contains(sample)),
        );
        require(
            family
                .heldout_samples
                .iter()
                .all(|sample| [105, 106, 107, 108].contains(sample)),
        );
    }
    require(retained_first);
    require(retained_second);

    // A matching held-out value reuses training evidence; a new value stays unassigned
    let first_family = main_selector
        .families
        .iter()
        .find(|family| family.value.len() == 1 && family.value.first() == Some(&first_value))
        .unwrap_or_else(|| fail());
    require(first_family.heldout_samples.contains(&105));
    require(main_selector.unassigned.iter().any(|observation| {
        observation.sample == 106
            && observation.reason.as_str() == "unseen_value"
            && observation
                .value
                .as_ref()
                .is_some_and(|value| value.len() == 1 && value.first() == Some(&heldout_value))
    }));

    // Invalid limits remain an error and do not create unsupported family values
    let invalid_limits = MessageFamilyLimits {
        max_samples: 0,
        ..MessageFamilyLimits::default()
    };
    require(discover_message_families(&samples, &[101, 102, 103, 104], invalid_limits).is_err());
}

fn length_constraint(
    report: &l2_workbench::protocol::observation::ObservationReport,
    sample: u64,
) -> &l2_workbench::protocol::observation::PartialConstraint {
    report
        .partial_constraints
        .iter()
        .find(|constraint| {
            constraint.sample == sample
                && constraint.hypothesis
                    == (FramingKind::LengthPrefix {
                        offset: 0,
                        width: 1,
                        byte_order: ByteOrder::BigEndian,
                        meaning: LengthMeaning::WholeMessage,
                    })
        })
        .unwrap_or_else(|| fail())
}

fn byte_observation(
    report: &l2_workbench::protocol::observation::ObservationReport,
    sample: u64,
    range: ByteRange,
) -> &l2_workbench::protocol::observation::ByteObservation {
    report
        .byte_observations
        .iter()
        .find(|fact| fact.sample == sample && fact.range == range)
        .unwrap_or_else(|| fail())
}

fn assert_omissions_clear_incompleteness(coverage: &ObservationCoverage) {
    let omitted = coverage.omitted_samples > 0
        || coverage.input_bytes_unmeasured_samples > 0
        || coverage.omitted_input_bytes > 0
        || coverage.omitted_contexts > 0
        || coverage.omitted_context_bytes > 0
        || coverage.omitted_hypotheses > 0
        || coverage.omitted_integer_interpretations > 0
        || coverage.omitted_constraints > 0
        || coverage.omitted_byte_observations > 0
        || coverage.omitted_origins > 0
        || coverage.omitted_origin_checks > 0
        || coverage.omitted_region_ranges > 0
        || coverage.omitted_region_values > 0
        || coverage.omitted_region_occurrences > 0
        || coverage.omitted_work_units > 0;
    require(!omitted || !coverage.complete);
}

fn complete_mappings(source: &str, packet: u64, length: usize) -> Vec<ByteMapping> {
    if length == 0 {
        return Vec::new();
    }
    let split = length / 2;
    if split == 0 {
        return vec![mapping(0, source, packet, 0, length)];
    }
    vec![
        mapping(0, source, packet, 0, split),
        mapping(split, source, packet, split, length - split),
    ]
}

fn gapped_mappings(source: &str, packet: u64) -> Vec<ByteMapping> {
    vec![
        mapping(0, source, packet, 0, 2),
        mapping(3, source, packet, 3, 2),
    ]
}

fn overlapping_mappings(source: &str, packet: u64) -> Vec<ByteMapping> {
    vec![
        mapping(0, source, packet, 0, 5),
        mapping(4, source, packet, 4, 4),
    ]
}

fn mapping(
    output_offset: usize,
    source: &str,
    packet: u64,
    source_offset: usize,
    length: usize,
) -> ByteMapping {
    ByteMapping {
        offset: output_offset,
        range: SourceRange {
            source: source.to_owned(),
            packet: Some(packet),
            offset: u64::try_from(source_offset).unwrap_or_else(|_| fail()),
            length: u64::try_from(length).unwrap_or_else(|_| fail()),
        },
    }
}

fn message_with_first(first: u8, length: usize, input: &[u8], salt: usize) -> Vec<u8> {
    let length = length.min(8);
    let mut bytes = Vec::with_capacity(length);
    if length == 0 {
        return bytes;
    }
    bytes.push(first);
    for offset in 1..length {
        let entropy = input.get(offset + salt).copied().unwrap_or_default();
        let step = u8::try_from(offset).unwrap_or_else(|_| fail());
        bytes.push(first.wrapping_add(entropy).wrapping_add(step));
    }
    bytes
}

fn message_length(input: &[u8], index: usize) -> usize {
    1 + usize::from(byte_at(input, index + 16) % 8)
}

fn message_context(
    source: &str,
    scope: &str,
    session: u64,
    direction: Direction,
) -> MessageContext {
    MessageContext {
        source: source.to_owned(),
        scope: scope.to_owned(),
        session,
        direction,
    }
}

fn message_role(value: u8) -> MessageRole {
    match value % 3 {
        0 => MessageRole::Request,
        1 => MessageRole::Response,
        _ => MessageRole::Unclassified,
    }
}

fn byte_at(input: &[u8], index: usize) -> u8 {
    input.get(index).copied().unwrap_or_default()
}

fn require(condition: bool) {
    if !condition {
        fail();
    }
}

fn fail() -> ! {
    std::process::abort()
}
