use l2_workbench::protocol::{
    Direction, MessageContext, MessageFamily, MessageFamilyLimits, MessageFamilySelector,
    MessageRole, MessageSample, UnassignedFamilyObservation, discover_message_families,
};
use std::error::Error;
use std::mem::size_of;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn family_discovery_keeps_region_facts_without_unrelated_length_analysis() -> TestResult {
    let samples = [
        sample(1, &[b'A', 1, 2, 3], 10),
        sample(2, &[b'A', 2, 3, 4], 11),
        sample(3, &[b'B', 3, 4, 5], 12),
        sample(4, &[b'B', 4, 5, 6], 13),
    ];
    let report = discover_message_families(&samples, &[1, 2, 3, 4], limits())?;
    assert!(
        report
            .selectors
            .iter()
            .any(|selector| selector.families.len() == 2)
    );
    assert_ne!(report.observations.byte_observations.len(), 0);
    assert_eq!(report.observations.integer_interpretations.len(), 0);
    assert_eq!(report.observations.partial_constraints.len(), 0);
    Ok(())
}

#[test]
fn report_budget_preserves_complete_selector_regions_and_reports_unexamined_ranges() -> TestResult {
    let mut bytes = Vec::new();
    for index in 0..16_u8 {
        let mut message = [0_u8; 22];
        message[0] = index.wrapping_mul(7);
        message[1] = index.wrapping_mul(11);
        message[2] = if index.is_multiple_of(2) { 0x39 } else { 0xc5 };
        for (offset, byte) in message.iter_mut().enumerate().skip(3) {
            *byte = index.wrapping_mul(17).wrapping_add(u8::try_from(offset)?);
        }
        bytes.push(message);
    }
    let samples = bytes
        .iter()
        .enumerate()
        .map(|(index, bytes)| -> Result<_, Box<dyn Error>> {
            let mut value = sample(
                u64::try_from(index + 1)?,
                bytes,
                u64::try_from(index / 4 + 1)?,
            );
            if let Some(context) = &mut value.context {
                context.source = format!("sha256:{}", "a".repeat(64));
                context.scope = "shared capture scope".to_owned();
            }
            Ok(value)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let training = (1..=8).collect::<Vec<u64>>();
    let limits = MessageFamilyLimits {
        max_selector_offset: 15,
        max_selector_width: 4,
        max_selectors: 8,
        max_families_per_selector: 4,
        max_report_bytes: 512 * 1024,
        ..MessageFamilyLimits::default()
    };
    let report = discover_message_families(&samples, &training, limits)?;
    assert!(
        report
            .selectors
            .iter()
            .any(|selector| selector.range.start == 2
                && selector.range.end == 3
                && selector.families.len() == 2)
    );
    assert!(report.omitted_report_budget_ranges > 0);
    assert!(!report.complete);
    assert!(report.report_bytes_retained <= limits.max_report_bytes);
    Ok(())
}

#[test]
fn families_use_repeated_training_values_and_do_not_learn_from_holdout() -> TestResult {
    let samples = [
        sample(1, &[b'A', 1], 10),
        sample(2, &[b'A', 2], 11),
        sample(3, &[b'B', 3], 12),
        sample(4, &[b'B', 4], 13),
        sample(5, &[b'A', 5], 14),
        sample(6, &[b'C', 6], 15),
    ];
    let report = discover_message_families(&samples, &[1, 2, 3, 4], limits())?;

    let selector = report
        .selectors
        .iter()
        .find(|selector| selector.range.start == 0 && selector.range.end == 1)
        .ok_or("expected a selector at the first byte")?;
    assert_eq!(selector.families.len(), 2);
    let family_a = selector
        .families
        .first()
        .ok_or("first family was not retained")?;
    let family_b = selector
        .families
        .get(1)
        .ok_or("second family was not retained")?;
    assert_eq!(family_a.value, b"A");
    assert_eq!(family_a.training_samples, [1, 2]);
    assert_eq!(family_a.heldout_samples, [5]);
    assert_eq!(family_b.value, b"B");
    assert_eq!(family_b.training_samples, [3, 4]);
    assert_eq!(family_b.heldout_samples.len(), 0);
    assert!(
        selector
            .unassigned
            .iter()
            .any(|sample| { sample.sample == 6 && sample.reason.as_str() == "unseen_value" })
    );
    assert_eq!(report.training_samples, 4);
    assert_eq!(report.heldout_samples, 2);
    Ok(())
}

#[test]
fn one_off_training_values_are_not_retained_as_family_types() -> TestResult {
    let samples = [
        sample(1, b"A", 10),
        sample(2, b"B", 11),
        sample(3, b"C", 12),
    ];
    let report = discover_message_families(&samples, &[1, 2, 3], limits())?;

    assert_eq!(report.selectors.len(), 0);
    assert_eq!(report.training_samples, 3);
    assert_eq!(report.heldout_samples, 0);
    let mut observed_samples = report
        .observations
        .byte_observations
        .iter()
        .map(|observation| observation.sample)
        .collect::<Vec<_>>();
    observed_samples.sort_unstable();
    assert_eq!(observed_samples, [1, 2, 3]);
    Ok(())
}

#[test]
fn selector_values_stay_inside_their_source_scope_and_direction_cohort() -> TestResult {
    let mut samples = [
        sample(1, b"A", 10),
        sample(2, b"A", 11),
        sample(3, b"A", 12),
        sample(4, b"A", 13),
    ];
    samples
        .get_mut(2)
        .and_then(|sample| sample.context.as_mut())
        .ok_or("context missing")?
        .source = "other".to_owned();
    samples
        .get_mut(3)
        .and_then(|sample| sample.context.as_mut())
        .ok_or("context missing")?
        .direction = Direction::SecondToFirst;
    let report = discover_message_families(&samples, &[1, 2, 3, 4], limits())?;

    assert_eq!(report.selectors.len(), 1);
    let selector = report
        .selectors
        .first()
        .ok_or("supported cohort is missing")?;
    let family = selector
        .families
        .first()
        .ok_or("supported family is missing")?;
    assert_eq!(family.training_samples, [1, 2]);
    Ok(())
}

#[test]
fn retained_unassigned_values_are_included_in_report_byte_accounting() -> TestResult {
    let samples = [
        sample(1, b"A", 10),
        sample(2, b"A", 11),
        sample(3, b"B", 12),
        sample(4, b"B", 13),
        sample(5, b"A", 14),
        sample(6, b"C", 15),
    ];
    let report = discover_message_families(&samples, &[1, 2, 3, 4], limits())?;

    let unassigned_value_bytes = report
        .selectors
        .iter()
        .flat_map(|selector| &selector.unassigned)
        .filter_map(|observation| observation.value.as_ref())
        .map(Vec::len)
        .sum::<usize>();
    assert!(unassigned_value_bytes > 0);
    assert_eq!(
        report.report_bytes_retained,
        report.observations.coverage.report_bytes_retained
            + report
                .selectors
                .iter()
                .map(logical_selector_bytes)
                .sum::<usize>()
    );
    Ok(())
}

#[test]
fn report_accounting_respects_the_exact_and_one_byte_short_budget() -> TestResult {
    let samples = [
        sample(1, b"A", 10),
        sample(2, b"A", 11),
        sample(3, b"B", 12),
        sample(4, b"B", 13),
        sample(5, b"A", 14),
        sample(6, b"C", 15),
    ];
    let baseline = discover_message_families(&samples, &[1, 2, 3, 4], limits())?;
    let report_bytes = baseline.observations.coverage.report_bytes_retained
        + baseline
            .selectors
            .iter()
            .map(logical_selector_bytes)
            .sum::<usize>();
    let exact_budget = report_bytes.max(
        baseline
            .observations
            .coverage
            .report_bytes_retained
            .saturating_mul(2),
    );
    let exact_limits = MessageFamilyLimits {
        max_report_bytes: exact_budget,
        ..limits()
    };
    let exact = discover_message_families(&samples, &[1, 2, 3, 4], exact_limits)?;
    assert!(exact.complete);
    assert_eq!(exact.report_bytes_retained, report_bytes);

    let short_limits = MessageFamilyLimits {
        max_report_bytes: exact_budget - 1,
        ..limits()
    };
    let short = discover_message_families(&samples, &[1, 2, 3, 4], short_limits)?;
    assert!(!short.complete);
    assert!(short.report_bytes_retained <= short_limits.max_report_bytes);
    Ok(())
}

#[test]
fn omitted_supported_families_make_the_report_incomplete() -> TestResult {
    let samples = [
        sample(1, b"A", 10),
        sample(2, b"A", 11),
        sample(3, b"B", 12),
        sample(4, b"B", 13),
    ];
    let limits = MessageFamilyLimits {
        max_families_per_selector: 1,
        ..limits()
    };
    let report = discover_message_families(&samples, &[1, 2, 3, 4], limits)?;

    let selector = report
        .selectors
        .first()
        .ok_or("expected a retained selector")?;
    assert_eq!(selector.omitted_families, 1);
    assert!(!report.complete);
    Ok(())
}

fn logical_selector_bytes(selector: &MessageFamilySelector) -> usize {
    let base = size_of::<MessageFamilySelector>()
        + selector.cohort.source.len()
        + selector.cohort.scope.len()
        + selector.families.len() * size_of::<MessageFamily>()
        + selector.unassigned.len() * size_of::<UnassignedFamilyObservation>();
    let family_bytes = selector
        .families
        .iter()
        .map(|family| {
            family.value.len()
                + (family.training_samples.len()
                    + family.training_sessions.len()
                    + family.heldout_samples.len()
                    + family.heldout_sessions.len())
                    * size_of::<u64>()
                + (family.training_observation_indices.len()
                    + family.heldout_observation_indices.len())
                    * size_of::<usize>()
        })
        .sum::<usize>();
    let unassigned_value_bytes = selector
        .unassigned
        .iter()
        .filter_map(|observation| observation.value.as_ref())
        .map(Vec::len)
        .sum::<usize>();

    base + family_bytes + unassigned_value_bytes
}

fn sample(id: u64, bytes: &[u8], session: u64) -> MessageSample<'_> {
    MessageSample {
        sample: id,
        role: MessageRole::Unclassified,
        bytes,
        context: Some(MessageContext {
            source: "source-a".to_owned(),
            scope: "scope-a".to_owned(),
            session,
            direction: Direction::FirstToSecond,
        }),
    }
}

fn limits() -> MessageFamilyLimits {
    MessageFamilyLimits {
        max_selector_offset: 0,
        max_selector_width: 1,
        ..MessageFamilyLimits::default()
    }
}
