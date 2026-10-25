use super::support::{calibration, event};
use l2_workbench::identity::{
    ComparisonRequest, CorrelationOptions, CorrelationPlan, TimeRelation, correlate, event_identity,
};
use std::error::Error;

#[test]
fn unrelated_clock_order() -> Result<(), Box<dyn Error>> {
    let a = event("capture-a", "vlan-7", 3);
    let b = event("capture-b", "vlan-7", 20);
    let plan = CorrelationPlan {
        comparisons: vec![ComparisonRequest {
            left_event: event_identity(&a)?,
            right_event: event_identity(&b)?,
            clock: "capture-b:clock".into(),
        }],
        ..CorrelationPlan::default()
    };
    let report = correlate(&[a, b], &plan, CorrelationOptions::default())?;
    assert_eq!(
        report
            .comparisons
            .first()
            .ok_or("missing comparison")?
            .relation,
        TimeRelation::Unmapped
    );
    Ok(())
}

#[test]
fn calibration_uncertainty_changes_order() -> Result<(), Box<dyn Error>> {
    let a = event("capture-a", "vlan-7", 3);
    let b = event("capture-b", "vlan-7", 20);
    let mut plan = CorrelationPlan {
        calibrations: vec![calibration("matched-clock", 10, 2)],
        comparisons: vec![ComparisonRequest {
            left_event: event_identity(&a)?,
            right_event: event_identity(&b)?,
            clock: "capture-b:clock".into(),
        }],
        ..CorrelationPlan::default()
    };
    let report = correlate(
        &[a.clone(), b.clone()],
        &plan,
        CorrelationOptions::default(),
    )?;
    assert_eq!(
        report
            .comparisons
            .first()
            .ok_or("missing comparison")?
            .relation,
        TimeRelation::Before
    );
    plan.calibrations
        .first_mut()
        .ok_or("missing calibration")?
        .uncertainty_ticks = 10;
    let report = correlate(&[a, b], &plan, CorrelationOptions::default())?;
    assert_eq!(
        report
            .comparisons
            .first()
            .ok_or("missing comparison")?
            .relation,
        TimeRelation::Overlapping
    );
    Ok(())
}

#[test]
fn competing_calibrations_preserve_incompatible_orderings() -> Result<(), Box<dyn Error>> {
    let a = event("capture-a", "vlan-7", 3);
    let b = event("capture-b", "vlan-7", 20);
    let plan = CorrelationPlan {
        calibrations: vec![calibration("first", 0, 0), calibration("second", 30, 0)],
        comparisons: vec![ComparisonRequest {
            left_event: event_identity(&a)?,
            right_event: event_identity(&b)?,
            clock: "capture-b:clock".into(),
        }],
        ..CorrelationPlan::default()
    };
    let report = correlate(&[a, b], &plan, CorrelationOptions::default())?;
    assert_eq!(
        report
            .comparisons
            .first()
            .ok_or("missing comparison")?
            .relation,
        TimeRelation::AmbiguousCalibration
    );
    Ok(())
}

#[test]
fn negative_fractional_deltas_round_outward() -> Result<(), Box<dyn Error>> {
    let a = event("capture-a", "vlan-7", 3);
    let b = event("capture-b", "vlan-7", 10);
    let mut mapping = calibration("rate", 10, 0);
    mapping.anchor_from = 4;
    mapping.numerator = 1;
    mapping.denominator = 2;
    let plan = CorrelationPlan {
        calibrations: vec![mapping],
        comparisons: vec![ComparisonRequest {
            left_event: event_identity(&a)?,
            right_event: event_identity(&b)?,
            clock: "capture-b:clock".into(),
        }],
        ..CorrelationPlan::default()
    };
    let report = correlate(&[a, b], &plan, CorrelationOptions::default())?;
    let interval = report
        .events
        .first()
        .ok_or("missing event")?
        .times
        .iter()
        .find(|v| v.clock == "capture-b:clock")
        .ok_or("missing mapped clock")?;
    assert_eq!((interval.earliest, interval.latest), (9, 10));
    assert_eq!(
        report
            .comparisons
            .first()
            .ok_or("missing comparison")?
            .relation,
        TimeRelation::Overlapping
    );
    Ok(())
}

#[test]
fn zero_denominator_calibration_rejected() {
    let mut mapping = calibration("invalid", 10, 0);
    mapping.denominator = 0;
    let plan = CorrelationPlan {
        calibrations: vec![mapping],
        ..CorrelationPlan::default()
    };
    assert!(correlate(&[], &plan, CorrelationOptions::default()).is_err());
}

#[test]
fn expired_calibration_leaves_event_unmapped() -> Result<(), Box<dyn Error>> {
    let a = event("capture-a", "vlan-7", 3);
    let mut mapping = calibration("expired", 10, 0);
    mapping.valid_through = Some(2);
    let plan = CorrelationPlan {
        calibrations: vec![mapping],
        ..CorrelationPlan::default()
    };
    let report = correlate(&[a], &plan, CorrelationOptions::default())?;
    assert_eq!(report.events.first().ok_or("missing event")?.times.len(), 1);
    Ok(())
}

#[test]
fn calibration_maps_only_valid_ticks() -> Result<(), Box<dyn Error>> {
    let events = [
        event("capture-a", "lan", 2),
        event("capture-a", "lan", 3),
        event("capture-a", "lan", 4),
    ];
    let mut mapping = calibration("single-tick", 10, 0);
    mapping.valid_from = 3;
    mapping.valid_through = Some(3);
    let plan = CorrelationPlan {
        calibrations: vec![mapping],
        ..CorrelationPlan::default()
    };
    let report = correlate(&events, &plan, CorrelationOptions::default())?;
    assert_eq!(
        report
            .events
            .iter()
            .map(|event| event.times.len())
            .collect::<Vec<_>>(),
        [1, 2, 1]
    );
    let mapped = report
        .events
        .get(1)
        .ok_or("missing boundary event")?
        .times
        .iter()
        .find(|time| time.calibration_id.as_deref() == Some("single-tick"))
        .ok_or("valid boundary was not mapped")?;
    assert_eq!((mapped.earliest, mapped.latest), (13, 13));
    Ok(())
}

#[test]
fn clock_overflow_ticks_decimal_strings() -> Result<(), Box<dyn Error>> {
    let a = event("capture-a", "vlan-7", u64::MAX);
    let mut mapping = calibration("large", 0, 0);
    mapping.valid_through = None;
    mapping.numerator = u64::MAX;
    let mut plan = CorrelationPlan {
        calibrations: vec![mapping],
        ..CorrelationPlan::default()
    };
    assert!(
        correlate(
            std::slice::from_ref(&a),
            &plan,
            CorrelationOptions::default()
        )
        .is_err()
    );
    plan.calibrations.clear();
    let report = correlate(&[a], &plan, CorrelationOptions::default())?;
    let json = serde_json::to_value(&report)?;
    assert_eq!(
        json.pointer("/events/0/times/0/earliest"),
        Some(&serde_json::Value::String(u64::MAX.to_string()))
    );
    Ok(())
}

#[test]
fn calibration_without_supporting_evidence_rejected() {
    let mut mapping = calibration("unsupported", 10, 0);
    mapping.evidence.clear();
    let plan = CorrelationPlan {
        calibrations: vec![mapping],
        ..CorrelationPlan::default()
    };
    assert!(correlate(&[], &plan, CorrelationOptions::default()).is_err());
}

#[test]
fn same_clock_event_overlap() -> Result<(), Box<dyn Error>> {
    let later = event("capture-a", "lan", 20);
    let earlier = event("capture-a", "lan", 10);
    let mut equal = event("capture-a", "lan", 30);
    equal.ticks = Some(10);
    let right_event = event_identity(&earlier)?;
    let plan = CorrelationPlan {
        comparisons: [event_identity(&later)?, event_identity(&equal)?]
            .into_iter()
            .map(|left_event| ComparisonRequest {
                left_event,
                right_event: right_event.clone(),
                clock: "capture-a:clock".into(),
            })
            .collect(),
        ..CorrelationPlan::default()
    };
    let report = correlate(
        &[later, earlier, equal],
        &plan,
        CorrelationOptions::default(),
    )?;
    assert_eq!(
        report
            .comparisons
            .iter()
            .map(|comparison| comparison.relation)
            .collect::<Vec<_>>(),
        [TimeRelation::After, TimeRelation::Overlapping]
    );
    Ok(())
}
