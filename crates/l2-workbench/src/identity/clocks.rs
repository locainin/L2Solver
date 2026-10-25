use super::{
    ClockCalibration, ComparisonRequest, ResolvedEvent, Result, TimeComparison, TimeInterval,
    TimeRelation, Work, invalid,
};
use crate::journal::Event;
use std::collections::BTreeSet;

pub(super) fn intervals(
    event: &Event,
    calibrations: &[ClockCalibration],
    work: &mut Work,
) -> Result<Vec<TimeInterval>> {
    let (Some(clock), Some(ticks)) = (&event.clock, event.ticks) else {
        return Ok(Vec::new());
    };
    let mut result = vec![TimeInterval {
        clock: clock.clone(),
        earliest: i128::from(ticks),
        latest: i128::from(ticks),
        calibration_id: None,
    }];
    for calibration in calibrations {
        work.charge()?;
        if calibration.from_clock != *clock
            || ticks < calibration.valid_from
            || calibration.valid_through.is_some_and(|end| ticks > end)
        {
            continue;
        }
        let delta = i128::from(ticks) - i128::from(calibration.anchor_from);
        let scaled = delta
            .checked_mul(i128::from(calibration.numerator))
            .ok_or_else(|| invalid("clock conversion exceeds signed 128-bit arithmetic"))?;
        let divisor = i128::from(calibration.denominator);
        // Round outward even when the event precedes the calibration anchor
        let lower = scaled.div_euclid(divisor);
        let upper = lower + i128::from(scaled.rem_euclid(divisor) != 0);
        let anchor = i128::from(calibration.anchor_to);
        let uncertainty = i128::from(calibration.uncertainty_ticks);
        let earliest = anchor
            .checked_add(lower)
            .and_then(|n| n.checked_sub(uncertainty))
            .ok_or_else(|| invalid("clock interval exceeds signed 128-bit arithmetic"))?;
        let latest = anchor
            .checked_add(upper)
            .and_then(|n| n.checked_add(uncertainty))
            .ok_or_else(|| invalid("clock interval exceeds signed 128-bit arithmetic"))?;
        result.push(TimeInterval {
            clock: calibration.to_clock.clone(),
            earliest,
            latest,
            calibration_id: Some(calibration.id.clone()),
        });
    }
    Ok(result)
}
pub(super) fn compare(
    request: &ComparisonRequest,
    left: Option<&ResolvedEvent>,
    right: Option<&ResolvedEvent>,
    work: &mut Work,
) -> Result<TimeComparison> {
    let left: Vec<_> = left
        .into_iter()
        .flat_map(|event| &event.times)
        .filter(|time| time.clock == request.clock)
        .collect();
    let right: Vec<_> = right
        .into_iter()
        .flat_map(|event| &event.times)
        .filter(|time| time.clock == request.clock)
        .collect();
    let mut relations = BTreeSet::new();
    for a in &left {
        for b in &right {
            work.charge()?;
            relations.insert(if a.latest < b.earliest {
                TimeRelation::Before
            } else if a.earliest > b.latest {
                TimeRelation::After
            } else {
                TimeRelation::Overlapping
            });
        }
    }
    let relation = if relations.len() > 1 {
        TimeRelation::AmbiguousCalibration
    } else {
        relations.first().copied().unwrap_or(TimeRelation::Unmapped)
    };
    Ok(TimeComparison {
        request: request.clone(),
        relation,
        left_calibrations: left
            .iter()
            .filter_map(|time| time.calibration_id.clone())
            .collect(),
        right_calibrations: right
            .iter()
            .filter_map(|time| time.calibration_id.clone())
            .collect(),
    })
}
