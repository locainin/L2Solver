use super::{CorrelationOptions, CorrelationPlan, Result, Work, invalid};
use crate::evidence::SourceRange;
use std::collections::BTreeSet;

pub(super) fn validate(
    plan: &CorrelationPlan,
    options: CorrelationOptions,
    work: &mut Work,
) -> Result<()> {
    if options.max_events == 0 || options.max_work_items == 0 {
        return Err(invalid("correlation budgets must be positive"));
    }
    let mut ids = BTreeSet::new();
    for binding in &plan.bindings {
        work.charge()?;
        if [
            &binding.id,
            &binding.source,
            &binding.scope,
            &binding.subject,
            &binding.identity,
            &binding.origin_claim,
        ]
        .iter()
        .any(|text| text.trim().is_empty())
            || !ids.insert(&binding.id)
            || binding.first_packet == 0
            || binding
                .last_packet
                .is_some_and(|last| last < binding.first_packet)
        {
            return Err(invalid(
                "identity bindings require unique IDs, explicit identities and valid record intervals",
            ));
        }
        evidence(&binding.evidence)?;
    }
    ids.clear();
    for calibration in &plan.calibrations {
        work.charge()?;
        if [
            &calibration.id,
            &calibration.from_clock,
            &calibration.to_clock,
            &calibration.origin_claim,
        ]
        .iter()
        .any(|text| text.trim().is_empty())
            || !ids.insert(&calibration.id)
            || calibration.from_clock == calibration.to_clock
            || calibration.numerator == 0
            || calibration.denominator == 0
            || calibration
                .valid_through
                .is_some_and(|end| end < calibration.valid_from)
        {
            return Err(invalid(
                "clock calibrations require unique IDs, distinct clocks, positive rates and valid intervals",
            ));
        }
        evidence(&calibration.evidence)?;
    }
    for request in &plan.comparisons {
        work.charge()?;
        if [&request.left_event, &request.right_event, &request.clock]
            .iter()
            .any(|text| text.trim().is_empty())
        {
            return Err(invalid(
                "time comparisons require exact event IDs and a target clock",
            ));
        }
    }
    Ok(())
}
fn evidence(ranges: &[SourceRange]) -> Result<()> {
    if ranges.is_empty()
        || ranges.iter().any(|range| {
            range.source.is_empty()
                || range.length == 0
                || range.packet == Some(0)
                || range.offset.checked_add(range.length).is_none()
        })
    {
        return Err(invalid(
            "identity and clock claims require nonempty, valid supporting source ranges",
        ));
    }
    Ok(())
}
