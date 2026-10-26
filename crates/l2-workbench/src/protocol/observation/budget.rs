use super::model::{ObservationCoverage, ObservationLimits};
pub(super) fn can_retain_report(
    coverage: &ObservationCoverage,
    cost: usize,
    limits: ObservationLimits,
) -> bool {
    coverage
        .report_bytes_retained
        .checked_add(cost)
        .is_some_and(|total| total <= limits.max_report_bytes)
}
pub(super) const fn consume_work(coverage: &mut ObservationCoverage, maximum: usize) -> bool {
    if coverage.work_units < maximum {
        coverage.work_units = coverage.work_units.saturating_add(1);
        true
    } else {
        coverage.omitted_work_units = coverage.omitted_work_units.saturating_add(1);
        coverage.complete = false;
        false
    }
}
pub(super) const fn reserve_work(
    coverage: &mut ObservationCoverage,
    amount: usize,
    maximum: usize,
) -> bool {
    let Some(next) = coverage.work_units.checked_add(amount) else {
        coverage.omitted_work_units = coverage.omitted_work_units.saturating_add(amount);
        coverage.complete = false;
        return false;
    };
    if next > maximum {
        coverage.omitted_work_units = coverage.omitted_work_units.saturating_add(amount);
        coverage.complete = false;
        return false;
    }
    coverage.work_units = next;
    true
}
pub(super) const fn add_saturating(value: &mut usize, amount: usize, complete: &mut bool) {
    if let Some(sum) = value.checked_add(amount) {
        *value = sum;
    } else {
        *value = usize::MAX;
        *complete = false;
    }
}
pub(super) const fn omit_sample(coverage: &mut ObservationCoverage, bytes: usize) {
    coverage.omitted_samples = coverage.omitted_samples.saturating_add(1);
    coverage.omitted_input_bytes = coverage.omitted_input_bytes.saturating_add(bytes);
    coverage.complete = false;
}
