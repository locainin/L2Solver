use super::model::{
    Ambiguity, MAX_OBSERVATIONS, MAX_OMISSION_DETAILS, MAX_REPORT_RANGES, MAX_REPORT_VALUE_BYTES,
    Observation, Omission, OmissionReason, Report, Rule, Value,
};
use crate::evidence::SourceRange;
use crate::measurement::Clock;

pub(super) struct Builder {
    pub(super) report: Report,
    retained_value_bytes: usize,
    pub(super) retained_ranges: usize,
}

pub(super) struct ObservationDraft {
    pub(super) sample_ids: Vec<u64>,
    pub(super) event_id: Option<String>,
    pub(super) rule: Rule,
    pub(super) component_index: Option<usize>,
    pub(super) value: Value,
    pub(super) ranges: Vec<SourceRange>,
    pub(super) ambiguity: Ambiguity,
}

impl Builder {
    pub(super) fn new(rules: &[Rule]) -> Self {
        Self {
            report: Report {
                rules: rules.to_vec(),
                complete: true,
                observations: Vec::new(),
                relationships: Vec::new(),
                omissions: Vec::new(),
                omitted_count: 0,
            },
            retained_value_bytes: 0,
            retained_ranges: 0,
        }
    }

    pub(super) fn omit(&mut self, sample_id: Option<u64>, rule: &Rule, reason: OmissionReason) {
        self.report.complete = false;
        self.report.omitted_count = self.report.omitted_count.saturating_add(1);
        if self.report.omissions.len() < MAX_OMISSION_DETAILS {
            self.report.omissions.push(Omission {
                sample_id,
                rule: rule.clone(),
                reason,
            });
        }
    }

    pub(super) fn observe(&mut self, draft: ObservationDraft) {
        let ObservationDraft {
            sample_ids,
            event_id,
            rule,
            component_index,
            value,
            ranges,
            ambiguity,
        } = draft;
        let value_bytes = projected_size(&value);
        let next_value_bytes = self.retained_value_bytes.saturating_add(value_bytes);
        let next_range_count = self.retained_ranges.saturating_add(ranges.len());
        // Keep output bounded even when every valid sample produces a separate observation
        if self.report.observations.len() == MAX_OBSERVATIONS
            || next_value_bytes > MAX_REPORT_VALUE_BYTES
            || next_range_count > MAX_REPORT_RANGES
        {
            self.omit(
                sample_ids.first().copied(),
                &rule,
                OmissionReason::ReportBudget,
            );
            return;
        }
        let Some(id) = u64::try_from(self.report.observations.len())
            .ok()
            .and_then(|number| number.checked_add(1))
        else {
            self.omit(
                sample_ids.first().copied(),
                &rule,
                OmissionReason::ReportBudget,
            );
            return;
        };
        self.report.observations.push(Observation {
            id,
            sample_ids,
            event_id,
            rule,
            component_index,
            value: Some(value),
            ranges,
            ambiguity,
        });
        self.retained_value_bytes = next_value_bytes;
        self.retained_ranges = next_range_count;
    }
}

const fn projected_size(value: &Value) -> usize {
    match value {
        Value::Bytes { bytes } | Value::Capitalization { pattern: bytes } => bytes.len(),
        Value::Bits { packed, .. } => packed.len(),
        Value::DnsLabel { raw, comparison } => raw.len().saturating_add(comparison.len()),
        Value::Unsigned { .. } => std::mem::size_of::<u64>(),
        Value::Timing {
            left_clock,
            right_clock,
            ..
        } => std::mem::size_of::<[Option<u64>; 5]>()
            .saturating_add(clock_size(left_clock.as_ref()))
            .saturating_add(clock_size(right_clock.as_ref())),
    }
}

const fn clock_size(clock: Option<&Clock>) -> usize {
    match clock {
        Some(clock) => std::mem::size_of::<Clock>()
            .saturating_add(clock.id.len())
            .saturating_add(clock.scope.len()),
        None => 0,
    }
}
