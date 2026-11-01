//! Shared resource limits for source-backed message-family discovery

use l2_workbench::protocol::{
    DEFAULT_MAX_FAMILY_RANGES, DEFAULT_MAX_FAMILY_REPORT_BYTES, DEFAULT_MAX_FAMILY_SAMPLES,
    MAX_MESSAGE_BYTES, MAX_PROTOCOL_BYTES, MessageFamilyLimits, RecordSchemaProposalLimits,
};

pub(super) const MAX_SELECTORS: usize = 8;
pub(super) const MAX_VALUES: usize = 4;
pub(super) const MAX_WORK_UNITS: usize = 1_000_000;

pub(super) fn limits(base: RecordSchemaProposalLimits, work_limit: usize) -> MessageFamilyLimits {
    MessageFamilyLimits {
        max_samples: DEFAULT_MAX_FAMILY_SAMPLES,
        // The record allowance covers all messages while this limit covers one
        max_message_bytes: base
            .discovery
            .record_limits
            .max_input_bytes
            .min(MAX_MESSAGE_BYTES),
        max_total_bytes: base
            .discovery
            .record_limits
            .max_input_bytes
            .min(MAX_PROTOCOL_BYTES),
        max_selector_offset: base.max_field_offset.min(15),
        max_selector_width: 4,
        min_training_sessions_per_family: 2,
        // The range limit counts each requested sample and range pair
        max_candidate_ranges: DEFAULT_MAX_FAMILY_RANGES,
        max_selectors: MAX_SELECTORS,
        max_families_per_selector: MAX_VALUES,
        max_work_units: work_limit.min(MAX_WORK_UNITS),
        max_report_bytes: DEFAULT_MAX_FAMILY_REPORT_BYTES / 2,
    }
}
