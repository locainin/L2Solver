use super::error::ObservationError;
use super::model::ObservationLimits;
pub(super) const MAX_PREFIX_OFFSET: usize = 255;
pub(super) const MAX_HYPOTHESES: usize = 8_192;
pub(super) const MAX_WORK_UNITS: usize = 4_000_000;
pub(super) const MAX_BYTE_OBSERVATIONS: usize = 262_144;
pub(super) const MAX_CONSTRAINTS: usize = 1_000_000;
pub(super) const MAX_REGION_RANGES: usize = 8_192;
pub(super) const MAX_REGION_WIDTH: usize = 4_096;
pub(super) const MAX_REGION_VALUES: usize = 65_536;
pub(super) const MAX_REGION_OCCURRENCES: usize = 262_144;
pub(super) const MAX_ORIGIN_RANGES: usize = 256;
pub(super) const MAX_REPORT_BYTES: usize = 16 * 1024 * 1024;
pub(super) const MAX_IDENTITY_BYTES: usize = 16 * 1024;
pub(super) const MAX_INPUT_MAPPINGS: usize = 65_536;
pub(super) const fn validate_limits(limits: ObservationLimits) -> Result<(), ObservationError> {
    if limits.max_samples > super::super::MAX_PROTOCOL_SAMPLES
        || limits.max_message_bytes > super::super::MAX_MESSAGE_BYTES
        || limits.max_total_bytes > super::super::MAX_PROTOCOL_BYTES
        || limits.max_prefix_offset > MAX_PREFIX_OFFSET
        || limits.max_hypotheses > MAX_HYPOTHESES
        || limits.max_work_units > MAX_WORK_UNITS
        || limits.max_byte_observations > MAX_BYTE_OBSERVATIONS
        || limits.max_constraints > MAX_CONSTRAINTS
        || limits.max_region_ranges > MAX_REGION_RANGES
        || limits.max_region_width > MAX_REGION_WIDTH
        || limits.max_region_values > MAX_REGION_VALUES
        || limits.max_region_occurrences > MAX_REGION_OCCURRENCES
        || limits.max_origin_ranges_per_observation > MAX_ORIGIN_RANGES
        || limits.max_report_bytes > MAX_REPORT_BYTES
        || limits.max_identity_bytes > MAX_IDENTITY_BYTES
        || limits.max_mappings_per_input > MAX_INPUT_MAPPINGS
    {
        return Err(ObservationError::InvalidLimits);
    }
    Ok(())
}
