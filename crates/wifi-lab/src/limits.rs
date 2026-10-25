use crate::LabError;

/// Absolute virtual-radio count accepted by the lab
pub const MAX_RADIOS: usize = 64;

/// Absolute dwell-window count accepted by the lab
pub const MAX_WINDOWS: usize = 16_384;

/// Absolute raw-record count accepted by the lab
pub const MAX_RECORDS: usize = 65_536;

/// Absolute raw-input byte count per record accepted by the lab
pub const MAX_FRAME_BYTES: usize = 65_535;

/// Absolute unique-frequency count accepted by the lab
pub const MAX_CHANNELS: usize = 1_024;

/// Absolute raw-input bytes retained by one virtual-air simulation
pub const MAX_INPUT_BYTES: usize = 512 * 1_024 * 1_024;

/// Absolute radio-specific observations produced by one simulation
pub const MAX_OBSERVATIONS: usize = 262_144;

/// Absolute bytes retained across all delivered observations
pub const MAX_OBSERVED_BYTES: usize = 512 * 1_024 * 1_024;

/// Runtime resource limits for one virtual-air simulation
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LabLimits {
    radios: usize,
    windows: usize,
    records: usize,
    frame_bytes: usize,
    channels: usize,
    input_bytes: usize,
    observations: usize,
    observed_bytes: usize,
}

impl LabLimits {
    /// Construct limits bounded by the lab's compile-time ceilings
    /// # Errors
    /// Returns [`LabError::InvalidLimit`] for zero or oversized values
    pub fn new(
        max_radios: usize,
        max_windows: usize,
        max_records: usize,
        max_frame_bytes: usize,
        max_channels: usize,
    ) -> Result<Self, LabError> {
        validate("radios", max_radios, MAX_RADIOS)?;
        validate("dwell windows", max_windows, MAX_WINDOWS)?;
        validate("records", max_records, MAX_RECORDS)?;
        validate("frame bytes", max_frame_bytes, MAX_FRAME_BYTES)?;
        validate("channels", max_channels, MAX_CHANNELS)?;
        Ok(Self {
            radios: max_radios,
            windows: max_windows,
            records: max_records,
            frame_bytes: max_frame_bytes,
            channels: max_channels,
            input_bytes: 64 * 1_024 * 1_024,
            observations: 65_536,
            observed_bytes: 64 * 1_024 * 1_024,
        })
    }

    /// Replace the cumulative input and delivery limits
    /// # Errors
    /// Returns [`LabError::InvalidLimit`] for zero or oversized values
    pub fn with_storage_limits(
        mut self,
        max_input_bytes: usize,
        max_observations: usize,
        max_observed_bytes: usize,
    ) -> Result<Self, LabError> {
        validate("input bytes", max_input_bytes, MAX_INPUT_BYTES)?;
        validate("observations", max_observations, MAX_OBSERVATIONS)?;
        validate("observed bytes", max_observed_bytes, MAX_OBSERVED_BYTES)?;
        self.input_bytes = max_input_bytes;
        self.observations = max_observations;
        self.observed_bytes = max_observed_bytes;
        Ok(self)
    }

    /// Return the configured maximum number of radios
    #[must_use]
    pub const fn max_radios(self) -> usize {
        self.radios
    }

    /// Return the configured maximum number of dwell windows
    #[must_use]
    pub const fn max_windows(self) -> usize {
        self.windows
    }

    /// Return the configured maximum number of raw records
    #[must_use]
    pub const fn max_records(self) -> usize {
        self.records
    }

    /// Return the configured maximum input size
    #[must_use]
    pub const fn max_frame_bytes(self) -> usize {
        self.frame_bytes
    }

    /// Return the configured maximum unique-frequency count
    #[must_use]
    pub const fn max_channels(self) -> usize {
        self.channels
    }

    /// Return the cumulative raw-input byte limit
    #[must_use]
    pub const fn max_input_bytes(self) -> usize {
        self.input_bytes
    }

    /// Return the radio-specific observation limit
    #[must_use]
    pub const fn max_observations(self) -> usize {
        self.observations
    }

    /// Return the cumulative delivered-byte limit
    #[must_use]
    pub const fn max_observed_bytes(self) -> usize {
        self.observed_bytes
    }

    pub(crate) fn validate(self) -> Result<(), LabError> {
        validate("radios", self.radios, MAX_RADIOS)?;
        validate("dwell windows", self.windows, MAX_WINDOWS)?;
        validate("records", self.records, MAX_RECORDS)?;
        validate("frame bytes", self.frame_bytes, MAX_FRAME_BYTES)?;
        validate("channels", self.channels, MAX_CHANNELS)?;
        validate("input bytes", self.input_bytes, MAX_INPUT_BYTES)?;
        validate("observations", self.observations, MAX_OBSERVATIONS)?;
        validate("observed bytes", self.observed_bytes, MAX_OBSERVED_BYTES)
    }
}

impl Default for LabLimits {
    fn default() -> Self {
        Self {
            radios: 16,
            windows: 4_096,
            records: 16_384,
            frame_bytes: MAX_FRAME_BYTES,
            channels: 256,
            input_bytes: 64 * 1_024 * 1_024,
            observations: 65_536,
            observed_bytes: 64 * 1_024 * 1_024,
        }
    }
}

const fn validate(field: &'static str, value: usize, maximum: usize) -> Result<(), LabError> {
    if value == 0 || value > maximum {
        return Err(LabError::InvalidLimit {
            field,
            value,
            maximum,
        });
    }
    Ok(())
}
