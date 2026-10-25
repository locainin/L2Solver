use crate::{ABSOLUTE_MAX_INPUT_BYTES, ABSOLUTE_MAX_RECORD_COUNT, Error};

/// Byte and record ceilings for one streaming capture reader
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureLimits {
    max_input_bytes: u64,
    max_records: u32,
}

impl CaptureLimits {
    /// Streaming totals use file-offset and record-number representation limits
    pub const STREAMING: Self = Self {
        max_input_bytes: ABSOLUTE_MAX_INPUT_BYTES,
        max_records: ABSOLUTE_MAX_RECORD_COUNT,
    };

    /// Construct source totals without changing per-record allocation bounds
    ///
    /// # Errors
    /// Returns an error when either requested ceiling exceeds the absolute maximum
    pub const fn new(max_input_bytes: u64, max_records: u32) -> Result<Self, Error> {
        if max_input_bytes > ABSOLUTE_MAX_INPUT_BYTES {
            return Err(Error::InvalidCaptureLimits {
                max_input_bytes,
                max_records,
            });
        }
        Ok(Self {
            max_input_bytes,
            max_records,
        })
    }

    /// Return the maximum number of source bytes accepted by one reader
    #[must_use]
    pub const fn max_input_bytes(self) -> u64 {
        self.max_input_bytes
    }

    /// Return the maximum number of packet records accepted by one reader
    #[must_use]
    pub const fn max_records(self) -> u32 {
        self.max_records
    }
}

impl Default for CaptureLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: crate::MAX_INPUT_BYTES,
            max_records: crate::MAX_RECORD_COUNT,
        }
    }
}
