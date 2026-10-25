use crate::LabError;

/// One half-open interval in which a radio is tuned to one frequency
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DwellWindow {
    start_ns: u64,
    end_ns: u64,
    frequency_mhz: u16,
}

impl DwellWindow {
    /// Construct a checked half-open `[start, end)` dwell interval
    /// # Errors
    /// Returns an error for a reversed or empty interval or a zero frequency
    pub const fn new(start_ns: u64, end_ns: u64, frequency_mhz: u16) -> Result<Self, LabError> {
        if frequency_mhz == 0 {
            return Err(LabError::InvalidFrequency { frequency_mhz });
        }
        if end_ns < start_ns {
            return Err(LabError::WindowReversed { start_ns, end_ns });
        }
        if end_ns == start_ns {
            return Err(LabError::ZeroLengthWindow { at_ns: start_ns });
        }
        Ok(Self {
            start_ns,
            end_ns,
            frequency_mhz,
        })
    }

    /// Construct a checked dwell interval from a start and duration
    /// # Errors
    /// Returns an error when the duration is zero or the end timestamp overflows
    pub const fn for_duration(
        start_ns: u64,
        duration_ns: u64,
        frequency_mhz: u16,
    ) -> Result<Self, LabError> {
        if duration_ns == 0 {
            return Err(LabError::ZeroLengthWindow { at_ns: start_ns });
        }
        let Some(end_ns) = start_ns.checked_add(duration_ns) else {
            return Err(LabError::TimeOverflow);
        };
        Self::new(start_ns, end_ns, frequency_mhz)
    }

    /// Return the inclusive start timestamp
    #[must_use]
    pub const fn start_ns(self) -> u64 {
        self.start_ns
    }

    /// Return the exclusive end timestamp
    #[must_use]
    pub const fn end_ns(self) -> u64 {
        self.end_ns
    }

    /// Return the frequency selected during this interval
    #[must_use]
    pub const fn frequency_mhz(self) -> u16 {
        self.frequency_mhz
    }

    /// Return the checked duration of this interval
    #[must_use]
    pub const fn duration_ns(self) -> u64 {
        self.end_ns - self.start_ns
    }

    /// Return whether a timestamp falls inside this half-open interval
    #[must_use]
    pub const fn contains(self, timestamp_ns: u64) -> bool {
        timestamp_ns >= self.start_ns && timestamp_ns < self.end_ns
    }
}
