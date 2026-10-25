/// Aggregate capture accounting for one virtual-air run
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureAccounting {
    offered_records: u64,
    captured_records: u64,
    lost_records: u64,
    observation_count: u64,
    observed_bytes: u64,
}

impl CaptureAccounting {
    pub(crate) const fn new(
        offered_records: u64,
        captured_records: u64,
        lost_records: u64,
        observation_count: u64,
        observed_bytes: u64,
    ) -> Self {
        Self {
            offered_records,
            captured_records,
            lost_records,
            observation_count,
            observed_bytes,
        }
    }

    /// Return records offered by the virtual air
    #[must_use]
    pub const fn offered_records(self) -> u64 {
        self.offered_records
    }

    /// Return unique records observed by at least one radio
    #[must_use]
    pub const fn captured_records(self) -> u64 {
        self.captured_records
    }

    /// Return unique records observed by no radio
    #[must_use]
    pub const fn lost_records(self) -> u64 {
        self.lost_records
    }

    /// Return radio-specific observations, including multi-radio duplicates
    #[must_use]
    pub const fn observation_count(self) -> u64 {
        self.observation_count
    }

    /// Return bytes delivered across all radio observations
    #[must_use]
    pub const fn observed_bytes(self) -> u64 {
        self.observed_bytes
    }
}

/// Capture counts and timing for one virtual radio
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RadioAccounting {
    radio_id: u16,
    scheduled_ns: u64,
    tuned_ns: u64,
    captured_records: u64,
    missed_records: u64,
    observation_count: u64,
}

impl RadioAccounting {
    pub(crate) const fn new(radio_id: u16, scheduled_ns: u64, tuned_ns: u64) -> Self {
        Self {
            radio_id,
            scheduled_ns,
            tuned_ns,
            captured_records: 0,
            missed_records: 0,
            observation_count: 0,
        }
    }

    pub(crate) const fn record_capture(&mut self) {
        self.captured_records = self.captured_records.saturating_add(1);
        self.observation_count = self.observation_count.saturating_add(1);
    }

    pub(crate) const fn record_miss(&mut self) {
        self.missed_records = self.missed_records.saturating_add(1);
    }

    /// Return the radio identity
    #[must_use]
    pub const fn radio_id(self) -> u16 {
        self.radio_id
    }

    /// Return the explicit schedule horizon
    #[must_use]
    pub const fn scheduled_ns(self) -> u64 {
        self.scheduled_ns
    }

    /// Return the sum of tuned dwell intervals
    #[must_use]
    pub const fn tuned_ns(self) -> u64 {
        self.tuned_ns
    }

    /// Return unique records delivered by this radio
    #[must_use]
    pub const fn captured_records(self) -> u64 {
        self.captured_records
    }

    /// Return records outside this radio's matching windows
    #[must_use]
    pub const fn missed_records(self) -> u64 {
        self.missed_records
    }

    /// Return observations delivered by this radio
    #[must_use]
    pub const fn observation_count(self) -> u64 {
        self.observation_count
    }
}
