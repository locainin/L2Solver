use crate::CaptureInput;

/// One raw record offered to virtual radios
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawCapture {
    sequence: u64,
    timestamp_ns: u64,
    frequency_mhz: u16,
    input: CaptureInput,
}

impl RawCapture {
    /// Build a raw record; frame parsing is intentionally left to the consumer
    #[must_use]
    pub const fn new(timestamp_ns: u64, frequency_mhz: u16, input: CaptureInput) -> Self {
        Self {
            sequence: 0,
            timestamp_ns,
            frequency_mhz,
            input,
        }
    }

    /// Return the insertion sequence assigned by [`crate::VirtualAir`]
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Return the monotonic timestamp in nanoseconds
    #[must_use]
    pub const fn timestamp_ns(&self) -> u64 {
        self.timestamp_ns
    }

    /// Return the frequency on which this record was emitted
    #[must_use]
    pub const fn frequency_mhz(&self) -> u16 {
        self.frequency_mhz
    }

    /// Return the explicit raw input
    #[must_use]
    pub const fn input(&self) -> &CaptureInput {
        &self.input
    }

    pub(crate) const fn assign_sequence(&mut self, sequence: u64) {
        self.sequence = sequence;
    }
}

/// One raw record delivered to one observing virtual radio
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedFrame {
    radio_id: u16,
    record: RawCapture,
}

impl CapturedFrame {
    pub(crate) const fn new(radio_id: u16, record: RawCapture) -> Self {
        // Each radio receipt retains the original source sequence
        Self { radio_id, record }
    }

    /// Return the observing radio identity
    #[must_use]
    pub const fn radio_id(&self) -> u16 {
        self.radio_id
    }

    /// Return the deterministic record sequence
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.record.sequence()
    }

    /// Return the record timestamp
    #[must_use]
    pub const fn timestamp_ns(&self) -> u64 {
        self.record.timestamp_ns()
    }

    /// Return the record frequency
    #[must_use]
    pub const fn frequency_mhz(&self) -> u16 {
        self.record.frequency_mhz()
    }

    /// Return the owned raw input retained for the downstream parser
    #[must_use]
    pub const fn input(&self) -> &CaptureInput {
        self.record.input()
    }

    /// Return the input as a borrowed `wifi-discovery` value
    #[must_use]
    pub fn wireless_input(&self) -> wifi_discovery::WirelessInput<'_> {
        self.input().as_discovery_input()
    }

    /// Return a discovery observation context with the record sequence and time
    #[must_use]
    pub const fn observation_context(&self) -> wifi_discovery::ObservationContext {
        wifi_discovery::ObservationContext::new(self.sequence(), self.timestamp_ns())
    }

    /// Return the same context under the shorter name used by capture consumers
    #[must_use]
    pub const fn context(&self) -> wifi_discovery::ObservationContext {
        self.observation_context()
    }
}

/// Why a raw record had no observing radio
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LossReason {
    /// No virtual radio was registered
    NoRadio,
    /// Radios existed, but all were outside a tuned dwell window
    OutsideDwell,
    /// A radio was tuned at the timestamp, but to another frequency
    FrequencyNotTuned,
}

/// One raw record that no virtual radio delivered
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureLoss {
    sequence: u64,
    timestamp_ns: u64,
    frequency_mhz: u16,
    reason: LossReason,
}

impl CaptureLoss {
    pub(crate) const fn new(record: &RawCapture, reason: LossReason) -> Self {
        Self {
            sequence: record.sequence(),
            timestamp_ns: record.timestamp_ns(),
            frequency_mhz: record.frequency_mhz(),
            reason,
        }
    }

    /// Return the deterministic source sequence
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Return the source timestamp
    #[must_use]
    pub const fn timestamp_ns(&self) -> u64 {
        self.timestamp_ns
    }

    /// Return the source frequency
    #[must_use]
    pub const fn frequency_mhz(&self) -> u16 {
        self.frequency_mhz
    }

    /// Return the reason the source record was lost
    #[must_use]
    pub const fn reason(&self) -> LossReason {
        self.reason
    }
}
