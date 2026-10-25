use std::collections::BTreeSet;

use crate::{
    CaptureAccounting, CaptureLoss, CapturedFrame, CoverageInput, LabError, LabLimits, LossReason,
    RadioAccounting, RawCapture, VirtualRadio,
};

/// Deterministic collection of raw wireless records and virtual radios
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VirtualAir {
    limits: LabLimits,
    radios: Vec<VirtualRadio>,
    records: Vec<RawCapture>,
    record_bytes: usize,
}

impl VirtualAir {
    /// Create an empty simulation with default bounded resources
    #[must_use]
    pub fn new() -> Self {
        Self {
            limits: LabLimits::default(),
            radios: Vec::new(),
            records: Vec::new(),
            record_bytes: 0,
        }
    }

    /// Create an empty simulation with checked runtime limits
    /// # Errors
    /// Returns [`LabError::InvalidLimit`] for invalid limits
    pub fn with_limits(limits: LabLimits) -> Result<Self, LabError> {
        limits.validate()?;
        Ok(Self {
            limits,
            radios: Vec::new(),
            records: Vec::new(),
            record_bytes: 0,
        })
    }

    /// Return the active runtime limits
    #[must_use]
    pub const fn limits(&self) -> LabLimits {
        self.limits
    }

    /// Register one virtual radio in stable identity order
    /// # Errors
    /// Returns duplicate, radio, window, or frequency budget errors
    pub fn add_radio(&mut self, radio: VirtualRadio) -> Result<(), LabError> {
        // Radio identities are the stable key used by every output ordering
        if self.radios.iter().any(|item| item.id() == radio.id()) {
            return Err(LabError::DuplicateRadio { radio: radio.id() });
        }
        if self.radios.len() >= self.limits.max_radios() {
            return Err(LabError::RadioLimit {
                maximum: self.limits.max_radios(),
            });
        }
        // Count existing and incoming windows before moving the radio
        let window_count = self
            .radios
            .iter()
            .try_fold(radio.windows().len(), |count, item| {
                count
                    .checked_add(item.windows().len())
                    .ok_or(LabError::ArithmeticOverflow)
            })?;
        if window_count > self.limits.max_windows() {
            return Err(LabError::WindowLimit {
                maximum: self.limits.max_windows(),
            });
        }
        // Distinct frequencies share one bounded air-level channel budget
        let mut channels = BTreeSet::new();
        for item in &self.radios {
            channels.extend(item.windows().iter().map(|window| window.frequency_mhz()));
        }
        channels.extend(radio.windows().iter().map(|window| window.frequency_mhz()));
        if channels.len() > self.limits.max_channels() {
            return Err(LabError::ChannelLimit {
                maximum: self.limits.max_channels(),
            });
        }
        self.radios.push(radio);
        // Keep lookup and report order independent of registration order
        self.radios.sort_by_key(VirtualRadio::id);
        Ok(())
    }

    /// Return registered radios ordered by identity
    #[must_use]
    pub fn radios(&self) -> &[VirtualRadio] {
        &self.radios
    }

    /// Return one registered radio by identity
    #[must_use]
    pub fn radio(&self, radio_id: u16) -> Option<&VirtualRadio> {
        self.radios.iter().find(|item| item.id() == radio_id)
    }

    /// Add one raw record and assign its deterministic insertion sequence
    /// # Errors
    /// Returns invalid-frequency, byte-budget, or record-budget errors
    pub fn add_record(&mut self, mut record: RawCapture) -> Result<u64, LabError> {
        // Raw bytes remain opaque, but their channel and size are checked here
        if record.frequency_mhz() == 0 {
            return Err(LabError::InvalidFrequency {
                frequency_mhz: record.frequency_mhz(),
            });
        }
        let actual = record.input().bytes().len();
        if actual > self.limits.max_frame_bytes() {
            return Err(LabError::FrameTooLarge {
                maximum: self.limits.max_frame_bytes(),
                actual,
            });
        }
        if self.records.len() >= self.limits.max_records() {
            return Err(LabError::RecordLimit {
                maximum: self.limits.max_records(),
            });
        }
        // Bound retained input separately from each frame's size
        let record_bytes = self
            .record_bytes
            .checked_add(actual)
            .ok_or(LabError::ArithmeticOverflow)?;
        if record_bytes > self.limits.max_input_bytes() {
            return Err(LabError::InputByteLimit {
                maximum: self.limits.max_input_bytes(),
                attempted: record_bytes,
            });
        }
        let sequence =
            u64::try_from(self.records.len()).map_err(|_| LabError::ArithmeticOverflow)?;
        record.assign_sequence(sequence);
        self.records.push(record);
        self.record_bytes = record_bytes;
        // Timestamp order models the air timeline while sequence breaks ties
        self.records
            .sort_by_key(|item| (item.timestamp_ns(), item.sequence()));
        Ok(sequence)
    }

    /// Add one explicitly typed raw capture without constructing a record first
    /// # Errors
    /// Returns the same validation and budget errors as [`Self::add_record`]
    pub fn add_capture(
        &mut self,
        timestamp_ns: u64,
        frequency_mhz: u16,
        input: crate::CaptureInput,
    ) -> Result<u64, LabError> {
        self.add_record(RawCapture::new(timestamp_ns, frequency_mhz, input))
    }

    /// Return offered records ordered by timestamp and insertion sequence
    #[must_use]
    pub fn records(&self) -> &[RawCapture] {
        &self.records
    }

    /// Deliver all records through matching windows and return accounting
    /// # Errors
    /// Returns an arithmetic error if a bounded report aggregate overflows
    pub fn run(&self) -> Result<CaptureReport, LabError> {
        // Calculate the clone multiplication before allocating report storage
        let (observation_capacity, observed_byte_capacity) = self.output_requirements()?;
        let mut observations = Vec::with_capacity(observation_capacity);
        let mut losses = Vec::with_capacity(self.records.len());
        let mut radio_accounting = self
            .radios
            .iter()
            .map(|radio| RadioAccounting::new(radio.id(), radio.scheduled_ns(), radio.dwell_ns()))
            .collect::<Vec<_>>();
        let mut captured_records = 0_u64;

        for record in &self.records {
            // A source record can produce one observation per matching radio
            let mut captured = false;
            let mut any_tuned = false;
            for (radio, stats) in self.radios.iter().zip(radio_accounting.iter_mut()) {
                if radio.is_tuned(record.timestamp_ns()) {
                    any_tuned = true;
                }
                if radio.is_tuned_to(record.timestamp_ns(), record.frequency_mhz()) {
                    captured = true;
                    stats.record_capture();
                    observations.push(CapturedFrame::new(radio.id(), record.clone()));
                } else {
                    stats.record_miss();
                }
            }
            if captured {
                captured_records = captured_records
                    .checked_add(1)
                    .ok_or(LabError::ArithmeticOverflow)?;
            } else {
                // Losses describe records missed by every radio
                let reason = if self.radios.is_empty() {
                    LossReason::NoRadio
                } else if any_tuned {
                    LossReason::FrequencyNotTuned
                } else {
                    LossReason::OutsideDwell
                };
                losses.push(CaptureLoss::new(record, reason));
            }
        }
        // Keep one source record adjacent across radios so observation order never regresses
        observations.sort_by_key(|item| (item.timestamp_ns(), item.sequence(), item.radio_id()));
        let offered_records =
            u64::try_from(self.records.len()).map_err(|_| LabError::ArithmeticOverflow)?;
        let lost_records = u64::try_from(losses.len()).map_err(|_| LabError::ArithmeticOverflow)?;
        let observation_count =
            u64::try_from(observations.len()).map_err(|_| LabError::ArithmeticOverflow)?;
        let observed_bytes =
            u64::try_from(observed_byte_capacity).map_err(|_| LabError::ArithmeticOverflow)?;
        let coverage_inputs = self
            .radios
            .iter()
            .map(VirtualRadio::coverage_input)
            .collect::<Result<Vec<CoverageInput>, LabError>>()?;
        Ok(CaptureReport {
            observations,
            losses,
            accounting: CaptureAccounting::new(
                offered_records,
                captured_records,
                lost_records,
                observation_count,
                observed_bytes,
            ),
            radio_accounting,
            coverage_inputs,
        })
    }

    /// Alias for [`Self::run`] for callers describing the operation as capture
    /// # Errors
    /// Returns the same bounded aggregate errors as [`Self::run`]
    pub fn capture(&self) -> Result<CaptureReport, LabError> {
        self.run()
    }

    fn output_requirements(&self) -> Result<(usize, usize), LabError> {
        let mut observations = 0_usize;
        let mut observed_bytes = 0_usize;
        for record in &self.records {
            let matching_radios = self
                .radios
                .iter()
                .filter(|radio| radio.is_tuned_to(record.timestamp_ns(), record.frequency_mhz()))
                .count();
            observations = observations
                .checked_add(matching_radios)
                .ok_or(LabError::ArithmeticOverflow)?;
            if observations > self.limits.max_observations() {
                return Err(LabError::ObservationLimit {
                    maximum: self.limits.max_observations(),
                    attempted: observations,
                });
            }
            let delivered = record
                .input()
                .bytes()
                .len()
                .checked_mul(matching_radios)
                .ok_or(LabError::ArithmeticOverflow)?;
            observed_bytes = observed_bytes
                .checked_add(delivered)
                .ok_or(LabError::ArithmeticOverflow)?;
            if observed_bytes > self.limits.max_observed_bytes() {
                return Err(LabError::ObservedByteLimit {
                    maximum: self.limits.max_observed_bytes(),
                    attempted: observed_bytes,
                });
            }
        }
        Ok((observations, observed_bytes))
    }
}

/// Complete deterministic result of one virtual-air run
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureReport {
    observations: Vec<CapturedFrame>,
    losses: Vec<CaptureLoss>,
    accounting: CaptureAccounting,
    radio_accounting: Vec<RadioAccounting>,
    coverage_inputs: Vec<CoverageInput>,
}

impl CaptureReport {
    /// Return delivered observations ordered by timestamp, radio, and sequence
    #[must_use]
    pub fn observations(&self) -> &[CapturedFrame] {
        &self.observations
    }

    /// Return records missed by every radio in timestamp order
    #[must_use]
    pub fn losses(&self) -> &[CaptureLoss] {
        &self.losses
    }

    /// Return aggregate offered, captured, and loss counts
    #[must_use]
    pub const fn accounting(&self) -> CaptureAccounting {
        self.accounting
    }

    /// Return per-radio counts and timing in radio identity order
    #[must_use]
    pub fn radio_accounting(&self) -> &[RadioAccounting] {
        &self.radio_accounting
    }

    /// Return explicit coverage inputs for downstream discovery
    #[must_use]
    pub fn coverage_inputs(&self) -> &[CoverageInput] {
        &self.coverage_inputs
    }

    /// Apply all radio schedules and dwell records to a discovery survey
    /// # Errors
    /// Returns the downstream survey's schedule or resource error
    pub fn apply_coverage_to(
        &self,
        survey: &mut wifi_discovery::Survey,
    ) -> Result<(), wifi_discovery::SurveyError> {
        // Keep a multi-radio report atomic as one survey update
        let mut staged = survey.clone();
        for input in &self.coverage_inputs {
            input.apply_to_staged(&mut staged)?;
        }
        *survey = staged;
        Ok(())
    }
}
