use crate::{LabError, MAX_CHANNELS};

/// Dwell attributed to one frequency in a coverage input
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ChannelDwell {
    frequency_mhz: u16,
    dwell_ns: u64,
}

impl ChannelDwell {
    /// Build one frequency dwell record
    #[must_use]
    pub const fn new(frequency_mhz: u16, dwell_ns: u64) -> Self {
        Self {
            frequency_mhz,
            dwell_ns,
        }
    }

    /// Return the frequency attributed to this dwell
    #[must_use]
    pub const fn frequency_mhz(self) -> u16 {
        self.frequency_mhz
    }

    /// Return the dwell duration in nanoseconds
    #[must_use]
    pub const fn dwell_ns(self) -> u64 {
        self.dwell_ns
    }
}

/// Explicit schedule and per-frequency dwell consumable by `wifi-discovery`
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageInput {
    radio_id: u16,
    total_scheduled_ns: u64,
    channels: Vec<ChannelDwell>,
}

impl CoverageInput {
    /// Build checked, sorted coverage input
    /// # Errors
    /// Returns an arithmetic error for an overflowing dwell aggregate
    pub fn new(
        radio_id: u16,
        total_scheduled_ns: u64,
        mut channels: Vec<ChannelDwell>,
    ) -> Result<Self, LabError> {
        if channels.len() > MAX_CHANNELS {
            return Err(LabError::ChannelLimit {
                maximum: MAX_CHANNELS,
            });
        }
        // Sorting makes deduplication and serialized review deterministic
        if channels.iter().any(|item| item.frequency_mhz() == 0) {
            return Err(LabError::InvalidFrequency { frequency_mhz: 0 });
        }
        channels.sort_by_key(|item| item.frequency_mhz());
        let mut deduplicated: Vec<ChannelDwell> = Vec::with_capacity(channels.len());
        for channel in channels {
            if let Some(existing) = deduplicated.last_mut()
                && existing.frequency_mhz() == channel.frequency_mhz()
            {
                let dwell_ns = existing
                    .dwell_ns()
                    .checked_add(channel.dwell_ns())
                    .ok_or(LabError::ArithmeticOverflow)?;
                *existing = ChannelDwell::new(channel.frequency_mhz(), dwell_ns);
                continue;
            }
            deduplicated.push(channel);
        }
        let dwell_ns = deduplicated.iter().try_fold(0_u64, |total, channel| {
            total
                .checked_add(channel.dwell_ns())
                .ok_or(LabError::ArithmeticOverflow)
        })?;
        // Dwell cannot claim more time than the declared schedule horizon
        if dwell_ns > total_scheduled_ns {
            return Err(LabError::DwellExceedsSchedule {
                radio: radio_id,
                dwell_ns,
                scheduled_ns: total_scheduled_ns,
            });
        }
        Ok(Self {
            radio_id,
            total_scheduled_ns,
            channels: deduplicated,
        })
    }

    /// Return the radio identity represented by this input
    #[must_use]
    pub const fn radio_id(&self) -> u16 {
        self.radio_id
    }

    /// Return the total scheduled horizon
    #[must_use]
    pub const fn total_scheduled_ns(&self) -> u64 {
        self.total_scheduled_ns
    }

    /// Return sorted per-frequency dwell records
    #[must_use]
    pub fn channels(&self) -> &[ChannelDwell] {
        &self.channels
    }

    /// Return total tuned dwell represented by the channels
    #[must_use]
    pub fn dwell_ns(&self) -> u64 {
        self.channels.iter().fold(0_u64, |total, channel| {
            total.saturating_add(channel.dwell_ns())
        })
    }

    /// Return schedule coverage in basis points, from zero through ten thousand
    #[must_use]
    pub fn coverage_basis_points(&self) -> u16 {
        basis_points(self.dwell_ns(), self.total_scheduled_ns())
    }

    /// Apply this explicit schedule and dwell to a discovery survey
    /// # Errors
    /// Returns the downstream survey's schedule or resource error
    pub fn apply_to(
        &self,
        survey: &mut wifi_discovery::Survey,
    ) -> Result<(), wifi_discovery::SurveyError> {
        // Commit the batch only after every downstream limit accepts it
        let mut staged = survey.clone();
        self.apply_to_staged(&mut staged)?;
        *survey = staged;
        Ok(())
    }

    pub(crate) fn apply_to_staged(
        &self,
        survey: &mut wifi_discovery::Survey,
    ) -> Result<(), wifi_discovery::SurveyError> {
        survey.record_radio_schedule(self.radio_id, self.total_scheduled_ns)?;
        for channel in &self.channels {
            survey.record_channel_dwell(
                self.radio_id,
                channel.frequency_mhz(),
                channel.dwell_ns(),
            )?;
        }
        Ok(())
    }
}

fn basis_points(dwell_ns: u64, scheduled_ns: u64) -> u16 {
    if scheduled_ns == 0 {
        return 0;
    }
    let scaled = u128::from(dwell_ns).saturating_mul(10_000) / u128::from(scheduled_ns);
    u16::try_from(scaled).unwrap_or(u16::MAX)
}
