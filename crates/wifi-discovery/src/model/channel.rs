//! Radio schedule and channel coverage records

use crate::SurveyError;
use serde::Serialize;

/// Dwell time explicitly attributed to one frequency
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ChannelDwell {
    frequency_mhz: u16,
    dwell_ns: u64,
}

impl ChannelDwell {
    #[must_use]
    pub const fn frequency_mhz(self) -> u16 {
        self.frequency_mhz
    }

    #[must_use]
    pub const fn dwell_ns(self) -> u64 {
        self.dwell_ns
    }
}

/// Honest channel coverage for one scheduled radio
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ChannelCoverage {
    radio: u16,
    total_scheduled_ns: u64,
    observed_ns: u64,
    coverage_basis_points: u16,
    channels: Vec<ChannelDwell>,
}

impl ChannelCoverage {
    pub(crate) const fn new(
        radio: u16,
        total_scheduled_ns: u64,
        observed_ns: u64,
        coverage_basis_points: u16,
        channels: Vec<ChannelDwell>,
    ) -> Self {
        Self {
            radio,
            total_scheduled_ns,
            observed_ns,
            coverage_basis_points,
            channels,
        }
    }

    #[must_use]
    pub const fn radio(&self) -> u16 {
        self.radio
    }

    #[must_use]
    pub const fn total_scheduled_ns(&self) -> u64 {
        self.total_scheduled_ns
    }

    #[must_use]
    pub const fn observed_ns(&self) -> u64 {
        self.observed_ns
    }

    #[must_use]
    pub const fn coverage_basis_points(&self) -> u16 {
        self.coverage_basis_points
    }

    #[must_use]
    pub fn channels(&self) -> &[ChannelDwell] {
        &self.channels
    }
}

#[derive(Clone)]
pub struct RadioSchedule {
    pub radio: u16,
    pub total_ns: u64,
    pub channels: Vec<ChannelDwell>,
}

impl RadioSchedule {
    pub(crate) const fn new(radio: u16, total_ns: u64) -> Self {
        Self {
            radio,
            total_ns,
            channels: Vec::new(),
        }
    }

    pub(crate) fn observed_ns(&self) -> Result<u64, SurveyError> {
        self.channels.iter().try_fold(0_u64, |total, item| {
            total
                .checked_add(item.dwell_ns)
                .ok_or(SurveyError::ArithmeticOverflow)
        })
    }

    pub(crate) fn add_dwell(
        &mut self,
        frequency_mhz: u16,
        dwell_ns: u64,
    ) -> Result<(), SurveyError> {
        if let Some(channel) = self
            .channels
            .iter_mut()
            .find(|item| item.frequency_mhz == frequency_mhz)
        {
            channel.dwell_ns = channel
                .dwell_ns
                .checked_add(dwell_ns)
                .ok_or(SurveyError::ArithmeticOverflow)?;
            return Ok(());
        }
        self.channels.push(ChannelDwell {
            frequency_mhz,
            dwell_ns,
        });
        Ok(())
    }
}
