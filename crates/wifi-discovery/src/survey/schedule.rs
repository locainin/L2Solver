//! Radio schedule updates and explicit channel coverage accounting

use crate::model::RadioSchedule;
use crate::{ChannelCoverage, SurveyError};

use super::Survey;

impl Survey {
    /// Set the bounded observation schedule for one radio
    ///
    /// # Errors
    ///
    /// Returns [`SurveyError`] when existing dwell exceeds the schedule or the
    /// configured radio/channel budget is exhausted
    pub fn record_radio_schedule(&mut self, radio: u16, total_ns: u64) -> Result<(), SurveyError> {
        match self
            .schedules
            .binary_search_by_key(&radio, |schedule| schedule.radio)
        {
            Ok(index) => {
                let schedule = self
                    .schedules
                    .get_mut(index)
                    .ok_or(SurveyError::UnknownRadio(radio))?;
                let observed = schedule.observed_ns()?;
                if observed > total_ns {
                    return Err(SurveyError::DwellExceedsSchedule {
                        radio,
                        observed_ns: observed,
                        scheduled_ns: total_ns,
                    });
                }
                schedule.total_ns = total_ns;
            }
            Err(index) => {
                if self.schedules.len() == self.limits.channels {
                    return Err(SurveyError::ChannelLimit {
                        maximum: self.limits.channels,
                    });
                }
                self.schedules
                    .insert(index, RadioSchedule::new(radio, total_ns));
            }
        }
        Ok(())
    }

    /// Record explicit dwell time for one radio and frequency
    ///
    /// # Errors
    ///
    /// Returns [`SurveyError`] for an unknown radio, exhausted channel budget,
    /// arithmetic overflow, or dwell beyond the declared schedule
    pub fn record_channel_dwell(
        &mut self,
        radio: u16,
        frequency_mhz: u16,
        dwell_ns: u64,
    ) -> Result<(), SurveyError> {
        if frequency_mhz == 0 {
            return Err(SurveyError::InvalidFrequency { frequency_mhz });
        }
        let total_channels = self.schedules.iter().try_fold(0_usize, |total, item| {
            total
                .checked_add(item.channels.len())
                .ok_or(SurveyError::ArithmeticOverflow)
        })?;
        let schedule_index = self
            .schedules
            .binary_search_by_key(&radio, |schedule| schedule.radio)
            .map_err(|_| SurveyError::UnknownRadio(radio))?;
        let schedule = self
            .schedules
            .get_mut(schedule_index)
            .ok_or(SurveyError::UnknownRadio(radio))?;
        let is_new = schedule
            .channels
            .iter()
            .all(|item| item.frequency_mhz() != frequency_mhz);
        if is_new && total_channels == self.limits.channels {
            return Err(SurveyError::ChannelLimit {
                maximum: self.limits.channels,
            });
        }
        let observed = schedule
            .observed_ns()?
            .checked_add(dwell_ns)
            .ok_or(SurveyError::ArithmeticOverflow)?;
        if observed > schedule.total_ns {
            return Err(SurveyError::DwellExceedsSchedule {
                radio,
                observed_ns: observed,
                scheduled_ns: schedule.total_ns,
            });
        }
        schedule.add_dwell(frequency_mhz, dwell_ns)?;
        schedule.channels.sort_by_key(|item| item.frequency_mhz());
        Ok(())
    }

    /// Calculate coverage from the declared schedule and recorded dwell
    ///
    /// # Errors
    ///
    /// Returns [`SurveyError`] for an unknown radio or arithmetic overflow
    pub fn channel_coverage(&self, radio: u16) -> Result<ChannelCoverage, SurveyError> {
        let schedule_index = self
            .schedules
            .binary_search_by_key(&radio, |schedule| schedule.radio)
            .map_err(|_| SurveyError::UnknownRadio(radio))?;
        let schedule = self
            .schedules
            .get(schedule_index)
            .ok_or(SurveyError::UnknownRadio(radio))?;
        let observed = schedule.observed_ns()?;
        let basis_points = if schedule.total_ns == 0 {
            0
        } else {
            let scaled = u128::from(observed)
                .checked_mul(10_000)
                .ok_or(SurveyError::ArithmeticOverflow)?
                / u128::from(schedule.total_ns);
            u16::try_from(scaled).map_err(|_| SurveyError::ArithmeticOverflow)?
        };
        Ok(ChannelCoverage::new(
            radio,
            schedule.total_ns,
            observed,
            basis_points,
            schedule.channels.clone(),
        ))
    }
}
