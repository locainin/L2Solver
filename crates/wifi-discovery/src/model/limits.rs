//! Runtime resource limits and compile-time ceiling validation

use crate::{
    ABSOLUTE_MAX_ACCESS_POINTS, ABSOLUTE_MAX_CHANNELS, ABSOLUTE_MAX_DIAGNOSTICS,
    ABSOLUTE_MAX_STATIONS, SurveyError,
};
use serde::{Deserialize, Serialize};

/// Runtime inventory limits bounded by compile-time ceilings
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SurveyLimits {
    pub(crate) access_points: usize,
    pub(crate) stations: usize,
    pub(crate) diagnostics: usize,
    pub(crate) channels: usize,
}

impl SurveyLimits {
    /// Construct limits that remain within the compiled resource ceilings
    ///
    /// # Errors
    ///
    /// Returns [`SurveyError`] when any limit is zero or exceeds its ceiling
    pub fn new(
        access_points: usize,
        stations: usize,
        diagnostics: usize,
        channels: usize,
    ) -> Result<Self, SurveyError> {
        validate_limit("access points", access_points, ABSOLUTE_MAX_ACCESS_POINTS)?;
        validate_limit("stations", stations, ABSOLUTE_MAX_STATIONS)?;
        validate_limit("diagnostics", diagnostics, ABSOLUTE_MAX_DIAGNOSTICS)?;
        validate_limit("channels", channels, ABSOLUTE_MAX_CHANNELS)?;
        Ok(Self {
            access_points,
            stations,
            diagnostics,
            channels,
        })
    }
}

impl Default for SurveyLimits {
    fn default() -> Self {
        Self {
            access_points: 4_096,
            stations: 16_384,
            diagnostics: 1_024,
            channels: 256,
        }
    }
}

const fn validate_limit(
    field: &'static str,
    value: usize,
    maximum: usize,
) -> Result<(), SurveyError> {
    if value == 0 || value > maximum {
        return Err(SurveyError::InvalidLimit {
            field,
            value,
            maximum,
        });
    }
    Ok(())
}
