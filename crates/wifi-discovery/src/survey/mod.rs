//! State machine coordinating capture observation, bounded inventory, and channel accounting

mod inventory;
mod observation;
mod parsing;
mod schedule;

use std::collections::BTreeMap;

use crate::model::RadioSchedule;
use crate::{AccessPoint, Diagnostic, Station, SurveyError, SurveyLimits};
use wifi_core::MacAddress;

/// Bounded passive wireless inventory
#[derive(Clone)]
pub struct Survey {
    limits: SurveyLimits,
    access_points: BTreeMap<MacAddress, AccessPoint>,
    stations: BTreeMap<MacAddress, Station>,
    diagnostics: Vec<Diagnostic>,
    // Radio IDs stay ascending so schedule lookups can use binary search
    schedules: Vec<RadioSchedule>,
    inventory_incomplete: bool,
    last_sequence: Option<u64>,
    last_monotonic_ns: Option<u64>,
}

impl Survey {
    /// Create an empty survey with checked resource limits
    ///
    /// # Errors
    ///
    /// Returns [`SurveyError`] when deserialized limits exceed a compiled ceiling
    pub fn new(limits: SurveyLimits) -> Result<Self, SurveyError> {
        // Revalidate deserialized values at the normalized boundary
        let limits = SurveyLimits::new(
            limits.access_points,
            limits.stations,
            limits.diagnostics,
            limits.channels,
        )?;
        Ok(Self {
            limits,
            access_points: BTreeMap::new(),
            stations: BTreeMap::new(),
            diagnostics: Vec::new(),
            schedules: Vec::new(),
            inventory_incomplete: false,
            last_sequence: None,
            last_monotonic_ns: None,
        })
    }
}
