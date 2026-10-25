use crate::{ChannelDwell, CoverageInput, DwellWindow, LabError, MAX_WINDOWS};

/// Maximum windows retained by one virtual radio before air-level limits apply
const MAX_WINDOWS_PER_RADIO: usize = MAX_WINDOWS;

/// Deterministic radio model with explicit non-overlapping tuned windows
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VirtualRadio {
    id: u16,
    windows: Vec<DwellWindow>,
    scheduled_ns: Option<u64>,
}

impl VirtualRadio {
    /// Create an empty virtual radio with the given stable identity
    #[must_use]
    pub const fn new(id: u16) -> Self {
        Self {
            id,
            windows: Vec::new(),
            scheduled_ns: None,
        }
    }

    /// Build a radio from a collection of checked dwell windows
    /// # Errors
    /// Returns an overlap, arithmetic, or per-radio budget error
    pub fn from_windows(id: u16, windows: Vec<DwellWindow>) -> Result<Self, LabError> {
        let mut radio = Self::new(id);
        for window in windows {
            radio.add_window(window)?;
        }
        Ok(radio)
    }

    /// Return the stable radio identity
    #[must_use]
    pub const fn id(&self) -> u16 {
        self.id
    }

    /// Add one checked dwell window and keep windows ordered by time
    /// # Errors
    /// Returns an overlap, arithmetic, or per-radio budget error
    pub fn add_window(&mut self, window: DwellWindow) -> Result<(), LabError> {
        // Windows are half-open, so touching endpoints remain valid
        if self.windows.len() >= MAX_WINDOWS_PER_RADIO {
            return Err(LabError::WindowLimit {
                maximum: MAX_WINDOWS_PER_RADIO,
            });
        }
        if let Some(existing) = self.windows.iter().find(|existing| {
            window.start_ns() < existing.end_ns() && existing.start_ns() < window.end_ns()
        }) {
            return Err(LabError::WindowOverlap {
                radio: self.id,
                existing_start_ns: existing.start_ns(),
                existing_end_ns: existing.end_ns(),
                requested_start_ns: window.start_ns(),
                requested_end_ns: window.end_ns(),
            });
        }
        let next_dwell = self
            .checked_dwell_ns()?
            .checked_add(window.duration_ns())
            .ok_or(LabError::ArithmeticOverflow)?;
        if let Some(scheduled_ns) = self.scheduled_ns
            && next_dwell > scheduled_ns
        {
            return Err(LabError::DwellExceedsSchedule {
                radio: self.id,
                dwell_ns: next_dwell,
                scheduled_ns,
            });
        }
        self.windows.push(window);
        // Registration order must never affect simulation order
        self.windows
            .sort_by_key(|item| (item.start_ns(), item.end_ns(), item.frequency_mhz()));
        Ok(())
    }

    /// Add a half-open tuned interval directly
    /// # Errors
    /// Returns a window validation, overlap, arithmetic, or budget error
    pub fn tune(&mut self, start_ns: u64, end_ns: u64, frequency_mhz: u16) -> Result<(), LabError> {
        let window = DwellWindow::new(start_ns, end_ns, frequency_mhz)?;
        self.add_window(window)
    }

    /// Add a tuned interval from a start timestamp and duration
    /// # Errors
    /// Returns a window validation, overlap, arithmetic, or budget error
    pub fn tune_for(
        &mut self,
        start_ns: u64,
        duration_ns: u64,
        frequency_mhz: u16,
    ) -> Result<(), LabError> {
        let window = DwellWindow::for_duration(start_ns, duration_ns, frequency_mhz)?;
        self.add_window(window)
    }

    /// Set the total schedule horizon used for honest coverage reporting
    /// # Errors
    /// Returns an error when the horizon is shorter than existing dwell
    pub fn set_scheduled_ns(&mut self, scheduled_ns: u64) -> Result<(), LabError> {
        let dwell_ns = self.checked_dwell_ns()?;
        if dwell_ns > scheduled_ns {
            return Err(LabError::DwellExceedsSchedule {
                radio: self.id,
                dwell_ns,
                scheduled_ns,
            });
        }
        self.scheduled_ns = Some(scheduled_ns);
        Ok(())
    }

    /// Return the schedule horizon, or explicit dwell when no horizon was set
    #[must_use]
    pub fn scheduled_ns(&self) -> u64 {
        self.scheduled_ns.unwrap_or_else(|| self.dwell_ns())
    }

    /// Return the sum of all tuned dwell intervals
    #[must_use]
    pub fn dwell_ns(&self) -> u64 {
        self.windows.iter().fold(0_u64, |total, window| {
            total.saturating_add(window.duration_ns())
        })
    }

    /// Return ordered non-overlapping tuned windows
    #[must_use]
    pub fn windows(&self) -> &[DwellWindow] {
        &self.windows
    }

    /// Build the channel dwell input consumed by `wifi-discovery`
    /// # Errors
    /// Returns an arithmetic error if a checked aggregate cannot be represented
    pub fn coverage_input(&self) -> Result<CoverageInput, LabError> {
        let mut channels = Vec::new();
        for window in &self.windows {
            // Consecutive windows on one frequency become one discovery dwell
            if let Some(existing) = channels
                .iter_mut()
                .find(|item: &&mut ChannelDwell| item.frequency_mhz() == window.frequency_mhz())
            {
                let dwell_ns = existing
                    .dwell_ns()
                    .checked_add(window.duration_ns())
                    .ok_or(LabError::ArithmeticOverflow)?;
                *existing = ChannelDwell::new(window.frequency_mhz(), dwell_ns);
            } else {
                channels.push(ChannelDwell::new(
                    window.frequency_mhz(),
                    window.duration_ns(),
                ));
            }
        }
        channels.sort_by_key(|item| item.frequency_mhz());
        CoverageInput::new(self.id, self.scheduled_ns(), channels)
    }

    pub(crate) fn is_tuned_to(&self, timestamp_ns: u64, frequency_mhz: u16) -> bool {
        self.windows
            .iter()
            .any(|window| window.contains(timestamp_ns) && window.frequency_mhz() == frequency_mhz)
    }

    pub(crate) fn is_tuned(&self, timestamp_ns: u64) -> bool {
        self.windows
            .iter()
            .any(|window| window.contains(timestamp_ns))
    }

    fn checked_dwell_ns(&self) -> Result<u64, LabError> {
        self.windows.iter().try_fold(0_u64, |total, window| {
            total
                .checked_add(window.duration_ns())
                .ok_or(LabError::ArithmeticOverflow)
        })
    }
}
