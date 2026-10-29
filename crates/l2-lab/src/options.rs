//! Explicit virtual observer and cancellation controls

/// Modeled collection conditions for receiver and state observations
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ObservationMode {
    /// Configured receiver and state observations are available and complete
    #[default]
    Healthy,
    /// Configured observation windows and state views are unavailable
    Unavailable,
    /// Collection reports loss that prevents a complete observation claim
    Dropped,
}

/// Boundary at which the independent scheduler receives cancellation
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Cancellation {
    /// Allow all admitted probes to run
    #[default]
    Never,
    /// Request cancellation after this many complete dispatches
    After(u64),
}

/// Fault controls applied to one bounded virtual execution
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RunOptions {
    pub(crate) observer: ObservationMode,
    pub(crate) cancellation: Cancellation,
}

impl RunOptions {
    /// Select receiver conditions and a cancellation boundary
    #[must_use]
    pub const fn new(observer: ObservationMode, cancellation: Cancellation) -> Self {
        Self {
            observer,
            cancellation,
        }
    }
}
