//! Explicit virtual observer and cancellation controls

/// Modeled receiver collection conditions for every planned observation
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ObservationMode {
    /// Every forwarded unicast frame is captured at its destination
    #[default]
    Healthy,
    /// No receiver window is available
    Unavailable,
    /// Collection drops frames and reports loss for each receiver window
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
