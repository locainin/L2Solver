use clap::Args;
use l2_workbench::reconstruction::Limits;
use std::num::NonZeroUsize;

/// Shared record-retention and reconstruction budgets for bounded evidence cases
#[derive(Clone, Debug, PartialEq, Eq, Args)]
pub struct ReconstructionArgs {
    /// Maximum input records retained before case construction
    #[arg(long = "max-frames", value_name = "COUNT", default_value_t = Limits::default().frames, value_parser = clap::value_parser!(u64).range(1..))]
    frames: u64,
    /// Maximum captured packet bytes retained
    #[arg(long = "max-bytes", value_name = "BYTES", default_value = Limits::default().bytes.to_string())]
    bytes: NonZeroUsize,
    /// Maximum packet and fragment units retained
    #[arg(long = "max-units", value_name = "COUNT", default_value = Limits::default().units.to_string())]
    units: NonZeroUsize,
    /// Maximum TCP sessions retained
    #[arg(long = "max-sessions", value_name = "COUNT", default_value = Limits::default().sessions.to_string())]
    sessions: NonZeroUsize,
    /// Maximum fragment datagrams retained
    #[arg(long = "max-datagrams", value_name = "COUNT", default_value = Limits::default().datagrams.to_string())]
    datagrams: NonZeroUsize,
    /// Maximum byte positions visited during range assembly
    #[arg(long = "max-range-bytes", value_name = "BYTES", default_value = Limits::default().range_bytes.to_string())]
    range_bytes: NonZeroUsize,
    /// Maximum source observations retained in one assembled range
    #[arg(long = "max-range-observations", value_name = "COUNT", default_value = Limits::default().range_observations.to_string())]
    range_observations: NonZeroUsize,
    /// Maximum copied source bytes retained in one assembled range
    #[arg(long = "max-range-retained-bytes", value_name = "BYTES", default_value = Limits::default().range_retained_bytes.to_string())]
    range_retained_bytes: NonZeroUsize,
}

impl ReconstructionArgs {
    /// Return the configured budgets, including their displayed defaults
    #[must_use]
    pub const fn limits(&self) -> Limits {
        // The reader and analysis engine receive the same caller-selected limits
        Limits {
            frames: self.frames,
            bytes: self.bytes.get(),
            units: self.units.get(),
            sessions: self.sessions.get(),
            datagrams: self.datagrams.get(),
            range_bytes: self.range_bytes.get(),
            range_observations: self.range_observations.get(),
            range_retained_bytes: self.range_retained_bytes.get(),
        }
    }
}
