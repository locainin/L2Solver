use std::fmt;
use std::io;

use crate::arguments::ProgressMode;
use l2_workbench::job::JobError;

/// Selects the amount of human-readable status information
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RenderVerbosity {
    /// Suppress human-readable status
    Quiet,
    /// Show the active stage and its measurements
    #[default]
    Normal,
    /// Include every cumulative counter
    Verbose,
}

/// Configuration for a job progress renderer
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RendererOptions {
    /// Output behavior
    pub mode: ProgressMode,
    /// Human-readable detail level
    pub verbosity: RenderVerbosity,
}

/// Errors produced while a progress renderer observes or writes job snapshots
#[derive(Debug)]
#[non_exhaustive]
pub enum RendererError {
    /// Shared job state could not be read
    Job(JobError),
    /// Snapshot could not be encoded as JSON
    Json(serde_json::Error),
    /// Stderr output failed
    Io(io::Error),
    /// The renderer worker thread terminated unexpectedly
    WorkerPanicked,
    /// A built-in progress style failed to parse
    InvalidStyle(String),
}

impl fmt::Display for RendererError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Job(error) => write!(formatter, "could not read job progress: {error}"),
            Self::Json(error) => write!(formatter, "could not encode progress snapshot: {error}"),
            Self::Io(error) => write!(formatter, "could not write progress output: {error}"),
            Self::WorkerPanicked => formatter.write_str("progress renderer worker panicked"),
            Self::InvalidStyle(error) => write!(formatter, "invalid progress style: {error}"),
        }
    }
}

impl std::error::Error for RendererError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Job(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::WorkerPanicked | Self::InvalidStyle(_) => None,
        }
    }
}

impl From<&crate::arguments::RecoveryOptions> for RendererOptions {
    fn from(options: &crate::arguments::RecoveryOptions) -> Self {
        let verbosity = if options.quiet {
            RenderVerbosity::Quiet
        } else if options.verbosity > 0 {
            RenderVerbosity::Verbose
        } else {
            RenderVerbosity::Normal
        };

        Self {
            mode: options.progress,
            verbosity,
        }
    }
}

impl From<JobError> for RendererError {
    fn from(error: JobError) -> Self {
        Self::Job(error)
    }
}

impl From<serde_json::Error> for RendererError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<io::Error> for RendererError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
