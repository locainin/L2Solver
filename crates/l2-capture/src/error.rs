//! Errors produced while constructing a canonical capture frame

use core::fmt;

/// Validation failures from [`crate::CapturedFrame::new`]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FrameError {
    /// Retained bytes exceed the process-wide frame limit
    FrameTooLong {
        /// Number of supplied bytes
        length: usize,
        /// Maximum retained bytes
        max: usize,
    },
    /// Retained bytes exceed the source-reported wire length
    CapturedLengthExceedsOriginal {
        /// Number of retained bytes
        captured: usize,
        /// Number of bytes reported by the source
        original: u32,
    },
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLong { length, max } => {
                write!(
                    formatter,
                    "captured frame length {length} exceeds maximum {max}"
                )
            }
            Self::CapturedLengthExceedsOriginal { captured, original } => write!(
                formatter,
                "captured frame length {captured} exceeds original length {original}"
            ),
        }
    }
}

impl std::error::Error for FrameError {}
