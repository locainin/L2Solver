//! Survey failures stop reporting before partial state can look complete

use crate::SourceLabelMapError;
use std::fmt;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AuditError {
    Limit(&'static str),
    InvalidLimit(&'static str),
    Policy(&'static str),
    SourceMapping(SourceLabelMapError),
    Terminated,
}
impl fmt::Display for AuditError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limit(resource) => write!(output, "survey {resource} limit exceeded"),
            Self::InvalidLimit(reason) => write!(output, "invalid survey limit: {reason}"),
            Self::Policy(reason) => write!(output, "invalid survey policy: {reason}"),
            Self::SourceMapping(error) => write!(output, "invalid source mapping: {error}"),
            Self::Terminated => {
                output.write_str("survey is terminal after an earlier collection error")
            }
        }
    }
}
impl std::error::Error for AuditError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SourceMapping(error) => Some(error),
            Self::Limit(_) | Self::InvalidLimit(_) | Self::Policy(_) | Self::Terminated => None,
        }
    }
}
