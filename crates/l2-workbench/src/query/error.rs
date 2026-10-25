use core::fmt;

/// Invalid or unavailable query input
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueryError {
    /// A filter is malformed, unknown, duplicated, or outside its supported range
    InvalidFilter(String),
}

impl fmt::Display for QueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFilter(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for QueryError {}
