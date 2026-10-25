use core::fmt;

/// Invalid wireless policy or assessment input
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditError {
    InvalidPolicy(&'static str),
    PolicyLimit {
        field: &'static str,
        count: usize,
        maximum: usize,
    },
    AssessmentLimit {
        field: &'static str,
        count: usize,
        maximum: usize,
    },
}

impl fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy(reason) => write!(formatter, "invalid wireless policy: {reason}"),
            Self::PolicyLimit {
                field,
                count,
                maximum,
            } => write!(
                formatter,
                "wireless policy {field} count {count} exceeds limit {maximum}"
            ),
            Self::AssessmentLimit {
                field,
                count,
                maximum,
            } => write!(
                formatter,
                "wireless assessment {field} count {count} exceeds limit {maximum}"
            ),
        }
    }
}

impl std::error::Error for AuditError {}
