use super::RecordError;
use std::{error::Error, fmt};

impl fmt::Display for RecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("record limits must be positive"),
            Self::InvalidSchema { field } => {
                write!(formatter, "record schema field {field} is invalid")
            }
            Self::InputTooLarge { length, maximum } => {
                write!(
                    formatter,
                    "record input has {length} bytes; maximum is {maximum}"
                )
            }
            Self::IdentifierTooLarge { width, maximum } => write!(
                formatter,
                "record identifier width {width} exceeds {maximum}"
            ),
            Self::TooManyRecords { count, maximum } => {
                write!(formatter, "record count {count} exceeds {maximum}")
            }
            Self::ReportTooLarge { bytes, maximum } => write!(
                formatter,
                "record metadata needs {bytes} bytes; maximum is {maximum}"
            ),
            Self::TruncatedPreamble { needed, available } => write!(
                formatter,
                "record preamble needs {needed} bytes; only {available} are available"
            ),
            Self::TruncatedRecord {
                record,
                offset,
                needed,
                available,
            } => write!(
                formatter,
                "record {record} at offset {offset} needs an end offset of {needed}; input ends at {available}"
            ),
            Self::InvalidRecordLength { record, encoded } => write!(
                formatter,
                "record {record} has impossible encoded length {encoded}"
            ),
            Self::LengthOverflow { record } => {
                write!(
                    formatter,
                    "record {record} length or offset cannot be represented"
                )
            }
            Self::TrailingBytes { offset, remaining } => write!(
                formatter,
                "record parse stopped at {offset} with {remaining} unconsumed bytes"
            ),
            Self::InvalidReport => {
                formatter.write_str("record report does not match the supplied source bytes")
            }
            Self::TooManyGroups { count, maximum } => {
                write!(formatter, "record group count {count} exceeds {maximum}")
            }
            Self::OutputTooLarge { length, maximum } => write!(
                formatter,
                "record candidate output needs {length} bytes; maximum is {maximum}"
            ),
            Self::AllocationFailed => formatter.write_str("record operation allocation failed"),
        }
    }
}

impl Error for RecordError {}
