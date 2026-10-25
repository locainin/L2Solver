use super::ProtocolError;
use std::{error::Error, fmt};

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_analysis_error(self, formatter)
            .or_else(|| format_stream_error(self, formatter))
            .unwrap_or(Err(fmt::Error))
    }
}

fn format_analysis_error(
    error: &ProtocolError,
    formatter: &mut fmt::Formatter<'_>,
) -> Option<fmt::Result> {
    Some(match error {
        ProtocolError::InsufficientSamples { count } => write!(
            formatter,
            "protocol analysis needs at least four samples; received {count}"
        ),
        ProtocolError::InsufficientRuns { count } => write!(
            formatter,
            "framing bootstrap needs at least one contiguous run; received {count}"
        ),
        ProtocolError::TooManySamples { count, maximum } => {
            write!(formatter, "protocol sample count {count} exceeds {maximum}")
        }
        ProtocolError::TooManyCandidates { count, maximum } => write!(
            formatter,
            "protocol candidate count {count} exceeds {maximum}"
        ),
        ProtocolError::IncompleteContext { sample } => write!(
            formatter,
            "sample {sample} lacks the complete context supplied by other samples"
        ),
        ProtocolError::InsufficientSessionGroups { count } => write!(
            formatter,
            "protocol holdout needs at least two complete sessions; received {count}"
        ),
        ProtocolError::InvalidContext { sample } => write!(
            formatter,
            "sample {sample} has an invalid source, scope, or session context"
        ),
        ProtocolError::InvalidSourceIdentity | ProtocolError::InvalidBoundaryRange { .. } => {
            return Some(format_reconstructed_source_error(error, formatter));
        }
        ProtocolError::MessageTooLarge { .. }
        | ProtocolError::TotalBytesTooLarge { .. }
        | ProtocolError::RunTooLarge { .. } => {
            return Some(format_input_size_error(error, formatter));
        }
        ProtocolError::InvalidSampleId { sample } => {
            write!(formatter, "sample identifier {sample} is zero or repeated")
        }
        ProtocolError::InvalidFieldWidth { width, maximum } => write!(
            formatter,
            "field width {width} must be between 1 and {maximum}"
        ),
        ProtocolError::InvalidFieldRange {
            offset,
            width,
            maximum,
        } => write!(
            formatter,
            "field {offset}+{width} exceeds the message boundary {maximum}"
        ),
        ProtocolError::InvalidLimits => formatter.write_str("protocol budgets must be positive"),
        ProtocolError::AllocationFailed => {
            formatter.write_str("protocol report could not allocate retained candidate ranges")
        }
        ProtocolError::NoFramingCandidates => {
            formatter.write_str("at least one framing candidate is required")
        }
        ProtocolError::InvalidFramingCandidate => {
            formatter.write_str("framing candidates must be valid and distinct")
        }
        ProtocolError::ParserFinalized
        | ProtocolError::InvalidParserState
        | ProtocolError::OutOfOrderChunk { .. }
        | ProtocolError::IncompleteSourceMap
        | ProtocolError::StreamOffsetOverflow => return None,
    })
}

fn format_input_size_error(
    error: &ProtocolError,
    formatter: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    match error {
        ProtocolError::MessageTooLarge {
            sample,
            length,
            maximum,
        } => write!(
            formatter,
            "sample {sample} has {length} bytes; maximum is {maximum}"
        ),
        ProtocolError::TotalBytesTooLarge { total, maximum } => write!(
            formatter,
            "protocol analysis budget {total} exceeds {maximum}"
        ),
        ProtocolError::RunTooLarge {
            sample,
            length,
            maximum,
        } => write!(
            formatter,
            "run sample {sample} has {length} bytes; scan limit is {maximum}"
        ),
        _ => Err(fmt::Error),
    }
}

fn format_reconstructed_source_error(
    error: &ProtocolError,
    formatter: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    match error {
        ProtocolError::InvalidSourceIdentity => {
            formatter.write_str("reconstructed framing needs a nonempty source identity")
        }
        ProtocolError::InvalidBoundaryRange {
            start,
            end,
            run_length,
        } => write!(
            formatter,
            "source mapping interval {start}..{end} is outside the reconstructed run of length {run_length}"
        ),
        _ => Err(fmt::Error),
    }
}

fn format_stream_error(
    error: &ProtocolError,
    formatter: &mut fmt::Formatter<'_>,
) -> Option<fmt::Result> {
    Some(match error {
        ProtocolError::ParserFinalized => formatter.write_str("stream message parser is finalized"),
        ProtocolError::InvalidParserState => {
            formatter.write_str("stream message parser checkpoint is inconsistent")
        }
        ProtocolError::OutOfOrderChunk {
            offset,
            next_offset,
        } => write!(
            formatter,
            "stream chunk starts at {offset}; expected offset {next_offset}"
        ),
        ProtocolError::IncompleteSourceMap => {
            formatter.write_str("source ranges do not cover every supplied stream byte")
        }
        ProtocolError::StreamOffsetOverflow => {
            formatter.write_str("stream offset or length cannot be represented")
        }
        ProtocolError::InsufficientSamples { .. }
        | ProtocolError::InsufficientRuns { .. }
        | ProtocolError::TooManySamples { .. }
        | ProtocolError::TooManyCandidates { .. }
        | ProtocolError::IncompleteContext { .. }
        | ProtocolError::InsufficientSessionGroups { .. }
        | ProtocolError::InvalidContext { .. }
        | ProtocolError::InvalidSourceIdentity
        | ProtocolError::InvalidBoundaryRange { .. }
        | ProtocolError::MessageTooLarge { .. }
        | ProtocolError::TotalBytesTooLarge { .. }
        | ProtocolError::RunTooLarge { .. }
        | ProtocolError::InvalidSampleId { .. }
        | ProtocolError::InvalidFieldWidth { .. }
        | ProtocolError::InvalidFieldRange { .. }
        | ProtocolError::InvalidLimits
        | ProtocolError::AllocationFailed
        | ProtocolError::NoFramingCandidates
        | ProtocolError::InvalidFramingCandidate => return None,
    })
}

impl Error for ProtocolError {}
