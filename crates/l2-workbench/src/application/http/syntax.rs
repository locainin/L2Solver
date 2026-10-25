use super::model::HttpLineEnding;
use crate::application::{ByteRange, MAX_LINE_BYTES, ParseStatus, ParserBudget};

pub(super) struct LineError {
    pub status: ParseStatus,
    pub budget: Option<ParserBudget>,
}

pub(super) struct ScannedLine {
    pub range: ByteRange,
    pub ending: HttpLineEnding,
}

impl ScannedLine {
    pub const fn next_offset(&self) -> usize {
        self.range.offset + self.range.length + self.ending.length()
    }
}

pub(super) fn line_range(bytes: &[u8], start: usize) -> Result<ScannedLine, LineError> {
    let remaining = bytes.get(start..).ok_or(LineError {
        status: ParseStatus::Unsupported,
        budget: None,
    })?;
    let scan_length = remaining.len().min(MAX_LINE_BYTES + 2);
    let scan = remaining.get(..scan_length).ok_or(LineError {
        status: ParseStatus::Unsupported,
        budget: None,
    })?;
    let line_feed = scan.iter().position(|byte| *byte == b'\n');
    let (prefix, _) = scan.split_at(line_feed.unwrap_or(scan.len()));
    // A CR can begin a delimiter only at the captured tail or before a known LF
    let content = if line_feed.is_some()
        || scan.len() == remaining.len()
        || remaining.get(scan.len()) == Some(&b'\n')
    {
        prefix.strip_suffix(b"\r").unwrap_or(prefix)
    } else {
        prefix
    };
    if content.iter().any(|byte| invalid_field_value(*byte)) {
        return Err(LineError {
            status: ParseStatus::Unsupported,
            budget: None,
        });
    }
    if let Some(line_feed_offset) = line_feed {
        let ending = if line_feed_offset > 0 && scan.get(line_feed_offset - 1) == Some(&b'\r') {
            HttpLineEnding::CrLf
        } else {
            HttpLineEnding::Lf
        };
        let line_length = line_feed_offset - usize::from(ending == HttpLineEnding::CrLf);
        if line_length > MAX_LINE_BYTES {
            return Err(LineError {
                status: ParseStatus::Unsupported,
                budget: Some(ParserBudget::LineBytes),
            });
        }
        return Ok(ScannedLine {
            range: ByteRange::new(start, line_length),
            ending,
        });
    }
    if content.len() > MAX_LINE_BYTES {
        Err(LineError {
            status: ParseStatus::Unsupported,
            budget: Some(ParserBudget::LineBytes),
        })
    } else {
        Err(LineError {
            status: ParseStatus::Incomplete,
            budget: None,
        })
    }
}

const fn invalid_field_value(byte: u8) -> bool {
    byte < 0x20 && byte != b'\t' || byte == 0x7f
}

impl HttpLineEnding {
    const fn length(self) -> usize {
        match self {
            Self::CrLf => 2,
            Self::Lf => 1,
        }
    }
}

pub(super) fn trim_ows(bytes: &[u8]) -> (usize, usize) {
    let start = bytes
        .iter()
        .position(|byte| !matches!(*byte, b' ' | b'\t'))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !matches!(*byte, b' ' | b'\t'))
        .map_or(start, |index| index + 1);
    (start, end.saturating_sub(start))
}

pub(super) fn valid_token(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|byte| is_token_byte(*byte))
}

pub(super) const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}
