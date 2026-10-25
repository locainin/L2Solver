use super::syntax::{ScannedLine, is_token_byte, line_range};
use super::{
    consume_entry,
    headers::parse_header,
    model::{ChunkScan, HttpHeader, HttpLineEnding},
};
use crate::application::{ByteRange, MAX_HTTP_HEADER_BYTES, ParseStatus, ParserBudget};

pub(super) fn scan_chunked(bytes: &[u8], start: usize, budget: &mut usize) -> ChunkScan {
    let mut cursor = start;
    let mut chunks = Vec::new();
    let trailers = Vec::new();

    loop {
        let (chunk_line, chunk_size) = match next_chunk_line(bytes, cursor, budget) {
            Ok(chunk) => chunk,
            Err(error) => {
                return incomplete_chunk_scan(
                    chunks,
                    trailers,
                    cursor,
                    bytes.len(),
                    error.status,
                    error.budget,
                );
            }
        };
        let data_start = chunk_line.next_offset();

        if chunk_size == 0 {
            return scan_terminal_chunk(bytes, data_start, chunks, trailers, budget);
        }
        match chunk_data(bytes, data_start, chunk_size) {
            Ok((range, next)) => {
                chunks.push(range);
                cursor = next;
            }
            Err(status) => {
                return incomplete_chunk_scan(
                    chunks,
                    trailers,
                    chunk_line.range.offset,
                    bytes.len(),
                    status,
                    None,
                );
            }
        }
    }
}

fn next_chunk_line(
    bytes: &[u8],
    cursor: usize,
    budget: &mut usize,
) -> Result<(ScannedLine, usize), ChunkLineError> {
    if cursor == bytes.len() {
        return Err(ChunkLineError::new(ParseStatus::Incomplete, None));
    }
    if !consume_entry(budget) {
        return Err(ChunkLineError::new(
            ParseStatus::Unsupported,
            Some(ParserBudget::Entries),
        ));
    }
    let line = line_range(bytes, cursor)
        .map_err(|error| ChunkLineError::new(error.status, error.budget))?;
    if line.ending != HttpLineEnding::CrLf {
        return Err(ChunkLineError::new(ParseStatus::Unsupported, None));
    }
    let bytes = line
        .range
        .slice(bytes)
        .ok_or_else(|| ChunkLineError::new(ParseStatus::Incomplete, None))?;
    let size = parse_chunk_size(bytes)
        .ok_or_else(|| ChunkLineError::new(ParseStatus::Unsupported, None))?;
    Ok((line, size))
}

struct ChunkLineError {
    status: ParseStatus,
    budget: Option<ParserBudget>,
}

impl ChunkLineError {
    const fn new(status: ParseStatus, budget: Option<ParserBudget>) -> Self {
        Self { status, budget }
    }
}

fn scan_terminal_chunk(
    bytes: &[u8],
    trailer_start: usize,
    chunks: Vec<ByteRange>,
    mut trailers: Vec<HttpHeader>,
    budget: &mut usize,
) -> ChunkScan {
    let mut cursor = trailer_start;
    match scan_trailers(bytes, trailer_start, &mut cursor, &mut trailers, budget) {
        Ok(()) => ChunkScan {
            chunks,
            trailers,
            trailer_range: Some(ByteRange::new(trailer_start, cursor - trailer_start)),
            raw_remainder: None,
            next_offset: cursor,
            status: ParseStatus::Complete,
            budget: None,
            complete: true,
        },
        Err(error) => incomplete_chunk_scan(
            chunks,
            trailers,
            error.raw_start,
            bytes.len(),
            error.status,
            error.budget,
        ),
    }
}

fn chunk_data(
    bytes: &[u8],
    data_start: usize,
    length: usize,
) -> Result<(ByteRange, usize), ParseStatus> {
    let data_end = data_start
        .checked_add(length)
        .ok_or(ParseStatus::Unsupported)?;
    if data_end > bytes.len() {
        return Err(ParseStatus::Incomplete);
    }
    let next = data_end.checked_add(2).ok_or(ParseStatus::Unsupported)?;
    if next > bytes.len() {
        return Err(ParseStatus::Incomplete);
    }
    if bytes.get(data_end..next) != Some(b"\r\n") {
        return Err(ParseStatus::Unsupported);
    }
    Ok((ByteRange::new(data_start, length), next))
}

fn scan_trailers(
    bytes: &[u8],
    start: usize,
    cursor: &mut usize,
    trailers: &mut Vec<HttpHeader>,
    budget: &mut usize,
) -> Result<(), ChunkError> {
    loop {
        let raw_start = *cursor;
        let line_scan = line_range(bytes, raw_start).map_err(|error| ChunkError {
            status: error.status,
            raw_start,
            budget: error.budget,
        })?;
        if line_scan.ending != HttpLineEnding::CrLf {
            return Err(ChunkError {
                status: ParseStatus::Unsupported,
                raw_start,
                budget: None,
            });
        }
        let Some(line) = line_scan.range.slice(bytes) else {
            return Err(ChunkError {
                status: ParseStatus::Incomplete,
                raw_start,
                budget: None,
            });
        };
        *cursor = line_scan.next_offset();
        if *cursor - start > MAX_HTTP_HEADER_BYTES {
            return Err(ChunkError {
                status: ParseStatus::Unsupported,
                raw_start,
                budget: Some(ParserBudget::HeaderBytes),
            });
        }
        if line.is_empty() {
            return Ok(());
        }
        if !consume_entry(budget) {
            return Err(ChunkError {
                status: ParseStatus::Unsupported,
                raw_start,
                budget: Some(ParserBudget::Entries),
            });
        }
        let Some(header) = parse_header(line_scan.range, line) else {
            return Err(ChunkError {
                status: ParseStatus::Unsupported,
                raw_start,
                budget: None,
            });
        };
        trailers.push(header);
    }
}

struct ChunkError {
    status: ParseStatus,
    raw_start: usize,
    budget: Option<ParserBudget>,
}

fn parse_chunk_size(line: &[u8]) -> Option<usize> {
    let size_end = line
        .iter()
        .position(|byte| *byte == b';')
        .map_or(line.len(), |index| index);
    let digits = line.get(..size_end)?;
    if digits.is_empty() || !valid_chunk_extension(line.get(size_end..)?) {
        return None;
    }
    digits.iter().try_fold(0_usize, |value, digit| {
        let nibble = match digit {
            b'0'..=b'9' => usize::from(digit - b'0'),
            b'a'..=b'f' => usize::from(digit - b'a' + 10),
            b'A'..=b'F' => usize::from(digit - b'A' + 10),
            _ => return None,
        };
        value.checked_mul(16)?.checked_add(nibble)
    })
}

fn valid_chunk_extension(extension: &[u8]) -> bool {
    if extension.is_empty() {
        return true;
    }
    let mut cursor = 0;
    loop {
        skip_ows(extension, &mut cursor);
        if cursor == extension.len() || extension.get(cursor) != Some(&b';') {
            return false;
        }
        cursor += 1;
        skip_ows(extension, &mut cursor);
        let name_start = cursor;
        while extension
            .get(cursor)
            .is_some_and(|byte| is_token_byte(*byte))
        {
            cursor += 1;
        }
        if cursor == name_start {
            return false;
        }
        let before_ows = cursor;
        skip_ows(extension, &mut cursor);
        if extension.get(cursor) == Some(&b'=') {
            cursor += 1;
            skip_ows(extension, &mut cursor);
            if extension.get(cursor) == Some(&b'"') {
                let Some(next) = quoted_string_end(extension, cursor) else {
                    return false;
                };
                cursor = next;
            } else {
                let value_start = cursor;
                while extension
                    .get(cursor)
                    .is_some_and(|byte| is_token_byte(*byte))
                {
                    cursor += 1;
                }
                if cursor == value_start {
                    return false;
                }
            }
        } else if cursor == extension.len() && cursor != before_ows {
            // Whitespace can precede another extension or an equals sign
            return false;
        }
        if cursor == extension.len() {
            return true;
        }
    }
}

fn skip_ows(bytes: &[u8], cursor: &mut usize) {
    while bytes
        .get(*cursor)
        .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
    {
        *cursor += 1;
    }
}

fn quoted_string_end(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start) != Some(&b'"') {
        return None;
    }
    let mut cursor = start + 1;
    while let Some(byte) = bytes.get(cursor).copied() {
        match byte {
            b'"' => return Some(cursor + 1),
            b'\\' => {
                cursor += 1;
                let escaped = *bytes.get(cursor)?;
                if !is_quoted_pair_byte(escaped) {
                    return None;
                }
            }
            _ if !is_quoted_text_byte(byte) => return None,
            _ => {}
        }
        cursor += 1;
    }
    None
}

fn is_quoted_text_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b' ' | b'!')
        || (b'#'..=b'[').contains(&byte)
        || (b']'..=b'~').contains(&byte)
        || byte >= 0x80
}

fn is_quoted_pair_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b' ') || (b'!'..=b'~').contains(&byte) || byte >= 0x80
}

const fn incomplete_chunk_scan(
    chunks: Vec<ByteRange>,
    trailers: Vec<HttpHeader>,
    remainder_start: usize,
    input_end: usize,
    status: ParseStatus,
    budget: Option<ParserBudget>,
) -> ChunkScan {
    ChunkScan {
        chunks,
        trailers,
        trailer_range: None,
        raw_remainder: Some(ByteRange::new(remainder_start, input_end - remainder_start)),
        next_offset: input_end,
        status,
        budget,
        complete: false,
    }
}
