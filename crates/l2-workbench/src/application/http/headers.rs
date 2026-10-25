use super::{
    consume_entry,
    model::{BodyPolicy, HeadScan, HttpHeader, HttpRequestMethod, HttpStart},
    syntax::{LineError, line_range, trim_ows, valid_token},
};
use crate::application::{ByteRange, MAX_HTTP_HEADER_BYTES, ParseStatus, ParserBudget};

pub(super) struct HeaderError {
    pub status: ParseStatus,
    pub range: ByteRange,
    pub budget: Option<ParserBudget>,
}

pub(super) fn scan_head(
    bytes: &[u8],
    start: usize,
    budget: &mut usize,
) -> Result<HeadScan, HeaderError> {
    let start_line_scan =
        line_range(bytes, start).map_err(|error| tail_error(bytes.len(), start, &error))?;
    let start_line = start_line_scan.range;
    let line_ending = start_line_scan.ending;
    let start_line_bytes = start_line
        .slice(bytes)
        .ok_or_else(|| unsupported_tail(bytes, start, ParseStatus::Unsupported))?;
    let start_kind = parse_start_line(start_line, start_line_bytes)
        .ok_or_else(|| unsupported_tail(bytes, start, ParseStatus::Unsupported))?;
    let mut cursor = start_line_scan.next_offset();
    let mut headers = Vec::new();

    loop {
        if cursor - start > MAX_HTTP_HEADER_BYTES {
            return Err(limited_tail_error(
                bytes,
                start,
                ParseStatus::Unsupported,
                ParserBudget::HeaderBytes,
            ));
        }
        let field_scan =
            line_range(bytes, cursor).map_err(|error| tail_error(bytes.len(), start, &error))?;
        if field_scan.ending != line_ending {
            return Err(unsupported_tail(bytes, start, ParseStatus::Unsupported));
        }
        let field_range = field_scan.range;
        let Some(line) = field_range.slice(bytes) else {
            return Err(unsupported_tail(bytes, start, ParseStatus::Unsupported));
        };
        cursor = field_scan.next_offset();
        if cursor - start > MAX_HTTP_HEADER_BYTES {
            return Err(limited_tail_error(
                bytes,
                start,
                ParseStatus::Unsupported,
                ParserBudget::HeaderBytes,
            ));
        }
        if line.is_empty() {
            return Ok(HeadScan {
                line_ending,
                start_line,
                start: start_kind,
                headers,
                body_offset: cursor,
            });
        }
        if !consume_entry(budget) {
            return Err(limited_tail_error(
                bytes,
                start,
                ParseStatus::Unsupported,
                ParserBudget::Entries,
            ));
        }
        let Some(header) = parse_header(field_range, line) else {
            return Err(unsupported_tail(bytes, start, ParseStatus::Unsupported));
        };
        headers.push(header);
    }
}

pub(super) fn body_policy(
    bytes: &[u8],
    head: &HeadScan,
    request_method: Option<HttpRequestMethod>,
) -> BodyPolicy {
    if let HttpStart::Response { status_code } = head.start {
        if let Some(method) = request_method {
            if method == HttpRequestMethod::Connect && (200..=299).contains(&status_code) {
                return BodyPolicy::Tunnel(no_body_status(bytes, head, method));
            }
            if method == HttpRequestMethod::Head {
                return BodyPolicy::NoBody(no_body_status(bytes, head, method));
            }
        } else if !response_has_no_body(head.start) {
            return BodyPolicy::Ambiguous;
        }
    }
    if response_has_no_body(head.start) {
        return BodyPolicy::NoBody(no_body_status(bytes, head, HttpRequestMethod::Other));
    }
    let mut content_length_seen = false;
    let mut transfer_encoding_seen = false;
    for header in &head.headers {
        if header_name(bytes, header, b"content-length") {
            content_length_seen = true;
        }
        if header_name(bytes, header, b"transfer-encoding") {
            transfer_encoding_seen = true;
        }
    }
    if content_length_seen && transfer_encoding_seen {
        return BodyPolicy::Ambiguous;
    }
    if transfer_encoding_seen {
        return transfer_policy(bytes, head);
    }
    if content_length_seen {
        return parse_content_length(bytes, head)
            .map_or(BodyPolicy::Ambiguous, BodyPolicy::ContentLength);
    }
    match head.start {
        HttpStart::Request { .. } => BodyPolicy::NoBody(ParseStatus::Complete),
        HttpStart::Response { .. } => BodyPolicy::CloseDelimited,
    }
}

fn no_body_status(bytes: &[u8], head: &HeadScan, request_method: HttpRequestMethod) -> ParseStatus {
    let has_content_length = head
        .headers
        .iter()
        .any(|header| header_name(bytes, header, b"content-length"));
    let has_transfer_encoding = head
        .headers
        .iter()
        .any(|header| header_name(bytes, header, b"transfer-encoding"));
    let forbidden_fields = match head.start {
        HttpStart::Response { status_code } => {
            ((100..=199).contains(&status_code) || status_code == 204)
                && (has_content_length || has_transfer_encoding)
                || request_method == HttpRequestMethod::Connect
                    && (200..=299).contains(&status_code)
                    && (has_content_length || has_transfer_encoding)
        }
        HttpStart::Request { .. } => false,
    };
    if forbidden_fields
        || has_content_length && has_transfer_encoding
        || has_content_length && parse_content_length(bytes, head).is_none()
        || has_transfer_encoding && transfer_policy(bytes, head) == BodyPolicy::Unsupported
    {
        ParseStatus::Unsupported
    } else {
        ParseStatus::Complete
    }
}

pub(super) fn parse_header(range: ByteRange, line: &[u8]) -> Option<HttpHeader> {
    if line
        .first()
        .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
    {
        return None;
    }
    let colon = line.iter().position(|byte| *byte == b':')?;
    let name = line.get(..colon)?;
    let raw_value_start = colon.checked_add(1)?;
    let raw_value = line.get(raw_value_start..)?;
    // The line scanner already rejected forbidden control bytes in the value
    if !valid_token(name) {
        return None;
    }
    let (trimmed_start, trimmed_length) = trim_ows(raw_value);
    let value_offset = range
        .offset
        .checked_add(raw_value_start)?
        .checked_add(trimmed_start)?;
    Some(HttpHeader {
        range,
        name: ByteRange::new(range.offset, colon),
        value: ByteRange::new(value_offset, trimmed_length),
    })
}

fn parse_start_line(range: ByteRange, line: &[u8]) -> Option<HttpStart> {
    if line.starts_with(b"HTTP/") {
        return parse_response_line(line);
    }
    parse_request_line(range, line)
}

fn parse_request_line(range: ByteRange, line: &[u8]) -> Option<HttpStart> {
    let first_space = line.iter().position(|byte| *byte == b' ')?;
    let after_first = first_space.checked_add(1)?;
    let rest = line.get(after_first..)?;
    let second_space = rest.iter().position(|byte| *byte == b' ')?;
    let method = line.get(..first_space)?;
    let target = rest.get(..second_space)?;
    let version_start = after_first.checked_add(second_space)?.checked_add(1)?;
    let version = line.get(version_start..)?;
    if !valid_token(method)
        || target.is_empty()
        || target
            .iter()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        || !valid_http_version(version)
    {
        return None;
    }
    Some(HttpStart::Request {
        method: ByteRange::new(range.offset, method.len()),
        target: ByteRange::new(range.offset + after_first, target.len()),
    })
}

fn parse_response_line(line: &[u8]) -> Option<HttpStart> {
    let first_space = line.iter().position(|byte| *byte == b' ')?;
    let version = line.get(..first_space)?;
    let rest = line.get(first_space.checked_add(1)?..)?;
    if !valid_http_version(version) {
        return None;
    }
    let status = rest.get(..3)?;
    // The separator remains required when the reason phrase is empty
    if !status.iter().all(u8::is_ascii_digit) || rest.get(3) != Some(&b' ') {
        return None;
    }
    if rest.get(4..).is_some_and(|reason| {
        reason
            .iter()
            .any(|byte| *byte != b'\t' && (*byte < b' ' || *byte == 0x7f))
    }) {
        return None;
    }
    let hundreds = u16::from(status.first().copied()?.checked_sub(b'0')?);
    let tens = u16::from(status.get(1).copied()?.checked_sub(b'0')?);
    let ones = u16::from(status.get(2).copied()?.checked_sub(b'0')?);
    let status_code = hundreds * 100 + tens * 10 + ones;
    (100..=599)
        .contains(&status_code)
        .then_some(HttpStart::Response { status_code })
}

fn parse_content_length(bytes: &[u8], head: &HeadScan) -> Option<usize> {
    let mut expected = None;
    for header in &head.headers {
        if !header_name(bytes, header, b"content-length") {
            continue;
        }
        let value = header.value.slice(bytes)?;
        for item in value.split(|byte| *byte == b',') {
            let (start, length) = trim_ows(item);
            let number = decimal(item.get(start..start.checked_add(length)?)?)?;
            if expected.is_some_and(|prior| prior != number) {
                return None;
            }
            expected = Some(number);
        }
    }
    expected
}

fn transfer_policy(bytes: &[u8], head: &HeadScan) -> BodyPolicy {
    let mut count = 0_usize;
    let mut chunked_count = 0_usize;
    let mut last_is_chunked = false;
    for header in &head.headers {
        if !header_name(bytes, header, b"transfer-encoding") {
            continue;
        }
        let Some(value) = header.value.slice(bytes) else {
            return BodyPolicy::Unsupported;
        };
        for coding in value.split(|byte| *byte == b',') {
            let (start, length) = trim_ows(coding);
            let Some(end) = start.checked_add(length) else {
                return BodyPolicy::Unsupported;
            };
            let Some(name) = coding.get(start..end) else {
                return BodyPolicy::Unsupported;
            };
            if !valid_token(name) {
                return BodyPolicy::Unsupported;
            }
            count += 1;
            last_is_chunked = name.eq_ignore_ascii_case(b"chunked");
            chunked_count += usize::from(last_is_chunked);
        }
    }
    if chunked_count > 1 {
        return BodyPolicy::Unsupported;
    }
    match (count, chunked_count, last_is_chunked, head.start) {
        (0, _, _, _) => BodyPolicy::Unsupported,
        (_, 1, true, _) => BodyPolicy::Chunked,
        (_, _, _, HttpStart::Response { .. }) => BodyPolicy::CloseDelimited,
        _ => BodyPolicy::Unsupported,
    }
}

fn header_name(bytes: &[u8], header: &HttpHeader, expected: &[u8]) -> bool {
    header
        .name
        .slice(bytes)
        .is_some_and(|name| name.eq_ignore_ascii_case(expected))
}

const fn response_has_no_body(start: HttpStart) -> bool {
    matches!(
        start,
        HttpStart::Response {
            status_code: 100..=199 | 204 | 304
        }
    )
}

fn valid_http_version(bytes: &[u8]) -> bool {
    bytes == b"HTTP/1.0" || bytes == b"HTTP/1.1"
}

fn decimal(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }
    bytes.iter().try_fold(0_usize, |value, digit| {
        if !digit.is_ascii_digit() {
            return None;
        }
        value
            .checked_mul(10)?
            .checked_add(usize::from(digit - b'0'))
    })
}

const fn tail_error(input_length: usize, start: usize, error: &LineError) -> HeaderError {
    HeaderError {
        status: error.status,
        range: ByteRange::new(start, input_length - start),
        budget: error.budget,
    }
}

const fn limited_tail_error(
    bytes: &[u8],
    start: usize,
    status: ParseStatus,
    budget: ParserBudget,
) -> HeaderError {
    HeaderError {
        status,
        range: ByteRange::new(start, bytes.len() - start),
        budget: Some(budget),
    }
}

const fn unsupported_tail(bytes: &[u8], start: usize, status: ParseStatus) -> HeaderError {
    HeaderError {
        status,
        range: ByteRange::new(start, bytes.len() - start),
        budget: None,
    }
}
