//! FTP control-line facts and advertised data endpoints

pub mod association;

pub use association::{FtpControlEvent, FtpDataMode};

use super::{
    ByteRange, MAX_ENTRIES, MAX_INPUT_BYTES, MAX_LINE_BYTES, ParseContext, ParseReport,
    ParseStatus, ParserBudget, empty_report, finish_report, record_omission, record_status,
    unsupported_input,
};
use l2_discovery::NetworkAddress;
use serde::Serialize;
use std::net::{Ipv4Addr, Ipv6Addr};

const MAX_REPLY_BYTES: usize = 32_768;
const MAX_COMMAND_VERB_BYTES: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FtpItem {
    pub range: ByteRange,
    pub status: ParseStatus,
    pub kind: FtpKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum FtpKind {
    Command(FtpCommand),
    Reply(FtpReply),
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FtpCommand {
    pub verb_range: ByteRange,
    pub argument_range: Option<ByteRange>,
    pub action: FtpCommandAction,
    pub endpoint: Option<FtpEndpoint>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FtpCommandAction {
    Retrieve,
    Store,
    Passive,
    ExtendedPassive,
    ActiveEndpoint,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FtpReply {
    pub code: u16,
    pub text_range: ByteRange,
    pub multiline: bool,
    pub endpoint: Option<FtpEndpoint>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct FtpEndpoint {
    /// EPSV reports only a port; its address comes from the control peer
    pub address: Option<NetworkAddress>,
    pub port: u16,
}

/// Parse CRLF-delimited FTP control candidates without executing commands
#[must_use]
pub fn decode_ftp(bytes: &[u8], context: ParseContext) -> ParseReport<FtpItem> {
    if bytes.len() > MAX_INPUT_BYTES {
        return unsupported_input(bytes);
    }
    let mut report = empty_report();
    let mut cursor = 0;

    while cursor < bytes.len() {
        if report.findings.len() == MAX_ENTRIES {
            record_omission(
                &mut report,
                ParserBudget::Entries,
                ByteRange::new(cursor, bytes.len() - cursor),
            );
            record_status(&mut report, ParseStatus::Unsupported);
            break;
        }
        match parse_item(bytes, cursor) {
            Ok((item, next, budget)) => {
                if let Some(budget) = budget {
                    record_omission(&mut report, budget, item.range);
                }
                record_status(&mut report, item.status);
                report.findings.push(item);
                cursor = next;
            }
            Err(error) => {
                if let Some(budget) = error.budget {
                    record_omission(&mut report, budget, error.range);
                } else {
                    report.unparsed.push(error.range);
                }
                record_status(&mut report, error.status);
                cursor = bytes.len();
            }
        }
    }
    finish_report(report, context, set_item_status, |item| item.status)
}

struct ParseError {
    status: ParseStatus,
    range: ByteRange,
    budget: Option<ParserBudget>,
}

fn parse_item(
    bytes: &[u8],
    start: usize,
) -> Result<(FtpItem, usize, Option<ParserBudget>), ParseError> {
    let line = line_range(bytes, start).map_err(|mut error| {
        if error.budget == Some(ParserBudget::LineBytes)
            && bytes.get(start..).is_some_and(|tail| {
                let (prefix, _) = tail.split_at(tail.len().min(MAX_COMMAND_VERB_BYTES + 1));
                reply_prefix(prefix).is_none() && command_verb(prefix).is_none()
            })
        {
            // A bounded prefix can already rule out both supported line forms
            error.budget = None;
        }
        error
    })?;
    let Some(line_bytes) = line.slice(bytes) else {
        return Err(tail_error(bytes, start, ParseStatus::Unsupported));
    };
    if contains_control(line_bytes) {
        return Err(tail_error(bytes, start, ParseStatus::Unsupported));
    }
    let next = line.offset + line.length + 2;
    if let Some((code, separator)) = reply_prefix(line_bytes) {
        return Ok(parse_reply(bytes, start, line, code, separator, next));
    }
    let item = parse_command(bytes, line, line_bytes);
    Ok((item, next, None))
}

fn parse_reply(
    bytes: &[u8],
    start: usize,
    first_line: ByteRange,
    code: u16,
    separator: u8,
    next: usize,
) -> (FtpItem, usize, Option<ParserBudget>) {
    let scan = if separator == b'-' {
        scan_multiline(bytes, start, first_line, code, next)
    } else {
        ReplyScan {
            range: ByteRange::new(start, next - start),
            text_range: ByteRange::new(first_line.offset + 4, first_line.length - 4),
            next,
            multiline: false,
            status: ParseStatus::Complete,
            budget: None,
        }
    };
    let endpoint_result = if scan.status == ParseStatus::Complete && matches!(code, 227 | 229) {
        parse_passive_endpoint(bytes, scan.range, code)
    } else {
        Ok(None)
    };
    let (endpoint, final_status) = match endpoint_result {
        Ok(endpoint) => (endpoint, scan.status),
        Err(error_status) => (None, error_status),
    };
    let item = FtpItem {
        range: scan.range,
        status: final_status,
        kind: FtpKind::Reply(FtpReply {
            code,
            text_range: scan.text_range,
            multiline: scan.multiline,
            endpoint,
        }),
    };
    (item, scan.next, scan.budget)
}

struct ReplyScan {
    range: ByteRange,
    text_range: ByteRange,
    next: usize,
    multiline: bool,
    status: ParseStatus,
    budget: Option<ParserBudget>,
}

fn scan_multiline(
    bytes: &[u8],
    start: usize,
    first_line: ByteRange,
    code: u16,
    mut cursor: usize,
) -> ReplyScan {
    let text_start = first_line.offset + 4;
    let mut line_count = 1;
    loop {
        if cursor == bytes.len() {
            return incomplete_reply_scan(bytes, start, text_start, ParseStatus::Incomplete, None);
        }
        if line_count >= MAX_ENTRIES {
            return incomplete_reply_scan(
                bytes,
                start,
                text_start,
                ParseStatus::Unsupported,
                Some(ParserBudget::Entries),
            );
        }
        let next_line = match line_range(bytes, cursor) {
            Ok(range) => range,
            Err(error) => {
                return incomplete_reply_scan(bytes, start, text_start, error.status, error.budget);
            }
        };
        let Some(next_bytes) = next_line.slice(bytes) else {
            return incomplete_reply_scan(bytes, start, text_start, ParseStatus::Unsupported, None);
        };
        let next_cursor = next_line.offset + next_line.length + 2;
        if next_cursor - start > MAX_REPLY_BYTES {
            return incomplete_reply_scan(
                bytes,
                start,
                text_start,
                ParseStatus::Unsupported,
                Some(ParserBudget::ReplyBytes),
            );
        }
        if contains_control(next_bytes) {
            return incomplete_reply_scan(bytes, start, text_start, ParseStatus::Unsupported, None);
        }
        line_count += 1;
        if response_terminates(next_bytes, code) {
            return ReplyScan {
                range: ByteRange::new(start, next_cursor - start),
                text_range: ByteRange::new(text_start, next_cursor - text_start),
                next: next_cursor,
                multiline: true,
                status: ParseStatus::Complete,
                budget: None,
            };
        }
        cursor = next_cursor;
    }
}

const fn incomplete_reply_scan(
    bytes: &[u8],
    start: usize,
    text_start: usize,
    status: ParseStatus,
    budget: Option<ParserBudget>,
) -> ReplyScan {
    ReplyScan {
        range: ByteRange::new(start, bytes.len() - start),
        text_range: ByteRange::new(text_start, bytes.len() - text_start),
        next: bytes.len(),
        multiline: true,
        status,
        budget,
    }
}

fn parse_command(bytes: &[u8], line: ByteRange, line_bytes: &[u8]) -> FtpItem {
    let Some(verb) = command_verb(line_bytes) else {
        return other_item(line, ParseStatus::Complete);
    };
    let verb_end = verb.len();
    let argument_range = if verb_end < line_bytes.len() {
        Some(ByteRange::new(
            line.offset + verb_end + 1,
            line.length - verb_end - 1,
        ))
    } else {
        None
    };
    let argument = argument_range.and_then(|range| range.slice(bytes));
    let (action, endpoint, status) = command_action(verb, argument);
    FtpItem {
        range: ByteRange::new(line.offset, line.length + 2),
        status,
        kind: FtpKind::Command(FtpCommand {
            verb_range: ByteRange::new(line.offset, verb.len()),
            argument_range,
            action,
            endpoint,
        }),
    }
}

fn command_verb(line: &[u8]) -> Option<&[u8]> {
    let verb_end = line
        .iter()
        .position(|byte| *byte == b' ')
        .unwrap_or(line.len());
    let (verb, _) = line.split_at(verb_end);
    (!verb.is_empty()
        && verb.len() <= MAX_COMMAND_VERB_BYTES
        && verb.iter().all(u8::is_ascii_alphabetic))
    .then_some(verb)
}

fn command_action(
    verb: &[u8],
    argument: Option<&[u8]>,
) -> (FtpCommandAction, Option<FtpEndpoint>, ParseStatus) {
    if verb.eq_ignore_ascii_case(b"RETR") {
        return transfer_action(argument, FtpCommandAction::Retrieve);
    }
    if verb.eq_ignore_ascii_case(b"STOR") {
        return transfer_action(argument, FtpCommandAction::Store);
    }
    if verb.eq_ignore_ascii_case(b"PASV") {
        return no_argument_action(argument, FtpCommandAction::Passive);
    }
    if verb.eq_ignore_ascii_case(b"EPSV") {
        return (
            FtpCommandAction::ExtendedPassive,
            None,
            ParseStatus::Complete,
        );
    }
    if verb.eq_ignore_ascii_case(b"PORT") {
        return active_action(argument, parse_port);
    }
    if verb.eq_ignore_ascii_case(b"EPRT") {
        return active_action(argument, parse_eprt);
    }
    (FtpCommandAction::Other, None, ParseStatus::Complete)
}

fn transfer_action(
    argument: Option<&[u8]>,
    action: FtpCommandAction,
) -> (FtpCommandAction, Option<FtpEndpoint>, ParseStatus) {
    let status = if argument.is_some_and(|value| !value.is_empty()) {
        ParseStatus::Complete
    } else {
        ParseStatus::Unsupported
    };
    (action, None, status)
}

fn no_argument_action(
    argument: Option<&[u8]>,
    action: FtpCommandAction,
) -> (FtpCommandAction, Option<FtpEndpoint>, ParseStatus) {
    let status = if argument.is_none_or(<[u8]>::is_empty) {
        ParseStatus::Complete
    } else {
        ParseStatus::Unsupported
    };
    (action, None, status)
}

fn active_action(
    argument: Option<&[u8]>,
    parse: fn(&[u8]) -> Option<FtpEndpoint>,
) -> (FtpCommandAction, Option<FtpEndpoint>, ParseStatus) {
    let endpoint = argument.and_then(parse);
    let status = if endpoint.is_some() {
        ParseStatus::Complete
    } else {
        ParseStatus::Unsupported
    };
    (FtpCommandAction::ActiveEndpoint, endpoint, status)
}

fn parse_port(argument: &[u8]) -> Option<FtpEndpoint> {
    parse_ipv4_endpoint_tuple(argument)
}

fn parse_ipv4_endpoint_tuple(bytes: &[u8]) -> Option<FtpEndpoint> {
    let fields = decimal_fields(bytes, 6)?;
    let mut address = [0_u8; 4];
    for (slot, field) in address.iter_mut().zip(fields.iter().take(4)) {
        *slot = u8::try_from(*field).ok()?;
    }
    let high = u8::try_from(*fields.get(4)?).ok()?;
    let low = u8::try_from(*fields.get(5)?).ok()?;
    let port = u16::from(high) * 256 + u16::from(low);
    (port != 0).then_some(FtpEndpoint {
        address: Some(NetworkAddress::Ipv4(address)),
        port,
    })
}

fn parse_eprt(argument: &[u8]) -> Option<FtpEndpoint> {
    let delimiter = *argument.first()?;
    if !(33..=126).contains(&delimiter) {
        return None;
    }
    let fields = argument
        .split(|byte| *byte == delimiter)
        .collect::<Vec<_>>();
    if fields.len() != 5 || *fields.first()? != b"" || *fields.get(4)? != b"" {
        return None;
    }
    let family = *fields.get(1)?;
    let address = *fields.get(2)?;
    let port = parse_port_number(fields.get(3)?)?;
    let address_text = std::str::from_utf8(address).ok()?;
    let address = match family {
        b"1" => NetworkAddress::Ipv4(address_text.parse::<Ipv4Addr>().ok()?.octets()),
        b"2" => NetworkAddress::Ipv6(address_text.parse::<Ipv6Addr>().ok()?.octets()),
        _ => return None,
    };
    Some(FtpEndpoint {
        address: Some(address),
        port,
    })
}

fn parse_passive_endpoint(
    bytes: &[u8],
    range: ByteRange,
    code: u16,
) -> Result<Option<FtpEndpoint>, ParseStatus> {
    let Some(reply) = range.slice(bytes) else {
        return Err(ParseStatus::Unsupported);
    };
    let mut endpoint = None;
    let mut search_start = 0;
    while let Some(relative_open) = reply
        .get(search_start..)
        .and_then(|tail| tail.iter().position(|byte| *byte == b'('))
    {
        let open = search_start + relative_open;
        let after_open = open + 1;
        let Some(relative_close) = reply
            .get(after_open..)
            .and_then(|tail| tail.iter().position(|byte| *byte == b')'))
        else {
            return Err(ParseStatus::Unsupported);
        };
        let close = after_open + relative_close;
        let content = reply
            .get(after_open..close)
            .ok_or(ParseStatus::Unsupported)?;
        let candidate = match code {
            227 => parse_pasv_tuple(content),
            229 => parse_epsv_tuple(content),
            _ => None,
        };
        if let Some(candidate) = candidate {
            if endpoint.is_some() {
                return Err(ParseStatus::Ambiguous);
            }
            endpoint = Some(candidate);
        }
        search_start = close + 1;
    }
    endpoint.map(Some).ok_or(ParseStatus::Unsupported)
}

fn parse_pasv_tuple(content: &[u8]) -> Option<FtpEndpoint> {
    parse_ipv4_endpoint_tuple(content)
}

fn parse_epsv_tuple(content: &[u8]) -> Option<FtpEndpoint> {
    let delimiter = *content.first()?;
    if !(33..=126).contains(&delimiter) || matches!(delimiter, b'(' | b')') {
        return None;
    }
    if content.get(1) != Some(&delimiter) || content.get(2) != Some(&delimiter) {
        return None;
    }
    let last = content.len().checked_sub(1)?;
    if content.get(last) != Some(&delimiter) || last < 4 {
        return None;
    }
    let port = parse_port_number(content.get(3..last)?)?;
    Some(FtpEndpoint {
        address: None,
        port,
    })
}

fn decimal_fields(bytes: &[u8], expected: usize) -> Option<Vec<u16>> {
    let mut fields = Vec::with_capacity(expected);
    for value in bytes.split(|byte| *byte == b',') {
        if fields.len() == expected {
            return None;
        }
        let number = parse_decimal(value)?;
        fields.push(number);
    }
    (fields.len() == expected).then_some(fields)
}

fn parse_port_number(bytes: &[u8]) -> Option<u16> {
    let port = parse_decimal(bytes)?;
    if port == 0 {
        return None;
    }
    Some(port)
}

fn parse_decimal(bytes: &[u8]) -> Option<u16> {
    if bytes.is_empty() {
        return None;
    }
    bytes.iter().try_fold(0_u16, |value, digit| {
        if !digit.is_ascii_digit() {
            return None;
        }
        value.checked_mul(10)?.checked_add(u16::from(digit - b'0'))
    })
}

fn reply_prefix(line: &[u8]) -> Option<(u16, u8)> {
    let code = line.get(..3)?;
    if !code.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let separator = *line.get(3)?;
    if !matches!(separator, b' ' | b'-') {
        return None;
    }
    let value = parse_decimal(code)?;
    Some((value, separator))
}

fn response_terminates(line: &[u8], code: u16) -> bool {
    reply_prefix(line).is_some_and(|(candidate, separator)| candidate == code && separator == b' ')
}

fn line_range(bytes: &[u8], start: usize) -> Result<ByteRange, ParseError> {
    let remaining = bytes
        .get(start..)
        .ok_or_else(|| tail_error(bytes, start, ParseStatus::Unsupported))?;
    let scan_length = remaining.len().min(MAX_LINE_BYTES + 2);
    let scan = remaining
        .get(..scan_length)
        .ok_or_else(|| tail_error(bytes, start, ParseStatus::Unsupported))?;
    if let Some(offset) = scan.windows(2).position(|pair| pair == b"\r\n") {
        return Ok(ByteRange::new(start, offset));
    }
    // A CR can begin a delimiter only at the captured tail or before a known LF
    let content = if scan.len() == remaining.len() || remaining.get(scan.len()) == Some(&b'\n') {
        scan.strip_suffix(b"\r").unwrap_or(scan)
    } else {
        scan
    };
    if contains_control(content) {
        return Err(tail_error(bytes, start, ParseStatus::Unsupported));
    }
    let (status, budget) = if content.len() > MAX_LINE_BYTES {
        (ParseStatus::Unsupported, Some(ParserBudget::LineBytes))
    } else {
        (ParseStatus::Incomplete, None)
    };
    Err(ParseError {
        status,
        range: ByteRange::new(start, bytes.len() - start),
        budget,
    })
}

fn contains_control(line: &[u8]) -> bool {
    line.iter().any(|byte| *byte < 0x20 || *byte == 0x7f)
}

const fn other_item(range: ByteRange, status: ParseStatus) -> FtpItem {
    FtpItem {
        range: ByteRange::new(range.offset, range.length + 2),
        status,
        kind: FtpKind::Other,
    }
}

const fn tail_error(bytes: &[u8], start: usize, status: ParseStatus) -> ParseError {
    ParseError {
        status,
        range: ByteRange::new(start, bytes.len() - start),
        budget: None,
    }
}

const fn set_item_status(item: &mut FtpItem, status: ParseStatus) {
    item.status = status;
}
