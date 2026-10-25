use super::common::{
    EndpointImportError, MAX_ENDPOINT_RECORDS, error, source_id, source_length, source_range,
};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, str::FromStr};

const MAX_STRACE_LINE_BYTES: usize = 1024 * 1024;
const MAX_STRACE_FRAME_BYTES: usize = 8192;
const MAX_TRACE_IO_BYTES: usize = 1024 * 1024;
const MAX_RETAINED_TRACE_BYTES: usize = 16 * 1024 * 1024;
const MAX_RETAINED_FRAME_BYTES: usize = 8 * 1024 * 1024;
const MAX_TRACE_STACK_FRAMES: usize = 256;

/// Data direction observed at the syscall boundary
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IoDirection {
    /// A read or receive syscall copied bytes into the process
    IntoProcess,
    /// A write or send syscall passed bytes out of the process
    OutOfProcess,
}

/// Transport named by a strace socket descriptor annotation
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceTransport {
    /// TCP socket annotation
    Tcp,
    /// UDP socket annotation
    Udp,
}

/// One address and port from a parsed socket descriptor annotation
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SocketEndpoint {
    /// Parsed IPv4 or IPv6 address
    pub address: IpAddr,
    /// Parsed transport port
    pub port: u16,
}

/// Local and peer endpoints printed by strace `-yy`
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SocketTuple {
    /// TCP or UDP transport from the descriptor annotation
    pub transport: TraceTransport,
    /// Local endpoint reported by the operating system
    pub local: SocketEndpoint,
    /// Remote endpoint reported by the operating system
    pub peer: SocketEndpoint,
}

/// One syscall-level byte observation from strace output
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TraceIoEvent {
    /// Process ID printed by strace, when present
    pub pid: Option<u32>,
    /// Supported syscall name
    pub syscall: String,
    /// File descriptor passed to the syscall
    pub fd: Option<i32>,
    /// Direction bytes moved relative to the traced process
    pub direction: IoDirection,
    /// Socket tuple reported by `strace -yy`, when available
    pub socket: Option<SocketTuple>,
    /// Retained bytes printed for the data argument; result and completeness govern transfer claims
    pub bytes: Vec<u8>,
    /// True only when the strace string and syscall result expose every transferred byte
    pub bytes_complete: bool,
    /// Stack frames printed after the syscall by strace `-k`, when supplied
    pub frames: Vec<TraceCodeFrame>,
    /// Syscall return value, or `None` when the line omitted one
    pub return_value: Option<i64>,
    /// Exact syscall line range in the original trace file
    pub source_range: crate::evidence::SourceRange,
    /// Exact quoted second-argument range, absent when strace printed a pointer
    pub data_source_range: Option<crate::evidence::SourceRange>,
}

/// One stack frame line printed by the configured strace unwinder
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TraceCodeFrame {
    /// Module label printed by strace, without independent binary verification
    pub module: Option<String>,
    /// Symbol label printed by the unwinder, when present
    pub symbol: Option<String>,
    /// Offset printed relative to the displayed symbol, not the module base
    pub symbol_offset: Option<u64>,
    /// Process virtual address printed in the frame line
    pub instruction_pointer: Option<u64>,
    /// Original stack-frame line without its line terminator
    pub raw: String,
    /// Exact frame line range in the strace output
    pub source_range: crate::evidence::SourceRange,
}

/// Bounded import of actual strace syscall output
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TraceIoReport {
    /// SHA-256 identity of the exact strace output bytes
    pub source_sha256: String,
    /// Exact source length in bytes
    pub source_length: u64,
    /// Parsed read/write/send/receive observations
    pub events: Vec<TraceIoEvent>,
    /// Supported syscall lines whose string or result was incomplete
    pub incomplete_events: u64,
    /// Relevant syscalls that need a richer decoder
    pub unsupported_io_lines: u64,
    /// Stack-frame lines omitted after parser resource limits
    pub omitted_stack_frames: u64,
    /// Bytes or events omitted after resource limits
    pub omitted_events: u64,
    /// Non-syscall trace lines that were not interpreted
    pub ignored_lines: u64,
    /// False when relevant I/O evidence was incomplete or omitted
    pub complete: bool,
    /// True when the source included at least one stack-frame line
    pub stack_frames_observed: bool,
    /// Limits on what syscall traces establish
    pub limitations: Vec<String>,
}

/// Parse read, write, sendto, and recvfrom calls from `strace -xx -s 65535 -yy` output
///
/// The import observes syscall I/O bytes and does not infer code functions or symbols
///
/// # Errors
/// Rejects source lengths that cannot be represented in byte ranges
pub fn parse_strace(bytes: &[u8]) -> Result<TraceIoReport, EndpointImportError> {
    let source = source_id(bytes);
    let mut report = empty_report(bytes, &source)?;
    let mut line_offset = 0_usize;
    let mut retained_bytes = 0_usize;
    let mut retained_frame_bytes = 0_usize;
    let mut last_event = None;
    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        parse_line(
            line,
            line_offset,
            &source,
            &mut retained_bytes,
            &mut retained_frame_bytes,
            &mut last_event,
            &mut report,
        )?;
        line_offset = line_offset
            .checked_add(line.len())
            .ok_or_else(|| error("strace source offset overflows"))?;
    }
    report.complete = report.incomplete_events == 0
        && report.unsupported_io_lines == 0
        && report.omitted_events == 0
        && report.omitted_stack_frames == 0;
    Ok(report)
}

fn empty_report(bytes: &[u8], source: &str) -> Result<TraceIoReport, EndpointImportError> {
    Ok(TraceIoReport {
        source_sha256: source.to_owned(),
        source_length: source_length(bytes)?,
        events: Vec::new(),
        incomplete_events: 0,
        unsupported_io_lines: 0,
        omitted_stack_frames: 0,
        omitted_events: 0,
        ignored_lines: 0,
        complete: true,
        stack_frames_observed: false,
        limitations: vec![
            "Syscall bytes and descriptors are observed; source log authenticity depends on the trace acquisition process".to_owned(),
            "Syscall observations do not establish function identity or static code location".to_owned(),
            "Stack module, symbol, and address labels are strace unwinder output; binary identity and source mapping are not verified".to_owned(),
            "Exact packet correlation requires a unique captured flow and complete byte match".to_owned(),
        ],
    })
}

fn parse_line(
    line: &[u8],
    line_offset: usize,
    source: &str,
    retained_bytes: &mut usize,
    retained_frame_bytes: &mut usize,
    last_event: &mut Option<usize>,
    report: &mut TraceIoReport,
) -> Result<(), EndpointImportError> {
    if line.len() > MAX_STRACE_LINE_BYTES {
        report.omitted_events = report.omitted_events.saturating_add(1);
        *last_event = None;
        return Ok(());
    }
    if is_stack_frame_line(line) {
        retain_stack_frame(
            line,
            line_offset,
            source,
            retained_frame_bytes,
            *last_event,
            report,
        )?;
        return Ok(());
    }
    *last_event = None;
    let Ok(value) = std::str::from_utf8(line) else {
        report.ignored_lines = report.ignored_lines.saturating_add(1);
        return Ok(());
    };
    let text = value.trim_end_matches(['\r', '\n']);
    let Some(parsed) = parse_io_line(text, line_offset, source)? else {
        if unsupported_io_line(text) {
            report.unsupported_io_lines = report.unsupported_io_lines.saturating_add(1);
        } else {
            report.ignored_lines = report.ignored_lines.saturating_add(1);
        }
        return Ok(());
    };
    if !parsed.bytes_complete {
        report.incomplete_events = report.incomplete_events.saturating_add(1);
    }
    if retain_trace_event(&parsed, retained_bytes, report) {
        report.events.push(parsed);
        *last_event = report.events.len().checked_sub(1);
    }
    Ok(())
}

fn is_stack_frame_line(line: &[u8]) -> bool {
    std::str::from_utf8(line)
        .ok()
        .is_some_and(|text| text.trim_start().starts_with('>'))
}

fn retain_stack_frame(
    line: &[u8],
    line_offset: usize,
    source: &str,
    retained_frame_bytes: &mut usize,
    last_event: Option<usize>,
    report: &mut TraceIoReport,
) -> Result<(), EndpointImportError> {
    report.stack_frames_observed = true;
    let Some(event_index) = last_event else {
        report.ignored_lines = report.ignored_lines.saturating_add(1);
        return Ok(());
    };
    if line.len() > MAX_STRACE_FRAME_BYTES {
        report.omitted_stack_frames = report.omitted_stack_frames.saturating_add(1);
        return Ok(());
    }
    let frame = parse_stack_frame(line, line_offset, source)?;
    let next_size = retained_frame_bytes.saturating_add(frame.raw.len());
    let frame_count = report
        .events
        .get(event_index)
        .map_or(MAX_TRACE_STACK_FRAMES, |event| event.frames.len());
    if frame_count >= MAX_TRACE_STACK_FRAMES || next_size > MAX_RETAINED_FRAME_BYTES {
        report.omitted_stack_frames = report.omitted_stack_frames.saturating_add(1);
        return Ok(());
    }
    let event = report
        .events
        .get_mut(event_index)
        .ok_or_else(|| error("strace stack frame has no retained syscall"))?;
    event.frames.push(frame);
    *retained_frame_bytes = next_size;
    Ok(())
}

fn parse_stack_frame(
    line: &[u8],
    line_offset: usize,
    source: &str,
) -> Result<TraceCodeFrame, EndpointImportError> {
    let text = std::str::from_utf8(line)
        .map_err(|_| error("strace stack-frame line is not valid UTF-8"))?
        .trim_end_matches(['\r', '\n']);
    let payload = text
        .trim_start()
        .strip_prefix('>')
        .map_or("", str::trim_start);
    let address = payload
        .rsplit_once(" [0x")
        .and_then(|(_, value)| value.strip_suffix(']'))
        .and_then(|value| u64::from_str_radix(value, 16).ok());
    let frame_description = payload
        .rsplit_once(" [0x")
        .map_or(payload, |(description, _)| description);
    let (module, symbol, symbol_offset) = parse_frame_description(frame_description);
    Ok(TraceCodeFrame {
        module,
        symbol,
        symbol_offset,
        instruction_pointer: address,
        raw: text.to_owned(),
        source_range: source_range(source, line_offset, line.len())?,
    })
}

fn parse_frame_description(description: &str) -> (Option<String>, Option<String>, Option<u64>) {
    let Some((module, symbol_text)) = description.rsplit_once('(') else {
        return (None, None, None);
    };
    let (symbol, offset) = parse_frame_symbol(symbol_text);
    let module = (!module.is_empty()).then(|| module.to_owned());
    (module, symbol, offset)
}

fn parse_frame_symbol(text: &str) -> (Option<String>, Option<u64>) {
    let Some(text) = text.strip_suffix(')') else {
        return (None, None);
    };
    let Some((symbol, raw_offset)) = text.rsplit_once("+0x") else {
        return ((!text.is_empty()).then(|| text.to_owned()), None);
    };
    let offset = u64::from_str_radix(raw_offset, 16).ok();
    let symbol = (!symbol.is_empty()).then(|| symbol.to_owned());
    (symbol, offset)
}

fn parse_io_line(
    line: &str,
    line_offset: usize,
    source: &str,
) -> Result<Option<TraceIoEvent>, EndpointImportError> {
    let Some(open) = line.find('(') else {
        return Ok(None);
    };
    let prefix = line
        .get(..open)
        .ok_or_else(|| error("strace syscall prefix range is invalid"))?;
    let name_start = prefix
        .rfind(char::is_whitespace)
        .map_or(0, |index| index.saturating_add(1));
    let syscall = line
        .get(name_start..open)
        .ok_or_else(|| error("strace syscall name range is invalid"))?;
    let Some(direction) = syscall_direction(syscall) else {
        return Ok(None);
    };
    let arguments = line
        .get(open + 1..)
        .ok_or_else(|| error("strace argument range is invalid"))?;
    // The descriptor is the first argument; syscall data is only the second
    let first_comma = arguments
        .find(',')
        .ok_or_else(|| error("strace syscall descriptor argument is missing"))?;
    let first_argument = arguments
        .get(..first_comma)
        .ok_or_else(|| error("strace descriptor range is invalid"))?;
    let data_argument_start = first_comma
        .checked_add(1)
        .ok_or_else(|| error("strace buffer argument offset overflows"))?;
    let data_argument = arguments
        .get(data_argument_start..)
        .ok_or_else(|| error("strace buffer argument range is invalid"))?;
    let trimmed_argument = data_argument.trim_start();
    let leading_whitespace = data_argument.len().saturating_sub(trimmed_argument.len());
    let (mut bytes, truncated, data_bounds) = if trimmed_argument.starts_with('"') {
        let string_start = data_argument_start
            .checked_add(leading_whitespace)
            .ok_or_else(|| error("strace buffer string offset overflows"))?;
        let (bytes, string_length, truncated) = parse_string_literal(trimmed_argument)?;
        let string_end = string_start
            .checked_add(string_length)
            .ok_or_else(|| error("strace buffer string end overflows"))?;
        (bytes, truncated, Some((string_start, string_end)))
    } else {
        (Vec::new(), false, None)
    };
    let return_value = parse_return_value(line);
    let (actual_bytes, bytes_complete) = transferred_bytes(&mut bytes, return_value, truncated);
    let line_length = line.len();
    let line_range = source_range(source, line_offset, line_length)?;
    let data_range = data_bounds
        .map(|(string_start, string_end)| {
            let data_offset = line_offset
                .checked_add(open)
                .and_then(|offset| offset.checked_add(1))
                .and_then(|offset| offset.checked_add(string_start))
                .ok_or_else(|| error("strace data source offset overflows"))?;
            source_range(source, data_offset, string_end - string_start)
        })
        .transpose()?;
    let descriptor = descriptor_text(first_argument);
    Ok(Some(TraceIoEvent {
        pid: parse_pid(
            line.get(..name_start)
                .ok_or_else(|| error("strace PID prefix range is invalid"))?,
        ),
        syscall: syscall.to_owned(),
        fd: parse_fd(first_argument),
        direction,
        socket: parse_socket_tuple(descriptor),
        bytes: actual_bytes,
        bytes_complete,
        frames: Vec::new(),
        return_value,
        source_range: line_range,
        data_source_range: data_range,
    }))
}

fn syscall_direction(syscall: &str) -> Option<IoDirection> {
    match syscall {
        "read" | "recvfrom" => Some(IoDirection::IntoProcess),
        "write" | "sendto" => Some(IoDirection::OutOfProcess),
        _ => None,
    }
}

fn unsupported_io_line(line: &str) -> bool {
    [
        "readv(",
        "writev(",
        "sendmsg(",
        "recvmsg(",
        "pread64(",
        "pwrite64(",
    ]
    .iter()
    .any(|call| line.contains(call))
}

fn parse_string_literal(raw: &str) -> Result<(Vec<u8>, usize, bool), EndpointImportError> {
    if !raw.starts_with('"') {
        return Err(error("strace buffer argument is not a quoted string"));
    }
    let mut output = Vec::new();
    let mut cursor = 1_usize;
    loop {
        let byte = raw
            .as_bytes()
            .get(cursor)
            .copied()
            .ok_or_else(|| error("strace byte string is unterminated"))?;
        if byte == b'"' {
            let end = cursor
                .checked_add(1)
                .ok_or_else(|| error("strace string end offset overflows"))?;
            let suffix = raw.get(end..).map_or("", str::trim_start);
            return Ok((output, end, suffix.starts_with("...")));
        }
        if byte == b'\\' {
            cursor = decode_hex_escape(raw.as_bytes(), cursor, &mut output)?;
        } else if byte.is_ascii_graphic() || byte == b' ' {
            output.push(byte);
            cursor = cursor
                .checked_add(1)
                .ok_or_else(|| error("strace string cursor overflows"))?;
        } else {
            return Err(error("strace byte string contains unsupported escaping"));
        }
        if output.len() > MAX_TRACE_IO_BYTES {
            return Err(error("strace syscall byte string exceeds its limit"));
        }
    }
}

fn decode_hex_escape(
    raw: &[u8],
    cursor: usize,
    output: &mut Vec<u8>,
) -> Result<usize, EndpointImportError> {
    let marker = raw
        .get(cursor + 1)
        .copied()
        .ok_or_else(|| error("strace byte escape is truncated"))?;
    if marker != b'x' {
        return Err(error("strace byte escape is not hexadecimal"));
    }
    let high = raw
        .get(cursor + 2)
        .and_then(|byte| crate::hex::decode_nibble(*byte))
        .ok_or_else(|| error("strace byte escape has an invalid high digit"))?;
    let low = raw
        .get(cursor + 3)
        .and_then(|byte| crate::hex::decode_nibble(*byte))
        .ok_or_else(|| error("strace byte escape has an invalid low digit"))?;
    output.push(high * 16 + low);
    cursor
        .checked_add(4)
        .ok_or_else(|| error("strace escape cursor overflows"))
}

fn parse_return_value(line: &str) -> Option<i64> {
    let end = line.rfind(") =")?;
    let value = line.get(end + 3..)?.split_whitespace().next()?;
    value.parse().ok()
}

fn transferred_bytes(
    bytes: &mut Vec<u8>,
    returned: Option<i64>,
    truncated: bool,
) -> (Vec<u8>, bool) {
    let Some(returned) = returned else {
        return (std::mem::take(bytes), false);
    };
    if returned < 0 {
        return (Vec::new(), true);
    }
    let Ok(length) = usize::try_from(returned) else {
        return (std::mem::take(bytes), false);
    };
    if length > bytes.len() || truncated {
        return (std::mem::take(bytes), false);
    }
    bytes.truncate(length);
    (std::mem::take(bytes), true)
}

fn parse_pid(prefix: &str) -> Option<u32> {
    let value = prefix.trim();
    if let Some(bracketed) = value.strip_prefix("[pid ") {
        return bracketed.split(']').next()?.trim().parse().ok();
    }
    value.split_whitespace().last()?.parse().ok()
}

fn parse_fd(argument: &str) -> Option<i32> {
    let digits = argument
        .trim_start()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    digits.parse().ok()
}

fn descriptor_text(argument: &str) -> &str {
    let Some(open) = argument.find('<') else {
        return "";
    };
    let Some(close) = argument.rfind('>') else {
        return "";
    };
    argument.get(open + 1..close).map_or("", |value| value)
}

fn parse_socket_tuple(descriptor: &str) -> Option<SocketTuple> {
    let (transport, prefix) = if let Some(rest) = descriptor.strip_prefix("TCP:[") {
        (TraceTransport::Tcp, rest)
    } else if let Some(rest) = descriptor.strip_prefix("UDP:[") {
        (TraceTransport::Udp, rest)
    } else {
        return None;
    };
    let tuple = prefix.strip_suffix(']')?;
    let (local, peer) = tuple.split_once("->")?;
    Some(SocketTuple {
        transport,
        local: parse_endpoint(local)?,
        peer: parse_endpoint(peer)?,
    })
}

fn parse_endpoint(value: &str) -> Option<SocketEndpoint> {
    let (address, port) = value.rsplit_once(':')?;
    let address = address
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .map_or(address, |inner| inner);
    Some(SocketEndpoint {
        address: IpAddr::from_str(address).ok()?,
        port: port.parse().ok()?,
    })
}

const fn retain_trace_event(
    event: &TraceIoEvent,
    retained_bytes: &mut usize,
    report: &mut TraceIoReport,
) -> bool {
    let next_bytes = retained_bytes.saturating_add(event.bytes.len());
    if report.events.len() >= MAX_ENDPOINT_RECORDS || next_bytes > MAX_RETAINED_TRACE_BYTES {
        report.omitted_events = report.omitted_events.saturating_add(1);
        report.complete = false;
        return false;
    }
    *retained_bytes = next_bytes;
    true
}
