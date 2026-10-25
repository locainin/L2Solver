//! Bounded HTTP/1 request and response framing candidates

mod chunks;
mod headers;
mod model;
mod syntax;

pub use model::{
    HttpBody, HttpFraming, HttpHeader, HttpLineEnding, HttpMessage, HttpRequestMethod, HttpStart,
};

use self::{chunks::scan_chunked, headers::scan_head, model::BodyPolicy};
use super::{
    ByteRange, MAX_ENTRIES, MAX_INPUT_BYTES, ParseContext, ParseReport, ParseStatus, ParserBudget,
    empty_report, finish_report, record_omission, record_status, unsupported_input,
};

/// Frame complete HTTP/1 messages from one contiguous stream candidate
#[must_use]
pub fn decode_http(bytes: &[u8], context: ParseContext) -> ParseReport<HttpMessage> {
    decode_http_with_methods(bytes, context, &[])
}

/// Frame HTTP/1 candidates using request methods paired to final responses
///
/// Each slot describes the method for one final response, with `None` keeping
/// an unknown association in its wire-order position. Informational responses
/// do not consume a slot. Missing associations leave body framing ambiguous,
/// except for status codes that prohibit an HTTP body
#[must_use]
pub fn decode_http_with_methods(
    bytes: &[u8],
    context: ParseContext,
    request_methods: &[Option<HttpRequestMethod>],
) -> ParseReport<HttpMessage> {
    if bytes.len() > MAX_INPUT_BYTES {
        return unsupported_input(bytes);
    }
    let mut report = empty_report();
    let mut budget = 0;
    let mut cursor = 0;
    let mut response_method_index = 0;

    while cursor < bytes.len() {
        let message_start = cursor;
        if !consume_message_entry(&mut report, &mut budget, message_start, bytes.len()) {
            break;
        }
        let head = match scan_head(bytes, message_start, &mut budget) {
            Ok(head) => head,
            Err(error) => {
                if let Some(budget) = error.budget {
                    record_omission(&mut report, budget, error.range);
                } else {
                    report.unparsed.push(error.range);
                }
                record_status(&mut report, error.status);
                break;
            }
        };
        let associated_method =
            response_method(&head.start, request_methods, &mut response_method_index);
        let policy = headers::body_policy(bytes, &head, associated_method);
        let body = parse_body(
            bytes,
            head.body_offset,
            policy,
            &mut budget,
            context.end_observed,
        );
        // The successful CONNECT response ends at its header boundary
        let message_end = if body.framing == HttpFraming::Tunnel {
            head.body_offset
        } else {
            body.next_offset
        };
        let message_range = ByteRange::new(message_start, message_end - message_start);
        let status = body.status;
        let stop_after =
            body.stop_after || matches!(head.start, HttpStart::Response { status_code: 101 });
        report.findings.push(HttpMessage {
            range: message_range,
            status,
            line_ending: head.line_ending,
            start_line: head.start_line,
            start: head.start,
            headers: head.headers,
            framing: body.framing,
            body: body.body,
        });
        record_status(&mut report, status);
        if let Some(range) = body.unparsed {
            if let Some(budget) = body.budget {
                record_omission(&mut report, budget, range);
            } else {
                report.unparsed.push(range);
            }
        }
        cursor = body.next_offset;
        if stop_after {
            if cursor < bytes.len() {
                append_unparsed(&mut report, cursor, bytes.len());
                record_status(&mut report, ParseStatus::Unsupported);
            }
            break;
        }
        if cursor <= message_start {
            append_unparsed(&mut report, message_start, bytes.len());
            record_status(&mut report, ParseStatus::Unsupported);
            break;
        }
    }

    finish_report(report, context, set_message_status, |message| {
        message.status
    })
}

struct BodyParse {
    framing: HttpFraming,
    body: HttpBody,
    status: ParseStatus,
    next_offset: usize,
    unparsed: Option<ByteRange>,
    budget: Option<ParserBudget>,
    stop_after: bool,
}

fn parse_body(
    bytes: &[u8],
    body_start: usize,
    policy: BodyPolicy,
    budget: &mut usize,
    end_observed: bool,
) -> BodyParse {
    match policy {
        BodyPolicy::NoBody(status) => BodyParse {
            framing: HttpFraming::NoBody,
            body: HttpBody::Empty,
            status,
            next_offset: body_start,
            unparsed: None,
            budget: None,
            stop_after: false,
        },
        BodyPolicy::ContentLength(expected) => parse_content_body(bytes, body_start, expected),
        BodyPolicy::Chunked => parse_chunk_body(bytes, body_start, budget),
        BodyPolicy::CloseDelimited => parse_close_body(bytes, body_start, end_observed),
        BodyPolicy::Tunnel(status) => parse_tunnel_body(bytes, body_start, status),
        BodyPolicy::Unsupported => unresolved_body(bytes, body_start, ParseStatus::Unsupported),
        BodyPolicy::Ambiguous => unresolved_body(bytes, body_start, ParseStatus::Ambiguous),
    }
}

fn response_method(
    start: &HttpStart,
    request_methods: &[Option<HttpRequestMethod>],
    method_index: &mut usize,
) -> Option<HttpRequestMethod> {
    let HttpStart::Response { status_code } = start else {
        return None;
    };
    if (100..=199).contains(status_code) && *status_code != 101 {
        return None;
    }
    let method = request_methods.get(*method_index).copied().flatten();
    *method_index += 1;
    method
}

fn parse_content_body(bytes: &[u8], start: usize, expected: usize) -> BodyParse {
    let available = bytes.len() - start;
    let captured = available.min(expected);
    let range = ByteRange::new(start, captured);
    let complete = captured == expected;
    let status = if complete {
        ParseStatus::Complete
    } else {
        ParseStatus::Incomplete
    };
    let body = if captured == 0 {
        HttpBody::Empty
    } else {
        HttpBody::Contiguous { range, complete }
    };
    let next_offset = start + captured;
    BodyParse {
        framing: HttpFraming::ContentLength { expected },
        body,
        status,
        next_offset,
        unparsed: (!complete).then_some(range),
        budget: None,
        stop_after: !complete,
    }
}

fn parse_chunk_body(bytes: &[u8], start: usize, budget: &mut usize) -> BodyParse {
    let scan = scan_chunked(bytes, start, budget);
    BodyParse {
        framing: HttpFraming::Chunked,
        body: HttpBody::Chunked {
            chunks: scan.chunks,
            trailers: scan.trailers,
            trailer_range: scan.trailer_range,
            raw_remainder: scan.raw_remainder,
            complete: scan.complete,
        },
        status: scan.status,
        next_offset: scan.next_offset,
        unparsed: scan.raw_remainder,
        budget: scan.budget,
        stop_after: !scan.complete,
    }
}

fn parse_close_body(bytes: &[u8], start: usize, end_observed: bool) -> BodyParse {
    let range = ByteRange::new(start, bytes.len() - start);
    BodyParse {
        framing: HttpFraming::CloseDelimited,
        body: HttpBody::Contiguous {
            range,
            complete: end_observed,
        },
        status: if end_observed {
            ParseStatus::Complete
        } else {
            ParseStatus::Incomplete
        },
        next_offset: bytes.len(),
        unparsed: (!end_observed).then_some(range),
        budget: None,
        stop_after: true,
    }
}

const fn parse_tunnel_body(bytes: &[u8], start: usize, status: ParseStatus) -> BodyParse {
    let range = ByteRange::new(start, bytes.len() - start);
    BodyParse {
        framing: HttpFraming::Tunnel,
        body: HttpBody::Tunnel { range },
        status,
        next_offset: bytes.len(),
        unparsed: None,
        budget: None,
        stop_after: true,
    }
}

const fn unresolved_body(bytes: &[u8], start: usize, status: ParseStatus) -> BodyParse {
    let range = ByteRange::new(start, bytes.len() - start);
    BodyParse {
        framing: match status {
            ParseStatus::Ambiguous => HttpFraming::Ambiguous,
            _ => HttpFraming::Unsupported,
        },
        body: HttpBody::Unresolved { range },
        status,
        next_offset: bytes.len(),
        unparsed: Some(range),
        budget: None,
        stop_after: true,
    }
}

const fn set_message_status(message: &mut HttpMessage, status: ParseStatus) {
    message.status = status;
}

fn append_unparsed(report: &mut ParseReport<HttpMessage>, start: usize, end: usize) {
    report.unparsed.push(ByteRange::new(start, end - start));
}

fn consume_message_entry(
    report: &mut ParseReport<HttpMessage>,
    budget: &mut usize,
    start: usize,
    end: usize,
) -> bool {
    if consume_entry(budget) {
        return true;
    }
    record_omission(
        report,
        ParserBudget::Entries,
        ByteRange::new(start, end - start),
    );
    record_status(report, ParseStatus::Unsupported);
    false
}

pub(super) const fn consume_entry(budget: &mut usize) -> bool {
    if *budget >= MAX_ENTRIES {
        return false;
    }
    *budget += 1;
    true
}
