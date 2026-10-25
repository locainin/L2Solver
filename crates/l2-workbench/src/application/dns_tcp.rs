//! Length-prefixed DNS-over-TCP message candidates

use super::{
    ByteRange, MAX_ENTRIES, MAX_INPUT_BYTES, ParseContext, ParseReport, ParseStatus, ParserBudget,
    empty_report, finish_report, record_omission, record_status, unsupported_input,
};
use l2_discovery::dns::{DnsError, DnsErrorKind, DnsMessage};
use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DnsTcpFrame {
    pub frame_range: ByteRange,
    pub prefix_range: ByteRange,
    /// Message bytes omit the two-byte TCP length prefix
    pub message_range: ByteRange,
    pub status: ParseStatus,
    pub message: Option<DnsMessage>,
    pub error: Option<DnsError>,
}

/// Decode bounded DNS-over-TCP candidates without selecting a flow by port
#[must_use]
pub fn decode_dns_tcp(bytes: &[u8], context: ParseContext) -> ParseReport<DnsTcpFrame> {
    if bytes.len() > MAX_INPUT_BYTES {
        return unsupported_input(bytes);
    }
    let mut report = empty_report();
    let mut cursor = 0;

    while cursor < bytes.len() {
        if let Some(range) = empty_frame_run(bytes, cursor) {
            // Empty frames cannot hold the mandatory DNS header, so retain them as one rejected range
            report.unparsed.push(range);
            record_status(&mut report, ParseStatus::Unsupported);
            cursor += range.length;
            continue;
        }
        if report.findings.len() == MAX_ENTRIES {
            record_omission(
                &mut report,
                ParserBudget::Entries,
                ByteRange::new(cursor, bytes.len() - cursor),
            );
            record_status(&mut report, ParseStatus::Unsupported);
            break;
        }
        match parse_next_frame(bytes, cursor) {
            FrameOutcome::Complete { frame, next } => {
                if let Some(error) = frame.error {
                    let budget = match error.kind {
                        DnsErrorKind::EntryLimit => Some(ParserBudget::DnsEntries),
                        DnsErrorKind::MessageLimit => Some(ParserBudget::DnsMessageBytes),
                        _ => None,
                    };
                    if let Some(budget) = budget {
                        record_omission(&mut report, budget, frame.message_range);
                    }
                }
                record_status(&mut report, frame.status);
                report.findings.push(frame);
                cursor = next;
            }
            FrameOutcome::Incomplete(frame) => {
                report.unparsed.push(frame.message_range);
                record_status(&mut report, frame.status);
                report.findings.push(frame);
                break;
            }
            FrameOutcome::Tail(range, status) => {
                report.unparsed.push(range);
                record_status(&mut report, status);
                break;
            }
        }
    }

    finish_report(report, context, set_frame_status, |frame| frame.status)
}

fn empty_frame_run(bytes: &[u8], start: usize) -> Option<ByteRange> {
    let mut end = start;
    while let Some(prefix) = bytes.get(end..).and_then(|tail| tail.get(..2)) {
        if prefix != [0, 0] {
            break;
        }
        end += 2;
    }
    (end > start).then_some(ByteRange::new(start, end - start))
}

enum FrameOutcome {
    Complete { frame: DnsTcpFrame, next: usize },
    Incomplete(DnsTcpFrame),
    Tail(ByteRange, ParseStatus),
}

fn parse_next_frame(bytes: &[u8], cursor: usize) -> FrameOutcome {
    let prefix_end = cursor + 2;
    let Some(prefix) = bytes.get(cursor..prefix_end) else {
        return FrameOutcome::Tail(
            ByteRange::new(cursor, bytes.len() - cursor),
            ParseStatus::Incomplete,
        );
    };
    let Ok(prefix) = <[u8; 2]>::try_from(prefix) else {
        return FrameOutcome::Tail(
            ByteRange::new(cursor, bytes.len() - cursor),
            ParseStatus::Incomplete,
        );
    };
    let declared_length = usize::from(u16::from_be_bytes(prefix));
    let message_start = prefix_end;
    let captured_length = declared_length.min(bytes.len() - message_start);
    let message_range = ByteRange::new(message_start, captured_length);
    let frame = DnsTcpFrame {
        frame_range: ByteRange::new(cursor, 2 + captured_length),
        prefix_range: ByteRange::new(cursor, 2),
        message_range,
        status: ParseStatus::Complete,
        message: None,
        error: None,
    };
    if captured_length < declared_length {
        let error = DnsError {
            kind: DnsErrorKind::Incomplete,
            offset: captured_length,
        };
        return FrameOutcome::Incomplete(DnsTcpFrame {
            status: ParseStatus::Incomplete,
            error: Some(error),
            ..frame
        });
    }
    let Some(message_bytes) = message_range.slice(bytes) else {
        return FrameOutcome::Incomplete(DnsTcpFrame {
            status: ParseStatus::Incomplete,
            ..frame
        });
    };
    match l2_discovery::dns::decode(message_bytes) {
        Ok(message) => FrameOutcome::Complete {
            frame: DnsTcpFrame {
                message: Some(message),
                ..frame
            },
            next: message_start + declared_length,
        },
        Err(error) => FrameOutcome::Complete {
            frame: DnsTcpFrame {
                status: ParseStatus::Unsupported,
                error: Some(error),
                ..frame
            },
            next: message_start + declared_length,
        },
    }
}

const fn set_frame_status(frame: &mut DnsTcpFrame, status: ParseStatus) {
    frame.status = status;
}
