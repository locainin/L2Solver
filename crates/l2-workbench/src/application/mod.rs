//! Bounded application framing candidates for contiguous TCP evidence
//!
//! These parsers describe byte structure and preserve source ranges without
//! selecting a protocol from ports or claiming endpoint intent

pub mod dns_tcp;
pub mod ftp;
pub mod http;

use serde::Serialize;

pub const MAX_INPUT_BYTES: usize = 1_048_576;
pub const MAX_ENTRIES: usize = 256;
pub const MAX_LINE_BYTES: usize = 8_192;
pub const MAX_HTTP_HEADER_BYTES: usize = 32_768;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseStatus {
    Complete,
    Incomplete,
    Unsupported,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseContext {
    pub start_known: bool,
    pub end_observed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ByteRange {
    pub offset: usize,
    pub length: usize,
}

impl ByteRange {
    #[must_use]
    pub const fn new(offset: usize, length: usize) -> Self {
        Self { offset, length }
    }

    #[must_use]
    pub fn slice(self, source: &[u8]) -> Option<&[u8]> {
        let end = self.offset.checked_add(self.length)?;
        source.get(self.offset..end)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ParseReport<T> {
    pub status: ParseStatus,
    pub findings: Vec<T>,
    /// Bytes that could not be assigned to a complete parsed finding
    pub unparsed: Vec<ByteRange>,
    /// Byte ranges left unprocessed because a configured parser budget was reached
    pub budget_omissions: Vec<BudgetOmission>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParserBudget {
    InputBytes,
    Entries,
    LineBytes,
    HeaderBytes,
    ReplyBytes,
    DnsMessageBytes,
    DnsEntries,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct BudgetOmission {
    pub budget: ParserBudget,
    pub range: ByteRange,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApplicationReport {
    pub dns_tcp: ParseReport<dns_tcp::DnsTcpFrame>,
    pub http: ParseReport<http::HttpMessage>,
    pub ftp: ParseReport<ftp::FtpItem>,
}

/// Run all bounded format candidates while keeping each result explicitly labeled
#[must_use]
pub fn inspect(bytes: &[u8], start_known: bool, end_observed: bool) -> ApplicationReport {
    let context = ParseContext {
        start_known,
        end_observed,
    };
    ApplicationReport {
        dns_tcp: dns_tcp::decode_dns_tcp(bytes, context),
        http: http::decode_http(bytes, context),
        ftp: ftp::decode_ftp(bytes, context),
    }
}

pub(crate) const fn empty_report<T>() -> ParseReport<T> {
    ParseReport {
        status: ParseStatus::Complete,
        findings: Vec::new(),
        unparsed: Vec::new(),
        budget_omissions: Vec::new(),
    }
}

pub(crate) fn unsupported_input<T>(bytes: &[u8]) -> ParseReport<T> {
    let range = ByteRange::new(0, bytes.len());
    ParseReport {
        status: ParseStatus::Unsupported,
        findings: Vec::new(),
        unparsed: vec![range],
        budget_omissions: vec![BudgetOmission {
            budget: ParserBudget::InputBytes,
            range,
        }],
    }
}

pub(crate) fn record_omission<T>(
    report: &mut ParseReport<T>,
    budget: ParserBudget,
    range: ByteRange,
) {
    if !report.unparsed.contains(&range) {
        report.unparsed.push(range);
    }
    report
        .budget_omissions
        .push(BudgetOmission { budget, range });
}

pub(crate) const fn record_status(report: &mut ParseReport<impl Sized>, status: ParseStatus) {
    report.status = match (report.status, status) {
        (ParseStatus::Ambiguous, _) | (_, ParseStatus::Ambiguous) => ParseStatus::Ambiguous,
        (ParseStatus::Unsupported, _) | (_, ParseStatus::Unsupported) => ParseStatus::Unsupported,
        (ParseStatus::Incomplete, _) | (_, ParseStatus::Incomplete) => ParseStatus::Incomplete,
        _ => ParseStatus::Complete,
    };
}

pub(crate) fn finish_report<T>(
    mut report: ParseReport<T>,
    context: ParseContext,
    mut set_status: impl FnMut(&mut T, ParseStatus),
    status_of: impl Fn(&T) -> ParseStatus,
) -> ParseReport<T> {
    if !context.start_known {
        report.status = ParseStatus::Ambiguous;
        for finding in &mut report.findings {
            if status_of(finding) == ParseStatus::Complete {
                set_status(finding, ParseStatus::Ambiguous);
            }
        }
        return report;
    }
    if !context.end_observed && report.status == ParseStatus::Complete {
        report.status = ParseStatus::Incomplete;
    }
    report
}
