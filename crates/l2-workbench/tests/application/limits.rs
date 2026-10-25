use super::support::COMPLETE;
use l2_discovery::dns::MAX_MESSAGE_BYTES;
use l2_workbench::application::{
    MAX_ENTRIES, MAX_HTTP_HEADER_BYTES, MAX_LINE_BYTES, ParseStatus, ParserBudget, inspect,
};
use serde_json::Value;
use std::error::Error;

#[test]
fn dns_http_tail_limit_reason() -> Result<(), Box<dyn Error>> {
    let mut dns_frame = 12_u16.to_be_bytes().to_vec();
    dns_frame.extend_from_slice(&[0; 12]);
    let dns = dns_frame.repeat(MAX_ENTRIES + 1);
    let http = b"GET / HTTP/1.1\r\n\r\n".repeat(MAX_ENTRIES + 1);
    let dns_report = inspect(&dns, COMPLETE.start_known, COMPLETE.end_observed).dns_tcp;
    let http_report = inspect(&http, COMPLETE.start_known, COMPLETE.end_observed).http;

    assert_eq!(dns_report.status, ParseStatus::Unsupported);
    assert_eq!(http_report.status, ParseStatus::Unsupported);
    assert_eq!(dns_report.findings.len(), MAX_ENTRIES);
    assert_eq!(http_report.findings.len(), MAX_ENTRIES);
    assert_entry_omission(
        &serde_json::to_value(dns_report)?,
        MAX_ENTRIES * dns_frame.len(),
        dns_frame.len(),
    );
    assert_entry_omission(&serde_json::to_value(http_report)?, MAX_ENTRIES * 18, 18);
    Ok(())
}

#[test]
fn nested_parser_specific_reasons_ranges() -> Result<(), Box<dyn Error>> {
    let mut dns_message_limited = Vec::new();
    let oversized_dns_length = u16::try_from(MAX_MESSAGE_BYTES + 1)?;
    dns_message_limited.extend_from_slice(&oversized_dns_length.to_be_bytes());
    dns_message_limited.resize(2 + usize::from(oversized_dns_length), 0);

    let mut dns_entry_limited_message = vec![0; 12];
    let question_count = u16::try_from(l2_discovery::dns::MAX_ENTRIES + 1)?;
    dns_entry_limited_message
        .get_mut(4..6)
        .ok_or("DNS header is missing the question count")?
        .copy_from_slice(&question_count.to_be_bytes());
    for _ in 0..question_count {
        dns_entry_limited_message.extend_from_slice(&[0, 0, 1, 0, 1]);
    }
    let dns_entries_length = u16::try_from(dns_entry_limited_message.len())?;
    let mut dns_entries_limited = dns_entries_length.to_be_bytes().to_vec();
    dns_entries_limited.extend_from_slice(&dns_entry_limited_message);

    let mut ftp_line_limited = b"RETR ".to_vec();
    ftp_line_limited.extend(std::iter::repeat_n(
        b'A',
        MAX_LINE_BYTES + 1 - b"RETR ".len(),
    ));
    ftp_line_limited.extend_from_slice(b"\r\n");
    let ftp_reply_limited = oversized_multiline_reply();

    let mut http_header_limited = b"GET / HTTP/1.1\r\n".to_vec();
    for _ in 0..5 {
        http_header_limited.extend_from_slice(b"X:");
        http_header_limited.extend(std::iter::repeat_n(b'a', 7_000));
        http_header_limited.extend_from_slice(b"\r\n");
    }
    http_header_limited.extend_from_slice(b"\r\n");
    assert!(http_header_limited.len() > MAX_HTTP_HEADER_BYTES);

    assert_single_omission(
        &inspect(&dns_message_limited, true, true).dns_tcp,
        ParserBudget::DnsMessageBytes,
        2,
        usize::from(oversized_dns_length),
    );
    assert_single_omission(
        &inspect(&dns_entries_limited, true, true).dns_tcp,
        ParserBudget::DnsEntries,
        2,
        usize::from(dns_entries_length),
    );
    assert_single_omission(
        &inspect(&ftp_line_limited, true, true).ftp,
        ParserBudget::LineBytes,
        0,
        ftp_line_limited.len(),
    );
    assert_single_omission(
        &inspect(&ftp_reply_limited, true, true).ftp,
        ParserBudget::ReplyBytes,
        0,
        ftp_reply_limited.len(),
    );
    assert_single_omission(
        &inspect(&http_header_limited, true, true).http,
        ParserBudget::HeaderBytes,
        0,
        http_header_limited.len(),
    );
    Ok(())
}

#[test]
fn nested_entry_incomplete_without_omissions() {
    let mut ftp = b"220-start\r\n".to_vec();
    ftp.extend(b"x\r\n".repeat(MAX_ENTRIES - 1));
    let ftp_report = inspect(&ftp, true, true).ftp;

    let mut http = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    http.extend(b"1\r\na\r\n".repeat(MAX_ENTRIES - 2));
    let http_report = inspect(&http, true, true).http;

    assert_eq!(http_report.status, ParseStatus::Incomplete);
    assert!(http_report.budget_omissions.is_empty());
    assert_eq!(ftp_report.status, ParseStatus::Incomplete);
    assert!(ftp_report.budget_omissions.is_empty());
}

fn oversized_multiline_reply() -> Vec<u8> {
    let mut reply = b"220-start\r\n".to_vec();
    for _ in 0..220 {
        reply.extend(std::iter::repeat_n(b'a', 150));
        reply.extend_from_slice(b"\r\n");
    }
    reply
}

fn assert_single_omission<T: serde::Serialize>(
    report: &l2_workbench::application::ParseReport<T>,
    budget: ParserBudget,
    offset: usize,
    length: usize,
) {
    assert_eq!(report.budget_omissions.len(), 1);
    let omission = report.budget_omissions.first();
    assert_eq!(omission.map(|omission| omission.budget), Some(budget));
    assert_eq!(omission.map(|omission| omission.range.offset), Some(offset));
    assert_eq!(omission.map(|omission| omission.range.length), Some(length));
    assert!(omission.is_some_and(|omission| report.unparsed.contains(&omission.range)));
}

fn assert_entry_omission(report: &Value, offset: usize, length: usize) {
    assert_eq!(
        report.pointer("/unparsed/0/offset"),
        Some(&Value::from(offset))
    );
    assert_eq!(
        report.pointer("/unparsed/0/length"),
        Some(&Value::from(length))
    );
    assert_eq!(
        report.pointer("/budget_omissions/0/budget"),
        Some(&Value::from("entries"))
    );
    assert_eq!(
        report.pointer("/budget_omissions/0/range/offset"),
        Some(&Value::from(offset))
    );
    assert_eq!(
        report.pointer("/budget_omissions/0/range/length"),
        Some(&Value::from(length))
    );
}
