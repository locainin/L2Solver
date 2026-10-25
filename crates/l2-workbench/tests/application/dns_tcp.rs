use super::support::{
    COMPLETE, OPEN_END, UNKNOWN_START, append_dns_frame, dns_query, dns_tcp_frame, slice,
};
use l2_discovery::dns::{DnsErrorKind, MAX_MESSAGE_BYTES};
use l2_workbench::application::{
    ByteRange, MAX_ENTRIES, ParseStatus, ParserBudget, dns_tcp::decode_dns_tcp,
};

#[test]
fn length_prefixed_dns_ranges() -> Result<(), &'static str> {
    let message = dns_query();
    let bytes = dns_tcp_frame(&message)?;
    let report = decode_dns_tcp(&bytes, COMPLETE);
    let frame = report
        .findings
        .first()
        .ok_or("missing DNS-over-TCP frame")?;

    assert_eq!(report.status, ParseStatus::Complete);
    assert_eq!(frame.status, ParseStatus::Complete);
    assert_eq!(
        frame.frame_range,
        ByteRange {
            offset: 0,
            length: bytes.len()
        }
    );
    assert_eq!(
        frame.prefix_range,
        ByteRange {
            offset: 0,
            length: 2
        }
    );
    assert_eq!(
        frame.message_range,
        ByteRange {
            offset: 2,
            length: message.len()
        }
    );
    assert_eq!(slice(&bytes, frame.message_range)?, message);
    assert_eq!(frame.message.as_ref().map(|value| value.id), Some(0x1234));
    assert!(frame.error.is_none());
    assert!(report.unparsed.is_empty());
    Ok(())
}

#[test]
fn concatenated_messages_independent_prefix_offsets() -> Result<(), &'static str> {
    let mut bytes = Vec::new();
    let first = append_dns_frame(&mut bytes, &dns_query())?;
    let second_message = dns_query();
    let second = append_dns_frame(&mut bytes, &second_message)?;
    let report = decode_dns_tcp(&bytes, COMPLETE);

    assert_eq!(report.status, ParseStatus::Complete);
    assert_eq!(report.findings.len(), 2);
    assert_eq!(
        report.findings.first().map(|value| value.frame_range),
        Some(first)
    );
    assert_eq!(
        report.findings.get(1).map(|value| value.frame_range),
        Some(second)
    );
    assert!(report.findings.iter().all(|value| value.message.is_some()));
    Ok(())
}

#[test]
fn malformed_frame_preserves_next_dns() -> Result<(), &'static str> {
    let mut bytes = vec![0, 1, 0xff];
    let valid = append_dns_frame(&mut bytes, &dns_query())?;
    let report = decode_dns_tcp(&bytes, COMPLETE);

    assert_eq!(report.status, ParseStatus::Unsupported);
    assert_eq!(report.findings.len(), 2);
    assert_eq!(
        report.findings.first().map(|value| value.status),
        Some(ParseStatus::Unsupported)
    );
    assert_eq!(
        report.findings.get(1).map(|value| value.frame_range),
        Some(valid)
    );
    assert!(
        report
            .findings
            .get(1)
            .and_then(|value| value.message.as_ref())
            .is_some()
    );
    Ok(())
}

#[test]
fn partial_prefix_message_exact_tail() -> Result<(), &'static str> {
    let partial_prefix = [0];
    let prefix_report = decode_dns_tcp(&partial_prefix, COMPLETE);
    assert_eq!(prefix_report.status, ParseStatus::Incomplete);
    assert_eq!(
        prefix_report.unparsed,
        [ByteRange {
            offset: 0,
            length: 1
        }]
    );

    let partial_message = [0, 8, 0x12, 0x34, 0, 0];
    let message_report = decode_dns_tcp(&partial_message, COMPLETE);
    let frame = message_report
        .findings
        .first()
        .ok_or("missing incomplete frame")?;
    assert_eq!(message_report.status, ParseStatus::Incomplete);
    assert_eq!(frame.status, ParseStatus::Incomplete);
    assert_eq!(
        frame.message_range,
        ByteRange {
            offset: 2,
            length: 4
        }
    );
    assert_eq!(
        message_report.unparsed,
        [ByteRange {
            offset: 2,
            length: 4
        }]
    );
    Ok(())
}

#[test]
fn unknown_ambiguous_all_input() -> Result<(), &'static str> {
    let bytes = dns_tcp_frame(&dns_query())?;
    let report = decode_dns_tcp(&bytes, UNKNOWN_START);
    let frame = report
        .findings
        .first()
        .ok_or("candidate frame was discarded")?;

    assert_eq!(report.status, ParseStatus::Ambiguous);
    assert_eq!(frame.status, ParseStatus::Ambiguous);
    assert!(frame.message.is_some());
    assert_eq!(
        frame.frame_range,
        ByteRange {
            offset: 0,
            length: bytes.len()
        }
    );
    Ok(())
}

#[test]
fn end_incomplete_valid_frames() -> Result<(), &'static str> {
    let bytes = dns_tcp_frame(&dns_query())?;
    let report = decode_dns_tcp(&bytes, OPEN_END);

    assert_eq!(report.status, ParseStatus::Incomplete);
    assert_eq!(
        report.findings.first().map(|value| value.status),
        Some(ParseStatus::Complete)
    );
    Ok(())
}

#[test]
fn aggregate_frame_limit_unparsed_suffix() -> Result<(), &'static str> {
    let message = dns_query();
    let mut bytes = Vec::new();
    for _ in 0..=l2_workbench::application::MAX_ENTRIES {
        append_dns_frame(&mut bytes, &message)?;
    }
    let report = decode_dns_tcp(&bytes, COMPLETE);
    let retained = l2_workbench::application::MAX_ENTRIES;
    let expected_offset = retained
        .checked_mul(message.len() + 2)
        .ok_or("fixture offset overflow")?;

    assert_eq!(report.status, ParseStatus::Unsupported);
    assert_eq!(report.findings.len(), retained);
    assert_eq!(
        report.unparsed,
        [ByteRange {
            offset: expected_offset,
            length: message.len() + 2
        }]
    );
    assert_eq!(report.budget_omissions.len(), 1);
    assert_eq!(
        report
            .budget_omissions
            .first()
            .map(|omission| omission.budget),
        Some(ParserBudget::Entries)
    );
    Ok(())
}

#[test]
fn zero_length_not_frame_entries() -> Result<(), &'static str> {
    let zero_prefix_count = MAX_ENTRIES + 17;
    let zero_prefix_bytes = zero_prefix_count
        .checked_mul(2)
        .ok_or("zero-prefix length overflow")?;
    let bytes = vec![0; zero_prefix_bytes];
    let report = decode_dns_tcp(&bytes, COMPLETE);

    assert_eq!(report.status, ParseStatus::Unsupported);
    assert!(report.findings.is_empty());
    assert_eq!(
        report.unparsed,
        [ByteRange {
            offset: 0,
            length: zero_prefix_bytes,
        }]
    );
    assert!(report.budget_omissions.is_empty());
    Ok(())
}

#[test]
fn zero_length_dns_frame_decoded() -> Result<(), &'static str> {
    let zero_prefix_count = MAX_ENTRIES + 17;
    let zero_prefix_bytes = zero_prefix_count
        .checked_mul(2)
        .ok_or("zero-prefix length overflow")?;
    let mut bytes = vec![0; zero_prefix_bytes];
    let valid_frame = append_dns_frame(&mut bytes, &dns_query())?;
    let report = decode_dns_tcp(&bytes, COMPLETE);

    assert_eq!(report.status, ParseStatus::Unsupported);
    assert_eq!(report.unparsed, [ByteRange::new(0, zero_prefix_bytes)]);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(
        report.findings.first().map(|frame| frame.frame_range),
        Some(valid_frame)
    );
    assert!(
        report
            .findings
            .first()
            .is_some_and(|frame| frame.message.is_some())
    );
    assert!(report.budget_omissions.is_empty());
    Ok(())
}

#[test]
fn impossible_dns_not_entry_budget() -> Result<(), &'static str> {
    let mut message = vec![0; 12];
    let question_count = u16::try_from(l2_workbench::application::MAX_ENTRIES + 1)
        .map_err(|_| "DNS question count does not fit in the header")?;
    message
        .get_mut(4..6)
        .ok_or("DNS header is missing the question count")?
        .copy_from_slice(&question_count.to_be_bytes());
    let bytes = dns_tcp_frame(&message)?;
    let report = decode_dns_tcp(&bytes, COMPLETE);
    let frame = report
        .findings
        .first()
        .ok_or("missing DNS/TCP candidate frame")?;

    assert_eq!(
        frame.error.map(|error| error.kind),
        Some(DnsErrorKind::Incomplete)
    );
    assert!(report.budget_omissions.is_empty());
    Ok(())
}

#[test]
fn oversized_dns_not_message_budget() -> Result<(), &'static str> {
    let mut message = vec![0; MAX_MESSAGE_BYTES + 1];
    let question_count = 4_000_u16;
    message
        .get_mut(4..6)
        .ok_or("DNS header is missing the question count")?
        .copy_from_slice(&question_count.to_be_bytes());
    let bytes = dns_tcp_frame(&message)?;
    let report = decode_dns_tcp(&bytes, COMPLETE);
    let frame = report
        .findings
        .first()
        .ok_or("missing oversized DNS/TCP candidate frame")?;

    assert_eq!(
        frame.error.map(|error| error.kind),
        Some(DnsErrorKind::Incomplete)
    );
    assert!(report.budget_omissions.is_empty());
    Ok(())
}
