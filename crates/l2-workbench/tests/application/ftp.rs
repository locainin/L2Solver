use super::support::{COMPLETE, UNKNOWN_START, slice};
use l2_discovery::NetworkAddress;
use l2_workbench::application::ftp::{FtpCommandAction, FtpEndpoint, FtpKind};
use l2_workbench::application::{
    ByteRange, MAX_ENTRIES, MAX_LINE_BYTES, ParseStatus, ftp::decode_ftp,
};

#[test]
fn invalid_controls_without_budget_omission() {
    for control in [0_u8, 9, 10, 13, 31, 127] {
        let mut input = b"NOOP ".to_vec();
        input.push(control);
        input.extend(std::iter::repeat_n(b'A', MAX_LINE_BYTES));
        let report = decode_ftp(&input, COMPLETE);
        assert_eq!(report.status, ParseStatus::Unsupported);
        assert_eq!(report.budget_omissions.len(), 0);
        assert_eq!(report.findings.len(), 0);
        assert_eq!(report.unparsed, [ByteRange::new(0, input.len())]);
    }
}

#[test]
fn unfinished_crlf_without_budget_omission() {
    let report = decode_ftp(b"NOOP\r", COMPLETE);
    assert_eq!(report.status, ParseStatus::Incomplete);
    assert_eq!(report.budget_omissions.len(), 0);
}

#[test]
fn unfinished_delimiter_at_exact_limit() {
    let mut input = b"RETR ".to_vec();
    input.resize(MAX_LINE_BYTES, b'A');
    input.push(b'\r');
    let report = decode_ftp(&input, COMPLETE);
    assert_eq!(report.status, ParseStatus::Incomplete);
    assert_eq!(report.budget_omissions.len(), 0);
}

#[test]
fn interior_cr_over_line_limit() {
    let mut input = b"RETR ".to_vec();
    input.resize(MAX_LINE_BYTES + 1, b'A');
    input.extend_from_slice(b"\rZ");
    let report = decode_ftp(&input, COMPLETE);
    assert_eq!(report.status, ParseStatus::Unsupported);
    assert_eq!(report.budget_omissions.len(), 0);
}

#[test]
fn impossible_command_without_budget_omission() {
    for prefix in [
        b"<tag ".as_slice(),
        b"1x ".as_slice(),
        b"ABCDEFGHIJKLMNOPQ ".as_slice(),
    ] {
        let mut input = prefix.to_vec();
        input.extend(std::iter::repeat_n(b'A', MAX_LINE_BYTES));
        let report = decode_ftp(&input, COMPLETE);
        assert_eq!(report.status, ParseStatus::Unsupported);
        assert_eq!(report.budget_omissions.len(), 0);
        assert_eq!(report.unparsed, [ByteRange::new(0, input.len())]);
    }
}

#[test]
fn long_printable_replies_real_budget() {
    let mut input = b"220-first line\r\n<tag ".to_vec();
    input.extend(std::iter::repeat_n(b'A', MAX_LINE_BYTES));
    let report = decode_ftp(&input, COMPLETE);
    assert_eq!(report.status, ParseStatus::Unsupported);
    assert_eq!(report.budget_omissions.len(), 1);
    assert_eq!(
        report
            .budget_omissions
            .first()
            .map(|omission| omission.budget),
        Some(l2_workbench::application::ParserBudget::LineBytes)
    );
}

#[test]
fn transfer_commands_exact_path_ranges() -> Result<(), &'static str> {
    let bytes = b"RETR /pub/file name.bin\r\nSTOR ./incoming.bin\r\n";
    let report = decode_ftp(bytes, COMPLETE);
    let retrieve = report.findings.first().ok_or("missing RETR command")?;
    let store = report.findings.get(1).ok_or("missing STOR command")?;
    let FtpKind::Command(retrieve) = &retrieve.kind else {
        return Err("first line is not a command");
    };
    let FtpKind::Command(store) = &store.kind else {
        return Err("second line is not a command");
    };

    assert_eq!(report.status, ParseStatus::Complete);
    assert_eq!(retrieve.action, FtpCommandAction::Retrieve);
    assert_eq!(
        slice(bytes, retrieve.argument_range.ok_or("missing RETR path")?)?,
        b"/pub/file name.bin"
    );
    assert_eq!(store.action, FtpCommandAction::Store);
    assert_eq!(
        slice(bytes, store.argument_range.ok_or("missing STOR path")?)?,
        b"./incoming.bin"
    );
    Ok(())
}

#[test]
fn active_endpoint_ipv4_ipv6_facts() -> Result<(), &'static str> {
    let bytes = b"PORT 203,0,113,7,195,80\r\nEPRT |2|2001:db8::7|6446|\r\n";
    let report = decode_ftp(bytes, COMPLETE);
    let port_line = report.findings.first().ok_or("missing PORT command")?;
    let eprt_line = report.findings.get(1).ok_or("missing EPRT command")?;
    let FtpKind::Command(port) = &port_line.kind else {
        return Err("PORT line was not parsed as a command");
    };
    let FtpKind::Command(eprt) = &eprt_line.kind else {
        return Err("EPRT line was not parsed as a command");
    };

    assert_eq!(port.action, FtpCommandAction::ActiveEndpoint);
    assert_eq!(
        port.endpoint,
        Some(FtpEndpoint {
            address: Some(NetworkAddress::Ipv4([203, 0, 113, 7])),
            port: 50_000,
        })
    );
    assert_eq!(eprt.action, FtpCommandAction::ActiveEndpoint);
    assert_eq!(
        eprt.endpoint,
        Some(FtpEndpoint {
            address: Some(NetworkAddress::Ipv6([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
            ])),
            port: 6446,
        })
    );
    assert_eq!(
        slice(bytes, port.argument_range.ok_or("missing PORT argument")?)?,
        b"203,0,113,7,195,80"
    );
    assert_eq!(
        slice(bytes, eprt.argument_range.ok_or("missing EPRT argument")?)?,
        b"|2|2001:db8::7|6446|"
    );
    Ok(())
}

#[test]
fn eprt_accepts_ascii_delimiter_wire() -> Result<(), &'static str> {
    let bytes = b"EPRT (1(192.0.2.5(21(\r\n";
    let report = decode_ftp(bytes, COMPLETE);
    let line = report.findings.first().ok_or("missing EPRT command")?;
    let FtpKind::Command(command) = &line.kind else {
        return Err("EPRT line was not parsed as a command");
    };

    assert_eq!(report.status, ParseStatus::Complete);
    assert_eq!(
        command.endpoint,
        Some(FtpEndpoint {
            address: Some(NetworkAddress::Ipv4([192, 0, 2, 5])),
            port: 21,
        })
    );
    Ok(())
}

#[test]
fn passive_replies_optional_address_facts() -> Result<(), &'static str> {
    let bytes = b"227 Entering Passive Mode (203,0,113,8,195,80)\r\n229 Entering Extended Passive Mode (|||6446|)\r\n";
    let report = decode_ftp(bytes, COMPLETE);
    let pasv = report.findings.first().ok_or("missing PASV reply")?;
    let epsv = report.findings.get(1).ok_or("missing EPSV reply")?;
    let FtpKind::Reply(pasv) = &pasv.kind else {
        return Err("227 line was not parsed as a reply");
    };
    let FtpKind::Reply(epsv) = &epsv.kind else {
        return Err("229 line was not parsed as a reply");
    };

    assert_eq!(report.status, ParseStatus::Complete);
    assert_eq!(pasv.code, 227);
    assert_eq!(
        pasv.endpoint,
        Some(FtpEndpoint {
            address: Some(NetworkAddress::Ipv4([203, 0, 113, 8])),
            port: 50_000,
        })
    );
    assert_eq!(epsv.code, 229);
    assert_eq!(
        epsv.endpoint,
        Some(FtpEndpoint {
            address: None,
            port: 6446
        })
    );
    assert_eq!(
        slice(bytes, pasv.text_range)?,
        b"Entering Passive Mode (203,0,113,8,195,80)"
    );
    Ok(())
}

#[test]
fn multiline_passive_lines_extracting_endpoint() -> Result<(), &'static str> {
    let bytes =
        b"227-Entering Passive Mode\r\n(203,0,113,8,195,80)\r\n227 Transfer socket ready\r\n";
    let report = decode_ftp(bytes, COMPLETE);
    let reply_line = report.findings.first().ok_or("missing grouped reply")?;
    let FtpKind::Reply(reply) = &reply_line.kind else {
        return Err("multi-line response was not parsed as a reply");
    };

    assert_eq!(report.findings.len(), 1);
    assert_eq!(reply_line.status, ParseStatus::Complete);
    assert_eq!(reply.code, 227);
    assert!(reply.multiline);
    assert_eq!(reply.endpoint.map(|value| value.port), Some(50_000));
    assert_eq!(slice(bytes, reply_line.range)?, bytes);
    Ok(())
}

#[test]
fn malformed_ambiguous_endpoints_not_selected() -> Result<(), &'static str> {
    let malformed = b"PORT 203,0,113,7,256,1\r\n";
    let report = decode_ftp(malformed, COMPLETE);
    let line = report.findings.first().ok_or("missing malformed PORT")?;
    let FtpKind::Command(command) = &line.kind else {
        return Err("malformed PORT line was not retained as a command");
    };
    assert_eq!(report.status, ParseStatus::Unsupported);
    assert_eq!(line.status, ParseStatus::Unsupported);
    assert_eq!(command.endpoint, None);
    assert_eq!(
        slice(
            malformed,
            command.argument_range.ok_or("missing bad argument")?
        )?,
        b"203,0,113,7,256,1"
    );

    let ambiguous = b"227 Choices (203,0,113,7,195,80) or (203,0,113,8,195,81)\r\n";
    let report = decode_ftp(ambiguous, COMPLETE);
    let line = report.findings.first().ok_or("missing ambiguous reply")?;
    let FtpKind::Reply(reply) = &line.kind else {
        return Err("ambiguous response was not parsed as a reply");
    };
    assert_eq!(report.status, ParseStatus::Ambiguous);
    assert_eq!(line.status, ParseStatus::Ambiguous);
    assert_eq!(reply.endpoint, None);
    Ok(())
}

#[test]
fn port_octets_range_not_endpoints() -> Result<(), &'static str> {
    let cases = [
        b"PORT 203,0,113,7,1,256\r\n".as_slice(),
        b"227 Passive (203,0,113,7,1,256)\r\n".as_slice(),
    ];
    for bytes in cases {
        let report = decode_ftp(bytes, COMPLETE);
        let line = report
            .findings
            .first()
            .ok_or("missing malformed endpoint line")?;
        assert_eq!(line.status, ParseStatus::Unsupported);
        match &line.kind {
            FtpKind::Command(command) => assert_eq!(command.endpoint, None),
            FtpKind::Reply(reply) => assert_eq!(reply.endpoint, None),
            FtpKind::Other => return Err("malformed endpoint line lost its parsed kind"),
        }
    }
    Ok(())
}

#[test]
fn incomplete_lines_replies_raw_ranges() -> Result<(), &'static str> {
    let partial = b"RETR /path-without-terminator";
    let partial_report = decode_ftp(partial, COMPLETE);
    assert_eq!(partial_report.status, ParseStatus::Incomplete);
    assert_eq!(
        partial_report.unparsed,
        [ByteRange {
            offset: 0,
            length: partial.len()
        }]
    );

    let multiline = b"220-Welcome\r\nAdditional text\r\n";
    let multiline_report = decode_ftp(multiline, COMPLETE);
    let finding = multiline_report
        .findings
        .first()
        .ok_or("missing incomplete reply")?;
    assert_eq!(multiline_report.status, ParseStatus::Incomplete);
    assert_eq!(finding.status, ParseStatus::Incomplete);
    assert_eq!(slice(multiline, finding.range)?, multiline);
    Ok(())
}

#[test]
fn unknown_parsed_line_boundary_ambiguous() -> Result<(), &'static str> {
    let bytes = b"RETR /captured/path\r\n";
    let report = decode_ftp(bytes, UNKNOWN_START);
    let finding = report
        .findings
        .first()
        .ok_or("candidate line was discarded")?;

    assert_eq!(report.status, ParseStatus::Ambiguous);
    assert_eq!(finding.status, ParseStatus::Ambiguous);
    assert_eq!(slice(bytes, finding.range)?, bytes);
    assert!(matches!(finding.kind, FtpKind::Command(_)));
    Ok(())
}

#[test]
fn parser_limits_exact_unprocessed_suffix() -> Result<(), &'static str> {
    let mut stream = Vec::new();
    for _ in 0..=MAX_ENTRIES {
        stream.extend_from_slice(b"NOOP\r\n");
    }
    let report = decode_ftp(&stream, COMPLETE);
    let last_line = report.findings.last().ok_or("missing retained FTP line")?;
    let retained_end = last_line
        .range
        .offset
        .checked_add(last_line.range.length)
        .ok_or("line range overflow")?;
    let retained_length = stream
        .len()
        .checked_sub(retained_end)
        .ok_or("retained range exceeds fixture")?;
    assert_eq!(report.status, ParseStatus::Unsupported);
    assert_eq!(report.findings.len(), MAX_ENTRIES);
    assert_eq!(
        report.unparsed,
        [ByteRange {
            offset: retained_end,
            length: retained_length,
        }]
    );

    let long_line = vec![b'A'; MAX_LINE_BYTES + 1];
    let long_report = decode_ftp(&long_line, COMPLETE);
    assert_eq!(long_report.status, ParseStatus::Unsupported);
    assert_eq!(
        long_report.unparsed,
        [ByteRange {
            offset: 0,
            length: long_line.len()
        }]
    );
    Ok(())
}
