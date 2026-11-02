use super::support::{COMPLETE, OPEN_END, UNKNOWN_START, locate, slice};
use l2_workbench::application::{
    ByteRange, MAX_ENTRIES, MAX_HTTP_HEADER_BYTES, MAX_INPUT_BYTES, MAX_LINE_BYTES, ParseReport,
    ParseStatus, ParserBudget,
    http::{
        HttpBody, HttpFraming, HttpLineEnding, HttpRequestMethod, HttpStart, decode_http,
        decode_http_with_methods,
    },
};

#[test]
fn invalid_controls_reporting_line_budget() {
    for prefix in [b"GET /\0".as_slice(), b"GET / HTTP/1.1\r\nX: \0".as_slice()] {
        let mut input = prefix.to_vec();
        input.extend(std::iter::repeat_n(b'A', MAX_LINE_BYTES));
        let report = decode_http(&input, COMPLETE);
        assert_eq!(report.status, ParseStatus::Unsupported);
        assert_eq!(report.budget_omissions.len(), 0);
        assert_eq!(report.findings.len(), 0);
        assert_eq!(report.unparsed, [ByteRange::new(0, input.len())]);
    }
}

#[test]
fn unfinished_delimiter_at_exact_limit() {
    let mut input = b"GET / HTTP/1.1\r\nX: ".to_vec();
    input.extend(std::iter::repeat_n(b'A', MAX_LINE_BYTES - b"X: ".len()));
    input.push(b'\r');
    let report = decode_http(&input, COMPLETE);
    assert_eq!(report.status, ParseStatus::Incomplete);
    assert_eq!(report.budget_omissions.len(), 0);
}

#[test]
fn interior_cr_over_line_limit() {
    let mut input = b"GET / HTTP/1.1\r\nX: ".to_vec();
    input.extend(std::iter::repeat_n(b'A', MAX_LINE_BYTES + 1 - b"X: ".len()));
    input.extend_from_slice(b"\rZ");
    let report = decode_http(&input, COMPLETE);
    assert_eq!(report.status, ParseStatus::Unsupported);
    assert_eq!(report.budget_omissions.len(), 0);
}

#[test]
fn content_length_request_exact_ranges() -> Result<(), &'static str> {
    let bytes = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhelloGET /next HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
    let report = decode_http(bytes, COMPLETE);
    let first = report
        .findings
        .first()
        .ok_or("missing first HTTP message")?;
    let second = report
        .findings
        .get(1)
        .ok_or("missing pipelined HTTP message")?;
    let HttpBody::Contiguous { range, complete } = &first.body else {
        return Err("expected one contiguous HTTP body range");
    };

    assert_eq!(report.status, ParseStatus::Complete);
    assert_eq!(report.findings.len(), 2);
    assert_eq!(first.line_ending, HttpLineEnding::CrLf);
    assert!(*complete);
    assert_eq!(*range, locate(bytes, b"hello")?);
    assert_eq!(slice(bytes, *range)?, b"hello");
    assert_eq!(first.status, ParseStatus::Complete);
    assert_eq!(second.status, ParseStatus::Complete);
    assert!(matches!(&second.body, HttpBody::Empty));
    assert_eq!(first.framing, HttpFraming::ContentLength { expected: 5 });
    Ok(())
}

#[test]
fn unique_content_length() -> Result<(), &'static str> {
    let bytes = b"POST / HTTP/1.1\r\nContent-Length: 3, 03\r\n\r\nabc";
    let report = decode_http(bytes, COMPLETE);
    let message = report.findings.first().ok_or("missing HTTP message")?;
    let HttpBody::Contiguous { range, complete } = &message.body else {
        return Err("expected a contiguous body");
    };

    assert_eq!(report.status, ParseStatus::Complete);
    assert_eq!(message.framing, HttpFraming::ContentLength { expected: 3 });
    assert!(complete);
    assert_eq!(slice(bytes, *range)?, b"abc");
    Ok(())
}

#[test]
fn conflicting_lengths_transfer_encoding_ambiguous() -> Result<(), &'static str> {
    let conflicting = b"POST / HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nabc";
    let report = decode_http(conflicting, COMPLETE);
    let message = report.findings.first().ok_or("missing ambiguous message")?;
    assert_eq!(report.status, ParseStatus::Ambiguous);
    assert_eq!(message.status, ParseStatus::Ambiguous);
    assert_eq!(message.framing, HttpFraming::Ambiguous);
    assert!(matches!(&message.body, HttpBody::Unresolved { .. }));

    let both =
        b"POST / HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    let report = decode_http(both, COMPLETE);
    let message = report.findings.first().ok_or("missing CL/TE message")?;
    assert_eq!(report.status, ParseStatus::Ambiguous);
    assert_eq!(message.framing, HttpFraming::Ambiguous);
    assert!(matches!(&message.body, HttpBody::Unresolved { .. }));
    assert_eq!(report.findings.len(), 1);
    Ok(())
}

#[test]
fn chunked_body_trailer_source_range() -> Result<(), &'static str> {
    let bytes = b"POST /chunk HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Check: yes\r\n\r\n";
    let report = decode_http(bytes, COMPLETE);
    let message = report.findings.first().ok_or("missing chunked message")?;
    let HttpBody::Chunked {
        chunks,
        trailers,
        trailer_range,
        raw_remainder,
        complete,
    } = &message.body
    else {
        return Err("expected chunked body evidence");
    };

    assert_eq!(report.status, ParseStatus::Complete);
    assert_eq!(message.framing, HttpFraming::Chunked);
    assert_eq!(chunks.len(), 2);
    assert_eq!(trailers.len(), 1);
    assert_eq!(
        slice(bytes, *chunks.first().ok_or("missing first chunk")?)?,
        b"Wiki"
    );
    assert_eq!(
        slice(bytes, *chunks.get(1).ok_or("missing second chunk")?)?,
        b"pedia"
    );
    assert_eq!(
        slice(bytes, (*trailer_range).ok_or("missing trailer range")?)?,
        b"X-Check: yes\r\n\r\n"
    );
    let trailer = trailers.first().ok_or("missing parsed trailer")?;
    assert_eq!(slice(bytes, trailer.name)?, b"X-Check");
    assert_eq!(slice(bytes, trailer.value)?, b"yes");
    assert!(raw_remainder.is_none());
    assert!(complete);
    Ok(())
}

#[test]
fn chunk_extensions_tokens_quoted_values() -> Result<(), &'static str> {
    let bytes = b"POST /chunk HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4;name=value;note=\"a\\\"b\"\r\nWiki\r\n0\r\n\r\n";
    let report = decode_http(bytes, COMPLETE);
    let message = report.findings.first().ok_or("missing chunked message")?;
    let HttpBody::Chunked {
        chunks, complete, ..
    } = &message.body
    else {
        return Err("expected chunked body evidence");
    };

    assert_eq!(report.status, ParseStatus::Complete);
    assert!(complete);
    assert_eq!(
        slice(bytes, *chunks.first().ok_or("missing body chunk")?)?,
        b"Wiki"
    );
    Ok(())
}

#[test]
fn incomplete_chunked_unparsed_chunk_bytes() -> Result<(), &'static str> {
    let bytes = b"POST /chunk HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabc";
    let report = decode_http(bytes, COMPLETE);
    let message = report
        .findings
        .first()
        .ok_or("missing partial chunked message")?;
    let HttpBody::Chunked {
        raw_remainder,
        complete,
        ..
    } = &message.body
    else {
        return Err("expected partial chunked evidence");
    };

    assert_eq!(report.status, ParseStatus::Incomplete);
    assert_eq!(message.status, ParseStatus::Incomplete);
    assert!(!complete);
    assert_eq!(
        slice(bytes, (*raw_remainder).ok_or("missing raw chunk tail")?)?,
        b"5\r\nabc"
    );
    Ok(())
}

#[test]
fn complete_chunk_input_end_range() -> Result<(), &'static str> {
    let bytes = b"POST /chunk HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n";
    let report = decode_http(bytes, COMPLETE);
    let message = report
        .findings
        .first()
        .ok_or("missing incomplete chunked message")?;
    let HttpBody::Chunked {
        chunks,
        raw_remainder,
        complete,
        ..
    } = &message.body
    else {
        return Err("expected a chunked body candidate");
    };

    assert_eq!(report.status, ParseStatus::Incomplete);
    assert!(!complete);
    assert_eq!(
        slice(
            bytes,
            *chunks.first().ok_or("complete data chunk was lost")?
        )?,
        b"Wiki"
    );
    assert_eq!(*raw_remainder, Some(ByteRange::new(bytes.len(), 0)));
    Ok(())
}

#[test]
fn incomplete_content_prefix_expected_size() -> Result<(), &'static str> {
    let bytes = b"POST / HTTP/1.1\r\nContent-Length: 8\r\n\r\ndata";
    let report = decode_http(bytes, COMPLETE);
    let message = report.findings.first().ok_or("missing incomplete body")?;
    let HttpBody::Contiguous { range, complete } = &message.body else {
        return Err("expected partial contiguous body");
    };

    assert_eq!(report.status, ParseStatus::Incomplete);
    assert_eq!(message.framing, HttpFraming::ContentLength { expected: 8 });
    assert!(!complete);
    assert_eq!(slice(bytes, *range)?, b"data");
    Ok(())
}

#[test]
fn close_delimited_needs_observed_end() -> Result<(), &'static str> {
    let bytes = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbody";
    let methods = [Some(HttpRequestMethod::Other)];
    let complete = decode_http_with_methods(bytes, COMPLETE, &methods);
    let complete_message = complete.findings.first().ok_or("missing response")?;
    let HttpBody::Contiguous {
        range: complete_range,
        complete: body_complete,
    } = &complete_message.body
    else {
        return Err("expected close-delimited body");
    };
    assert_eq!(complete.status, ParseStatus::Complete);
    assert_eq!(complete_message.framing, HttpFraming::CloseDelimited);
    assert!(body_complete);
    assert_eq!(slice(bytes, *complete_range)?, b"body");

    let open = decode_http_with_methods(bytes, OPEN_END, &methods);
    let open_message = open.findings.first().ok_or("missing open response")?;
    assert_eq!(open.status, ParseStatus::Incomplete);
    assert_eq!(open_message.status, ParseStatus::Incomplete);
    Ok(())
}

#[test]
fn unpaired_response_body_is_ambiguous() -> Result<(), &'static str> {
    let bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndata";
    let report = decode_http(bytes, COMPLETE);
    let message = report
        .findings
        .first()
        .ok_or("missing response candidate")?;

    assert_eq!(report.status, ParseStatus::Ambiguous);
    assert_eq!(message.status, ParseStatus::Ambiguous);
    assert_eq!(message.framing, HttpFraming::Ambiguous);
    let HttpBody::Unresolved { range } = &message.body else {
        return Err("unpaired response body was treated as known");
    };
    assert_eq!(slice(bytes, *range)?, b"data");
    Ok(())
}

#[test]
fn head_response_preserves_next_response() {
    let bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n";
    let methods = [
        Some(HttpRequestMethod::Head),
        Some(HttpRequestMethod::Other),
    ];
    let report = decode_http_with_methods(bytes, COMPLETE, &methods);

    assert_eq!(report.status, ParseStatus::Complete);
    assert_eq!(report.findings.len(), 2);
    assert!(matches!(
        report.findings.first().map(|item| &item.body),
        Some(HttpBody::Empty)
    ));
    assert_eq!(
        report.findings.first().map(|item| item.framing),
        Some(HttpFraming::NoBody)
    );
    assert!(matches!(
        report.findings.get(1).map(|item| &item.body),
        Some(HttpBody::Empty)
    ));
}

#[test]
fn successful_connect_without_http_parsing() -> Result<(), &'static str> {
    let bytes = b"HTTP/1.1 200 Connection Established\r\n\r\ntunnel bytes";
    let methods = [Some(HttpRequestMethod::Connect)];
    let report = decode_http_with_methods(bytes, COMPLETE, &methods);
    let message = report.findings.first().ok_or("missing CONNECT response")?;

    assert_eq!(report.status, ParseStatus::Complete);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(message.framing, HttpFraming::Tunnel);
    let HttpBody::Tunnel { range } = &message.body else {
        return Err("successful CONNECT was not reported as a tunnel transition");
    };
    assert_eq!(slice(bytes, *range)?, b"tunnel bytes");
    assert_eq!(message.range, ByteRange::new(0, range.offset));
    assert_eq!(
        slice(bytes, message.range)?,
        b"HTTP/1.1 200 Connection Established\r\n\r\n"
    );
    assert_eq!(report.unparsed.len(), 0);
    Ok(())
}

#[test]
fn successful_connect_tunnel_bytes_unqualified() -> Result<(), &'static str> {
    for framing_header in ["Content-Length: 5\r\n", "Transfer-Encoding: chunked\r\n"] {
        let bytes = format!("HTTP/1.1 200 Connection Established\r\n{framing_header}\r\ntunnel");
        let report = decode_http_with_methods(
            bytes.as_bytes(),
            COMPLETE,
            &[Some(HttpRequestMethod::Connect)],
        );
        let message = report.findings.first().ok_or("missing CONNECT response")?;

        assert_eq!(report.status, ParseStatus::Unsupported);
        assert_eq!(message.status, ParseStatus::Unsupported);
        assert_eq!(message.framing, HttpFraming::Tunnel);
        let HttpBody::Tunnel { range } = &message.body else {
            return Err("CONNECT tunnel candidate was discarded");
        };
        assert_eq!(slice(bytes.as_bytes(), *range)?, b"tunnel");
    }
    Ok(())
}

#[test]
fn bodyless_status_without_next_response() -> Result<(), &'static str> {
    for framing_header in ["Content-Length: 0\r\n", "Transfer-Encoding: chunked\r\n"] {
        let bytes = format!(
            "HTTP/1.1 204 No Content\r\n{framing_header}\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        );
        let methods = [
            Some(HttpRequestMethod::Other),
            Some(HttpRequestMethod::Other),
        ];
        let report = decode_http_with_methods(bytes.as_bytes(), COMPLETE, &methods);
        let first = report.findings.first().ok_or("missing bodyless response")?;
        let second = report.findings.get(1).ok_or("next response was lost")?;

        assert_eq!(report.status, ParseStatus::Unsupported);
        assert_eq!(report.findings.len(), 2);
        assert_eq!(first.status, ParseStatus::Unsupported);
        assert_eq!(first.framing, HttpFraming::NoBody);
        assert!(matches!(first.body, HttpBody::Empty));
        assert_eq!(second.status, ParseStatus::Complete);
        assert_eq!(report.unparsed.len(), 0);
    }
    Ok(())
}

#[test]
fn head_not_losing_next_response() -> Result<(), &'static str> {
    let cases = [
        (
            "HTTP/1.1 200 OK\r\nContent-Length: invalid\r\n\r\n",
            Some(HttpRequestMethod::Head),
        ),
        (
            "HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked, chunked\r\n\r\n",
            Some(HttpRequestMethod::Other),
        ),
    ];
    for (first, method) in cases {
        let bytes = format!("{first}HTTP/1.1 204 No Content\r\n\r\n");
        let report = decode_http_with_methods(
            bytes.as_bytes(),
            COMPLETE,
            &[method, Some(HttpRequestMethod::Other)],
        );
        let first_message = report.findings.first().ok_or("missing bodyless response")?;
        let next_message = report.findings.get(1).ok_or("next response was lost")?;

        assert_eq!(report.status, ParseStatus::Unsupported);
        assert_eq!(report.findings.len(), 2);
        assert_eq!(first_message.status, ParseStatus::Unsupported);
        assert_eq!(first_message.framing, HttpFraming::NoBody);
        assert_eq!(next_message.status, ParseStatus::Complete);
        assert_eq!(report.unparsed.len(), 0);
    }
    Ok(())
}

#[test]
fn switching_protocol_not_http_message() -> Result<(), &'static str> {
    let bytes = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: example\r\n\r\nopaque frame";
    let methods = [Some(HttpRequestMethod::Other)];
    let report = decode_http_with_methods(bytes, COMPLETE, &methods);
    let message = report
        .findings
        .first()
        .ok_or("missing protocol-switch response")?;
    let suffix = locate(bytes, b"opaque frame")?;

    assert_eq!(report.status, ParseStatus::Unsupported);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(message.range, ByteRange::new(0, suffix.offset));
    assert_eq!(message.status, ParseStatus::Complete);
    assert!(matches!(&message.body, HttpBody::Empty));
    assert_eq!(report.unparsed, [suffix]);
    assert_eq!(slice(bytes, suffix)?, b"opaque frame");
    Ok(())
}

#[test]
fn informational_response_not_method_association() {
    let bytes = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n";
    let methods = [Some(HttpRequestMethod::Head)];
    let report = decode_http_with_methods(bytes, COMPLETE, &methods);

    assert_eq!(report.status, ParseStatus::Complete);
    assert_eq!(report.findings.len(), 2);
    assert!(matches!(
        report.findings.get(1).map(|item| &item.body),
        Some(HttpBody::Empty)
    ));
}

#[test]
fn unknown_overlong_header_unparsed_bytes() -> Result<(), &'static str> {
    let bytes = b"GET / HTTP/1.1\r\n\r\n";
    let unknown = decode_http(bytes, UNKNOWN_START);
    let unknown_message = unknown
        .findings
        .first()
        .ok_or("candidate message was discarded")?;
    assert_eq!(unknown.status, ParseStatus::Ambiguous);
    assert_eq!(unknown_message.status, ParseStatus::Ambiguous);
    assert_eq!(
        unknown_message.range,
        ByteRange {
            offset: 0,
            length: bytes.len()
        }
    );

    let mut oversized = b"GET / HTTP/1.1\r\nX-Long: ".to_vec();
    oversized.resize(MAX_HTTP_HEADER_BYTES + 1, b'a');
    let report = decode_http(&oversized, COMPLETE);
    assert_eq!(report.status, ParseStatus::Unsupported);
    assert_eq!(
        report.unparsed,
        [ByteRange {
            offset: 0,
            length: oversized.len()
        }]
    );
    Ok(())
}

#[test]
fn request_header_budget_relative_message() {
    let first = b"GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
    let mut exact = first.to_vec();
    exact.extend_from_slice(b"GET /large HTTP/1.1\r\n");
    append_sized_headers(&mut exact, [8185, 8184, 8184, 8184]);
    exact.extend_from_slice(b"\r\n");
    let exact_report = decode_http(&exact, COMPLETE);
    assert_eq!(exact_report.status, ParseStatus::Complete);
    assert_eq!(exact_report.findings.len(), 2);

    let mut over_limit = first.to_vec();
    over_limit.extend_from_slice(b"GET /large HTTP/1.1\r\n");
    append_sized_headers(&mut over_limit, [8186, 8184, 8184, 8184]);
    over_limit.extend_from_slice(b"\r\n");
    let report = decode_http(&over_limit, COMPLETE);

    assert_eq!(report.status, ParseStatus::Unsupported);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(
        report.unparsed,
        [ByteRange::new(first.len(), over_limit.len() - first.len())]
    );
}

#[test]
fn unterminated_request_exact_budget_incomplete() {
    let first = b"GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
    let mut bytes = first.to_vec();
    bytes.extend_from_slice(b"GET /large HTTP/1.1\r\n");
    append_sized_headers(&mut bytes, [8187, 8184, 8184, 8184]);
    assert_eq!(bytes.len() - first.len(), MAX_HTTP_HEADER_BYTES);

    let report = decode_http(&bytes, COMPLETE);

    assert_eq!(report.status, ParseStatus::Incomplete);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(
        report.unparsed,
        [ByteRange::new(first.len(), MAX_HTTP_HEADER_BYTES)]
    );
}

#[test]
fn chunk_trailer_exact_limit_overflow() -> Result<(), &'static str> {
    let prefix = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n";
    let mut exact = prefix.to_vec();
    append_sized_headers(&mut exact, [8190, 8189, 8189, 8190]);
    exact.extend_from_slice(b"\r\n");
    let exact_report = decode_http(&exact, COMPLETE);
    assert_eq!(exact_report.status, ParseStatus::Complete);
    let exact_message = exact_report
        .findings
        .first()
        .ok_or("missing exact-limit chunked message")?;
    assert!(matches!(
        &exact_message.body,
        HttpBody::Chunked { complete: true, .. }
    ));

    let mut over_limit = prefix.to_vec();
    append_sized_headers(&mut over_limit, [8191, 8189, 8189, 8190]);
    over_limit.extend_from_slice(b"\r\n");
    let report = decode_http(&over_limit, COMPLETE);
    let message = report
        .findings
        .first()
        .ok_or("missing over-limit chunked candidate")?;
    let HttpBody::Chunked { raw_remainder, .. } = &message.body else {
        return Err("expected an unresolved chunked candidate");
    };

    assert_eq!(report.status, ParseStatus::Unsupported);
    assert_eq!(
        slice(
            &over_limit,
            (*raw_remainder).ok_or("missing unprocessed trailer tail")?
        )?,
        b"\r\n"
    );
    Ok(())
}

#[test]
fn line_limit_boundary_overlong_input() {
    let mut exact_lf = request_start_line(MAX_LINE_BYTES);
    exact_lf.extend_from_slice(b"\n\n");
    let lf_report = decode_http(&exact_lf, COMPLETE);
    assert_eq!(lf_report.status, ParseStatus::Complete);
    assert_eq!(
        lf_report
            .findings
            .first()
            .map(|message| message.line_ending),
        Some(HttpLineEnding::Lf)
    );

    let mut exact_crlf = request_start_line(MAX_LINE_BYTES);
    exact_crlf.extend_from_slice(b"\r\n\r\n");
    let crlf_report = decode_http(&exact_crlf, COMPLETE);
    assert_eq!(crlf_report.status, ParseStatus::Complete);
    assert_eq!(
        crlf_report
            .findings
            .first()
            .map(|message| message.line_ending),
        Some(HttpLineEnding::CrLf)
    );

    let mut overlong_lf = request_start_line(MAX_LINE_BYTES.saturating_add(1));
    overlong_lf.extend_from_slice(b"\n\n");
    let overlong_report = decode_http(&overlong_lf, COMPLETE);
    assert_eq!(overlong_report.status, ParseStatus::Unsupported);
    assert_eq!(overlong_report.findings.len(), 0);
    assert_eq!(
        overlong_report.unparsed,
        [ByteRange::new(0, overlong_lf.len())]
    );

    let unterminated = request_start_line(MAX_LINE_BYTES);
    let partial_report = decode_http(&unterminated, OPEN_END);
    assert_eq!(partial_report.status, ParseStatus::Incomplete);
    assert_eq!(partial_report.findings.len(), 0);
    assert_eq!(
        partial_report.unparsed,
        [ByteRange::new(0, unterminated.len())]
    );
}

#[test]
fn whitespace_header_without_consuming_input() {
    let bytes = b"GET / HTTP/1.1\r\nBad Name: value\r\n\r\n";
    let report = decode_http(bytes, COMPLETE);

    assert_eq!(report.status, ParseStatus::Unsupported);
    assert_eq!(report.findings.len(), 0);
    assert_eq!(report.unparsed, [ByteRange::new(0, bytes.len())]);
}

#[test]
fn malformed_reason_not_complete_http() -> Result<(), &'static str> {
    let invalid_reason = b"HTTP/1.1 200 bad\x00reason\r\nContent-Length: 0\r\n\r\n";
    let reason_report =
        decode_http_with_methods(invalid_reason, COMPLETE, &[Some(HttpRequestMethod::Other)]);
    assert_eq!(reason_report.status, ParseStatus::Unsupported);
    assert_eq!(reason_report.findings.len(), 0);
    assert_eq!(
        reason_report.unparsed,
        [ByteRange {
            offset: 0,
            length: invalid_reason.len()
        }]
    );

    let invalid_extension =
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1;=x\r\na\r\n0\r\n\r\n";
    let extension_report = decode_http(invalid_extension, COMPLETE);
    let message = extension_report
        .findings
        .first()
        .ok_or("missing chunked candidate")?;
    assert_eq!(extension_report.status, ParseStatus::Unsupported);
    assert_eq!(message.status, ParseStatus::Unsupported);
    assert!(matches!(
        &message.body,
        HttpBody::Chunked {
            complete: false,
            ..
        }
    ));

    let invalid_trailer =
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Value: bad\x01value\r\n\r\n";
    let trailer_report = decode_http(invalid_trailer, COMPLETE);
    let message = trailer_report
        .findings
        .first()
        .ok_or("missing trailer candidate")?;
    assert_eq!(trailer_report.status, ParseStatus::Unsupported);
    assert_eq!(message.status, ParseStatus::Unsupported);
    assert!(matches!(
        &message.body,
        HttpBody::Chunked {
            complete: false,
            ..
        }
    ));
    Ok(())
}

#[test]
fn response_status_http_range_rejected() {
    for status_code in ["000", "099", "600", "999"] {
        let bytes = format!("HTTP/1.1 {status_code} Invalid\r\nContent-Length: 0\r\n\r\n");
        let report = decode_http_with_methods(
            bytes.as_bytes(),
            COMPLETE,
            &[Some(HttpRequestMethod::Other)],
        );

        assert_eq!(report.status, ParseStatus::Unsupported);
        assert_eq!(report.findings.len(), 0);
        assert_eq!(report.unparsed, [ByteRange::new(0, bytes.len())]);
    }
}

#[test]
fn http_status_code_boundaries() {
    let methods = [Some(HttpRequestMethod::Other)];
    for status_line in [
        "HTTP/1.1 100 Continue\r\n\r\n",
        "HTTP/1.1 599 Unknown\r\nContent-Length: 0\r\n\r\n",
    ] {
        let report = decode_http_with_methods(status_line.as_bytes(), COMPLETE, &methods);
        assert_eq!(report.status, ParseStatus::Complete);
        assert_eq!(report.findings.len(), 1);
        assert!(matches!(
            report.findings.first().map(|message| &message.start),
            Some(HttpStart::Response {
                status_code: 100 | 599
            })
        ));
    }
}

#[test]
fn response_status_optional_reason_phrase() {
    for status_line in ["HTTP/1.1 200\r\n\r\n", "HTTP/1.1 200x\r\n\r\n"] {
        let report = decode_http(status_line.as_bytes(), COMPLETE);
        assert_eq!(report.status, ParseStatus::Unsupported);
        assert_eq!(report.findings.len(), 0);
        assert_eq!(report.unparsed, [ByteRange::new(0, status_line.len())]);
    }

    let status_line = "HTTP/1.1 200 \r\n\r\n";
    let report = decode_http_with_methods(
        status_line.as_bytes(),
        COMPLETE,
        &[Some(HttpRequestMethod::Other)],
    );
    assert_eq!(report.status, ParseStatus::Complete);
    assert!(matches!(
        report.findings.first().map(|message| &message.start),
        Some(HttpStart::Response { status_code: 200 })
    ));
}

#[test]
fn input_limit_without_losing_tail() -> Result<(), &'static str> {
    let oversized = vec![b'a'; MAX_INPUT_BYTES + 1];
    let oversized_report = decode_http(&oversized, COMPLETE);
    assert_eq!(oversized_report.status, ParseStatus::Unsupported);
    assert_eq!(
        oversized_report.unparsed,
        [ByteRange {
            offset: 0,
            length: oversized.len()
        }]
    );

    let mut stream = Vec::new();
    for _ in 0..=MAX_ENTRIES {
        stream.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
    }
    let report = decode_http(&stream, COMPLETE);
    let last_message = report.findings.last().ok_or("missing retained message")?;
    let retained_end = last_message
        .range
        .offset
        .checked_add(last_message.range.length)
        .ok_or("message range overflow")?;
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
    Ok(())
}

#[test]
fn nested_budget_reports_omissions() {
    let mut header_overflow = b"GET / HTTP/1.1\r\n".to_vec();
    for _ in 0..MAX_ENTRIES {
        header_overflow.extend_from_slice(b"X: y\r\n");
    }
    header_overflow.extend_from_slice(b"\r\n");
    let header_report = decode_http(&header_overflow, COMPLETE);
    assert_entry_budget_omission(&header_report, ByteRange::new(0, header_overflow.len()));

    let chunk_prefix = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
    let mut chunk_overflow = chunk_prefix.to_vec();
    for _ in 0..MAX_ENTRIES - 1 {
        chunk_overflow.extend_from_slice(b"1\r\na\r\n");
    }
    let first_unprocessed_chunk = chunk_prefix.len() + (MAX_ENTRIES - 2) * 6;
    let chunk_report = decode_http(&chunk_overflow, COMPLETE);
    assert_entry_budget_omission(
        &chunk_report,
        ByteRange::new(
            first_unprocessed_chunk,
            chunk_overflow.len() - first_unprocessed_chunk,
        ),
    );

    let trailer_prefix = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n";
    let mut trailer_overflow = trailer_prefix.to_vec();
    for _ in 0..MAX_ENTRIES - 2 {
        trailer_overflow.extend_from_slice(b"X: y\r\n");
    }
    let first_unprocessed_trailer = trailer_prefix.len() + (MAX_ENTRIES - 3) * 6;
    let trailer_report = decode_http(&trailer_overflow, COMPLETE);
    assert_entry_budget_omission(
        &trailer_report,
        ByteRange::new(
            first_unprocessed_trailer,
            trailer_overflow.len() - first_unprocessed_trailer,
        ),
    );
}

#[test]
fn lf_request_lines_headers_bodies() -> Result<(), &'static str> {
    let request = b"POST /upload HTTP/1.1\nHost: example.test\nContent-Length: 5\n\nhelloGET /next HTTP/1.1\nHost: example.test\n\n";
    let report = decode_http(request, COMPLETE);
    let message = report
        .findings
        .first()
        .ok_or("missing LF-only request candidate")?;
    let next_message = report
        .findings
        .get(1)
        .ok_or("missing pipelined LF-only request")?;
    let HttpStart::Request { method, target } = message.start else {
        return Err("expected an HTTP request candidate");
    };
    let HttpBody::Contiguous { range, complete } = &message.body else {
        return Err("expected a complete request body");
    };
    let host = message
        .headers
        .first()
        .ok_or("missing request host header")?;

    assert_eq!(report.status, ParseStatus::Complete);
    assert_eq!(message.line_ending, HttpLineEnding::Lf);
    assert_eq!(slice(request, method)?, b"POST");
    assert_eq!(slice(request, target)?, b"/upload");
    assert_eq!(slice(request, host.value)?, b"example.test");
    assert!(complete);
    assert_eq!(slice(request, *range)?, b"hello");
    assert_eq!(next_message.line_ending, HttpLineEnding::Lf);

    let response = b"HTTP/1.1 200 OK\nContent-Length: 4\n\nbody";
    let report = decode_http_with_methods(response, COMPLETE, &[Some(HttpRequestMethod::Other)]);
    let message = report
        .findings
        .first()
        .ok_or("missing LF-only response candidate")?;
    let HttpBody::Contiguous { range, complete } = &message.body else {
        return Err("expected a complete response body");
    };

    assert_eq!(report.status, ParseStatus::Complete);
    assert_eq!(message.line_ending, HttpLineEnding::Lf);
    assert!(matches!(
        message.start,
        HttpStart::Response { status_code: 200 }
    ));
    assert!(complete);
    assert_eq!(slice(response, *range)?, b"body");
    Ok(())
}

#[test]
fn mixed_header_without_consuming_tail() {
    for bytes in [
        &b"GET / HTTP/1.1\nHost: example.test\r\n\r\n"[..],
        &b"GET / HTTP/1.1\r\nHost: example.test\n\n"[..],
    ] {
        let report = decode_http(bytes, COMPLETE);

        assert_eq!(report.status, ParseStatus::Unsupported);
        assert_eq!(report.findings.len(), 0);
        assert_eq!(report.unparsed, [ByteRange::new(0, bytes.len())]);
    }
}

#[test]
fn lf_chunk_body_tail_retained() -> Result<(), &'static str> {
    let bytes = b"POST /chunk HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\nWiki\n0\n\n";
    let report = decode_http(bytes, COMPLETE);
    let message = report
        .findings
        .first()
        .ok_or("missing chunked framing candidate")?;
    let HttpBody::Chunked {
        raw_remainder,
        complete,
        ..
    } = &message.body
    else {
        return Err("expected an unresolved chunked candidate");
    };

    assert_eq!(report.status, ParseStatus::Unsupported);
    assert_eq!(message.status, ParseStatus::Unsupported);
    assert!(!complete);
    assert_eq!(
        slice(bytes, raw_remainder.ok_or("missing unparsed chunk tail")?)?,
        b"4\nWiki\n0\n\n"
    );
    Ok(())
}

fn request_start_line(length: usize) -> Vec<u8> {
    let mut line = b"GET /".to_vec();
    line.resize(length.saturating_sub(b" HTTP/1.1".len()), b'x');
    line.extend_from_slice(b" HTTP/1.1");
    line
}

fn append_sized_headers(bytes: &mut Vec<u8>, line_lengths: [usize; 4]) {
    let names: [&[u8]; 4] = [b"A: ", b"B: ", b"C: ", b"D: "];
    for (name, line_length) in names.iter().zip(line_lengths) {
        bytes.extend_from_slice(name);
        let padding_length = line_length.saturating_sub(name.len());
        bytes.resize(bytes.len().saturating_add(padding_length), b'a');
        bytes.extend_from_slice(b"\r\n");
    }
}

fn assert_entry_budget_omission<T>(report: &ParseReport<T>, expected: ByteRange) {
    assert_eq!(report.status, ParseStatus::Unsupported);
    assert_eq!(report.budget_omissions.len(), 1);
    assert!(report.budget_omissions.first().is_some_and(|omission| {
        omission.budget == ParserBudget::Entries && omission.range == expected
    }));
    assert_eq!(report.unparsed, [expected]);
}
