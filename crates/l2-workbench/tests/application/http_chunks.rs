use super::support::{COMPLETE, locate};
use l2_workbench::application::{
    ParseStatus,
    http::{HttpBody, decode_http},
};

const HEAD: &str = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";

#[test]
fn whitespace_before_extensions_keeps_exact_data_ranges() -> Result<(), &'static str> {
    let input = format!(
        "{HEAD}4 \t; name = \"a\\\"b\" \t; flag\r\nDATA\r\n0\t; end = token\r\nX-End: yes\r\n\r\n"
    );
    let report = decode_http(input.as_bytes(), COMPLETE);
    let message = report.findings.first().ok_or("missing HTTP message")?;
    let HttpBody::Chunked {
        chunks,
        trailer_range,
        raw_remainder,
        complete,
        ..
    } = &message.body
    else {
        return Err("expected chunked body");
    };
    assert_eq!(report.status, ParseStatus::Complete);
    assert!(complete);
    assert!(raw_remainder.is_none());
    assert_eq!(chunks, &[locate(input.as_bytes(), b"DATA")?]);
    assert_eq!(
        *trailer_range,
        Some(locate(input.as_bytes(), b"X-End: yes\r\n\r\n")?)
    );
    Ok(())
}

#[test]
fn invalid_sizes_or_extension_tails_are_not_accepted() {
    for line in [
        "",
        " 4;name",
        "4 a;name",
        "4g;name",
        "4 ",
        "4 ;name ",
        "4 ;name=value\t",
        "4 ;name=\"unterminated",
        "4 ;name=\"quoted\"junk",
        "4 ;=value",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    ] {
        let input = format!("{HEAD}{line}\r\nDATA\r\n0\r\n\r\n");
        let report = decode_http(input.as_bytes(), COMPLETE);
        assert_eq!(report.status, ParseStatus::Unsupported, "line: {line:?}");
        assert!(
            matches!(
                report.findings.first().map(|message| &message.body),
                Some(HttpBody::Chunked {
                    complete: false,
                    ..
                })
            ),
            "line: {line:?}"
        );
    }
}

#[test]
fn truncated_data_after_a_valid_spaced_extension_remains_incomplete() {
    let input = format!("{HEAD}4 ;name=value\r\nDAT");
    let report = decode_http(input.as_bytes(), COMPLETE);
    assert_eq!(report.status, ParseStatus::Incomplete);
    assert!(matches!(
        report.findings.first().map(|message| &message.body),
        Some(HttpBody::Chunked {
            complete: false,
            ..
        })
    ));
}
