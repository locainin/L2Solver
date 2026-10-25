use super::support::COMPLETE;
use l2_workbench::application::{MAX_INPUT_BYTES, ParseStatus, inspect};

#[test]
fn candidate_separate_without_format_selection() {
    let bytes = b"GET /resource HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
    let report = inspect(bytes, COMPLETE.start_known, COMPLETE.end_observed);

    assert_eq!(report.http.status, ParseStatus::Complete);
    assert_eq!(report.http.findings.len(), 1);
    assert_ne!(report.dns_tcp.status, ParseStatus::Complete);
}

#[test]
fn input_limit_applied_candidate_parser() {
    let bytes = vec![0; MAX_INPUT_BYTES + 1];
    let report = inspect(&bytes, true, true);

    assert_eq!(report.dns_tcp.status, ParseStatus::Unsupported);
    assert_eq!(report.http.status, ParseStatus::Unsupported);
    assert_eq!(report.ftp.status, ParseStatus::Unsupported);
    assert_eq!(
        report.dns_tcp.unparsed.first().map(|range| range.length),
        Some(bytes.len())
    );
    assert_eq!(
        report.http.unparsed.first().map(|range| range.length),
        Some(bytes.len())
    );
    assert_eq!(
        report.ftp.unparsed.first().map(|range| range.length),
        Some(bytes.len())
    );
    assert_input_byte_omission(&report.dns_tcp, bytes.len());
    assert_input_byte_omission(&report.http, bytes.len());
    assert_input_byte_omission(&report.ftp, bytes.len());
}

fn assert_input_byte_omission<T>(
    report: &l2_workbench::application::ParseReport<T>,
    input_length: usize,
) {
    assert_eq!(report.budget_omissions.len(), 1);
    assert_eq!(
        report
            .budget_omissions
            .first()
            .map(|omission| omission.budget),
        Some(l2_workbench::application::ParserBudget::InputBytes)
    );
    assert_eq!(
        report
            .budget_omissions
            .first()
            .map(|omission| omission.range.length),
        Some(input_length)
    );
}
