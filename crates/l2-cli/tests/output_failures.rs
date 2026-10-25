#[path = "../src/forensic_report.rs"]
mod forensic_report;

#[path = "../src/html_report.rs"]
mod html_report;
#[path = "../src/presentation.rs"]
mod presentation;
#[path = "../src/render.rs"]
pub mod render;
#[path = "../src/survey_report.rs"]
mod survey_report;

use l2_cli::arguments::ReportOptions;
use std::io::{self, Write};

struct FailAfter {
    remaining: usize,
    accepted: usize,
}

impl FailAfter {
    const fn new(limit: usize) -> Self {
        Self {
            remaining: limit,
            accepted: 0,
        }
    }
}

impl Write for FailAfter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::other("injected sink failure"));
        }
        let accepted = self.remaining.min(bytes.len());
        self.remaining -= accepted;
        self.accepted += accepted;
        Ok(accepted)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn report() -> Result<l2_audit::Report, l2_audit::AuditError> {
    l2_audit::Survey::new().finish(&l2_audit::Policy::default())
}

#[test]
fn text_renderer_propagates_every_short() -> Result<(), Box<dyn std::error::Error>> {
    let report = report()?;
    let options = ReportOptions::default();
    let mut complete = Vec::new();
    survey_report::text_with_interface(&report, &options, "fixture", None, &mut complete)?;

    for boundary in 0..complete.len() {
        let mut sink = FailAfter::new(boundary);
        assert!(
            survey_report::text_with_interface(&report, &options, "fixture", None, &mut sink)
                .is_err(),
            "accepted a sink that fails after byte {boundary}"
        );
        assert!(sink.accepted <= boundary);
    }
    Ok(())
}

#[test]
fn html_renderer_propagates_every_short() -> Result<(), Box<dyn std::error::Error>> {
    let text = r#"hostile <switch> & "quoted""#;
    let mut complete = Vec::new();
    html_report::write(&mut complete, text)?;

    for boundary in 0..complete.len() {
        let mut sink = FailAfter::new(boundary);
        assert!(
            html_report::write(&mut sink, text).is_err(),
            "accepted a sink that fails after byte {boundary}"
        );
        assert!(sink.accepted <= boundary);
    }
    Ok(())
}
