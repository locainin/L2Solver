//! Capture relationship output shares the canonical forensic renderer

use crate::forensic_report;
use l2_audit::Report;
use l2_cli::arguments::ReportOptions;
use std::io::{self, Write};

/// Render capture-derived communications and protocol relationships as text
pub fn write(report: &Report, output: &mut impl Write) -> io::Result<()> {
    writeln!(output, "Capture relationships")?;
    forensic_report::write(
        report,
        &ReportOptions {
            verbosity: 2,
            ..ReportOptions::default()
        },
        output,
    )
}
