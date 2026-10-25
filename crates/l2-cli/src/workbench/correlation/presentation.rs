use crate::html_report;
use l2_workbench::identity::CorrelationReport;
use std::{error::Error, io::Write};

pub(super) fn text(
    report: &CorrelationReport,
    output: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    writeln!(
        output,
        "events={} omitted={} identity_groups={} clock_comparisons={} complete={}",
        report.events.len(),
        report.omitted_events,
        report.groups.len(),
        report.comparisons.len(),
        report.complete
    )?;
    for group in &report.groups {
        writeln!(
            output,
            "identity={} event_indices={:?}",
            group.identity.escape_debug(),
            group.event_indices
        )?;
    }
    for comparison in &report.comparisons {
        writeln!(
            output,
            "clock={} left={} right={} relation={:?}",
            comparison.request.clock.escape_debug(),
            comparison.request.left_event.escape_debug(),
            comparison.request.right_event.escape_debug(),
            comparison.relation
        )?;
    }
    for limitation in &report.limitations {
        writeln!(output, "Scope: {limitation}")?;
    }
    Ok(())
}

pub(super) fn html(
    report: &CorrelationReport,
    output: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    html_report::begin(output, "Identity and clock evidence")?;
    output.write_all(b"<p>Supplied identity and clock mappings retain their evidence and uncertainty. Equal labels do not establish physical ownership or causation.</p><pre>")?;
    let mut summary = Vec::new();
    text(report, &mut summary)?;
    html_report::escaped(output, &String::from_utf8(summary)?)?;
    output.write_all(b"</pre><h2>Identity groups</h2>")?;
    for group in &report.groups {
        output.write_all(b"<details><summary>")?;
        html_report::escaped(
            output,
            &format!(
                "{} — {} observations",
                group.identity,
                group.event_indices.len()
            ),
        )?;
        output.write_all(b"</summary><ul>")?;
        for index in &group.event_indices {
            if let Some(event) = report.events.get(*index) {
                write!(output, "<li><a href=\"#event-{}\">", event.identity)?;
                html_report::escaped(
                    output,
                    &format!(
                        "{} record {} {}",
                        event.event.source, event.event.packet, event.event.kind
                    ),
                )?;
                output.write_all(b"</a></li>")?;
            }
        }
        output.write_all(b"</ul></details>")?;
    }
    output.write_all(b"<h2>Mappings and time comparisons</h2><pre>")?;
    html_report::escaped(
        output,
        &serde_json::to_string_pretty(
            &serde_json::json!({"bindings":report.bindings,"calibrations":report.calibrations,"comparisons":report.comparisons}),
        )?,
    )?;
    output.write_all(b"</pre><h2>Source observations</h2>")?;
    for event in &report.events {
        write!(output, "<details id=\"event-{}\"><summary>", event.identity)?;
        html_report::escaped(
            output,
            &format!(
                "{} record {} {}",
                event.event.source, event.event.packet, event.event.kind
            ),
        )?;
        output.write_all(b"</summary><pre>")?;
        html_report::escaped(output, &serde_json::to_string_pretty(event)?)?;
        output.write_all(b"</pre></details>")?;
    }
    html_report::end(output)?;
    Ok(())
}
