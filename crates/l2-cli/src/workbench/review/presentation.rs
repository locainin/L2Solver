use super::collection::ReviewReport;
use crate::{html_report, workbench::journal};
use std::{error::Error, io::Write};

pub(super) fn text(report: &ReviewReport, output: &mut impl Write) -> Result<(), Box<dyn Error>> {
    text_with_status(report, report.complete, output)
}

fn text_with_status(
    report: &ReviewReport,
    complete: bool,
    output: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    writeln!(
        output,
        "Investigation review complete={} events={} omitted_events={}",
        complete,
        report.correlation.events.len(),
        report.correlation.omitted_events
    )?;
    writeln!(
        output,
        "Hypotheses shown={} omitted={} tool_receipts_shown={} omitted={}",
        report.hypotheses.len(),
        report.omitted_hypotheses,
        report.tools.len(),
        report.omitted_tools
    )?;
    // Both text and HTML use this summary, including the journal's scope limits
    for limitation in &report.journal.limitations {
        writeln!(output, "Journal limitation: {}", limitation.escape_debug())?;
    }
    for entry in &report.hypotheses {
        writeln!(
            output,
            "{} {} {}",
            entry.conclusion,
            entry.id,
            entry.hypothesis.title.escape_debug()
        )?;
    }
    for store in &report.carrier_results {
        writeln!(
            output,
            "Carrier store {} candidates={} preview_omitted={} enumerated={} source_scope={}",
            store.directory.display(),
            store.summary.candidate_count,
            store.omitted_candidates,
            store.summary.enumeration_complete,
            store.summary.identity.source_scope.escape_debug()
        )?;
    }
    Ok(())
}

pub(super) const fn html_view_complete(report: &ReviewReport, preview: usize) -> bool {
    report.complete
        && report.correlation.events.len() <= preview
        && report.correlation.header_associations.len() <= preview
}

pub(super) fn html(
    report: &ReviewReport,
    preview: usize,
    output: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let complete = html_view_complete(report, preview);
    html_report::begin(output, "L2Solver investigation review")?;
    writeln!(
        output,
        "<p>View complete: {complete}. HTML detail preview limit: {preview}.</p>"
    )?;
    output.write_all(b"<p>Observations, transformations and acceptance checks retain separate meanings. Preview omissions do not remove stored evidence.</p><nav><a href=\"#hypotheses\">Hypotheses</a> | <a href=\"#tools\">Tool evidence</a> | <a href=\"#carriers\">Carrier results</a> | <a href=\"#identities\">Identities and clocks</a></nav><pre>")?;
    let mut summary = Vec::new();
    text_with_status(report, complete, &mut summary)?;
    html_report::escaped(output, &String::from_utf8(summary)?)?;
    output.write_all(b"</pre><section id=\"hypotheses\"><h2>Hypotheses and checks</h2>")?;
    for entry in &report.hypotheses {
        journal::write_html_entry(entry, output)?;
    }
    output.write_all(b"</section><section id=\"tools\"><h2>Tool evidence</h2><pre>")?;
    html_report::escaped(output, &serde_json::to_string_pretty(&report.tools)?)?;
    output.write_all(b"</pre><p>Export a retained check with journal export-evidence. Tool evidence hashes identify the original imported reports; tool-derived fields do not invent physical byte ranges.</p></section><section id=\"carriers\"><h2>Carrier results</h2>")?;
    carrier_details(report, output)?;
    identity_details(report, preview, output)?;
    html_report::end(output)?;
    Ok(())
}

fn carrier_details(report: &ReviewReport, output: &mut impl Write) -> Result<(), Box<dyn Error>> {
    for store in &report.carrier_results {
        output.write_all(b"<details><summary>")?;
        html_report::escaped(
            output,
            &format!(
                "{}: {} candidates, {} omitted from this preview",
                store.directory.display(),
                store.summary.candidate_count,
                store.omitted_candidates
            ),
        )?;
        output.write_all(b"</summary><pre>")?;
        html_report::escaped(output, &serde_json::to_string_pretty(store)?)?;
        output.write_all(b"</pre><p>Use carrier-results show for mapped printable runs, export for exact transformed bytes, and replay to check the original source and plan.</p></details>")?;
    }
    Ok(())
}

fn identity_details(
    report: &ReviewReport,
    preview: usize,
    output: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    output
        .write_all(b"</section><section id=\"identities\"><h2>Identities and clocks</h2><pre>")?;
    let associations: Vec<_> = report
        .correlation
        .header_associations
        .iter()
        .take(preview)
        .collect();
    html_report::escaped(
        output,
        &serde_json::to_string_pretty(
            &serde_json::json!({"groups":report.correlation.groups,"header_associations":associations,"header_associations_omitted":report.correlation.header_associations.len().saturating_sub(preview),"comparisons":report.correlation.comparisons,"bindings":report.correlation.bindings,"calibrations":report.correlation.calibrations,"limitations":report.correlation.limitations}),
        )?,
    )?;
    output.write_all(b"</pre>")?;
    for event in report.correlation.events.iter().take(preview) {
        output.write_all(b"<details><summary>")?;
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
    writeln!(
        output,
        "<p>Event detail preview omitted {} retained observations. Full records remain accessible through correlate JSON and the journal.</p></section>",
        report.correlation.events.len().saturating_sub(preview)
    )?;
    Ok(())
}
