use super::model::{QueryReport, ScopedMatch};
use crate::html_report;
use std::{collections::BTreeMap, error::Error, io::Write};

pub(super) fn text(
    report: &QueryReport<'_>,
    output: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    summary(report, output)?;
    for result in &report.matches {
        writeln!(output)?;
        observation(result, output)?;
    }
    Ok(())
}

fn counts(report: &QueryReport<'_>, output: &mut impl Write) -> Result<(), Box<dyn Error>> {
    writeln!(
        output,
        "Evidence query: collection_complete={} complete={} pages={} matched={} shown={} omitted={}",
        report.inventory.collection_complete,
        report.complete,
        report.inventory.pages,
        report.matched_nodes,
        report.matches.len(),
        report.omitted_matches
    )?;
    Ok(())
}

fn summary(report: &QueryReport<'_>, output: &mut impl Write) -> Result<(), Box<dyn Error>> {
    counts(report, output)?;
    writeln!(
        output,
        "Filters: {}",
        serde_json::to_string(report.filters)?
    )?;
    for source in &report.sources {
        writeln!(
            output,
            "Source {} label={} kind={} bytes={}",
            source.id,
            source.label.escape_debug(),
            source.kind.escape_debug(),
            source.length
        )?;
    }
    for limitation in &report.case_limitations {
        writeln!(output, "Saved limitation: {}", limitation.escape_debug())?;
    }
    for limitation in &report.inventory.bundle_limitations {
        writeln!(output, "Bundle limitation: {}", limitation.escape_debug())?;
    }
    writeln!(
        output,
        "Omitted saved limitation occurrences: {}",
        report.omitted_limitation_occurrences
    )?;
    for limitation in &report.limitations {
        writeln!(output, "Scope: {limitation}")?;
    }
    if report.matched_nodes == 0 {
        writeln!(
            output,
            "No retained evidence matched; this does not establish absence in unobserved or unsupported traffic"
        )?;
    } else if report.matches.is_empty() {
        writeln!(
            output,
            "Matched evidence did not fit the report byte limit; narrow the filters to inspect those results"
        )?;
    }
    Ok(())
}

fn observation(result: &ScopedMatch, output: &mut impl Write) -> Result<(), Box<dyn Error>> {
    writeln!(
        output,
        "Node {} kind={} page={}",
        result.evidence.node_id,
        result.evidence.kind.escape_debug(),
        result
            .page
            .as_deref()
            .unwrap_or("saved case")
            .escape_debug()
    )?;
    writeln!(
        output,
        "Details: {}",
        serde_json::to_string_pretty(&result.details)?
    )?;
    for edge in &result.relations {
        writeln!(
            output,
            "Relation {} -> {} {} status={} reason={}",
            edge.from,
            edge.to,
            edge.relation.escape_debug(),
            serde_json::to_string(&edge.status)?,
            edge.reason.escape_debug()
        )?;
    }
    for range in &result.evidence.source_ranges {
        writeln!(
            output,
            "Range source={} packet={} offset={} length={}",
            range.source,
            range
                .packet
                .map_or_else(|| "none".to_owned(), |packet| packet.to_string()),
            range.offset,
            range.length
        )?;
    }
    for filter in &result.packet_filters {
        writeln!(
            output,
            "Wireshark-compatible display filter source={} expression={}",
            filter.source_id, filter.expression
        )?;
    }
    if let Some(blob) = &result.blob {
        writeln!(
            output,
            "Retained bytes: {blob}; export from the saved case/page with workbench export --node {}",
            result.evidence.node_id
        )?;
    }
    Ok(())
}

pub(super) fn html(
    report: &QueryReport<'_>,
    output: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    html_report::begin(output, "L2Solver evidence query")?;
    let mut header = Vec::new();
    counts(report, &mut header)?;
    output.write_all(b"<pre>")?;
    html_report::escaped(output, &String::from_utf8(header)?)?;
    output.write_all(b"</pre><details><summary>Sources and coverage notes</summary><pre>")?;
    let mut buffer = Vec::new();
    summary(report, &mut buffer)?;
    html_report::escaped(output, &String::from_utf8(buffer)?)?;
    output.write_all(
        b"</pre></details><nav aria-label=\"Evidence kinds\"><h2>Shown results by kind</h2><ul>",
    )?;
    let mut kinds: BTreeMap<&str, Vec<&ScopedMatch>> = BTreeMap::new();
    for result in &report.matches {
        kinds.entry(&result.evidence.kind).or_default().push(result);
    }
    for (index, (kind, results)) in kinds.iter().enumerate() {
        write!(output, "<li><a href=\"#kind-{index}\">")?;
        html_report::escaped(output, kind)?;
        write!(output, "</a> ({})</li>", results.len())?;
    }
    output.write_all(b"</ul></nav><p>Use the browser find command to search this saved report. Expand a result for its explanation and supporting bytes.</p>")?;
    for (index, (kind, results)) in kinds.iter().enumerate() {
        write!(output, "<section id=\"kind-{index}\"><h2>")?;
        html_report::escaped(output, kind)?;
        output.write_all(b"</h2>")?;
        for result in results {
            write!(
                output,
                "<details open><summary>Node {} / ",
                result.evidence.node_id
            )?;
            html_report::escaped(output, result.page.as_deref().unwrap_or("saved case"))?;
            output.write_all(b"</summary><pre>")?;
            let mut buffer = Vec::new();
            observation(result, &mut buffer)?;
            html_report::escaped(output, &String::from_utf8(buffer)?)?;
            output.write_all(b"</pre></details>")?;
        }
        output.write_all(b"</section>")?;
    }
    html_report::end(output)?;
    Ok(())
}
