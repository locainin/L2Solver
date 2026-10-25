//! Render bounded journal previews and links to retained evidence

use crate::{arguments::OutputFormat, html_report};
use l2_workbench::journal::{Entry, Journal, Overview};
use std::{error::Error, io::Write};

pub(super) fn render(
    journal: &Journal,
    format: OutputFormat,
    limit: Option<u64>,
    output: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    journal.read_snapshot(|journal| render_snapshot(journal, format, limit, output))
}

fn render_snapshot(
    journal: &Journal,
    format: OutputFormat,
    limit: Option<u64>,
    output: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    let summary = journal.overview()?;
    if format == OutputFormat::Html {
        html_report::begin(output, "L2Solver investigation")?;
        output.write_all(b"<p>Checks, contradictions and unresolved models retain their original evidence. Ordering does not establish causation or malicious intent.</p><pre>")?;
        html_report::escaped(output, &serde_json::to_string_pretty(&summary)?)?;
        output.write_all(b"</pre>")?;
        journal.visit_review(limit, |entry| write_html_entry(&entry, output))?;
        write_html_receipt_section(journal, output)?;
        html_report::end(output)?;
    } else {
        if format == OutputFormat::Json {
            line(output, &summary)?;
        } else {
            text_overview(output, &summary)?;
        }
        journal.visit_review(limit, |entry| {
            if format == OutputFormat::Json {
                line(output, &entry)
            } else {
                text_entry(output, &entry)
            }
        })?;
        journal.visit_tool_receipts(None, None, |receipt| {
            if format == OutputFormat::Json {
                line(output, &receipt)
            } else {
                writeln!(
                    output,
                    "tool receipt: {} {} evidence={} source={} linked_events={}",
                    receipt.tool.escape_debug(),
                    receipt.version.escape_debug(),
                    receipt.evidence_sha256,
                    receipt.source_sha256,
                    receipt.linked_events
                )?;
                Ok(())
            }
        })?;
    }
    Ok(())
}

fn text_overview(output: &mut impl Write, summary: &Overview) -> Result<(), Box<dyn Error>> {
    writeln!(
        output,
        "Investigation: hypotheses={} checks={} events={} tool receipts={}",
        summary.hypotheses, summary.checks, summary.events, summary.tool_receipts
    )?;
    writeln!(output, "Base case SHA-256: {}", summary.base_case_sha256)?;
    for limitation in &summary.limitations {
        writeln!(output, "Scope: {}", limitation.escape_debug())?;
    }
    Ok(())
}

fn text_entry(output: &mut impl Write, entry: &Entry) -> Result<(), Box<dyn Error>> {
    writeln!(
        output,
        "{} {} {}",
        entry.conclusion,
        entry.id,
        entry.hypothesis.title.escape_debug()
    )?;
    writeln!(
        output,
        "  check preview: {} shown, {} omitted; use checks {} for the full history",
        entry.checks.len(),
        entry.checks_omitted,
        entry.id
    )?;
    for premise in &entry.hypothesis.assumptions {
        writeln!(output, "  unresolved premise: {}", premise.escape_debug())?;
    }
    for check in &entry.checks {
        writeln!(
            output,
            "  check #{} {:?}/{:?} binding={:?} identity={} evidence={}: {}",
            check.id,
            check.check.kind,
            check.check.outcome,
            check.binding_origin,
            check.identity,
            check.evidence_sha256,
            check.check.explanation.escape_debug()
        )?;
    }
    Ok(())
}

pub fn write_html_entry(entry: &Entry, output: &mut impl Write) -> Result<(), Box<dyn Error>> {
    output.write_all(b"<details><summary>")?;
    html_report::escaped(
        output,
        &format!("{}: {}", entry.conclusion, entry.hypothesis.title),
    )?;
    output.write_all(b"</summary><pre>")?;
    html_report::escaped(output, &serde_json::to_string_pretty(entry)?)?;
    output.write_all(b"</pre><p>Full check history: journal checks ")?;
    html_report::escaped(output, &entry.id)?;
    output.write_all(b"</p></details>")?;
    Ok(())
}

pub fn write_html_receipt_section(
    journal: &Journal,
    output: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    output.write_all(b"<h2>External tool receipts</h2><ul>")?;
    journal.visit_tool_receipts(None, None, |receipt| {
        output.write_all(b"<li>")?;
        html_report::escaped(output, &receipt.tool)?;
        output.write_all(b" ")?;
        html_report::escaped(output, &receipt.version)?;
        output.write_all(b" evidence SHA-256 ")?;
        html_report::escaped(output, &receipt.evidence_sha256)?;
        output.write_all(b" source SHA-256 ")?;
        html_report::escaped(output, &receipt.source_sha256)?;
        write!(output, " linked events={}</li>", receipt.linked_events)?;
        Ok(())
    })?;
    output.write_all(b"</ul>")?;
    Ok(())
}

fn line(output: &mut impl Write, value: &impl serde::Serialize) -> Result<(), Box<dyn Error>> {
    serde_json::to_writer(&mut *output, value)?;
    output.write_all(b"\n")?;
    Ok(())
}
