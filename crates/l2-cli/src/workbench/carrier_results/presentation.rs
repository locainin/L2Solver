//! Text, JSON, and escaped HTML views over verified carrier result pages

use crate::{arguments::OutputFormat, html_report};
use l2_workbench::carrier::discovery::{
    DiscoveryCandidate, DiscoverySampleReceipt, PartitionSummary, PrintableRun, ResultPage,
    StoredDiscoverySummary,
};
use serde::Serialize;
use std::{
    error::Error,
    fmt::{Arguments, Display},
    io::Write,
    path::Path,
};

#[derive(Serialize)]
struct CandidateListing<'a> {
    summary: &'a StoredDiscoverySummary,
    page: PageView<'a, DiscoveryCandidate, usize>,
}

#[derive(Serialize)]
struct CandidateView<'a> {
    candidate: &'a DiscoveryCandidate,
    runs: PageView<'a, PrintableRun, usize>,
}

#[derive(Serialize)]
struct SourceListing<'a> {
    summary: &'a StoredDiscoverySummary,
    page: PageView<'a, DiscoverySampleReceipt, u64>,
}

#[derive(Serialize)]
struct PageView<'a, T, C> {
    rows: &'a [T],
    next_after: Option<C>,
}

pub(super) fn created(
    output: &mut impl Write,
    format: OutputFormat,
    directory: &Path,
    summary: &StoredDiscoverySummary,
) -> Result<(), Box<dyn Error>> {
    match format {
        OutputFormat::Json => serde_json::to_writer(output, summary)?,
        OutputFormat::Text => {
            let path = directory.display().to_string();
            writeln!(
                output,
                "Created carrier results directory: {}",
                path.escape_debug()
            )?;
            writeln!(
                output,
                "Candidates: {}; printable runs: {}; enumeration: {}",
                summary.candidate_count,
                summary.printable_run_count,
                if summary.enumeration_complete {
                    "complete"
                } else {
                    "incomplete"
                }
            )?;
        }
        OutputFormat::Html => return Err("directory summaries support only text or JSON".into()),
    }
    Ok(())
}

pub(super) fn list(
    output: &mut impl Write,
    format: OutputFormat,
    summary: &StoredDiscoverySummary,
    page: &ResultPage<DiscoveryCandidate>,
) -> Result<(), Box<dyn Error>> {
    if format == OutputFormat::Json {
        return Ok(serde_json::to_writer(
            output,
            &CandidateListing {
                summary,
                page: PageView {
                    rows: &page.rows,
                    next_after: page.next_after,
                },
            },
        )?);
    }

    begin(output, format, "Carrier discovery candidates")?;
    candidate_summary_lines(output, format, summary)?;
    candidate_lines(output, format, &page.rows)?;
    page_cursor(output, format, page.next_after, "candidate")?;
    end(output, format)?;
    Ok(())
}

fn candidate_summary_lines(
    output: &mut impl Write,
    format: OutputFormat,
    summary: &StoredDiscoverySummary,
) -> Result<(), Box<dyn Error>> {
    line(
        output,
        format,
        format_args!(
            "{} of {} parameter combinations attempted; enumeration complete: {}",
            summary.attempted_parameters,
            summary.parameter_space_size,
            summary.enumeration_complete
        ),
    )?;
    line(
        output,
        format,
        format_args!(
            "source receipts: {}; printable-run receipts: {}; transformed output bytes: {}",
            summary.sample_receipt_count, summary.printable_run_count, summary.output_bytes
        ),
    )?;
    line(
        output,
        format,
        format_args!(
            "budgets: input={} work={} candidates={} output={} disk={}",
            summary.input_budget_bytes,
            summary.work_budget_bytes,
            summary.candidate_budget,
            summary.output_budget_bytes,
            summary.disk_budget_bytes
        ),
    )?;
    if !summary.omitted_empty_sample_ids.is_empty() {
        line(
            output,
            format,
            format_args!(
                "empty source samples omitted from transforms: {:?}",
                summary.omitted_empty_sample_ids
            ),
        )?;
    }
    for reason in &summary.limits {
        line(
            output,
            format,
            format_args!("search stopped at its declared limit: {reason:?}"),
        )?;
    }
    Ok(())
}

fn candidate_lines(
    output: &mut impl Write,
    format: OutputFormat,
    candidates: &[DiscoveryCandidate],
) -> Result<(), Box<dyn Error>> {
    for candidate in candidates {
        line(
            output,
            format,
            format_args!(
                "candidate {}: width={} phase={} byte_offset={} reset={:?} order={:?} competitors={} work={}",
                candidate.id,
                candidate.width,
                candidate.phase,
                candidate.source_byte_offset,
                candidate.reset_mode,
                candidate.sample_order,
                candidate.competitor_count,
                candidate.work_bytes
            ),
        )?;
        partition_line(output, format, "discovery", candidate.discovery.as_ref())?;
        partition_line(output, format, "control", candidate.control.as_ref())?;
    }
    Ok(())
}

pub(super) fn candidate(
    output: &mut impl Write,
    format: OutputFormat,
    candidate: &DiscoveryCandidate,
    runs: &ResultPage<PrintableRun>,
) -> Result<(), Box<dyn Error>> {
    if format == OutputFormat::Json {
        return Ok(serde_json::to_writer(
            output,
            &CandidateView {
                candidate,
                runs: PageView {
                    rows: &runs.rows,
                    next_after: runs.next_after,
                },
            },
        )?);
    }

    begin(output, format, "Carrier discovery candidate")?;
    line(
        output,
        format,
        format_args!(
            "candidate {}: width={} phase={} byte_offset={} reset={:?} order={:?} competitors={} work={}",
            candidate.id,
            candidate.width,
            candidate.phase,
            candidate.source_byte_offset,
            candidate.reset_mode,
            candidate.sample_order,
            candidate.competitor_count,
            candidate.work_bytes
        ),
    )?;
    line(
        output,
        format,
        format_args!(
            "bit mapping: start_bit={} stride_bits={} bits_per_byte={} remainder={:?}",
            candidate.bit_mapping.start_bit,
            candidate.bit_mapping.stride_bits,
            candidate.bit_mapping.bits_per_byte,
            candidate.bit_mapping.remainder
        ),
    )?;
    partition_line(output, format, "discovery", candidate.discovery.as_ref())?;
    partition_line(output, format, "control", candidate.control.as_ref())?;
    for run in &runs.rows {
        line(
            output,
            format,
            format_args!(
                "printable run {}: partition={:?} unit={} samples={:?} output_byte={} text={:?}",
                run.run_id,
                run.partition,
                run.unit_index,
                run.sample_ids,
                run.output_offset,
                run.text
            ),
        )?;
        for mapping in &run.source_bit_mappings {
            line(
                output,
                format,
                format_args!(
                    "  source-bit map: output_bit_start={} bit_count={} source={:?} packet={:?} offset={} length={} source_bit={} stride_bits={}",
                    mapping.output_bit_start,
                    mapping.bit_count,
                    mapping.source.source,
                    mapping.source.packet,
                    mapping.source.offset,
                    mapping.source.length,
                    mapping.source_bit_offset,
                    mapping.source_stride_bits
                ),
            )?;
        }
    }
    page_cursor(output, format, runs.next_after, "printable-run")?;
    end(output, format)?;
    Ok(())
}

pub(super) fn sources(
    output: &mut impl Write,
    format: OutputFormat,
    summary: &StoredDiscoverySummary,
    page: &ResultPage<DiscoverySampleReceipt, u64>,
) -> Result<(), Box<dyn Error>> {
    if format == OutputFormat::Json {
        return Ok(serde_json::to_writer(
            output,
            &SourceListing {
                summary,
                page: PageView {
                    rows: &page.rows,
                    next_after: page.next_after,
                },
            },
        )?);
    }

    begin(output, format, "Carrier discovery source mappings")?;
    for receipt in &page.rows {
        source_receipt_lines(output, format, receipt)?;
    }
    page_cursor(output, format, page.next_after, "source sample")?;
    end(output, format)?;
    Ok(())
}

fn source_receipt_lines(
    output: &mut impl Write,
    format: OutputFormat,
    receipt: &DiscoverySampleReceipt,
) -> Result<(), Box<dyn Error>> {
    line(
        output,
        format,
        format_args!(
            "source receipt sample {}: session={} sequence={} partition={:?} bytes={}",
            receipt.sample_id,
            receipt.session_id,
            receipt.sequence,
            receipt.partition,
            receipt.input_length
        ),
    )?;
    line(
        output,
        format,
        format_args!(
            "  source identity: scope={:?} direction={:?} local_endpoint={:?}",
            receipt.source_scope, receipt.direction, receipt.local_identity
        ),
    )?;
    line(
        output,
        format,
        format_args!(
            "  selected source bits: start={} count={}",
            receipt.source_bit_start, receipt.source_bit_count
        ),
    )?;
    for mapping in &receipt.mappings {
        line(
            output,
            format,
            format_args!(
                "  byte mapping: output_offset={} source={:?} packet={:?} offset={} length={}",
                mapping.offset,
                mapping.range.source,
                mapping.range.packet,
                mapping.range.offset,
                mapping.range.length
            ),
        )?;
    }
    Ok(())
}

fn partition_line(
    output: &mut impl Write,
    format: OutputFormat,
    name: &str,
    summary: Option<&PartitionSummary>,
) -> Result<(), Box<dyn Error>> {
    let Some(summary) = summary else {
        return line(output, format, format_args!("{name} partition: absent"));
    };
    line(
        output,
        format,
        format_args!(
            "{name} partition: units={} failed_units={} output_bytes={} printable_runs_omitted={}",
            summary.unit_count,
            summary.failed_units,
            summary.output_length,
            summary.printable_runs_omitted
        ),
    )?;
    for constraint in &summary.constraints {
        line(
            output,
            format,
            format_args!(
                "  constraint {} {:?}: satisfied={} violated={} invalid={} not_evaluated={}",
                constraint.constraint_index,
                constraint.kind,
                constraint.satisfied,
                constraint.violated,
                constraint.invalid,
                constraint.not_evaluated
            ),
        )?;
    }
    Ok(())
}

fn begin(output: &mut impl Write, format: OutputFormat, title: &str) -> Result<(), Box<dyn Error>> {
    match format {
        OutputFormat::Text => line(output, format, format_args!("{title}"))?,
        OutputFormat::Html => {
            html_report::begin(output, title)?;
            output.write_all(b"<pre>")?;
        }
        OutputFormat::Json => return Ok(()),
    }
    Ok(())
}

fn end(output: &mut impl Write, format: OutputFormat) -> Result<(), Box<dyn Error>> {
    if format == OutputFormat::Html {
        output.write_all(b"</pre>")?;
        html_report::end(output)?;
    }
    Ok(())
}

fn line(
    output: &mut impl Write,
    format: OutputFormat,
    content: Arguments<'_>,
) -> Result<(), Box<dyn Error>> {
    let content = content.to_string();
    if format == OutputFormat::Html {
        html_report::escaped(output, &content)?;
        output.write_all(b"\n")?;
    } else {
        writeln!(output, "{content}")?;
    }
    Ok(())
}

fn page_cursor<T: Display>(
    output: &mut impl Write,
    format: OutputFormat,
    cursor: Option<T>,
    row_kind: &str,
) -> Result<(), Box<dyn Error>> {
    if let Some(cursor) = cursor {
        line(
            output,
            format,
            format_args!("more {row_kind}s available; use cursor {cursor} for the next page"),
        )?;
    }
    Ok(())
}
