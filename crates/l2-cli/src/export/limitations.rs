//! Aggregate extraction limitations and render retained omission reports

use super::{
    coverage::{
        cohort_analysis_complete, coverage_add, flow_reconstruction_coverage,
        reconstruction_is_complete,
    },
    evidence::EvidenceCoverage,
    summary::{Summary, summary_text, write_reconstruction_omissions},
};
use crate::workbench;
use serde::Serialize;
use std::{
    collections::BTreeMap,
    error::Error,
    fs,
    fs::File,
    io,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

#[derive(serde::Deserialize, Serialize)]
struct Limitation {
    flow_id: Option<i64>,
    message: String,
}

#[derive(Clone, Copy, Default)]
struct StaticCaseLimitationCoverage {
    flow_cases: u64,
    cohort_cases: u64,
}

#[derive(Clone, Copy)]
pub(super) enum CaseLimitationOrigin<'a> {
    Flow(i64),
    Cohort(&'a str),
}

pub(super) struct LimitationSpool {
    path: PathBuf,
    file: File,
    pub(super) count: u64,
    pub(super) blocking_count: u64,
    static_case_limitations: BTreeMap<String, StaticCaseLimitationCoverage>,
}

impl LimitationSpool {
    pub(super) fn new(staging: &Path) -> io::Result<Self> {
        let path = staging.join(".l2solver-limitations.jsonl");
        let file = File::options().write(true).create_new(true).open(&path)?;
        Ok(Self {
            path,
            file,
            count: 0,
            blocking_count: 0,
            static_case_limitations: BTreeMap::new(),
        })
    }

    pub(super) fn push_case_limitation(
        &mut self,
        origin: CaseLimitationOrigin<'_>,
        message: &str,
    ) -> Result<(), Box<dyn Error>> {
        if let Some(static_message) = static_case_limitation(message) {
            if !self.static_case_limitations.contains_key(static_message) {
                self.count = coverage_add(self.count, 1)?;
            }
            let coverage = self
                .static_case_limitations
                .entry(static_message.to_owned())
                .or_default();
            match origin {
                CaseLimitationOrigin::Flow(_) => {
                    coverage.flow_cases = coverage_add(coverage.flow_cases, 1)?;
                }
                CaseLimitationOrigin::Cohort(_) => {
                    coverage.cohort_cases = coverage_add(coverage.cohort_cases, 1)?;
                }
            }
            return Ok(());
        }

        match origin {
            CaseLimitationOrigin::Flow(flow_id) => {
                self.push_with_impact(Some(flow_id), message.to_owned(), false)
            }
            CaseLimitationOrigin::Cohort(label) => {
                self.push_with_impact(None, format!("{label}: {message}"), false)
            }
        }
    }

    pub(super) fn push(
        &mut self,
        flow_id: Option<i64>,
        message: String,
    ) -> Result<(), Box<dyn Error>> {
        self.push_with_impact(flow_id, message, true)
    }

    pub(super) fn push_with_impact(
        &mut self,
        flow_id: Option<i64>,
        message: String,
        discovery_incomplete: bool,
    ) -> Result<(), Box<dyn Error>> {
        serde_json::to_writer(&mut self.file, &Limitation { flow_id, message })?;
        self.file.write_all(b"\n")?;
        self.count = self
            .count
            .checked_add(1)
            .ok_or("export limitation count overflow")?;
        if discovery_incomplete {
            self.blocking_count = self
                .blocking_count
                .checked_add(1)
                .ok_or("export discovery limitation count overflow")?;
        }
        Ok(())
    }

    pub(super) fn write_to(&mut self, output: &mut File) -> Result<(), Box<dyn Error>> {
        self.file.flush()?;
        self.file.sync_all()?;
        let mut rows = BufReader::new(File::open(&self.path)?);
        let mut line = String::new();
        loop {
            line.clear();
            if rows.read_line(&mut line)? == 0 {
                break;
            }
            let limitation: Limitation = serde_json::from_str(line.trim_end())?;
            if let Some(flow_id) = limitation.flow_id {
                writeln!(
                    output,
                    "- Flow {flow_id}: {}",
                    summary_text(&limitation.message)
                )?;
            } else {
                writeln!(output, "- {}", summary_text(&limitation.message))?;
            }
        }
        for (message, coverage) in &self.static_case_limitations {
            writeln!(
                output,
                "- Case limitation applies to {} flow Cases and {} cohort Cases: {}",
                coverage.flow_cases,
                coverage.cohort_cases,
                summary_text(message)
            )?;
        }
        Ok(())
    }

    pub(super) fn remove(self) -> io::Result<()> {
        self.file.sync_all()?;
        drop(self.file);
        fs::remove_file(self.path)
    }
}

const STATIC_CASE_LIMITATIONS: &[&str] = &[
    "This case contains explicitly selected original records; absence and event chains outside that selection remain unresolved",
    "This selected record window preserves original source positions; absence, protocol state, and event chains outside the window remain unresolved",
    "Capture order and header addresses do not establish ownership, delivery, causality, or malicious intent",
    "Checksums, peer processing, decryption authenticity, and external credential acceptance are not validated",
    "Fragment IDs and TCP tuples can be reused; reconstructed bytes are candidates and endpoint overlap policy is unresolved",
    "Length fields, bit planes, capitalization, and timing are measurements; matching hypotheses are not protocol or covert-channel proof",
    "Some capture evidence or analysis is incomplete; case limitations identify omitted or unsupported inputs",
    "Evidence describes capture record order and does not establish ownership, delivery, cause, or intent",
    "IP and Ethernet addresses are header claims at the capture point; routing, proxies, and spoofed fields can explain pairings",
    "IP and transport checksums, DNS authenticity, and endpoint processing are not validated",
    "Nonzero bytes after a declared length may be ordinary padding; FCS absence is a source declaration",
    "Missing, dropped, unsupported, or omitted records cannot establish absence of an event",
    "DNS matches describe retained outstanding queries; collisions stay ambiguous and unique matches consume their query",
    "DNS address uses describe later destination co-occurrence; TTL validity, resolver caching, application use, and causality are unresolved",
    "Exact tuple mismatches do not rule out NAT, proxies, protocol helpers, or omitted capture data",
    "A correlated session is an observed endpoint and timing match, not proof that the FTP command was accepted or caused the session",
    "This indexed flow selection includes complete unfragmented transport envelopes only; raw fragments remain in the source and may require separate reconstruction",
];

fn static_case_limitation(message: &str) -> Option<&str> {
    let is_source_quality = message.starts_with("Source sha256:")
        && message.ends_with(
            "has unknown collection quality for one or more sections; analysis is scoped to captured bytes",
        );
    STATIC_CASE_LIMITATIONS
        .contains(&message)
        .then_some(message)
        .or_else(|| is_source_quality.then_some(message))
}

pub(super) fn add_source_limitations(
    limitations: &mut LimitationSpool,
    source: &workbench::full_source::SourceCoverage,
) -> Result<(), Box<dyn Error>> {
    if l2_workbench::capture_collection::has_unknown_quality(source.collection_summary) {
        limitations.push_with_impact(
            None,
            String::from(
                "Source collection quality was not reported for every capture section; analysis is scoped to captured bytes",
            ),
            false,
        )?;
    }
    if l2_workbench::capture_collection::reports_incomplete_collection(source.collection_summary) {
        if source.collection_summary.incomplete_sections != 0 {
            limitations.push(
                None,
                format!(
                    "Source reports {} incomplete collection sections",
                    source.collection_summary.incomplete_sections
                ),
            )?;
        }
        if source.collection_summary.packet_block_packets_dropped != 0 {
            limitations.push(
                None,
                format!(
                    "Obsolete Packet Blocks report {} packets dropped between captured packets",
                    source.collection_summary.packet_block_packets_dropped
                ),
            )?;
        }
        if source
            .collection_summary
            .packet_blocks_with_unavailable_drop_count
            != 0
        {
            limitations.push(
                None,
                format!(
                    "{} obsolete Packet Blocks have an unavailable drop count",
                    source
                        .collection_summary
                        .packet_blocks_with_unavailable_drop_count
                ),
            )?;
        }
    }
    if source.packets_without_supported_transport != 0 {
        // Scope exclusions remain visible without implying that native work failed
        limitations.push_with_impact(
            None,
            format!(
                "Artifact discovery is scoped to supported-transport flow Cases; {} packets without supported transport are outside that scope, including fragments not assigned to an indexed flow",
                source.packets_without_supported_transport
            ),
            false,
        )?;
    }
    Ok(())
}

pub(super) fn write_limitations(
    directory: &Path,
    summary: &mut Summary<'_>,
) -> Result<(), Box<dyn Error>> {
    if !limitations_required(summary) {
        return Ok(());
    }
    let mut output = File::create_new(directory.join("limitations.txt"))?;
    writeln!(output, "L2Solver capture export limitations")?;
    write_flow_limitations(&mut output, summary)?;
    write_cohort_limitations(&mut output, summary)?;
    write_evidence_limitations(&mut output, summary.evidence)?;
    write_artifact_limitations(&mut output, summary)?;
    write_tshark_limitations(&mut output, summary)?;
    summary.limitations.write_to(&mut output)?;
    output.sync_all()?;
    Ok(())
}

const fn limitations_required(summary: &Summary<'_>) -> bool {
    summary.limitations.count != 0
        || summary.coverage.analysis.incomplete_flows != 0
        || summary.coverage.analysis.omitted_flow_records != 0
        || summary.coverage.analysis.range_omission_flows != 0
        || summary.coverage.analysis.omitted_tcp_records != 0
        || summary.coverage.analysis.omitted_fragments != 0
        || summary.coverage.analysis.omitted_sequence_ranges != 0
        || summary.coverage.analysis.omitted_tcp_bytes != 0
        || summary.coverage.analysis.omitted_tcp_observations != 0
        || summary.coverage.analysis.omitted_fragment_bytes != 0
        || summary.coverage.analysis.omitted_fragment_observations != 0
        || summary.coverage.analysis.unmeasured_omitted_ranges != 0
        || summary.coverage.analysis.omitted_state_observations != 0
        || !reconstruction_is_complete(
            &summary
                .coverage
                .analysis
                .supplementary_pages
                .reconstruction_omissions,
        )
        || !reconstruction_is_complete(&summary.coverage.cohort_reconstruction)
        || !cohort_analysis_complete(summary.coverage)
        || l2_workbench::capture_collection::reports_incomplete_collection(
            summary.coverage.source.collection_summary,
        )
        || summary.discovery.artifacts.references_omitted != 0
        || summary.evidence.omitted_cases != 0
        || summary.tshark_error.is_some()
        || !summary.tshark.issues.is_empty()
}

fn write_evidence_limitations(output: &mut File, evidence: EvidenceCoverage) -> io::Result<()> {
    if evidence.omitted_cases != 0 {
        writeln!(
            output,
            "Evidence sidecar retained {} of {} Cases; {} complete Case records ({} encoded bytes) exceeded the {} byte aggregate evidence budget",
            evidence.retained_cases,
            evidence.selected_cases,
            evidence.omitted_cases,
            evidence.omitted_bytes,
            evidence.budget_bytes
        )?;
    }
    Ok(())
}

fn write_flow_limitations(output: &mut File, summary: &Summary<'_>) -> io::Result<()> {
    if summary.coverage.analysis.incomplete_flows != 0
        || summary.coverage.analysis.omitted_flow_records != 0
    {
        writeln!(
            output,
            "Flow analysis selected {} records, retained {}, and omitted {}",
            summary.coverage.analysis.selected_flow_records,
            summary.coverage.analysis.retained_flow_records,
            summary.coverage.analysis.omitted_flow_records
        )?;
    }
    let pages = summary.coverage.analysis.supplementary_pages;
    if pages.pages != 0 {
        writeln!(
            output,
            "Supplementary flow pages: {} across {} flows; selected records {}; retained records {}; omitted records {}; each page was analyzed independently and state was not joined across page boundaries",
            pages.pages,
            pages.flows,
            pages.selected_records,
            pages.retained_records,
            pages.omitted_records
        )?;
    }
    if summary.coverage.analysis.selection_truncated_flows != 0 {
        writeln!(
            output,
            "Flow retention limits: {} prefix-truncated flows ({} frame-limited, {} byte-limited, {} unit-limited)",
            summary.coverage.analysis.selection_truncated_flows,
            summary.coverage.analysis.frame_limited_flows,
            summary.coverage.analysis.byte_limited_flows,
            summary.coverage.analysis.unit_limited_flows
        )?;
    }
    write_reconstruction_omissions(
        output,
        "Flow",
        flow_reconstruction_coverage(summary.coverage),
        false,
    )?;
    write_reconstruction_omissions(
        output,
        "Supplementary page",
        pages.reconstruction_omissions,
        false,
    )?;
    Ok(())
}

fn write_cohort_limitations(output: &mut File, summary: &Summary<'_>) -> io::Result<()> {
    if !cohort_analysis_complete(summary.coverage) {
        if let Some(cohorts) = summary.coverage.cohort_analysis {
            writeln!(
                output,
                "Unordered source/scope/IP-pair cohort analysis was partial: {} multi-flow groups ({} complete, {} incomplete), {} split groups, {} chunks ({} complete, {} incomplete), {} records selected, {} retained, {} omitted, {} flows reanalyzed, {} singleton chunks skipped, {} oversized flows skipped",
                cohorts.multi_flow_groups,
                cohorts.complete_groups,
                cohorts.incomplete_groups,
                cohorts.split_groups,
                cohorts.analysis_chunks,
                cohorts.complete_chunks,
                cohorts.incomplete_chunks,
                cohorts.selected_records,
                cohorts.retained_records,
                cohorts.omitted_records,
                cohorts.reanalyzed_flows,
                cohorts.singleton_chunks_skipped,
                cohorts.oversized_flows_skipped,
            )?;
        } else {
            writeln!(
                output,
                "Unordered source/scope/IP-pair cohort analysis was not run"
            )?;
        }
    }
    write_reconstruction_omissions(
        output,
        "Cohort",
        summary.coverage.cohort_reconstruction,
        false,
    )?;
    Ok(())
}

pub(super) fn write_artifact_limitations(
    output: &mut File,
    summary: &Summary<'_>,
) -> io::Result<()> {
    let coverage = summary.discovery.artifacts;
    if coverage.references_omitted != 0 {
        writeln!(
            output,
            "Artifact references selected {}, retained {}, and omitted {}",
            coverage.references_selected, coverage.references_retained, coverage.references_omitted
        )?;
        write_omission_count(
            output,
            "artifact count limit",
            coverage.count_limit_omissions,
        )?;
        write_omission_count(
            output,
            "artifact byte limit",
            coverage.artifact_byte_limit_omissions,
        )?;
        write_omission_count(
            output,
            "provenance count limit",
            coverage.provenance_count_limit_omissions,
        )?;
        write_omission_count(
            output,
            "provenance byte limit",
            coverage.provenance_byte_limit_omissions,
        )?;
        write_omission_count(
            output,
            "unreadable TShark object",
            coverage.unreadable_object_omissions,
        )?;
        writeln!(
            output,
            "Omission details: {} retained in manifest; {} exceeded the detail bound; {} unidentified TShark omissions",
            coverage.omission_details_retained,
            coverage.omission_details_not_retained,
            coverage.unidentified_omissions
        )?;
    }
    Ok(())
}

fn write_tshark_limitations(output: &mut File, summary: &Summary<'_>) -> io::Result<()> {
    if let Some(error) = summary.tshark_error {
        writeln!(output, "TShark: {}", summary_text(error))?;
    }
    for issue in &summary.tshark.issues {
        writeln!(output, "TShark: {}", summary_text(issue))?;
    }
    Ok(())
}

fn write_omission_count(output: &mut File, label: &str, count: u64) -> io::Result<()> {
    if count != 0 {
        writeln!(output, "- {label}: {count} omitted references")?;
    }
    Ok(())
}
