use super::{input, read_bounded, visit};
use crate::{arguments::PatternReportLimits, output::BoundedWriter};
use l2_workbench::{
    behavior::{self, BehaviorConfig, BehaviorFinding, BehaviorKind, EndpointEventReport},
    query::IpCidr,
};
use serde::Serialize;
use std::{collections::BTreeSet, error::Error, io::Write, path::Path};

#[derive(Serialize)]
struct ScopedFinding {
    page: Option<String>,
    #[serde(flatten)]
    finding: BehaviorFinding,
}

#[derive(Serialize)]
struct PatternReport<'a> {
    inventory: visit::VisitSummary,
    report_limits: &'a PatternReportLimits,
    retained_finding_bytes: usize,
    complete: bool,
    findings: Vec<ScopedFinding>,
    omitted_findings: usize,
    endpoint_events: Option<EndpointEventReport>,
    limitations: BTreeSet<String>,
}

pub(super) fn behavior(
    path: &Path,
    internal: &[String],
    gap: Option<u64>,
    limits: &PatternReportLimits,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    if internal.len() > 128 {
        return Err("too many internal networks".into());
    }
    let networks = internal
        .iter()
        .map(|network| IpCidr::parse(network))
        .collect::<Result<Vec<_>, _>>()?;
    run(
        path,
        &BehaviorConfig {
            internal_networks: networks,
            large_forward_gap_ticks: gap,
        },
        None,
        false,
        limits,
        output,
    )
}

pub(super) fn timestamps(
    path: &Path,
    events: Option<&Path>,
    gap: Option<u64>,
    limits: &PatternReportLimits,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    let endpoint = events
        .map(|path| {
            let bytes = read_bounded(input::regular(path)?, behavior::MAX_ENDPOINT_EVENT_BYTES)?;
            Ok::<_, Box<dyn Error>>(behavior::parse_endpoint_events(&bytes)?)
        })
        .transpose()?;
    run(
        path,
        &BehaviorConfig {
            internal_networks: Vec::new(),
            large_forward_gap_ticks: gap,
        },
        endpoint,
        true,
        limits,
        output,
    )
}

fn run(
    path: &Path,
    config: &BehaviorConfig,
    endpoint_events: Option<EndpointEventReport>,
    timestamps_only: bool,
    limits: &PatternReportLimits,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    let mut findings = Vec::new();
    let mut matched_findings = 0_usize;
    let mut bytes = 0_usize;
    let mut limitations = BTreeSet::new();
    let inventory = visit::cases(path, |case, page| {
        let page_limitations = behavior::visit_case(case, config, |finding| {
            if timestamps_only && !timestamp_kind(finding.kind) {
                return Ok(());
            }
            if page.primary.is_some_and(|(first, last)| {
                !finding.packet_numbers.is_empty()
                    && !finding
                        .packet_numbers
                        .iter()
                        .any(|number| (u64::from(first)..=u64::from(last)).contains(number))
            }) {
                return Ok(());
            }
            // Count every selected finding even after either output budget is exhausted
            matched_findings = matched_findings
                .checked_add(1)
                .ok_or("selected behavior finding count overflow")?;
            if findings.len() == limits.max_findings.get() {
                return Ok(());
            }
            let result = ScopedFinding {
                page: page.path.map(str::to_owned),
                finding,
            };
            // Count encoded bytes without allocating a second JSON document for the finding
            let mut counter = BoundedWriter::named(
                std::io::sink(),
                limits.max_report_bytes.get() - bytes,
                "behavior finding",
            );
            match serde_json::to_writer(&mut counter, &result) {
                Ok(()) => {
                    bytes = bytes
                        .checked_add(counter.written())
                        .ok_or("retained behavior finding byte count overflow")?;
                    // Reserve space only for findings that pass both retention budgets
                    findings.try_reserve(1)?;
                    findings.push(result);
                }
                // The sink cannot fail; I/O errors mean this finding exceeded the byte budget
                Err(error) if error.is_io() => {}
                Err(error) => return Err(error.into()),
            }
            Ok(())
        })?;
        limitations.extend(page_limitations);
        Ok(())
    })?;
    let omitted = matched_findings - findings.len();
    let complete = inventory.collection_complete && omitted == 0;
    limitations.insert("Each bundle page has a bounded context window; patterns and chains spanning farther than that window remain unresolved".to_owned());
    if omitted != 0 {
        limitations
            .insert("Some findings were omitted after the output count or byte budget".to_owned());
    }
    let report = PatternReport {
        inventory,
        report_limits: limits,
        retained_finding_bytes: bytes,
        complete,
        findings,
        omitted_findings: omitted,
        endpoint_events,
        limitations,
    };
    serde_json::to_writer(output, &report)?;
    Ok(complete)
}

const fn timestamp_kind(kind: BehaviorKind) -> bool {
    matches!(
        kind,
        BehaviorKind::CaptureClockAnomaly
            | BehaviorKind::TimestampClockMismatch
            | BehaviorKind::RegularConnectionIntervals
            | BehaviorKind::Smb2FileBasicInfoSetRequest
            | BehaviorKind::Smb2UnparsedRange
    )
}
