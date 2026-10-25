use super::{
    Case, EvidenceError, MAX_NODE_RANGES, MAX_NODES, MAX_SOURCE_ALIASES, MAX_SOURCES,
    case::encoded_details_length, model::SourceRange,
};
use crate::{artifact, sha256};
use serde::Serialize;
use serde_json::{Value, json};
use std::net::IpAddr;

/// Default number of leading bytes examined by an import scan
pub const DEFAULT_IMPORT_SCAN_BYTES: usize = 1024 * 1024;
/// Default finding budget used by an import scan
pub const MAX_IMPORT_FINDINGS: usize = 4_096;
/// Shortest printable ASCII run retained as a string observation
pub const MIN_ASCII_STRING_BYTES: usize = 4;
/// Maximum string excerpt retained in one observation's details
pub const MAX_ASCII_PREVIEW_BYTES: usize = 256;
const MAX_IP_TOKEN_BYTES: usize = 64;
const SCAN_SCOPE_LIMITATION: &str = "This scan records supported format-defined-offset file signatures, IP literal spellings, and printable ASCII runs; it does not establish that other file formats, binary values, or encoded observations are absent";
const SCAN_DISABLED_LIMITATION: &str =
    "Optional literal and file-signature scanning was disabled for this import";
const SOURCE_RETENTION_LIMITATION: &str =
    "Complete source bytes were not retained because a blob quota was reached";
const FINDING_OMISSION_LIMITATION: &str =
    "Some source observations were omitted after the configured finding or case quota";

/// Select whether an import only retains source bytes or also scans literal observations
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportScanMode {
    /// Retain and hash the full source without producing optional observations
    None,
    /// Record supported file signatures, IP literal spellings, and printable ASCII runs
    #[default]
    #[serde(rename = "literal-signature")]
    LiteralsAndSignatures,
}

/// Caller-selected byte and finding budgets for an import scan
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportScanOptions {
    /// Select optional observation scanning
    pub mode: ImportScanMode,
    /// Maximum leading source bytes examined by the scanner
    pub max_scan_bytes: usize,
    /// Maximum scanner observations retained before case-level quotas
    pub max_findings: usize,
}

impl Default for ImportScanOptions {
    fn default() -> Self {
        Self {
            mode: ImportScanMode::LiteralsAndSignatures,
            max_scan_bytes: DEFAULT_IMPORT_SCAN_BYTES,
            max_findings: MAX_IMPORT_FINDINGS,
        }
    }
}

/// Summary of bounded literal observations made from one imported source
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ImportScanReport {
    /// Content-derived source identity
    pub source_id: String,
    /// Identifier of the source node added before optional observations
    pub source_node_id: u64,
    /// Full source length, independently of the configured scan range
    pub source_length: u64,
    /// Whether the complete source bytes were retained in the case
    pub blob_retained: bool,
    /// Whether source acquisition retained the complete byte artifact
    pub source_complete: bool,
    /// Selected optional scanner mode
    pub scan_mode: ImportScanMode,
    /// Start offset of the scanned source range
    pub scanned_offset: u64,
    /// Number of source bytes examined by the optional scanner
    pub scanned_bytes: usize,
    /// Number of source bytes outside the optional scanner range
    pub unscanned_bytes: usize,
    /// Byte budget supplied by the caller
    pub max_scan_bytes: usize,
    /// Finding budget supplied by the caller
    pub max_findings: usize,
    /// Whether the selected scanner covered its configured source scope without omissions
    pub scan_complete: bool,
    /// Number of syntactically valid IPv4 literals found
    pub ipv4_literals: u64,
    /// Number of syntactically valid IPv6 literals found
    pub ipv6_literals: u64,
    /// Number of printable ASCII runs found
    pub ascii_strings: u64,
    /// Number of supported file signatures found at their declared offsets
    pub file_signatures: u64,
    /// Number of observation nodes retained
    pub retained_findings: usize,
    /// Exact number of findings left out by scanner or case quotas
    pub omitted_findings: u64,
    /// Node identifiers retained for this source
    pub node_ids: Vec<u64>,
    /// Explicit reasons that constrain this scan result
    pub limitations: Vec<String>,
}

#[derive(Clone)]
struct Finding {
    kind: &'static str,
    offset: usize,
    length: usize,
    details: Value,
}

struct CandidateScan {
    findings: Vec<Finding>,
    omitted: u64,
    ipv4: u64,
    ipv6: u64,
    ascii: u64,
    signatures: u64,
}

impl CandidateScan {
    const fn empty() -> Self {
        Self {
            findings: Vec::new(),
            omitted: 0,
            ipv4: 0,
            ipv6: 0,
            ascii: 0,
            signatures: 0,
        }
    }
}

struct RetainedFindings {
    node_ids: Vec<u64>,
    omitted: u64,
}

struct PreparedImport {
    digest: String,
    report: ImportScanReport,
    candidates: CandidateScan,
    ranges: Vec<SourceRange>,
    initial_details: Value,
    finding_node_ids: Vec<u64>,
}

impl Case {
    /// Retain a full import and scan its leading configured byte range
    ///
    /// The full input is always hashed and offered for blob retention. Optional
    /// literal and signature observations are bounded independently by scan options.
    ///
    /// # Errors
    /// Returns an error when source metadata, selected scan limits, or case quotas
    /// prevent retaining source provenance
    pub fn scan_import(
        &mut self,
        label: &str,
        kind: &str,
        bytes: &[u8],
    ) -> Result<ImportScanReport, EvidenceError> {
        self.scan_import_with_options(label, kind, bytes, ImportScanOptions::default())
    }

    /// Retain a full import and apply caller-selected optional scan budgets
    ///
    /// Source retention is recorded independently of scanner coverage. The root
    /// `imported_source` node is inserted before any optional finding nodes.
    ///
    /// # Errors
    /// Returns an error when source metadata or required root provenance is invalid
    pub fn scan_import_with_options(
        &mut self,
        label: &str,
        kind: &str,
        bytes: &[u8],
        options: ImportScanOptions,
    ) -> Result<ImportScanReport, EvidenceError> {
        let prepared = self.prepare_import(label, kind, bytes, options)?;
        self.commit_import(label, kind, bytes, prepared)
    }

    fn prepare_import(
        &self,
        label: &str,
        kind: &str,
        bytes: &[u8],
        options: ImportScanOptions,
    ) -> Result<PreparedImport, EvidenceError> {
        let digest = sha256(bytes);
        let source_id = format!("sha256:{digest}");
        self.validate_source_insert(label, kind, bytes, &source_id)?;
        let source_length =
            u64::try_from(bytes.len()).map_err(|_| EvidenceError::SourceMetadataConflict)?;
        let (scanned_bytes, unscanned_bytes, candidates) = scan_import_bytes(bytes, options)?;
        let candidate_finding_count = candidates.findings.len();
        let blob_retained = self.can_retain_blob(bytes, &source_id)?;
        let blob_id = blob_retained.then_some(source_id.as_str());

        // Validate the root before changing source or blob state
        let ranges = source_range(&source_id, bytes.len())?;
        let mut report = ImportScanReport {
            source_id: source_id.clone(),
            source_node_id: 0,
            source_length,
            blob_retained,
            source_complete: blob_retained,
            scan_mode: options.mode,
            scanned_offset: 0,
            scanned_bytes,
            unscanned_bytes,
            max_scan_bytes: options.max_scan_bytes,
            max_findings: options.max_findings,
            scan_complete: false,
            ipv4_literals: candidates.ipv4,
            ipv6_literals: candidates.ipv6,
            ascii_strings: candidates.ascii,
            file_signatures: candidates.signatures,
            retained_findings: candidate_finding_count,
            omitted_findings: u64::MAX,
            node_ids: Vec::new(),
            limitations: Vec::new(),
        };
        let initial_details = source_details(kind, &report);
        self.validate_import_root(blob_id, &ranges, &initial_details)?;
        let (expected_retained, expected_omitted) = self.expected_import_omissions(
            &initial_details,
            ranges.len(),
            &candidates,
            options.max_findings,
        )?;
        let planned_limitations = import_limitations(
            options,
            blob_retained,
            source_length,
            scanned_bytes,
            unscanned_bytes,
            expected_omitted,
        );
        self.validate_limitations(&planned_limitations)?;
        let mut finding_node_ids = Vec::new();
        finding_node_ids
            .try_reserve(expected_retained)
            .map_err(|_| EvidenceError::AllocationFailed {
                field: "import finding identifiers",
            })?;
        report.limitations = planned_limitations;

        Ok(PreparedImport {
            digest,
            report,
            candidates,
            ranges,
            initial_details,
            finding_node_ids,
        })
    }

    fn commit_import(
        &mut self,
        label: &str,
        kind: &str,
        bytes: &[u8],
        prepared: PreparedImport,
    ) -> Result<ImportScanReport, EvidenceError> {
        let PreparedImport {
            digest,
            mut report,
            mut candidates,
            ranges,
            initial_details,
            finding_node_ids,
        } = prepared;
        let source_id = report.source_id.clone();
        let blob_id = report.blob_retained.then_some(source_id.as_str());
        self.record_source(
            label,
            kind,
            bytes,
            &digest,
            &source_id,
            report.blob_retained,
        )?;
        report.source_node_id =
            self.add_node("imported_source", blob_id, ranges, initial_details)?;
        let retained = self.retain_findings(
            &source_id,
            blob_id,
            std::mem::take(&mut candidates.findings),
            finding_node_ids,
            report.max_findings,
        )?;
        report.omitted_findings = candidates.omitted.checked_add(retained.omitted).ok_or(
            EvidenceError::QuotaExceeded {
                field: "scan findings",
                maximum: report.max_findings,
            },
        )?;
        report.retained_findings = retained.node_ids.len();
        report.scan_complete = report.scan_mode != ImportScanMode::None
            && report.unscanned_bytes == 0
            && report.omitted_findings == 0;
        report.node_ids = retained.node_ids;

        // Fill the source summary after optional nodes reveal case-level omissions
        let final_details = source_details(kind, &report);
        self.replace_node_details(report.source_node_id, final_details)?;
        for limitation in &report.limitations {
            if *limitation == SOURCE_RETENTION_LIMITATION {
                self.mark_incomplete(limitation)?;
            } else {
                self.add_limitation(limitation)?;
            }
        }

        Ok(report)
    }

    fn validate_import_root(
        &self,
        blob_id: Option<&str>,
        ranges: &[SourceRange],
        details: &Value,
    ) -> Result<(), EvidenceError> {
        if ranges.len() > MAX_NODE_RANGES {
            return Err(EvidenceError::QuotaExceeded {
                field: "node source ranges",
                maximum: MAX_NODE_RANGES,
            });
        }
        if ranges.len() > self.remaining_range_capacity() {
            return Err(EvidenceError::QuotaExceeded {
                field: "source ranges",
                maximum: super::MAX_TOTAL_SOURCE_RANGES,
            });
        }
        // The source record is intentionally committed after this quota preflight
        self.validate_node("imported_source", blob_id, blob_id, &[], details)
    }

    fn plan_import_findings(
        &self,
        root_details: &Value,
        root_ranges: usize,
        findings: &[Finding],
    ) -> Result<usize, EvidenceError> {
        let root_detail_bytes = encoded_details_length(root_details)?;
        let mut detail_bytes = self.details_bytes.checked_add(root_detail_bytes).ok_or(
            EvidenceError::TotalDetailsTooLarge {
                length: usize::MAX,
                maximum: super::MAX_TOTAL_DETAILS_BYTES,
            },
        )?;
        let mut remaining_nodes = MAX_NODES.saturating_sub(self.nodes.len() + 1);
        let mut remaining_ranges = self.remaining_range_capacity().saturating_sub(root_ranges);
        let mut retained = 0;
        for finding in findings {
            let next_detail_bytes = detail_bytes
                .checked_add(encoded_details_length(&finding.details)?)
                .ok_or(EvidenceError::TotalDetailsTooLarge {
                    length: usize::MAX,
                    maximum: super::MAX_TOTAL_DETAILS_BYTES,
                })?;
            if remaining_nodes == 0
                || remaining_ranges == 0
                || next_detail_bytes > super::MAX_TOTAL_DETAILS_BYTES
            {
                continue;
            }
            detail_bytes = next_detail_bytes;
            remaining_nodes -= 1;
            remaining_ranges -= 1;
            retained += 1;
        }
        Ok(retained)
    }

    fn expected_import_omissions(
        &self,
        root_details: &Value,
        root_ranges: usize,
        candidates: &CandidateScan,
        finding_budget: usize,
    ) -> Result<(usize, u64), EvidenceError> {
        let candidate_count = candidates.findings.len();
        let retained =
            self.plan_import_findings(root_details, root_ranges, &candidates.findings)?;
        let case_omissions = u64::try_from(candidate_count - retained).map_err(|_| {
            EvidenceError::QuotaExceeded {
                field: "scan findings",
                maximum: finding_budget,
            }
        })?;
        let omitted =
            candidates
                .omitted
                .checked_add(case_omissions)
                .ok_or(EvidenceError::QuotaExceeded {
                    field: "scan findings",
                    maximum: finding_budget,
                })?;
        Ok((retained, omitted))
    }

    fn validate_source_insert(
        &self,
        label: &str,
        kind: &str,
        bytes: &[u8],
        source_id: &str,
    ) -> Result<(), EvidenceError> {
        super::case::validate_import_source_label(label, kind)?;
        let length =
            u64::try_from(bytes.len()).map_err(|_| EvidenceError::SourceMetadataConflict)?;
        if let Some(source) = self.source(source_id) {
            if source.length != length || source.kind != kind {
                return Err(EvidenceError::SourceMetadataConflict);
            }
            let needs_alias =
                source.label != label && !source.aliases.iter().any(|alias| alias == label);
            if needs_alias && source.aliases.len() == MAX_SOURCE_ALIASES {
                return Err(EvidenceError::QuotaExceeded {
                    field: "source aliases",
                    maximum: MAX_SOURCE_ALIASES,
                });
            }
        } else if self.sources.len() == MAX_SOURCES {
            return Err(EvidenceError::QuotaExceeded {
                field: "sources",
                maximum: MAX_SOURCES,
            });
        }
        Ok(())
    }

    fn can_retain_blob(&self, bytes: &[u8], source_id: &str) -> Result<bool, EvidenceError> {
        if let Some(existing) = self.blob(source_id) {
            if existing.bytes != bytes {
                return Err(EvidenceError::HashCollision);
            }
            return Ok(true);
        }
        Ok(self.blobs.len() < super::MAX_BLOBS
            && self
                .blob_bytes
                .checked_add(bytes.len())
                .is_some_and(|total| {
                    self.blob_byte_limit()
                        .is_none_or(|maximum| total <= maximum)
                }))
    }

    fn record_source(
        &mut self,
        label: &str,
        kind: &str,
        bytes: &[u8],
        digest: &str,
        source_id: &str,
        blob_retained: bool,
    ) -> Result<(), EvidenceError> {
        if blob_retained && self.blob(source_id).is_none() {
            self.add_blob(bytes)?;
        }
        self.add_source(
            label,
            kind,
            u64::try_from(bytes.len()).map_err(|_| EvidenceError::SourceMetadataConflict)?,
            digest,
            blob_retained.then_some(source_id),
        )?;
        Ok(())
    }

    fn retain_findings(
        &mut self,
        source_id: &str,
        blob_id: Option<&str>,
        findings: Vec<Finding>,
        mut node_ids: Vec<u64>,
        finding_budget: usize,
    ) -> Result<RetainedFindings, EvidenceError> {
        let mut omitted = 0_u64;
        let mut detail_bytes = self.details_bytes;
        let mut remaining_nodes = MAX_NODES.saturating_sub(self.nodes.len());
        let mut remaining_ranges = self.remaining_range_capacity();
        for finding in findings {
            let next_detail_bytes = detail_bytes
                .checked_add(encoded_details_length(&finding.details)?)
                .ok_or(EvidenceError::TotalDetailsTooLarge {
                    length: usize::MAX,
                    maximum: super::MAX_TOTAL_DETAILS_BYTES,
                })?;
            if remaining_nodes == 0
                || remaining_ranges == 0
                || next_detail_bytes > super::MAX_TOTAL_DETAILS_BYTES
            {
                omitted = omitted.checked_add(1).ok_or(EvidenceError::QuotaExceeded {
                    field: "scan findings",
                    maximum: finding_budget,
                })?;
                continue;
            }
            let range = SourceRange {
                source: source_id.to_owned(),
                packet: None,
                offset: u64::try_from(finding.offset)
                    .map_err(|_| EvidenceError::InvalidSourceRange)?,
                length: u64::try_from(finding.length)
                    .map_err(|_| EvidenceError::InvalidSourceRange)?,
            };
            let id = self.add_node(finding.kind, blob_id, vec![range], finding.details)?;
            node_ids.push(id);
            detail_bytes = next_detail_bytes;
            remaining_nodes -= 1;
            remaining_ranges -= 1;
        }
        Ok(RetainedFindings { node_ids, omitted })
    }
}

fn source_range(source_id: &str, length: usize) -> Result<Vec<SourceRange>, EvidenceError> {
    if length == 0 {
        return Ok(Vec::new());
    }
    Ok(vec![SourceRange {
        source: source_id.to_owned(),
        packet: None,
        offset: 0,
        length: u64::try_from(length).map_err(|_| EvidenceError::InvalidSourceRange)?,
    }])
}

fn scan_import_bytes(
    bytes: &[u8],
    options: ImportScanOptions,
) -> Result<(usize, usize, CandidateScan), EvidenceError> {
    let scanned_bytes = match options.mode {
        ImportScanMode::None => 0,
        ImportScanMode::LiteralsAndSignatures => bytes.len().min(options.max_scan_bytes),
    };
    let scan_window = bytes
        .get(..scanned_bytes)
        .ok_or(EvidenceError::InvalidSourceRange)?;
    let candidates = if options.mode == ImportScanMode::None {
        CandidateScan::empty()
    } else {
        scan_bytes(
            scan_window,
            bytes.len() == scanned_bytes,
            options.max_findings,
        )?
    };
    Ok((scanned_bytes, bytes.len() - scanned_bytes, candidates))
}

fn import_limitations(
    options: ImportScanOptions,
    blob_retained: bool,
    source_length: u64,
    scanned_bytes: usize,
    unscanned_bytes: usize,
    omitted_findings: u64,
) -> Vec<String> {
    let mut limitations = Vec::new();
    match options.mode {
        ImportScanMode::None => limitations.push(SCAN_DISABLED_LIMITATION.to_owned()),
        ImportScanMode::LiteralsAndSignatures => {
            limitations.push(SCAN_SCOPE_LIMITATION.to_owned());
        }
    }
    if !blob_retained {
        limitations.push(SOURCE_RETENTION_LIMITATION.to_owned());
    }
    if unscanned_bytes != 0 && options.mode != ImportScanMode::None {
        limitations.push(format!(
            "Optional scanning covered source range 0..{scanned_bytes} of {source_length}; {unscanned_bytes} source bytes were not scanned"
        ));
    }
    if omitted_findings != 0 {
        limitations.push(FINDING_OMISSION_LIMITATION.to_owned());
    }
    limitations
}

fn source_details(kind: &str, report: &ImportScanReport) -> Value {
    json!({
        "kind": kind,
        "length": report.source_length,
        "source_complete": report.source_complete,
        "scan_mode": report.scan_mode,
        "scanned_offset": report.scanned_offset,
        "scanned_bytes": report.scanned_bytes,
        "unscanned_bytes": report.unscanned_bytes,
        "max_scan_bytes": report.max_scan_bytes,
        "max_findings": report.max_findings,
        "scan_complete": report.scan_complete,
        "retained_findings": report.retained_findings,
        "omitted_findings": report.omitted_findings,
        "ipv4_literals": report.ipv4_literals,
        "ipv6_literals": report.ipv6_literals,
        "ascii_strings": report.ascii_strings,
        "file_signatures": report.file_signatures,
    })
}

fn scan_bytes(
    bytes: &[u8],
    source_end_is_scanned: bool,
    finding_budget: usize,
) -> Result<CandidateScan, EvidenceError> {
    let (signature_findings, signatures) = scan_signatures(bytes, finding_budget)?;
    let mut address_findings = Vec::new();
    let mut ascii_findings = Vec::new();
    let mut ipv4 = 0_u64;
    let mut ipv6 = 0_u64;
    let mut ascii = 0_u64;
    scan_addresses(
        bytes,
        source_end_is_scanned,
        &mut address_findings,
        finding_budget,
        &mut ipv4,
        &mut ipv6,
    )?;
    scan_ascii(
        bytes,
        source_end_is_scanned,
        &mut ascii_findings,
        finding_budget,
        &mut ascii,
    )?;
    let findings = merge_findings(
        signature_findings,
        address_findings,
        ascii_findings,
        finding_budget,
    )?;
    let total_findings = signatures
        .checked_add(ipv4)
        .and_then(|count| count.checked_add(ipv6))
        .and_then(|count| count.checked_add(ascii))
        .ok_or(EvidenceError::QuotaExceeded {
            field: "scan findings",
            maximum: finding_budget,
        })?;
    let omitted = omitted_count(total_findings, findings.len(), finding_budget)?;
    Ok(CandidateScan {
        findings,
        omitted,
        ipv4,
        ipv6,
        ascii,
        signatures,
    })
}

fn scan_signatures(
    bytes: &[u8],
    finding_budget: usize,
) -> Result<(Vec<Finding>, u64), EvidenceError> {
    let report = artifact::scan_file_signatures(bytes);
    let count = u64::try_from(report.matches.len()).map_err(|_| EvidenceError::QuotaExceeded {
        field: "scan findings",
        maximum: finding_budget,
    })?;
    let mut findings = Vec::new();
    for evidence in report.evidence_matches().take(finding_budget) {
        let signature = evidence.signature();
        try_push_finding(
            &mut findings,
            Finding {
                kind: "file_signature_match",
                offset: signature.range.offset,
                length: signature.range.length,
                details: json!(evidence),
            },
        )?;
    }
    Ok((findings, count))
}

fn merge_findings(
    signature_findings: Vec<Finding>,
    address_findings: Vec<Finding>,
    ascii_findings: Vec<Finding>,
    finding_budget: usize,
) -> Result<Vec<Finding>, EvidenceError> {
    let mut findings = Vec::new();
    let reserve = signature_findings
        .len()
        .checked_add(address_findings.len())
        .and_then(|count| count.checked_add(ascii_findings.len()))
        .ok_or(EvidenceError::AllocationFailed {
            field: "import scan findings",
        })?;
    findings
        .try_reserve(reserve)
        .map_err(|_| EvidenceError::AllocationFailed {
            field: "import scan findings",
        })?;
    findings.extend(signature_findings);
    findings.extend(address_findings);
    findings.extend(ascii_findings);
    findings.sort_by_key(|finding| (finding.offset, finding.kind));
    findings.truncate(finding_budget);
    Ok(findings)
}

fn omitted_count(
    total_findings: u64,
    retained_count: usize,
    finding_budget: usize,
) -> Result<u64, EvidenceError> {
    total_findings
        .checked_sub(
            u64::try_from(retained_count).map_err(|_| EvidenceError::QuotaExceeded {
                field: "scan findings",
                maximum: finding_budget,
            })?,
        )
        .ok_or(EvidenceError::QuotaExceeded {
            field: "scan findings",
            maximum: finding_budget,
        })
}

fn scan_addresses(
    bytes: &[u8],
    source_end_is_scanned: bool,
    findings: &mut Vec<Finding>,
    finding_budget: usize,
    ipv4_count: &mut u64,
    ipv6_count: &mut u64,
) -> Result<(), EvidenceError> {
    let mut start = 0_usize;
    while start < bytes.len() {
        if !is_address_byte(bytes.get(start).copied()) {
            start += 1;
            continue;
        }
        let token_start = start;
        while is_address_byte(bytes.get(start).copied()) {
            start += 1;
        }
        if !source_end_is_scanned && start == bytes.len() {
            continue;
        }
        let Some(token) = bytes.get(token_start..start) else {
            continue;
        };
        if token.len() > MAX_IP_TOKEN_BYTES || !address_boundary(bytes, token_start, start) {
            continue;
        }
        let Some((literal, offset, address)) = parse_address_token(token, token_start) else {
            continue;
        };
        let kind = match &address {
            IpAddr::V4(_) => {
                *ipv4_count = increment_count(*ipv4_count)?;
                "ipv4_literal"
            }
            IpAddr::V6(_) => {
                *ipv6_count = increment_count(*ipv6_count)?;
                "ipv6_literal"
            }
        };
        let literal = std::str::from_utf8(literal).map_err(|_| EvidenceError::InvalidText {
            field: "address literal",
        })?;
        if findings.len() < finding_budget {
            try_push_finding(
                findings,
                Finding {
                    kind,
                    offset,
                    length: literal.len(),
                    details: json!({
                        "literal": literal,
                        "parsed": address.to_string(),
                    }),
                },
            )?;
        }
    }
    Ok(())
}

fn parse_address_token(token: &[u8], token_offset: usize) -> Option<(&[u8], usize, IpAddr)> {
    if let Ok(text) = std::str::from_utf8(token)
        && let Ok(address) = text.parse::<IpAddr>()
    {
        return Some((token, token_offset, address));
    }
    let separator = token.iter().rposition(|byte| *byte == b':')?;
    let (host, colon_and_port) = token.split_at_checked(separator)?;
    let port = colon_and_port.get(1..)?;
    if host.is_empty() || port.is_empty() || !port.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let text = std::str::from_utf8(host).ok()?;
    let address = text.parse::<IpAddr>().ok()?;
    matches!(address, IpAddr::V4(_)).then_some((host, token_offset, address))
}

fn scan_ascii(
    bytes: &[u8],
    source_end_is_scanned: bool,
    findings: &mut Vec<Finding>,
    finding_budget: usize,
    count: &mut u64,
) -> Result<(), EvidenceError> {
    let mut offset = 0_usize;
    while offset < bytes.len() {
        if !bytes
            .get(offset)
            .is_some_and(|byte| (0x20..=0x7e).contains(byte))
        {
            offset += 1;
            continue;
        }
        let start = offset;
        while bytes
            .get(offset)
            .is_some_and(|byte| (0x20..=0x7e).contains(byte))
        {
            offset += 1;
        }
        let length = offset - start;
        if length < MIN_ASCII_STRING_BYTES {
            continue;
        }
        let run = bytes
            .get(start..offset)
            .ok_or(EvidenceError::InvalidSourceRange)?;
        let preview = run
            .get(..run.len().min(MAX_ASCII_PREVIEW_BYTES))
            .ok_or(EvidenceError::InvalidSourceRange)?;
        let preview_text =
            std::str::from_utf8(preview).map_err(|_| EvidenceError::InvalidText {
                field: "ASCII string",
            })?;
        *count = increment_count(*count)?;
        let ends_at_scan_boundary = !source_end_is_scanned && offset == bytes.len();
        if findings.len() < finding_budget {
            try_push_finding(
                findings,
                Finding {
                    kind: "ascii_string",
                    offset: start,
                    length,
                    details: json!({
                        "preview": preview_text,
                        "preview_truncated": length > preview.len(),
                        "length": length,
                    "ends_at_scan_boundary": ends_at_scan_boundary,
                    }),
                },
            )?;
        }
    }
    Ok(())
}

fn try_push_finding(findings: &mut Vec<Finding>, finding: Finding) -> Result<(), EvidenceError> {
    if findings.len() == findings.capacity() {
        findings
            .try_reserve(1)
            .map_err(|_| EvidenceError::AllocationFailed {
                field: "import scan findings",
            })?;
    }
    findings.push(finding);
    Ok(())
}

fn increment_count(count: u64) -> Result<u64, EvidenceError> {
    count.checked_add(1).ok_or(EvidenceError::QuotaExceeded {
        field: "scan observation count",
        maximum: usize::MAX,
    })
}

fn is_address_byte(byte: Option<u8>) -> bool {
    byte.is_some_and(|value| value.is_ascii_hexdigit() || matches!(value, b'.' | b':'))
}

fn address_boundary(bytes: &[u8], start: usize, end: usize) -> bool {
    let is_word =
        |byte: Option<u8>| byte.is_some_and(|value| value.is_ascii_alphanumeric() || value == b'_');
    !is_word(
        start
            .checked_sub(1)
            .and_then(|index| bytes.get(index).copied()),
    ) && !is_word(bytes.get(end).copied())
}
