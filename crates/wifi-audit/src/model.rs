use serde::{Deserialize, Serialize};
use wifi_core::MacAddress;

/// Report severity independent from test verdict
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Policy assertion result
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Verdict {
    Fail,
    Potential,
}

/// Passive security-relevant observation without policy assertion
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Exposure {
    id: &'static str,
    severity: Severity,
    title: String,
    bssid: MacAddress,
    evidence_sequences: Vec<u64>,
}

impl Exposure {
    pub(crate) const fn new(
        id: &'static str,
        severity: Severity,
        title: String,
        bssid: MacAddress,
        evidence_sequences: Vec<u64>,
    ) -> Self {
        Self {
            id,
            severity,
            title,
            bssid,
            evidence_sequences,
        }
    }

    #[must_use]
    pub const fn id(&self) -> &'static str {
        self.id
    }

    #[must_use]
    pub const fn severity(&self) -> Severity {
        self.severity
    }

    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    #[must_use]
    pub const fn bssid(&self) -> MacAddress {
        self.bssid
    }

    #[must_use]
    pub fn evidence_sequences(&self) -> &[u64] {
        &self.evidence_sequences
    }
}

/// Evidence-backed wireless policy mismatch
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Finding {
    id: &'static str,
    verdict: Verdict,
    severity: Severity,
    title: String,
    expected: String,
    observed: String,
    bssid: MacAddress,
    evidence_sequences: Vec<u64>,
}

impl Finding {
    pub(crate) fn new(input: FindingInput) -> Self {
        Self {
            id: input.id,
            verdict: input.verdict,
            severity: input.severity,
            title: input.title,
            expected: input.expected,
            observed: input.observed,
            bssid: input.bssid,
            evidence_sequences: input.evidence_sequences,
        }
    }

    #[must_use]
    pub const fn id(&self) -> &'static str {
        self.id
    }

    #[must_use]
    pub const fn verdict(&self) -> Verdict {
        self.verdict
    }

    #[must_use]
    pub const fn severity(&self) -> Severity {
        self.severity
    }

    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    #[must_use]
    pub fn expected(&self) -> &str {
        &self.expected
    }

    #[must_use]
    pub fn observed(&self) -> &str {
        &self.observed
    }

    #[must_use]
    pub const fn bssid(&self) -> MacAddress {
        self.bssid
    }

    #[must_use]
    pub fn evidence_sequences(&self) -> &[u64] {
        &self.evidence_sequences
    }
}

pub struct FindingInput {
    pub id: &'static str,
    pub verdict: Verdict,
    pub severity: Severity,
    pub title: String,
    pub expected: String,
    pub observed: String,
    pub bssid: MacAddress,
    pub evidence_sequences: Vec<u64>,
}

/// Coverage state stays separate from findings
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CoverageStatus {
    Tested,
    NotTested,
    Incomplete,
    NotApplicable,
}

/// One assessed or unavailable wireless check
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Coverage {
    id: &'static str,
    status: CoverageStatus,
    reason: String,
}

impl Coverage {
    pub(crate) const fn new(id: &'static str, status: CoverageStatus, reason: String) -> Self {
        Self { id, status, reason }
    }

    #[must_use]
    pub const fn id(&self) -> &'static str {
        self.id
    }

    #[must_use]
    pub const fn status(&self) -> CoverageStatus {
        self.status
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Deterministically ordered wireless assessment output
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct Assessment {
    exposures: Vec<Exposure>,
    findings: Vec<Finding>,
    coverage: Vec<Coverage>,
}

impl Assessment {
    pub(crate) fn new(
        mut exposures: Vec<Exposure>,
        mut findings: Vec<Finding>,
        mut coverage: Vec<Coverage>,
    ) -> Self {
        exposures.sort_by(|left, right| {
            left.id()
                .cmp(right.id())
                .then_with(|| left.bssid().cmp(&right.bssid()))
        });
        findings.sort_by(|left, right| {
            left.id()
                .cmp(right.id())
                .then_with(|| left.bssid().cmp(&right.bssid()))
        });
        coverage.sort_by_key(Coverage::id);
        Self {
            exposures,
            findings,
            coverage,
        }
    }

    #[must_use]
    pub fn exposures(&self) -> &[Exposure] {
        &self.exposures
    }

    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    #[must_use]
    pub fn coverage_entries(&self) -> &[Coverage] {
        &self.coverage
    }

    #[must_use]
    pub fn exposure(&self, id: &str) -> Option<&Exposure> {
        self.exposures.iter().find(|item| item.id() == id)
    }

    #[must_use]
    pub fn finding(&self, id: &str) -> Option<&Finding> {
        self.findings.iter().find(|item| item.id() == id)
    }

    #[must_use]
    pub fn coverage(&self, id: &str) -> Option<&Coverage> {
        self.coverage.iter().find(|item| item.id() == id)
    }
}
