use super::plan::Mutation;
use crate::application::ParseStatus;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExperimentMode {
    Offline,
    Loopback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExperimentStatus {
    /// All planned operations and parser budgets completed; candidate ambiguity is reported separately
    Complete,
    /// An operation failed, a loopback receipt mismatched, or a parser budget omitted bytes
    Partial,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationFailure {
    InvalidBit,
    InvalidHex,
    InvalidKeyLength,
    EmptyRange,
    RangeOutOfBounds,
    InvalidTruncateLength,
    OutputTooLarge,
    TotalBytesExceeded,
    AllocationFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ExperimentOutcome {
    Baseline,
    Applied,
    Failed { reason: MutationFailure },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CandidateSummary {
    pub status: ParseStatus,
    pub finding_count: usize,
    pub unparsed_bytes: usize,
    pub budget_omissions: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ParserSummary {
    /// The parser's structural DNS-over-TCP candidate, not port attribution
    pub dns_tcp: CandidateSummary,
    /// The parser's structural HTTP candidate, not endpoint intent
    pub http: CandidateSummary,
    /// The parser's structural FTP candidate, not transfer acceptance
    pub ftp: CandidateSummary,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TransportReceipt {
    pub address: String,
    pub port: u16,
    pub sent_length: usize,
    pub received_length: usize,
    pub received_sha256: String,
    pub matches_sent: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExperimentStep {
    pub sequence: usize,
    pub mutation: Option<Mutation>,
    pub outcome: ExperimentOutcome,
    pub input_length: usize,
    pub output_length: usize,
    pub input_sha256: String,
    pub output_sha256: String,
    pub parser: Option<ParserSummary>,
    pub transport: Option<TransportReceipt>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExperimentReport {
    pub schema_version: u32,
    pub mode: ExperimentMode,
    pub status: ExperimentStatus,
    pub input_sha256: String,
    pub final_sha256: String,
    /// Aggregate bytes passed to the parsers, including the baseline
    pub inspected_bytes: usize,
    pub steps: Vec<ExperimentStep>,
}
