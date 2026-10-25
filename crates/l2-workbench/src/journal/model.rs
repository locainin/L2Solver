use super::ChainDeadline;
use crate::evidence::SourceRange;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const DEFAULT_MAX_TOOL_REPORT_BYTES: usize = 256 * 1024 * 1024;

/// Operator-selected memory budgets, separate from evidence or protocol sizes
#[derive(Clone, Copy, Debug)]
pub struct JournalOptions {
    pub cache_mib: u32,
    pub max_entry_bytes: usize,
    pub max_tool_report_bytes: usize,
}
impl Default for JournalOptions {
    fn default() -> Self {
        Self {
            cache_mib: 64,
            max_entry_bytes: 1024 * 1024,
            max_tool_report_bytes: DEFAULT_MAX_TOOL_REPORT_BYTES,
        }
    }
}

/// An exact model; changing inputs, operations or premises creates a new identity
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hypothesis {
    pub title: String,
    pub input: Value,
    pub operation: Value,
    pub assumptions: Vec<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckKind {
    Structural,
    Independent,
    ReportedExternal,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckOutcome {
    Pass,
    Fail,
    Unresolved,
}

/// Shows when a stored check binding was first created
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckBindingOrigin {
    /// The row is marked as recorded in this journal; this origin is stored metadata, not a signature
    Recorded,
    /// The binding was created while migrating a legacy journal without one
    LegacyUnverified,
}

/// Check classifications are analyst assertions retained with the supplied evidence
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub kind: CheckKind,
    pub outcome: CheckOutcome,
    pub explanation: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct RecordedCheck {
    pub id: u64,
    pub identity: String,
    pub binding_origin: CheckBindingOrigin,
    pub check: Check,
    pub evidence_sha256: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Entry {
    pub id: String,
    pub hypothesis: Hypothesis,
    pub conclusion: &'static str,
    pub checks: Vec<RecordedCheck>,
    pub checks_omitted: u64,
    pub output_sha256: Option<String>,
    pub receipt_sha256: Option<String>,
    pub derivation: Option<DerivationSummary>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Overview {
    pub hypotheses: u64,
    pub checks: u64,
    pub events: u64,
    pub tool_receipts: u64,
    pub base_case_sha256: String,
    pub limitations: Vec<&'static str>,
}

/// A retained external-tool report and its linked journal observations
#[derive(Clone, Debug, Serialize)]
pub struct ToolReceiptSummary {
    pub evidence_sha256: String,
    pub tool: String,
    pub version: String,
    pub source_sha256: String,
    pub linked_events: u64,
}

/// A source-scoped observation with its original record order and exact clock
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub source: String,
    pub scope: String,
    pub packet: u64,
    pub kind: String,
    pub actor: Option<String>,
    pub peer: Option<String>,
    pub clock: Option<String>,
    pub ticks: Option<u64>,
    pub fields: Value,
    pub ranges: Vec<SourceRange>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventSelector {
    pub kind: Option<String>,
    pub actor: Option<String>,
    pub peer: Option<String>,
    #[serde(default)]
    pub fields: BTreeMap<String, Value>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventJoin {
    pub left_step: usize,
    pub left_field: String,
    pub right_step: usize,
    pub right_field: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainPlan {
    /// Wall-clock work budget; explicit null disables the deadline
    #[serde(default)]
    pub max_elapsed_ms: ChainDeadline,
    #[serde(default)]
    pub joins: Vec<EventJoin>,
    pub steps: Vec<EventSelector>,
    #[serde(default = "yes")]
    pub same_actor: bool,
    pub max_gap_ticks: Option<u64>,
    pub limit: Option<u64>,
}
const fn yes() -> bool {
    true
}
#[derive(Clone, Debug, Serialize)]
pub struct Chain {
    pub relation: &'static str,
    pub events: Vec<Event>,
    pub interpretation: &'static str,
}

/// Execution and structural checks remain separate from independent acceptance
#[derive(Clone, Debug, Serialize)]
pub struct DerivationSummary {
    pub operation_completed: bool,
    pub constraints_satisfied: bool,
    pub failed_step: Option<usize>,
}

/// Exactly one verified input for a journal derivation
#[derive(Clone, Copy, Debug)]
pub enum DerivationInput<'a> {
    BaseNode(u64),
    DerivedOutput(&'a str),
}
