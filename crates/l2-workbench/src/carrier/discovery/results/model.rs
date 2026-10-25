//! Public budgets and receipts for durable discovery results

use super::super::model::{DiscoveryIdentity, DiscoveryLimit};
use serde::{Deserialize, Serialize};

pub(super) const RESULTS_FILE: &str = "results.sqlite";
pub(super) const RESULTS_SCHEMA: u32 = 1;
/// Default bound for one metadata, candidate, source, or printable-run record
pub const DEFAULT_MAX_RESULT_RECORD_BYTES: u64 = 64 * 1024 * 1024;
/// Default aggregate encoded-size bound for one requested result page
pub const DEFAULT_MAX_RESULT_PAGE_BYTES: u64 = 64 * 1024 * 1024;

/// Reader budgets for opening and paging a durable discovery result store
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResultReadOptions {
    /// Maximum result database file size accepted by the reader
    pub max_disk_bytes: u64,
    /// Maximum encoded size copied into memory for any single result record
    pub max_record_bytes: u64,
    /// Maximum encoded size copied into memory across one requested page
    pub max_page_bytes: u64,
}

/// Independent output and disk budgets for durable discovery results
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreOptions {
    /// Maximum transformed bytes retained across every candidate and partition
    pub max_output_bytes: u64,
    /// Maximum size of the published `SQLite` result database
    pub max_disk_bytes: u64,
}

/// Summary fields retained separately from pageable candidate and printable-run rows
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredDiscoverySummary {
    /// Result database schema version
    pub schema_version: u32,
    /// Exact plan identity used for the discovery pass
    pub plan_sha256: String,
    /// Shared source scope and selected endpoint identity
    pub identity: DiscoveryIdentity,
    /// Number of selected source samples with complete mapping receipts
    pub sample_receipt_count: usize,
    /// Sample identifiers omitted because a selected payload was empty
    pub omitted_empty_sample_ids: Vec<u64>,
    /// Number of parameter combinations in the plan
    pub parameter_space_size: usize,
    /// Sum of selected source bytes
    pub input_bytes: usize,
    /// Caller-supplied input budget
    pub input_budget_bytes: usize,
    /// Number of candidates attempted
    pub attempted_parameters: usize,
    /// Number of reset-unit transforms attempted
    pub attempted_transforms: usize,
    /// Work charged to the deterministic search
    pub work_bytes: usize,
    /// Caller-supplied work budget
    pub work_budget_bytes: usize,
    /// Caller-supplied candidate budget
    pub candidate_budget: usize,
    /// Transformed output bytes retained in the store
    pub output_bytes: u64,
    /// Caller-supplied transformed output budget
    pub output_budget_bytes: u64,
    /// Caller-supplied result database size budget
    pub disk_budget_bytes: u64,
    /// Candidate row count
    pub candidate_count: usize,
    /// Printable-run row count
    pub printable_run_count: usize,
    /// Whether the complete caller-selected parameter space was enumerated
    pub enumeration_complete: bool,
    /// Explicit reasons enumeration ended early
    pub limits: Vec<DiscoveryLimit>,
    /// Digest over the plan, receipts, candidates, runs, and output rows
    pub result_sha256: String,
}

/// One result page with the cursor needed to request the following page
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResultPage<T, C = usize> {
    /// Rows in ascending stable identifier order
    pub rows: Vec<T>,
    /// Cursor for the next page, when another page may exist
    pub next_after: Option<C>,
}

/// Identity retained after a selected candidate was recomputed against its original inputs
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayReceipt {
    /// Candidate identifier selected from the durable result store
    pub candidate_id: usize,
    /// Exact source plan digest checked before replay
    pub plan_sha256: String,
    /// Result store digest checked before replay
    pub result_sha256: String,
    /// Whether the re-created measurements match the stored candidate
    pub matches_stored_output: bool,
}
