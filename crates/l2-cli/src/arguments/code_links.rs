use clap::Args;
use l2_workbench::artifact::{MAX_CODE_LINKS, MAX_RUNTIME_MODULE_MAPPINGS};
use std::path::PathBuf;

/// Link explicit runtime mappings to existing syscall trace correlations
#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct CodeLinksArgs {
    /// Source-bound static analysis receipt JSON
    #[arg(value_name = "ANALYSIS_RECEIPT_JSON")]
    pub receipt: PathBuf,
    /// Existing trace report with syscall-to-capture correlation results
    #[arg(long, value_name = "TRACE_MATCH_REPORT_JSON")]
    pub trace_matches: PathBuf,
    /// Caller-provided runtime address to binary file mapping JSON
    #[arg(long, value_name = "RUNTIME_MAP_JSON")]
    pub runtime_map: PathBuf,
    /// Supply the analyzed binary bytes to recheck its hash and static function offsets
    #[arg(long, value_name = "BINARY")]
    pub binary: Option<PathBuf>,
    /// Supply the raw acquisition source used to produce the runtime map
    #[arg(long, value_name = "MAPPING_SOURCE")]
    pub mapping_source: Option<PathBuf>,
    /// Maximum bytes read from each JSON document and optional mapping source
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    pub max_input_bytes: usize,
    /// Maximum runtime mapping ranges accepted
    #[arg(long, default_value_t = MAX_RUNTIME_MODULE_MAPPINGS)]
    pub max_mappings: usize,
    /// Maximum stack-frame links retained in the report
    #[arg(long, default_value_t = MAX_CODE_LINKS)]
    pub max_links: usize,
}
