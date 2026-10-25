use clap::Args;
use l2_workbench::{
    artifact::zip::{MAX_ZIP_ENTRIES, MAX_ZIP_ENTRY_EXPANDED_BYTES, MAX_ZIP_TOTAL_EXPANDED_BYTES},
    evidence::{MAX_BLOB_TOTAL_BYTES, MAX_NODES},
};
use std::{num::NonZeroUsize, path::PathBuf};

/// Recursive structured-artifact expansion options
#[derive(Clone, Debug, PartialEq, Eq, Args)]
pub struct ExpandArgs {
    /// Evidence case containing the selected byte node
    #[arg(value_name = "CASE", allow_hyphen_values = true)]
    pub case: PathBuf,
    /// Retained byte node to expand
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pub node: u64,
    /// Maximum child nesting depth, with the selected object at depth zero
    #[arg(long, default_value_t = 8)]
    pub max_depth: u32,
    /// Maximum format, member, chunk, value, issue, and omission nodes added
    #[arg(long, default_value = MAX_NODES.to_string())]
    pub max_objects: NonZeroUsize,
    /// Maximum bytes accepted for any object inspected by a format parser
    #[arg(long, default_value = MAX_BLOB_TOTAL_BYTES.to_string())]
    pub max_input_bytes: NonZeroUsize,
    /// Maximum ZIP entries inspected before a preallocation is attempted
    #[arg(long, default_value = MAX_ZIP_ENTRIES.to_string())]
    pub max_archive_entries: NonZeroUsize,
    /// Maximum expanded bytes retained from one archive member
    #[arg(long, default_value = MAX_ZIP_ENTRY_EXPANDED_BYTES.to_string())]
    pub max_member_bytes: NonZeroUsize,
    /// Maximum declared ZIP member bytes charged before extraction across all ZIPs, including failed validation; defaults to 64 MiB
    #[arg(long = "max-zip-work-bytes", alias = "max-archive-output-bytes", default_value = MAX_ZIP_TOTAL_EXPANDED_BYTES.to_string())]
    pub max_zip_work_bytes: NonZeroUsize,
    /// Maximum new distinct blob bytes retained by this expansion
    #[arg(long, default_value = MAX_BLOB_TOTAL_BYTES.to_string())]
    pub max_retained_bytes: NonZeroUsize,
    /// Write the updated case atomically to this path
    #[arg(long, value_name = "NEW_CASE")]
    pub output: Option<PathBuf>,
}
