use clap::Args;
use l2_workbench::evidence::MAX_BLOB_TOTAL_BYTES;
use std::{num::NonZeroUsize, path::PathBuf};

/// Explicit byte-node concatenation options
#[derive(Clone, Debug, PartialEq, Eq, Args)]
pub struct ConcatenateArgs {
    /// Evidence case containing every selected byte node
    #[arg(value_name = "CASE", allow_hyphen_values = true)]
    pub case: PathBuf,
    /// Byte nodes in exact output order; repeated nodes remain repeated
    #[arg(long = "node", required = true, value_parser = clap::value_parser!(u64).range(1..))]
    pub nodes: Vec<u64>,
    /// Maximum concatenated output bytes
    #[arg(long, default_value = MAX_BLOB_TOTAL_BYTES.to_string())]
    pub max_output_bytes: NonZeroUsize,
    /// Write the updated case atomically to this path
    #[arg(long, value_name = "NEW_CASE")]
    pub output: Option<PathBuf>,
}
