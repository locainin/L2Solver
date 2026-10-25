use clap::{Args, Subcommand};
use std::path::{Path, PathBuf};

use super::{model::OutputFormat, value};

fn positive_usize(value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .ok()
        .filter(|number| *number > 0)
        .ok_or_else(|| String::from("value must be a positive integer"))
}

/// Durable carrier discovery operations over a published result directory
#[derive(Clone, Debug, PartialEq, Eq, Args)]
pub struct CarrierResultsArgs {
    /// Optional no-overwrite output file for report pages or exported bytes
    #[arg(long, global = true)]
    pub output: Option<PathBuf>,
    /// Result-store operation
    #[command(subcommand)]
    pub operation: CarrierResultsCommand,
}

/// Operations for creating, paging, exporting, and replaying durable carrier results
#[derive(Clone, Debug, PartialEq, Eq, Subcommand)]
pub enum CarrierResultsCommand {
    /// Discover caller-selected hypotheses and create a new durable result directory
    Discover {
        #[arg(value_name = "CASE")]
        case: PathBuf,
        #[arg(long = "node", required = true)]
        nodes: Vec<u64>,
        #[arg(long, default_value = "bytes", value_parser = ["bytes", "payload"])]
        view: String,
        #[arg(long)]
        plan: PathBuf,
        #[arg(long, value_name = "NEW_DIRECTORY")]
        directory: PathBuf,
        /// Choose a concise text summary naming the directory or the machine-readable JSON receipt
        #[arg(long, default_value = "text", value_parser = value::compare_format)]
        format: OutputFormat,
        /// Maximum number of bytes read from the plan document
        #[arg(long, default_value_t = 1_048_576, value_parser = positive_usize)]
        max_plan_bytes: usize,
        /// Maximum transformed bytes retained across candidates and partitions
        #[arg(long, default_value_t = 1_073_741_824, value_parser = clap::value_parser!(u64).range(1..))]
        max_output_bytes: u64,
        /// Maximum `SQLite` result database size
        #[arg(long, default_value_t = 4_294_967_296, value_parser = clap::value_parser!(u64).range(1..))]
        max_disk_bytes: u64,
    },
    /// List candidate summaries as one bounded page
    List {
        #[arg(value_name = "RESULT_DIRECTORY")]
        directory: PathBuf,
        #[arg(long, value_parser = clap::value_parser!(usize))]
        after: Option<usize>,
        #[arg(long, default_value_t = 256, value_parser = positive_usize)]
        limit: usize,
        /// Choose text, JSON, or HTML output
        #[arg(long, default_value = "text", value_parser = value::output_format)]
        format: OutputFormat,
        /// Maximum `SQLite` result database size accepted while reading
        #[arg(long, default_value_t = 4_294_967_296, value_parser = clap::value_parser!(u64).range(1..))]
        max_disk_bytes: u64,
        /// Maximum encoded size of one stored metadata or receipt record
        #[arg(long, default_value_t = l2_workbench::carrier::discovery::DEFAULT_MAX_RESULT_RECORD_BYTES, value_parser = clap::value_parser!(u64).range(1..))]
        max_record_bytes: u64,
        /// Maximum encoded bytes loaded for one candidate page
        #[arg(long, default_value_t = l2_workbench::carrier::discovery::DEFAULT_MAX_RESULT_PAGE_BYTES, value_parser = clap::value_parser!(u64).range(1..))]
        max_page_bytes: u64,
    },
    /// Show one candidate and a bounded page of its printable-run receipts
    Show {
        #[arg(value_name = "RESULT_DIRECTORY")]
        directory: PathBuf,
        #[arg(value_parser = clap::value_parser!(usize))]
        candidate: usize,
        #[arg(long, value_parser = clap::value_parser!(usize))]
        after_run_id: Option<usize>,
        #[arg(long, default_value_t = 256, value_parser = positive_usize)]
        limit: usize,
        #[arg(long, default_value = "discovery", value_parser = ["discovery", "control"])]
        partition: String,
        /// Choose text, JSON, or HTML output
        #[arg(long, default_value = "text", value_parser = value::output_format)]
        format: OutputFormat,
        /// Maximum `SQLite` result database size accepted while reading
        #[arg(long, default_value_t = 4_294_967_296, value_parser = clap::value_parser!(u64).range(1..))]
        max_disk_bytes: u64,
        /// Maximum encoded size of one stored metadata or receipt record
        #[arg(long, default_value_t = l2_workbench::carrier::discovery::DEFAULT_MAX_RESULT_RECORD_BYTES, value_parser = clap::value_parser!(u64).range(1..))]
        max_record_bytes: u64,
        /// Maximum encoded bytes loaded for one candidate page
        #[arg(long, default_value_t = l2_workbench::carrier::discovery::DEFAULT_MAX_RESULT_PAGE_BYTES, value_parser = clap::value_parser!(u64).range(1..))]
        max_page_bytes: u64,
    },
    /// Page exact source receipts, mappings, and discovery/control assignments
    Sources {
        #[arg(value_name = "RESULT_DIRECTORY")]
        directory: PathBuf,
        #[arg(long, value_parser = clap::value_parser!(u64))]
        after_sample_id: Option<u64>,
        #[arg(long, default_value_t = 128, value_parser = positive_usize)]
        limit: usize,
        /// Choose text, JSON, or HTML output
        #[arg(long, default_value = "text", value_parser = value::output_format)]
        format: OutputFormat,
        /// Maximum `SQLite` result database size accepted while reading
        #[arg(long, default_value_t = 4_294_967_296, value_parser = clap::value_parser!(u64).range(1..))]
        max_disk_bytes: u64,
        /// Maximum encoded size of one stored metadata or receipt record
        #[arg(long, default_value_t = l2_workbench::carrier::discovery::DEFAULT_MAX_RESULT_RECORD_BYTES, value_parser = clap::value_parser!(u64).range(1..))]
        max_record_bytes: u64,
        /// Maximum encoded bytes loaded for one source page
        #[arg(long, default_value_t = l2_workbench::carrier::discovery::DEFAULT_MAX_RESULT_PAGE_BYTES, value_parser = clap::value_parser!(u64).range(1..))]
        max_page_bytes: u64,
    },
    /// Export exact transformed output bytes for one candidate and partition
    Export {
        #[arg(value_name = "RESULT_DIRECTORY")]
        directory: PathBuf,
        #[arg(value_parser = clap::value_parser!(usize))]
        candidate: usize,
        #[arg(long, default_value = "discovery", value_parser = ["discovery", "control"])]
        partition: String,
        /// Maximum `SQLite` result database size accepted while reading
        #[arg(long, default_value_t = 4_294_967_296, value_parser = clap::value_parser!(u64).range(1..))]
        max_disk_bytes: u64,
        /// Maximum encoded size of one stored metadata or receipt record
        #[arg(long, default_value_t = l2_workbench::carrier::discovery::DEFAULT_MAX_RESULT_RECORD_BYTES, value_parser = clap::value_parser!(u64).range(1..))]
        max_record_bytes: u64,
    },
    /// Recompute a selected candidate after checking source and plan identity
    Replay {
        #[arg(value_name = "CASE")]
        case: PathBuf,
        #[arg(long = "node", required = true)]
        nodes: Vec<u64>,
        #[arg(long, default_value = "bytes", value_parser = ["bytes", "payload"])]
        view: String,
        #[arg(long)]
        plan: PathBuf,
        #[arg(long, value_name = "RESULT_DIRECTORY")]
        directory: PathBuf,
        #[arg(value_parser = clap::value_parser!(usize))]
        candidate: usize,
        /// Maximum number of bytes read from the plan document
        #[arg(long, default_value_t = 1_048_576, value_parser = positive_usize)]
        max_plan_bytes: usize,
        /// Maximum `SQLite` result database size accepted while reading
        #[arg(long, default_value_t = 4_294_967_296, value_parser = clap::value_parser!(u64).range(1..))]
        max_disk_bytes: u64,
        /// Maximum encoded size of one stored metadata or receipt record
        #[arg(long, default_value_t = l2_workbench::carrier::discovery::DEFAULT_MAX_RESULT_RECORD_BYTES, value_parser = clap::value_parser!(u64).range(1..))]
        max_record_bytes: u64,
    },
}

impl CarrierResultsArgs {
    #[must_use]
    pub fn output(&self) -> Option<&Path> {
        self.output.as_deref()
    }
}
