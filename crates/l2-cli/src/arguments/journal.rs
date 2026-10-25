use super::OutputFormat;
use clap::{Args, Subcommand};
use std::path::PathBuf;

/// Durable investigation state kept separate from original capture evidence
#[derive(Clone, Debug, PartialEq, Eq, Args)]
pub struct JournalArgs {
    pub directory: PathBuf,
    #[arg(long,default_value_t=64,global=true,value_parser=clap::value_parser!(u32).range(1..))]
    pub cache_mib: u32,
    /// Per-record metadata read/allocation budget, adjustable for larger analyst plans
    #[arg(long, default_value_t = 1_048_576, global = true)]
    pub max_entry_bytes: usize,
    /// Maximum retained `TShark` report bytes loaded for integrity checks
    #[arg(
        long,
        default_value_t = l2_workbench::journal::DEFAULT_MAX_TOOL_REPORT_BYTES,
        global = true
    )]
    pub max_tool_report_bytes: usize,
    #[arg(long, global = true)]
    pub output: Option<PathBuf>,
    #[command(subcommand)]
    pub operation: JournalCommand,
}
#[derive(Clone, Debug, PartialEq, Eq, Subcommand)]
pub enum JournalCommand {
    /// Retain one base case and create an empty investigation database
    Create { case: PathBuf },
    /// Recheck retained evidence, model identities and stored object hashes
    Verify,
    /// Add an exact model without replacing an existing model's checks
    Add { model: PathBuf },
    /// Append a check and its exact supporting document
    Check {
        hypothesis: String,
        check: PathBuf,
        evidence: PathBuf,
    },
    /// Store a decoder result and receipt without copying the complete case
    Derive {
        #[arg(
            long,
            conflicts_with = "hypothesis",
            required_unless_present = "hypothesis"
        )]
        node: Option<u64>,
        #[arg(long, required_unless_present = "node")]
        hypothesis: Option<String>,
        #[arg(long)]
        recipe: PathBuf,
    },
    /// Stream the complete ordered check history for one model
    Checks {
        hypothesis: String,
        #[arg(long, default_value_t = 0)]
        after: u64,
        #[arg(long)]
        limit: Option<u64>,
    },
    /// Stream model entries with stable identity pagination
    Entries {
        #[arg(long)]
        after: Option<String>,
        #[arg(long)]
        limit: Option<u64>,
    },
    /// Summarize evidence, active models, failures and unresolved assumptions
    Review {
        /// Choose text, JSON, or HTML report output
        #[arg(long, default_value = "text", value_parser = super::value::output_format)]
        format: OutputFormat,
        #[arg(long)]
        limit: Option<u64>,
    },
    /// Retain source-scoped events from the base case, another case or a whole disk index
    Events {
        #[arg(long, conflicts_with = "index")]
        case: Option<PathBuf>,
        #[arg(long)]
        index: Option<PathBuf>,
    },
    /// Stream matching event sequences across the whole journal in source record order
    Chains { plan: PathBuf },
    /// Export exact stored output bytes
    Export { hypothesis: String },
    /// Export one check's exact evidence by numeric ID, check identity, or object hash
    ExportEvidence { reference: String },
    /// Copy and verify a version 1 or 2 journal into a new destination
    Migrate { destination: PathBuf },
    /// Import an `L2Solver` `TShark` receipt after matching its source hash and length
    ImportTshark {
        report: PathBuf,
        #[arg(long, required = true)]
        source: PathBuf,
        /// Maximum `TShark` report size in MiB
        #[arg(long, default_value_t = 256, value_parser = clap::value_parser!(u64).range(1..))]
        max_report_mib: u64,
        /// Maximum capture size to hash in MiB
        #[arg(long, default_value_t = 256, value_parser = clap::value_parser!(u64).range(1..))]
        max_source_mib: u64,
    },
}
