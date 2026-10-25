use super::ReconstructionArgs;
use clap::{Args, Subcommand};
use l2_workbench::reconstruction::Limits;

/// Queries stream rows from a persistent index rather than collecting every connection
#[derive(Clone, Debug, PartialEq, Eq, Subcommand)]
pub enum IndexedCommand {
    /// Extract candidate messages and test decoding hypotheses across one complete indexed tuple
    Messages(super::MessagesArgs),
    /// Report capture, tuple, and relationship counts
    Summary,
    /// Reparse retained sources and check hashes, ranges, metadata, and flow membership
    Verify,
    /// Stream tuple summaries as JSON lines
    Flows {
        #[arg(long,default_value_t=0,value_parser=clap::value_parser!(i64).range(0..))]
        after: i64,
        #[arg(long)]
        limit: Option<u64>,
    },
    /// Stream DNS answer-to-later-destination relationships as JSON lines
    Relationships {
        #[arg(long)]
        limit: Option<u64>,
    },
    /// Stream exact values shared by at least two distinct capture sources
    SharedGroups {
        #[arg(long, requires = "after_key_hex")]
        after_kind: Option<String>,
        #[arg(long, requires = "after_kind")]
        after_key_hex: Option<String>,
        #[arg(long)]
        limit: Option<u64>,
    },
    /// Stream source-qualified packet witnesses for one shared value
    SharedOccurrences {
        #[arg(long, value_parser = ["ip_address", "dns_question", "packet_bytes"])]
        kind: String,
        #[arg(long, value_name = "HEX_BYTES")]
        key_hex: String,
        #[arg(long, requires = "after_packet")]
        after_source: Option<String>,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..), requires = "after_source")]
        after_packet: Option<u32>,
        #[arg(long)]
        limit: Option<u64>,
    },
    /// Reconstruct the selected packet union of one or more tuples from one source
    Flow(IndexedFlowArgs),
    /// Export exact retained bytes of one original source record
    Packet {
        #[arg(long)]
        source: String,
        #[arg(value_parser=clap::value_parser!(u32).range(1..))]
        packet: u32,
    },
}

/// Ordered indexed-flow selection and reconstruction budget overrides
#[derive(Clone, Debug, PartialEq, Eq, Args)]
pub struct IndexedFlowArgs {
    /// One or more flow IDs from `indexed DIRECTORY flows`
    #[arg(value_name = "FLOW", required = true, num_args = 1.., value_parser = clap::value_parser!(i64).range(1..))]
    pub flow: Vec<i64>,
    // Whole-capture and selected-flow cases share one argument definition
    #[command(flatten)]
    resources: ReconstructionArgs,
}

impl IndexedFlowArgs {
    /// Return the configured reconstruction budgets, including their displayed defaults
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.resources.limits()
    }
}
