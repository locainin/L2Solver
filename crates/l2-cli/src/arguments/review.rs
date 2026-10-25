use super::{CorrelationResources, OutputFormat, value};
use clap::Args;
use std::{
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
};

/// One review view joins hypotheses, tool evidence, carrier results and identity mappings
#[derive(Clone, Debug, PartialEq, Eq, Args)]
pub struct ReviewArgs {
    pub directory: PathBuf,
    #[arg(long = "carrier-results")]
    pub carrier_results: Vec<PathBuf>,
    #[arg(long)]
    pub correlation_plan: Option<PathBuf>,
    #[command(flatten)]
    pub resources: CorrelationResources,
    /// Preview rows for each hypothesis, tool or candidate section
    #[arg(long, default_value = "100")]
    pub limit: NonZeroUsize,
    #[arg(long, default_value = "4294967296")]
    pub max_result_disk_bytes: NonZeroU64,
    #[arg(long, default_value = "67108864")]
    pub max_result_record_bytes: NonZeroU64,
    #[arg(long, default_value = "67108864")]
    pub max_result_page_bytes: NonZeroU64,
    #[arg(long, default_value = "16777216")]
    pub max_report_bytes: NonZeroUsize,
    /// Choose text, JSON, or HTML report output
    #[arg(long, default_value = "text", value_parser = value::output_format)]
    pub format: OutputFormat,
    /// Write the report to FILE instead of standard output
    #[arg(long, value_name = "FILE")]
    pub output: Option<PathBuf>,
}
