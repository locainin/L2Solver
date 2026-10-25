use super::{OutputFormat, value};
use clap::Args;
use std::{
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    path::PathBuf,
};

/// Review supplied identity and clock evidence against a persistent event journal
#[derive(Clone, Debug, PartialEq, Eq, Args)]
pub struct CorrelationArgs {
    pub directory: PathBuf,
    #[arg(long)]
    pub plan: PathBuf,
    #[command(flatten)]
    pub resources: CorrelationResources,
    /// Choose text, JSON, or HTML report output
    #[arg(long, default_value = "text", value_parser = value::output_format)]
    pub format: OutputFormat,
    #[arg(long)]
    pub output: Option<PathBuf>,
}

/// Shared reader and working-set controls for correlation and investigation views
#[derive(Clone, Debug, PartialEq, Eq, Args)]
pub struct CorrelationResources {
    #[arg(long, default_value = "100000")]
    pub max_events: NonZeroUsize,
    /// Shared work budget for event scanning and correlation
    #[arg(long, default_value = "10000000")]
    pub max_work_items: NonZeroU64,
    /// Encoded event bytes retained before correlation, independent of event count
    #[arg(long, default_value = "67108864")]
    pub max_retained_bytes: NonZeroUsize,
    #[arg(long, default_value = "1048576")]
    pub max_entry_bytes: NonZeroUsize,
    /// Maximum retained tool-report bytes loaded for integrity checks
    #[arg(long, default_value = "268435456")]
    pub max_tool_report_bytes: NonZeroUsize,
    #[arg(long, default_value = "1048576")]
    pub max_plan_bytes: NonZeroUsize,
    #[arg(long, default_value = "64")]
    pub cache_mib: NonZeroU32,
}
