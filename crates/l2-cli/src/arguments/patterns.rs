use clap::Args;
use serde::Serialize;
use std::num::NonZeroUsize;

/// Shared retention budgets for behavior and timestamp finding reports
#[derive(Clone, Debug, PartialEq, Eq, Args, Serialize)]
pub struct PatternReportLimits {
    /// Maximum selected findings retained across the entire case or bundle
    #[arg(long, value_name = "COUNT", default_value = "4096")]
    pub max_findings: NonZeroUsize,
    /// Maximum encoded finding bytes retained, excluding report metadata
    #[arg(long, value_name = "BYTES", default_value = "8388608")]
    pub max_report_bytes: NonZeroUsize,
}
