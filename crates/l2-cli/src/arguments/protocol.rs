use clap::Args;
use l2_workbench::protocol::ProtocolLimits;

/// Checked resource budgets and optional run-level boundary discovery
#[derive(Clone, Copy, Debug, Eq, PartialEq, Args)]
pub struct ProtocolAnalysisArgs {
    /// Maximum labeled messages considered in one protocol analysis
    #[arg(long, default_value_t = l2_workbench::protocol::MAX_PROTOCOL_SAMPLES)]
    pub protocol_max_samples: usize,
    /// Maximum bytes retained from one selected message sample
    #[arg(long, default_value_t = l2_workbench::protocol::MAX_MESSAGE_BYTES)]
    pub protocol_max_message_bytes: usize,
    /// Maximum aggregate selected bytes analyzed in one protocol command
    #[arg(long, default_value_t = l2_workbench::protocol::MAX_PROTOCOL_BYTES)]
    pub protocol_max_total_bytes: usize,
    /// Maximum bytes scanned from one selected contiguous TCP run
    #[arg(long, default_value_t = l2_workbench::protocol::MAX_PROTOCOL_RUN_BYTES)]
    pub protocol_max_run_bytes: usize,
    /// Inclusive highest prefix offset considered during length-field inference
    #[arg(long, default_value_t = l2_workbench::protocol::MAX_PROTOCOL_PREFIX_OFFSET)]
    pub protocol_max_prefix_offset: usize,
    /// Maximum framing and field candidates retained in one report
    #[arg(long, default_value_t = l2_workbench::protocol::MAX_FRAMING_CANDIDATES)]
    pub protocol_max_candidates: usize,
    /// Maximum frame ranges retained for each candidate partition
    #[arg(long, default_value_t = l2_workbench::protocol::MAX_PROTOCOL_RETAINED_FRAMES)]
    pub protocol_max_retained_frames: usize,
    /// Storage budget for candidate boundary ranges and alias examples
    #[arg(long, default_value_t = l2_workbench::protocol::MAX_PROTOCOL_REPORT_BYTES)]
    pub protocol_max_report_bytes: usize,
    /// Extract candidate delimiters and length prefixes from selected TCP byte runs
    #[arg(long)]
    pub infer_run_boundaries: bool,
}

impl ProtocolAnalysisArgs {
    /// Convert CLI values to the protocol module's checked budgets
    #[must_use]
    pub const fn limits(self) -> ProtocolLimits {
        ProtocolLimits {
            max_samples: self.protocol_max_samples,
            max_message_bytes: self.protocol_max_message_bytes,
            max_total_bytes: self.protocol_max_total_bytes,
            max_run_bytes: self.protocol_max_run_bytes,
            max_prefix_offset: self.protocol_max_prefix_offset,
            max_candidates: self.protocol_max_candidates,
            max_retained_frames: self.protocol_max_retained_frames,
            max_report_bytes: self.protocol_max_report_bytes,
        }
    }
}
