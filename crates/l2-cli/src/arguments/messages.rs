use clap::Args;
use l2_workbench::{
    hypothesis::{SearchLimits, workflow::WorkflowLimits},
    protocol::ProtocolLimits,
    reconstruction::Limits as ReconstructionLimits,
};
use std::path::PathBuf;

/// Run source-mapped message extraction and bounded recipe search over one indexed TCP flow
#[derive(Clone, Debug, PartialEq, Eq, Args)]
pub struct MessagesArgs {
    /// Stable indexed tuple identifier
    #[arg(value_parser = clap::value_parser!(i64).range(1..))]
    pub flow: i64,
    /// JSON framing and decoder plan
    #[arg(long, value_name = "PLAN_JSON")]
    pub plan: PathBuf,
    /// Maximum plan file bytes read before JSON parsing
    #[arg(long, default_value_t = 1_048_576)]
    pub max_plan_bytes: usize,

    /// Maximum selected-flow records retained by reconstruction
    #[arg(long, default_value_t = ReconstructionLimits::default().frames)]
    pub reconstruction_frames: u64,
    /// Maximum selected-flow captured frame bytes retained
    #[arg(long, default_value_t = ReconstructionLimits::default().bytes)]
    pub reconstruction_bytes: usize,
    /// Maximum selected-flow packet and transport observations retained
    #[arg(long, default_value_t = ReconstructionLimits::default().units)]
    pub reconstruction_units: usize,
    /// Maximum TCP sessions retained for the selected flow
    #[arg(long, default_value_t = ReconstructionLimits::default().sessions)]
    pub reconstruction_sessions: usize,
    /// Maximum fragment groups retained for the selected flow
    #[arg(long, default_value_t = ReconstructionLimits::default().datagrams)]
    pub reconstruction_datagrams: usize,
    /// Aggregate byte positions visited during stream and fragment reconstruction
    #[arg(long, default_value_t = ReconstructionLimits::default().range_bytes)]
    pub reconstruction_range_bytes: usize,
    /// Maximum source observations retained in one reconstructed TCP range
    #[arg(long, default_value_t = l2_workbench::tcp_range::MAX_OBSERVATIONS)]
    pub reconstruction_range_observations: usize,
    /// Maximum copied source bytes retained in one reconstructed TCP range
    #[arg(long, default_value_t = l2_workbench::tcp_range::MAX_RETAINED_BYTES)]
    pub reconstruction_range_retained_bytes: usize,

    /// Maximum candidate-framed message records retained across the flow
    #[arg(long, default_value_t = ProtocolLimits::default().max_samples)]
    pub protocol_max_samples: usize,
    /// Maximum bytes in one candidate-framed message
    #[arg(long, default_value_t = ProtocolLimits::default().max_message_bytes)]
    pub protocol_max_message_bytes: usize,
    /// Maximum unique reconstructed bytes supplied to candidate parsers
    #[arg(long, default_value_t = ProtocolLimits::default().max_total_bytes)]
    pub protocol_max_total_bytes: usize,
    /// Maximum unique bytes supplied from one directional TCP stream
    #[arg(long, default_value_t = ProtocolLimits::default().max_run_bytes)]
    pub protocol_max_run_bytes: usize,
    /// Maximum candidate framing rules applied to each stream
    #[arg(long, default_value_t = ProtocolLimits::default().max_candidates)]
    pub protocol_max_candidates: usize,
    /// Estimated aggregate storage for mapped messages and transitions
    #[arg(long, default_value_t = ProtocolLimits::default().max_report_bytes)]
    pub protocol_max_report_bytes: usize,
    /// Aggregate search candidate, recipe assessment, and held-out check rows retained
    #[arg(long, default_value_t = WorkflowLimits::default().max_result_rows)]
    pub workflow_max_result_rows: usize,

    /// Maximum bytes accepted by one canonical decoder run or expanded search candidate
    #[arg(long, default_value_t = SearchLimits::default().max_input_bytes)]
    pub search_max_input_bytes: usize,
    /// Maximum output bytes from one canonical transformation
    #[arg(long, default_value_t = SearchLimits::default().max_output_bytes)]
    pub search_max_output_bytes: usize,
    /// Maximum intermediate output bytes in one canonical recipe
    #[arg(long, default_value_t = SearchLimits::default().max_intermediate_bytes)]
    pub search_max_intermediate_bytes: usize,
    /// Maximum cumulative attempted input and output bytes in the transformation search
    #[arg(long, default_value_t = SearchLimits::default().max_work_bytes)]
    pub search_max_work_bytes: usize,
    /// Maximum known-plaintext consistency tests retained
    #[arg(long, default_value_t = SearchLimits::default().max_key_tests)]
    pub search_max_key_tests: usize,
    /// Maximum caller-supplied recipe parameter bytes
    #[arg(long, default_value_t = SearchLimits::default().max_recipe_parameter_bytes)]
    pub search_max_recipe_parameter_bytes: usize,
}

impl MessagesArgs {
    /// Build the exact runtime budgets recorded in workflow output
    #[must_use]
    pub const fn limits(&self) -> WorkflowLimits {
        WorkflowLimits {
            reconstruction: ReconstructionLimits {
                frames: self.reconstruction_frames,
                bytes: self.reconstruction_bytes,
                units: self.reconstruction_units,
                sessions: self.reconstruction_sessions,
                datagrams: self.reconstruction_datagrams,
                range_bytes: self.reconstruction_range_bytes,
                range_observations: self.reconstruction_range_observations,
                range_retained_bytes: self.reconstruction_range_retained_bytes,
            },
            protocol: ProtocolLimits {
                max_samples: self.protocol_max_samples,
                max_message_bytes: self.protocol_max_message_bytes,
                max_total_bytes: self.protocol_max_total_bytes,
                max_run_bytes: self.protocol_max_run_bytes,
                max_prefix_offset: l2_workbench::protocol::MAX_PROTOCOL_PREFIX_OFFSET,
                max_candidates: self.protocol_max_candidates,
                max_retained_frames: l2_workbench::protocol::MAX_PROTOCOL_RETAINED_FRAMES,
                max_report_bytes: self.protocol_max_report_bytes,
            },
            search: SearchLimits {
                max_input_bytes: self.search_max_input_bytes,
                max_output_bytes: self.search_max_output_bytes,
                max_intermediate_bytes: self.search_max_intermediate_bytes,
                max_work_bytes: self.search_max_work_bytes,
                max_key_tests: self.search_max_key_tests,
                max_recipe_parameter_bytes: self.search_max_recipe_parameter_bytes,
            },
            max_result_rows: self.workflow_max_result_rows,
        }
    }
}
