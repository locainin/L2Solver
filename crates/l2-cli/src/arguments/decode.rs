use clap::Args;
use l2_workbench::derivation::{
    DEFAULT_MAX_WORK_BYTES, DerivationLimits, MAX_CONSTRAINTS, MAX_INPUT_BYTES,
    MAX_INTERMEDIATE_BYTES, MAX_OUTPUT_BYTES, MAX_RECIPE_PARAMETER_BYTES, MAX_STEPS,
};
use std::{num::NonZeroUsize, path::PathBuf};

/// Default maximum number of selected inputs in one decode command
pub const DEFAULT_MAX_DECODE_ITEMS: usize = 64;
/// Default aggregate input bytes across selected decode nodes
pub const DEFAULT_MAX_DECODE_INPUT_BYTES: usize = 16 * 1024 * 1024;
/// Default aggregate derivation work across selected decode nodes
pub const DEFAULT_MAX_DECODE_WORK_BYTES: usize = DEFAULT_MAX_WORK_BYTES * 4;
/// Default aggregate output bytes across selected decode nodes
pub const DEFAULT_MAX_DECODE_OUTPUT_BYTES: usize = MAX_OUTPUT_BYTES * 16;
/// Default aggregate serialized receipt bytes across selected decode nodes
pub const DEFAULT_MAX_DECODE_REPORT_BYTES: usize = 4 * 1024 * 1024;

/// Explicit derivation recipe and runtime budget options
#[derive(Clone, Debug, PartialEq, Eq, Args)]
pub struct DecodeArgs {
    /// Evidence case containing the selected byte node
    #[arg(value_name = "CASE", allow_hyphen_values = true)]
    pub case: PathBuf,
    /// Retained byte node supplied to the recipe; repeat to decode several nodes
    #[arg(long = "node", required = true, value_parser = clap::value_parser!(u64).range(1..))]
    pub nodes: Vec<u64>,
    /// JSON derivation recipe
    #[arg(long)]
    pub recipe: PathBuf,
    /// Maximum recipe document bytes read before parsing
    #[arg(long, default_value = "65536")]
    pub max_recipe_bytes: NonZeroUsize,
    /// Maximum selected input bytes
    #[arg(long, default_value = MAX_INPUT_BYTES.to_string())]
    pub max_input_bytes: NonZeroUsize,
    /// Maximum bytes emitted by one operation
    #[arg(long, default_value = MAX_OUTPUT_BYTES.to_string())]
    pub max_output_bytes: NonZeroUsize,
    /// Maximum cumulative successful intermediate bytes
    #[arg(long, default_value = MAX_INTERMEDIATE_BYTES.to_string())]
    pub max_intermediate_bytes: NonZeroUsize,
    /// Maximum cumulative bytes charged as transformation work
    #[arg(long, default_value = DEFAULT_MAX_WORK_BYTES.to_string())]
    pub max_work_bytes: NonZeroUsize,
    /// Maximum recipe operations
    #[arg(long, default_value = MAX_STEPS.to_string())]
    pub max_steps: NonZeroUsize,
    /// Maximum explicit output checks
    #[arg(long, default_value = MAX_CONSTRAINTS.to_string())]
    pub max_constraints: NonZeroUsize,
    /// Maximum variable-length recipe parameter bytes
    #[arg(long, default_value = MAX_RECIPE_PARAMETER_BYTES.to_string())]
    pub max_recipe_parameter_bytes: NonZeroUsize,
    /// Maximum selected input nodes processed by one command
    #[arg(long, default_value = DEFAULT_MAX_DECODE_ITEMS.to_string())]
    pub max_items: NonZeroUsize,
    /// Maximum selected input bytes across the complete command
    #[arg(long, default_value = DEFAULT_MAX_DECODE_INPUT_BYTES.to_string())]
    pub max_total_input_bytes: NonZeroUsize,
    /// Maximum transformation work across the complete command
    #[arg(long, default_value = DEFAULT_MAX_DECODE_WORK_BYTES.to_string())]
    pub max_total_work_bytes: NonZeroUsize,
    /// Maximum retained output bytes across the complete command
    #[arg(long, default_value = DEFAULT_MAX_DECODE_OUTPUT_BYTES.to_string())]
    pub max_total_output_bytes: NonZeroUsize,
    /// Maximum serialized receipt bytes across the complete command
    #[arg(long, default_value = DEFAULT_MAX_DECODE_REPORT_BYTES.to_string())]
    pub max_total_report_bytes: NonZeroUsize,
    /// Write the updated case atomically to this path
    #[arg(long, value_name = "NEW_CASE")]
    pub output: Option<PathBuf>,
}

impl DecodeArgs {
    /// Build the exact runtime budgets retained in the derivation receipt
    #[must_use]
    pub const fn limits(&self) -> DerivationLimits {
        DerivationLimits {
            max_input_bytes: self.max_input_bytes.get(),
            max_output_bytes: self.max_output_bytes.get(),
            max_intermediate_bytes: self.max_intermediate_bytes.get(),
            max_work_bytes: self.max_work_bytes.get(),
            max_steps: self.max_steps.get(),
            max_constraints: self.max_constraints.get(),
            max_recipe_parameter_bytes: self.max_recipe_parameter_bytes.get(),
        }
    }
}
