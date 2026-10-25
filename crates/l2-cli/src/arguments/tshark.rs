use clap::Args;
use std::path::PathBuf;

/// Offline `TShark` enrichment budgets and explicit key-log input
#[derive(Clone, Debug, PartialEq, Eq, Args)]
pub struct TsharkOptions {
    /// Capture file to read without opening a capture interface
    #[arg(value_name = "CAPTURE", allow_hyphen_values = true)]
    pub capture: PathBuf,
    /// `TShark` executable, resolved through `PATH` when it is not a path
    #[arg(long, default_value = "tshark", value_name = "PROGRAM")]
    pub executable: PathBuf,
    /// Explicit TLS key-log file for decryption
    #[arg(long, value_name = "KEYLOG")]
    pub tls_keylog: Option<PathBuf>,
    /// Write the enrichment receipt to a new file
    #[arg(long, value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// Shared subprocess time budget in seconds (default 120; operational deadline across phases)
    #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u32).range(1..))]
    pub timeout_seconds: u32,
    /// Maximum combined capture and key-log snapshot size in MiB (default 256; increase for larger captures)
    #[arg(long, default_value_t = 256, value_parser = clap::value_parser!(u32).range(1..))]
    pub max_input_mib: u32,
    /// Maximum metadata stdout in MiB per phase (default 16; covers plugin and source-frame-count output)
    #[arg(long, default_value_t = 16, value_parser = clap::value_parser!(u32).range(1..))]
    pub max_metadata_mib: u32,
    /// Maximum JSON stdout in MiB (default 256 to bound memory; excess output fails, never truncates)
    #[arg(long, default_value_t = 256, value_parser = clap::value_parser!(u32).range(1..))]
    pub max_output_mib: u32,
    /// Maximum captured stderr in MiB per phase (default 1; increase for verbose plugin diagnostics)
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
    pub max_diagnostics_mib: u32,
}
