use super::WorkbenchCommand;
use clap::{Args, Subcommand, ValueEnum};
use l2_audit::{AssessmentProfile, SourceLabelMap, SourceLabelMapError};
use l2_capture::InterfaceId;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};

pub use l2_audit::MAX_SOURCE_LABEL_BYTES;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    Html,
}

// Presentation choices never alter assessment or evidence state
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ColorChoice {
    #[default]
    Auto,
    Always,
    Never,
}

/// The operator-selected condition that completes a bounded live receive run
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveLimit {
    Packets(u32),
    Duration(Duration),
}

#[cfg(feature = "live")]
impl LiveLimit {
    const DEFAULT_PACKETS: u32 = 10_000;
    const DEFAULT_DURATION: Duration = Duration::from_secs(30);

    #[must_use]
    pub const fn packet_ceiling(self) -> u32 {
        match self {
            Self::Packets(packets) => packets,
            Self::Duration(_) => Self::DEFAULT_PACKETS,
        }
    }

    #[must_use]
    pub const fn duration_ceiling(self) -> Duration {
        match self {
            Self::Packets(_) => Self::DEFAULT_DURATION,
            Self::Duration(duration) => duration,
        }
    }

    #[must_use]
    pub const fn duration_is_goal(self) -> bool {
        matches!(self, Self::Duration(_))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SurveyInput {
    File(PathBuf),
    Live { interface: String, limit: LiveLimit },
}

// Report controls remain shared by wired and wireless assessment
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReportOptions {
    pub output: Option<PathBuf>,
    pub color: ColorChoice,
    pub verbosity: u8,
    pub evidence: bool,
    pub fail_on_findings: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SurveyOptions {
    pub input: SurveyInput,
    pub policy: Option<PathBuf>,
    pub sources: Vec<SourceMapping>,
    pub source_label: Option<String>,
    pub format: OutputFormat,
    pub profile: AssessmentProfile,
    pub report: ReportOptions,
}

/// Presentation identity for one assessment input
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisplaySource {
    pub label: String,
    pub interface: Option<String>,
}

impl SurveyOptions {
    /// Return the operator label separately from the kernel interface name
    #[must_use]
    pub fn display_source(&self) -> DisplaySource {
        match &self.input {
            SurveyInput::File(path) => DisplaySource {
                label: path.to_string_lossy().into_owned(),
                interface: None,
            },
            SurveyInput::Live { interface, .. } => DisplaySource {
                label: self.live_source_label().to_owned(),
                interface: Some(interface.clone()),
            },
        }
    }

    /// Build the checked capture-local to operator-label mapping
    ///
    /// # Errors
    /// Returns an error for duplicate, excessive, or unsafe labels
    pub fn source_labels(&self) -> Result<SourceLabelMap, SourceLabelMapError> {
        let entries = self.sources.iter().map(|mapping| {
            (
                InterfaceId {
                    section: mapping.section,
                    index: mapping.index,
                },
                mapping.label.clone(),
            )
        });
        if self.sources.is_empty() && matches!(self.input, SurveyInput::Live { .. }) {
            return SourceLabelMap::new([(
                InterfaceId {
                    section: 0,
                    index: 0,
                },
                self.live_source_label().to_owned(),
            )]);
        }
        SourceLabelMap::new(entries)
    }

    fn live_source_label(&self) -> &str {
        self.source_label
            .as_deref()
            .or_else(|| {
                self.sources
                    .iter()
                    .find(|mapping| mapping.section == 0 && mapping.index == 0)
                    .map(|mapping| mapping.label.as_str())
            })
            .unwrap_or("live")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WifiOptions {
    pub input: SurveyInput,
    pub policy: Option<PathBuf>,
    pub format: OutputFormat,
    pub report: ReportOptions,
}

/// Explicit packet selections and byte ranges for one offline comparison
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureCompareOptions {
    pub capture: PathBuf,
    pub left_packet: u32,
    pub right_packet: u32,
    pub left_offset: usize,
    pub right_offset: usize,
    pub length: Option<usize>,
    pub xor_key: Option<Vec<u8>>,
    pub format: OutputFormat,
}

/// A directional TCP payload range within an explicit capture-record window
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureTcpOptions {
    pub capture: PathBuf,
    pub packet: u32,
    pub last_packet: Option<u32>,
    pub sequence: Option<u32>,
    pub length: usize,
    pub format: OutputFormat,
}

/// Operator-defined stable label for one capture-local source interface
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceMapping {
    pub section: u32,
    pub index: u32,
    pub label: String,
}

/// Return whether a stable source label is bounded, printable, and path-neutral
#[must_use]
pub fn valid_source_label(label: &str) -> bool {
    l2_audit::valid_source_label(label)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DevDecodeCommand {
    Ethernet { hex: String },
    Radiotap { capture: PathBuf },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DevCommand {
    Catalog,
    Planner {
        report: PathBuf,
    },
    Decode(DevDecodeCommand),
    PcapNgBlocks {
        capture: PathBuf,
    },
    PolicyDump {
        policy: PathBuf,
    },
    CanaryInspect {
        capture: PathBuf,
    },
    HelperDecode {
        capture: PathBuf,
    },
    ReportRender {
        report: PathBuf,
    },
    #[cfg(feature = "dev-fixtures")]
    FixtureInspect {
        name: String,
    },
    Limits,
}

/// Recover files and other complete byte objects from one capture
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportOptions {
    pub capture: PathBuf,
    pub output: Option<PathBuf>,
    /// Require optional `TShark` enrichment to finish before reporting success
    pub require_tshark: bool,
    pub recovery: RecoveryOptions,
}

/// Recovery search effort, ordered from quickest to most thorough
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryProfile {
    Fast,
    #[default]
    Normal,
    Deep,
}

/// How progress is presented while recovery work is running
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum ProgressMode {
    #[default]
    Auto,
    Always,
    Never,
    Json,
}

/// Shared search, cache, reporting, and resource controls for recovery commands
#[derive(Clone, Debug, Args, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "recovery controls are independent CLI switches"
)]
pub struct RecoveryOptions {
    /// Select the search effort: fast, normal, or deep
    #[arg(long, value_enum, default_value = "normal")]
    pub profile: RecoveryProfile,
    /// Recompute and atomically replace owned output
    #[arg(long)]
    pub refresh: bool,
    /// Skip recovery cache reads and writes
    #[arg(long)]
    pub no_cache: bool,
    /// Verify cached content in full before reuse
    #[arg(long)]
    pub strict_cache: bool,
    /// Choose progress output: auto, always, never, or json
    #[arg(long, value_enum, default_value = "auto")]
    pub progress: ProgressMode,
    /// Limit the number of parallel workers; default chooses automatically
    #[arg(long, value_name = "COUNT", value_parser = super::value::nonzero_jobs)]
    pub jobs: Option<usize>,
    /// Hide routine recovery progress and status messages
    #[arg(long)]
    pub quiet: bool,
    /// Increase diagnostic detail; repeat for more detail
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbosity: u8,
    /// Set the recovery memory limit using bytes, KB/MB/GB/TB, or KiB/MiB/GiB/TiB
    #[arg(
        long,
        value_name = "SIZE",
        default_value = "512MiB",
        value_parser = super::value::parse_byte_size
    )]
    pub memory_limit: u64,
    /// Set the aggregate byte limit for refinement source and manifest reads
    #[arg(skip = 4_u64 * 1024 * 1024 * 1024)]
    pub source_read_limit: u64,
    /// Set the maximum retained cache size using bytes, KB/MB/GB/TB, or KiB/MiB/GiB/TiB
    #[arg(
        long,
        value_name = "SIZE",
        default_value = "2GiB",
        value_parser = super::value::parse_byte_size
    )]
    pub cache_max_bytes: u64,
}

impl Default for RecoveryOptions {
    fn default() -> Self {
        Self {
            profile: RecoveryProfile::Normal,
            refresh: false,
            no_cache: false,
            strict_cache: false,
            progress: ProgressMode::Auto,
            jobs: None,
            quiet: false,
            verbosity: 0,
            memory_limit: 512 * 1024 * 1024,
            source_read_limit: 4 * 1024 * 1024 * 1024,
            cache_max_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

/// File refinement options and its shared recovery policy
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefineOptions {
    pub input: PathBuf,
    pub output: Option<PathBuf>,
    pub dry_run: bool,
    pub salvage: bool,
    pub recovery: RecoveryOptions,
}

/// Requested operation on the on-disk recovery cache
#[derive(Clone, Debug, PartialEq, Eq, Subcommand)]
pub enum CacheCommand {
    /// Show current cache size and entry counts
    Stats,
    /// Remove old cache entries until the selected size is reached
    Prune {
        /// Target cache size, such as 512MiB
        #[arg(long, value_name = "SIZE", value_parser = super::value::parse_byte_size)]
        max_bytes: Option<u64>,
    },
    /// Remove all retained recovery cache entries
    Clear,
}

/// Supported shell formats for generated command completions
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum CompletionShell {
    Bash,
    Zsh,
    Fish,
}

// Compatibility forms are normalized into this one command model
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Export(ExportOptions),
    Refine(RefineOptions),
    Cache(CacheCommand),
    Completions(CompletionShell),
    Inspect(PathBuf),
    Relationships(PathBuf),
    Json(PathBuf),
    Observe(PathBuf),
    Wifi(WifiOptions),
    Interfaces,
    Listen {
        interface: String,
        limit: LiveLimit,
    },
    Record {
        interface: String,
        limit: LiveLimit,
        output: PathBuf,
    },
    CaptureCompare(CaptureCompareOptions),
    CaptureTcp(CaptureTcpOptions),
    Workbench(WorkbenchCommand),
    Assess(SurveyOptions),
    BaselineCreate {
        capture: PathBuf,
        output: PathBuf,
        sources: Vec<SourceMapping>,
    },
    BaselineCompare {
        baseline: PathBuf,
        capture: PathBuf,
        fail_on_change: bool,
        sources: Vec<SourceMapping>,
    },
    PolicyValidate {
        policy: PathBuf,
    },
    Dev(DevCommand),
}
