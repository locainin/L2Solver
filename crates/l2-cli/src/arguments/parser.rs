mod capture;

use super::{
    model::{
        CacheCommand, ColorChoice, Command, CompletionShell, DevCommand, DevDecodeCommand,
        ExportOptions, RecoveryOptions, RefineOptions, ReportOptions, SurveyInput, SurveyOptions,
        WifiOptions,
    },
    value,
};
use capture::CaptureCommand;
use clap::{ArgAction, Args, CommandFactory, Parser, Subcommand, error::ErrorKind};
use l2_audit::AssessmentProfile;
use std::{
    ffi::{OsStr, OsString},
    path::PathBuf,
    time::Duration,
};

const ROOT_HELP: &str = r"Examples:
  l2solver extract traffic.pcapng -o recovered/
  l2solver refine unknown.bin --dry-run
  l2solver cache stats
  l2solver completions bash
  l2solver inspect traffic.pcapng
  l2solver workbench --help

Exit status:
  0  Command completed within its declared scope
  1  Runtime, I/O, or internal failure
  2  Usage error
  3  Assessment, collection, export, or workbench result is incomplete
  4  Findings found with --fail-on-findings/--ci, or baseline changes with --fail-on-change";

const DEV_HELP: &str =
    "Developer:\n  l2solver dev --help       Internal diagnostics and fixture tooling";

const EXTRACT_HELP: &str = r"The default is CAPTURE.export. Matching owned output is reused. --refresh atomically replaces owned output, even when its previous input differs. Unrelated destinations are refused. Standard input requires --output and skips TShark.

Progress defaults to automatic terminal detection. --refresh recomputes results, --no-cache skips reads and writes, and --strict-cache checks cached content in full.

TShark enrichment is optional. If TShark is missing or object export fails, available artifacts are still published. --require-tshark requires successful enrichment. Incomplete native analysis or a required TShark failure returns status 3. Packets outside discovery scope are reported without failing extraction. summary.txt shows native and TShark status separately.

Examples:
  l2solver extract traffic.pcapng -o recovered/
  l2solver extract traffic.pcapng --profile deep --progress json
  l2solver extract traffic.pcapng --strict-cache --memory-limit 1GiB";

#[derive(Debug, Parser)]
#[command(
    name = "l2solver",
    version,
    about = "Network forensics and artifact recovery",
    long_about = None,
    after_help = ROOT_HELP,
    after_long_help = format!("{ROOT_HELP}\n\n{DEV_HELP}"),
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: TopCommand,
}

#[derive(Debug, Subcommand)]
enum TopCommand {
    /// Recover artifacts from a PCAP/PCAPNG capture
    #[command(
        arg_required_else_help = true,
        alias = "export",
        display_order = 0,
        long_about = "Recover complete native HTTP bodies and FTP transfer candidates. Recursively validated archive members are published with their parent archives. TShark on PATH adds objects with safe generated names. TShark objects do not include packet provenance; native provenance is retained in the export reports.",
        after_help = EXTRACT_HELP
    )]
    Extract(ExportArgs),
    /// Refine an ordinary file or export directory without requiring a capture
    #[command(
        long_about = "Analyze an ordinary file or export directory, including .bin files, without requiring a PCAP or PCAPNG input. Refinement writes immutable artifacts, a manifest, and a summary into a result directory. Small inputs may be retained; larger inputs stay in place while bounded PNG and ZIP ranges may be published with partial coverage. By default the directory is INPUT.refined; use --output to select another directory. Use --dry-run to report planned work without writing a result. --salvage enables recovery of supported partial archive members; it does not repair arbitrary damaged files. An existing matching owned result is reused. On reuse, --strict-cache verifies complete source and output bytes. --refresh recomputes and atomically replaces that owned result. Unrelated existing paths are refused. Shared search, progress, cache, worker, and memory controls are available through the recovery options."
    )]
    Refine(RefineArgs),
    /// Inspect or manage persistent recovery results
    Cache {
        #[command(subcommand)]
        command: CacheCommand,
    },
    /// Generate shell completion scripts
    Completions {
        #[arg(value_enum, value_name = "SHELL")]
        shell: CompletionShell,
    },
    /// Decode captured frames and inspect protocol details
    Inspect(CapturePath),
    /// Show MAC/IP, ARP, DNS, and transport relationships in one capture
    Relationships(CapturePath),
    /// Assess an offline capture or a bounded live interface
    #[command(
        long_about = "Assess an offline capture or a bounded live interface.\n\nPass CAPTURE to read a capture file, or use --interface to capture from a live interface. These input modes are mutually exclusive. Live capture requires exactly one limit: --duration (1s to 5m) or --packets (1 to 10000).\n\nLive capture is an optional build feature. Enable it with `cargo build -p l2-cli --features live`.\n\nReports go to standard output by default. Use --format to choose text, JSON, or HTML. Use --output FILE to write the report to a file instead."
    )]
    Assess(AssessmentArgs),
    /// Create or compare a typed observation baseline
    Baseline {
        #[command(subcommand)]
        command: BaselineCommand,
    },
    /// Inspect, observe, export, or record capture data
    Capture {
        #[command(subcommand)]
        command: CaptureCommand,
    },
    /// Reconstruct traffic, recover artifacts, and test explicit byte hypotheses
    Workbench {
        #[command(subcommand)]
        command: crate::arguments::WorkbenchCommand,
    },
    /// Assess raw IEEE 802.11 or radiotap evidence
    Wifi {
        #[command(subcommand)]
        command: WifiCommand,
    },
    /// List interfaces and their capture capabilities
    Interfaces,
    /// Validate assessment policy files
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    #[command(hide = true)]
    Dev {
        #[command(subcommand)]
        command: RawDevCommand,
    },
    // Compatibility names remain parseable for one release but stay out of help
    #[command(hide = true)]
    Survey(AssessmentArgs),
    #[command(hide = true)]
    Observe(CapturePath),
    #[command(hide = true)]
    Json(CapturePath),
    #[command(hide = true)]
    Listen(LegacyLiveArgs),
    #[command(hide = true, name = "wifi-listen")]
    WifiListen(LegacyLiveArgs),
    #[command(hide = true)]
    Record(LegacyRecordArgs),
}

#[derive(Debug, Args)]
struct CapturePath {
    /// Capture file to read
    #[arg(value_name = "CAPTURE", allow_hyphen_values = true)]
    capture: PathBuf,
}

#[derive(Debug, Args)]
struct ExportArgs {
    #[arg(value_name = "CAPTURE", allow_hyphen_values = true)]
    capture: PathBuf,
    /// Write to DIRECTORY instead of CAPTURE.export; reuse matching owned results
    #[arg(short, long, value_name = "DIRECTORY")]
    output: Option<PathBuf>,
    /// Return status 3 if `TShark` enrichment is missing, skipped, or incomplete
    #[arg(long)]
    require_tshark: bool,
    #[command(flatten)]
    recovery: RecoveryOptions,
}

#[derive(Debug, Args)]
struct RefineArgs {
    /// Input file or export directory to refine
    #[arg(value_name = "INPUT", allow_hyphen_values = true)]
    input: PathBuf,
    /// Write the refined result to this directory instead of INPUT.refined
    #[arg(short, long, value_name = "DIRECTORY")]
    output: Option<PathBuf>,
    /// Show planned work without writing a result
    #[arg(long)]
    dry_run: bool,
    /// Recover supported partial archive members
    #[arg(long)]
    salvage: bool,
    #[command(flatten)]
    recovery: RecoveryOptions,
}

#[derive(Debug, Args)]
struct AssessmentArgs {
    /// Offline capture to assess; use --interface for live capture
    #[arg(
        value_name = "CAPTURE",
        conflicts_with = "interface",
        allow_hyphen_values = true
    )]
    capture: Option<PathBuf>,
    /// Capture from this live interface instead of reading CAPTURE
    #[arg(
        short = 'i',
        long,
        value_name = "INTERFACE",
        conflicts_with = "capture"
    )]
    interface: Option<String>,
    /// Stop live capture after 1s to 5m (requires --interface)
    #[arg(long, value_parser = value::duration, requires = "interface", conflicts_with = "packets")]
    duration: Option<Duration>,
    /// Stop live capture after 1 to 10000 packets (requires --interface)
    #[arg(long, value_parser = value::packets, requires = "interface", conflicts_with = "duration")]
    packets: Option<u32>,
    /// Read assessment policy from this JSON file
    #[arg(long, value_name = "POLICY")]
    policy: Option<PathBuf>,
    /// Bind a live interface to a stable operator source label
    #[arg(
        long = "source-label",
        value_name = "LABEL",
        value_parser = value::source_label,
        requires = "interface",
        conflicts_with_all = ["capture", "sources"]
    )]
    source_label: Option<String>,
    /// Map a capture-local interface to a stable operator source label
    #[arg(
        long = "source",
        value_name = "SECTION:INDEX=LABEL",
        value_parser = value::source_mapping
    )]
    sources: Vec<super::model::SourceMapping>,
    /// Choose the assessment coverage profile
    #[arg(long, default_value = "opportunistic", value_parser = value::profile)]
    profile: AssessmentProfile,
    #[command(flatten)]
    report: RawReportOptions,
}

#[derive(Clone, Debug, Args)]
struct RawReportOptions {
    /// Choose text, JSON, or HTML report output
    #[arg(long, default_value = "text", value_parser = value::output_format)]
    format: super::model::OutputFormat,
    /// Write the report to FILE instead of standard output
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Set text report color: auto, always, or never
    #[arg(long, default_value = "auto", value_parser = value::color)]
    color: ColorChoice,
    /// Increase report detail; repeat for more detail
    #[arg(short = 'v', action = ArgAction::Count)]
    verbosity: u8,
    /// Include packet references and the evidence index in text reports
    #[arg(long)]
    evidence: bool,
    /// Exit with status 4 when the assessment has confirmed findings
    #[arg(long, alias = "ci")]
    fail_on_findings: bool,
}

impl RawReportOptions {
    fn finish(self) -> ReportOptions {
        ReportOptions {
            output: self.output,
            color: self.color,
            verbosity: self.verbosity,
            evidence: self.evidence,
            fail_on_findings: self.fail_on_findings,
        }
    }
}

#[derive(Debug, Subcommand)]
enum BaselineCommand {
    /// Create a baseline only from complete authoritative observations
    Create {
        #[arg(value_name = "CAPTURE")]
        capture: PathBuf,
        #[arg(value_name = "OUTPUT")]
        output: PathBuf,
        /// Bind a capture-local interface to a stable operator label
        #[arg(long = "source", value_name = "SECTION:INDEX=LABEL", value_parser = value::source_mapping)]
        sources: Vec<super::model::SourceMapping>,
    },
    /// Compare retained observations with a prior baseline
    Compare {
        #[arg(value_name = "BASELINE")]
        baseline: PathBuf,
        #[arg(value_name = "CAPTURE")]
        capture: PathBuf,
        #[arg(long)]
        fail_on_change: bool,
        /// Bind a capture-local interface to the same stable label used at creation
        #[arg(long = "source", value_name = "SECTION:INDEX=LABEL", value_parser = value::source_mapping)]
        sources: Vec<super::model::SourceMapping>,
    },
}

#[derive(Debug, Subcommand)]
enum WifiCommand {
    /// Assess an offline wireless capture or bounded monitor interface
    Assess(WifiAssessmentArgs),
}

#[derive(Debug, Args)]
struct WifiAssessmentArgs {
    #[arg(
        value_name = "CAPTURE",
        conflicts_with = "interface",
        allow_hyphen_values = true
    )]
    capture: Option<PathBuf>,
    #[arg(
        short = 'i',
        long,
        value_name = "INTERFACE",
        conflicts_with = "capture"
    )]
    interface: Option<String>,
    #[arg(long, value_parser = value::duration, requires = "interface", conflicts_with = "packets")]
    duration: Option<Duration>,
    #[arg(long, value_parser = value::packets, requires = "interface", conflicts_with = "duration")]
    packets: Option<u32>,
    #[arg(long, value_name = "POLICY")]
    policy: Option<PathBuf>,
    #[command(flatten)]
    report: RawReportOptions,
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// Parse, bound, and validate a policy without running an assessment
    Validate {
        #[arg(value_name = "POLICY")]
        policy: PathBuf,
    },
}

#[derive(Debug, Args)]
struct LegacyLiveArgs {
    interface: String,
    #[arg(value_parser = legacy_limit)]
    limit: super::model::LiveLimit,
}

#[derive(Debug, Args)]
struct LegacyRecordArgs {
    interface: String,
    #[arg(value_parser = legacy_limit)]
    limit: super::model::LiveLimit,
    output: PathBuf,
}

fn legacy_limit(value: &str) -> Result<super::model::LiveLimit, String> {
    if value.ends_with('s') || value.ends_with('m') {
        value::duration(value).map(super::model::LiveLimit::Duration)
    } else {
        value::packets(value).map(super::model::LiveLimit::Packets)
    }
}

#[derive(Debug, Subcommand)]
enum RawDevCommand {
    Catalog,
    Planner {
        report: PathBuf,
    },
    Decode {
        #[command(subcommand)]
        command: RawDecodeCommand,
    },
    Pcapng {
        #[command(subcommand)]
        command: PcapNgCommand,
    },
    Policy {
        #[command(subcommand)]
        command: DevPolicyCommand,
    },
    Canary {
        #[command(subcommand)]
        command: CanaryCommand,
    },
    Helper {
        #[command(subcommand)]
        command: HelperCommand,
    },
    Report {
        #[command(subcommand)]
        command: ReportCommand,
    },
    #[cfg(feature = "dev-fixtures")]
    Fixture {
        #[command(subcommand)]
        command: FixtureCommand,
    },
    Limits,
}

#[derive(Debug, Subcommand)]
enum RawDecodeCommand {
    Ethernet { hex: String },
    Radiotap { capture: PathBuf },
}

#[derive(Debug, Subcommand)]
enum PcapNgCommand {
    Blocks { capture: PathBuf },
}

#[derive(Debug, Subcommand)]
enum DevPolicyCommand {
    Dump { policy: PathBuf },
}

#[derive(Debug, Subcommand)]
enum CanaryCommand {
    Inspect { capture: PathBuf },
}

#[derive(Debug, Subcommand)]
enum HelperCommand {
    Decode { capture: PathBuf },
}

#[derive(Debug, Subcommand)]
enum ReportCommand {
    Render { report: PathBuf },
}

#[cfg(feature = "dev-fixtures")]
#[derive(Debug, Subcommand)]
enum FixtureCommand {
    Inspect { name: String },
}

/// Parse command arguments supplied without the executable name
///
/// # Errors
/// Returns clap's structured usage error when the arguments do not match the
/// bounded command grammar
pub fn parse(arguments: &[OsString]) -> Result<Command, clap::Error> {
    let mut with_program = Vec::with_capacity(arguments.len().saturating_add(1));
    with_program.push(OsString::from("l2solver"));
    with_program.extend_from_slice(arguments);
    parse_from(with_program)
}

/// Parse a complete process argument vector including the executable name
///
/// # Errors
/// Returns clap's structured usage error when the arguments do not match the
/// bounded command grammar
pub fn parse_from<I, T>(arguments: I) -> Result<Command, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let mut arguments: Vec<OsString> = arguments.into_iter().map(Into::into).collect();
    normalize_legacy_wifi(&mut arguments);
    Cli::try_parse_from(arguments)?.command.finish()
}

fn normalize_legacy_wifi(arguments: &mut Vec<OsString>) {
    let Some(command) = arguments.get(1) else {
        return;
    };
    let Some(operand) = arguments.get(2) else {
        return;
    };
    let control_word = ["assess", "help", "-h", "--help"]
        .iter()
        .any(|value| operand == OsStr::new(value));
    if command == OsStr::new("wifi") && !control_word {
        arguments.insert(2, OsString::from("assess"));
    }
}

#[must_use]
pub fn command() -> clap::Command {
    Cli::command()
}

impl TopCommand {
    fn finish(self) -> Result<Command, clap::Error> {
        match self {
            Self::Extract(arguments) => Ok(Command::Export(ExportOptions {
                capture: arguments.capture,
                output: arguments.output,
                require_tshark: arguments.require_tshark,
                recovery: arguments.recovery,
            })),
            Self::Refine(arguments) => Ok(Command::Refine(RefineOptions {
                input: arguments.input,
                output: arguments.output,
                dry_run: arguments.dry_run,
                salvage: arguments.salvage,
                recovery: arguments.recovery,
            })),
            Self::Cache { command } => Ok(Command::Cache(command)),
            Self::Completions { shell } => Ok(Command::Completions(shell)),
            Self::Assess(arguments) | Self::Survey(arguments) => {
                arguments.finish().map(Command::Assess)
            }
            Self::Baseline { command } => Ok(command.finish()),
            Self::Capture { command } => command.finish(),
            Self::Workbench { command } => Ok(Command::Workbench(command)),
            Self::Wifi { command } => command.finish(),
            Self::Interfaces => Ok(Command::Interfaces),
            Self::Policy { command } => Ok(command.finish()),
            Self::Dev { command } => Ok(Command::Dev(command.finish())),
            Self::Inspect(path) => Ok(Command::Inspect(path.capture)),
            Self::Relationships(path) => Ok(Command::Relationships(path.capture)),
            Self::Observe(path) => Ok(Command::Observe(path.capture)),
            Self::Json(path) => Ok(Command::Json(path.capture)),
            Self::Listen(arguments) => Ok(Command::Listen {
                interface: arguments.interface,
                limit: arguments.limit,
            }),
            Self::WifiListen(arguments) => Ok(Command::Wifi(WifiOptions {
                input: SurveyInput::Live {
                    interface: arguments.interface,
                    limit: arguments.limit,
                },
                policy: None,
                format: super::model::OutputFormat::Text,
                report: ReportOptions::default(),
            })),
            Self::Record(arguments) => Ok(Command::Record {
                interface: arguments.interface,
                limit: arguments.limit,
                output: arguments.output,
            }),
        }
    }
}

impl AssessmentArgs {
    fn finish(self) -> Result<SurveyOptions, clap::Error> {
        let input = input(self.capture, self.interface, self.duration, self.packets)?;
        let format = self.report.format;
        Ok(SurveyOptions {
            input,
            policy: self.policy,
            sources: self.sources,
            source_label: self.source_label,
            format,
            profile: self.profile,
            report: self.report.finish(),
        })
    }
}

impl WifiAssessmentArgs {
    fn finish(self) -> Result<WifiOptions, clap::Error> {
        let input = input(self.capture, self.interface, self.duration, self.packets)?;
        let format = self.report.format;
        Ok(WifiOptions {
            input,
            policy: self.policy,
            format,
            report: self.report.finish(),
        })
    }
}

fn input(
    capture: Option<PathBuf>,
    interface: Option<String>,
    duration: Option<Duration>,
    packets: Option<u32>,
) -> Result<SurveyInput, clap::Error> {
    // A file source cannot consume limits intended for a live interface
    if capture.is_some() && (duration.is_some() || packets.is_some()) {
        return Err(usage_error("live limits require --interface"));
    }
    match (capture, interface) {
        (Some(capture), None) => Ok(SurveyInput::File(capture)),
        (None, Some(interface)) => value::limit(duration, packets)
            .map(|limit| SurveyInput::Live { interface, limit })
            .map_err(usage_error),
        (None, None) => Err(usage_error("CAPTURE or --interface is required")),
        (Some(_), Some(_)) => Err(usage_error(
            "CAPTURE and --interface are mutually exclusive",
        )),
    }
}

impl BaselineCommand {
    fn finish(self) -> Command {
        match self {
            Self::Create {
                capture,
                output,
                sources,
            } => Command::BaselineCreate {
                capture,
                output,
                sources,
            },
            Self::Compare {
                baseline,
                capture,
                fail_on_change,
                sources,
            } => Command::BaselineCompare {
                baseline,
                capture,
                fail_on_change,
                sources,
            },
        }
    }
}

impl WifiCommand {
    fn finish(self) -> Result<Command, clap::Error> {
        match self {
            Self::Assess(arguments) => arguments.finish().map(Command::Wifi),
        }
    }
}

impl PolicyCommand {
    fn finish(self) -> Command {
        match self {
            Self::Validate { policy } => Command::PolicyValidate { policy },
        }
    }
}

impl RawDevCommand {
    fn finish(self) -> DevCommand {
        match self {
            Self::Catalog => DevCommand::Catalog,
            Self::Planner { report } => DevCommand::Planner { report },
            Self::Decode { command } => DevCommand::Decode(command.finish()),
            Self::Pcapng { command } => match command {
                PcapNgCommand::Blocks { capture } => DevCommand::PcapNgBlocks { capture },
            },
            Self::Policy { command } => match command {
                DevPolicyCommand::Dump { policy } => DevCommand::PolicyDump { policy },
            },
            Self::Canary { command } => match command {
                CanaryCommand::Inspect { capture } => DevCommand::CanaryInspect { capture },
            },
            Self::Helper { command } => match command {
                HelperCommand::Decode { capture } => DevCommand::HelperDecode { capture },
            },
            Self::Report { command } => match command {
                ReportCommand::Render { report } => DevCommand::ReportRender { report },
            },
            #[cfg(feature = "dev-fixtures")]
            Self::Fixture { command } => match command {
                FixtureCommand::Inspect { name } => DevCommand::FixtureInspect { name },
            },
            Self::Limits => DevCommand::Limits,
        }
    }
}

impl RawDecodeCommand {
    fn finish(self) -> DevDecodeCommand {
        match self {
            Self::Ethernet { hex } => DevDecodeCommand::Ethernet { hex },
            Self::Radiotap { capture } => DevDecodeCommand::Radiotap { capture },
        }
    }
}

fn usage_error(message: &'static str) -> clap::Error {
    Cli::command().error(ErrorKind::MissingRequiredArgument, message)
}
