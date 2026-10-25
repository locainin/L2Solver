use super::{
    CarrierResultsArgs, CodeLinksArgs, ConcatenateArgs, CorrelationArgs, DecodeArgs, ExpandArgs,
    ImageReachabilityArgs, IndexedCommand, JournalArgs, MaterializeFramesArgs, OutputFormat,
    PatternReportLimits, ProtocolAnalysisArgs, ReconstructionArgs, RecordsArgs, ReviewArgs,
    TsharkOptions, value,
};
use clap::Subcommand;
use std::path::{Path, PathBuf};

/// Offline operations retain evidence and publish new results without replacing inputs
#[derive(Clone, Debug, PartialEq, Eq, Subcommand)]
pub enum WorkbenchCommand {
    /// Review hypotheses, tool evidence, carrier results and identity mappings together
    Review(ReviewArgs),
    /// Inspect identity and clock mappings against retained source events
    Correlate(CorrelationArgs),
    /// Retain, inspect and replay carrier candidates independently of report previews
    CarrierResults(CarrierResultsArgs),
    /// Enrich an offline capture using an explicitly selected optional `TShark` process
    Tshark(TsharkOptions),
    /// Link static functions to observed runtime addresses through an explicit module map
    CodeLinks {
        #[command(flatten)]
        args: CodeLinksArgs,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Keep hypotheses, check evidence and event chains in a durable investigation
    Journal(JournalArgs),
    /// Generate source-verified byte or transport-payload carrier selections
    CarrierPlan {
        case: PathBuf,
        #[arg(long = "node", required = true)]
        nodes: Vec<u64>,
        #[arg(long, default_value = "bytes", value_parser = ["bytes", "payload"])]
        view: String,
        #[arg(long = "source", required = true)]
        sources: Vec<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Enumerate explicit carrier hypotheses with held-out source receipts
    CarrierDiscover {
        case: PathBuf,
        #[arg(long = "node", required = true)]
        nodes: Vec<u64>,
        #[arg(long, default_value = "bytes", value_parser = ["bytes", "payload"])]
        view: String,
        #[arg(long)]
        plan: PathBuf,
        /// Reader allocation budget for the discovery plan JSON
        #[arg(long, default_value_t = 1_048_576)]
        max_plan_bytes: usize,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Extract explicit carriers and run reproducible compositions and decoding plans
    Carrier {
        #[arg(value_name = "PLAN_JSON")]
        plan: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Import native filesystem, event-log, or observed process I/O evidence
    Endpoint {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(long,value_parser=["usn","usn-device","mft","evtx","event-xml","strace"])]
        format: String,
        #[arg(long, value_name = "CAPTURE")]
        capture: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Retain captures once and index all packet/tuple relationships on disk
    Index {
        #[arg(required = true, value_name = "CAPTURE")]
        captures: Vec<PathBuf>,
        #[arg(long, value_name = "NEW_DIRECTORY")]
        directory: PathBuf,
        /// Choose a concise text summary naming the directory or the machine-readable JSON receipt
        #[arg(long, default_value = "text", value_parser = value::compare_format)]
        format: OutputFormat,
        #[arg(long,default_value_t=64,value_parser=clap::value_parser!(u32).range(1..))]
        cache_mib: u32,
    },
    /// Inspect a persistent index with bounded memory and streaming results
    Indexed {
        #[arg(value_name = "DIRECTORY")]
        directory: PathBuf,
        #[arg(long,default_value_t=64,value_parser=clap::value_parser!(u32).range(1..),global=true)]
        cache_mib: u32,
        #[arg(long, global = true)]
        output: Option<PathBuf>,
        #[command(subcommand)]
        operation: IndexedCommand,
    },
    /// Build one bounded persistent evidence case
    ///
    /// Input and reconstruction budgets retain a capture prefix; status 3 and case
    /// limitations identify omissions. Larger budgets do not remove evidence or
    /// application-analysis limits
    #[command(
        after_help = "For all original packets, use workbench index CAPTURE --directory NEW_DIRECTORY.\nFor analysis of every record in bounded windows, use workbench stream CAPTURE --directory NEW_DIRECTORY."
    )]
    Build {
        #[arg(value_name = "CAPTURE", allow_hyphen_values = true)]
        capture: PathBuf,
        #[command(flatten)]
        resources: ReconstructionArgs,
        #[arg(long, value_name = "NEW_CASE")]
        output: Option<PathBuf>,
    },
    /// Analyze the entire capture into bounded on-disk windows with original provenance
    Stream {
        #[arg(value_name = "CAPTURE")]
        capture: PathBuf,
        #[arg(long, value_name = "NEW_DIRECTORY")]
        directory: PathBuf,
        /// Choose a concise text summary naming the directory or the machine-readable JSON receipt
        #[arg(long, default_value = "text", value_parser = value::compare_format)]
        format: OutputFormat,
        #[arg(long, default_value_t = 512, value_parser = clap::value_parser!(u16).range(1..=768))]
        page_records: u16,
        #[arg(long, default_value_t = 128, value_parser = clap::value_parser!(u16).range(0..=128))]
        context_records: u16,
    },
    /// Import file bytes and exact string/address observations
    Import {
        #[arg(value_name = "CASE", allow_hyphen_values = true)]
        case: PathBuf,
        #[arg(value_name = "FILE", allow_hyphen_values = true)]
        file: PathBuf,
        #[arg(long, default_value = "file", value_parser = ["file", "config", "binary", "key"])]
        kind: String,
        /// Select whether optional literal and file-signature observations are recorded
        #[arg(long, default_value = "literal-signature", value_parser = ["none", "literal-signature"])]
        scan_mode: String,
        /// Maximum leading bytes examined by the optional scanner
        #[arg(long, default_value_t = l2_workbench::evidence::DEFAULT_IMPORT_SCAN_BYTES)]
        max_scan_bytes: usize,
        /// Maximum optional observations retained for this source
        #[arg(long, default_value_t = l2_workbench::evidence::MAX_IMPORT_FINDINGS)]
        max_findings: usize,
        /// Optional ceiling for total source bytes read and attached
        #[arg(long, value_name = "BYTES")]
        max_input_bytes: Option<std::num::NonZeroUsize>,
        #[arg(long, value_name = "NEW_CASE")]
        output: Option<PathBuf>,
    },
    /// Apply an explicit recipe and retain its derivation receipt
    Decode(DecodeArgs),
    /// Parse an explicit repeated-record layout and retain complete assembled objects
    Records(RecordsArgs),
    /// Concatenate retained byte nodes in an explicit order
    Concatenate(ConcatenateArgs),
    /// Recursively expand supported structured artifacts with byte-exact provenance
    Expand(ExpandArgs),
    /// Test PNG pixels against the complete JPEG BT.601 full-range fixed-point RGB set
    ImageReachability(ImageReachabilityArgs),
    /// Validate a saved case and inspect its evidence inventory
    Inspect {
        #[arg(value_name = "CASE", allow_hyphen_values = true)]
        case: PathBuf,
        #[arg(long, default_value = "text", value_parser = value::compare_format)]
        format: OutputFormat,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Verify one supported built-in receipt against its retained case claims
    VerifyReceipt {
        #[arg(value_name = "CASE", allow_hyphen_values = true)]
        case: PathBuf,
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        node: u64,
        /// Optional ceiling for the encoded case input
        #[arg(long, value_name = "BYTES")]
        max_input_bytes: Option<std::num::NonZeroUsize>,
        /// Optional ceiling for the selected receipt blob
        #[arg(long, value_name = "BYTES")]
        max_receipt_bytes: Option<std::num::NonZeroUsize>,
        /// Optional combined ceiling for entries in receipt lists
        #[arg(long, value_name = "COUNT")]
        max_list_entries: Option<std::num::NonZeroUsize>,
        #[arg(long, value_name = "REPORT_JSON")]
        output: Option<PathBuf>,
    },
    /// Extract exact retained bytes from one evidence node
    #[command(
        name = "extract-node",
        alias = "export",
        after_help = "Writes exact bytes to binary stdout unless --output selects a new file. Notices use stderr.\nRetained bytes are also written from an incomplete case, followed by exit status 3."
    )]
    ExtractNode {
        #[arg(value_name = "CASE", allow_hyphen_values = true)]
        case: PathBuf,
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        node: u64,
        /// Write to a new file without replacing an existing destination
        #[arg(long, value_name = "NEW_FILE")]
        output: Option<PathBuf>,
    },
    /// Materialize recovered artifacts already retained in a Case into a new directory
    ExtractAll {
        #[arg(value_name = "CASE", allow_hyphen_values = true)]
        case: PathBuf,
        #[arg(long, value_name = "NEW_DIRECTORY")]
        directory: PathBuf,
    },
    /// Select retained evidence with explicit key=value filters
    Query {
        #[arg(value_name = "CASE_OR_BUNDLE", allow_hyphen_values = true)]
        case: PathBuf,
        #[arg(long = "filter", value_name = "KEY=VALUE")]
        filters: Vec<String>,
        #[arg(long, default_value = "1024")]
        limit: std::num::NonZeroUsize,
        /// Memory budget for retained match records, adjustable for complete exports
        #[arg(long, default_value = "8388608")]
        max_report_bytes: std::num::NonZeroUsize,
        #[arg(long, default_value = "text", value_parser = value::output_format)]
        format: OutputFormat,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Report exact network behavior patterns without assigning actor identity
    Behavior {
        #[arg(value_name = "CASE_OR_BUNDLE", allow_hyphen_values = true)]
        case: PathBuf,
        #[arg(long, value_name = "CIDR")]
        internal: Vec<String>,
        #[arg(long, value_name = "TICKS")]
        large_gap_ticks: Option<u64>,
        #[command(flatten)]
        limits: PatternReportLimits,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Compare capture clocks and normalized endpoint time-change evidence
    Timestamps {
        #[arg(value_name = "CASE_OR_BUNDLE", allow_hyphen_values = true)]
        case: PathBuf,
        #[arg(long, value_name = "ENDPOINT_EVENTS_JSON")]
        events: Option<PathBuf>,
        #[arg(long, value_name = "TICKS")]
        large_gap_ticks: Option<u64>,
        #[command(flatten)]
        limits: PatternReportLimits,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Test framing and explicit request/response fields on ordered samples
    Protocol {
        #[arg(value_name = "CASE", allow_hyphen_values = true)]
        case: PathBuf,
        #[arg(long = "sample", required = true, value_name = "NODE:ROLE")]
        samples: Vec<String>,
        #[arg(long, value_name = "REQUEST_OFFSET:RESPONSE_OFFSET:WIDTH")]
        field: Option<String>,
        #[command(flatten)]
        analysis: ProtocolAnalysisArgs,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Materialize one explicitly selected framing rule as source-mapped frame nodes
    #[command(
        after_help = "Examples:\n  l2solver workbench materialize-frames CASE --node 12 --delimiter-byte 0x0a\n  l2solver workbench materialize-frames CASE --node 12 --fixed-size 256\n  l2solver workbench materialize-frames CASE --node 12 --length-prefix 0:2:big_endian:bytes_after_field\n\nUse --rule-json with a FramingKind copied from workbench protocol output."
    )]
    MaterializeFrames(MaterializeFramesArgs),
    /// Inspect file signatures, PE/ELF headers, or bounded read-only radare2 analysis
    Binary {
        #[arg(value_name = "FILE", allow_hyphen_values = true)]
        file: PathBuf,
        #[arg(long, default_value = "headers", value_parser = ["signatures", "headers", "r2"])]
        engine: String,
        /// Override the 16 MiB in-memory default for the signature engine
        #[arg(long, value_name = "BYTES")]
        max_input_bytes: Option<std::num::NonZeroUsize>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Search bounded decoding pipelines against explicit requirements
    Search {
        #[arg(value_name = "CASE", allow_hyphen_values = true)]
        case: PathBuf,
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        node: u64,
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Mutate bytes offline or through an owned loopback parser
    Experiment {
        #[arg(value_name = "CASE", allow_hyphen_values = true)]
        case: PathBuf,
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        node: u64,
        #[arg(long)]
        plan: PathBuf,
        #[arg(long, default_value = "offline", value_parser = ["offline", "loopback"])]
        mode: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

impl WorkbenchCommand {
    #[must_use]
    pub fn output(&self) -> Option<&Path> {
        match self {
            Self::Tshark(options) => options.output.as_deref(),
            Self::Journal(options) => options.output.as_deref(),
            Self::Correlate(options) => options.output.as_deref(),
            Self::Review(options) => options.output.as_deref(),
            Self::CarrierResults(options) => options.output(),
            Self::Stream { .. } | Self::Index { .. } | Self::ExtractAll { .. } => None,
            Self::CodeLinks { output, .. }
            | Self::CarrierPlan { output, .. }
            | Self::CarrierDiscover { output, .. }
            | Self::Build { output, .. }
            | Self::Carrier { output, .. }
            | Self::Endpoint { output, .. }
            | Self::Indexed { output, .. }
            | Self::Import { output, .. }
            | Self::Inspect { output, .. }
            | Self::VerifyReceipt { output, .. }
            | Self::ExtractNode { output, .. }
            | Self::Query { output, .. }
            | Self::Behavior { output, .. }
            | Self::Timestamps { output, .. }
            | Self::Protocol { output, .. }
            | Self::MaterializeFrames(MaterializeFramesArgs { output, .. })
            | Self::Binary { output, .. }
            | Self::Search { output, .. }
            | Self::Experiment { output, .. } => output.as_deref(),
            Self::Records(args) => args.output.as_deref(),
            Self::Expand(args) => args.output.as_deref(),
            Self::ImageReachability(args) => args.output.as_deref(),
            Self::Concatenate(args) => args.output.as_deref(),
            Self::Decode(args) => args.output.as_deref(),
        }
    }
}
