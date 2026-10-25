use super::{CapturePath, usage_error};
use crate::arguments::{CaptureCompareOptions, CaptureTcpOptions, Command, OutputFormat, value};
use clap::{Args, Subcommand, error::ErrorKind};
use std::{path::PathBuf, time::Duration};

#[derive(Debug, Subcommand)]
pub(super) enum CaptureCommand {
    /// Decode every captured frame for interactive inspection
    Inspect(CapturePath),
    /// Track Spanning Tree Protocol (STP) advertisements and root changes
    #[command(
        long_about = "Replay a capture and track Spanning Tree Protocol (STP) advertisements and root changes over capture time. Capture timestamps drive the 20-second advertisement lifetime. Missing or regressing timestamps are reported in the final summary."
    )]
    Observe(CapturePath),
    /// Export one machine-readable record per frame
    Dump {
        #[arg(value_name = "CAPTURE", allow_hyphen_values = true)]
        capture: PathBuf,
        #[arg(long, default_value = "ndjson", value_parser = ["ndjson"])]
        format: String,
    },
    /// Record a bounded receive-only evidence file
    Record(RecordArgs),
    /// Compare exact byte ranges from two explicitly selected capture records
    Compare(CaptureCompareArgs),
    /// Reconstruct a bounded TCP payload range while preserving gaps and conflicting bytes
    TcpRange(CaptureTcpArgs),
}

#[derive(Debug, Args)]
pub(super) struct CaptureTcpArgs {
    /// Capture path or - for standard input
    #[arg(value_name = "CAPTURE", allow_hyphen_values = true)]
    capture: PathBuf,
    /// First included record; selects directed IP endpoints, ports, and capture/VLAN scope
    #[arg(long, value_parser = value::capture_packet_index)]
    packet: u32,
    /// Inclusive last included record; omitted windows extend through end of capture
    #[arg(long, value_parser = value::capture_packet_index)]
    last_packet: Option<u32>,
    /// Raw payload sequence origin; defaults to the selected packet's first payload byte
    #[arg(long)]
    sequence: Option<u32>,
    /// Number of payload sequence positions, from 1 to 65535
    #[arg(long, value_parser = value::byte_length)]
    length: usize,
    #[arg(long, default_value = "text", value_parser = value::compare_format)]
    format: OutputFormat,
}

#[derive(Debug, Args)]
pub(super) struct CaptureCompareArgs {
    /// Capture path or - for standard input
    #[arg(value_name = "CAPTURE", allow_hyphen_values = true)]
    capture: PathBuf,
    /// One-based record number for the left byte source
    #[arg(long, value_parser = value::capture_packet_index)]
    left_packet: u32,
    /// One-based record number for the right byte source
    #[arg(long, value_parser = value::capture_packet_index)]
    right_packet: u32,
    /// Zero-based byte offset in the left captured frame
    #[arg(long, default_value = "0", value_parser = value::byte_offset)]
    left_offset: usize,
    /// Zero-based byte offset in the right captured frame
    #[arg(long, default_value = "0", value_parser = value::byte_offset)]
    right_offset: usize,
    /// Equal length to select from each frame; omitted ranges use each remainder
    #[arg(long, value_parser = value::byte_length)]
    length: Option<usize>,
    /// Optional repeating XOR key as 1 to 256 ASCII hexadecimal bytes, checked without inference
    #[arg(long, value_name = "HEX")]
    xor_key: Option<String>,
    /// Report encoding
    #[arg(long, default_value = "text", value_parser = value::compare_format)]
    format: OutputFormat,
}

#[derive(Debug, Args)]
pub(super) struct RecordArgs {
    #[arg(short = 'i', long, value_name = "INTERFACE")]
    interface: String,
    #[arg(long, value_parser = value::duration, conflicts_with = "packets")]
    duration: Option<Duration>,
    #[arg(long, value_parser = value::packets, conflicts_with = "duration")]
    packets: Option<u32>,
    #[arg(short, long, value_name = "FILE")]
    output: PathBuf,
}

impl CaptureCommand {
    pub(super) fn finish(self) -> Result<Command, clap::Error> {
        match self {
            Self::Inspect(path) => Ok(Command::Inspect(path.capture)),
            Self::Observe(path) => Ok(Command::Observe(path.capture)),
            Self::Dump { capture, format } => {
                debug_assert_eq!(format, "ndjson");
                Ok(Command::Json(capture))
            }
            Self::Record(arguments) => Ok(Command::Record {
                interface: arguments.interface,
                limit: value::limit(arguments.duration, arguments.packets).map_err(usage_error)?,
                output: arguments.output,
            }),
            Self::Compare(arguments) => {
                let xor_key = arguments
                    .xor_key
                    .as_deref()
                    .map(value::xor_key)
                    .transpose()
                    .map_err(|message| clap::Error::raw(ErrorKind::ValueValidation, message))?;
                Ok(Command::CaptureCompare(CaptureCompareOptions {
                    capture: arguments.capture,
                    left_packet: arguments.left_packet,
                    right_packet: arguments.right_packet,
                    left_offset: arguments.left_offset,
                    right_offset: arguments.right_offset,
                    length: arguments.length,
                    xor_key,
                    format: arguments.format,
                }))
            }
            Self::TcpRange(arguments) => {
                if arguments
                    .last_packet
                    .is_some_and(|last| last < arguments.packet)
                {
                    return Err(clap::Error::raw(
                        ErrorKind::ValueValidation,
                        "last packet must be at or after the selected first packet",
                    ));
                }
                Ok(Command::CaptureTcp(CaptureTcpOptions {
                    capture: arguments.capture,
                    packet: arguments.packet,
                    last_packet: arguments.last_packet,
                    sequence: arguments.sequence,
                    length: arguments.length,
                    format: arguments.format,
                }))
            }
        }
    }
}
