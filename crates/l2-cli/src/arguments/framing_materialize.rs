use clap::{ArgGroup, Args, value_parser};
use std::{num::NonZeroUsize, path::PathBuf};

/// Apply one caller-selected framing rule to a retained TCP byte run
#[derive(Clone, Debug, PartialEq, Eq, Args)]
#[command(group(
    ArgGroup::new("framing_rule")
        .required(true)
        .multiple(false)
        .args(["delimiter_byte", "fixed_size", "length_prefix", "rule_json"])
))]
pub struct MaterializeFramesArgs {
    /// Evidence case containing the selected TCP byte run
    #[arg(value_name = "CASE", allow_hyphen_values = true)]
    pub case: PathBuf,
    /// Retained contiguous TCP byte run to frame
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pub node: u64,
    /// Frame through this delimiter byte in decimal or 0x-prefixed hexadecimal
    #[arg(long, value_name = "BYTE", value_parser = parse_byte, group = "framing_rule")]
    pub delimiter_byte: Option<u8>,
    /// Frame using this exact positive byte size
    #[arg(long, value_name = "BYTES", value_parser = value_parser!(NonZeroUsize), group = "framing_rule")]
    pub fixed_size: Option<NonZeroUsize>,
    /// Frame using `OFFSET:WIDTH:BYTE_ORDER:LENGTH_MEANING`; order is `big_endian` or `little_endian`
    /// Length meaning is `whole_message` or `bytes_after_field`
    #[arg(
        long,
        value_name = "OFFSET:WIDTH:BYTE_ORDER:LENGTH_MEANING",
        group = "framing_rule"
    )]
    pub length_prefix: Option<String>,
    /// Use a serialized `FramingKind` copied from a protocol report
    #[arg(long, value_name = "FRAMING_KIND_JSON", group = "framing_rule")]
    pub rule_json: Option<String>,
    /// Identify the retained framing discovery report that supplied this rule
    #[arg(long, value_name = "REPORT_NODE", value_parser = clap::value_parser!(u64).range(1..))]
    pub discovery_report: Option<u64>,
    /// Write the updated case atomically to this path
    #[arg(long, value_name = "NEW_CASE")]
    pub output: Option<PathBuf>,
}

fn parse_byte(value: &str) -> Result<u8, String> {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(
            || {
                value.parse::<u8>().map_err(|_| {
                    "delimiter byte must be decimal or 0x-prefixed hexadecimal".to_owned()
                })
            },
            |hexadecimal| {
                u8::from_str_radix(hexadecimal, 16)
                    .map_err(|_| "delimiter byte must fit in one byte".to_owned())
            },
        )
}
