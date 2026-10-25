use clap::Args;
use l2_workbench::protocol::{
    ByteOrder, DEFAULT_MAX_IDENTIFIER_BYTES, DEFAULT_MAX_RECORD_GROUPS,
    DEFAULT_MAX_RECORD_INPUT_BYTES, DEFAULT_MAX_RECORD_ISSUE_EXAMPLES,
    DEFAULT_MAX_RECORD_OUTPUT_BYTES, DEFAULT_MAX_RECORD_REPORT_BYTES, DEFAULT_MAX_RECORDS,
    RecordLimits,
};
use std::{num::NonZeroUsize, path::PathBuf, str::FromStr};

/// Explicit retained byte range containing one part's declared record count
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordCountSource {
    /// Retained byte node containing the count field
    pub node: u64,
    /// Zero-based count field offset in the selected node
    pub offset: usize,
    /// Count field width in bytes
    pub width: usize,
    /// Explicit unsigned integer byte order
    pub byte_order: ByteOrder,
}

impl FromStr for RecordCountSource {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut node = None;
        let mut offset = None;
        let mut width = None;
        let mut byte_order = None;
        for assignment in value.split(',') {
            let (key, raw) = assignment
                .split_once('=')
                .ok_or_else(|| "count source fields must use key=value syntax".to_owned())?;
            match key {
                "node" => set_once(
                    &mut node,
                    raw.parse::<u64>()
                        .map_err(|_| "count source node must be an integer".to_owned())?,
                    "node",
                )?,
                "offset" => set_once(
                    &mut offset,
                    raw.parse::<usize>()
                        .map_err(|_| "count source offset must be an integer".to_owned())?,
                    "offset",
                )?,
                "width" => set_once(
                    &mut width,
                    raw.parse::<usize>()
                        .map_err(|_| "count source width must be an integer".to_owned())?,
                    "width",
                )?,
                "byte_order" => {
                    let order = match raw {
                        "big_endian" => ByteOrder::BigEndian,
                        "little_endian" => ByteOrder::LittleEndian,
                        _ => {
                            return Err(
                                "count source byte_order must be big_endian or little_endian"
                                    .to_owned(),
                            );
                        }
                    };
                    set_once(&mut byte_order, order, "byte_order")?;
                }
                _ => return Err(format!("unknown count source field {key}")),
            }
        }
        let node = node.ok_or("count source is missing node")?;
        if node == 0 {
            return Err("count source node must be positive".to_owned());
        }
        let width = width.ok_or("count source is missing width")?;
        if !matches!(width, 1 | 2 | 4 | 8) {
            return Err("count source width must be 1, 2, 4, or 8".to_owned());
        }
        Ok(Self {
            node,
            offset: offset.ok_or("count source is missing offset")?,
            width,
            byte_order: byte_order.ok_or("count source is missing byte_order")?,
        })
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T, name: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("count source field {name} appears more than once"));
    }
    Ok(())
}

/// Explicit repeated-record parsing and object assembly options
#[derive(Clone, Debug, PartialEq, Eq, Args)]
pub struct RecordsArgs {
    /// Evidence case containing the selected byte nodes
    #[arg(value_name = "CASE", allow_hyphen_values = true)]
    pub case: PathBuf,
    /// Retained byte node to parse, repeat in source order
    #[arg(long = "node", required = true, value_parser = clap::value_parser!(u64).range(1..))]
    pub nodes: Vec<u64>,
    /// External count field using `node=N,offset=N,width=N,byte_order=ORDER`
    ///
    /// Omit for schema-defined counts, or repeat exactly once per --node in the same order
    #[arg(long = "count-source", value_name = "COUNT_SOURCE")]
    pub count_sources: Vec<RecordCountSource>,
    /// JSON record schema with explicit offsets, widths, byte orders, and length meaning
    #[arg(long, value_name = "SCHEMA_JSON")]
    pub schema: PathBuf,
    /// Reader ceiling for the schema document
    #[arg(long, default_value = "1048576")]
    pub max_schema_bytes: NonZeroUsize,
    /// Aggregate selected byte input ceiling
    #[arg(long, default_value = DEFAULT_MAX_RECORD_INPUT_BYTES.to_string())]
    pub max_input_bytes: NonZeroUsize,
    /// Parsed record ceiling
    #[arg(long, default_value = DEFAULT_MAX_RECORDS.to_string())]
    pub max_records: NonZeroUsize,
    /// Opaque identifier width ceiling
    #[arg(long, default_value = DEFAULT_MAX_IDENTIFIER_BYTES.to_string())]
    pub max_identifier_bytes: NonZeroUsize,
    /// Logical parsed metadata ceiling
    #[arg(long, default_value = DEFAULT_MAX_RECORD_REPORT_BYTES.to_string())]
    pub max_report_bytes: NonZeroUsize,
    /// Distinct identifier ceiling
    #[arg(long, default_value = DEFAULT_MAX_RECORD_GROUPS.to_string())]
    pub max_groups: NonZeroUsize,
    /// Aggregate complete object byte ceiling
    #[arg(long, default_value = DEFAULT_MAX_RECORD_OUTPUT_BYTES.to_string())]
    pub max_output_bytes: NonZeroUsize,
    /// Retained examples for each missing or repeated sequence class
    #[arg(long, default_value = DEFAULT_MAX_RECORD_ISSUE_EXAMPLES.to_string())]
    pub max_issue_examples: NonZeroUsize,
    /// Write the updated case atomically to this path
    #[arg(long, value_name = "NEW_CASE")]
    pub output: Option<PathBuf>,
}

impl RecordsArgs {
    /// Build the exact limits selected at the command boundary
    #[must_use]
    pub const fn limits(&self) -> RecordLimits {
        RecordLimits {
            max_input_bytes: self.max_input_bytes.get(),
            max_records: self.max_records.get(),
            max_identifier_bytes: self.max_identifier_bytes.get(),
            max_report_bytes: self.max_report_bytes.get(),
            max_groups: self.max_groups.get(),
            max_output_bytes: self.max_output_bytes.get(),
            max_issue_examples: self.max_issue_examples.get(),
        }
    }
}
