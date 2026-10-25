use super::label;
use crate::{
    arguments::{IndexedCommand, IndexedFlowArgs, OutputFormat},
    input, publish,
};
use l2_workbench::store::{
    IngestReceipt, Inventory, Options, SharedFactKind, SharedGroupCursor, SharedOccurrenceCursor,
    Store,
};
use serde::Serialize;
use std::{
    error::Error,
    fs::File,
    io::{self, Write},
    path::{Path, PathBuf},
};

#[derive(Serialize)]
struct IndexReceipt {
    schema_version: u32,
    format: &'static str,
    inventory: Inventory,
    sources: Vec<IngestReceipt>,
}

pub(super) fn create(
    captures: &[PathBuf],
    directory: &Path,
    cache_mib: u32,
    format: OutputFormat,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    super::validate_directory_format(format)?;
    let receipt = publish::create_directory(directory, |staging| {
        let mut store = Store::create(staging, Options { cache_mib })?;
        let mut sources = Vec::new();
        for capture in captures {
            let reader = input::capture(capture)?;
            let receipt = store
                .ingest(label(capture, "capture"), reader)
                .map_err(|error| input::boxed_capture_error(capture, error))?;
            sources.push(receipt);
        }
        let receipt = IndexReceipt {
            schema_version: l2_workbench::store::SCHEMA_VERSION,
            format: "l2solver_index",
            inventory: store.inventory()?,
            sources,
        };
        drop(store);
        File::open(staging.join("index.sqlite"))?.sync_all()?;
        let mut manifest = File::create_new(staging.join("manifest.json"))?;
        serde_json::to_writer(&mut manifest, &receipt)?;
        manifest.sync_all()?;
        File::open(staging)?.sync_all()?;
        Ok(receipt)
    })?;
    match format {
        OutputFormat::Json => serde_json::to_writer(output, &receipt)?,
        OutputFormat::Text => {
            let path = directory.display().to_string();
            writeln!(output, "Created index directory: {}", path.escape_debug())?;
            writeln!(
                output,
                "Sources: {}; packets: {}; flows: {}",
                receipt.inventory.sources, receipt.inventory.packets, receipt.inventory.flows
            )?;
        }
        OutputFormat::Html => return Err("directory summaries support only text or JSON".into()),
    }
    Ok(true)
}

pub(super) fn run(
    directory: &Path,
    cache_mib: u32,
    command: &IndexedCommand,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    let store = Store::open(directory, Options { cache_mib })?;
    match command {
        IndexedCommand::Messages(args) => return super::messages::run(&store, args, output),
        IndexedCommand::Summary => serde_json::to_writer(output, &store.inventory()?)?,
        IndexedCommand::Verify => {
            store.verify_sources()?;
            serde_json::to_writer(
                output,
                &serde_json::json!({"verified":true,"inventory":store.inventory()?}),
            )?;
        }
        IndexedCommand::Flows { after, limit } => {
            store.visit_flows(*after, *limit, |flow| json_line(output, &flow))?;
        }
        IndexedCommand::Relationships { limit } => {
            store.visit_relationships(*limit, |relationship| json_line(output, &relationship))?;
        }
        IndexedCommand::SharedGroups {
            after_kind,
            after_key_hex,
            limit,
        } => {
            let cursor = group_cursor(after_kind.as_deref(), after_key_hex.as_deref())?;
            store
                .visit_shared_groups(cursor.as_ref(), *limit, |group| json_line(output, &group))?;
        }
        IndexedCommand::SharedOccurrences {
            kind,
            key_hex,
            after_source,
            after_packet,
            limit,
        } => {
            let kind = kind.parse::<SharedFactKind>()?;
            let key = decode_hex(key_hex)?;
            let cursor = occurrence_cursor(after_source.as_deref(), *after_packet)?;
            store.visit_shared_occurrences(kind, &key, cursor.as_ref(), *limit, |occurrence| {
                json_line(output, &occurrence)
            })?;
        }
        IndexedCommand::Packet { source, packet } => {
            output.write_all(store.frame(source, *packet)?.bytes())?;
        }
        IndexedCommand::Flow(args) => return reconstruct(&store, args, output),
    }
    Ok(true)
}

fn group_cursor(
    kind: Option<&str>,
    key: Option<&str>,
) -> Result<Option<SharedGroupCursor>, Box<dyn Error>> {
    match (kind, key) {
        (None, None) => Ok(None),
        (Some(kind), Some(key)) => Ok(Some(SharedGroupCursor {
            kind: kind.parse()?,
            key: decode_hex(key)?,
        })),
        _ => Err(invalid_argument("group cursor requires both kind and key")),
    }
}

fn occurrence_cursor(
    source: Option<&str>,
    packet: Option<u32>,
) -> Result<Option<SharedOccurrenceCursor>, Box<dyn Error>> {
    match (source, packet) {
        (None, None) => Ok(None),
        (Some(source_id), Some(packet)) => Ok(Some(SharedOccurrenceCursor {
            source_id: source_id.to_owned(),
            packet,
        })),
        _ => Err(invalid_argument(
            "occurrence cursor requires both source and packet",
        )),
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut chunks = value.as_bytes().chunks_exact(2);
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in &mut chunks {
        let high = pair
            .first()
            .copied()
            .ok_or_else(|| invalid_argument("invalid hex key"))?;
        let low = pair
            .get(1)
            .copied()
            .ok_or_else(|| invalid_argument("invalid hex key"))?;
        bytes.push((hex_digit(high)? << 4) | hex_digit(low)?);
    }
    if !chunks.remainder().is_empty() {
        return Err(invalid_argument("hex key must contain pairs of digits"));
    }
    Ok(bytes)
}

fn hex_digit(value: u8) -> Result<u8, Box<dyn Error>> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(invalid_argument("hex key contains a non-hexadecimal digit")),
    }
}

fn invalid_argument(message: &str) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidInput, message).into()
}

fn reconstruct(
    store: &Store,
    args: &IndexedFlowArgs,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    let result = store.investigate_flows(&args.flow, args.limits())?;
    result.case.write_json(output)?;
    Ok(result.complete)
}

fn json_line(output: &mut impl Write, value: &impl Serialize) -> Result<(), Box<dyn Error>> {
    serde_json::to_writer(&mut *output, value)?;
    output.write_all(b"\n")?;
    Ok(())
}
