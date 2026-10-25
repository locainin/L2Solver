//! Offline case operations stage valid documents before publication

pub mod artifact_export;
mod binary;
mod bundle_budget;
mod capture;
mod carrier_discovery;
mod carrier_plan;
mod carrier_results;
mod carriers;
mod code_links;
mod concatenate;
mod correlation;
mod decode;
mod endpoints;
mod expand;
mod export;
mod extract_all;
mod file_signatures;
mod framing_materialize;
pub mod full_source;
mod image_reachability;
mod imports;
mod indexed;
mod journal;
mod messages;
mod patterns;
mod protocol;
mod query;
mod receipt_verification;
mod records;
mod recovery_executor;
mod review;
mod searches;
mod selected;
mod stream;
mod tshark;
mod visit;

pub use recovery_executor::{
    RecoveryOmission, RecoveryResourceSummary, RecoveryRunSummary, recover_case,
};
pub use tshark::{ExportObjectSet, ObjectExportBudget, ObjectExportStatus, ObjectExportUsage};

pub fn export_tshark_objects(
    capture: &Path,
    temporary_parent: &Path,
    budget: ObjectExportBudget,
) -> Result<ExportObjectSet, Box<dyn Error>> {
    tshark::export_objects(capture, temporary_parent, budget)
}

use crate::{
    arguments::{OutputFormat, WorkbenchCommand},
    input,
};
use l2_workbench::evidence::{Case, MAX_CASE_JSON_BYTES};
use std::{
    collections::BTreeMap,
    error::Error,
    io::{Read, Write},
    path::Path,
};

pub fn run(command: &WorkbenchCommand, output: &mut impl Write) -> Result<bool, Box<dyn Error>> {
    match command {
        WorkbenchCommand::Review(args) => review::run(args, output),
        WorkbenchCommand::Correlate(args) => correlation::run(args, output),
        WorkbenchCommand::CarrierResults(args) => carrier_results::run(args, output),
        WorkbenchCommand::Tshark(options) => tshark::run(options, output),
        WorkbenchCommand::CodeLinks { args, .. } => code_links::run(args, output),
        WorkbenchCommand::Journal(options) => journal::run(options, output),
        WorkbenchCommand::Decode(args) => decode::run(args, output),
        WorkbenchCommand::Records(args) => records::run(args, output),
        WorkbenchCommand::Concatenate(args) => concatenate::run(args, output),
        WorkbenchCommand::Expand(args) => expand::run(args, output),
        WorkbenchCommand::ImageReachability(args) => image_reachability::run(args, output),
        WorkbenchCommand::MaterializeFrames(args) => framing_materialize::run(args, output),
        WorkbenchCommand::Inspect { case, format, .. } => inspect_saved(case, *format, output),
        WorkbenchCommand::VerifyReceipt {
            case,
            node,
            max_input_bytes,
            max_receipt_bytes,
            max_list_entries,
            ..
        } => receipt_verification::run(
            case,
            *node,
            max_input_bytes.map(std::num::NonZeroUsize::get),
            max_receipt_bytes.map(std::num::NonZeroUsize::get),
            max_list_entries.map(std::num::NonZeroUsize::get),
            output,
        ),
        WorkbenchCommand::ExtractNode { case, node, .. } => export::run(case, *node, output),
        WorkbenchCommand::ExtractAll { case, directory } => {
            extract_all::run(case, directory, output)
        }
        WorkbenchCommand::Search {
            case, node, plan, ..
        } => searches::search(case, *node, plan, output),
        source @ (WorkbenchCommand::CarrierPlan { .. }
        | WorkbenchCommand::CarrierDiscover { .. }
        | WorkbenchCommand::Carrier { .. }
        | WorkbenchCommand::Endpoint { .. }
        | WorkbenchCommand::Index { .. }
        | WorkbenchCommand::Indexed { .. }
        | WorkbenchCommand::Stream { .. }
        | WorkbenchCommand::Build { .. }
        | WorkbenchCommand::Import { .. }) => run_source_command(source, output),
        analysis @ (WorkbenchCommand::Query { .. }
        | WorkbenchCommand::Behavior { .. }
        | WorkbenchCommand::Timestamps { .. }
        | WorkbenchCommand::Protocol { .. }
        | WorkbenchCommand::Binary { .. }
        | WorkbenchCommand::Experiment { .. }) => run_analysis_command(analysis, output),
    }
}

fn validate_directory_format(format: OutputFormat) -> Result<(), Box<dyn Error>> {
    if format == OutputFormat::Html {
        return Err("directory creation supports only text or JSON output".into());
    }
    Ok(())
}

fn run_source_command(
    command: &WorkbenchCommand,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    match command {
        WorkbenchCommand::CarrierPlan {
            case,
            nodes,
            view,
            sources,
            ..
        } => carrier_plan::run(case, nodes, view, sources, output),
        WorkbenchCommand::CarrierDiscover {
            case,
            nodes,
            view,
            plan,
            max_plan_bytes,
            ..
        } => carrier_discovery::run(case, nodes, view, plan, *max_plan_bytes, output),
        WorkbenchCommand::Carrier { plan, .. } => carriers::run(plan, output),
        WorkbenchCommand::Endpoint {
            file,
            format,
            capture,
            ..
        } => endpoints::run(file, format, capture.as_deref(), output),
        WorkbenchCommand::Index {
            captures,
            directory,
            format,
            cache_mib,
        } => indexed::create(captures, directory, *cache_mib, *format, output),
        WorkbenchCommand::Indexed {
            directory,
            cache_mib,
            operation,
            ..
        } => indexed::run(directory, *cache_mib, operation, output),
        WorkbenchCommand::Stream {
            capture,
            directory,
            format,
            page_records,
            context_records,
            ..
        } => stream::run(
            capture,
            directory,
            *page_records,
            *context_records,
            *format,
            output,
        ),
        WorkbenchCommand::Build {
            capture: path,
            resources,
            ..
        } => capture::run(path, resources.limits(), output),
        WorkbenchCommand::Import {
            case,
            file,
            kind,
            scan_mode,
            max_scan_bytes,
            max_findings,
            max_input_bytes,
            ..
        } => imports::run(
            case,
            file,
            &imports::Options::new(
                kind,
                scan_mode,
                *max_scan_bytes,
                *max_findings,
                max_input_bytes.map(std::num::NonZeroUsize::get),
            ),
            output,
        ),
        _ => Err("internal workbench source-command routing mismatch".into()),
    }
}

fn run_analysis_command(
    command: &WorkbenchCommand,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    match command {
        WorkbenchCommand::Query {
            case,
            filters,
            limit,
            max_report_bytes,
            format,
            ..
        } => query::run(
            case,
            filters,
            limit.get(),
            max_report_bytes.get(),
            *format,
            output,
        ),
        WorkbenchCommand::Behavior {
            case,
            internal,
            large_gap_ticks,
            limits,
            ..
        } => patterns::behavior(case, internal, *large_gap_ticks, limits, output),
        WorkbenchCommand::Timestamps {
            case,
            events,
            large_gap_ticks,
            limits,
            ..
        } => patterns::timestamps(case, events.as_deref(), *large_gap_ticks, limits, output),
        WorkbenchCommand::Protocol {
            case,
            samples,
            field,
            analysis,
            ..
        } => protocol::run(case, samples, field.as_deref(), analysis, output),
        WorkbenchCommand::Binary {
            file,
            engine,
            max_input_bytes,
            ..
        } => binary::run(
            file,
            engine,
            max_input_bytes.map(std::num::NonZeroUsize::get),
            output,
        ),
        WorkbenchCommand::Experiment {
            case,
            node,
            plan,
            mode,
            ..
        } => searches::experiment(case, *node, plan, mode, output),
        _ => Err("internal workbench analysis-command routing mismatch".into()),
    }
}

fn load(path: &Path) -> Result<Case, Box<dyn Error>> {
    // Existing commands keep the documented standard-input budget
    let maximum = (path == Path::new("-")).then_some(MAX_CASE_JSON_BYTES);
    load_with_limit(path, maximum)
}

fn load_with_limit(path: &Path, maximum: Option<usize>) -> Result<Case, Box<dyn Error>> {
    let bytes = if path == Path::new("-") {
        match maximum {
            Some(maximum) => read_bounded(input::capture(path)?, maximum)?,
            None => read_to_end_fallible(input::capture(path)?)?,
        }
    } else {
        read_regular_case(path, maximum)?
    };
    Ok(Case::from_json(&bytes)?)
}

fn read_regular_case(path: &Path, maximum: Option<usize>) -> Result<Vec<u8>, Box<dyn Error>> {
    let file = input::regular(path)?;
    let metadata_length = file.metadata()?.len();
    if let Some(maximum) = maximum
        && metadata_length > u64::try_from(maximum)?
    {
        return Err(format!("input exceeds {maximum} bytes").into());
    }
    let length = usize::try_from(metadata_length)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| "could not allocate the case file input buffer")?;
    let sentinel = u64::try_from(length)?
        .checked_add(1)
        .ok_or("case file length exceeds the supported range")?;
    file.take(sentinel).read_to_end(&mut bytes)?;
    if bytes.len() != length {
        return Err("case file length changed while it was being read".into());
    }
    Ok(bytes)
}

fn read_to_end_fallible(mut reader: impl Read) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    let mut chunk = input::io_buffer()?;
    loop {
        let count = match reader.read(&mut chunk) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        if count == 0 {
            break;
        }
        let received = chunk
            .get(..count)
            .ok_or("input read exceeded its I/O buffer")?;
        // Reserve before copying so allocation failure becomes a normal command error
        bytes
            .try_reserve(count)
            .map_err(|_| "could not allocate the case file input buffer")?;
        bytes.extend_from_slice(received);
    }
    Ok(bytes)
}

fn inspect_saved(
    path: &Path,
    format: OutputFormat,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    let case = load(path)?;
    match format {
        OutputFormat::Json => case.write_json(output)?,
        OutputFormat::Text => inspect(path, &case, output)?,
        OutputFormat::Html => return Err("case format must be text or json".into()),
    }
    Ok(case.collection_complete())
}

fn read_bounded(reader: impl Read, maximum: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    let sentinel = u64::try_from(maximum)?
        .checked_add(1)
        .ok_or("input byte budget exceeds the supported range")?;
    reader.take(sentinel).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(format!("input exceeds {maximum} bytes").into());
    }
    Ok(bytes)
}

fn label<'a>(path: &'a Path, fallback: &'a str) -> &'a str {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| {
            !name.is_empty()
                && name.len() <= 256
                && !name.chars().any(char::is_control)
                && !name.contains(['/', '\\'])
        })
        .unwrap_or(fallback)
}

fn inspect(path: &Path, case: &Case, output: &mut impl Write) -> Result<(), Box<dyn Error>> {
    writeln!(
        output,
        "Saved analysis: file={} collection={} sources={} byte_objects={} observations={} relationships={}",
        path.display().to_string().escape_debug(),
        if case.collection_complete() {
            "complete"
        } else {
            "incomplete"
        },
        case.sources().len(),
        case.blobs().len(),
        case.nodes().len(),
        case.edges().len()
    )?;
    for source in case.sources() {
        writeln!(
            output,
            "source type={} bytes={} label={}",
            source.kind,
            source.length,
            source.label.escape_debug()
        )?;
    }
    let mut kinds = BTreeMap::new();
    for node in case.nodes() {
        *kinds.entry(node.kind.as_str()).or_insert(0_usize) += 1;
    }
    for (kind, count) in kinds {
        writeln!(output, "{kind}: {count}")?;
    }
    for node in case.nodes() {
        if node.blob.is_some() {
            writeln!(output, "retained bytes item={} type={}", node.id, node.kind)?;
        }
    }
    for limitation in case.limitations() {
        writeln!(output, "limitation: {}", limitation.escape_debug())?;
    }
    Ok(())
}
