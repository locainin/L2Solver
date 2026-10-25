//! Durable carrier result creation, retrieval, export, and replay

mod presentation;

use super::{carrier_plan::parse_view, input, load, read_bounded};
use crate::{
    arguments::{CarrierResultsArgs, CarrierResultsCommand, OutputFormat},
    publish,
};
use l2_workbench::carrier::discovery::{
    DEFAULT_MAX_RESULT_PAGE_BYTES, DiscoveryResultStore, Partition, ResultReadOptions,
    StoreOptions, discover_case_to_store, replay_case_candidate,
};
use std::{error::Error, fs::File, io::Write, path::Path};

#[derive(Clone, Copy)]
struct DiscoverRequest<'a> {
    case_path: &'a Path,
    nodes: &'a [u64],
    view: &'a str,
    plan_path: &'a Path,
    destination: &'a Path,
    format: OutputFormat,
    max_plan_bytes: usize,
    store_options: StoreOptions,
}

#[derive(Clone, Copy)]
struct ReplayRequest<'a> {
    case_path: &'a Path,
    nodes: &'a [u64],
    view: &'a str,
    plan_path: &'a Path,
    directory: &'a Path,
    candidate_id: usize,
    max_plan_bytes: usize,
    read_options: ResultReadOptions,
}

#[derive(Clone, Copy)]
struct ListRequest<'a> {
    directory: &'a Path,
    after: Option<usize>,
    limit: usize,
    format: OutputFormat,
    read_options: ResultReadOptions,
}

#[derive(Clone, Copy)]
struct ShowRequest<'a> {
    directory: &'a Path,
    candidate_id: usize,
    after_run_id: Option<usize>,
    limit: usize,
    partition: &'a str,
    format: OutputFormat,
    read_options: ResultReadOptions,
}

#[derive(Clone, Copy)]
struct SourcesRequest<'a> {
    directory: &'a Path,
    after_sample_id: Option<u64>,
    limit: usize,
    format: OutputFormat,
    read_options: ResultReadOptions,
}

#[derive(Clone, Copy)]
struct ExportRequest<'a> {
    directory: &'a Path,
    candidate_id: usize,
    partition: &'a str,
    read_options: ResultReadOptions,
}

/// Run one durable result operation
pub(super) fn run(
    args: &CarrierResultsArgs,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    match &args.operation {
        CarrierResultsCommand::Discover { .. } | CarrierResultsCommand::Replay { .. } => {
            run_case_operations(&args.operation, output)
        }
        CarrierResultsCommand::List { .. }
        | CarrierResultsCommand::Show { .. }
        | CarrierResultsCommand::Sources { .. }
        | CarrierResultsCommand::Export { .. } => run_result_operations(&args.operation, output),
    }
}

fn run_case_operations(
    operation: &CarrierResultsCommand,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    match operation {
        CarrierResultsCommand::Discover {
            case,
            nodes,
            view,
            plan,
            directory,
            format,
            max_plan_bytes,
            max_output_bytes,
            max_disk_bytes,
        } => discover(
            DiscoverRequest {
                case_path: case,
                nodes,
                view,
                plan_path: plan,
                destination: directory,
                format: *format,
                max_plan_bytes: *max_plan_bytes,
                store_options: StoreOptions {
                    max_output_bytes: *max_output_bytes,
                    max_disk_bytes: *max_disk_bytes,
                },
            },
            output,
        ),
        CarrierResultsCommand::Replay {
            case,
            nodes,
            view,
            plan,
            directory,
            candidate,
            max_plan_bytes,
            max_disk_bytes,
            max_record_bytes,
        } => replay(
            ReplayRequest {
                case_path: case,
                nodes,
                view,
                plan_path: plan,
                directory,
                candidate_id: *candidate,
                max_plan_bytes: *max_plan_bytes,
                read_options: read_options(
                    *max_disk_bytes,
                    *max_record_bytes,
                    DEFAULT_MAX_RESULT_PAGE_BYTES,
                ),
            },
            output,
        ),
        _ => Err("expected a carrier result discover or replay operation".into()),
    }
}

fn run_result_operations(
    operation: &CarrierResultsCommand,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    match operation {
        CarrierResultsCommand::List {
            directory,
            after,
            limit,
            format,
            max_disk_bytes,
            max_record_bytes,
            max_page_bytes,
        } => list(
            ListRequest {
                directory,
                after: *after,
                limit: *limit,
                format: *format,
                read_options: read_options(*max_disk_bytes, *max_record_bytes, *max_page_bytes),
            },
            output,
        ),
        CarrierResultsCommand::Show {
            directory,
            candidate,
            after_run_id,
            limit,
            partition,
            format,
            max_disk_bytes,
            max_record_bytes,
            max_page_bytes,
        } => show(
            ShowRequest {
                directory,
                candidate_id: *candidate,
                after_run_id: *after_run_id,
                limit: *limit,
                partition,
                format: *format,
                read_options: read_options(*max_disk_bytes, *max_record_bytes, *max_page_bytes),
            },
            output,
        ),
        CarrierResultsCommand::Sources {
            directory,
            after_sample_id,
            limit,
            format,
            max_disk_bytes,
            max_record_bytes,
            max_page_bytes,
        } => sources(
            SourcesRequest {
                directory,
                after_sample_id: *after_sample_id,
                limit: *limit,
                format: *format,
                read_options: read_options(*max_disk_bytes, *max_record_bytes, *max_page_bytes),
            },
            output,
        ),
        CarrierResultsCommand::Export {
            directory,
            candidate,
            partition,
            max_disk_bytes,
            max_record_bytes,
        } => export(
            ExportRequest {
                directory,
                candidate_id: *candidate,
                partition,
                read_options: read_options(
                    *max_disk_bytes,
                    *max_record_bytes,
                    DEFAULT_MAX_RESULT_PAGE_BYTES,
                ),
            },
            output,
        ),
        _ => Err("expected a carrier result retrieval or export operation".into()),
    }
}

const fn read_options(
    max_disk_bytes: u64,
    max_record_bytes: u64,
    max_page_bytes: u64,
) -> ResultReadOptions {
    ResultReadOptions {
        max_disk_bytes,
        max_record_bytes,
        max_page_bytes,
    }
}

fn open_store(
    directory: &Path,
    options: ResultReadOptions,
) -> Result<DiscoveryResultStore, Box<dyn Error>> {
    DiscoveryResultStore::open_with_options(directory, options)
}

fn list(request: ListRequest<'_>, output: &mut impl Write) -> Result<bool, Box<dyn Error>> {
    let store = open_store(request.directory, request.read_options)?;
    let page = store.list_candidates(request.after, request.limit)?;
    presentation::list(output, request.format, store.summary(), &page)?;
    Ok(true)
}

fn show(request: ShowRequest<'_>, output: &mut impl Write) -> Result<bool, Box<dyn Error>> {
    let store = open_store(request.directory, request.read_options)?;
    let candidate = store.candidate(request.candidate_id)?;
    let runs = store.printable_runs(
        request.candidate_id,
        parse_partition(request.partition)?,
        request.after_run_id,
        request.limit,
    )?;
    presentation::candidate(output, request.format, &candidate, &runs)?;
    Ok(true)
}

fn sources(request: SourcesRequest<'_>, output: &mut impl Write) -> Result<bool, Box<dyn Error>> {
    let store = open_store(request.directory, request.read_options)?;
    let page = store.sample_receipts(request.after_sample_id, request.limit)?;
    presentation::sources(output, request.format, store.summary(), &page)?;
    Ok(true)
}

fn export(request: ExportRequest<'_>, output: &mut impl Write) -> Result<bool, Box<dyn Error>> {
    let store = open_store(request.directory, request.read_options)?;
    store.export_output(
        request.candidate_id,
        parse_partition(request.partition)?,
        output,
    )?;
    Ok(true)
}

fn discover(request: DiscoverRequest<'_>, output: &mut impl Write) -> Result<bool, Box<dyn Error>> {
    super::validate_directory_format(request.format)?;
    let view = parse_view(request.view)?;
    let plan = read_plan(request.plan_path, request.max_plan_bytes)?;
    let case = load(request.case_path)?;
    let summary = publish::create_directory(request.destination, |staging| {
        let summary = discover_case_to_store(
            &case,
            request.nodes,
            view,
            &plan,
            staging,
            request.store_options,
        )?;
        let mut manifest = File::create_new(staging.join("manifest.json"))?;
        serde_json::to_writer(&mut manifest, &summary)?;
        manifest.sync_all()?;
        File::open(staging)?.sync_all()?;
        Ok(summary)
    })?;
    presentation::created(output, request.format, request.destination, &summary)?;
    Ok(case.collection_complete() && summary.enumeration_complete)
}

fn replay(request: ReplayRequest<'_>, output: &mut impl Write) -> Result<bool, Box<dyn Error>> {
    let view = parse_view(request.view)?;
    let plan = read_plan(request.plan_path, request.max_plan_bytes)?;
    let case = load(request.case_path)?;
    let store = open_store(request.directory, request.read_options)?;
    let receipt = replay_case_candidate(
        &case,
        request.nodes,
        view,
        &plan,
        &store,
        request.candidate_id,
    )?;
    serde_json::to_writer(output, &receipt)?;
    Ok(receipt.matches_stored_output && case.collection_complete())
}

fn read_plan(
    path: &Path,
    maximum: usize,
) -> Result<l2_workbench::carrier::discovery::DiscoveryPlan, Box<dyn Error>> {
    if maximum == 0 || maximum.checked_add(1).is_none() {
        return Err("max-plan-bytes must be positive and allow oversize detection".into());
    }
    let bytes = read_bounded(input::regular_no_follow(path)?, maximum)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn parse_partition(value: &str) -> Result<Partition, Box<dyn Error>> {
    match value {
        "discovery" => Ok(Partition::Discovery),
        "control" => Ok(Partition::Control),
        _ => Err("partition must be discovery or control".into()),
    }
}
