//! Collect native and recovered artifacts from indexed capture Cases

#[cfg(test)]
#[path = "../../tests/export/archive_parent.rs"]
mod archive_parent_tests;

use super::{
    artifact_collection::{ArtifactCollection, ArtifactLimits},
    coverage::{RecoveryCoverage, retention_limit_names},
    evidence::EvidenceSidecar,
    limitations::{CaseLimitationOrigin, LimitationSpool, add_source_limitations},
    processing::{
        CollectionPhases, PendingCase, RecoveredCase, batch_ready, process_case_batch,
        recovery_worker_count,
    },
    provenance::{
        ArtifactSourceContext, CohortArtifactContextIndex, artifact_provenance,
        selected_artifact_source_ranges,
    },
    recovery_cache::{CachedRecovery, RecoveryContext},
    tshark_objects,
};
use crate::{arguments::ExportOptions, workbench};
use l2_workbench::{
    evidence::{Case, EvidenceStatus, Node},
    job::{MemoryBudget, MemoryError, Phase},
    reconstruction::Limits,
    tshark::SourceIdentity,
};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt, io,
    path::{Path, PathBuf},
};

const TSHARK_OBJECT_BUDGET: workbench::ObjectExportBudget = workbench::ObjectExportBudget::DEFAULT;

struct CaseCollection<'a> {
    artifacts: ArtifactCollection,
    evidence: EvidenceSidecar,
    limitations: LimitationSpool,
    recovery: RecoveryCoverage,
    memory: Option<&'a MemoryBudget>,
}

pub(super) struct CollectedExport {
    pub(super) artifacts: ArtifactCollection,
    pub(super) evidence: EvidenceSidecar,
    pub(super) limitations: LimitationSpool,
    pub(super) coverage: workbench::full_source::FullSourceCoverage,
    pub(super) recovery: RecoveryCoverage,
    pub(super) tshark: tshark_objects::Collection,
    pub(super) tshark_error: Option<String>,
}

pub(super) fn collect_export(
    staging: &Path,
    options: &ExportOptions,
    limits: ArtifactLimits,
    context: &RecoveryContext<'_>,
) -> Result<CollectedExport, Box<dyn Error>> {
    collect_export_inner(staging, options, limits, context).map_err(|source| {
        Box::new(CaptureAnalysisError {
            capture: options.capture.clone(),
            source,
        }) as Box<dyn Error>
    })
}

fn collect_export_inner(
    staging: &Path,
    options: &ExportOptions,
    limits: ArtifactLimits,
    context: &RecoveryContext<'_>,
) -> Result<CollectedExport, Box<dyn Error>> {
    let mut collection = CaseCollection {
        artifacts: ArtifactCollection::new(staging, limits)?,
        evidence: EvidenceSidecar::new(staging, limits.evidence_bytes, context.memory)?,
        limitations: LimitationSpool::new(staging)?,
        recovery: RecoveryCoverage::default(),
        memory: context.memory,
    };
    let capture_cache = context
        .cache
        .filter(|_| !context.options.no_cache && options.capture != Path::new("-"));
    let mut indexed = workbench::full_source::acquire_indexed_source(
        &options.capture,
        staging,
        &workbench::full_source::AcquisitionOptions {
            cache: capture_cache,
            job: context.job,
            fingerprint: None,
            strict_cache: context.options.strict_cache,
        },
    )?;
    if let Some(memory) = context.memory {
        indexed.store.set_memory_budget(memory.clone())?;
    }
    let worker_count = recovery_worker_count(
        context.options.jobs,
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get),
    );
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(worker_count)
        .build()?;
    let phases = CollectionPhases::start(context.job)?;
    if let Some(job) = context.job {
        job.set_current(
            Phase::Expansion,
            format!("Analyzing capture with up to {worker_count} recovery worker(s)"),
        )?;
    }
    let coverage = collect_flow_cases(&indexed, options, &mut collection, context, &pool, staging)?;
    let (tshark, tshark_error) = collect_tshark_and_finish(
        &options.capture,
        staging,
        &coverage.source,
        &mut collection.artifacts,
        phases,
        context.job,
    )?;
    let CaseCollection {
        artifacts,
        evidence,
        limitations,
        recovery,
        memory: _,
    } = collection;
    Ok(CollectedExport {
        artifacts,
        evidence,
        limitations,
        coverage,
        recovery,
        tshark,
        tshark_error,
    })
}

fn collect_tshark_and_finish(
    capture: &Path,
    staging: &Path,
    source: &workbench::full_source::SourceCoverage,
    artifacts: &mut ArtifactCollection,
    phases: CollectionPhases<'_>,
    job: Option<&l2_workbench::job::Job>,
) -> Result<(tshark_objects::Collection, Option<String>), Box<dyn Error>> {
    if let Some(job) = job {
        job.set_current(
            Phase::NativeExtraction,
            "Collecting optional TShark objects",
        )?;
    }
    let tshark_result = collect_tshark_objects(
        capture,
        staging,
        source,
        artifacts,
        TSHARK_OBJECT_BUDGET,
        job,
    );
    let phase_result = phases.finish(match &tshark_result {
        Ok(_) => l2_workbench::job::PhaseOutcome::Completed,
        Err(_) if job.is_some_and(l2_workbench::job::Job::is_cancelled) => {
            l2_workbench::job::PhaseOutcome::Cancelled
        }
        Err(_) => l2_workbench::job::PhaseOutcome::Failed,
    });
    match (tshark_result, phase_result) {
        (Ok(result), Ok(())) => Ok(result),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(tshark_error), Err(phase_error)) => Err(io::Error::other(format!(
            "TShark object collection failed: {tshark_error}; could not finish collection progress: {phase_error}"
        ))
        .into()),
    }
}

fn collect_flow_cases(
    indexed: &workbench::full_source::IndexedSource,
    options: &ExportOptions,
    collection: &mut CaseCollection,
    context: &RecoveryContext<'_>,
    pool: &rayon::ThreadPool,
    staging: &Path,
) -> Result<workbench::full_source::FullSourceCoverage, Box<dyn Error>> {
    let native_cache = context.cache.filter(|_| !context.options.no_cache);
    let source_id = indexed.receipt.source_id.as_str();
    let source_label = workbench::full_source::source_label(&options.capture);
    let worker_count = pool.current_num_threads();
    let mut batch = Vec::with_capacity(worker_count);
    let mut collect_case = |mut case: RecoveredCase| {
        // Bind the request's basename after cached recovery and before evidence identity is written
        bind_current_source_label(&mut case.item, source_id, source_label)?;
        collect_recovered_case(case, collection)
    };
    let analysis = workbench::full_source::analyze_indexed_source_with_context(
        &indexed.store,
        &indexed.receipt,
        workbench::full_source::IndexedAnalysisOptions {
            limits: Limits::default(),
            include_cohorts: true,
        },
        workbench::full_source::IndexedAnalysisContext {
            cache: native_cache,
            job: context.job,
            strict_cache: context.options.strict_cache,
        },
        |item| {
            let pending = PendingCase::new(item)?;
            if let Some(job) = context.job
                && let Some(counter) = pending.progress_counter()
            {
                job.increment(counter, 1)?;
            }
            batch.push(pending);
            if batch_ready(batch.len(), worker_count, context.memory)? {
                process_case_batch(&mut batch, pool, staging, context, &mut collect_case)?;
            }
            Ok(())
        },
    );
    let analysis = analysis.and_then(|coverage| {
        process_case_batch(&mut batch, pool, staging, context, &mut collect_case)?;
        Ok(coverage)
    });
    let coverage = analysis?;
    add_source_limitations(&mut collection.limitations, &coverage.source)?;
    Ok(coverage)
}

#[derive(Debug)]
struct CaptureAnalysisError {
    capture: PathBuf,
    source: Box<dyn Error>,
}

impl fmt::Display for CaptureAnalysisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "could not analyze {}: {}",
            self.capture.display().to_string().escape_debug(),
            self.source.to_string().escape_debug()
        )
    }
}

impl Error for CaptureAnalysisError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

fn bind_current_source_label(
    item: &mut workbench::full_source::FullSourceItem,
    source_id: &str,
    source_label: &str,
) -> Result<(), Box<dyn Error>> {
    let case = match item {
        workbench::full_source::FullSourceItem::Flow(analysis) => &mut analysis.result.case,
        workbench::full_source::FullSourceItem::FlowPage(page) => &mut page.result.case,
        workbench::full_source::FullSourceItem::Cohort(cohort) => &mut cohort.result.case,
    };
    case.rebind_source_label(source_id, source_label)?;
    Ok(())
}

fn collect_recovered_case(
    case: RecoveredCase,
    collection: &mut CaseCollection,
) -> Result<(), Box<dyn Error>> {
    let RecoveredCase {
        item,
        recovery,
        scope,
    } = case;
    match item {
        workbench::full_source::FullSourceItem::Flow(analysis) => {
            collect_flow_case(&analysis, &recovery, &scope, collection)
        }
        workbench::full_source::FullSourceItem::FlowPage(page) => {
            collect_flow_page_case(&page, &recovery, &scope, collection)
        }
        workbench::full_source::FullSourceItem::Cohort(cohort) => {
            collect_cohort_case(&cohort, &recovery, &scope, collection)
        }
    }
}

fn collect_flow_case(
    analysis: &workbench::full_source::FlowAnalysis,
    recovery: &CachedRecovery,
    scope: &serde_json::Value,
    collection: &mut CaseCollection,
) -> Result<(), Box<dyn Error>> {
    let flow_id = analysis.flow.id;
    collection.recovery.merge(&recovery.coverage)?;
    for omission in &recovery.omissions {
        collection.limitations.push(
            Some(flow_id),
            format!("Default recovery omission: {omission}"),
        )?;
    }
    let omissions = analysis.coverage.reconstruction_omissions;
    if analysis.coverage.omitted_records != 0 || omissions.has_omissions() {
        let limits = retention_limit_names(&analysis.coverage.retention_limits);
        collection.limitations.push_with_impact(
            Some(flow_id),
            format!(
                "Flow analysis selected {} records, retained {}, and omitted {}; retention ceilings reached: {limits}; reconstruction omissions: {} TCP records, {} fragments, {} ranges, {} TCP byte positions affected by omitted observations or rejected ranges, {} TCP observations, {} fragment byte positions affected by omitted observations or rejected ranges, {} fragment observations, {} state observations, {} unmeasured ranges",
                analysis.coverage.selected_records,
                analysis.coverage.retained_records,
                analysis.coverage.omitted_records,
                omissions.omitted_tcp_records,
                omissions.omitted_fragments,
                omissions.omitted_sequence_ranges,
                omissions.omitted_tcp_bytes,
                omissions.omitted_tcp_observations,
                omissions.omitted_fragment_bytes,
                omissions.omitted_fragment_observations,
                omissions.omitted_state_observations,
                omissions.unmeasured_omitted_ranges
            ),
            false,
        )?;
    }
    let case_id = record_case_evidence(
        &mut collection.evidence,
        &analysis.result.case,
        scope,
        CaseLimitationOrigin::Flow(flow_id),
        &mut collection.limitations,
    )?;
    collect_case_artifacts(
        &mut collection.artifacts,
        &analysis.result.case,
        &analysis.flow,
        case_id.as_deref(),
        scope,
        collection.memory,
    )?;
    for message in analysis.result.case.limitations() {
        collection
            .limitations
            .push_case_limitation(CaseLimitationOrigin::Flow(flow_id), message)?;
    }
    Ok(())
}

fn collect_flow_page_case(
    page: &workbench::full_source::SupplementaryFlowPage,
    recovery: &CachedRecovery,
    scope: &serde_json::Value,
    collection: &mut CaseCollection,
) -> Result<(), Box<dyn Error>> {
    let flow_id = page.flow.id;
    collection.recovery.merge(&recovery.coverage)?;
    for omission in &recovery.omissions {
        collection.limitations.push(
            Some(flow_id),
            format!(
                "Flow page {} (packets {}–{}): default recovery omission: {omission}",
                page.page_index, page.first_packet, page.last_packet
            ),
        )?;
    }
    collection.limitations.push_with_impact(
        Some(flow_id),
        format!(
            "Flow page {} (packets {}–{}): selected records {}, retained records {}, omitted records {}; TCP/session/application state was not joined across page boundaries",
            page.page_index,
            page.first_packet,
            page.last_packet,
            page.selected_records,
            page.retained_records,
            page.omitted_records
        ),
        false,
    )?;
    let case_id = record_case_evidence(
        &mut collection.evidence,
        &page.result.case,
        scope,
        CaseLimitationOrigin::Flow(flow_id),
        &mut collection.limitations,
    )?;
    collect_case_artifacts(
        &mut collection.artifacts,
        &page.result.case,
        &page.flow,
        case_id.as_deref(),
        scope,
        collection.memory,
    )?;
    for message in page.result.case.limitations() {
        collection
            .limitations
            .push_case_limitation(CaseLimitationOrigin::Flow(flow_id), message)?;
    }
    Ok(())
}

fn collect_cohort_case(
    cohort: &workbench::full_source::CohortAnalysis,
    recovery: &CachedRecovery,
    scope: &serde_json::Value,
    collection: &mut CaseCollection,
) -> Result<(), Box<dyn Error>> {
    let flow_ids = cohort
        .member_flows
        .iter()
        .map(|flow| flow.id)
        .collect::<Vec<_>>();
    let cohort_label = format!("IP-pair cohort flows {flow_ids:?}");
    collection.recovery.merge(&recovery.coverage)?;
    for omission in &recovery.omissions {
        collection.limitations.push(
            None,
            format!("{cohort_label}: Default recovery omission: {omission}"),
        )?;
    }
    let case_id = record_case_evidence(
        &mut collection.evidence,
        &cohort.result.case,
        scope,
        CaseLimitationOrigin::Cohort(&cohort_label),
        &mut collection.limitations,
    )?;
    collect_cohort_artifacts(
        &mut collection.artifacts,
        cohort,
        case_id.as_deref(),
        scope,
        collection.memory,
    )?;
    for message in cohort.result.case.limitations() {
        collection
            .limitations
            .push_case_limitation(CaseLimitationOrigin::Cohort(&cohort_label), message)?;
    }
    Ok(())
}

fn record_case_evidence(
    evidence: &mut EvidenceSidecar,
    case: &Case,
    scope: &serde_json::Value,
    origin: CaseLimitationOrigin<'_>,
    limitations: &mut LimitationSpool,
) -> Result<Option<String>, Box<dyn Error>> {
    let result = evidence.record_case(case, scope)?;
    if result.retained {
        return Ok(Some(result.case_id));
    }
    let coverage = evidence.coverage();
    let message = format!(
        "Case {} was omitted from {} as one complete record ({} compressed bytes; {} logical JSONL bytes); aggregate evidence storage budget is {} bytes",
        result.case_id,
        super::evidence::SIDECAR_FILE_NAME,
        result.compressed_bytes,
        result.encoded_bytes,
        coverage.budget_bytes
    );
    match origin {
        CaseLimitationOrigin::Flow(flow_id) => limitations.push(Some(flow_id), message)?,
        CaseLimitationOrigin::Cohort(label) => {
            limitations.push(None, format!("{label}: {message}"))?;
        }
    }
    Ok(None)
}

fn collect_tshark_objects(
    capture: &Path,
    staging: &Path,
    source: &workbench::full_source::SourceCoverage,
    artifacts: &mut ArtifactCollection,
    budget: workbench::ObjectExportBudget,
    job: Option<&l2_workbench::job::Job>,
) -> Result<(tshark_objects::Collection, Option<String>), Box<dyn Error>> {
    if let Some(job) = job {
        job.check_cancelled()?;
    }
    if capture == Path::new("-") {
        return Ok((
            tshark_objects::Collection::default(),
            Some(String::from(
                "TShark export omitted for standard input because full-source ingest consumed the source and it cannot be reopened safely",
            )),
        ));
    }
    match workbench::export_tshark_objects_with_job(capture, staging, budget, job) {
        Ok(objects) => {
            let result = collect_matching_tshark_snapshot(source, &objects, artifacts)?;
            if let Some(job) = job {
                job.check_cancelled()?;
            }
            // The private snapshot stays alive until every selected object is staged
            objects.temporary_directory.close()?;
            Ok(result)
        }
        Err(error) if job.is_some_and(l2_workbench::job::Job::is_cancelled) => Err(error),
        Err(error) => Ok((
            tshark_objects::Collection::default(),
            Some(error.to_string()),
        )),
    }
}

pub(super) fn collect_matching_tshark_snapshot(
    source: &workbench::full_source::SourceCoverage,
    objects: &workbench::ExportObjectSet,
    artifacts: &mut ArtifactCollection,
) -> Result<(tshark_objects::Collection, Option<String>), Box<dyn Error>> {
    let identity_matches = capture_identity_matches(source, &objects.source_identity);
    let mut collection = if identity_matches {
        let directories = match objects.status {
            workbench::ObjectExportStatus::Complete => &objects.directories,
            workbench::ObjectExportStatus::Partial => &objects.partial_directories,
        };
        tshark_objects::collect(directories, artifacts, objects.budget.temporary_files)?
    } else {
        tshark_objects::Collection::default()
    };
    collection.export_status = Some(objects.status);
    collection.export_budget = Some(objects.budget);
    collection.export_usage = Some(objects.usage);
    collection.issues.extend(objects.issues.iter().cloned());
    let mismatch = (!identity_matches).then(|| {
        String::from(
            "capture changed between full-source ingest and the TShark snapshot; TShark objects were omitted",
        )
    });
    Ok((collection, mismatch))
}

fn collect_case_artifacts(
    collection: &mut ArtifactCollection,
    case: &Case,
    flow: &l2_workbench::store::Flow,
    case_id: Option<&str>,
    case_scope: &serde_json::Value,
    memory: Option<&MemoryBudget>,
) -> Result<(), Box<dyn Error>> {
    let flow_context = serde_json::to_value(flow)?;
    let context = ArtifactSourceContext {
        flow: Some(flow_context.clone()),
        supporting_flows: vec![flow_context],
        cohort_scope: None,
        case_id: case_id.map(str::to_owned),
        case_scope: case_scope.clone(),
    };
    collect_case_artifacts_with_context(collection, case, memory, |_, _| Ok(context.clone()))
}

pub(super) fn collect_cohort_artifacts(
    collection: &mut ArtifactCollection,
    cohort: &workbench::full_source::CohortAnalysis,
    case_id: Option<&str>,
    case_scope: &serde_json::Value,
    memory: Option<&MemoryBudget>,
) -> Result<(), Box<dyn Error>> {
    // Native and recovered artifacts share this collection-scoped lookup
    let context_index = CohortArtifactContextIndex::new(cohort)?;
    collect_case_artifacts_with_context(collection, &cohort.result.case, memory, |node, case| {
        context_index.for_node(node, case, case_id, case_scope)
    })
}

pub(super) fn collect_case_artifacts_with_context(
    collection: &mut ArtifactCollection,
    case: &Case,
    memory: Option<&MemoryBudget>,
    mut context_for_node: impl FnMut(&Node, &Case) -> Result<ArtifactSourceContext, Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    let index = CaseArtifactIndex::new(case)?;
    collect_native_case_artifacts(collection, &index, memory, &mut context_for_node)?;
    collect_selected_case_artifacts(collection, &index, memory, &mut context_for_node)
}

pub(super) struct CaseArtifactIndex<'a> {
    pub(super) case: &'a Case,
    signature_candidates: HashMap<u64, Vec<&'a Node>>,
    pub(super) mapping_receipts_by_output: HashMap<u64, &'a Node>,
}

impl<'a> CaseArtifactIndex<'a> {
    pub(super) fn new(case: &'a Case) -> Result<Self, Box<dyn Error>> {
        let mut mapping_receipts_by_output = HashMap::new();
        // Imported receipt details are provenance only when their link is observed
        for node in case
            .nodes()
            .iter()
            .filter(|node| node.kind == "byte_mapping_receipt")
        {
            let Some(output_node) = node
                .details
                .get("output_node")
                .and_then(serde_json::Value::as_u64)
            else {
                continue;
            };
            if node
                .details
                .get("representation")
                .and_then(serde_json::Value::as_str)
                != Some("json_blob")
                || !case.has_edge(output_node, node.id, "mapped_by", EvidenceStatus::Observed)
            {
                continue;
            }
            if mapping_receipts_by_output
                .insert(output_node, node)
                .is_some()
            {
                return Err("multiple byte mapping receipts reference one output node".into());
            }
        }
        Ok(Self {
            case,
            signature_candidates: signature_candidates(case),
            mapping_receipts_by_output,
        })
    }
}

fn collect_native_case_artifacts(
    collection: &mut ArtifactCollection,
    index: &CaseArtifactIndex<'_>,
    memory: Option<&MemoryBudget>,
    context_for_node: &mut impl FnMut(&Node, &Case) -> Result<ArtifactSourceContext, Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    let case = index.case;
    for node in case.nodes() {
        let Some(description) = export_description(node) else {
            continue;
        };
        let Some(blob_id) = node.blob.as_deref() else {
            continue;
        };
        let blob = case
            .blob(blob_id)
            .ok_or("exportable node references a missing byte object")?;
        let context = context_for_node(node, case)?;
        let number = collection.next_file_number()?;
        let origin = artifact_provenance(
            native_category(node),
            &context,
            Some(node),
            Some(description.to_owned()),
            None,
            index
                .signature_candidates
                .get(&node.id)
                .map_or(&[], Vec::as_slice),
            case,
        )?;
        let name = file_name(number, node, &blob.bytes, memory)?;
        collection.add_bytes(&blob.bytes, &name, &origin)?;
    }
    Ok(())
}

fn collect_selected_case_artifacts(
    collection: &mut ArtifactCollection,
    index: &CaseArtifactIndex<'_>,
    memory: Option<&MemoryBudget>,
    context_for_node: &mut impl FnMut(&Node, &Case) -> Result<ArtifactSourceContext, Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    let case = index.case;
    let selected_artifacts = workbench::artifact_export::select_artifacts(case, memory)?;
    let archive_member_paths = selected_artifacts
        .iter()
        .flat_map(workbench::artifact_export::SelectedArtifact::provenance)
        .filter_map(|provenance| {
            provenance
                .archive_path
                .as_ref()
                .map(|path| (provenance.id, path.as_str()))
        })
        .collect::<HashMap<_, _>>();
    for artifact in selected_artifacts.iter() {
        for selected_origin in artifact.provenance() {
            let node = case
                .node(selected_origin.id)
                .ok_or("recovered artifact provenance references a missing node")?;
            let number = collection.next_file_number()?;
            let mut selection = serde_json::to_value(selected_origin)?;
            let source_ranges = selected_artifact_source_ranges(selected_origin, index, memory)?;
            if let Some(fields) = selection.as_object_mut() {
                fields.insert(
                    "selected_file_name".to_owned(),
                    serde_json::json!(artifact.file_name()),
                );
                if selected_origin.archive_path.is_some()
                    && let Some(parent_id) = node
                        .details
                        .get("archive_node")
                        .and_then(serde_json::Value::as_u64)
                    && let Some(parent) = case.node(parent_id)
                {
                    fields.insert(
                        "archive_parent".to_owned(),
                        serde_json::json!({
                            "node_id": parent_id,
                            "kind": parent.kind,
                            "member_path": archive_member_ancestor_path(
                                parent_id,
                                case,
                                &archive_member_paths,
                            ),
                        }),
                    );
                }
                if !source_ranges.ranges.is_empty() {
                    fields.insert(
                        "source_ranges".to_owned(),
                        serde_json::json!(&source_ranges.ranges),
                    );
                }
            }
            let context = context_for_node(node, case)?;
            let origin = artifact_provenance(
                "recovered_artifact",
                &context,
                Some(node),
                None,
                Some(selection),
                index
                    .signature_candidates
                    .get(&node.id)
                    .map_or(&[], Vec::as_slice),
                case,
            )?;
            collection.add_bytes(
                artifact.bytes(),
                &recovered_file_name(number, artifact.file_name()),
                &origin,
            )?;
        }
    }
    Ok(())
}

fn archive_member_ancestor_path<'a>(
    node_id: u64,
    case: &Case,
    archive_member_paths: &HashMap<u64, &'a str>,
) -> Option<&'a str> {
    let mut current_id = node_id;
    let mut visited = HashSet::new();
    loop {
        if !visited.insert(current_id) {
            return None;
        }
        if let Some(path) = archive_member_paths.get(&current_id) {
            return Some(*path);
        }
        let node = case.node(current_id)?;
        current_id = node
            .details
            .get("input_node")
            .and_then(serde_json::Value::as_u64)?;
    }
}

fn signature_candidates(case: &Case) -> HashMap<u64, Vec<&Node>> {
    let mut candidates = HashMap::<u64, Vec<&Node>>::new();
    for node in case
        .nodes()
        .iter()
        .filter(|node| node.kind == "file_signature_match")
    {
        let Some(input_node) = node
            .details
            .get("input_node")
            .and_then(serde_json::Value::as_u64)
        else {
            continue;
        };
        candidates.entry(input_node).or_default().push(node);
    }
    candidates
}

fn native_category(node: &Node) -> &'static str {
    match node.kind.as_str() {
        "http_body" => "native_http_body",
        "ftp_data_candidate" => "native_ftp_candidate",
        _ => "native_artifact",
    }
}

fn export_description(node: &Node) -> Option<&'static str> {
    match node.kind.as_str() {
        "http_body"
            if node
                .details
                .get("status")
                .and_then(serde_json::Value::as_str)
                == Some("complete")
                && node
                    .details
                    .get("framing_complete")
                    .and_then(serde_json::Value::as_bool)
                    == Some(true) =>
        {
            Some("complete HTTP body")
        }
        // FTP control and endpoint matching identify useful bytes, not a proven file boundary
        "ftp_data_candidate" => Some("FTP transfer candidate; file boundary unresolved"),
        _ => None,
    }
}

fn file_name(
    number: u64,
    node: &Node,
    bytes: &[u8],
    memory: Option<&MemoryBudget>,
) -> Result<String, MemoryError> {
    let prefix = match node.kind.as_str() {
        "http_body" => "http",
        "ftp_data_candidate" => "ftp",
        _ => "file",
    };
    let extension =
        workbench::artifact_export::validated_extension(bytes, memory)?.unwrap_or("bin");
    Ok(format!("{number:06}-{prefix}.{extension}"))
}

fn recovered_file_name(number: u64, selected_name: &str) -> String {
    let extension = Path::new(selected_name)
        .extension()
        .and_then(|extension| extension.to_str())
        .filter(|extension| {
            !extension.is_empty()
                && extension.len() <= 16
                && extension.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
        .unwrap_or("bin");
    format!("{number:06}-recovered.{extension}")
}

pub(super) fn capture_identity_matches(
    source: &workbench::full_source::SourceCoverage,
    identity: &SourceIdentity,
) -> bool {
    source.bytes == identity.length
        && source.source_id.strip_prefix("sha256:") == Some(identity.sha256.as_str())
}
