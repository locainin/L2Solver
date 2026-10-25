//! Collect native and recovered artifacts from indexed capture Cases

use super::{
    artifact_collection::{ArtifactCollection, ArtifactLimits},
    coverage::{RecoveryCaseKind, RecoveryCoverage, retention_limit_names},
    evidence::EvidenceSidecar,
    limitations::{CaseLimitationOrigin, LimitationSpool, add_source_limitations},
    provenance::{
        ArtifactSourceContext, CohortArtifactContextIndex, artifact_provenance, cohort_scope,
        selected_artifact_source_ranges,
    },
    tshark_objects,
};
use crate::{arguments::ExportOptions, workbench};
use l2_workbench::{
    evidence::{Blob, Case, EvidenceStatus, Node},
    reconstruction::Limits,
    tshark::SourceIdentity,
};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    io,
    path::Path,
};

const TSHARK_OBJECT_BUDGET: workbench::ObjectExportBudget = workbench::ObjectExportBudget::DEFAULT;

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
) -> Result<CollectedExport, Box<dyn Error>> {
    let mut artifacts = ArtifactCollection::new(staging, limits)?;
    let mut evidence = EvidenceSidecar::new(staging, limits.evidence_bytes)?;
    let mut limitations = LimitationSpool::new(staging)?;
    let mut recovery = RecoveryCoverage::default();
    let coverage = collect_flow_cases(
        options,
        staging,
        &mut artifacts,
        &mut evidence,
        &mut limitations,
        &mut recovery,
    )?;
    let (tshark, tshark_error) = collect_tshark_objects(
        &options.capture,
        staging,
        &coverage.source,
        &mut artifacts,
        TSHARK_OBJECT_BUDGET,
    )?;
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

fn collect_flow_cases(
    options: &ExportOptions,
    staging: &Path,
    artifacts: &mut ArtifactCollection,
    evidence: &mut EvidenceSidecar,
    limitations: &mut LimitationSpool,
    recovery_coverage: &mut RecoveryCoverage,
) -> Result<workbench::full_source::FullSourceCoverage, Box<dyn Error>> {
    let coverage = workbench::full_source::acquire_full_source_with_cohorts_in(
        &options.capture,
        staging,
        Limits::default(),
        |item| match item {
            workbench::full_source::FullSourceItem::Flow(analysis) => collect_flow_case(
                *analysis,
                artifacts,
                evidence,
                limitations,
                recovery_coverage,
            ),
            workbench::full_source::FullSourceItem::FlowPage(page) => {
                collect_flow_page_case(*page, artifacts, evidence, limitations, recovery_coverage)
            }
            workbench::full_source::FullSourceItem::Cohort(cohort) => {
                collect_cohort_case(*cohort, artifacts, evidence, limitations, recovery_coverage)
            }
        },
    )
    .map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("could not analyze {}: {error}", options.capture.display()),
        )
    })?;
    add_source_limitations(limitations, &coverage.source)?;
    Ok(coverage)
}

fn collect_flow_case(
    mut analysis: workbench::full_source::FlowAnalysis,
    artifacts: &mut ArtifactCollection,
    evidence: &mut EvidenceSidecar,
    limitations: &mut LimitationSpool,
    recovery_coverage: &mut RecoveryCoverage,
) -> Result<(), Box<dyn Error>> {
    let flow_id = analysis.flow.id;
    let recovery = workbench::recover_case(&mut analysis.result.case)?;
    recovery_coverage.record(&recovery, RecoveryCaseKind::Flow)?;
    for omission in &recovery.omissions {
        limitations.push(
            Some(flow_id),
            format!("Default recovery omission: {omission}"),
        )?;
    }
    let omissions = analysis.coverage.reconstruction_omissions;
    if analysis.coverage.omitted_records != 0 || omissions.has_omissions() {
        let limits = retention_limit_names(&analysis.coverage.retention_limits);
        limitations.push_with_impact(
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
    let scope = serde_json::json!({
        "kind": "flow",
        "source_id": analysis.flow.source_id,
        "flow_id": flow_id,
        "flow": serde_json::to_value(&analysis.flow)?,
    });
    let case_id = record_case_evidence(
        evidence,
        &analysis.result.case,
        &scope,
        CaseLimitationOrigin::Flow(flow_id),
        limitations,
    )?;
    collect_case_artifacts(
        artifacts,
        &analysis.result.case,
        &analysis.flow,
        case_id.as_deref(),
        &scope,
    )?;
    for message in analysis.result.case.limitations() {
        limitations.push_case_limitation(CaseLimitationOrigin::Flow(flow_id), message)?;
    }
    Ok(())
}

fn collect_flow_page_case(
    mut page: workbench::full_source::SupplementaryFlowPage,
    artifacts: &mut ArtifactCollection,
    evidence: &mut EvidenceSidecar,
    limitations: &mut LimitationSpool,
    recovery_coverage: &mut RecoveryCoverage,
) -> Result<(), Box<dyn Error>> {
    let flow_id = page.flow.id;
    let recovery = workbench::recover_case(&mut page.result.case)?;
    recovery_coverage.record(&recovery, RecoveryCaseKind::Flow)?;
    for omission in &recovery.omissions {
        limitations.push(
            Some(flow_id),
            format!(
                "Flow page {} (packets {}–{}): default recovery omission: {omission}",
                page.page_index, page.first_packet, page.last_packet
            ),
        )?;
    }
    limitations.push_with_impact(
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
    let scope = serde_json::json!({
        "kind": "flow_page",
        "source_id": page.flow.source_id,
        "flow_id": flow_id,
        "page_index": page.page_index,
        "first_packet": page.first_packet,
        "last_packet": page.last_packet,
        "selected_records": page.selected_records,
        "retained_records": page.retained_records,
        "omitted_records": page.omitted_records,
        "flow": serde_json::to_value(&page.flow)?,
    });
    let case_id = record_case_evidence(
        evidence,
        &page.result.case,
        &scope,
        CaseLimitationOrigin::Flow(flow_id),
        limitations,
    )?;
    collect_case_artifacts(
        artifacts,
        &page.result.case,
        &page.flow,
        case_id.as_deref(),
        &scope,
    )?;
    for message in page.result.case.limitations() {
        limitations.push_case_limitation(CaseLimitationOrigin::Flow(flow_id), message)?;
    }
    Ok(())
}

fn collect_cohort_case(
    mut cohort: workbench::full_source::CohortAnalysis,
    artifacts: &mut ArtifactCollection,
    evidence: &mut EvidenceSidecar,
    limitations: &mut LimitationSpool,
    recovery_coverage: &mut RecoveryCoverage,
) -> Result<(), Box<dyn Error>> {
    let flow_ids = cohort
        .member_flows
        .iter()
        .map(|flow| flow.id)
        .collect::<Vec<_>>();
    let cohort_label = format!("IP-pair cohort flows {flow_ids:?}");
    let recovery = workbench::recover_case(&mut cohort.result.case)?;
    recovery_coverage.record(&recovery, RecoveryCaseKind::Cohort)?;
    for omission in &recovery.omissions {
        limitations.push(
            None,
            format!("{cohort_label}: Default recovery omission: {omission}"),
        )?;
    }
    let scope = serde_json::json!({
        "kind": "cohort",
        "flow_ids": flow_ids,
        "split": cohort.split,
        "cohort_scope": cohort_scope(&cohort)?,
    });
    let case_id = record_case_evidence(
        evidence,
        &cohort.result.case,
        &scope,
        CaseLimitationOrigin::Cohort(&cohort_label),
        limitations,
    )?;
    collect_cohort_artifacts(artifacts, &cohort, case_id.as_deref(), &scope)?;
    for message in cohort.result.case.limitations() {
        limitations.push_case_limitation(CaseLimitationOrigin::Cohort(&cohort_label), message)?;
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
        "Case {} was omitted from evidence.jsonl as one complete record ({} encoded bytes); aggregate evidence budget is {} bytes",
        result.case_id, result.encoded_bytes, coverage.budget_bytes
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
) -> Result<(tshark_objects::Collection, Option<String>), Box<dyn Error>> {
    if capture == Path::new("-") {
        return Ok((
            tshark_objects::Collection::default(),
            Some(String::from(
                "TShark export omitted for standard input because full-source ingest consumed the source and it cannot be reopened safely",
            )),
        ));
    }
    match workbench::export_tshark_objects(capture, staging, budget) {
        Ok(objects) => {
            let result = collect_matching_tshark_snapshot(source, &objects, artifacts)?;
            // The private snapshot stays alive until every selected object is staged
            objects.temporary_directory.close()?;
            Ok(result)
        }
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
) -> Result<(), Box<dyn Error>> {
    let flow_context = serde_json::to_value(flow)?;
    let context = ArtifactSourceContext {
        flow: Some(flow_context.clone()),
        supporting_flows: vec![flow_context],
        cohort_scope: None,
        case_id: case_id.map(str::to_owned),
        case_scope: case_scope.clone(),
    };
    collect_case_artifacts_with_context(collection, case, |_, _| Ok(context.clone()))
}

pub(super) fn collect_cohort_artifacts(
    collection: &mut ArtifactCollection,
    cohort: &workbench::full_source::CohortAnalysis,
    case_id: Option<&str>,
    case_scope: &serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    // Native and recovered artifacts share this collection-scoped lookup
    let context_index = CohortArtifactContextIndex::new(cohort)?;
    collect_case_artifacts_with_context(collection, &cohort.result.case, |node, nodes_by_id| {
        context_index.for_node(node, nodes_by_id, case_id, case_scope)
    })
}

pub(super) fn collect_case_artifacts_with_context(
    collection: &mut ArtifactCollection,
    case: &Case,
    mut context_for_node: impl FnMut(
        &Node,
        &HashMap<u64, &Node>,
    ) -> Result<ArtifactSourceContext, Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    let index = CaseArtifactIndex::new(case)?;
    collect_native_case_artifacts(collection, case, &index, &mut context_for_node)?;
    collect_selected_case_artifacts(collection, case, &index, &mut context_for_node)
}

pub(super) struct CaseArtifactIndex<'a> {
    pub(super) nodes_by_id: HashMap<u64, &'a Node>,
    pub(super) blobs_by_id: HashMap<&'a str, &'a Blob>,
    signature_candidates: HashMap<u64, Vec<Node>>,
    pub(super) mapping_receipts_by_output: HashMap<u64, &'a Node>,
}

impl<'a> CaseArtifactIndex<'a> {
    pub(super) fn new(case: &'a Case) -> Result<Self, Box<dyn Error>> {
        let nodes_by_id = case
            .nodes()
            .iter()
            .map(|node| (node.id, node))
            .collect::<HashMap<_, _>>();
        let blobs_by_id = case
            .blobs()
            .iter()
            .map(|blob| (blob.id.as_str(), blob))
            .collect::<HashMap<_, _>>();
        let mut mapping_receipts_by_output = HashMap::new();
        let observed_mapping_edges = case
            .edges()
            .iter()
            .filter(|edge| edge.relation == "mapped_by" && edge.status == EvidenceStatus::Observed)
            .map(|edge| (edge.from, edge.to))
            .collect::<HashSet<_>>();
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
                || !observed_mapping_edges.contains(&(output_node, node.id))
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
            nodes_by_id,
            blobs_by_id,
            signature_candidates: signature_candidates(case),
            mapping_receipts_by_output,
        })
    }
}

fn collect_native_case_artifacts(
    collection: &mut ArtifactCollection,
    case: &Case,
    index: &CaseArtifactIndex<'_>,
    context_for_node: &mut impl FnMut(
        &Node,
        &HashMap<u64, &Node>,
    ) -> Result<ArtifactSourceContext, Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    for node in case.nodes() {
        let Some(description) = export_description(node) else {
            continue;
        };
        let Some(blob_id) = node.blob.as_deref() else {
            continue;
        };
        let blob = index
            .blobs_by_id
            .get(blob_id)
            .copied()
            .ok_or("exportable node references a missing byte object")?;
        let context = context_for_node(node, &index.nodes_by_id)?;
        let number = collection.next_file_number()?;
        let origin = artifact_provenance(
            native_category(node),
            &context,
            Some(node.clone()),
            Some(description.to_owned()),
            None,
            index
                .signature_candidates
                .get(&node.id)
                .cloned()
                .unwrap_or_default(),
            &index.nodes_by_id,
        )?;
        collection.add_bytes(&blob.bytes, &file_name(number, node, &blob.bytes), &origin)?;
    }
    Ok(())
}

fn collect_selected_case_artifacts(
    collection: &mut ArtifactCollection,
    case: &Case,
    index: &CaseArtifactIndex<'_>,
    context_for_node: &mut impl FnMut(
        &Node,
        &HashMap<u64, &Node>,
    ) -> Result<ArtifactSourceContext, Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    let selected_artifacts = workbench::artifact_export::select_artifacts(case)?;
    let archive_member_paths = selected_artifacts
        .iter()
        .flat_map(workbench::artifact_export::SelectedArtifact::provenance)
        .filter_map(|provenance| {
            provenance
                .archive_path
                .as_ref()
                .map(|path| (provenance.id, path.clone()))
        })
        .collect::<HashMap<_, _>>();
    for artifact in selected_artifacts {
        for selected_origin in artifact.provenance() {
            let node = index
                .nodes_by_id
                .get(&selected_origin.id)
                .copied()
                .ok_or("recovered artifact provenance references a missing node")?;
            let number = collection.next_file_number()?;
            let mut selection = serde_json::to_value(selected_origin)?;
            let source_ranges = selected_artifact_source_ranges(selected_origin, index)?;
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
                    && let Some(parent) = index.nodes_by_id.get(&parent_id)
                {
                    fields.insert(
                        "archive_parent".to_owned(),
                        serde_json::json!({
                            "node_id": parent_id,
                            "kind": parent.kind,
                            "member_path": archive_member_ancestor_path(
                                parent_id,
                                &index.nodes_by_id,
                                &archive_member_paths,
                            ),
                        }),
                    );
                }
                if !source_ranges.is_empty() {
                    fields.insert("source_ranges".to_owned(), serde_json::json!(source_ranges));
                }
            }
            let context = context_for_node(node, &index.nodes_by_id)?;
            let origin = artifact_provenance(
                "recovered_artifact",
                &context,
                Some(node.clone()),
                None,
                Some(selection),
                index
                    .signature_candidates
                    .get(&node.id)
                    .cloned()
                    .unwrap_or_default(),
                &index.nodes_by_id,
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

fn archive_member_ancestor_path(
    node_id: u64,
    nodes_by_id: &HashMap<u64, &Node>,
    archive_member_paths: &HashMap<u64, String>,
) -> Option<String> {
    let mut current_id = node_id;
    let mut visited = HashSet::new();
    loop {
        if !visited.insert(current_id) {
            return None;
        }
        if let Some(path) = archive_member_paths.get(&current_id) {
            return Some(path.clone());
        }
        let node = nodes_by_id.get(&current_id)?;
        current_id = node
            .details
            .get("input_node")
            .and_then(serde_json::Value::as_u64)?;
    }
}

fn signature_candidates(case: &Case) -> HashMap<u64, Vec<Node>> {
    let mut candidates = HashMap::<u64, Vec<Node>>::new();
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
        candidates.entry(input_node).or_default().push(node.clone());
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

fn file_name(number: u64, node: &Node, bytes: &[u8]) -> String {
    let prefix = match node.kind.as_str() {
        "http_body" => "http",
        "ftp_data_candidate" => "ftp",
        _ => "file",
    };
    let extension = workbench::artifact_export::validated_extension(bytes).unwrap_or("bin");
    format!("{number:06}-{prefix}.{extension}")
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
