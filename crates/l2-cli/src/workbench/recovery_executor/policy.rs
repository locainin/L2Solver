use super::model::TransformExplorationBudget;
use super::{
    DecodeBatchLimits, ExpansionLimits, RecoveryExecutionError, RecoveryExecutionPolicy,
    RecoveryPlan,
    case_scan::{
        CaseScanWorkBounds, RecordDiscoverySnapshot, ScanAdmission, case_scan_work_bounds,
        preflight_scan,
    },
    framing_discovery::{
        FramingDiscoveryPlan, case_max_cohort_input_bytes, case_work_bound, collect_plan,
    },
    record_discovery::{
        RecordDiscoveryPlan, apply_input_limits,
        case_max_cohort_input_bytes as record_case_max_input_bytes,
        case_work_bound as record_case_work_bound, collect_input_plan as collect_record_plan,
    },
};
use l2_workbench::artifact::zip::{
    MAX_ZIP_DEPTH, MAX_ZIP_ENTRIES, MAX_ZIP_ENTRY_EXPANDED_BYTES, MAX_ZIP_TOTAL_EXPANDED_BYTES,
};
use l2_workbench::{
    artifact::{ArtifactValidationPolicy, EmbeddedDiscoveryLimits},
    derivation::DerivationLimits,
    evidence::{Case, MAX_BLOB_TOTAL_BYTES, MAX_EDGES, MAX_NODES},
    measurement::LengthMeaning,
    protocol::{
        ByteField, ByteOrder, FramingKind, IntegerField, ProtocolLimits, RecordCount,
        RecordLengthMeaning, RecordLimits, RecordSchema, RecordSchemaProposalLimits,
    },
    recovery::{
        RecoveryError, RecoveryResourcePolicy, RecoveryTask,
        proposals::{
            TRANSFORM_PROPOSAL_OPERATION_COUNT, TransformProposalBudget,
            transform_proposal_operations, transform_proposal_scan_work_bound,
        },
    },
};
use std::collections::HashMap;
use std::sync::Arc;

const BYTE_SOURCE_KINDS: &[&str] = &[
    "tcp_byte_run",
    "udp_payload",
    "http_body",
    "ftp_data_candidate",
    "imported_source",
    "udp_trailing_bytes",
];

pub(super) fn normal_policy(
    case: &Case,
) -> Result<RecoveryExecutionPolicy, RecoveryExecutionError> {
    let decode_work_bytes = DerivationLimits::default().max_work_bytes;
    let max_input_bytes = case
        .blobs()
        .iter()
        .map(|blob| blob.bytes.len())
        .max()
        .unwrap_or_default()
        .max(MAX_ZIP_TOTAL_EXPANDED_BYTES);
    let scan_bounds = case_scan_work_bounds(case)?;
    let framing_discovery_plan =
        match preflight_scan(scan_bounds.framing, scan_bounds.framing, || {
            let plan = collect_plan(case, ProtocolLimits::default())?;
            let work = super::framing_discovery::scan_work(&plan);
            Ok((Arc::new(plan), work))
        })? {
            ScanAdmission::Scanned { value, .. } => value,
            ScanAdmission::Exhausted { .. } => {
                return Err(RecoveryExecutionError::InvalidPolicy(
                    "framing discovery scan allowance was not available during policy sizing"
                        .into(),
                ));
            }
        };
    let record_schema_proposal_limits = RecordSchemaProposalLimits::default();
    let record_discovery_plan =
        match preflight_scan(scan_bounds.record, scan_bounds.record, || {
            let plan = collect_record_plan(case)?;
            let work = super::record_discovery::scan_work(&plan);
            Ok((Arc::new(plan), work))
        })? {
            ScanAdmission::Scanned { value, .. } => value,
            ScanAdmission::Exhausted { .. } => {
                return Err(RecoveryExecutionError::InvalidPolicy(
                    "record discovery scan allowance was not available during policy sizing".into(),
                ));
            }
        };
    let record_discovery_snapshot =
        Arc::new(RecordDiscoverySnapshot::new(case, record_discovery_plan));
    let sized_record_discovery_plan = apply_input_limits(
        (*record_discovery_snapshot.plan).clone(),
        record_schema_proposal_limits,
    )?;
    let source_work = source_work_profile(
        case,
        max_input_bytes,
        &framing_discovery_plan,
        &sized_record_discovery_plan,
        record_schema_proposal_limits,
        scan_bounds,
    )?;
    build_execution_policy(
        max_input_bytes,
        decode_work_bytes,
        source_work,
        framing_discovery_plan,
        record_discovery_snapshot,
        record_schema_proposal_limits,
    )
}

fn build_execution_policy(
    max_input_bytes: usize,
    decode_work_bytes: usize,
    source_work: SourceWorkProfile,
    framing_discovery_plan: Arc<FramingDiscoveryPlan>,
    record_discovery_snapshot: Arc<RecordDiscoverySnapshot>,
    record_schema_proposal_limits: RecordSchemaProposalLimits,
) -> Result<RecoveryExecutionPolicy, RecoveryExecutionError> {
    let max_output_bytes = MAX_ZIP_TOTAL_EXPANDED_BYTES;
    let default_plan = RecoveryPlan {
        discover_transforms: true,
        discover_framing: true,
        discover_records: true,
        ..RecoveryPlan::default()
    };
    let max_scan_work_bytes_per_input = transform_proposal_scan_work_bound(max_input_bytes)
        .ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy(
                "transform proposal scan allowance cannot be represented".to_owned(),
            )
        })?;
    let embedded_child_tasks = task_templates_for_node(&default_plan, "embedded_artifact", true);
    let expanded_child_tasks = task_templates_for_node(&default_plan, "archive_member", true);
    let embedded_child_input_work = task_input_work(max_output_bytes, &embedded_child_tasks)?;
    let expanded_child_input_work = task_input_work(max_output_bytes, &expanded_child_tasks)?;
    let max_work_bytes = default_work_allowance(
        source_work,
        decode_work_bytes,
        max_output_bytes,
        embedded_child_input_work,
        expanded_child_input_work,
        &embedded_child_tasks,
        &expanded_child_tasks,
    )?;
    let parent_task_multiplicity = embedded_child_tasks
        .len()
        .max(expanded_child_tasks.len())
        .checked_add(TRANSFORM_PROPOSAL_OPERATION_COUNT)
        .ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy(
                "recovery parent-link allowance exceeds this platform's address space".into(),
            )
        })?;
    let resources = default_resource_policy(
        max_input_bytes,
        source_work.max_candidate_bytes,
        max_output_bytes,
        max_work_bytes,
        parent_task_multiplicity,
    )?;
    Ok(RecoveryExecutionPolicy {
        resources,
        derivation_limits: default_derivation_limits(max_input_bytes),
        decode_batch_limits: default_decode_batch_limits(
            max_input_bytes,
            max_work_bytes,
            resources.max_output_bytes,
        ),
        record_limits: default_record_limits(max_input_bytes, resources.max_output_bytes),
        expansion_limits: default_expansion_limits(
            resources.max_depth,
            max_input_bytes,
            resources.max_output_bytes,
            MAX_ZIP_TOTAL_EXPANDED_BYTES,
        ),
        embedded_limits: default_embedded_limits(max_input_bytes, MAX_ZIP_TOTAL_EXPANDED_BYTES),
        artifact_validation_policy: default_validation_policy(
            max_input_bytes,
            MAX_ZIP_TOTAL_EXPANDED_BYTES,
        ),
        transform_exploration: TransformExplorationBudget {
            proposal_budget: TransformProposalBudget {
                max_candidates: TRANSFORM_PROPOSAL_OPERATION_COUNT,
                max_reports: TRANSFORM_PROPOSAL_OPERATION_COUNT,
            },
            max_scan_work_bytes_per_input,
        },
        framing_discovery_plan: Some(framing_discovery_plan),
        record_discovery_snapshot: Some(record_discovery_snapshot),
        record_schema_proposal_limits,
        record_phase_work_limit: source_work.record_phase_work,
    })
}

fn default_work_allowance(
    source: SourceWorkProfile,
    decode_work_bytes: usize,
    max_output_bytes: usize,
    embedded_child_input_work: usize,
    expanded_child_input_work: usize,
    embedded_child_tasks: &[RecoveryTask],
    expanded_child_tasks: &[RecoveryTask],
) -> Result<usize, RecoveryExecutionError> {
    let embedded_parser_work = if embedded_child_tasks.contains(&RecoveryTask::EmbeddedDiscovery) {
        max_output_bytes
    } else {
        0
    };
    let expanded_parser_work = if expanded_child_tasks.contains(&RecoveryTask::RecursiveExpansion) {
        max_output_bytes
    } else {
        0
    };
    checked_work_sum(&[
        source.task_work,
        source.record_phase_work,
        decode_work_bytes,
        source.unique_bytes,
        source.unique_bytes,
        embedded_child_input_work,
        expanded_child_input_work,
        embedded_parser_work,
        expanded_parser_work,
        MAX_ZIP_TOTAL_EXPANDED_BYTES,
        MAX_ZIP_TOTAL_EXPANDED_BYTES,
        MAX_ZIP_TOTAL_EXPANDED_BYTES,
    ])
}

fn default_resource_policy(
    max_input_bytes: usize,
    max_total_input_bytes: usize,
    max_output_bytes: usize,
    max_work_bytes: usize,
    parent_task_multiplicity: usize,
) -> Result<RecoveryResourcePolicy, RecoveryExecutionError> {
    let max_depth = MAX_ZIP_DEPTH;
    // One evidence relationship may feed several independent recovery operations
    let max_parent_links = MAX_EDGES
        .checked_mul(parent_task_multiplicity)
        .ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy(
                "recovery parent-link allowance exceeds this platform's address space".into(),
            )
        })?;
    let max_context_aliases = MAX_NODES
        .checked_mul(parent_task_multiplicity)
        .ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy(
                "recovery context-alias allowance exceeds this platform's address space".into(),
            )
        })?;
    let max_transform_proposal_associations = MAX_NODES
        .checked_mul(TRANSFORM_PROPOSAL_OPERATION_COUNT)
        .ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy(
                "transform-proposal association allowance exceeds this platform's address space"
                    .into(),
            )
        })?
        .min(MAX_EDGES);
    let max_candidate_task_identity_bytes = candidate_task_identity_byte_budget(MAX_NODES)?;
    let max_transform_proposal_identity_bytes =
        transform_proposal_identity_byte_budget(max_transform_proposal_associations)?;
    let max_lineage_work = lineage_work_allowance(MAX_NODES, max_parent_links, max_depth)?;
    Ok(RecoveryResourcePolicy {
        max_candidates: MAX_NODES,
        max_frontier: MAX_NODES,
        max_inputs_per_candidate: MAX_NODES,
        max_origins_per_candidate: MAX_NODES,
        max_input_bytes_per_item: max_input_bytes,
        max_total_input_bytes_per_candidate: max_total_input_bytes,
        max_depth,
        max_output_bytes,
        max_work_bytes,
        max_candidate_task_identity_bytes,
        max_transform_proposal_identity_bytes,
        max_transform_proposal_associations,
        max_parent_links,
        max_lineage_work,
        max_context_aliases,
        max_pending_origin_links: MAX_EDGES,
    })
}

fn candidate_task_identity_byte_budget(
    max_candidates: usize,
) -> Result<usize, RecoveryExecutionError> {
    let tasks = candidate_task_identity_templates();
    let maximum_identity_bytes = maximum_task_identity_bytes(&tasks)?;
    max_candidates
        .checked_mul(maximum_identity_bytes)
        .ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy(
                "candidate task-identity byte allowance exceeds this platform's address space"
                    .into(),
            )
        })
}

fn candidate_task_identity_templates() -> Vec<RecoveryTask> {
    let plan = RecoveryPlan {
        discover_transforms: true,
        discover_framing: true,
        discover_records: true,
        ..RecoveryPlan::default()
    };
    let mut tasks = task_templates_for_node(&plan, "tcp_byte_run", true);
    tasks.extend([
        RecoveryTask::FramingDiscovery,
        RecoveryTask::RecordDiscovery,
    ]);
    tasks.extend(framing_identity_templates());
    tasks.extend(record_identity_templates());
    tasks.extend(transform_proposal_operations().map(RecoveryTask::transform));
    tasks
}

fn framing_identity_templates() -> Vec<RecoveryTask> {
    let mut tasks = vec![
        RecoveryTask::MaterializeFraming(FramingKind::Delimiter { byte: u8::MAX }),
        RecoveryTask::MaterializeFraming(FramingKind::FixedSize { bytes: usize::MAX }),
    ];
    for byte_order in [ByteOrder::BigEndian, ByteOrder::LittleEndian] {
        for meaning in [LengthMeaning::WholeMessage, LengthMeaning::BytesAfterField] {
            tasks.push(RecoveryTask::MaterializeFraming(
                FramingKind::LengthPrefix {
                    offset: usize::MAX,
                    width: 8,
                    byte_order,
                    meaning,
                },
            ));
        }
    }
    tasks
}

fn record_identity_templates() -> Vec<RecoveryTask> {
    let byte_orders = [ByteOrder::BigEndian, ByteOrder::LittleEndian];
    let length_meanings = [
        RecordLengthMeaning::PayloadBytes,
        RecordLengthMeaning::WholeRecord,
        RecordLengthMeaning::BytesAfterLengthField,
    ];
    let mut tasks = Vec::new();
    for count_order in byte_orders {
        let count_field = maximum_integer_field(count_order);
        for count in [
            RecordCount::UntilEnd,
            RecordCount::Exact { records: u64::MAX },
            RecordCount::Field { field: count_field },
        ] {
            for field_order in byte_orders {
                for length_meaning in length_meanings {
                    tasks.push(RecoveryTask::AssembleRecords(maximum_record_schema(
                        count,
                        field_order,
                        length_meaning,
                    )));
                }
            }
        }
    }
    tasks
}

fn transform_proposal_identity_byte_budget(
    max_associations: usize,
) -> Result<usize, RecoveryExecutionError> {
    let mut maximum_identity_bytes = None;
    for operation in transform_proposal_operations() {
        let task = RecoveryTask::transform(operation);
        let identity_bytes = serialized_task_identity_bytes(&task)?;
        maximum_identity_bytes = Some(
            maximum_identity_bytes
                .map_or(identity_bytes, |maximum: usize| maximum.max(identity_bytes)),
        );
    }
    let maximum_identity_bytes = maximum_identity_bytes.ok_or_else(|| {
        RecoveryExecutionError::InvalidPolicy(
            "transform proposal operation templates are empty".into(),
        )
    })?;
    max_associations
        .checked_mul(maximum_identity_bytes)
        .ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy(
                "transform-proposal identity-byte allowance exceeds this platform's address space"
                    .into(),
            )
        })
}

fn maximum_task_identity_bytes(tasks: &[RecoveryTask]) -> Result<usize, RecoveryExecutionError> {
    let mut maximum = None;
    for task in tasks {
        let identity_bytes = serialized_task_identity_bytes(task)?;
        maximum =
            Some(maximum.map_or(identity_bytes, |current: usize| current.max(identity_bytes)));
    }
    maximum.ok_or_else(|| {
        RecoveryExecutionError::InvalidPolicy("recovery task identity templates are empty".into())
    })
}

fn serialized_task_identity_bytes(task: &RecoveryTask) -> Result<usize, RecoveryExecutionError> {
    serde_json::to_vec(task)
        .map(|identity| identity.len())
        .map_err(|error| {
            RecoveryExecutionError::InvalidPolicy(format!(
                "recovery task identity template could not be encoded: {error}"
            ))
        })
}

const fn maximum_integer_field(byte_order: ByteOrder) -> IntegerField {
    IntegerField {
        offset: usize::MAX,
        width: 8,
        byte_order,
    }
}

const fn maximum_record_schema(
    count: RecordCount,
    byte_order: ByteOrder,
    length_meaning: RecordLengthMeaning,
) -> RecordSchema {
    RecordSchema {
        records_offset: usize::MAX,
        count,
        identifier: ByteField {
            offset: usize::MAX,
            width: usize::MAX,
        },
        sequence: maximum_integer_field(byte_order),
        length: maximum_integer_field(byte_order),
        data_offset: usize::MAX,
        length_meaning,
        sequence_base: u64::MAX,
        terminal_sequence: Some(u64::MAX),
    }
}

#[cfg(test)]
#[path = "../../../tests/workbench/recovery_identity_policy.rs"]
mod identity_budget_tests;

fn lineage_work_allowance(
    max_candidates: usize,
    max_parent_links: usize,
    max_depth: usize,
) -> Result<usize, RecoveryExecutionError> {
    // Reserve one worst-case complete lineage scan per allowed depth layer
    max_candidates
        .checked_mul(3)
        .and_then(|candidate_work| {
            max_parent_links
                .checked_mul(2)
                .and_then(|parent_work| candidate_work.checked_add(parent_work))
        })
        .and_then(|per_layer| {
            max_depth
                .checked_add(1)
                .and_then(|layers| per_layer.checked_mul(layers))
        })
        .ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy(
                "recovery lineage-work allowance exceeds this platform's address space".into(),
            )
        })
}

fn default_derivation_limits(max_input_bytes: usize) -> DerivationLimits {
    DerivationLimits {
        max_input_bytes,
        ..DerivationLimits::default()
    }
}

const fn default_decode_batch_limits(
    max_input_bytes: usize,
    max_work_bytes: usize,
    max_output_bytes: usize,
) -> DecodeBatchLimits {
    DecodeBatchLimits {
        items: 1,
        total_input_bytes: max_input_bytes,
        total_work_bytes: max_work_bytes,
        total_output_bytes: max_output_bytes,
        total_report_bytes: MAX_BLOB_TOTAL_BYTES,
    }
}

fn default_record_limits(max_input_bytes: usize, max_output_bytes: usize) -> RecordLimits {
    let mut limits = RecordLimits::default();
    limits.max_input_bytes = max_input_bytes;
    limits.max_output_bytes = limits.max_output_bytes.min(max_output_bytes);
    limits
}

const fn default_expansion_limits(
    depth: usize,
    max_input_bytes: usize,
    max_output_bytes: usize,
    zip_work_bytes: usize,
) -> ExpansionLimits {
    ExpansionLimits {
        depth,
        objects: MAX_NODES,
        input_bytes: max_input_bytes,
        archive_entries: MAX_ZIP_ENTRIES,
        member_bytes: MAX_ZIP_ENTRY_EXPANDED_BYTES,
        zip_work_bytes,
        retained_bytes: max_output_bytes,
    }
}

fn default_embedded_limits(
    max_input_bytes: usize,
    zip_work_bytes: usize,
) -> EmbeddedDiscoveryLimits {
    EmbeddedDiscoveryLimits {
        max_scan_bytes: max_input_bytes,
        max_validation_attempts: MAX_ZIP_ENTRIES,
        max_candidates: MAX_ZIP_ENTRIES,
        png_limits: l2_workbench::artifact::PngLimits {
            max_input_bytes,
            ..l2_workbench::artifact::PngLimits::default()
        },
        zip_limits: l2_workbench::artifact::zip::ZipArtifactLimits {
            max_archive_bytes: max_input_bytes,
            ..l2_workbench::artifact::zip::ZipArtifactLimits::default()
        },
        max_zip_operation_expanded_bytes: zip_work_bytes,
    }
}

fn default_validation_policy(
    max_input_bytes: usize,
    zip_work_bytes: usize,
) -> ArtifactValidationPolicy {
    ArtifactValidationPolicy {
        max_input_bytes,
        png_limits: l2_workbench::artifact::PngLimits {
            max_input_bytes,
            ..l2_workbench::artifact::PngLimits::default()
        },
        zip_limits: l2_workbench::artifact::zip::ZipArtifactLimits {
            max_archive_bytes: max_input_bytes,
            max_total_expanded_bytes: zip_work_bytes,
            ..l2_workbench::artifact::zip::ZipArtifactLimits::default()
        },
        ..ArtifactValidationPolicy::default()
    }
}

pub(super) fn seed_nodes(case: &Case) -> Vec<(u64, String)> {
    let mut nodes = case
        .nodes()
        .iter()
        .filter_map(|node| {
            if !BYTE_SOURCE_KINDS.contains(&node.kind.as_str()) {
                return None;
            }
            let blob = node.blob.as_ref()?;
            Some((
                source_priority(&node.kind)?,
                node.id,
                node.kind.clone(),
                blob.clone(),
            ))
        })
        .collect::<Vec<_>>();
    nodes.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.3.cmp(&right.3))
            .then_with(|| left.1.cmp(&right.1))
    });
    nodes
        .into_iter()
        .map(|(_, node_id, kind, _)| (node_id, kind))
        .collect()
}

pub(super) fn source_priority(kind: &str) -> Option<(u8, u8)> {
    match kind {
        "imported_source" => Some((0, 0)),
        "http_body" => Some((0, 1)),
        "ftp_data_candidate" => Some((0, 2)),
        "tcp_byte_run" => Some((1, 0)),
        "udp_payload" => Some((2, 0)),
        "udp_trailing_bytes" => Some((2, 1)),
        _ => None,
    }
}

pub(super) fn resolve_policy(
    mut policy: RecoveryExecutionPolicy,
) -> Result<RecoveryExecutionPolicy, RecoveryExecutionError> {
    if policy.expansion_limits.depth != policy.resources.max_depth {
        return Err(RecoveryExecutionError::InvalidPolicy(
            "expansion depth must equal the coordinator's absolute maximum depth".to_owned(),
        ));
    }
    policy.derivation_limits.max_output_bytes = policy
        .derivation_limits
        .max_output_bytes
        .min(policy.resources.max_output_bytes);
    policy.decode_batch_limits.total_output_bytes = policy
        .decode_batch_limits
        .total_output_bytes
        .min(policy.resources.max_output_bytes);
    policy.record_limits.max_output_bytes = policy
        .record_limits
        .max_output_bytes
        .min(policy.resources.max_output_bytes);
    policy.expansion_limits.retained_bytes = policy
        .expansion_limits
        .retained_bytes
        .min(policy.resources.max_output_bytes);
    Ok(policy)
}

pub(super) fn task_templates_for_node(
    plan: &RecoveryPlan,
    kind: &str,
    include_expansion: bool,
) -> Vec<RecoveryTask> {
    let mut tasks = Vec::new();
    tasks.extend(plan.recipes.iter().cloned().map(RecoveryTask::Transform));
    if plan.discover_transforms {
        tasks.push(RecoveryTask::TransformDiscovery);
    }
    if kind == "tcp_byte_run" {
        tasks.extend(
            plan.framings
                .iter()
                .cloned()
                .map(RecoveryTask::MaterializeFraming),
        );
    }
    tasks.extend(
        plan.record_schemas
            .iter()
            .cloned()
            .map(RecoveryTask::AssembleRecords),
    );
    tasks.push(RecoveryTask::EmbeddedDiscovery);
    if include_expansion {
        tasks.push(RecoveryTask::RecursiveExpansion);
    }
    tasks.push(RecoveryTask::StructuralValidation);
    let mut unique = Vec::new();
    for task in tasks {
        if !unique.contains(&task) {
            unique.push(task);
        }
    }
    unique
}

fn source_work_profile(
    case: &Case,
    max_input_bytes: usize,
    framing_plan: &FramingDiscoveryPlan,
    record_plan: &RecordDiscoveryPlan,
    record_limits: RecordSchemaProposalLimits,
    scan_bounds: CaseScanWorkBounds,
) -> Result<SourceWorkProfile, RecoveryExecutionError> {
    let node_blobs = case
        .nodes()
        .iter()
        .filter_map(|node| node.blob.as_deref().map(|blob_id| (node.id, blob_id)))
        .collect::<HashMap<_, _>>();
    let blob_lengths = case
        .blobs()
        .iter()
        .map(|blob| (blob.id.as_str(), blob.bytes.len()))
        .collect::<HashMap<_, _>>();
    let plan = RecoveryPlan {
        discover_transforms: true,
        discover_framing: true,
        ..RecoveryPlan::default()
    };
    let mut profile = SourceWorkProfile {
        task_work: 0,
        record_phase_work: 0,
        unique_bytes: 0,
        max_candidate_bytes: max_input_bytes
            .max(case_max_cohort_input_bytes(framing_plan)?)
            .max(record_case_max_input_bytes(record_plan)?),
    };

    accumulate_seed_task_work(case, &plan, &node_blobs, &blob_lengths, &mut profile)?;
    reserve_discovery_phase_work(
        case,
        framing_plan,
        record_plan,
        record_limits,
        scan_bounds,
        &mut profile,
    )?;
    Ok(profile)
}

fn accumulate_seed_task_work(
    case: &Case,
    plan: &RecoveryPlan,
    node_blobs: &HashMap<u64, &str>,
    blob_lengths: &HashMap<&str, usize>,
    profile: &mut SourceWorkProfile,
) -> Result<(), RecoveryExecutionError> {
    let mut scheduled = HashMap::<&str, Vec<RecoveryTask>>::new();
    // Count the same root task identities that the default executor queues
    for (node_id, kind) in seed_nodes(case) {
        let blob_id = node_blobs
            .get(&node_id)
            .copied()
            .ok_or(RecoveryError::UnknownEvidenceNode { node_id })?;
        let input_length = blob_lengths.get(blob_id).copied().ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy(
                "a retained byte-source node references no stored blob".to_owned(),
            )
        })?;
        let scheduled_tasks = scheduled.entry(blob_id).or_default();
        if scheduled_tasks.is_empty() {
            profile.unique_bytes =
                profile
                    .unique_bytes
                    .checked_add(input_length)
                    .ok_or_else(|| {
                        RecoveryExecutionError::InvalidPolicy(
                            "unique source byte work cannot be represented".to_owned(),
                        )
                    })?;
        }
        for task in task_templates_for_node(plan, &kind, true) {
            let context_sensitive = matches!(task, RecoveryTask::TransformDiscovery);
            if !context_sensitive && scheduled_tasks.contains(&task) {
                continue;
            }
            profile.task_work = profile
                .task_work
                .checked_add(task_input_bytes(input_length, &task)?)
                .ok_or_else(|| {
                    RecoveryExecutionError::InvalidPolicy(
                        "fundamental source work cannot be represented".to_owned(),
                    )
                })?;
            if !context_sensitive {
                scheduled_tasks.push(task);
            }
        }
    }
    Ok(())
}

fn reserve_discovery_phase_work(
    case: &Case,
    framing_plan: &FramingDiscoveryPlan,
    record_plan: &RecordDiscoveryPlan,
    record_limits: RecordSchemaProposalLimits,
    scan_bounds: CaseScanWorkBounds,
    profile: &mut SourceWorkProfile,
) -> Result<(), RecoveryExecutionError> {
    let framing_work =
        case_work_bound(framing_plan, ProtocolLimits::default())?.max(scan_bounds.framing);
    profile.task_work = profile.task_work.checked_add(framing_work).ok_or_else(|| {
        RecoveryExecutionError::InvalidPolicy(
            "Case-wide framing discovery work cannot be represented".to_owned(),
        )
    })?;
    let initial_record_work =
        record_case_work_bound(record_plan, record_limits)?.max(scan_bounds.record);
    let post_framing_record_work = super::framing_discovery::post_framing_record_phase_work_bound(
        case,
        framing_plan,
        ProtocolLimits::default(),
        record_limits,
        MAX_ZIP_TOTAL_EXPANDED_BYTES,
    )?;
    profile.record_phase_work = initial_record_work
        .checked_add(post_framing_record_work)
        .ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy(
                "record discovery phase work cannot be represented".to_owned(),
            )
        })?;
    Ok(())
}

fn task_input_work(
    bytes_per_input: usize,
    tasks: &[RecoveryTask],
) -> Result<usize, RecoveryExecutionError> {
    tasks.iter().try_fold(0_usize, |total, task| {
        total
            .checked_add(task_input_bytes(bytes_per_input, task)?)
            .ok_or_else(|| {
                RecoveryExecutionError::InvalidPolicy(
                    "scheduled child input work cannot be represented".to_owned(),
                )
            })
    })
}

fn task_input_bytes(
    input_bytes: usize,
    task: &RecoveryTask,
) -> Result<usize, RecoveryExecutionError> {
    let assessment_bytes = if matches!(task, RecoveryTask::TransformDiscovery) {
        transform_proposal_scan_work_bound(input_bytes).ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy(
                "transform proposal scan work cannot be represented".to_owned(),
            )
        })?
    } else {
        0
    };
    input_bytes.checked_add(assessment_bytes).ok_or_else(|| {
        RecoveryExecutionError::InvalidPolicy(
            "scheduled input work cannot be represented".to_owned(),
        )
    })
}

fn checked_work_sum(parts: &[usize]) -> Result<usize, RecoveryExecutionError> {
    parts.iter().try_fold(0_usize, |total, part| {
        total.checked_add(*part).ok_or_else(|| {
            RecoveryExecutionError::InvalidPolicy(
                "default work ceiling cannot represent all scheduled passes".to_owned(),
            )
        })
    })
}

#[derive(Clone, Copy)]
struct SourceWorkProfile {
    task_work: usize,
    record_phase_work: usize,
    unique_bytes: usize,
    max_candidate_bytes: usize,
}
