use super::{
    DecodeBatchLimits, ExpansionLimits, case_scan::RecordDiscoverySnapshot,
    framing_discovery::FramingDiscoveryPlan,
};
#[cfg(test)]
use l2_workbench::recovery::RecoveryCandidate;
use l2_workbench::{
    artifact::{
        ArtifactResourceOmissionReason, ArtifactValidationPolicy, EmbeddedDiscoveryLimits,
        EmbeddedDiscoveryOmissions,
    },
    derivation::{DerivationLimits, Recipe},
    evidence::EvidenceError,
    protocol::{FramingKind, RecordError, RecordLimits, RecordSchema, RecordSchemaProposalLimits},
    recovery::{
        RecoveryError, RecoveryResource, RecoveryResourcePolicy, RecoveryResult, RecoveryStage,
        RecoveryTask, proposals::TransformProposalBudget,
    },
};
use serde_json::Value;
use std::{collections::BTreeMap, error::Error, fmt, sync::Arc};

/// Exact caller-selected recovery operations, independent of evidence node identifiers
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct RecoveryPlan {
    /// Ordered canonical transformations; recipe step order is preserved
    pub(super) recipes: Vec<Recipe>,
    /// Exact caller-selected frame boundaries
    pub(super) framings: Vec<FramingKind>,
    /// Exact caller-selected record layouts
    pub(super) record_schemas: Vec<RecordSchema>,
    /// Enable syntax-gated proposals during default recursive recovery
    pub(super) discover_transforms: bool,
    /// Infer framing hypotheses from each retained capture source's TCP runs
    pub(super) discover_framing: bool,
    /// Propose record schemas only from frames materialized before this recovery pass
    pub(super) discover_records: bool,
}

/// Bounded syntax assessment work and retained proposal evidence
#[derive(Clone, Copy)]
pub(super) struct TransformExplorationBudget {
    /// Limits for retained canonical candidates and per-operation reports
    pub(super) proposal_budget: TransformProposalBudget,
    /// Maximum assessment scan work for one input
    pub(super) max_scan_work_bytes_per_input: usize,
}

/// Typed resource values passed to every recovery stage
#[derive(Clone)]
pub(super) struct RecoveryExecutionPolicy {
    /// Shared candidate, depth, origin, output, and work ceilings
    pub(super) resources: RecoveryResourcePolicy,
    /// Per-recipe derivation bounds
    pub(super) derivation_limits: DerivationLimits,
    /// Aggregate bounds for one exact recipe application
    pub(super) decode_batch_limits: DecodeBatchLimits,
    /// Per-schema record parsing and assembly bounds
    pub(super) record_limits: RecordLimits,
    /// Recursive artifact parsing and retention bounds
    pub(super) expansion_limits: ExpansionLimits,
    /// Embedded-object scan and parser bounds
    pub(super) embedded_limits: EmbeddedDiscoveryLimits,
    /// Structural artifact parser bounds
    pub(super) artifact_validation_policy: ArtifactValidationPolicy,
    /// Limits for syntax-gated transform proposal work and evidence retention
    pub(super) transform_exploration: TransformExplorationBudget,
    /// Case-scoped framing plan reused after policy sizing
    pub(super) framing_discovery_plan: Option<Arc<FramingDiscoveryPlan>>,
    /// Record plan and exact scan work collected while sizing this policy
    pub(super) record_discovery_snapshot: Option<Arc<RecordDiscoverySnapshot>>,
    /// Bounds for automatic record-field proposal and strict candidate validation
    pub(super) record_schema_proposal_limits: RecordSchemaProposalLimits,
    /// Bounded session-relative transform family tested after record assembly
    pub(super) relational_transform_plan: l2_workbench::protocol::RelationalTransformPlan,
    /// Additional relational domain searched after the normal recovery work drains
    pub(super) relational_incremental_plan: Option<l2_workbench::protocol::RelationalTransformPlan>,
    /// Immutable work reservation for the post-framing record phase
    pub(super) record_phase_work_limit: usize,
}

/// Explicit work or format omissions recorded during one recovery run
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryOmission {
    /// A typed coordinator budget prevented work or result retention
    ResourceExhausted {
        task: RecoveryTask,
        input_node_ids: Vec<u64>,
        resource: RecoveryResource,
        limit: usize,
        used: usize,
        requested: usize,
    },
    /// Transform proposal pairs were truncated at the shared association ceiling
    TransformProposalAssociations {
        report_node_id: u64,
        input_node_id: u64,
        used: usize,
        limit: usize,
        requested: usize,
        omitted_count: usize,
    },
    /// Candidate or assessment details omitted from a transform proposal report
    TransformDiscoveryAnalysis {
        input_node_id: u64,
        omitted_candidates: usize,
        omitted_reports: usize,
    },
    /// TCP runs could not be included in an automatic framing discovery cohort
    FramingDiscoveryInputs {
        source_id: Option<String>,
        omitted_runs: usize,
        reason_counts: BTreeMap<&'static str, usize>,
    },
    /// Framing discovery omitted search work or retained report details
    FramingDiscoveryAnalysis {
        source_id: String,
        search_exhaustive_within_plan: bool,
        report_details_complete: bool,
        omitted_candidates: usize,
        omitted_hypothesis_details: usize,
        omitted_candidate_details: usize,
        omitted_alias_candidates: usize,
        detail_incomplete_runs: usize,
        omitted_frame_examples: usize,
    },
    /// The retained framing receipt omitted per-run or hypothesis detail to meet its byte ceiling
    FramingDiscoveryReportDetails {
        source_id: String,
        omitted_input_runs: usize,
        omitted_hypotheses: usize,
    },
    /// Materialized frames were excluded because their provenance was invalid or ambiguous
    RecordDiscoveryInputs {
        source_id: Option<String>,
        omitted_frames: usize,
        reason_counts: BTreeMap<&'static str, usize>,
        examples: Vec<Value>,
    },
    /// Record schema proposal or strict validation work was incomplete under selected limits
    RecordDiscoveryAnalysis {
        source_id: String,
        search_exhaustive_within_plan: bool,
        report_details_complete: bool,
        omitted_candidates: Option<usize>,
        omitted_survivors: usize,
        omitted_falsification_examples: usize,
        omitted_field_checks: usize,
        omitted_pair_checks: usize,
        omitted_length_checks: usize,
    },
    /// Additional relational views for this Case were discarded before wider discovery
    RelationalIncrementalMetadata { limit: usize, reason: &'static str },
    /// Relational transform work or report details were bounded or lacked eligible sessions
    RelationalTransformAnalysis {
        source_id: String,
        sessions_available: usize,
        omitted_sessions: usize,
        omitted_samples: usize,
        omitted_rules: usize,
        candidate_limit_remaining: usize,
        locator_candidate_limit_remaining: usize,
        work_bytes_remaining: usize,
        input_coverage_complete: bool,
        search_exhaustive_within_plan: bool,
        report_details_complete: bool,
        reason: Option<&'static str>,
    },
    /// Full record discovery frame descriptors and schema details were omitted from the compact summary
    RecordDiscoveryReportDetails {
        source_id: String,
        omitted_input_frames: usize,
        omitted_schema_proposals: usize,
        omitted_surviving_schemas: usize,
        omitted_falsification_details: usize,
    },
    /// Embedded discovery retained less work than its caller-selected limits allowed
    EmbeddedDiscovery {
        input_node_id: u64,
        omissions: EmbeddedDiscoveryOmissions,
    },
    /// Recursive expansion recorded an explicit parser or resource omission
    ArtifactExpansion {
        input_node_id: u64,
        created_node_count: usize,
    },
    /// Structural validation could not complete under its selected policy
    ArtifactValidation {
        input_node_id: u64,
        reason: ArtifactResourceOmissionReason,
    },
    /// A record parser or output limit prevented a complete exact result
    RecordService {
        input_node_ids: Vec<u64>,
        error: RecordError,
    },
    /// One exact record input contradicted the supplied strict schema
    RecordInputRejected {
        input_index: usize,
        input_node_id: u64,
        error: RecordError,
    },
    /// A rejected or incomplete transform slot was excluded from its sibling record batch
    SiblingTransformExcluded {
        input_node_id: u64,
        task: RecoveryTask,
        result: RecoveryResult,
    },
    /// A task stopped at its explicit per-stage work ceiling
    StageWorkLimit {
        task: RecoveryTask,
        input_node_ids: Vec<u64>,
        limit: usize,
        work_bytes: usize,
    },
    /// A recipe stopped at its explicit per-stage output ceiling
    StageOutputLimit {
        task: RecoveryTask,
        input_node_ids: Vec<u64>,
        limit: usize,
        requested: usize,
    },
}

impl fmt::Display for RecoveryOmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RelationalIncrementalMetadata { limit, reason } => write!(
                formatter,
                "incremental relational metadata for this Case was omitted ({reason}; budget {limit} bytes)"
            ),
            Self::FramingDiscoveryInputs { .. }
            | Self::FramingDiscoveryAnalysis { .. }
            | Self::FramingDiscoveryReportDetails { .. }
            | Self::RecordDiscoveryInputs { .. }
            | Self::RecordDiscoveryAnalysis { .. }
            | Self::RecordDiscoveryReportDetails { .. } => format_framing_omission(formatter, self),
            Self::RelationalTransformAnalysis { .. } => format_relational_analysis(formatter, self),
            Self::TransformDiscoveryAnalysis { .. } => {
                format_transform_discovery_analysis(formatter, self)
            }
            Self::ResourceExhausted { .. }
            | Self::TransformProposalAssociations { .. }
            | Self::StageWorkLimit { .. }
            | Self::StageOutputLimit { .. } => format_budget_omission(formatter, self),
            _ => format_content_omission(formatter, self),
        }
    }
}

fn format_framing_omission(
    formatter: &mut fmt::Formatter<'_>,
    omission: &RecoveryOmission,
) -> fmt::Result {
    match omission {
        RecoveryOmission::FramingDiscoveryInputs {
            source_id,
            omitted_runs,
            reason_counts,
        } => format_framing_inputs(
            formatter,
            source_id.as_deref(),
            *omitted_runs,
            reason_counts,
        ),
        RecoveryOmission::FramingDiscoveryAnalysis { .. } => {
            format_framing_analysis(formatter, omission)
        }
        RecoveryOmission::FramingDiscoveryReportDetails {
            source_id,
            omitted_input_runs,
            omitted_hypotheses,
        } => format_framing_report_details(
            formatter,
            source_id,
            *omitted_input_runs,
            *omitted_hypotheses,
        ),
        RecoveryOmission::RecordDiscoveryInputs { .. }
        | RecoveryOmission::RecordDiscoveryAnalysis { .. }
        | RecoveryOmission::RecordDiscoveryReportDetails { .. } => {
            format_record_discovery_omission(formatter, omission)
        }
        _ => Err(fmt::Error),
    }
}

fn format_record_discovery_omission(
    formatter: &mut fmt::Formatter<'_>,
    omission: &RecoveryOmission,
) -> fmt::Result {
    match omission {
        RecoveryOmission::RecordDiscoveryInputs {
            source_id,
            omitted_frames,
            reason_counts,
            examples,
        } => {
            let omitted_examples = omitted_frames
                .checked_sub(examples.len())
                .ok_or(fmt::Error)?;
            write!(
                formatter,
                "record discovery for source {} omitted {omitted_frames} materialized frames with reason counts {reason_counts:?} ({} examples retained, {omitted_examples} examples not retained)",
                source_id.as_deref().unwrap_or("unresolved"),
                examples.len()
            )
        }
        RecoveryOmission::RecordDiscoveryAnalysis {
            source_id,
            search_exhaustive_within_plan,
            report_details_complete,
            omitted_candidates,
            omitted_survivors,
            omitted_falsification_examples,
            omitted_field_checks,
            omitted_pair_checks,
            omitted_length_checks,
        } => write!(
            formatter,
            "record discovery for source {source_id} searched {} of its plan and retained {} report details ({} schema candidates, {omitted_survivors} survivors, {omitted_falsification_examples} falsifications, {omitted_field_checks} field, {omitted_pair_checks} pair, and {omitted_length_checks} length checks omitted)",
            if *search_exhaustive_within_plan {
                "all"
            } else {
                "part"
            },
            if *report_details_complete {
                "all"
            } else {
                "some"
            },
            omitted_candidates.map_or_else(
                || "an unknown number of".to_owned(),
                |count| count.to_string()
            )
        ),
        RecoveryOmission::RecordDiscoveryReportDetails {
            source_id,
            omitted_input_frames,
            omitted_schema_proposals,
            omitted_surviving_schemas,
            omitted_falsification_details,
        } => write!(
            formatter,
            "record discovery report for source {source_id} retained compact frame references and omitted {omitted_input_frames} full input-frame descriptors, {omitted_schema_proposals} proposal detail sets, {omitted_surviving_schemas} survivor details, and {omitted_falsification_details} falsification details"
        ),
        _ => Err(fmt::Error),
    }
}

fn format_transform_discovery_analysis(
    formatter: &mut fmt::Formatter<'_>,
    omission: &RecoveryOmission,
) -> fmt::Result {
    let RecoveryOmission::TransformDiscoveryAnalysis {
        input_node_id,
        omitted_candidates,
        omitted_reports,
    } = omission
    else {
        return Err(fmt::Error);
    };
    write!(
        formatter,
        "transform discovery for input node {input_node_id} omitted {omitted_candidates} eligible candidates and {omitted_reports} operation assessments"
    )
}

fn format_budget_omission(
    formatter: &mut fmt::Formatter<'_>,
    omission: &RecoveryOmission,
) -> fmt::Result {
    match omission {
        RecoveryOmission::ResourceExhausted {
            task,
            input_node_ids,
            resource,
            limit,
            used,
            requested,
        } => format_resource_exhausted(
            formatter,
            task,
            input_node_ids,
            *resource,
            *limit,
            *used,
            *requested,
        ),
        RecoveryOmission::TransformProposalAssociations {
            report_node_id,
            input_node_id,
            used,
            limit,
            requested,
            omitted_count,
        } => write!(
            formatter,
            "transform proposal report {report_node_id} on input node {input_node_id} retained {used} of {limit} associations before omitting {omitted_count} proposal pairs (request size {requested})"
        ),
        RecoveryOmission::StageWorkLimit {
            task,
            input_node_ids,
            limit,
            work_bytes,
        } => format_stage_work_limit(formatter, task, input_node_ids, *limit, *work_bytes),
        RecoveryOmission::StageOutputLimit {
            task,
            input_node_ids,
            limit,
            requested,
        } => format_stage_output_limit(formatter, task, input_node_ids, *limit, *requested),
        _ => Err(fmt::Error),
    }
}

fn format_content_omission(
    formatter: &mut fmt::Formatter<'_>,
    omission: &RecoveryOmission,
) -> fmt::Result {
    match omission {
        RecoveryOmission::EmbeddedDiscovery {
            input_node_id,
            omissions,
        } => write!(
            formatter,
            "embedded discovery on input node {input_node_id} was partial ({} candidates omitted, {} validations omitted, {} ZIP entry-count limits, unscanned range: {})",
            omissions.output_candidate_count,
            omissions.unvalidated_candidate_count,
            omissions.zip_entry_count_limited,
            omissions.unscanned_range.is_some()
        ),
        RecoveryOmission::ArtifactExpansion {
            input_node_id,
            created_node_count,
        } => write!(
            formatter,
            "recursive artifact expansion on input node {input_node_id} was partial after retaining {created_node_count} nodes"
        ),
        RecoveryOmission::ArtifactValidation {
            input_node_id,
            reason,
        } => write!(
            formatter,
            "structural validation on input node {input_node_id} was omitted ({reason:?})"
        ),
        RecoveryOmission::RecordService {
            input_node_ids,
            error,
        } => write!(
            formatter,
            "record assembly on input nodes {input_node_ids:?} was omitted ({error})"
        ),
        RecoveryOmission::RecordInputRejected {
            input_index,
            input_node_id,
            error,
        } => write!(
            formatter,
            "record input {input_index} (node {input_node_id}) was excluded by the strict schema ({error})"
        ),
        RecoveryOmission::SiblingTransformExcluded {
            input_node_id,
            task,
            result,
        } => write!(
            formatter,
            "{} on sibling input node {input_node_id} produced no record-batch output ({})",
            task_label(task),
            result_label(result)
        ),
        _ => Err(fmt::Error),
    }
}

fn format_relational_analysis(
    formatter: &mut fmt::Formatter<'_>,
    omission: &RecoveryOmission,
) -> fmt::Result {
    let RecoveryOmission::RelationalTransformAnalysis {
        source_id,
        sessions_available,
        omitted_sessions,
        omitted_samples,
        omitted_rules,
        candidate_limit_remaining,
        locator_candidate_limit_remaining,
        work_bytes_remaining,
        input_coverage_complete,
        search_exhaustive_within_plan,
        report_details_complete,
        reason,
    } = omission
    else {
        return Err(fmt::Error);
    };
    write!(
        formatter,
        "relational analysis for source {source_id} checked {sessions_available} sessions; remaining budgets: {candidate_limit_remaining} candidates, {locator_candidate_limit_remaining} locators, {work_bytes_remaining} work bytes; omitted {omitted_sessions} sessions, {omitted_samples} samples, and {omitted_rules} supported rules from output application; coverage {}, search {}, report details {}{}",
        if *input_coverage_complete {
            "complete"
        } else {
            "partial"
        },
        if *search_exhaustive_within_plan {
            "exhaustive within plan"
        } else {
            "bounded or incomplete"
        },
        if *report_details_complete {
            "complete"
        } else {
            "compact"
        },
        reason.map_or_else(String::new, |reason| format!(" ({reason})")),
    )
}

fn format_framing_inputs(
    formatter: &mut fmt::Formatter<'_>,
    source_id: Option<&str>,
    omitted_runs: usize,
    reason_counts: &BTreeMap<&'static str, usize>,
) -> fmt::Result {
    write!(
        formatter,
        "framing discovery for source {} omitted {omitted_runs} TCP runs by reason {reason_counts:?}",
        source_id.unwrap_or("unresolved")
    )
}

fn format_framing_analysis(
    formatter: &mut fmt::Formatter<'_>,
    omission: &RecoveryOmission,
) -> fmt::Result {
    let RecoveryOmission::FramingDiscoveryAnalysis {
        source_id,
        search_exhaustive_within_plan,
        report_details_complete,
        omitted_candidates,
        omitted_hypothesis_details,
        omitted_candidate_details,
        omitted_alias_candidates,
        detail_incomplete_runs,
        omitted_frame_examples,
    } = omission
    else {
        return Err(fmt::Error);
    };
    write!(
        formatter,
        "framing discovery for source {source_id} searched {} of its plan; report detail retention was {} ({omitted_candidates} candidates not evaluated, {omitted_hypothesis_details} hypothesis details, {omitted_candidate_details} candidate details, {omitted_alias_candidates} alias references, and {omitted_frame_examples} frame previews omitted across {detail_incomplete_runs} runs)",
        if *search_exhaustive_within_plan {
            "all"
        } else {
            "part"
        },
        if *report_details_complete {
            "complete"
        } else {
            "incomplete"
        }
    )
}

fn format_framing_report_details(
    formatter: &mut fmt::Formatter<'_>,
    source_id: &str,
    omitted_input_runs: usize,
    omitted_hypotheses: usize,
) -> fmt::Result {
    write!(
        formatter,
        "framing discovery report for source {source_id} omitted details for {omitted_input_runs} runs and {omitted_hypotheses} hypotheses to fit its byte limit"
    )
}

fn format_resource_exhausted(
    formatter: &mut fmt::Formatter<'_>,
    task: &RecoveryTask,
    input_node_ids: &[u64],
    resource: RecoveryResource,
    limit: usize,
    used: usize,
    requested: usize,
) -> fmt::Result {
    write!(
        formatter,
        "{} for input nodes {input_node_ids:?} stopped at the {} limit {limit} (used {used}, requested {requested})",
        task_label(task),
        resource_label(resource)
    )
}

fn format_stage_work_limit(
    formatter: &mut fmt::Formatter<'_>,
    task: &RecoveryTask,
    input_node_ids: &[u64],
    limit: usize,
    work_bytes: usize,
) -> fmt::Result {
    write!(
        formatter,
        "{} for input nodes {input_node_ids:?} used {work_bytes} bytes and reached the stage work limit {limit}",
        task_label(task)
    )
}

fn format_stage_output_limit(
    formatter: &mut fmt::Formatter<'_>,
    task: &RecoveryTask,
    input_node_ids: &[u64],
    limit: usize,
    requested: usize,
) -> fmt::Result {
    write!(
        formatter,
        "{} for input nodes {input_node_ids:?} requested {requested} output bytes and reached the stage output limit {limit}",
        task_label(task)
    )
}

const fn result_label(result: &RecoveryResult) -> &'static str {
    match result {
        RecoveryResult::ObservedValidation { .. } => "validated",
        RecoveryResult::Derived { .. } => "derived",
        RecoveryResult::Hypothesis { .. } => "unresolved",
        RecoveryResult::Rejected { .. } => "rejected",
        RecoveryResult::Unsupported => "unsupported",
        RecoveryResult::Omitted => "omitted",
        RecoveryResult::ResourceExhausted { .. } => "resource limit",
    }
}

const fn task_label(task: &RecoveryTask) -> &'static str {
    match task {
        RecoveryTask::Transform(_) => "transform",
        RecoveryTask::TransformDiscovery => "transform discovery",
        RecoveryTask::MaterializeFraming(_) => "framing materialization",
        RecoveryTask::AssembleRecords(_) => "record assembly",
        RecoveryTask::EmbeddedDiscovery => "embedded discovery",
        RecoveryTask::RecursiveExpansion => "recursive artifact expansion",
        RecoveryTask::StructuralValidation => "structural validation",
        RecoveryTask::FramingDiscovery => "framing discovery",
        RecoveryTask::RecordDiscovery => "record discovery",
        RecoveryTask::RelationalTransformDiscovery => "relational transform discovery",
        RecoveryTask::RelationalTransformDiscoveryIncremental => {
            "incremental relational transform discovery"
        }
    }
}

const fn resource_label(resource: RecoveryResource) -> &'static str {
    match resource {
        RecoveryResource::CandidateCount => "candidate count",
        RecoveryResource::FrontierCount => "pending queue",
        RecoveryResource::InputCount => "input count",
        RecoveryResource::OriginCount => "origin count",
        RecoveryResource::InputBytesPerItem => "input byte",
        RecoveryResource::TotalInputBytes => "total input byte",
        RecoveryResource::OutputBytes => "output byte",
        RecoveryResource::WorkBytes => "work byte",
        RecoveryResource::TransformProposalAssociations => "transform-proposal association",
        RecoveryResource::CandidateTaskIdentityBytes => "candidate task-identity byte",
        RecoveryResource::TransformProposalIdentityBytes => "transform-proposal identity byte",
        RecoveryResource::EvidenceEdges => "evidence edge",
        RecoveryResource::EvidenceNodes => "evidence node",
        RecoveryResource::EvidenceBlobs => "evidence blob",
        RecoveryResource::EvidenceBlobBytes => "evidence blob byte",
        RecoveryResource::EvidenceTotalDetailsBytes => "evidence details byte",
        RecoveryResource::EvidenceSourceRanges => "evidence source range",
        RecoveryResource::EvidenceLimitations => "evidence limitation",
        RecoveryResource::ParentLinks => "parent link",
        RecoveryResource::LineageWork => "lineage and queue-entry work unit",
        RecoveryResource::RecursionDepth => "recursion depth",
        RecoveryResource::ContextAliases => "context alias",
        RecoveryResource::PendingOriginLinks => "pending origin link",
    }
}

/// Terminal recovery evidence and the unique validated byte objects for later publication
#[derive(Debug)]
pub(super) struct RecoveryExecutionOutcome {
    /// One completed coordinator entry for every accepted task identity
    #[cfg(test)]
    pub candidates: Vec<RecoveryCandidate>,
    /// Number of accepted task identities
    pub candidate_count: usize,
    /// Complete transform searches that found no eligible recipes
    pub complete_negative_transform_searches: usize,
    /// Unique retained byte objects with a successful structural validation result
    pub validated_artifact_count: usize,
    /// Caller-visible work, format, and resource omissions
    pub omissions: Vec<RecoveryOmission>,
    /// Number of reversible paths suppressed by the coordinator's fixed-point check
    pub cycle_skips: usize,
    /// Configured ceilings and work remaining at the fixed point
    pub(super) resources: RecoveryResourceSummary,
    /// Whether the declared work drained without omissions or prior Case incompleteness
    #[cfg(test)]
    pub complete: bool,
}

/// Concise recovery facts required by case-wide artifact collection
#[derive(Debug)]
pub struct RecoveryRunSummary {
    /// Whether the Case retained every collection and retention result recorded so far
    pub case_evidence_collection_complete: bool,
    /// Independent coverage, search, and report-detail facts for discovery stages
    pub discovery: RecoveryDiscoveryStatus,
    pub omissions: Vec<RecoveryOmission>,
    pub candidate_count: usize,
    /// Complete transform searches that found no eligible recipes
    pub complete_negative_transform_searches: usize,
    pub validated_artifact_count: usize,
    pub cycle_skips: usize,
    pub resources: RecoveryResourceSummary,
}

/// Independent status facts retained for automatic recovery discovery
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryDiscoveryStatus {
    /// Whether every candidate framing run and record frame fit its discovery inputs
    pub input_coverage_complete: bool,
    /// Whether framing, record, and transform proposal discovery exhausted their declared plans
    pub search_exhaustive_within_plan: bool,
    /// Whether each retained discovery report kept all available details
    pub report_details_complete: bool,
}

/// Configured ceilings and actual shared work use for one recovery run
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryResourceSummary {
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
    pub max_work_bytes: usize,
    pub work_charged_bytes: usize,
    pub work_remaining_bytes: usize,
    /// Maximum logical work for the retained Case index over its full validated lifetime
    pub max_case_index_work_units: usize,
    /// Logical field-inspection and seed-ordering work charged to the retained Case index
    pub case_index_work_units_charged: usize,
    /// Unspent retained-index work allowance
    pub case_index_work_units_remaining: usize,
    /// Immutable allowance reserved for post-framing record discovery and assembly
    pub max_record_phase_work: usize,
    /// Record-phase graph scans, proposals, parsing, reports, and assembly work already charged
    pub record_phase_work_charged: usize,
    /// Unspent portion of the record-phase allowance
    pub record_phase_work_remaining: usize,
    /// Maximum serialized task-identity bytes retained across candidates
    pub max_candidate_task_identity_bytes: usize,
    /// Serialized task-identity bytes currently retained across candidates
    pub candidate_task_identity_bytes_charged: usize,
    /// Unspent candidate task-identity byte allowance
    pub candidate_task_identity_bytes_remaining: usize,
    /// Maximum canonical recipe-identity bytes retained for transform proposals
    pub max_transform_proposal_identity_bytes: usize,
    /// Canonical recipe-identity bytes currently retained for transform proposals
    pub transform_proposal_identity_bytes_charged: usize,
    /// Unspent transform-proposal identity byte allowance
    pub transform_proposal_identity_bytes_remaining: usize,
    pub max_transform_proposal_associations: usize,
    pub transform_proposal_associations_charged: usize,
    pub transform_proposal_associations_remaining: usize,
    pub max_parent_links: usize,
    pub parent_links_retained: usize,
    pub parent_links_remaining: usize,
    /// Maximum cycle-analysis visits and queue entries inspected or shifted
    pub max_lineage_work: usize,
    /// Cycle-analysis visits and queue entries inspected or shifted
    pub lineage_work_charged: usize,
    /// Unspent cycle-analysis and queue-entry work units
    pub lineage_work_remaining: usize,
    pub max_context_aliases: usize,
    pub context_aliases_retained: usize,
    pub context_aliases_remaining: usize,
    pub max_pending_origin_links: usize,
    pub pending_origin_links_retained: usize,
    pub pending_origin_links_remaining: usize,
    pub max_depth: usize,
}

/// Failure that prevented one requested recovery run from completing
#[derive(Debug)]
pub enum RecoveryExecutionError {
    /// The supplied stage budgets cannot safely share one recovery policy
    InvalidPolicy(String),
    /// The coordinator rejected an invalid evidence or queue transition
    Coordinator(RecoveryError),
    /// A shared recovery job could not continue or record progress
    Job(l2_workbench::job::JobError),
    /// A relational discovery or exact rule replay failed
    Relational(l2_workbench::protocol::RelationalTransformError),
    /// A checked case evidence write failed
    Evidence(EvidenceError),
    /// A reusable operation failed outside speculative format rejection
    Operational {
        stage: RecoveryStage,
        source: Box<dyn Error>,
    },
}

impl fmt::Display for RecoveryExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy(reason) => write!(formatter, "invalid recovery policy: {reason}"),
            Self::Coordinator(error) => write!(formatter, "recovery coordinator failed: {error}"),
            Self::Job(error) => write!(formatter, "recovery job failed: {error}"),
            Self::Relational(error) => write!(formatter, "relational recovery failed: {error}"),
            Self::Evidence(error) => write!(formatter, "recovery evidence write failed: {error}"),
            Self::Operational { stage, source } => {
                write!(formatter, "{stage:?} operation failed: {source}")
            }
        }
    }
}

impl Error for RecoveryExecutionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidPolicy(_) => None,
            Self::Coordinator(error) => Some(error),
            Self::Job(error) => Some(error),
            Self::Relational(error) => Some(error),
            Self::Evidence(error) => Some(error),
            Self::Operational { source, .. } => Some(source.as_ref()),
        }
    }
}

impl From<RecoveryError> for RecoveryExecutionError {
    fn from(error: RecoveryError) -> Self {
        Self::Coordinator(error)
    }
}

impl From<l2_workbench::job::JobError> for RecoveryExecutionError {
    fn from(error: l2_workbench::job::JobError) -> Self {
        Self::Job(error)
    }
}

impl From<l2_workbench::protocol::RelationalTransformError> for RecoveryExecutionError {
    fn from(error: l2_workbench::protocol::RelationalTransformError) -> Self {
        Self::Relational(error)
    }
}

impl From<EvidenceError> for RecoveryExecutionError {
    fn from(error: EvidenceError) -> Self {
        Self::Evidence(error)
    }
}
