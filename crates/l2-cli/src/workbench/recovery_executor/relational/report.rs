// Describe frozen relational rules and their limits without repeating source bytes

use super::{REPORT_VERSION, RelationalDiscoveryContext};
use l2_workbench::protocol::{RelationalTransformPlan, RelationalTransformReport};
use serde_json::{Map, Value, json};

pub(super) fn report_json(
    context: &RelationalDiscoveryContext,
    report: &RelationalTransformReport,
    plan: &RelationalTransformPlan,
    supported_rules: usize,
    applied_rules: usize,
    aggregate_parser_checks: &[Value],
    application_evidence_checks: &[Value],
) -> Value {
    let mut fields = Map::new();
    add_cohort_and_membership_fields(&mut fields, context, report, plan);
    add_search_counter_fields(&mut fields, report);
    add_prefix_probe_fields(&mut fields, report);
    add_search_status_fields(&mut fields, report);
    add_search_domain_fields(&mut fields, report, plan);
    add_application_fields(
        &mut fields,
        supported_rules,
        applied_rules,
        aggregate_parser_checks,
        application_evidence_checks,
    );
    Value::Object(fields)
}

fn add_cohort_and_membership_fields(
    fields: &mut Map<String, Value>,
    context: &RelationalDiscoveryContext,
    report: &RelationalTransformReport,
    plan: &RelationalTransformPlan,
) {
    fields.extend([
        ("version".to_owned(), json!(REPORT_VERSION)),
        ("case_scope".to_owned(), json!("current_case")),
        ("claim_scope".to_owned(), json!("bounded_hypothesis_space")),
        ("search_family".to_owned(), json!("sha256_counter_xor")),
        ("parser_scope".to_owned(), json!(plan.parser_scope)),
        ("split_basis".to_owned(), json!(report.split_basis)),
        ("cohort".to_owned(), cohort_json(context)),
        (
            "input_sample_node_ids".to_owned(),
            json!(context.sample_node_ids),
        ),
        (
            "sessions_available".to_owned(),
            json!(context.sessions_available),
        ),
        (
            "omitted_sessions".to_owned(),
            json!(context.omitted_sessions),
        ),
        ("omitted_samples".to_owned(), json!(context.omitted_samples)),
        (
            "source_eligibility_omissions".to_owned(),
            json!(context.source_eligibility_omissions),
        ),
        (
            "input_coverage_complete".to_owned(),
            json!(context.input_coverage_complete),
        ),
        (
            "discovery_sessions".to_owned(),
            json!(
                report
                    .discovery_sessions
                    .iter()
                    .map(|session| session.session)
                    .collect::<Vec<_>>()
            ),
        ),
        (
            "heldout_sessions".to_owned(),
            json!(
                report
                    .heldout_sessions
                    .iter()
                    .map(|session| session.session)
                    .collect::<Vec<_>>()
            ),
        ),
    ]);
    if context.lane == super::RelationalLane::Incremental {
        fields.insert("search_lane".to_owned(), json!("incremental"));
    }
}

fn add_search_counter_fields(fields: &mut Map<String, Value>, report: &RelationalTransformReport) {
    fields.extend([
        (
            "candidate_count_examined".to_owned(),
            json!(report.candidates_examined),
        ),
        (
            "equivalent_candidate_aliases".to_owned(),
            json!(report.equivalent_candidate_aliases),
        ),
        (
            "candidate_count_omitted".to_owned(),
            json!(report.omitted_candidates),
        ),
        (
            "candidate_omitted_count_exact".to_owned(),
            json!(report.omitted_candidates_exact),
        ),
        (
            "candidate_limit_remaining".to_owned(),
            json!(report.candidate_limit_remaining),
        ),
        (
            "locator_candidates_examined".to_owned(),
            json!(report.locator_candidates_examined),
        ),
        (
            "locator_candidate_limit_remaining".to_owned(),
            json!(report.locator_candidate_limit_remaining),
        ),
        ("work_bytes".to_owned(), json!(report.work_bytes)),
        (
            "work_bytes_remaining".to_owned(),
            json!(report.work_bytes_remaining),
        ),
    ]);
}

fn add_prefix_probe_fields(fields: &mut Map<String, Value>, report: &RelationalTransformReport) {
    fields.extend([
        (
            "prefix_probe_hypotheses_examined".to_owned(),
            json!(report.prefix_probe_hypotheses_examined),
        ),
        (
            "prefix_probes_examined".to_owned(),
            json!(report.prefix_probes_examined),
        ),
        (
            "prefix_probe_cache_reuses".to_owned(),
            json!(report.prefix_probe_cache_reuses),
        ),
        (
            "prefix_probe_candidates_with_novelty".to_owned(),
            json!(report.prefix_probe_candidates_with_novelty),
        ),
        (
            "prefix_probe_work_bytes".to_owned(),
            json!(report.prefix_probe_work_bytes),
        ),
        (
            "prefix_probe_complete".to_owned(),
            json!(report.prefix_probe_complete),
        ),
    ]);
}

fn add_search_status_fields(fields: &mut Map<String, Value>, report: &RelationalTransformReport) {
    fields.extend([
        (
            "search_exhaustive_within_plan".to_owned(),
            json!(report.search_exhaustive_within_plan),
        ),
        ("search_limits".to_owned(), json!(report.search_limits)),
    ]);
}

fn add_search_domain_fields(
    fields: &mut Map<String, Value>,
    report: &RelationalTransformReport,
    plan: &RelationalTransformPlan,
) {
    fields.extend([
        ("candidate_domains".to_owned(), candidate_domains_json(plan)),
        ("configured_limits".to_owned(), configured_limits_json(plan)),
        (
            "retained_rules".to_owned(),
            json!(
                report
                    .candidates
                    .iter()
                    .map(candidate_json)
                    .collect::<Vec<_>>()
            ),
        ),
    ]);
}

fn add_application_fields(
    fields: &mut Map<String, Value>,
    supported_rules: usize,
    applied_rules: usize,
    aggregate_parser_checks: &[Value],
    application_evidence_checks: &[Value],
) {
    fields.extend([
        (
            "aggregate_parser_checks".to_owned(),
            json!(aggregate_parser_checks),
        ),
        (
            "application_evidence_checks".to_owned(),
            json!(application_evidence_checks),
        ),
        (
            "output_application".to_owned(),
            json!({
                "supported_rules":supported_rules,
                "applied_rules":applied_rules,
                "uniqueness_established":false,
                "terminal_sequence":"unknown",
            }),
        ),
    ]);
}

fn cohort_json(context: &RelationalDiscoveryContext) -> Value {
    json!({
        "source_id":context.key.source_id,
        "scope_json":context.key.scope_json,
        "endpoints_json":context.key.endpoints_json,
        "direction":context.key.direction,
        "framing_rule_json":context.key.framing_rule_json,
        "record_schema_json":context.key.schema_json,
    })
}

fn candidate_domains_json(plan: &RelationalTransformPlan) -> Value {
    json!({
        "operation_templates":["sha256_counter_xor"],
        "parser_formats":plan.parser_formats.iter().map(|format| format!("{format:?}")).collect::<Vec<_>>(),
        "counter_widths":plan.counter_widths,
        "counter_byte_orders":plan.counter_byte_orders,
        "seed_orders":plan.seed_orders,
        "initial_counters":plan.initial_counters,
        "counter_resets":plan.counter_resets,
    })
}

fn configured_limits_json(plan: &RelationalTransformPlan) -> Value {
    json!({
        "max_cohorts":plan.limits.max_cohorts,
        "max_sessions":plan.limits.max_sessions,
        "max_records_per_session":plan.limits.max_records_per_session,
        "max_record_bytes":plan.limits.max_record_bytes,
        "max_total_bytes":plan.limits.max_total_bytes,
        "max_marker_bytes":plan.limits.max_marker_bytes,
        "max_marker_offset":plan.limits.max_marker_offset,
        "max_seed_bytes":plan.limits.max_seed_bytes,
        "max_locator_offset":plan.limits.max_locator_offset,
        "max_locator_candidates":plan.limits.max_locator_candidates,
        "max_candidates":plan.limits.max_candidates,
        "max_retained_candidates":plan.limits.max_retained_candidates,
        "max_work_bytes":plan.limits.max_work_bytes,
    })
}

fn candidate_json(candidate: &l2_workbench::protocol::RelationalTransformCandidate) -> Value {
    json!({
        "rule":rule_json(&candidate.rule),
        "status":candidate.status,
        "discovery":fit_json(&candidate.discovery),
        "heldout":fit_json(&candidate.heldout),
    })
}

pub(super) fn rule_json(rule: &l2_workbench::protocol::RelationalTransformRule) -> Value {
    json!({
        "seed_locator":locator_summary(&rule.seed_locator),
        "payload_locator":locator_summary(&rule.payload_locator),
        "operation":rule.operation,
        "counter_reset":rule.counter_reset,
        "parser_format":format!("{:?}", rule.parser_format),
        "parser_scope":rule.parser_scope,
    })
}

fn locator_summary(locator: &l2_workbench::protocol::RelationalByteRangeLocator) -> Value {
    json!({
        "coordinate_basis":locator.coordinate_basis,
        "direction":locator.direction,
        "marker_offset":locator.marker_offset,
        "marker_length":locator.marker.len(),
        "value_offset":locator.value_offset,
        "value_length":locator.value_length,
        "declared_length":locator.declared_length.map(|field| json!({
            "offset":field.offset,
            "width":field.width,
            "byte_order":field.byte_order,
        })),
    })
}

#[cfg(test)]
#[path = "../../../../tests/workbench/recovery_relational/report.rs"]
mod tests;

pub(super) fn fit_json(fit: &l2_workbench::protocol::RelationalFit) -> Value {
    json!({
        "status":fit.status,
        "supported_sessions":fit.supported_sessions,
        "contradicted_sessions":fit.contradicted_sessions,
        "unresolved_sessions":fit.unresolved_sessions,
        "checks":fit.checks.iter().map(|check| json!({
            "session":check.session,
            "seed_sample":check.seed_sample,
            "payload_samples":check.payload_samples,
            "status":check.status,
            "output_length":check.output_length,
            "output_sha256":check.output_sha256,
            "falsification":check.falsification.as_ref().map(|failure| format!("{failure:?}")),
        })).collect::<Vec<_>>(),
    })
}

pub(super) fn insufficient_sessions_report(
    context: &RelationalDiscoveryContext,
    plan: &RelationalTransformPlan,
) -> Value {
    let mut report = json!({
        "version":REPORT_VERSION,
        "case_scope":"current_case",
        "claim_scope":"bounded_hypothesis_space",
        "result":"not_eligible_for_independent_session_checks",
        "eligible_for_relational_search":false,
        "independent_corroboration":"unavailable",
        "minimum_independent_sessions":2,
        "sessions_available":context.sessions_available,
        "input_sample_node_ids":context.sample_node_ids,
        "omitted_sessions":context.omitted_sessions,
        "omitted_samples":context.omitted_samples,
        "source_eligibility_omissions":context.source_eligibility_omissions,
        "input_coverage_complete":context.input_coverage_complete,
        "candidate_limit_remaining":plan.limits.max_candidates,
        "locator_candidate_limit_remaining":plan.limits.max_locator_candidates.saturating_mul(2),
        "work_bytes_remaining":plan.limits.max_work_bytes,
        "search_exhaustive_within_plan":null,
        "retained_rules":[],
    });
    if context.lane == super::RelationalLane::Incremental
        && let Some(fields) = report.as_object_mut()
    {
        fields.insert("search_lane".to_owned(), json!("incremental"));
    }
    report
}

pub(super) fn budget_report(
    context: &RelationalDiscoveryContext,
    plan: &RelationalTransformPlan,
    reason: &'static str,
) -> Value {
    let mut report = json!({
        "version":REPORT_VERSION,
        "case_scope":"current_case",
        "claim_scope":"bounded_hypothesis_space",
        "result":"unresolved_on_budget",
        "reason":reason,
        "sessions_available":context.sessions_available,
        "input_sample_node_ids":context.sample_node_ids,
        "candidate_limit_remaining":plan.limits.max_candidates,
        "locator_candidate_limit_remaining":plan.limits.max_locator_candidates.saturating_mul(2),
        "work_bytes_remaining":plan.limits.max_work_bytes,
        "search_exhaustive_within_plan":false,
        "retained_rules":[],
    });
    if context.lane == super::RelationalLane::Incremental
        && let Some(fields) = report.as_object_mut()
    {
        fields.insert("search_lane".to_owned(), json!("incremental"));
    }
    report
}
