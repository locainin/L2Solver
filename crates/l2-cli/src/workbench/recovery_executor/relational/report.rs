// Describe frozen relational rules and their limits without repeating source bytes

use super::{REPORT_VERSION, RelationalDiscoveryContext};
use l2_workbench::protocol::{RelationalTransformPlan, RelationalTransformReport};
use serde_json::{Value, json};

pub(super) fn report_json(
    context: &RelationalDiscoveryContext,
    report: &RelationalTransformReport,
    plan: &RelationalTransformPlan,
    supported_rules: usize,
    applied_rules: usize,
    aggregate_parser_checks: &[Value],
    application_evidence_checks: &[Value],
) -> Value {
    json!({
        "version":REPORT_VERSION,
        "case_scope":"current_case",
        "claim_scope":"bounded_hypothesis_space",
        "search_family":"sha256_counter_xor",
        "parser_scope":plan.parser_scope,
        "split_basis":report.split_basis,
        "cohort":{
            "source_id":context.key.source_id,
            "scope_json":context.key.scope_json,
            "endpoints_json":context.key.endpoints_json,
            "direction":context.key.direction,
            "framing_rule_json":context.key.framing_rule_json,
            "record_schema_json":context.key.schema_json,
        },
        "input_sample_node_ids":context.sample_node_ids,
        "sessions_available":context.sessions_available,
        "omitted_sessions":context.omitted_sessions,
        "omitted_samples":context.omitted_samples,
        "source_eligibility_omissions":context.source_eligibility_omissions,
        "input_coverage_complete":context.input_coverage_complete,
        "discovery_sessions":report.discovery_sessions.iter().map(|session| session.session).collect::<Vec<_>>(),
        "heldout_sessions":report.heldout_sessions.iter().map(|session| session.session).collect::<Vec<_>>(),
        "candidate_count_examined":report.candidates_examined,
        "equivalent_candidate_aliases":report.equivalent_candidate_aliases,
        "candidate_count_omitted":report.omitted_candidates,
        "candidate_omitted_count_exact":report.omitted_candidates_exact,
        "candidate_limit_remaining":report.candidate_limit_remaining,
        "locator_candidates_examined":report.locator_candidates_examined,
        "locator_candidate_limit_remaining":report.locator_candidate_limit_remaining,
        "work_bytes":report.work_bytes,
        "work_bytes_remaining":report.work_bytes_remaining,
        "search_exhaustive_within_plan":report.search_exhaustive_within_plan,
        "search_limits":report.search_limits,
        "candidate_domains":{
            "operation_templates":["sha256_counter_xor"],
            "parser_formats":plan.parser_formats.iter().map(|format| format!("{format:?}")).collect::<Vec<_>>(),
            "counter_widths":plan.counter_widths,
            "counter_byte_orders":plan.counter_byte_orders,
            "seed_orders":plan.seed_orders,
            "initial_counters":plan.initial_counters,
            "counter_resets":plan.counter_resets,
        },
        "configured_limits":{
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
        },
        "retained_rules":report.candidates.iter().map(candidate_json).collect::<Vec<_>>(),
        "aggregate_parser_checks":aggregate_parser_checks,
        "application_evidence_checks":application_evidence_checks,
        "output_application":{
            "supported_rules":supported_rules,
            "applied_rules":applied_rules,
            "uniqueness_established":false,
            "terminal_sequence":"unknown",
        },
    })
}

fn candidate_json(candidate: &l2_workbench::protocol::RelationalTransformCandidate) -> Value {
    let rule = &candidate.rule;
    json!({
        "rule":{
            "seed_locator":locator_summary(&rule.seed_locator),
            "payload_locator":locator_summary(&rule.payload_locator),
            "operation":rule.operation,
            "counter_reset":rule.counter_reset,
            "parser_format":format!("{:?}", rule.parser_format),
            "parser_scope":rule.parser_scope,
        },
        "status":candidate.status,
        "discovery":fit_json(&candidate.discovery),
        "heldout":fit_json(&candidate.heldout),
    })
}

fn locator_summary(locator: &l2_workbench::protocol::RelationalByteRangeLocator) -> Value {
    json!({
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

fn fit_json(fit: &l2_workbench::protocol::RelationalFit) -> Value {
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
    json!({
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
    })
}

pub(super) fn budget_report(
    context: &RelationalDiscoveryContext,
    plan: &RelationalTransformPlan,
    reason: &'static str,
) -> Value {
    json!({
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
    })
}
