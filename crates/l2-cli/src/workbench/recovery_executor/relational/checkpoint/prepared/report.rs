//! Check saved report fields that can be derived from the current cohort

use super::super::super::{MAX_RETAINED_RELATIONAL_APPLICATIONS, PreparedRelationalCohort, report};
use crate::workbench::recovery_executor::RecoveryExecutionError;
use l2_workbench::{
    protocol::{RelationalTransformPlan, RelationalTransformReport},
    recovery::RecoveryError,
};
use serde_json::{Value, json};

pub(super) fn preflight(
    cohort: &PreparedRelationalCohort,
    plan: &RelationalTransformPlan,
    report_value: &Value,
    sample_bytes: usize,
    before: usize,
) -> Result<bool, RecoveryExecutionError> {
    let expected = if cohort.context.sessions_available < 2 {
        Some((
            report::insufficient_sessions_report(&cohort.context, plan),
            "insufficient_independent_sessions",
        ))
    } else if sample_bytes >= before {
        Some((
            report::budget_report(&cohort.context, plan, "coordinator_work_limit"),
            "coordinator_work_limit",
        ))
    } else {
        None
    };
    let Some((expected, reason)) = expected else {
        return Ok(false);
    };
    let spent = if sample_bytes >= before {
        0
    } else {
        sample_bytes
    };
    if report_value != &expected
        || cohort.reason.as_deref() != Some(reason)
        || !cohort.report_details_complete
        || cohort.search_exhaustive_within_plan
        || cohort.candidate_limit_remaining != plan.limits.max_candidates
        || cohort.locator_candidate_limit_remaining
            != plan.limits.max_locator_candidates.saturating_mul(2)
        || before.checked_sub(spent) != Some(cohort.work_bytes_remaining)
        || !cohort.outputs.is_empty()
        || !cohort.decoded_frames.is_empty()
        || !cohort.accepted_schemas.is_empty()
        || !cohort.structural_evidence.is_empty()
        || !cohort.producer_rules.is_empty()
        || !cohort.published_rules.is_empty()
        || cohort.history_used
    {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    Ok(true)
}

#[derive(Clone, Copy)]
pub(super) struct SearchedReport<'a> {
    pub(super) cohort: &'a PreparedRelationalCohort,
    pub(super) plan: &'a RelationalTransformPlan,
    pub(super) canonical: &'a RelationalTransformReport,
    pub(super) value: &'a Value,
    pub(super) sample_bytes: usize,
    pub(super) cohort_work_budget: usize,
    pub(super) before: usize,
}

pub(super) fn searched(check: SearchedReport<'_>) -> Result<(), RecoveryExecutionError> {
    verify_shape(&check)?;
    verify_counters(&check)?;
    let supported = verify_rules(&check)?;
    verify_application(check.cohort, check.value, supported)?;
    verify_reported_positives(check.cohort, check.value)
}

fn verify_shape(check: &SearchedReport<'_>) -> Result<(), RecoveryExecutionError> {
    let SearchedReport {
        cohort,
        plan,
        canonical,
        value,
        ..
    } = *check;
    let reference = report::report_json(&cohort.context, canonical, plan, 0, 0, &[], &[]);
    let fields = value.as_object().ok_or(RecoveryError::InvalidCheckpoint)?;
    let reference_fields = reference
        .as_object()
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    let incremental = cohort.context.lane == super::super::super::RelationalLane::Incremental;
    let expected_fields = reference_fields
        .len()
        .checked_add(if incremental { 4 } else { 0 })
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    if fields.len() != expected_fields {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    for name in fields.keys() {
        if !(reference_fields.contains_key(name)
            || incremental
                && matches!(
                    name.as_str(),
                    "history_reused_rejections"
                        | "history_reused_published"
                        | "history_search_recording_omissions"
                        | "history_complete_before_publication"
                ))
        {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
    }
    if incremental {
        for field in [
            "history_reused_rejections",
            "history_reused_published",
            "history_search_recording_omissions",
        ] {
            number(value, field)?;
        }
        if value
            .get("history_complete_before_publication")
            .is_none_or(|field| !field.is_null() && !field.is_boolean())
        {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
        if value
            .get("history_complete_before_publication")
            .is_some_and(Value::is_boolean)
            != cohort.history_used
        {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
    }
    verify_fixed_fields(value, &reference)
}

fn verify_fixed_fields(value: &Value, reference: &Value) -> Result<(), RecoveryExecutionError> {
    for field in [
        "version",
        "case_scope",
        "claim_scope",
        "search_family",
        "parser_scope",
        "split_basis",
        "cohort",
        "input_sample_node_ids",
        "sessions_available",
        "omitted_sessions",
        "omitted_samples",
        "source_eligibility_omissions",
        "input_coverage_complete",
        "discovery_sessions",
        "heldout_sessions",
        "candidate_domains",
        "configured_limits",
        "search_lane",
    ] {
        if value.get(field) != reference.get(field) {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
    }
    Ok(())
}

fn verify_counters(check: &SearchedReport<'_>) -> Result<(), RecoveryExecutionError> {
    let SearchedReport {
        cohort,
        plan,
        value,
        sample_bytes,
        cohort_work_budget,
        before,
        ..
    } = *check;
    let candidates = number(value, "candidate_count_examined")?;
    let locators = number(value, "locator_candidates_examined")?;
    let search_work = number(value, "work_bytes")?;
    number(value, "candidate_count_omitted")?;
    number(value, "equivalent_candidate_aliases")?;
    for field in ["candidate_omitted_count_exact", "prefix_probe_complete"] {
        if value.get(field).and_then(Value::as_bool).is_none() {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
    }
    let limits = value
        .get("search_limits")
        .and_then(Value::as_array)
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    let mut seen_limits = 0_u8;
    for limit in limits {
        let bit = match limit.as_str() {
            Some("candidate_count") => 1,
            Some("work_bytes") => 2,
            Some("locator_count") => 4,
            Some("retained_candidates") => 8,
            _ => return Err(RecoveryError::InvalidCheckpoint.into()),
        };
        if seen_limits & bit != 0 {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
        seen_limits |= bit;
    }
    let hypotheses = number(value, "prefix_probe_hypotheses_examined")?;
    let probes = number(value, "prefix_probes_examined")?;
    let locator_limit = plan.limits.max_locator_candidates.saturating_mul(2);
    let used = before
        .checked_sub(cohort.work_bytes_remaining)
        .and_then(|spent| spent.checked_sub(sample_bytes))
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    let reported_application_work = application_work(value)?;
    if !cohort.report_details_complete
        || !matches!(
            cohort.reason.as_deref(),
            None | Some("aggregate_application_unresolved" | "supported_rule_application_limit")
        )
        || value.get("search_exhaustive_within_plan")
            != Some(&json!(cohort.search_exhaustive_within_plan))
        || candidates > plan.limits.max_candidates
        || locators > locator_limit
        || search_work > plan.limits.max_work_bytes
        || number(value, "prefix_probe_work_bytes")? > search_work
        || probes > hypotheses
        || number(value, "prefix_probe_cache_reuses")? > hypotheses
        || number(value, "prefix_probe_candidates_with_novelty")? > probes
        || used
            < search_work
                .checked_add(reported_application_work)
                .ok_or(RecoveryError::InvalidCheckpoint)?
        || used > cohort_work_budget
        || cohort.candidate_limit_remaining != plan.limits.max_candidates - candidates
        || cohort.locator_candidate_limit_remaining != locator_limit - locators
        || number(value, "candidate_limit_remaining")? != cohort.candidate_limit_remaining
        || number(value, "locator_candidate_limit_remaining")?
            != cohort.locator_candidate_limit_remaining
        || number(value, "work_bytes_remaining")? != plan.limits.max_work_bytes - search_work
    {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    Ok(())
}

fn verify_rules(check: &SearchedReport<'_>) -> Result<usize, RecoveryExecutionError> {
    let SearchedReport {
        cohort,
        plan,
        value,
        ..
    } = *check;
    let rules = value
        .get("retained_rules")
        .and_then(Value::as_array)
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    let mut supported = 0_usize;
    for candidate in rules {
        if candidate.as_object().is_none_or(|fields| {
            fields.len() != 4
                || !["rule", "status", "discovery", "heldout"]
                    .iter()
                    .all(|name| fields.contains_key(*name))
        }) {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
        match candidate.get("status").and_then(Value::as_str) {
            Some("heldout_constraints_satisfied" | "awaiting_across_session_validation") => {
                supported += 1;
            }
            Some(
                "discovery_only_hypothesis"
                | "contradicted_by_heldout_session"
                | "discovery_contradicted"
                | "unresolved_on_budget",
            ) => {}
            _ => return Err(RecoveryError::InvalidCheckpoint.into()),
        }
    }
    if rules.len() > plan.limits.max_retained_candidates
        || cohort.producer_rules.len() > plan.limits.max_retained_candidates
        || cohort
            .producer_rules
            .windows(2)
            .any(|pair| matches!(pair, [left, right] if left.0 >= right.0))
    {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    for (index, rule) in &cohort.producer_rules {
        let saved = rules.get(*index).ok_or(RecoveryError::InvalidCheckpoint)?;
        if saved.get("rule") != Some(&report::rule_json(rule)) {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
    }
    for index in cohort
        .outputs
        .iter()
        .map(|output| output.candidate_index)
        .chain(
            cohort
                .decoded_frames
                .iter()
                .map(|frame| frame.candidate_index),
        )
        .chain(cohort.accepted_schemas.iter().map(|(index, _)| *index))
        .chain(cohort.structural_evidence.iter().map(|(index, _)| *index))
    {
        if cohort
            .producer_rules
            .binary_search_by_key(&index, |(candidate, _)| *candidate)
            .is_err()
        {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
    }
    Ok(supported)
}

fn verify_application(
    cohort: &PreparedRelationalCohort,
    value: &Value,
    supported: usize,
) -> Result<(), RecoveryExecutionError> {
    let retained = cohort
        .producer_rules
        .iter()
        .filter(|(index, _)| {
            cohort
                .decoded_frames
                .iter()
                .any(|frame| frame.candidate_index == *index)
        })
        .count();
    let application = value
        .get("output_application")
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    if application.get("uniqueness_established") != Some(&Value::Bool(false))
        || application.get("terminal_sequence") != Some(&json!("unknown"))
        || application
            .as_object()
            .is_none_or(|fields| fields.len() != 4)
        || number(application, "supported_rules")? != supported
        || retained > supported
        || cohort
            .accepted_schemas
            .windows(2)
            .any(|pair| matches!(pair, [left, right] if left.0 >= right.0))
        || cohort
            .structural_evidence
            .windows(2)
            .any(|pair| matches!(pair, [left, right] if left.0 >= right.0))
        || retained > MAX_RETAINED_RELATIONAL_APPLICATIONS
        || number(application, "applied_rules")? != retained
    {
        return Err(RecoveryError::InvalidCheckpoint.into());
    }
    Ok(())
}

fn application_work(report: &Value) -> Result<usize, RecoveryExecutionError> {
    let mut total = 0_usize;
    let aggregates = report
        .get("aggregate_parser_checks")
        .and_then(Value::as_array)
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    for aggregate in aggregates {
        if aggregate.get("parser_work_bytes").is_some() {
            total = total
                .checked_add(number(aggregate, "parser_work_bytes")?)
                .ok_or(RecoveryError::InvalidCheckpoint)?;
        }
    }
    let evidence = report
        .get("application_evidence_checks")
        .and_then(Value::as_array)
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    for item in evidence {
        if let Some(fallback) = item.pointer("/details/full_inference_fallback") {
            total = total
                .checked_add(number(fallback, "work_bytes")?)
                .ok_or(RecoveryError::InvalidCheckpoint)?;
        }
    }
    Ok(total)
}

fn verify_reported_positives(
    cohort: &PreparedRelationalCohort,
    report: &Value,
) -> Result<(), RecoveryExecutionError> {
    let checks = report
        .get("application_evidence_checks")
        .and_then(Value::as_array)
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    for check in checks {
        let artifact = check
            .get("artifact_validated")
            .and_then(Value::as_bool)
            .ok_or(RecoveryError::InvalidCheckpoint)?;
        let structural = check
            .get("structurally_supported")
            .and_then(Value::as_bool)
            .ok_or(RecoveryError::InvalidCheckpoint)?;
        let status = check
            .get("status")
            .and_then(Value::as_str)
            .ok_or(RecoveryError::InvalidCheckpoint)?;
        if !matches!(
            status,
            "artifact_validated" | "structurally_supported" | "pending" | "contradicted"
        ) || (artifact && status != "artifact_validated")
            || (structural && status != "structurally_supported")
            || (artifact && structural)
            || check.get("accepted_record_schema").is_none()
            || (check
                .get("accepted_record_schema")
                .is_some_and(|schema| !schema.is_null())
                && status != "artifact_validated")
        {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
        let positive = artifact
            || structural
            || matches!(status, "artifact_validated" | "structurally_supported");
        if !positive {
            continue;
        }
        let index = number(check, "candidate_index")?;
        if cohort
            .producer_rules
            .binary_search_by_key(&index, |(candidate, _)| *candidate)
            .is_err()
        {
            // An evicted positive has no frozen producer and cannot be checked safely
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
    }
    let aggregates = report
        .get("aggregate_parser_checks")
        .and_then(Value::as_array)
        .ok_or(RecoveryError::InvalidCheckpoint)?;
    for check in aggregates {
        if check
            .get("accepted")
            .is_some_and(|value| !value.is_boolean())
        {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
        if check.get("accepted") != Some(&Value::Bool(true)) {
            continue;
        }
        let index = number(check, "candidate_index")?;
        if cohort
            .producer_rules
            .binary_search_by_key(&index, |(candidate, _)| *candidate)
            .is_err()
        {
            return Err(RecoveryError::InvalidCheckpoint.into());
        }
    }
    Ok(())
}

fn number(value: &Value, field: &str) -> Result<usize, RecoveryExecutionError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| RecoveryError::InvalidCheckpoint.into())
}
