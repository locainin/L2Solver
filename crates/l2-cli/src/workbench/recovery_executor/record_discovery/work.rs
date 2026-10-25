use super::super::RecoveryExecutionError;
use super::input::{RecordCohortKey, RecordDiscoveryPlan, RecordFrameInput};
use l2_workbench::protocol::RecordSchemaProposalLimits;

pub(super) fn cohort_work_bound(
    key: &RecordCohortKey,
    inputs: &[RecordFrameInput],
    limits: RecordSchemaProposalLimits,
) -> Option<usize> {
    let total_bytes = inputs
        .iter()
        .try_fold(0_usize, |total, input| total.checked_add(input.byte_length))?;
    let cohort_bytes = key
        .scope_json
        .len()
        .checked_add(key.endpoints_json.len())?
        .checked_add(key.framing_rule_json.len())?
        .checked_add(key.source_id.len())?;
    cohort_work_bound_for_sizes(total_bytes, inputs.len(), cohort_bytes, limits)
}

pub(in crate::workbench::recovery_executor) fn potential_framing_cohort_work_bound(
    raw_bytes: usize,
    run_count: usize,
    cohort_metadata_bytes: usize,
    framing_rule_count: usize,
    limits: RecordSchemaProposalLimits,
    max_assembly_output_bytes: usize,
) -> Option<usize> {
    let total_bytes = raw_bytes.min(limits.discovery.record_limits.max_input_bytes);
    let message_count = raw_bytes
        .min(limits.discovery.max_messages)
        .min(limits.discovery.record_limits.max_records);
    let per_cohort =
        cohort_work_bound_for_sizes(total_bytes, message_count, cohort_metadata_bytes, limits)?;

    // Retained schema hypotheses can each assemble every eligible session
    let survivor_count = limits
        .discovery
        .max_survivors
        .min(limits.discovery.max_candidates);
    let assembly_input_work = survivor_count.checked_mul(total_bytes)?;
    let assembly_output_count = survivor_count.checked_mul(run_count)?;
    let assembly_output_work = assembly_output_count.checked_mul(max_assembly_output_bytes)?;
    let one_rule_work = per_cohort
        .checked_add(assembly_input_work)?
        .checked_add(assembly_output_work)?;
    one_rule_work.checked_mul(framing_rule_count)
}

fn cohort_work_bound_for_sizes(
    total_bytes: usize,
    message_count: usize,
    cohort_metadata_bytes: usize,
    limits: RecordSchemaProposalLimits,
) -> Option<usize> {
    // Each field, pair, and length check may inspect every training byte
    let field_checks = limits.max_field_checks_per_domain.checked_mul(2)?;
    let proposal_checks = field_checks
        .checked_add(limits.max_pair_checks)?
        .checked_add(limits.max_length_checks)?
        .checked_add(8)?;
    let proposal_work = total_bytes.checked_mul(proposal_checks)?;

    // A strict candidate can scan every message byte and account for each record
    let candidate_checks = limits.discovery.max_candidates;
    let parse_per_candidate = total_bytes
        .checked_mul(2)?
        .checked_add(message_count.checked_mul(32)?)?;
    let parse_work = parse_per_candidate.checked_mul(candidate_checks)?;

    // This upper bound includes every configured row, schema, failure, and field-domain item
    let report_work =
        report_serialization_bound_for_sizes(message_count, cohort_metadata_bytes, limits)?;
    proposal_work
        .checked_add(parse_work)?
        .checked_add(report_work)
}

pub(in crate::workbench::recovery_executor) fn case_work_bound(
    plan: &RecordDiscoveryPlan,
    limits: RecordSchemaProposalLimits,
) -> Result<usize, RecoveryExecutionError> {
    plan.cohorts
        .iter()
        .try_fold(plan.graph_work, |total, (key, inputs)| {
            let Some(bound) = cohort_work_bound(key, inputs, limits) else {
                return Err(RecoveryExecutionError::InvalidPolicy(
                    "record discovery work bound exceeds this platform's address space".to_owned(),
                ));
            };
            total.checked_add(bound).ok_or_else(|| {
                RecoveryExecutionError::InvalidPolicy(
                    "Case-wide record discovery work exceeds this platform's address space"
                        .to_owned(),
                )
            })
        })
}

pub(in crate::workbench::recovery_executor) fn case_max_cohort_input_bytes(
    plan: &RecordDiscoveryPlan,
) -> Result<usize, RecoveryExecutionError> {
    plan.cohorts.values().try_fold(0_usize, |maximum, inputs| {
        let total = inputs.iter().try_fold(0_usize, |total, input| {
            total.checked_add(input.byte_length).ok_or_else(|| {
                RecoveryExecutionError::InvalidPolicy(
                    "record discovery input batch exceeds this platform's address space".to_owned(),
                )
            })
        })?;
        Ok(maximum.max(total))
    })
}

fn report_serialization_bound_for_sizes(
    message_count: usize,
    cohort_metadata_bytes: usize,
    limits: RecordSchemaProposalLimits,
) -> Option<usize> {
    let input_rows = message_count.checked_mul(1_024)?;
    let schemas = limits
        .discovery
        .max_survivors
        .checked_add(limits.discovery.max_falsifications)?
        .checked_mul(1_024)?;
    let proposal_checks = limits
        .max_field_checks_per_domain
        .checked_mul(2)?
        .checked_add(limits.max_pair_checks)?
        .checked_add(limits.max_length_checks)?
        .checked_mul(256)?;
    input_rows
        .checked_add(schemas)?
        .checked_add(proposal_checks)?
        .checked_add(cohort_metadata_bytes)?
        .checked_add(8_192)
}
