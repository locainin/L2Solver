use super::{
    ExperimentError, MAX_INPUT_BYTES, MAX_MUTATIONS, MAX_PLAN_BYTES, MAX_TOTAL_BYTES, Mutation,
    MutationFailure, loopback,
    mutation::apply,
    plan::MutationPlan,
    report::{
        CandidateSummary, ExperimentMode, ExperimentOutcome, ExperimentReport, ExperimentStatus,
        ExperimentStep, ParserSummary,
    },
};
use crate::{
    application::{self, ParseReport},
    sha256,
};

/// Apply a bounded mutation plan and inspect every accepted byte version
///
/// # Errors
/// Returns an error when input or plan bounds fail, or a loopback transfer cannot finish
pub fn run(
    input: &[u8],
    plan: &MutationPlan,
    mode: ExperimentMode,
) -> Result<ExperimentReport, ExperimentError> {
    validate_input_and_plan(input, plan)?;
    let original_hash = sha256(input);
    let (baseline_parser, baseline_transport) = inspect_candidate(input, mode)?;
    let mut report = ExperimentReport {
        schema_version: 1,
        mode,
        status: ExperimentStatus::Complete,
        input_sha256: original_hash.clone(),
        final_sha256: original_hash.clone(),
        inspected_bytes: input.len(),
        steps: vec![ExperimentStep {
            sequence: 0,
            mutation: None,
            outcome: ExperimentOutcome::Baseline,
            input_length: input.len(),
            output_length: input.len(),
            input_sha256: original_hash.clone(),
            output_sha256: original_hash,
            parser: Some(baseline_parser),
            transport: baseline_transport,
        }],
    };
    let mut current = input.to_vec();
    apply_plan(&mut report, &mut current, plan, mode)?;
    report.final_sha256 = sha256(&current);
    report.status = summarize_status(&report.steps);
    Ok(report)
}

fn validate_input_and_plan(input: &[u8], plan: &MutationPlan) -> Result<(), ExperimentError> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(ExperimentError::InputTooLarge {
            length: input.len(),
            maximum: MAX_INPUT_BYTES,
        });
    }
    if plan.mutations.len() > MAX_MUTATIONS {
        return Err(ExperimentError::TooManyMutations {
            count: plan.mutations.len(),
            maximum: MAX_MUTATIONS,
        });
    }
    let Some(length) = plan.estimated_bytes() else {
        return Err(ExperimentError::PlanTooLarge {
            length: usize::MAX,
            maximum: MAX_PLAN_BYTES,
        });
    };
    if length > MAX_PLAN_BYTES {
        return Err(ExperimentError::PlanTooLarge {
            length,
            maximum: MAX_PLAN_BYTES,
        });
    }
    Ok(())
}

fn apply_plan(
    report: &mut ExperimentReport,
    current: &mut Vec<u8>,
    plan: &MutationPlan,
    mode: ExperimentMode,
) -> Result<(), ExperimentError> {
    for (index, mutation) in plan.mutations.iter().enumerate() {
        let sequence = index + 1;
        match apply(current, mutation) {
            Ok(candidate) => {
                let Some(inspected_total) = report.inspected_bytes.checked_add(candidate.len())
                else {
                    push_failed(
                        report,
                        sequence,
                        mutation,
                        current,
                        MutationFailure::TotalBytesExceeded,
                    );
                    continue;
                };
                if inspected_total > MAX_TOTAL_BYTES {
                    push_failed(
                        report,
                        sequence,
                        mutation,
                        current,
                        MutationFailure::TotalBytesExceeded,
                    );
                    continue;
                }
                append_applied(
                    report,
                    sequence,
                    mutation,
                    current,
                    candidate,
                    mode,
                    inspected_total,
                )?;
            }
            Err(reason) => push_failed(report, sequence, mutation, current, reason),
        }
    }
    Ok(())
}

fn push_failed(
    report: &mut ExperimentReport,
    sequence: usize,
    mutation: &Mutation,
    current: &[u8],
    reason: MutationFailure,
) {
    let hash = sha256(current);
    report.steps.push(ExperimentStep {
        sequence,
        mutation: Some(mutation.clone()),
        outcome: ExperimentOutcome::Failed { reason },
        input_length: current.len(),
        output_length: current.len(),
        input_sha256: hash.clone(),
        output_sha256: hash,
        parser: None,
        transport: None,
    });
}

fn append_applied(
    report: &mut ExperimentReport,
    sequence: usize,
    mutation: &Mutation,
    current: &mut Vec<u8>,
    candidate: Vec<u8>,
    mode: ExperimentMode,
    inspected_total: usize,
) -> Result<(), ExperimentError> {
    let input_hash = sha256(current);
    let output_hash = sha256(&candidate);
    let (parser, transport) = inspect_candidate(&candidate, mode)?;
    report.steps.push(ExperimentStep {
        sequence,
        mutation: Some(mutation.clone()),
        outcome: ExperimentOutcome::Applied,
        input_length: current.len(),
        output_length: candidate.len(),
        input_sha256: input_hash,
        output_sha256: output_hash,
        parser: Some(parser),
        transport,
    });
    report.inspected_bytes = inspected_total;
    *current = candidate;
    Ok(())
}

fn inspect_candidate(
    bytes: &[u8],
    mode: ExperimentMode,
) -> Result<(ParserSummary, Option<super::TransportReceipt>), ExperimentError> {
    match mode {
        ExperimentMode::Offline => Ok((parser_summary(bytes), None)),
        ExperimentMode::Loopback => {
            let transfer = loopback::transfer(bytes).map_err(ExperimentError::Loopback)?;
            Ok((parser_summary(&transfer.received), Some(transfer.receipt)))
        }
    }
}

fn parser_summary(report: &[u8]) -> ParserSummary {
    let candidates = application::inspect(report, false, false);
    ParserSummary {
        dns_tcp: candidate_summary(&candidates.dns_tcp),
        http: candidate_summary(&candidates.http),
        ftp: candidate_summary(&candidates.ftp),
    }
}

fn candidate_summary<T>(report: &ParseReport<T>) -> CandidateSummary {
    let unparsed_bytes = report
        .unparsed
        .iter()
        .fold(0_usize, |total, range| total.saturating_add(range.length));
    CandidateSummary {
        status: report.status,
        finding_count: report.findings.len(),
        unparsed_bytes,
        budget_omissions: report.budget_omissions.len(),
    }
}

fn summarize_status(steps: &[ExperimentStep]) -> ExperimentStatus {
    let has_unresolved_step = steps.iter().any(|step| {
        matches!(step.outcome, ExperimentOutcome::Failed { .. })
            || step
                .transport
                .as_ref()
                .is_some_and(|receipt| !receipt.matches_sent)
            || step
                .parser
                .as_ref()
                .is_some_and(parser_has_budget_omissions)
    });
    if has_unresolved_step {
        ExperimentStatus::Partial
    } else {
        ExperimentStatus::Complete
    }
}

const fn parser_has_budget_omissions(parser: &ParserSummary) -> bool {
    parser.dns_tcp.budget_omissions > 0
        || parser.http.budget_omissions > 0
        || parser.ftp.budget_omissions > 0
}
