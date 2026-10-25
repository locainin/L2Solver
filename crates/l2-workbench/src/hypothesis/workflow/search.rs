use super::super::{CandidateStatus, SearchPlan, search_with_limits};
use super::{
    FrameSearch, FrameSearchOutcome, WorkflowError, WorkflowLimits, WorkflowPlan,
    model::{AssessmentBuilder, EvidenceKey, WorkflowBudget},
};
use crate::protocol::MessageRecord;
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct SearchOutput {
    pub(super) searches: Vec<FrameSearch>,
    pub(super) assessments: BTreeMap<String, AssessmentBuilder>,
    pub(super) omitted_searches: usize,
}

pub(super) fn search_discovery_frames(
    frames: &[MessageRecord],
    discovery: &BTreeSet<u32>,
    plan: &WorkflowPlan,
    limits: WorkflowLimits,
    budget: &mut WorkflowBudget,
) -> Result<SearchOutput, WorkflowError> {
    let mut searches = Vec::new();
    let mut assessments = BTreeMap::<String, AssessmentBuilder>::new();
    let mut omitted_searches = 0_usize;
    for (frame_index, frame) in frames.iter().enumerate() {
        let session = u32::try_from(frame.context.session).map_err(|_| {
            WorkflowError::InvalidPlan("message context has an invalid session identity")
        })?;
        if !discovery.contains(&session) {
            continue;
        }
        let outcome = search_frame(frame, plan, limits, budget)?;
        if matches!(&outcome, FrameSearchOutcome::ResultBudgetExceeded { .. }) {
            omitted_searches =
                omitted_searches
                    .checked_add(1)
                    .ok_or(WorkflowError::InvalidPlan(
                        "omitted search count overflowed",
                    ))?;
        }
        record_candidate_assessments(frame_index, frame, &outcome, &mut assessments)?;
        searches.push(FrameSearch {
            frame_index,
            outcome,
        });
    }
    Ok(SearchOutput {
        searches,
        assessments,
        omitted_searches,
    })
}

fn search_frame(
    frame: &MessageRecord,
    plan: &WorkflowPlan,
    limits: WorkflowLimits,
    budget: &mut WorkflowBudget,
) -> Result<FrameSearchOutcome, WorkflowError> {
    if frame.bytes.len() > limits.search.max_input_bytes {
        Ok(FrameSearchOutcome::InputTooLarge {
            length: frame.bytes.len(),
            maximum: limits.search.max_input_bytes,
        })
    } else if budget.remaining_work_bytes == 0 {
        Ok(FrameSearchOutcome::WorkBudgetExceeded {
            length: frame.bytes.len(),
            remaining: budget.remaining_work_bytes,
        })
    } else if result_budget_cannot_fit_search(plan, limits, budget.remaining_result_rows) {
        Ok(FrameSearchOutcome::ResultBudgetExceeded {
            length: frame.bytes.len(),
            remaining: budget.remaining_result_rows,
        })
    } else {
        completed_search(frame, plan, limits, budget)
    }
}

fn completed_search(
    frame: &MessageRecord,
    plan: &WorkflowPlan,
    limits: WorkflowLimits,
    budget: &mut WorkflowBudget,
) -> Result<FrameSearchOutcome, WorkflowError> {
    let mut effective_plan = plan.search_plan.clone();
    let mut search_limits = limits.search;
    search_limits.max_work_bytes = budget.remaining_work_bytes;
    // Reserve output rows for configured key checks before candidate enumeration
    let possible_key_tests =
        configured_key_test_count(&effective_plan).min(search_limits.max_key_tests);
    let retained_key_test_limit =
        possible_key_tests.min(budget.remaining_result_rows.saturating_sub(1));
    if possible_key_tests != 0 {
        search_limits.max_key_tests = retained_key_test_limit;
    }
    // Keep one row for the search's baseline candidate, even with key checks enabled
    effective_plan.max_candidates = effective_plan
        .max_candidates
        .min(budget.remaining_result_rows - retained_key_test_limit);
    let report = search_with_limits(&frame.bytes, &effective_plan, search_limits)?;
    budget.charge_work(report.work_bytes)?;
    let row_count = report
        .candidates
        .len()
        .checked_add(report.key_tests.len())
        .ok_or(WorkflowError::InvalidPlan(
            "workflow search result-row count overflowed",
        ))?;
    budget.retain_rows(row_count)?;
    Ok(FrameSearchOutcome::Completed {
        report: Box::new(report),
    })
}

fn record_candidate_assessments(
    frame_index: usize,
    frame: &MessageRecord,
    outcome: &FrameSearchOutcome,
    assessments: &mut BTreeMap<String, AssessmentBuilder>,
) -> Result<(), WorkflowError> {
    if let FrameSearchOutcome::Completed { report } = outcome {
        for candidate in &report.candidates {
            if candidate.status != CandidateStatus::ConstraintsSatisfied {
                continue;
            }
            let encoded = serde_json::to_vec(&candidate.recipe)?;
            let recipe_sha256 = crate::sha256(&encoded);
            let key = format!("{recipe_sha256}:{}", serde_json::to_string(&frame.framing)?);
            let builder = assessments.entry(key).or_insert_with(|| AssessmentBuilder {
                recipe_sha256,
                recipe: candidate.recipe.clone(),
                framing: frame.framing.clone(),
                discovery_evidence: Vec::new(),
                evidence_keys: BTreeSet::new(),
            });
            if builder
                .evidence_keys
                .insert(EvidenceKey::from_message(frame))
            {
                builder.discovery_evidence.push(frame_index);
            }
        }
    }
    Ok(())
}

fn result_budget_cannot_fit_search(
    plan: &WorkflowPlan,
    limits: WorkflowLimits,
    remaining_rows: usize,
) -> bool {
    remaining_rows == 0
        || (remaining_rows == 1
            && configured_key_test_count(&plan.search_plan).min(limits.search.max_key_tests) != 0)
}

fn configured_key_test_count(plan: &SearchPlan) -> usize {
    plan.families
        .iter()
        .filter_map(|family| match family {
            super::super::Family::KnownPlaintextXor { key_lengths, .. } => Some(key_lengths.len()),
            _ => None,
        })
        .fold(0, usize::saturating_add)
}
