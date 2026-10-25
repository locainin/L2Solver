use super::{
    Candidate, CandidateStatus, SearchError, SearchLimit, SearchLimits, SearchPlan, SearchReport,
    operations, validate,
};
use crate::derivation::{
    self, Constraint, ConstraintStatus, DerivationLimits, DerivationReport, DerivationStatus,
    Operation, Recipe,
};
use std::collections::{BTreeMap, VecDeque};

/// Enumerate bounded transformations, retaining failed checks and competing candidates
///
/// # Errors
/// Rejects missing or invalid constraints, oversized inputs, or unsupported plan budgets
pub fn search(input: &[u8], plan: &SearchPlan) -> Result<SearchReport, SearchError> {
    search_with_limits(input, plan, SearchLimits::default())
}

/// Check a plan once without starting candidate enumeration
///
/// # Errors
/// Rejects invalid plans and runtime budgets
pub fn validate_search_plan(plan: &SearchPlan, limits: SearchLimits) -> Result<(), SearchError> {
    validate::plan(&[], plan, limits).map(|_| ())
}

/// Enumerate transformations under caller-selected input, output, and total-work budgets
///
/// # Errors
/// Rejects invalid plans, invalid budgets, or inputs above the configured input limit
pub fn search_with_limits(
    input: &[u8],
    plan: &SearchPlan,
    limits: SearchLimits,
) -> Result<SearchReport, SearchError> {
    let baseline = validate::plan(input, plan, limits)?;
    let mut limitations = vec![
        "Transformation results do not establish source authenticity or external credential acceptance",
        "Known plaintext is a caller premise; withheld bytes test consistency and do not establish independent provenance",
        "Equivalent outputs share one expansion path; the selected families and depth do not cover every possible cipher or encoding",
        "Canonical decoder input, output, intermediate, and parameter budgets are explicit in resources",
        "Output capacity is reserved before each transform; a conservative reservation can stop a search before its charged byte count reaches the ceiling",
    ];
    if plan
        .constraints
        .iter()
        .any(|constraint| matches!(constraint, Constraint::AesGcm { .. }))
    {
        limitations.push(
            "An explicit AES-GCM constraint, when evaluated, checks authenticated decryption under its supplied key, nonce, and associated data; its candidate status records the result",
        );
    } else {
        limitations.push("No authenticated-decryption constraint was supplied");
    }
    let mut report = SearchReport {
        input_length: input.len(),
        input_sha256: baseline.input_sha256.clone(),
        plan: plan.clone(),
        resources: limits,
        candidates: Vec::new(),
        key_tests: Vec::new(),
        work_bytes: 0,
        search_exhaustive_within_plan: true,
        limits: Vec::new(),
        limitations,
    };
    let mut seen = BTreeMap::from([(baseline.output_sha256.clone(), 0)]);
    let mut initial = Vec::new();
    initial
        .try_reserve_exact(input.len())
        .map_err(|_| SearchError::AllocationFailed)?;
    initial.extend_from_slice(input);
    let mut pending = VecDeque::from([(0, initial)]);
    report.candidates.push(candidate(
        0,
        None,
        Vec::new(),
        Vec::new(),
        baseline,
        None,
        plan,
    ));
    enumerate_candidates(plan, limits, &mut report, &mut seen, &mut pending)?;
    Ok(report)
}

fn enumerate_candidates(
    plan: &SearchPlan,
    limits: SearchLimits,
    report: &mut SearchReport,
    seen: &mut BTreeMap<String, usize>,
    pending: &mut VecDeque<(usize, Vec<u8>)>,
) -> Result<(), SearchError> {
    while let Some((parent, current)) = pending.pop_front() {
        let depth = report
            .candidates
            .get(parent)
            .ok_or(SearchError::Invalid("search parent is absent"))?
            .recipe
            .steps
            .len();
        if depth == plan.max_depth {
            continue;
        }
        for operation in operations::generate(&current, parent, report) {
            if report.candidates.len() >= plan.max_candidates {
                mark_limit(report, SearchLimit::CandidateCount);
                return Ok(());
            }
            if !reserve_operation_work(&current, &operation, limits, report) {
                return Ok(());
            }
            attempt(&current, parent, operation, report, seen, pending, limits)?;
        }
    }
    Ok(())
}

fn reserve_operation_work(
    current: &[u8],
    operation: &Operation,
    limits: SearchLimits,
    report: &mut SearchReport,
) -> bool {
    // Reserve output before running a transform so one result cannot cross the ceiling
    let Some(reserved) =
        current
            .len()
            .checked_add(output_reservation(operation, current.len(), limits))
    else {
        mark_limit(report, SearchLimit::WorkBytes);
        return false;
    };
    if report
        .work_bytes
        .checked_add(reserved)
        .is_none_or(|work| work > limits.max_work_bytes)
    {
        mark_limit(report, SearchLimit::WorkBytes);
        return false;
    }
    true
}

fn mark_limit(report: &mut SearchReport, reason: SearchLimit) {
    limit(
        &mut report.limits,
        &mut report.search_exhaustive_within_plan,
        reason,
    );
}

fn attempt(
    current: &[u8],
    parent: usize,
    operation: Operation,
    report: &mut SearchReport,
    seen: &mut BTreeMap<String, usize>,
    pending: &mut VecDeque<(usize, Vec<u8>)>,
    limits: SearchLimits,
) -> Result<(), SearchError> {
    let mut result = derivation::run_with_limits(
        current,
        &Recipe {
            steps: vec![operation.clone()],
            constraints: report.plan.constraints.clone(),
        },
        derivation_limits(report.plan.max_depth, &report.plan, limits),
    )?;
    report.work_bytes = report
        .work_bytes
        .checked_add(result.work_bytes)
        .ok_or(SearchError::Invalid("search work accounting overflowed"))?;
    let id = report.candidates.len();
    let previous = report
        .candidates
        .get(parent)
        .ok_or(SearchError::Invalid("search parent is absent"))?;
    let mut steps = previous.steps.clone();
    let mut recipe = previous.recipe.steps.clone();
    recipe.push(operation);
    for check in &mut result.constraints {
        if let ConstraintStatus::NotEvaluated { after_step } = &mut check.status {
            *after_step = recipe.len() - 1;
        }
    }
    let duplicate = (result.status == DerivationStatus::Completed)
        .then(|| seen.get(&result.output_sha256).copied())
        .flatten();
    let expandable = result.status == DerivationStatus::Completed && duplicate.is_none();
    if expandable {
        seen.insert(result.output_sha256.clone(), id);
        if result.output.len() <= limits.max_input_bytes {
            let mut next = Vec::new();
            next.try_reserve_exact(result.output.len())
                .map_err(|_| SearchError::AllocationFailed)?;
            next.extend_from_slice(&result.output);
            pending.push_back((id, next));
        } else if recipe.len() < report.plan.max_depth {
            limit(
                &mut report.limits,
                &mut report.search_exhaustive_within_plan,
                SearchLimit::ExpansionBytes,
            );
        }
    }
    steps.extend(result.steps.iter().cloned());
    report.candidates.push(candidate(
        id,
        Some(parent),
        recipe,
        steps,
        result,
        duplicate,
        &report.plan,
    ));
    Ok(())
}

fn output_reservation(operation: &Operation, input_length: usize, limits: SearchLimits) -> usize {
    match operation {
        Operation::HexDecode {} => input_length / 2,
        Operation::Base64Decode { .. }
        | Operation::Reverse {}
        | Operation::XorRepeat { .. }
        | Operation::ByteAdd { .. }
        | Operation::RotateBits { .. } => input_length,
        // Compression reserves its configured maximum before the decoder starts
        _ => limits.max_output_bytes.min(limits.max_intermediate_bytes),
    }
}

const fn derivation_limits(
    max_steps: usize,
    plan: &SearchPlan,
    limits: SearchLimits,
) -> DerivationLimits {
    DerivationLimits {
        max_input_bytes: limits.max_input_bytes,
        max_output_bytes: limits.max_output_bytes,
        max_intermediate_bytes: limits.max_intermediate_bytes,
        max_work_bytes: limits.max_work_bytes,
        max_steps,
        max_constraints: plan.constraints.len(),
        max_recipe_parameter_bytes: limits.max_recipe_parameter_bytes,
    }
}

fn candidate(
    id: usize,
    parent: Option<usize>,
    operations: Vec<Operation>,
    steps: Vec<crate::derivation::StepReport>,
    result: DerivationReport,
    duplicate_of: Option<usize>,
    plan: &SearchPlan,
) -> Candidate {
    let status = if result.status != DerivationStatus::Completed {
        CandidateStatus::OperationFailed
    } else if result
        .constraints
        .iter()
        .all(|check| check.status == ConstraintStatus::Satisfied)
    {
        CandidateStatus::ConstraintsSatisfied
    } else {
        CandidateStatus::ConstraintFailed
    };
    Candidate {
        id,
        parent,
        recipe: Recipe {
            steps: operations,
            constraints: plan.constraints.clone(),
        },
        status,
        output_length: result.output.len(),
        output_sha256: result.output_sha256,
        steps,
        constraints: result.constraints,
        duplicate_of,
    }
}

pub(super) fn limit(limits: &mut Vec<SearchLimit>, exhaustive: &mut bool, limit: SearchLimit) {
    *exhaustive = false;
    if !limits.contains(&limit) {
        limits.push(limit);
    }
}
