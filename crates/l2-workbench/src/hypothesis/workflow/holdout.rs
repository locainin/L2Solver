use super::{
    HeldoutCheck, HeldoutCheckStatus, RecipeAssessment, RecipeAssessmentStatus, WorkflowError,
    WorkflowLimits,
    model::{AssessmentBuilder, EvidenceKey, WorkflowBudget},
};
use crate::{
    derivation::{
        self, ConstraintStatus, DerivationLimits, DerivationReport, DerivationStatus, Recipe,
        StepFailure, StepStatus,
    },
    protocol::MessageRecord,
};
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct Assessments {
    pub(super) recipes: Vec<RecipeAssessment>,
    pub(super) omitted_recipes: usize,
    pub(super) omitted_heldout_checks: usize,
}

pub(super) fn assess_heldout_frames(
    assessments: BTreeMap<String, AssessmentBuilder>,
    context: HeldoutContext<'_>,
    budget: &mut WorkflowBudget,
) -> Result<Assessments, WorkflowError> {
    let heldout_frames = context
        .frames
        .iter()
        .enumerate()
        .filter_map(|(index, frame)| {
            let session = u32::try_from(frame.context.session).ok()?;
            context
                .heldout_sessions
                .contains(&session)
                .then_some((index, frame))
        })
        .collect::<Vec<_>>();
    let mut recipes = Vec::new();
    let mut omitted_recipes = 0_usize;
    let mut omitted_heldout_checks = 0_usize;
    recipes
        .try_reserve_exact(assessments.len())
        .map_err(|_| WorkflowError::InvalidPlan("workflow could not retain recipe assessments"))?;
    for (_, builder) in assessments {
        if budget.remaining_result_rows == 0 {
            omitted_recipes = omitted_recipes
                .checked_add(1)
                .ok_or(WorkflowError::InvalidPlan(
                    "omitted recipe-assessment count overflowed",
                ))?;
            omitted_heldout_checks = omitted_heldout_checks
                .checked_add(count_matching_frames(&builder.framing, &heldout_frames))
                .ok_or(WorkflowError::InvalidPlan(
                    "omitted held-out check count overflowed",
                ))?;
            continue;
        }
        budget.retain_row()?;
        let (assessment, omitted_checks) =
            assess_builder(builder, &heldout_frames, &context, budget)?;
        omitted_heldout_checks = omitted_heldout_checks.checked_add(omitted_checks).ok_or(
            WorkflowError::InvalidPlan("omitted held-out check count overflowed"),
        )?;
        recipes.push(assessment);
    }
    Ok(Assessments {
        recipes,
        omitted_recipes,
        omitted_heldout_checks,
    })
}

#[derive(Clone, Copy)]
pub(super) struct HeldoutContext<'a> {
    pub(super) frames: &'a [MessageRecord],
    pub(super) heldout_sessions: &'a BTreeSet<u32>,
    pub(super) has_eligible_sessions: bool,
    pub(super) limits: WorkflowLimits,
}

fn assess_builder(
    builder: AssessmentBuilder,
    heldout_frames: &[(usize, &MessageRecord)],
    context: &HeldoutContext<'_>,
    budget: &mut WorkflowBudget,
) -> Result<(RecipeAssessment, usize), WorkflowError> {
    let mut checks = Vec::new();
    let mut checked_evidence = BTreeSet::new();
    let mut omitted_checks = 0_usize;
    for (frame_index, frame) in heldout_frames {
        if frame.framing != builder.framing
            || !checked_evidence.insert(EvidenceKey::from_message(frame))
        {
            continue;
        }
        if budget.remaining_result_rows == 0 {
            omitted_checks = omitted_checks
                .checked_add(1)
                .ok_or(WorkflowError::InvalidPlan(
                    "omitted held-out check count overflowed",
                ))?;
            continue;
        }
        budget.retain_row()?;
        let check = heldout_check(
            *frame_index,
            frame,
            &builder.recipe,
            context.limits,
            budget.remaining_work_bytes,
        )?;
        budget.charge_work(check.work_bytes)?;
        checks.push(check);
    }
    let status = assessment_status(context.has_eligible_sessions, &checks, omitted_checks);
    Ok((
        RecipeAssessment {
            recipe_sha256: builder.recipe_sha256,
            recipe: builder.recipe,
            framing: builder.framing,
            discovery_evidence: builder.discovery_evidence,
            heldout_checks: checks,
            omitted_heldout_checks: omitted_checks,
            status,
            assumption: "candidate framing and explicit decoder constraints".to_owned(),
        },
        omitted_checks,
    ))
}

fn count_matching_frames(
    framing: &crate::protocol::FramingKind,
    frames: &[(usize, &MessageRecord)],
) -> usize {
    let mut evidence = BTreeSet::new();
    frames
        .iter()
        .filter(|(_, frame)| frame.framing == *framing)
        .filter(|(_, frame)| evidence.insert(EvidenceKey::from_message(frame)))
        .count()
}

fn assessment_status(
    has_eligible_sessions: bool,
    checks: &[HeldoutCheck],
    omitted_checks: usize,
) -> RecipeAssessmentStatus {
    // A concrete operation or constraint failure remains evidence even if another check was skipped
    if checks.iter().any(|check| {
        matches!(
            check.status,
            HeldoutCheckStatus::ConstraintFailed | HeldoutCheckStatus::OperationFailed
        )
    }) {
        RecipeAssessmentStatus::ContradictedByHeldoutObservation
    } else if omitted_checks != 0
        || checks.iter().any(|check| {
            matches!(
                check.status,
                HeldoutCheckStatus::InputTooLarge
                    | HeldoutCheckStatus::WorkBudgetExceeded
                    | HeldoutCheckStatus::ResourceBudgetExceeded
            )
        })
    {
        RecipeAssessmentStatus::UnresolvedOnBudget
    } else if !has_eligible_sessions {
        RecipeAssessmentStatus::NoEligibleHeldoutSessions
    } else if checks.is_empty() {
        RecipeAssessmentStatus::NoMatchingFramedObservation
    } else {
        RecipeAssessmentStatus::ConstraintsSatisfiedOnHeldoutObservations
    }
}

fn heldout_check(
    frame_index: usize,
    frame: &MessageRecord,
    recipe: &Recipe,
    limits: WorkflowLimits,
    remaining_work_bytes: usize,
) -> Result<HeldoutCheck, WorkflowError> {
    if frame.bytes.len() > limits.search.max_input_bytes {
        return Ok(omitted_check(
            frame_index,
            frame,
            HeldoutCheckStatus::InputTooLarge,
        ));
    }
    if remaining_work_bytes == 0 && !recipe.steps.is_empty() {
        return Ok(omitted_check(
            frame_index,
            frame,
            HeldoutCheckStatus::WorkBudgetExceeded,
        ));
    }
    let derivation_limits = DerivationLimits {
        max_input_bytes: limits.search.max_input_bytes,
        max_output_bytes: limits.search.max_output_bytes,
        max_intermediate_bytes: limits.search.max_intermediate_bytes,
        max_work_bytes: remaining_work_bytes.max(1),
        max_steps: recipe.steps.len().max(1),
        max_constraints: recipe.constraints.len().max(1),
        max_recipe_parameter_bytes: limits.search.max_recipe_parameter_bytes,
    };
    let result = derivation::run_with_limits(&frame.bytes, recipe, derivation_limits)?;
    let constraints_satisfied = result.status == DerivationStatus::Completed
        && result
            .constraints
            .iter()
            .all(|check| check.status == ConstraintStatus::Satisfied);
    let status = classify_check(&result, constraints_satisfied);
    Ok(HeldoutCheck {
        frame_index,
        context: frame.context.clone(),
        framing: frame.framing.clone(),
        input_sha256: result.input_sha256,
        output_sha256: Some(result.output_sha256),
        output_length: Some(result.output.len()),
        derivation_status: Some(result.status),
        steps: result.steps,
        constraints: result.constraints,
        constraints_satisfied,
        work_bytes: result.work_bytes,
        status,
        role: frame.role,
        assumption: frame.assumption.clone(),
    })
}

fn classify_check(result: &DerivationReport, constraints_satisfied: bool) -> HeldoutCheckStatus {
    let budget_exceeded = result.steps.iter().any(|step| {
        matches!(
            step.status,
            StepStatus::Failed {
                error: StepFailure::WorkBudgetExceeded { .. }
            }
        )
    });
    let resource_limited = result.steps.iter().any(|step| {
        matches!(
            step.status,
            StepStatus::Failed {
                error: StepFailure::OutputLimitExceeded { .. }
                    | StepFailure::IntermediateBudgetExceeded { .. }
                    | StepFailure::AllocationFailed
                    | StepFailure::XorKeyTooLong { .. }
            }
        )
    });
    let constraint_failed = result
        .constraints
        .iter()
        .any(|check| matches!(check.status, ConstraintStatus::Violated { .. }));
    if budget_exceeded {
        HeldoutCheckStatus::WorkBudgetExceeded
    } else if resource_limited {
        HeldoutCheckStatus::ResourceBudgetExceeded
    } else if constraint_failed {
        HeldoutCheckStatus::ConstraintFailed
    } else if result.status == DerivationStatus::Completed && constraints_satisfied {
        HeldoutCheckStatus::ConstraintsSatisfied
    } else {
        HeldoutCheckStatus::OperationFailed
    }
}

fn omitted_check(
    frame_index: usize,
    frame: &MessageRecord,
    status: HeldoutCheckStatus,
) -> HeldoutCheck {
    HeldoutCheck {
        frame_index,
        context: frame.context.clone(),
        framing: frame.framing.clone(),
        input_sha256: frame.sha256.clone(),
        output_sha256: None,
        output_length: None,
        derivation_status: None,
        steps: Vec::new(),
        constraints: Vec::new(),
        constraints_satisfied: false,
        work_bytes: 0,
        status,
        role: frame.role,
        assumption: frame.assumption.clone(),
    }
}
