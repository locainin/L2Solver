//! Reproducible candidate extraction, transformation search, and session holdout checks

mod extraction;
mod holdout;
mod model;
mod search;

pub use model::{
    FrameSearch, FrameSearchOutcome, HeldoutCheck, HeldoutCheckStatus, RecipeAssessment,
    RecipeAssessmentStatus, ReconstructionReceipt, StreamReceipt, WorkflowError, WorkflowLimits,
    WorkflowPlan, WorkflowReport,
};

use crate::{
    protocol::{self, HoldoutBasis},
    reconstruction::ReconstructionReport,
};
use extraction::{Extraction, extract_sessions, session_split};
use holdout::{HeldoutContext, assess_heldout_frames};
use model::WorkflowBudget;
use search::search_discovery_frames;

/// Run framing, transform search, and whole-session held-out checks over reconstructed TCP data
///
/// # Errors
/// Rejects invalid source identity, plans, budgets, ambiguous source maps, or derivation failures
pub fn run_reconstructed(
    source_id: &str,
    reconstruction: &ReconstructionReport,
    plan: &WorkflowPlan,
) -> Result<WorkflowReport, WorkflowError> {
    if source_id.is_empty() {
        return Err(WorkflowError::InvalidPlan(
            "source identity cannot be empty",
        ));
    }
    let limits = plan.limits;
    validate_limits(limits)?;
    if reconstruction.limits != limits.reconstruction {
        return Err(WorkflowError::InvalidPlan(
            "workflow reconstruction budgets do not match the reconstructed input",
        ));
    }
    protocol::validate_stream_framings(&plan.framing_candidates, limits.protocol)?;
    super::validate_search_plan(&plan.search_plan, limits.search)?;

    // Keep complete, confidently attributed sessions intact across the evidence split
    let (discovery, holdout, has_eligible_sessions) = session_split(&reconstruction.sessions)?;
    let extracted = extract_sessions(source_id, reconstruction, plan, limits)?;
    build_report(WorkflowEvidence {
        source_id,
        plan,
        limits,
        discovery,
        holdout,
        has_eligible_sessions,
        extracted,
    })
}

struct WorkflowEvidence<'a> {
    source_id: &'a str,
    plan: &'a WorkflowPlan,
    limits: model::WorkflowLimits,
    discovery: std::collections::BTreeSet<u32>,
    holdout: std::collections::BTreeSet<u32>,
    has_eligible_sessions: bool,
    extracted: Extraction,
}

fn build_report(evidence: WorkflowEvidence<'_>) -> Result<WorkflowReport, WorkflowError> {
    let WorkflowEvidence {
        source_id,
        plan,
        limits,
        discovery,
        holdout,
        has_eligible_sessions,
        extracted,
    } = evidence;
    let discovery_sessions = discovery.iter().copied().collect();
    let heldout_sessions = holdout.iter().copied().collect();
    let holdout_basis = has_eligible_sessions.then_some(HoldoutBasis::CompleteSessions);
    let effective_plan_sha256 = crate::sha256(&serde_json::to_vec(plan)?);
    // One budget covers discovery transformations, held-out checks, and retained report rows
    let mut budget = WorkflowBudget::new(limits);
    let search_output =
        search_discovery_frames(&extracted.frames, &discovery, plan, limits, &mut budget)?;
    let assessments = assess_heldout_frames(
        search_output.assessments,
        HeldoutContext {
            frames: &extracted.frames,
            heldout_sessions: &holdout,
            has_eligible_sessions,
            limits,
        },
        &mut budget,
    )?;
    let recipes = assessments.recipes;
    let partial = workflow_is_partial(
        &extracted,
        &search_output.searches,
        search_output.omitted_searches,
        assessments.omitted_recipes,
        assessments.omitted_heldout_checks,
        &recipes,
    );
    Ok(WorkflowReport {
        schema_version: 1,
        source_id: source_id.to_owned(),
        reconstruction: extracted.reconstruction,
        limits,
        holdout_basis,
        discovery_sessions,
        heldout_sessions,
        frames: extracted.frames,
        streams: extracted.streams,
        transitions: extracted.transitions,
        searches: search_output.searches,
        framing_candidates: plan.framing_candidates.clone(),
        search_plan: plan.search_plan.clone(),
        effective_plan_sha256,
        work_bytes: budget.work_bytes,
        retained_result_rows: budget.retained_result_rows,
        omitted_searches: search_output.omitted_searches,
        omitted_recipe_assessments: assessments.omitted_recipes,
        omitted_heldout_checks: assessments.omitted_heldout_checks,
        recipes,
        omitted_streams: extracted.omitted_streams,
        partial_streams: extracted.partial_streams,
        partial,
        assumptions: vec![
            "candidate framing does not establish a complete application grammar",
            "the selected flow contains tuple-assigned TCP records; non-initial fragments without a tuple are not attributed automatically",
            "roles remain unknown unless separately established by observed evidence",
            "same-session framing aliases are collapsed when counting observations",
            "held-out sessions are disjoint within this capture and are not independent corroboration",
            "ambiguous TCP generations remain in discovery and cannot serve as held-out observations",
            "satisfied constraints test only the explicit recipe requirements",
        ],
    })
}

fn workflow_is_partial(
    extracted: &Extraction,
    searches: &[model::FrameSearch],
    omitted_searches: usize,
    omitted_recipes: usize,
    omitted_heldout_checks: usize,
    recipes: &[model::RecipeAssessment],
) -> bool {
    !extracted.reconstruction.complete
        || extracted.reconstruction.unsupported_frames != 0
        || extracted.omitted_streams != 0
        || extracted.partial_streams != 0
        || searches.iter().any(|search| match &search.outcome {
            FrameSearchOutcome::Completed { report } => !report.search_exhaustive_within_plan,
            FrameSearchOutcome::InputTooLarge { .. }
            | FrameSearchOutcome::WorkBudgetExceeded { .. }
            | FrameSearchOutcome::ResultBudgetExceeded { .. } => true,
        })
        || omitted_searches != 0
        || omitted_recipes != 0
        || omitted_heldout_checks != 0
        || recipes
            .iter()
            .any(|recipe| recipe.status == RecipeAssessmentStatus::UnresolvedOnBudget)
        || extracted.streams.iter().any(|stream| stream.partial)
}

const fn validate_limits(limits: model::WorkflowLimits) -> Result<(), WorkflowError> {
    let reconstruction = limits.reconstruction;
    if reconstruction.frames == 0
        || reconstruction.bytes == 0
        || reconstruction.units == 0
        || reconstruction.sessions == 0
        || reconstruction.datagrams == 0
        || reconstruction.range_bytes == 0
        || reconstruction.range_observations == 0
        || reconstruction.range_retained_bytes == 0
    {
        return Err(WorkflowError::InvalidPlan(
            "reconstruction budgets must be positive",
        ));
    }
    if limits.max_result_rows == 0 {
        return Err(WorkflowError::InvalidPlan(
            "workflow result-row budget must be positive",
        ));
    }
    Ok(())
}
