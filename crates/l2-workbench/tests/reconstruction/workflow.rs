use super::support;
use l2_workbench::{
    derivation::Constraint,
    hypothesis::{
        CandidateStatus, Family, SearchPlan,
        workflow::{
            FrameSearchOutcome, HeldoutCheckStatus, RecipeAssessmentStatus, WorkflowLimits,
            WorkflowPlan, run_reconstructed,
        },
    },
    protocol::{FramingKind, HoldoutBasis},
    reconstruction::Reconstructor,
};
use std::error::Error;

#[test]
fn workflow_unsupported_unexplained_partial_result() -> Result<(), Box<dyn Error>> {
    let frame = support::tcp(false, 100, 0x02, b"")?;
    let unsupported = l2_capture::CapturedFrame::new(
        frame.bytes().to_vec(),
        frame
            .metadata()
            .clone()
            .with_link_type(l2_capture::LinkType::Unknown(147)),
    )?;
    let mut reconstructor = Reconstructor::new();
    reconstructor.observe_selected(7, &unsupported)?;
    let report = run_reconstructed(&source_id(), &reconstructor.finish()?, &plan())?;
    assert!(report.partial);
    let json = serde_json::to_value(report)?;
    assert_eq!(
        json.pointer("/reconstruction/unsupported_frames"),
        Some(&serde_json::json!(1))
    );
    Ok(())
}

fn plan() -> WorkflowPlan {
    WorkflowPlan {
        framing_candidates: vec![FramingKind::FixedSize { bytes: 4 }],
        search_plan: SearchPlan {
            families: vec![Family::Hex],
            constraints: vec![Constraint::Prefix {
                bytes: b"h".to_vec(),
            }],
            max_depth: 1,
            max_candidates: 16,
        },
        limits: WorkflowLimits::default(),
    }
}

fn source_id() -> String {
    format!("sha256:{}", l2_workbench::sha256(b"whole source"))
}

#[test]
fn workflow_reconstructs_held_out_session() -> Result<(), Box<dyn Error>> {
    let mut reconstructor = Reconstructor::new();
    reconstructor.observe_selected(
        2,
        &support::tcp_ports(false, (40000, 9000), 100, 0x02, b"")?,
    )?;
    reconstructor.observe_selected(
        4,
        &support::tcp_ports(false, (40000, 9000), 103, 0x18, b"69")?,
    )?;
    reconstructor.observe_selected(
        8,
        &support::tcp_ports(false, (40000, 9000), 101, 0x18, b"68")?,
    )?;
    reconstructor.observe_selected(
        10,
        &support::tcp_ports(false, (40001, 9001), 500, 0x02, b"")?,
    )?;
    reconstructor.observe_selected(
        11,
        &support::tcp_ports(false, (40001, 9001), 503, 0x18, b"6f")?,
    )?;
    reconstructor.observe_selected(
        15,
        &support::tcp_ports(false, (40001, 9001), 501, 0x18, b"68")?,
    )?;
    let reconstruction = reconstructor.finish()?;

    let workflow_plan = plan();
    let report = run_reconstructed(&source_id(), &reconstruction, &workflow_plan)?;

    assert_eq!(report.source_id, source_id());
    assert_eq!(report.framing_candidates, workflow_plan.framing_candidates);
    assert_eq!(
        report.effective_plan_sha256,
        l2_workbench::sha256(&serde_json::to_vec(&workflow_plan)?)
    );
    assert_eq!(report.frames.len(), 2);
    assert!(report.frames.iter().all(|frame| frame.role.is_none()));
    assert!(report.frames.iter().all(|frame| frame.origins.len() == 2));
    assert_eq!(report.holdout_basis, Some(HoldoutBasis::CompleteSessions));
    assert!(report.searches.iter().any(|search| {
        matches!(&search.outcome, FrameSearchOutcome::Completed { report }
        if report.candidates.iter().any(|candidate| {
            candidate.status == CandidateStatus::ConstraintsSatisfied
        }))
    }));
    assert!(report.recipes.iter().any(|recipe| {
        recipe.status == RecipeAssessmentStatus::ConstraintsSatisfiedOnHeldoutObservations
            && recipe.heldout_checks.len() == 1
            && recipe
                .heldout_checks
                .first()
                .is_some_and(|check| check.constraints_satisfied)
    }));
    assert!(
        report
            .assumptions
            .iter()
            .any(|assumption| { assumption.contains("not independent corroboration") })
    );
    Ok(())
}

#[test]
fn observed_constraint_over_omitted_heldout() -> Result<(), Box<dyn Error>> {
    let mut reconstructor = Reconstructor::new();
    for session in 0..4_u32 {
        let first_packet = session * 4 + 1;
        let session_port = u16::try_from(session)?;
        let ports = (41_000 + session_port, 10_000 + session_port);
        let application_bytes = if session == 2 { b"746f" } else { b"6869" };
        reconstructor.observe_selected(
            first_packet,
            &support::tcp_ports(false, ports, 100, 0x02, b"")?,
        )?;
        reconstructor.observe_selected(
            first_packet + 1,
            &support::tcp_ports(false, ports, 101, 0x18, application_bytes)?,
        )?;
    }
    let reconstruction = reconstructor.finish()?;
    let mut workflow_plan = plan();
    workflow_plan.limits.search.max_work_bytes = 18;

    let report = run_reconstructed(&source_id(), &reconstruction, &workflow_plan)?;

    assert!(report.recipes.iter().any(|recipe| {
        recipe.status == RecipeAssessmentStatus::ContradictedByHeldoutObservation
            && recipe
                .heldout_checks
                .iter()
                .any(|check| check.status == HeldoutCheckStatus::ConstraintFailed)
            && recipe
                .heldout_checks
                .iter()
                .any(|check| check.status == HeldoutCheckStatus::WorkBudgetExceeded)
    }));
    Ok(())
}

#[test]
fn reused_ambiguous_generations_discovery_observations() -> Result<(), Box<dyn Error>> {
    let mut reconstructor = Reconstructor::new();
    reconstructor.observe_selected(1, &support::tcp(false, 100, 0x02, b"")?)?;
    reconstructor.observe_selected(3, &support::tcp(false, 101, 0x18, b"6869")?)?;
    reconstructor.observe_selected(8, &support::tcp(false, 900, 0x02, b"")?)?;
    reconstructor.observe_selected(12, &support::tcp(false, 901, 0x18, b"686f")?)?;
    let reconstruction = reconstructor.finish()?;

    let report = run_reconstructed(&source_id(), &reconstruction, &plan())?;

    assert_eq!(report.frames.len(), 2);
    assert!(report.frames.iter().all(|frame| frame.generation_ambiguous));
    assert_eq!(report.holdout_basis, None);
    assert!(
        report
            .recipes
            .iter()
            .all(|recipe| { recipe.status == RecipeAssessmentStatus::NoEligibleHeldoutSessions })
    );
    Ok(())
}

#[test]
fn workflow_shares_work_budget_across() -> Result<(), Box<dyn Error>> {
    let mut reconstructor = Reconstructor::new();
    for session in 0..4_u32 {
        let first_packet = session * 4 + 1;
        let session_port = u16::try_from(session)?;
        let ports = (40_000 + session_port, 9_000 + session_port);
        reconstructor.observe_selected(
            first_packet,
            &support::tcp_ports(false, ports, 100, 0x02, b"")?,
        )?;
        reconstructor.observe_selected(
            first_packet + 1,
            &support::tcp_ports(false, ports, 101, 0x18, b"6869")?,
        )?;
    }
    let reconstruction = reconstructor.finish()?;
    let mut workflow_plan = plan();
    workflow_plan.limits.search.max_work_bytes = 6;

    let report = run_reconstructed(&source_id(), &reconstruction, &workflow_plan)?;

    assert_eq!(report.work_bytes, 6);
    assert!(report.searches.iter().any(|search| {
        matches!(
            search.outcome,
            FrameSearchOutcome::WorkBudgetExceeded { remaining: 0, .. }
        )
    }));
    assert!(report.recipes.iter().any(|recipe| {
        recipe.status == RecipeAssessmentStatus::UnresolvedOnBudget
            && recipe
                .heldout_checks
                .iter()
                .any(|check| check.status == HeldoutCheckStatus::WorkBudgetExceeded)
    }));
    assert!(report.partial);
    Ok(())
}

#[test]
fn workflow_result_candidate_heldout_growth() -> Result<(), Box<dyn Error>> {
    let mut reconstructor = Reconstructor::new();
    for session in 0..8_u32 {
        let first_packet = session * 4 + 1;
        let session_port = u16::try_from(session)?;
        let ports = (42_000 + session_port, 11_000 + session_port);
        reconstructor.observe_selected(
            first_packet,
            &support::tcp_ports(false, ports, 100, 0x02, b"")?,
        )?;
        reconstructor.observe_selected(
            first_packet + 1,
            &support::tcp_ports(false, ports, 101, 0x18, b"6869")?,
        )?;
    }
    let reconstruction = reconstructor.finish()?;
    let mut workflow_plan = plan();
    workflow_plan.search_plan.families.push(Family::Reverse);
    workflow_plan.limits.max_result_rows = 16;

    let report = run_reconstructed(&source_id(), &reconstruction, &workflow_plan)?;

    assert_eq!(report.retained_result_rows, 16);
    assert_eq!(report.omitted_searches, 0);
    assert_eq!(report.omitted_recipe_assessments, 0);
    assert_eq!(report.omitted_heldout_checks, 1);
    assert!(report.searches.iter().all(|search| {
        matches!(&search.outcome, FrameSearchOutcome::Completed { report }
            if report.candidates.len() == 3)
    }));
    let recipe = report.recipes.first().ok_or("missing recipe assessment")?;
    assert_eq!(report.recipes.len(), 1);
    assert_eq!(recipe.heldout_checks.len(), 3);
    assert_eq!(recipe.omitted_heldout_checks, 1);
    assert_eq!(recipe.status, RecipeAssessmentStatus::UnresolvedOnBudget);
    assert!(report.partial);
    Ok(())
}

#[test]
fn workflow_result_plaintext_test_receipts() -> Result<(), Box<dyn Error>> {
    let mut reconstructor = Reconstructor::new();
    for session in 0..4_u32 {
        let first_packet = session * 4 + 1;
        let session_port = u16::try_from(session)?;
        let ports = (44_000 + session_port, 13_000 + session_port);
        reconstructor.observe_selected(
            first_packet,
            &support::tcp_ports(false, ports, 100, 0x02, b"")?,
        )?;
        reconstructor.observe_selected(
            first_packet + 1,
            &support::tcp_ports(false, ports, 101, 0x18, b"6869")?,
        )?;
    }
    let reconstruction = reconstructor.finish()?;
    let mut workflow_plan = plan();
    workflow_plan.search_plan.families = vec![Family::KnownPlaintextXor {
        offset: 0,
        bytes: b"66".to_vec(),
        key_lengths: vec![1],
    }];
    workflow_plan.limits.max_result_rows = 3;

    let report = run_reconstructed(&source_id(), &reconstruction, &workflow_plan)?;

    let search_rows = report
        .searches
        .iter()
        .filter_map(|search| match &search.outcome {
            FrameSearchOutcome::Completed { report } => {
                Some(report.candidates.len() + report.key_tests.len())
            }
            FrameSearchOutcome::InputTooLarge { .. }
            | FrameSearchOutcome::WorkBudgetExceeded { .. }
            | FrameSearchOutcome::ResultBudgetExceeded { .. } => None,
        })
        .sum::<usize>();
    let assessment_rows = report.recipes.len()
        + report
            .recipes
            .iter()
            .map(|recipe| recipe.heldout_checks.len())
            .sum::<usize>();

    assert_eq!(report.retained_result_rows, 2);
    assert_eq!(report.retained_result_rows, search_rows + assessment_rows);
    assert!(report.searches.iter().any(|search| {
        matches!(
            search.outcome,
            FrameSearchOutcome::ResultBudgetExceeded { .. }
        )
    }));
    assert!(report.searches.iter().any(|search| {
        matches!(&search.outcome, FrameSearchOutcome::Completed { report }
            if !report.key_tests.is_empty())
    }));
    assert!(report.partial);
    Ok(())
}

#[test]
fn heldout_output_unresolved_recipe_contradiction() -> Result<(), Box<dyn Error>> {
    let mut reconstructor = Reconstructor::new();
    reconstructor.observe_selected(
        1,
        &support::tcp_ports(false, (43_000, 12_000), 100, 0x02, b"")?,
    )?;
    reconstructor.observe_selected(
        2,
        &support::tcp_ports(false, (43_000, 12_000), 101, 0x18, b"YWI=")?,
    )?;
    reconstructor.observe_selected(
        5,
        &support::tcp_ports(false, (43_001, 12_001), 100, 0x02, b"")?,
    )?;
    reconstructor.observe_selected(
        6,
        &support::tcp_ports(false, (43_001, 12_001), 101, 0x18, b"YWJj")?,
    )?;
    let reconstruction = reconstructor.finish()?;
    let mut workflow_plan = WorkflowPlan {
        framing_candidates: vec![FramingKind::FixedSize { bytes: 4 }],
        search_plan: SearchPlan {
            families: vec![Family::Base64],
            constraints: vec![Constraint::Prefix {
                bytes: b"a".to_vec(),
            }],
            max_depth: 1,
            max_candidates: 16,
        },
        limits: WorkflowLimits::default(),
    };
    workflow_plan.limits.search.max_output_bytes = 2;

    let report = run_reconstructed(&source_id(), &reconstruction, &workflow_plan)?;

    assert!(report.recipes.iter().any(|recipe| {
        recipe.status == RecipeAssessmentStatus::UnresolvedOnBudget
            && recipe
                .heldout_checks
                .iter()
                .any(|check| check.status == HeldoutCheckStatus::ResourceBudgetExceeded)
    }));
    assert!(report.recipes.iter().all(|recipe| {
        recipe.status != RecipeAssessmentStatus::ContradictedByHeldoutObservation
    }));
    Ok(())
}
