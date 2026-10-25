use l2_workbench::{
    evidence::Case,
    journal::{Check, CheckKind, CheckOutcome, Hypothesis, Journal, JournalOptions},
};
use serde_json::json;
use std::error::Error;

#[test]
fn conclusions_require_passing_independent_check() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut journal = Journal::create(directory.path(), &Case::new(), JournalOptions::default())?;
    for kind in [
        CheckKind::Structural,
        CheckKind::Independent,
        CheckKind::ReportedExternal,
    ] {
        for outcome in [
            CheckOutcome::Pass,
            CheckOutcome::Fail,
            CheckOutcome::Unresolved,
        ] {
            let id = checked_model(&mut journal, kind, outcome)?;
            let conclusion = match (kind, outcome) {
                (_, CheckOutcome::Fail) => "falsified_under_recorded_checks",
                (CheckKind::Independent, CheckOutcome::Pass) => {
                    "best_supported_under_recorded_checks"
                }
                _ => "unresolved",
            };
            assert_eq!(journal.entry(&id)?.conclusion, conclusion);
        }
    }
    Ok(())
}

#[test]
fn unlimited_model_limits_prefix_pages() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut journal = Journal::create(directory.path(), &Case::new(), JournalOptions::default())?;
    // Insert the groups in a different order from their required review order
    let failed = checked_model(
        &mut journal,
        CheckKind::ReportedExternal,
        CheckOutcome::Fail,
    )?;
    let supported = checked_model(&mut journal, CheckKind::Independent, CheckOutcome::Pass)?;
    let unresolved = checked_model(&mut journal, CheckKind::Structural, CheckOutcome::Pass)?;

    // An omitted limit streams the whole review, including unresolved and falsified models
    let mut visited = Vec::new();
    journal.visit_review(None, |entry| {
        visited.push(entry.id);
        Ok(())
    })?;
    assert_eq!(visited, vec![supported, unresolved, failed]);
    let mut page = Vec::new();
    journal.visit_review(Some(2), |entry| {
        page.push(entry.id);
        Ok(())
    })?;
    assert_eq!(page, visited.iter().take(2).cloned().collect::<Vec<_>>());
    journal.visit_review(Some(0), |_| {
        Err("a zero-sized page must not invoke its visitor".into())
    })?;
    Ok(())
}

fn checked_model(
    journal: &mut Journal,
    kind: CheckKind,
    outcome: CheckOutcome,
) -> Result<String, Box<dyn Error>> {
    let id = journal.record(&Hypothesis {
        title: "Candidate with a recorded check".into(),
        input: json!({"kind": kind, "outcome": outcome}),
        operation: json!({"kind": "inspect"}),
        assumptions: Vec::new(),
    })?;
    journal.record_check(
        &id,
        &Check {
            kind,
            outcome,
            explanation: "Retained check classification".into(),
        },
        b"supporting document",
    )?;
    Ok(id)
}
