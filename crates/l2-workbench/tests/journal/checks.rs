use l2_workbench::{
    evidence::Case,
    journal::{Check, CheckKind, CheckOutcome, Hypothesis, Journal, JournalOptions},
};
use serde_json::json;
use std::error::Error;

fn model(title: &str) -> Hypothesis {
    Hypothesis {
        title: title.into(),
        input: json!({"source":title}),
        operation: json!({"kind":"inspect"}),
        assumptions: Vec::new(),
    }
}

fn check(outcome: CheckOutcome) -> Check {
    Check {
        kind: CheckKind::Independent,
        outcome,
        explanation: "retained independent result".into(),
    }
}

fn assert_error_contains<T, E: std::fmt::Display>(
    result: Result<T, E>,
    expected: &str,
) -> Result<(), Box<dyn Error>> {
    let message = match result {
        Err(error) => error.to_string(),
        Ok(_) => return Err(format!("expected error containing {expected:?}, got success").into()),
    };
    assert!(
        message.contains(expected),
        "expected error containing {expected:?}, got {message:?}"
    );
    Ok(())
}

#[test]
fn entry_verify_valid_outcome_tamper() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut journal = Journal::create(directory.path(), &Case::new(), JournalOptions::default())?;
    let id = journal.record(&model("candidate"))?;
    journal.record_check(&id, &check(CheckOutcome::Pass), b"evidence")?;
    assert_eq!(
        journal.entry(&id)?.conclusion,
        "best_supported_under_recorded_checks"
    );

    let connection = rusqlite::Connection::open(directory.path().join("journal.sqlite"))?;
    let changed = serde_json::to_string(&check(CheckOutcome::Fail))?;
    connection.execute("UPDATE checks SET value=?1", [changed])?;

    assert_error_contains(journal.entry(&id), "check identity mismatch")?;
    assert_error_contains(
        journal.visit_review(None, |_| Ok(())),
        "check identity mismatch",
    )?;
    assert_error_contains(journal.verify(), "check identity mismatch")?;
    Ok(())
}

#[test]
fn check_identity_bound_hypothesis() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut journal = Journal::create(directory.path(), &Case::new(), JournalOptions::default())?;
    let original = journal.record(&model("original"))?;
    let replacement = journal.record(&model("replacement"))?;
    journal.record_check(&original, &check(CheckOutcome::Pass), b"evidence")?;

    let connection = rusqlite::Connection::open(directory.path().join("journal.sqlite"))?;
    connection.execute(
        "UPDATE checks SET hypothesis=?1 WHERE hypothesis=?2",
        rusqlite::params![replacement, original],
    )?;

    assert_error_contains(journal.entry(&replacement), "check identity mismatch")?;
    assert_error_contains(journal.verify(), "check identity mismatch")?;
    Ok(())
}

#[test]
fn check_identity_bound_evidence_hash() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut journal = Journal::create(directory.path(), &Case::new(), JournalOptions::default())?;
    let id = journal.record(&model("candidate"))?;
    journal.record_check(&id, &check(CheckOutcome::Pass), b"first evidence")?;
    journal.record_check(&id, &check(CheckOutcome::Pass), b"second evidence")?;

    let connection = rusqlite::Connection::open(directory.path().join("journal.sqlite"))?;
    let second_evidence: String = connection.query_row(
        "SELECT evidence FROM checks ORDER BY id DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    connection.execute(
        "UPDATE checks SET evidence=?1 WHERE id=(SELECT MIN(id) FROM checks)",
        [second_evidence],
    )?;

    assert_error_contains(journal.entry(&id), "check identity mismatch")?;
    assert_error_contains(journal.verify(), "check identity mismatch")?;
    Ok(())
}
