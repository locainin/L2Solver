use l2_workbench::{
    derivation::{Operation, Recipe},
    evidence::Case,
    journal::{Check, CheckKind, CheckOutcome, Hypothesis, Journal, JournalOptions},
};
use serde_json::json;
use std::error::Error;
use std::path::Path;

#[test]
fn hypotheses_deduplicate_reported_rejections_reopen() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let case = Case::new();
    let mut journal = Journal::create(dir.path(), &case, JournalOptions::default())?;
    let model = Hypothesis {
        title: "A selected decoding model".into(),
        input: json!({"source":"sample","offset":4}),
        operation: json!({"kind":"reverse"}),
        assumptions: vec!["Boundary is supplied".into()],
    };
    let id = journal.record(&model)?;
    assert_eq!(id, journal.record(&model)?);
    journal.record_check(
        &id,
        &Check {
            kind: CheckKind::ReportedExternal,
            outcome: CheckOutcome::Fail,
            explanation: "Exact candidate was reported rejected".into(),
        },
        b"Original response supplied by analyst",
    )?;
    drop(journal);
    let journal = Journal::open(dir.path(), JournalOptions::default())?;
    let entry = journal.entry(&id)?;
    assert_eq!(entry.checks.len(), 1);
    assert_eq!(
        entry.checks.first().ok_or("missing check")?.check.outcome,
        CheckOutcome::Fail
    );
    assert_eq!(entry.conclusion, "falsified_under_recorded_checks");
    assert_eq!(journal.overview()?.hypotheses, 1);
    Ok(())
}

#[test]
fn derivations_store_without_base_case() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut case = Case::new();
    let node = case.add_bytes_node("sample", b"abc", Vec::new(), json!({}))?;
    let mut journal = Journal::create(dir.path(), &case, JournalOptions::default())?;
    let before = std::fs::read(dir.path().join("base-case.json"))?;
    let id = journal.derive(
        l2_workbench::journal::DerivationInput::BaseNode(node),
        &Recipe {
            steps: vec![Operation::Reverse {}],
            constraints: Vec::new(),
        },
    )?;
    let entry = journal.entry(&id)?;
    assert_eq!(journal.output(&id)?, b"cba");
    assert_eq!(entry.conclusion, "unresolved");
    assert_eq!(std::fs::read(dir.path().join("base-case.json"))?, before);
    Ok(())
}

#[test]
fn missing_hypotheses_base_evidence_rejected() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = Journal::create(dir.path(), &Case::new(), JournalOptions::default())?;
    assert!(
        journal
            .record_check(
                "missing",
                &Check {
                    kind: CheckKind::Structural,
                    outcome: CheckOutcome::Pass,
                    explanation: "check".into()
                },
                b"evidence"
            )
            .is_err()
    );
    std::fs::write(dir.path().join("base-case.json"), b"{}")?;
    assert!(journal.base_case().is_err());
    Ok(())
}

#[test]
fn verification_changed_metadata_budgets_insertion() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = Journal::create(
        dir.path(),
        &Case::new(),
        JournalOptions {
            cache_mib: 1,
            max_entry_bytes: 128,
            ..JournalOptions::default()
        },
    )?;
    let too_large = Hypothesis {
        title: "x".repeat(256),
        input: json!({}),
        operation: json!({}),
        assumptions: Vec::new(),
    };
    assert!(journal.record(&too_large).is_err());
    assert_eq!(journal.overview()?.hypotheses, 0);
    let model = Hypothesis {
        title: "model".into(),
        input: json!({}),
        operation: json!({}),
        assumptions: Vec::new(),
    };
    let id = journal.record(&model)?;
    journal.record_check(
        &id,
        &Check {
            kind: CheckKind::Structural,
            outcome: CheckOutcome::Pass,
            explanation: "input is valid".into(),
        },
        b"original",
    )?;
    journal.verify()?;
    let connection = rusqlite::Connection::open(dir.path().join("journal.sqlite"))?;
    connection.execute("UPDATE objects SET bytes=?1", [b"changed".as_slice()])?;
    assert!(journal.verify().is_err());
    Ok(())
}

#[test]
fn journal_verification_receipt_linked_output() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut case = Case::new();
    let node = case.add_bytes_node("sample", b"abc", Vec::new(), json!({}))?;
    let mut journal = Journal::create(dir.path(), &case, JournalOptions::default())?;
    let id = journal.derive(
        l2_workbench::journal::DerivationInput::BaseNode(node),
        &Recipe {
            steps: vec![Operation::Reverse {}],
            constraints: Vec::new(),
        },
    )?;
    journal.verify()?;
    let db = rusqlite::Connection::open(dir.path().join("journal.sqlite"))?;
    let digest = l2_workbench::sha256(b"other output");
    db.execute(
        "INSERT INTO objects VALUES(?1,?2)",
        rusqlite::params![digest, b"other output".as_slice()],
    )?;
    db.execute(
        "UPDATE hypotheses SET output=?1 WHERE id=?2",
        rusqlite::params![digest, id],
    )?;
    assert!(journal.verify().is_err());
    Ok(())
}

#[test]
fn long_histories_without_omitted_failure() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = Journal::create(
        dir.path(),
        &Case::new(),
        JournalOptions {
            cache_mib: 1,
            max_entry_bytes: 512,
            ..JournalOptions::default()
        },
    )?;
    let id = journal.record(&Hypothesis {
        title: "model".into(),
        input: json!({}),
        operation: json!({}),
        assumptions: Vec::new(),
    })?;
    for index in 0..12 {
        journal.record_check(
            &id,
            &Check {
                kind: CheckKind::Structural,
                outcome: if index == 11 {
                    CheckOutcome::Fail
                } else {
                    CheckOutcome::Pass
                },
                explanation: format!("condition {index}"),
            },
            b"evidence",
        )?;
    }
    let preview = journal.entry(&id)?;
    assert!(preview.checks_omitted > 0);
    assert_eq!(preview.conclusion, "falsified_under_recorded_checks");
    let mut cursor = 0;
    let mut seen = 0;
    loop {
        let mut added = 0;
        journal.visit_checks(&id, cursor, Some(3), |check| {
            cursor = check.id;
            seen += 1;
            added += 1;
            Ok(())
        })?;
        if added == 0 {
            break;
        }
    }
    assert_eq!(seen, 12);
    journal.verify()?;
    Ok(())
}

#[test]
fn derived_outputs_failed_parents_rejected() -> Result<(), Box<dyn Error>> {
    use l2_workbench::journal::DerivationInput;
    let dir = tempfile::tempdir()?;
    let mut case = Case::new();
    let node = case.add_bytes_node("sample", b"abc", Vec::new(), json!({}))?;
    let mut journal = Journal::create(dir.path(), &case, JournalOptions::default())?;
    let reverse = Recipe {
        steps: vec![Operation::Reverse {}],
        constraints: Vec::new(),
    };
    let parent = journal.derive(DerivationInput::BaseNode(node), &reverse)?;
    let child = journal.derive(DerivationInput::DerivedOutput(&parent), &reverse)?;
    assert_eq!(journal.output(&child)?, b"abc");
    assert_eq!(
        journal
            .entry(&child)?
            .hypothesis
            .input
            .get("parent")
            .ok_or("missing parent reference")?
            .as_str(),
        Some(parent.as_str())
    );
    let failed = journal.derive(
        DerivationInput::BaseNode(node),
        &Recipe {
            steps: vec![Operation::Slice {
                start: 10,
                length: Some(2),
            }],
            constraints: Vec::new(),
        },
    )?;
    assert!(
        journal
            .derive(DerivationInput::DerivedOutput(&failed), &reverse)
            .is_err()
    );
    journal.verify()?;
    Ok(())
}

#[test]
fn entry_models_current_reader_budget() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = Journal::create(dir.path(), &Case::new(), JournalOptions::default())?;
    let id = journal.record(&Hypothesis {
        title: "large".repeat(200),
        input: json!({}),
        operation: json!({}),
        assumptions: Vec::new(),
    })?;
    drop(journal);
    let journal = Journal::open(
        dir.path(),
        JournalOptions {
            cache_mib: 1,
            max_entry_bytes: 128,
            ..JournalOptions::default()
        },
    )?;
    assert!(journal.entry(&id).is_err());
    Ok(())
}

#[test]
fn entry_oversized_evaluating_json() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = Journal::create(dir.path(), &Case::new(), JournalOptions::default())?;
    let id = journal.record(&Hypothesis {
        title: "model".into(),
        input: json!({}),
        operation: json!({}),
        assumptions: Vec::new(),
    })?;
    journal.record_check(
        &id,
        &Check {
            kind: CheckKind::Independent,
            outcome: CheckOutcome::Pass,
            explanation: "evidence ".repeat(100),
        },
        b"support",
    )?;
    drop(journal);
    let journal = Journal::open(
        dir.path(),
        JournalOptions {
            cache_mib: 1,
            max_entry_bytes: 256,
            ..JournalOptions::default()
        },
    )?;
    assert!(journal.entry(&id).is_err());
    assert!(journal.visit_review(None, |_| Ok(())).is_err());
    let connection = rusqlite::Connection::open(dir.path().join("journal.sqlite"))?;
    connection.execute("UPDATE checks SET value=?1", ["malformed".repeat(100)])?;
    let error = journal
        .entry(&id)
        .err()
        .ok_or("expected oversized metadata error")?;
    assert!(
        error
            .to_string()
            .contains("configured metadata reader budget")
    );
    Ok(())
}

#[test]
fn derivation_receipts_inside_shared_snapshot() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut case = Case::new();
    let node = case.add_bytes_node("sample", b"abc", Vec::new(), json!({}))?;
    let mut journal = Journal::create(directory.path(), &case, JournalOptions::default())?;
    let id = journal.derive(
        l2_workbench::journal::DerivationInput::BaseNode(node),
        &Recipe {
            steps: vec![Operation::Reverse {}],
            constraints: Vec::new(),
        },
    )?;
    journal.record_check(
        &id,
        &Check {
            kind: CheckKind::Independent,
            outcome: CheckOutcome::Pass,
            explanation: "reviewed retained output".into(),
        },
        b"review evidence",
    )?;
    let mut visited = 0;
    journal.visit_review(None, |entry| {
        assert!(entry.derivation.is_some());
        let recorded = entry.checks.first().ok_or("missing recorded check")?;
        assert_eq!(recorded.identity.len(), 64);
        visited += 1;
        Ok(())
    })?;
    assert_eq!(visited, 1);
    journal.verify()?;
    Ok(())
}

fn supported_journal(path: &Path) -> Result<(Journal, String, String), Box<dyn Error>> {
    let mut journal = Journal::create(path, &Case::new(), JournalOptions::default())?;
    let model = Hypothesis {
        title: "Candidate".into(),
        input: json!({"source":"sample"}),
        operation: json!({"kind":"inspect"}),
        assumptions: Vec::new(),
    };
    let id = journal.record(&model)?;
    journal.record_check(
        &id,
        &Check {
            kind: CheckKind::Independent,
            outcome: CheckOutcome::Pass,
            explanation: "supporting bytes were checked".into(),
        },
        b"original supporting evidence",
    )?;
    let evidence_hash = journal
        .entry(&id)?
        .checks
        .first()
        .ok_or("missing supporting check")?
        .evidence_sha256
        .clone();
    Ok((journal, id, evidence_hash))
}

fn tamper_evidence_object(path: &Path, evidence_hash: &str) -> Result<(), Box<dyn Error>> {
    let connection = rusqlite::Connection::open(path.join("journal.sqlite"))?;
    connection.execute(
        "UPDATE objects SET bytes=?1 WHERE sha256=?2",
        rusqlite::params![b"changed supporting evidence".as_slice(), evidence_hash],
    )?;
    Ok(())
}

fn tamper_model_identity(path: &Path, id: &str) -> Result<(), Box<dyn Error>> {
    let connection = rusqlite::Connection::open(path.join("journal.sqlite"))?;
    let changed = Hypothesis {
        title: "Candidate".into(),
        input: json!({"source":"sample"}),
        operation: json!({"kind":"different operation"}),
        assumptions: Vec::new(),
    };
    connection.execute(
        "UPDATE hypotheses SET model=?1 WHERE id=?2",
        rusqlite::params![serde_json::to_string(&changed)?, id],
    )?;
    Ok(())
}

#[test]
fn entry_tampered_evidence_model_identity() -> Result<(), Box<dyn Error>> {
    for tamper in ["evidence", "model"] {
        let directory = tempfile::tempdir()?;
        let (journal, id, evidence_hash) = supported_journal(directory.path())?;
        match tamper {
            "evidence" => tamper_evidence_object(directory.path(), &evidence_hash)?,
            "model" => tamper_model_identity(directory.path(), &id)?,
            _ => return Err("unknown test tamper".into()),
        }

        assert!(
            journal.entry(&id).is_err(),
            "entry accepted {tamper} tampering"
        );
    }
    Ok(())
}

#[test]
fn entries_tampered_model_visiting_entry() -> Result<(), Box<dyn Error>> {
    for tamper in ["evidence", "model"] {
        let directory = tempfile::tempdir()?;
        let (journal, id, evidence_hash) = supported_journal(directory.path())?;
        match tamper {
            "evidence" => tamper_evidence_object(directory.path(), &evidence_hash)?,
            "model" => tamper_model_identity(directory.path(), &id)?,
            _ => return Err("unknown test tamper".into()),
        }

        let mut visited = false;
        let result = journal.visit_entries(None, None, |_| {
            visited = true;
            Ok(())
        });
        assert!(result.is_err(), "entries accepted {tamper} tampering");
        assert!(!visited, "entries must verify before invoking the visitor");
    }
    Ok(())
}

#[test]
fn tampered_evidence_visiting_entries() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut journal = Journal::create(directory.path(), &Case::new(), JournalOptions::default())?;
    let id = journal.record(&Hypothesis {
        title: "Candidate".into(),
        input: json!({"source":"sample"}),
        operation: json!({"kind":"inspect"}),
        assumptions: Vec::new(),
    })?;
    journal.record_check(
        &id,
        &Check {
            kind: CheckKind::Independent,
            outcome: CheckOutcome::Pass,
            explanation: "supporting bytes were checked".into(),
        },
        b"original supporting evidence",
    )?;
    let connection = rusqlite::Connection::open(directory.path().join("journal.sqlite"))?;
    connection.execute(
        "UPDATE objects SET bytes=?1 WHERE sha256=(SELECT evidence FROM checks WHERE hypothesis=?2)",
        rusqlite::params![b"changed supporting evidence".as_slice(), id],
    )?;

    let mut visited = false;
    let result = journal.visit_review(None, |_| {
        visited = true;
        Ok(())
    });

    assert!(result.is_err());
    assert!(
        !visited,
        "review must validate the journal before emitting entries"
    );
    Ok(())
}

#[test]
fn tampered_model_identity_visiting_entries() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut journal = Journal::create(directory.path(), &Case::new(), JournalOptions::default())?;
    let model = Hypothesis {
        title: "Candidate".into(),
        input: json!({"source":"sample"}),
        operation: json!({"kind":"inspect"}),
        assumptions: Vec::new(),
    };
    let id = journal.record(&model)?;
    let changed = Hypothesis {
        operation: json!({"kind":"different operation"}),
        ..model
    };
    let connection = rusqlite::Connection::open(directory.path().join("journal.sqlite"))?;
    connection.execute(
        "UPDATE hypotheses SET model=?1 WHERE id=?2",
        rusqlite::params![serde_json::to_string(&changed)?, id],
    )?;

    let mut visited = false;
    let result = journal.visit_review(None, |_| {
        visited = true;
        Ok(())
    });

    assert!(result.is_err());
    assert!(
        !visited,
        "review must validate the journal before emitting entries"
    );
    Ok(())
}
