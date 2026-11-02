use super::support::event;
use l2_workbench::{
    derivation::{Operation, Recipe},
    evidence::Case,
    journal::{
        ChainDeadline, ChainPlan, Check, CheckKind, CheckOutcome, EventSelector, Hypothesis,
        Journal, JournalOptions,
    },
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::error::Error;

const READER_BUDGET: usize = 256;
const OVERSIZED_COLUMN_BYTES: usize = 65_536;
const STREAMED_EVIDENCE_BYTES: usize = 128 * 1024 + 17;

fn journal(path: &std::path::Path) -> Result<Journal, Box<dyn Error>> {
    Journal::create(
        path,
        &Case::new(),
        JournalOptions {
            cache_mib: 1,
            max_entry_bytes: READER_BUDGET,
            ..JournalOptions::default()
        },
    )
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

fn hypothesis() -> Hypothesis {
    Hypothesis {
        title: "A retained model".into(),
        input: json!({"source":"sample"}),
        operation: json!({"kind":"inspect"}),
        assumptions: Vec::new(),
    }
}

#[test]
fn exact_metadata_budget() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let model = hypothesis();
    let encoded_length = serde_json::to_vec(&model)?.len();
    let mut writer = Journal::create(directory.path(), &Case::new(), JournalOptions::default())?;
    let id = writer.record(&model)?;
    drop(writer);
    for maximum in [encoded_length, encoded_length - 1] {
        let reader = Journal::open(
            directory.path(),
            JournalOptions {
                max_entry_bytes: maximum,
                ..JournalOptions::default()
            },
        )?;
        if maximum == encoded_length {
            assert_eq!(reader.entry(&id)?.hypothesis.title, model.title);
        } else {
            assert_error_contains(reader.entry(&id), "configured metadata reader budget")?;
        }
    }
    Ok(())
}

#[test]
fn verify_rejects_oversized_model_deserializing() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = journal(dir.path())?;
    let id = journal.record(&hypothesis())?;
    let mut changed = hypothesis();
    changed.title = "x".repeat(READER_BUDGET * 4);
    let connection = rusqlite::Connection::open(dir.path().join("journal.sqlite"))?;
    connection.execute(
        "UPDATE hypotheses SET model=?1 WHERE id=?2",
        rusqlite::params![serde_json::to_string(&changed)?, id],
    )?;

    assert_error_contains(
        journal.verify(),
        "hypothesis exceeds configured metadata reader budget",
    )?;
    Ok(())
}

#[test]
fn derivation_references_oversized_hashes_loading() -> Result<(), Box<dyn Error>> {
    for column in ["output", "receipt"] {
        let directory = tempfile::tempdir()?;
        let mut case = Case::new();
        let node = case.add_bytes_node("sample", b"abc", Vec::new(), json!({}))?;
        let mut journal = Journal::create(
            directory.path(),
            &case,
            JournalOptions {
                cache_mib: 1,
                max_entry_bytes: 1024,
                ..JournalOptions::default()
            },
        )?;
        let recipe = Recipe {
            steps: vec![Operation::Reverse {}],
            constraints: Vec::new(),
        };
        let id = journal.derive(
            l2_workbench::journal::DerivationInput::BaseNode(node),
            &recipe,
        )?;
        let connection = rusqlite::Connection::open(directory.path().join("journal.sqlite"))?;
        // Permit this fixture to contain the invalid reference checked by the reader
        connection.pragma_update(None, "foreign_keys", false)?;
        connection.execute(
            &format!("UPDATE hypotheses SET {column}=?1 WHERE id=?2"),
            rusqlite::params!["x".repeat(OVERSIZED_COLUMN_BYTES), id],
        )?;

        assert_error_contains(
            journal.entry(&id),
            &format!("journal derivation {column} must be a 64-character SHA-256 hash"),
        )?;
        if column == "output" {
            assert_error_contains(
                journal.derive(
                    l2_workbench::journal::DerivationInput::BaseNode(node),
                    &recipe,
                ),
                "journal derivation output must be a 64-character SHA-256 hash",
            )?;
        }
    }
    Ok(())
}

#[test]
fn verify_rejects_oversized_event_deserializing() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = journal(dir.path())?;
    journal.record_event(&event(1, "observation", "lan", "host"))?;
    let mut changed = event(1, "observation", "lan", "host");
    changed.fields = json!({"payload":"x".repeat(READER_BUDGET * 4)});
    let connection = rusqlite::Connection::open(dir.path().join("journal.sqlite"))?;
    connection.execute(
        "UPDATE events SET value=?1",
        [serde_json::to_string(&changed)?],
    )?;

    assert_error_contains(
        journal.verify(),
        "event exceeds configured metadata reader budget",
    )?;
    Ok(())
}

#[test]
fn verify_oversized_index_columns_loading() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = journal(dir.path())?;
    journal.record_event(&event(1, "observation", "lan", "host"))?;
    let connection = rusqlite::Connection::open(dir.path().join("journal.sqlite"))?;
    connection.execute("UPDATE events SET kind=?1", ["x".repeat(READER_BUDGET * 4)])?;

    assert_error_contains(
        journal.verify(),
        "event index column kind exceeds configured metadata reader budget",
    )?;
    Ok(())
}

#[test]
fn readers_oversized_binding_origin_loading() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = Journal::create(
        dir.path(),
        &Case::new(),
        JournalOptions {
            cache_mib: 1,
            max_entry_bytes: 1024,
            ..JournalOptions::default()
        },
    )?;
    let id = journal.record(&hypothesis())?;
    journal.record_check(
        &id,
        &Check {
            kind: CheckKind::Structural,
            outcome: CheckOutcome::Pass,
            explanation: "supporting evidence was checked".into(),
        },
        b"evidence",
    )?;
    let connection = rusqlite::Connection::open(dir.path().join("journal.sqlite"))?;
    let identity: String = connection.query_row(
        "SELECT identity FROM checks WHERE hypothesis=?1",
        [&id],
        |row| row.get(0),
    )?;
    connection.pragma_update(None, "ignore_check_constraints", "ON")?;
    connection.execute(
        "UPDATE checks SET binding_origin=?1",
        ["x".repeat(OVERSIZED_COLUMN_BYTES)],
    )?;

    assert_error_contains(
        journal.entry(&id),
        "check exceeds configured metadata reader budget",
    )?;
    assert_error_contains(
        journal.visit_checks(&id, 0, None, |_| Ok(())),
        "check exceeds configured metadata reader budget",
    )?;
    assert!(journal.verify().is_err());
    assert_error_contains(
        journal.write_evidence("1", &mut Vec::new()),
        "check exceeds configured metadata reader budget",
    )?;
    assert_error_contains(
        journal.write_evidence(&identity, &mut Vec::new()),
        "check exceeds configured metadata reader budget",
    )?;
    Ok(())
}

#[test]
fn evidence_larger_metadata_budget_exported() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = journal(dir.path())?;
    let id = journal.record(&hypothesis())?;
    let evidence = (0..STREAMED_EVIDENCE_BYTES)
        .map(|index| u8::try_from(index % 251))
        .collect::<Result<Vec<_>, _>>()?;
    journal.record_check(
        &id,
        &l2_workbench::journal::Check {
            kind: CheckKind::Structural,
            outcome: CheckOutcome::Pass,
            explanation: "large evidence remains streamable".into(),
        },
        &evidence,
    )?;
    let evidence_hash = format!("{:x}", Sha256::digest(&evidence));

    assert!(evidence.len() > READER_BUDGET);
    for reference in ["1", evidence_hash.as_str()] {
        let mut exported = Vec::new();
        assert_eq!(
            journal.write_evidence(reference, &mut exported)?,
            u64::try_from(evidence.len())?
        );
        assert_eq!(exported, evidence);
    }
    Ok(())
}

#[test]
fn base_case_oversized_metadata_loading() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let journal = journal(dir.path())?;
    let connection = rusqlite::Connection::open(dir.path().join("journal.sqlite"))?;
    connection.execute(
        "UPDATE metadata SET value=?1 WHERE key='base_case_sha256'",
        ["x".repeat(OVERSIZED_COLUMN_BYTES)],
    )?;

    assert_error_contains(
        journal.base_case(),
        "base-case metadata must be a 64-character SHA-256 hash",
    )?;
    assert_error_contains(
        journal.overview(),
        "base-case metadata must be a 64-character SHA-256 hash",
    )?;
    Ok(())
}

#[test]
fn base_case_invalid_digest_metadata() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let journal = journal(dir.path())?;
    let connection = rusqlite::Connection::open(dir.path().join("journal.sqlite"))?;
    connection.execute(
        "UPDATE metadata SET value='invalid' WHERE key='base_case_sha256'",
        [],
    )?;

    assert_error_contains(
        journal.base_case(),
        "base-case metadata must be a 64-character SHA-256 hash",
    )?;
    assert_error_contains(
        journal.overview(),
        "base-case metadata must be a 64-character SHA-256 hash",
    )?;
    Ok(())
}

#[test]
fn fixed_base_variable_entry_budget() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let options = JournalOptions {
        max_entry_bytes: 63,
        ..JournalOptions::default()
    };
    let journal = Journal::create(directory.path(), &Case::new(), options)?;
    let expected = l2_workbench::sha256(&Case::new().to_json()?);

    assert_eq!(journal.overview()?.base_case_sha256, expected);
    assert_eq!(journal.base_case()?.to_json()?, Case::new().to_json()?);
    Ok(())
}

#[test]
fn event_reader_values_disagree_evidence() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut journal = journal(directory.path())?;
    journal.record_event(&event(1, "observation", "lan", "host"))?;
    let connection = rusqlite::Connection::open(directory.path().join("journal.sqlite"))?;
    connection.execute("UPDATE events SET packet=2", [])?;

    assert_error_contains(
        journal.visit_events(0, None, |_| Ok(())),
        "journal event index columns disagree with its evidence",
    )?;
    assert_error_contains(
        journal.verify(),
        "journal event index columns disagree with its evidence",
    )?;
    Ok(())
}

#[test]
fn verify_non_event_identity_loading() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = journal(dir.path())?;
    journal.record_event(&event(1, "observation", "lan", "host"))?;
    let connection = rusqlite::Connection::open(dir.path().join("journal.sqlite"))?;
    connection.execute("UPDATE events SET identity=?1", ["x".repeat(4096)])?;

    assert_error_contains(
        journal.verify(),
        "journal event identity must be a 64-character SHA-256 hash",
    )?;
    Ok(())
}

#[test]
fn verify_non_hypothesis_identity_loading() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = journal(dir.path())?;
    journal.record(&hypothesis())?;
    let connection = rusqlite::Connection::open(dir.path().join("journal.sqlite"))?;
    connection.execute("UPDATE hypotheses SET id=?1", ["x".repeat(4096)])?;

    assert_error_contains(
        journal.verify(),
        "journal hypothesis identity must be a 64-character SHA-256 hash",
    )?;
    Ok(())
}

#[test]
fn verify_non_object_identity_loading() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let journal = journal(dir.path())?;
    let connection = rusqlite::Connection::open(dir.path().join("journal.sqlite"))?;
    connection.execute(
        "INSERT INTO objects(sha256,bytes) VALUES(?1,?2)",
        rusqlite::params!["x".repeat(4096), b"evidence".as_slice()],
    )?;

    assert_error_contains(
        journal.verify(),
        "journal object identity must be a 64-character SHA-256 hash",
    )?;
    Ok(())
}

#[test]
fn chain_reader_oversized_event_deserializing() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = journal(dir.path())?;
    journal.record_event(&event(1, "observation", "lan", "host"))?;
    let mut changed = event(1, "observation", "lan", "host");
    changed.fields = json!({"payload":"x".repeat(READER_BUDGET * 4)});
    let connection = rusqlite::Connection::open(dir.path().join("journal.sqlite"))?;
    connection.execute(
        "UPDATE events SET value=?1",
        [serde_json::to_string(&changed)?],
    )?;
    let plan = ChainPlan {
        steps: vec![EventSelector::default()],
        same_actor: false,
        max_gap_ticks: None,
        limit: Some(1),
        joins: Vec::new(),
        max_elapsed_ms: ChainDeadline::unlimited(),
    };

    assert_error_contains(
        journal.visit_chains(&plan, |_| Ok(())),
        "event exceeds configured metadata reader budget",
    )?;
    Ok(())
}

#[test]
fn chain_validation_json_field_filters() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = journal(dir.path())?;
    journal.record_event(&event(1, "observation", "lan", "host"))?;
    let connection = rusqlite::Connection::open(dir.path().join("journal.sqlite"))?;
    connection.execute(
        "UPDATE events SET value=?1",
        ["x".repeat(READER_BUDGET * 4)],
    )?;
    let mut selector = EventSelector {
        kind: Some("observation".into()),
        ..Default::default()
    };
    selector.fields.insert("result".into(), json!("observed"));
    let plan = ChainPlan {
        steps: vec![selector],
        same_actor: false,
        max_gap_ticks: None,
        limit: Some(1),
        joins: Vec::new(),
        max_elapsed_ms: ChainDeadline::unlimited(),
    };

    assert_error_contains(
        journal.visit_chains(&plan, |_| Ok(())),
        "event exceeds configured metadata reader budget",
    )?;
    Ok(())
}

#[test]
fn verify_rejects_hypothesis_empty_title() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = journal(dir.path())?;
    let id = journal.record(&hypothesis())?;
    let mut changed = hypothesis();
    changed.title.clear();
    let connection = rusqlite::Connection::open(dir.path().join("journal.sqlite"))?;
    connection.execute(
        "UPDATE hypotheses SET model=?1 WHERE id=?2",
        rusqlite::params![serde_json::to_string(&changed)?, id],
    )?;

    assert_error_contains(journal.verify(), "hypothesis needs a title")?;
    Ok(())
}

#[test]
fn verify_events_required_source_identity() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = journal(dir.path())?;
    let original = event(1, "observation", "lan", "host");
    journal.record_event(&original)?;
    let mut changed = original;
    changed.source.clear();
    let value = serde_json::to_string(&changed)?;
    let identity = format!("{:x}", Sha256::digest(value.as_bytes()));
    let connection = rusqlite::Connection::open(dir.path().join("journal.sqlite"))?;
    connection.execute(
        "UPDATE events SET identity=?1,source=?2,value=?3",
        rusqlite::params![identity, changed.source, value],
    )?;

    assert_error_contains(
        journal.verify(),
        "events need source, scope, kind and one-based packet order",
    )?;
    Ok(())
}

#[test]
fn object_reader_loading_output_bytes() -> Result<(), Box<dyn Error>> {
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
    let entry = journal.entry(&id)?;
    let output_hash = entry
        .output_sha256
        .ok_or("derivation output hash is missing")?;
    let receipt_hash = entry
        .receipt_sha256
        .ok_or("derivation receipt hash is missing")?;
    let too_large = vec![0_u8; l2_workbench::derivation::MAX_OUTPUT_BYTES + 1];
    let connection = rusqlite::Connection::open(dir.path().join("journal.sqlite"))?;
    let receipt: Vec<u8> = connection.query_row(
        "SELECT bytes FROM objects WHERE sha256=?1",
        [&receipt_hash],
        |row| row.get(0),
    )?;
    let mut receipt: serde_json::Value = serde_json::from_slice(&receipt)?;
    receipt
        .as_object_mut()
        .ok_or("derivation receipt must be a JSON object")?
        .insert("output_length".into(), json!(too_large.len()));
    let receipt = serde_json::to_vec(&receipt)?;
    let updated_receipt_hash = l2_workbench::sha256(&receipt);
    connection.execute(
        "INSERT INTO objects(sha256,bytes) VALUES(?1,?2)",
        rusqlite::params![updated_receipt_hash, receipt],
    )?;
    connection.execute(
        "UPDATE hypotheses SET receipt=?1 WHERE id=?2",
        rusqlite::params![updated_receipt_hash, id],
    )?;
    connection.execute(
        "UPDATE objects SET bytes=?1 WHERE sha256=?2",
        rusqlite::params![too_large, output_hash],
    )?;

    assert_error_contains(
        journal.output(&id),
        "stored object exceeds this reader's allocation budget",
    )?;
    Ok(())
}
