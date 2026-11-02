use l2_workbench::{
    derivation::{Operation, Recipe},
    evidence::Case,
    journal::{
        Check, CheckBindingOrigin, CheckKind, CheckOutcome, DerivationInput, Event, Hypothesis,
        Journal, JournalOptions,
    },
    sha256,
};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::{
    error::Error,
    fs,
    io::{Cursor, Write},
};

fn model() -> Hypothesis {
    Hypothesis {
        title: "candidate".into(),
        input: json!({"source":"capture"}),
        operation: json!({"kind":"inspect"}),
        assumptions: vec!["frame order is preserved".into()],
    }
}

fn check() -> Check {
    check_with_outcome(CheckOutcome::Pass)
}

fn check_with_outcome(outcome: CheckOutcome) -> Check {
    Check {
        kind: CheckKind::Independent,
        outcome,
        explanation: "retained independent check".into(),
    }
}

fn event(packet: u64) -> Event {
    Event {
        source: "capture-sha256".into(),
        scope: "offline".into(),
        packet,
        kind: "packet_test".into(),
        actor: None,
        peer: None,
        clock: None,
        ticks: None,
        fields: json!({"frame":packet}),
        ranges: Vec::new(),
    }
}

fn tshark_report(source_hash: &str, packet_numbers: &[u64]) -> Result<Vec<u8>, serde_json::Error> {
    let mut count_output = Vec::new();
    for number in 1..=packet_numbers.len() {
        writeln!(&mut count_output, "{number}").map_err(serde_json::Error::io)?;
    }
    let packets: Vec<Value> = packet_numbers
        .iter()
        .map(|packet_number| {
            json!({
                "packet_number":packet_number,
                "tool_derived":true,
                "fields":{"frame":{"frame.number":packet_number},"tcp":{"tcp.payload":"aabb"}},
                "reassembled_fields":["tcp.payload"]
            })
        })
        .collect();
    serde_json::to_vec(&json!({
        "schema_version":2,
        "source":{"label":"capture.pcap","length":7,"sha256":source_hash},
        "source_packet_count":{"count":packet_numbers.len(),"output_sha256":sha256(&count_output)},
        "provenance":{
            "source_change_verified":true,
            "tool_derived":true,
            "tls_decryption":"disabled",
            "physical_byte_ranges":"not_reported"
        },
        "tool":{
            "executable_requested":"tshark",
            "executable":"test-bin/tshark",
            "executable_bytes":1,
            "executable_sha256":sha256(b"tool"),
            "version":"TShark (Wireshark) 4.4.0",
            "budgets":{
                "timeout_seconds":1,
                "combined_input_bytes":7,
                "metadata_stdout_bytes_per_phase":1,
                "json_output_bytes":1,
                "diagnostic_bytes_per_phase":1
            },
            "profile":{
                "name":"l2solver-offline",
                "preferences_sha256":sha256(b"preferences"),
                "name_resolution":"disabled_by_-n",
                "reassembly_preferences":["tcp.desegment_tcp_streams=TRUE"],
                "process_environment":"isolated",
                "tls_keylog":null
            },
            "plugins":[],
            "plugin_inventory_sha256":sha256(b"plugins"),
            "version_output_sha256":sha256(b"version"),
            "effective_preferences_sha256":sha256(b"effective preferences"),
            "effective_preferences_count":1,
            "verified_profile_preferences":{"tcp.desegment_tcp_streams":"TRUE"},
            "invocations":[
                {"phase":"packet_count","argv":[
                    "-n","-C","l2solver-offline","--disable-all-protocols",
                    "-r","<source-snapshot>","-T","fields","-e","frame.number"
                ]},
                {"phase":"decode","argv":[
                    "-n","-2","-q","-C","l2solver-offline",
                    "-r","<source-snapshot>","-T","json","--no-duplicate-keys"
                ]}
            ],
            "diagnostics":[]
        },
        "output_sha256":sha256(b"decoded output"),
        "packets":packets
    }))
}

fn create_legacy_fixture(
    path: &std::path::Path,
    version: u32,
    outcome: CheckOutcome,
) -> Result<(String, String), Box<dyn Error>> {
    let mut case = Case::new();
    let node = case.add_bytes_node("sample", b"abc", Vec::new(), json!({}))?;
    let mut journal = Journal::create(path, &case, JournalOptions::default())?;
    let hypothesis = journal.record(&model())?;
    journal.record_check(
        &hypothesis,
        &check_with_outcome(outcome),
        b"retained check evidence",
    )?;
    let derived = journal.derive(
        DerivationInput::BaseNode(node),
        &Recipe {
            steps: vec![Operation::Reverse {}],
            constraints: Vec::new(),
        },
    )?;
    journal.record_event(&event(1))?;
    drop(journal);

    downgrade_legacy_schema(path, version)?;
    Ok((hypothesis, derived))
}

fn downgrade_legacy_schema(path: &std::path::Path, version: u32) -> Result<(), Box<dyn Error>> {
    let connection = Connection::open(path.join("journal.sqlite"))?;
    connection.execute_batch(
        "PRAGMA foreign_keys=OFF;
         DROP TABLE event_receipts;
         DROP TABLE tool_receipts;",
    )?;
    if version == 1 {
        connection.execute_batch(
            "ALTER TABLE checks RENAME TO checks_current;
             CREATE TABLE checks(
                 id INTEGER PRIMARY KEY CHECK(id>0),
                 hypothesis TEXT NOT NULL REFERENCES hypotheses(id),
                 value TEXT NOT NULL,
                 evidence TEXT NOT NULL REFERENCES objects(sha256)
             ) STRICT;
             INSERT INTO checks(id,hypothesis,value,evidence)
                 SELECT id,hypothesis,value,evidence FROM checks_current;
             DROP TABLE checks_current;
             PRAGMA user_version=1;",
        )?;
    } else {
        connection.execute_batch(
            "ALTER TABLE checks RENAME TO checks_current;
             CREATE TABLE checks(
                 id INTEGER PRIMARY KEY CHECK(id>0),
                 hypothesis TEXT NOT NULL REFERENCES hypotheses(id),
                 identity TEXT NOT NULL,
                 value TEXT NOT NULL,
                 evidence TEXT NOT NULL REFERENCES objects(sha256)
             ) STRICT;
             INSERT INTO checks(id,hypothesis,identity,value,evidence)
                 SELECT id,hypothesis,identity,value,evidence FROM checks_current;
             DROP TABLE checks_current;
             PRAGMA user_version=2;",
        )?;
    }
    Ok(())
}

#[test]
fn check_evidence_identity_hash() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut journal = Journal::create(directory.path(), &Case::new(), JournalOptions::default())?;
    let hypothesis = journal.record(&model())?;
    journal.record_check(&hypothesis, &check(), b"evidence bytes")?;
    let recorded = journal
        .entry(&hypothesis)?
        .checks
        .into_iter()
        .next()
        .ok_or("missing recorded check")?;

    for reference in [
        "1",
        recorded.identity.as_str(),
        recorded.evidence_sha256.as_str(),
    ] {
        let mut output = Cursor::new(Vec::new());
        assert_eq!(
            journal.write_evidence(reference, &mut output)?,
            u64::try_from(b"evidence bytes".len())?
        );
        assert_eq!(output.into_inner(), b"evidence bytes");
    }
    Ok(())
}

#[test]
fn writable_restores_identity_lookup_index() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let journal = Journal::create(directory.path(), &Case::new(), JournalOptions::default())?;
    drop(journal);
    let database = directory.path().join("journal.sqlite");

    let connection = Connection::open(&database)?;
    let created: u64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE type='index' AND name='checks_identity_order'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(created, 1, "new journals need the identity lookup index");
    connection.execute_batch("DROP INDEX checks_identity_order")?;
    drop(connection);

    let journal = Journal::open(directory.path(), JournalOptions::default())?;
    drop(journal);
    let connection = Connection::open(database)?;
    let restored: u64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE type='index' AND name='checks_identity_order'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        restored, 1,
        "writable open must repair a compatible journal created before this index existed"
    );

    let detail: String = connection.query_row(
        "EXPLAIN QUERY PLAN SELECT id FROM checks WHERE identity=?1 ORDER BY id LIMIT 1",
        ["0".repeat(64)],
        |row| row.get(3),
    )?;
    assert!(
        detail.contains("checks_identity_order"),
        "identity lookup should use its index: {detail}"
    );
    Ok(())
}

#[test]
fn read_only_journal_verification() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut journal = Journal::create(directory.path(), &Case::new(), JournalOptions::default())?;
    let hypothesis = journal.record(&model())?;
    journal.record_check(&hypothesis, &check(), b"evidence")?;
    journal.verify()?;
    drop(journal);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            directory.path().join("journal.sqlite"),
            fs::Permissions::from_mode(0o444),
        )?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o555))?;
    }
    let result = (|| -> Result<(), Box<dyn Error>> {
        let mut journal = Journal::open_readonly(directory.path(), JournalOptions::default())?;
        journal.verify()?;
        assert_eq!(journal.entry(&hypothesis)?.checks.len(), 1);
        journal.visit_review(None, |_| Ok(()))?;
        let mut exported = Cursor::new(Vec::new());
        journal.write_evidence("1", &mut exported)?;
        assert_eq!(exported.into_inner(), b"evidence");
        assert!(journal.record_event(&event(1)).is_err());
        Ok(())
    })();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(
            directory.path().join("journal.sqlite"),
            fs::Permissions::from_mode(0o600),
        )?;
    }
    result?;
    Ok(())
}

#[test]
fn evidence_hash_bytes_reach_writer() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut journal = Journal::create(directory.path(), &Case::new(), JournalOptions::default())?;
    let hypothesis = journal.record(&model())?;
    journal.record_check(&hypothesis, &check(), b"original evidence")?;
    let evidence_hash = journal
        .entry(&hypothesis)?
        .checks
        .first()
        .ok_or("missing recorded check")?
        .evidence_sha256
        .clone();
    drop(journal);

    let connection = Connection::open(directory.path().join("journal.sqlite"))?;
    connection.execute(
        "UPDATE objects SET bytes=?1 WHERE sha256=?2",
        rusqlite::params![b"tampered evidence".as_slice(), evidence_hash],
    )?;
    drop(connection);

    let journal = Journal::open_readonly(directory.path(), JournalOptions::default())?;
    let mut output = Cursor::new(Vec::new());
    assert!(journal.write_evidence(&evidence_hash, &mut output).is_err());
    assert_eq!(output.into_inner().len(), 0);
    Ok(())
}

#[test]
fn v1_migration_legacy_binding_unverified() -> Result<(), Box<dyn Error>> {
    let source = tempfile::tempdir()?;
    let (hypothesis, derived) = create_legacy_fixture(source.path(), 1, CheckOutcome::Pass)?;
    let original_database = fs::read(source.path().join("journal.sqlite"))?;
    let original_case = fs::read(source.path().join("base-case.json"))?;
    let destination = tempfile::tempdir()?;

    Journal::migrate_copy(source.path(), destination.path(), JournalOptions::default())?;
    let migrated = Journal::open(destination.path(), JournalOptions::default())?;
    migrated.verify()?;
    let entry = migrated.entry(&hypothesis)?;
    assert_eq!(entry.checks.len(), 1);
    assert_eq!(
        entry
            .checks
            .first()
            .ok_or("missing migrated check")?
            .binding_origin,
        CheckBindingOrigin::LegacyUnverified
    );
    assert_eq!(entry.conclusion, "unresolved");
    let legacy_check = entry.checks.first().ok_or("missing legacy check")?;
    let mut evidence = Cursor::new(Vec::new());
    migrated.write_evidence(&legacy_check.identity, &mut evidence)?;
    assert_eq!(evidence.into_inner(), b"retained check evidence");
    assert_eq!(migrated.output(&derived)?, b"cba");
    let overview = migrated.overview()?;
    assert_eq!(overview.events, 1);
    assert!(
        overview.limitations.iter().any(|limitation| {
            limitation.contains("Legacy-unverified checks remain in history")
        })
    );
    assert_eq!(
        fs::read(source.path().join("journal.sqlite"))?,
        original_database
    );
    assert_eq!(
        fs::read(source.path().join("base-case.json"))?,
        original_case
    );
    let old_version: u32 = Connection::open(source.path().join("journal.sqlite"))?
        .pragma_query_value(None, "user_version", |row| row.get(0))?;
    assert_eq!(old_version, 1);
    Ok(())
}

#[test]
fn migration_oversized_case_hash_loading() -> Result<(), Box<dyn Error>> {
    let source = tempfile::tempdir()?;
    create_legacy_fixture(source.path(), 2, CheckOutcome::Pass)?;
    let connection = Connection::open(source.path().join("journal.sqlite"))?;
    connection.execute(
        "UPDATE metadata SET value=?1 WHERE key='base_case_sha256'",
        ["x".repeat(65_536)],
    )?;
    drop(connection);
    let destination = tempfile::tempdir()?;

    let error = match Journal::migrate_copy(
        source.path(),
        destination.path(),
        JournalOptions {
            max_entry_bytes: 1024,
            ..JournalOptions::default()
        },
    ) {
        Err(error) => error.to_string(),
        Ok(()) => return Err("migration accepted oversized base-case metadata".into()),
    };
    assert!(error.contains("base-case metadata must be a 64-character SHA-256 hash"));
    Ok(())
}

#[test]
fn legacy_failure_not_migrated_hypothesis() -> Result<(), Box<dyn Error>> {
    let source = tempfile::tempdir()?;
    let (hypothesis, _) = create_legacy_fixture(source.path(), 1, CheckOutcome::Fail)?;
    let destination = tempfile::tempdir()?;

    Journal::migrate_copy(source.path(), destination.path(), JournalOptions::default())?;
    let migrated = Journal::open_readonly(destination.path(), JournalOptions::default())?;
    let entry = migrated.entry(&hypothesis)?;

    assert_eq!(entry.conclusion, "unresolved");
    assert_eq!(
        entry.checks.first().map(|check| check.check.outcome),
        Some(CheckOutcome::Fail)
    );
    assert_eq!(
        entry.checks.first().map(|check| check.binding_origin),
        Some(CheckBindingOrigin::LegacyUnverified)
    );
    Ok(())
}

#[test]
fn recorded_checks_control_conclusion_migration() -> Result<(), Box<dyn Error>> {
    for (legacy_outcome, recorded_outcome, expected_conclusion) in [
        (
            CheckOutcome::Fail,
            CheckOutcome::Pass,
            "best_supported_under_recorded_checks",
        ),
        (
            CheckOutcome::Pass,
            CheckOutcome::Fail,
            "falsified_under_recorded_checks",
        ),
    ] {
        let source = tempfile::tempdir()?;
        let (hypothesis, _) = create_legacy_fixture(source.path(), 1, legacy_outcome)?;
        let destination = tempfile::tempdir()?;

        Journal::migrate_copy(source.path(), destination.path(), JournalOptions::default())?;
        let mut migrated = Journal::open(destination.path(), JournalOptions::default())?;
        assert_eq!(migrated.entry(&hypothesis)?.conclusion, "unresolved");

        let mut current_check = check_with_outcome(recorded_outcome);
        current_check.explanation = "new evidence bound after migration".into();
        migrated.record_check(&hypothesis, &current_check, b"newly bound evidence")?;

        let entry = migrated.entry(&hypothesis)?;
        assert_eq!(entry.conclusion, expected_conclusion);
        assert_eq!(entry.checks.len(), 2);
        assert_eq!(
            entry.checks.first().map(|check| check.binding_origin),
            Some(CheckBindingOrigin::LegacyUnverified)
        );
        assert_eq!(
            entry.checks.get(1).map(|check| check.binding_origin),
            Some(CheckBindingOrigin::Recorded)
        );
    }
    Ok(())
}

#[test]
fn ranks_recorded_pass_legacy() -> Result<(), Box<dyn Error>> {
    let (legacy, recorded, reviewed) = review_order_for_migrated_pair(CheckOutcome::Pass, false)?;
    assert_eq!(reviewed.first(), Some(&recorded));
    assert!(reviewed.contains(&legacy));
    Ok(())
}

#[test]
fn not_rank_failure_recorded() -> Result<(), Box<dyn Error>> {
    let (legacy, recorded, reviewed) = review_order_for_migrated_pair(CheckOutcome::Fail, true)?;
    assert_eq!(reviewed.first(), Some(&legacy));
    assert!(reviewed.contains(&recorded));
    Ok(())
}

fn review_order_for_migrated_pair(
    outcome: CheckOutcome,
    legacy_is_larger: bool,
) -> Result<(String, String, Vec<String>), Box<dyn Error>> {
    let source = tempfile::tempdir()?;
    let mut journal = Journal::create(source.path(), &Case::new(), JournalOptions::default())?;
    let mut first = model();
    first.input = json!({"source":0});
    let mut second = model();
    second.input = json!({"source":1});
    let first_id = journal.record(&first)?;
    let second_id = journal.record(&second)?;
    let (lower_id, higher_id) = if first_id < second_id {
        (first_id, second_id)
    } else {
        (second_id, first_id)
    };
    let (legacy, recorded) = if legacy_is_larger {
        (higher_id, lower_id)
    } else {
        (lower_id, higher_id)
    };
    journal.record_check(
        &legacy,
        &check_with_outcome(outcome),
        b"legacy check evidence",
    )?;
    drop(journal);
    downgrade_legacy_schema(source.path(), 1)?;

    let destination = tempfile::tempdir()?;
    Journal::migrate_copy(source.path(), destination.path(), JournalOptions::default())?;
    let mut migrated = Journal::open(destination.path(), JournalOptions::default())?;
    migrated.record_check(
        &recorded,
        &check_with_outcome(outcome),
        b"current check evidence",
    )?;

    let mut reviewed = Vec::new();
    migrated.visit_review(None, |entry| {
        reviewed.push(entry.id);
        Ok(())
    })?;
    Ok((legacy, recorded, reviewed))
}

#[test]
fn failed_v1_original_database_unchanged() -> Result<(), Box<dyn Error>> {
    let source = tempfile::tempdir()?;
    let (_hypothesis, _) = create_legacy_fixture(source.path(), 1, CheckOutcome::Pass)?;
    let connection = Connection::open(source.path().join("journal.sqlite"))?;
    connection.execute("UPDATE checks SET value='not json'", [])?;
    drop(connection);
    let original_database = fs::read(source.path().join("journal.sqlite"))?;
    let destination = tempfile::tempdir()?;

    assert!(
        Journal::migrate_copy(source.path(), destination.path(), JournalOptions::default())
            .is_err()
    );
    assert_eq!(
        fs::read(source.path().join("journal.sqlite"))?,
        original_database
    );
    let old_version: u32 = Connection::open(source.path().join("journal.sqlite"))?
        .pragma_query_value(None, "user_version", |row| row.get(0))?;
    assert_eq!(old_version, 1);
    Ok(())
}

#[test]
fn migration_oversized_hashes_loading() -> Result<(), Box<dyn Error>> {
    let cases: &[(u32, &str)] = &[
        (1, "hypothesis"),
        (1, "evidence"),
        (2, "hypothesis"),
        (2, "identity"),
        (2, "evidence"),
    ];
    for (version, column) in cases {
        let source = tempfile::tempdir()?;
        create_legacy_fixture(source.path(), *version, CheckOutcome::Pass)?;
        let connection = Connection::open(source.path().join("journal.sqlite"))?;
        // Permit this fixture to contain the invalid reference checked by migration
        connection.pragma_update(None, "foreign_keys", false)?;
        connection.execute(
            &format!("UPDATE checks SET {column}=?1"),
            ["x".repeat(65_536)],
        )?;
        drop(connection);
        let destination = tempfile::tempdir()?;

        let Err(error) =
            Journal::migrate_copy(source.path(), destination.path(), JournalOptions::default())
        else {
            return Err("migration accepted an oversized check hash".into());
        };
        assert!(
            error.to_string().contains(&format!(
                "legacy check {column} must be a 64-character SHA-256 hash"
            )),
            "unexpected migration error for version {version} {column}: {error}"
        );
    }
    Ok(())
}

#[test]
fn migration_oversized_values_decoding_json() -> Result<(), Box<dyn Error>> {
    for version in [1, 2] {
        let source = tempfile::tempdir()?;
        create_legacy_fixture(source.path(), version, CheckOutcome::Pass)?;
        let connection = Connection::open(source.path().join("journal.sqlite"))?;
        connection.execute("UPDATE checks SET value=?1", ["[".repeat(65_536)])?;
        drop(connection);
        let destination = tempfile::tempdir()?;

        let Err(error) = Journal::migrate_copy(
            source.path(),
            destination.path(),
            JournalOptions {
                max_entry_bytes: 1024,
                ..JournalOptions::default()
            },
        ) else {
            return Err("migration accepted an oversized check value".into());
        };
        assert!(
            error
                .to_string()
                .contains("legacy check exceeds the migration metadata budget"),
            "unexpected migration error for version {version}: {error}"
        );
    }
    Ok(())
}

#[test]
fn migration_accepts_exact_metadata_budget() -> Result<(), Box<dyn Error>> {
    for version in [1, 2] {
        let source = tempfile::tempdir()?;
        let mut journal = Journal::create(source.path(), &Case::new(), JournalOptions::default())?;
        let hypothesis = journal.record(&model())?;
        let check = Check {
            kind: CheckKind::Structural,
            outcome: CheckOutcome::Pass,
            explanation: "x".repeat(4096),
        };
        journal.record_check(&hypothesis, &check, b"boundary evidence")?;
        drop(journal);
        downgrade_legacy_schema(source.path(), version)?;
        let connection = Connection::open(source.path().join("journal.sqlite"))?;
        let value_length: usize = connection.query_row(
            "SELECT length(CAST(value AS BLOB)) FROM checks",
            [],
            |row| row.get(0),
        )?;
        drop(connection);
        let destination = tempfile::tempdir()?;

        Journal::migrate_copy(
            source.path(),
            destination.path(),
            JournalOptions {
                max_entry_bytes: value_length,
                ..JournalOptions::default()
            },
        )?;
        Journal::open_readonly(
            destination.path(),
            JournalOptions {
                max_entry_bytes: value_length,
                ..JournalOptions::default()
            },
        )?
        .verify()?;
    }
    Ok(())
}

#[test]
fn migration_accepts_exact_file_budget() -> Result<(), Box<dyn Error>> {
    let source = tempfile::tempdir()?;
    create_legacy_fixture(source.path(), 2, CheckOutcome::Pass)?;
    let base_path = source.path().join("base-case.json");
    let current_length = usize::try_from(fs::metadata(&base_path)?.len())?;
    let padding_length = l2_workbench::evidence::MAX_CASE_JSON_BYTES
        .checked_sub(current_length)
        .ok_or("base-case fixture already exceeds its file budget")?;
    let mut base = fs::OpenOptions::new().append(true).open(&base_path)?;
    let padding = vec![b' '; 64 * 1024].into_boxed_slice();
    let mut remaining = padding_length;
    while remaining != 0 {
        let count = remaining.min(padding.len());
        base.write_all(
            padding
                .get(..count)
                .ok_or("padding chunk exceeds its buffer")?,
        )?;
        remaining -= count;
    }
    base.sync_all()?;
    drop(base);
    let bytes = fs::read(&base_path)?;
    assert_eq!(bytes.len(), l2_workbench::evidence::MAX_CASE_JSON_BYTES);
    let connection = Connection::open(source.path().join("journal.sqlite"))?;
    connection.execute(
        "UPDATE metadata SET value=?1 WHERE key='base_case_sha256'",
        [sha256(&bytes)],
    )?;
    drop(connection);
    let destination = tempfile::tempdir()?;

    Journal::migrate_copy(source.path(), destination.path(), JournalOptions::default())?;
    Journal::open_readonly(destination.path(), JournalOptions::default())?.verify()?;
    Ok(())
}

#[test]
fn v2_migration_recorded_bindings() -> Result<(), Box<dyn Error>> {
    let source = tempfile::tempdir()?;
    let (hypothesis, _derived) = create_legacy_fixture(source.path(), 2, CheckOutcome::Pass)?;
    let original_database = fs::read(source.path().join("journal.sqlite"))?;
    let destination = tempfile::tempdir()?;

    Journal::migrate_copy(source.path(), destination.path(), JournalOptions::default())?;
    let migrated = Journal::open_readonly(destination.path(), JournalOptions::default())?;
    migrated.verify()?;
    let migrated_check = migrated
        .entry(&hypothesis)?
        .checks
        .into_iter()
        .next()
        .ok_or("missing migrated check")?;
    assert_eq!(migrated_check.binding_origin, CheckBindingOrigin::Recorded);
    assert_eq!(
        fs::read(source.path().join("journal.sqlite"))?,
        original_database
    );
    let old_version: u32 = Connection::open(source.path().join("journal.sqlite"))?
        .pragma_query_value(None, "user_version", |row| row.get(0))?;
    assert_eq!(old_version, 2);
    Ok(())
}

#[test]
fn tshark_import_exact_source_raw() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let capture = b"capture";
    let capture_hash = sha256(capture);
    let report = tshark_report(&capture_hash, &[1, 2])?;
    let mut journal = Journal::create(directory.path(), &Case::new(), JournalOptions::default())?;

    let receipt_hash = journal.import_tshark_report(&report, &capture_hash, 7)?;
    let mut events = Vec::new();
    journal.visit_events(0, None, |event| {
        events.push(event);
        Ok(())
    })?;
    assert_eq!(events.len(), 2);
    let first_event = events.first().ok_or("missing first TShark event")?;
    assert_eq!(first_event.kind, "tshark_frame");
    assert_eq!(first_event.source, format!("sha256:{capture_hash}"));
    assert_eq!(first_event.ranges.len(), 0);
    assert_eq!(
        first_event
            .fields
            .get("receipt_sha256")
            .and_then(Value::as_str),
        Some(receipt_hash.as_str())
    );
    let reassembled_fields = first_event
        .fields
        .get("reassembled_fields")
        .and_then(Value::as_array)
        .ok_or("missing TShark reassembled fields")?;
    assert_eq!(reassembled_fields.len(), 1);
    assert_eq!(
        reassembled_fields.first().and_then(Value::as_str),
        Some("tcp.payload")
    );
    assert_eq!(journal.visit_tool_receipts(None, None, |_| Ok(()))?, 1);
    journal.verify()?;
    Ok(())
}

#[test]
fn tool_receipt_over_configured_budget() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let source_hash = sha256(b"capture");
    let mut report = tshark_report(&source_hash, &[1])?;
    report.resize(1024 * 1024, b' ');

    let mut journal = Journal::create(directory.path(), &Case::new(), JournalOptions::default())?;
    journal.import_tshark_report(&report, &source_hash, 7)?;
    drop(journal);

    let journal = Journal::open_readonly(
        directory.path(),
        JournalOptions {
            max_tool_report_bytes: 1024,
            ..JournalOptions::default()
        },
    )?;
    assert!(journal.visit_tool_receipts(None, None, |_| Ok(())).is_err());
    Ok(())
}

#[test]
fn tshark_import_frames_without_partial() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let capture_hash = sha256(b"capture");
    let mut journal = Journal::create(directory.path(), &Case::new(), JournalOptions::default())?;
    let valid = tshark_report(&capture_hash, &[1])?;
    assert!(
        journal
            .import_tshark_report(&valid, &sha256(b"other capture"), 7)
            .is_err()
    );
    let duplicated = tshark_report(&capture_hash, &[1, 1])?;
    assert!(
        journal
            .import_tshark_report(&duplicated, &capture_hash, 7)
            .is_err()
    );
    let mut mismatched = serde_json::from_slice::<Value>(&valid)?;
    *mismatched
        .pointer_mut("/packets/0/fields/frame/frame.number")
        .ok_or("missing packet frame number")? = json!(2);
    let mismatched = serde_json::to_vec(&mismatched)?;
    assert!(
        journal
            .import_tshark_report(&mismatched, &capture_hash, 7)
            .is_err()
    );
    assert_eq!(journal.overview()?.events, 0);
    assert_eq!(journal.visit_tool_receipts(None, None, |_| Ok(()))?, 0);
    Ok(())
}

#[test]
fn tool_receipt_event_index_columns() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let source_hash = sha256(b"capture");
    let report = tshark_report(&source_hash, &[1])?;
    let mut journal = Journal::create(directory.path(), &Case::new(), JournalOptions::default())?;
    journal.import_tshark_report(&report, &source_hash, 7)?;
    drop(journal);

    let connection = Connection::open(directory.path().join("journal.sqlite"))?;
    connection.execute("UPDATE events SET packet=2", [])?;
    drop(connection);

    let journal = Journal::open_readonly(directory.path(), JournalOptions::default())?;
    assert!(journal.visit_tool_receipts(None, None, |_| Ok(())).is_err());
    Ok(())
}

#[test]
fn journal_event_canonical_keyset_limits() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut journal = Journal::create(directory.path(), &Case::new(), JournalOptions::default())?;
    journal.record_event(&event(3))?;
    journal.record_event(&event(1))?;
    journal.record_event(&event(2))?;
    let mut packets = Vec::new();
    let emitted = journal.visit_events(1, Some(1), |event| {
        packets.push(event.packet);
        Ok(())
    })?;
    assert_eq!(emitted, 1);
    assert_eq!(packets, [1]);
    Ok(())
}

#[test]
fn nested_snapshots_same_journal_transaction() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut journal = Journal::create(directory.path(), &Case::new(), JournalOptions::default())?;
    journal.record_event(&event(1))?;

    journal.read_snapshot(|snapshot| {
        assert_eq!(snapshot.overview()?.events, 1);
        snapshot.read_snapshot(|nested| {
            nested.verify()?;
            let mut events = 0_u64;
            nested.visit_events(0, None, |_| {
                events += 1;
                Ok(())
            })?;
            nested.visit_review(None, |_| Ok(()))?;
            assert_eq!(events, 1);
            Ok(())
        })
    })?;
    assert_eq!(journal.overview()?.events, 1);
    Ok(())
}
