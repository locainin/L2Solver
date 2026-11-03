//! Keep validated recovery results usable while another SQLite writer is active

use super::*;
use rusqlite::Connection;

#[test]
fn strict_recovery_reuses_validated_case_during_sqlite_writer_contention()
-> Result<(), Box<dyn Error>> {
    assert_writer_does_not_force_recovery(true)
}

#[test]
fn optional_recovery_reuses_validated_case_during_sqlite_writer_contention()
-> Result<(), Box<dyn Error>> {
    assert_writer_does_not_force_recovery(false)
}

fn assert_writer_does_not_force_recovery(strict_cache: bool) -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = open_cache(temporary.path())?;
    let options = RecoveryOptions {
        strict_cache,
        ..RecoveryOptions::default()
    };
    let (mut expected_case, scope) = case_and_scope(b"4142", 107)?;
    let expected = recover(
        &mut expected_case,
        RecoveryCaseKind::Flow,
        &scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: None,
            options: &options,
        },
    )?;
    assert!(expected.coverage.candidates > 0);

    let writer = Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    let journal: String = writer.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    assert_eq!(journal, "wal");
    // BEGIN IMMEDIATE deterministically holds the real WAL writer lock
    writer.execute_batch("BEGIN IMMEDIATE; UPDATE entries SET accessed_ns = accessed_ns;")?;
    let job = Job::new("reuse during SQLite writer contention");
    let (mut actual_case, actual_scope) = case_and_scope(b"4142", 107)?;
    let actual = recover(
        &mut actual_case,
        RecoveryCaseKind::Flow,
        &actual_scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: Some(&job),
            options: &options,
        },
    )?;
    // Compare the entire evidence graph and provenance, not just an artifact hash
    assert_cases_equal(&actual_case, &expected_case);
    assert_eq!(
        serde_json::to_value(actual.coverage)?,
        serde_json::to_value(expected.coverage)?
    );
    assert_eq!(actual.omissions, expected.omissions);
    assert_reused_without_work(&job)?;
    writer.execute_batch("ROLLBACK;")?;

    let key = recovery_key(RecoveryCaseKind::Flow, &scope, &options)?;
    assert!(cache.lookup(&key, CacheReadPolicy::CompleteOnly)?.is_some());
    Ok(())
}

fn assert_reused_without_work(job: &Job) -> Result<(), Box<dyn Error>> {
    let snapshot = job.snapshot()?;
    assert_eq!(snapshot.counters.get(&Counter::CacheHits), Some(&1));
    assert!(snapshot.cache_fallbacks.records().is_empty());
    for counter in [
        Counter::CacheMisses,
        Counter::CandidatesExamined,
        Counter::ValidatedArtifacts,
    ] {
        assert_eq!(
            snapshot.counters.get(&counter).copied().unwrap_or(0),
            0,
            "validated cache hit performed {counter:?} work"
        );
    }
    Ok(())
}
