use crate::{
    evidence::Case,
    journal::{ChainDeadline, ChainPlan, Event, EventSelector, Journal, JournalOptions, Result},
};
use rusqlite::ErrorCode;
use serde_json::json;
use std::{
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    time::Instant,
};

const COUNT_QUERY: &str = "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10000) SELECT sum(x) FROM n";

fn journal_with_event() -> Result<(tempfile::TempDir, Journal)> {
    let directory = tempfile::tempdir()?;
    let mut journal = Journal::create(directory.path(), &Case::new(), JournalOptions::default())?;
    journal.record_event(&Event {
        source: "capture".into(),
        scope: "lan".into(),
        packet: 1,
        kind: "observation".into(),
        actor: None,
        peer: None,
        clock: None,
        ticks: None,
        fields: json!({}),
        ranges: Vec::new(),
    })?;
    Ok((directory, journal))
}

fn plan() -> ChainPlan {
    ChainPlan {
        steps: vec![EventSelector::default()],
        same_actor: false,
        max_gap_ticks: None,
        limit: Some(1),
        joins: Vec::new(),
        max_elapsed_ms: ChainDeadline::limited(30_000),
    }
}

fn expire_handler(journal: &Journal) -> Result<()> {
    // Arm the live SQLite handler without relying on a thread sleep
    *journal
        .chain_deadline
        .lock()
        .map_err(|_| std::io::Error::other("deadline state is unavailable"))? =
        Some(Instant::now());
    Ok(())
}

#[test]
fn sqlite_deadline_expiry() -> Result<()> {
    let (_directory, journal) = journal_with_event()?;
    let mut query_result = None;

    let _ = journal.visit_chains(&plan(), |_| {
        expire_handler(&journal)?;
        // The recursive query runs enough SQLite instructions to invoke the handler
        query_result = Some(
            journal
                .connection
                .query_row(COUNT_QUERY, [], |row| row.get::<_, i64>(0)),
        );
        Ok(())
    });

    let query_result = query_result.ok_or("the visitor did not run")?;
    assert!(
        matches!(&query_result, Err(rusqlite::Error::SqliteFailure(error, _)) if error.code == ErrorCode::OperationInterrupted),
        "the expired deadline must interrupt SQLite: {query_result:?}"
    );
    Ok(())
}

#[test]
fn sqlite_unwind_cleanup() -> Result<()> {
    let (_directory, journal) = journal_with_event()?;
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let _ = journal.visit_chains(&plan(), |_| {
            expire_handler(&journal)?;
            resume_unwind(Box::new("visitor unwind"))
        });
    }));
    let payload = outcome.err().ok_or("the visitor did not unwind")?;
    assert_eq!(
        payload.downcast_ref::<&str>().copied(),
        Some("visitor unwind")
    );

    // An unrelated query runs before another chain can replace the deadline
    let count = journal
        .connection
        .query_row(COUNT_QUERY, [], |row| row.get::<_, i64>(0));
    assert!(
        count.is_ok(),
        "the expired handler must be cleared: {count:?}"
    );
    assert_eq!(count?, 50_005_000);
    Ok(())
}
