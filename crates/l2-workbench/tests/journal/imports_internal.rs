use super::{Event, Journal, Result};
use crate::{
    evidence::{Case, SourceRange},
    journal::JournalOptions,
    store::{Options, Store},
};
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use serde_json::json;
use std::{io::Cursor, sync::mpsc, thread, time::Duration};

const WAIT: Duration = Duration::from_secs(30);

#[test]
fn case_import_transaction_count() -> Result<()> {
    let mut case = Case::new();
    let source = case.add_source("capture", "capture", 1, &"a".repeat(64), None)?;
    let range = SourceRange {
        source,
        packet: Some(1),
        offset: 0,
        length: 1,
    };
    case.add_node("packet", None, vec![range.clone()], json!({}))?;
    case.add_node("packet", None, vec![range.clone()], json!({}))?;
    case.add_node("observation", None, vec![range.clone()], json!({}))?;
    let events = assert_import_count(2, |journal| journal.import_case_events(&case))?;
    let observation = events
        .iter()
        .find(|event| event.kind == "observation")
        .ok_or("imported observation is missing")?;
    assert_eq!(observation.ranges, vec![range]);
    Ok(())
}

#[test]
fn index_import_transaction_count() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut store = Store::create(directory.path(), Options::default())?;
    // A single Ethernet record is enough to exercise the index import
    let mut capture = Vec::new();
    capture.extend_from_slice(&0xa1b2_c3d4_u32.to_le_bytes());
    capture.extend_from_slice(&[2, 0, 4, 0]);
    capture.extend_from_slice(&[0; 8]);
    capture.extend_from_slice(&65_535_u32.to_le_bytes());
    capture.extend_from_slice(&1_u32.to_le_bytes());
    capture.extend_from_slice(&1_u32.to_le_bytes());
    capture.extend_from_slice(&0_u32.to_le_bytes());
    capture.extend_from_slice(&14_u32.to_le_bytes());
    capture.extend_from_slice(&14_u32.to_le_bytes());
    capture.extend_from_slice(&[0; 14]);
    store.ingest("capture", Cursor::new(capture))?;
    assert_import_count(1, |journal| journal.import_index_events(&store))?;
    Ok(())
}

fn assert_import_count(
    expected: u64,
    import: impl FnOnce(&mut Journal) -> Result<u64>,
) -> Result<Vec<Event>> {
    let directory = tempfile::tempdir()?;
    let mut journal = Journal::create(directory.path(), &Case::new(), JournalOptions::default())?;
    let path = directory.path().to_owned();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    let writer = thread::spawn(move || {
        let mut journal =
            Journal::open(&path, JournalOptions::default()).map_err(|error| error.to_string())?;
        ready_tx.send(()).map_err(|error| error.to_string())?;
        release_rx
            .recv_timeout(WAIT)
            .map_err(|error| error.to_string())?;
        let event = Event {
            source: "other".into(),
            scope: "other".into(),
            packet: 1,
            kind: "other".into(),
            actor: None,
            peer: None,
            clock: None,
            ticks: None,
            fields: json!({}),
            ranges: Vec::new(),
        };
        journal
            .record_event(&event)
            .map_err(|error| error.to_string())?;
        finished_tx.send(()).map_err(|error| error.to_string())
    });
    ready_rx.recv_timeout(WAIT)?;
    let mut release = Some(release_tx);
    journal
        .connection
        .authorizer(Some(move |context: AuthContext<'_>| {
            if matches!(
                context.action,
                AuthAction::Insert {
                    table_name: "events"
                }
            ) && let Some(release) = release.take()
            {
                // Commit the other writer after any preliminary counts and before this insert
                if release.send(()).is_err() || finished_rx.recv_timeout(WAIT).is_err() {
                    return Authorization::Deny;
                }
            }
            Authorization::Allow
        }))?;
    let added = import(&mut journal)?;
    writer.join().map_err(|_| "concurrent writer panicked")??;
    assert_eq!(
        added, expected,
        "the other writer is not part of this import"
    );
    assert_eq!(journal.overview()?.events, expected + 1);
    let mut events = Vec::new();
    journal.visit_events(0, None, |event| {
        events.push(event);
        Ok(())
    })?;
    Ok(events)
}
