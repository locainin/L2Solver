use super::{capture, frames, vlan};
use l2_workbench::store::{Options, Store};
use rusqlite::Connection;
use std::{error::Error, io::Cursor, path::Path};

fn count_insert_attempts(path: &Path) -> Result<Connection, Box<dyn Error>> {
    let connection = Connection::open(path)?;
    connection.execute_batch(
        "CREATE TABLE insert_attempts(table_name TEXT NOT NULL);
        CREATE TRIGGER count_scope_inserts BEFORE INSERT ON scopes
        BEGIN INSERT INTO insert_attempts VALUES('scopes'); END;
        CREATE TRIGGER count_flow_inserts BEFORE INSERT ON flows
        BEGIN INSERT INTO insert_attempts VALUES('flows'); END;",
    )?;
    Ok(connection)
}

fn attempts(connection: &Connection, table: &str) -> Result<u64, rusqlite::Error> {
    connection.query_row(
        "SELECT COUNT(*) FROM insert_attempts WHERE table_name=?1",
        [table],
        |row| row.get(0),
    )
}

#[test]
fn alternating_scope_bounded_cache_entries() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let connection = count_insert_attempts(&temporary.path().join("index.sqlite"))?;
    let frame = frames::tcp(false, 100, 2, b"")?;
    let packets = [vlan(&frame, 7)?, vlan(&frame, 8)?, vlan(&frame, 7)?];
    store.ingest("alternating-scopes", Cursor::new(capture(&packets)?))?;

    assert_eq!(store.inventory()?.flows, 2);
    assert_eq!(attempts(&connection, "scopes")?, 2);
    assert_eq!(attempts(&connection, "flows")?, 2);
    store.verify_sources()?;
    Ok(())
}

#[test]
fn operator_cache_without_allocating_memory() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let store = Store::create(directory.path(), Options { cache_mib: 65_537 })?;
    assert_eq!(store.inventory()?.packets, 0);
    store.verify_sources()?;
    Ok(())
}
