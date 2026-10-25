use super::{capture, dns, frames, udp, vlan};
use l2_workbench::store::{Options, Store};
use rusqlite::Connection;
use std::{error::Error, io::Cursor};

#[test]
fn repeated_scopes_once_referenced_integer() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    for (label, sequence) in [("first", 100), ("second", 200)] {
        let packets = [
            udp(false, &dns(false))?,
            udp(true, &dns(true))?,
            frames::tcp(false, sequence, 2, b"")?,
        ];
        store.ingest(label, Cursor::new(capture(&packets)?))?;
    }
    let connection = Connection::open(temporary.path().join("index.sqlite"))?;
    assert_eq!(
        connection.query_row("SELECT COUNT(*) FROM scopes", [], |row| row
            .get::<_, u64>(0))?,
        1
    );
    for table in ["flows", "dns_addresses", "shared_facts"] {
        let query = format!("SELECT COUNT(*) FROM {table} WHERE typeof(scope)!='integer'");
        assert_eq!(
            connection.query_row(&query, [], |row| row.get::<_, u64>(0))?,
            0
        );
    }
    let mut relationships = 0;
    store.visit_relationships(None, |_| {
        relationships += 1;
        Ok(())
    })?;
    assert_eq!(relationships, 2);
    store.verify_sources()?;
    Ok(())
}

#[test]
fn normalized_scopes_distinct_vlans_separate() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let packet = frames::tcp(false, 100, 2, b"")?;
    let source = store.ingest(
        "vlans",
        Cursor::new(capture(&[
            vlan(&packet, 7)?,
            vlan(&packet, 8)?,
            vlan(&packet, 7)?,
        ])?),
    )?;
    assert_eq!(store.inventory()?.flows, 2);
    assert_eq!(
        store.packet(&source.source_id, 1)?.flow,
        store.packet(&source.source_id, 3)?.flow
    );
    assert_ne!(
        store.packet(&source.source_id, 1)?.flow,
        store.packet(&source.source_id, 2)?.flow
    );
    let mut exported_scopes = Vec::new();
    store.visit_flows(0, None, |flow| {
        let value = serde_json::to_value(flow)?;
        exported_scopes.push(value.get("scope").cloned());
        Ok(())
    })?;
    assert_eq!(
        exported_scopes,
        [
            Some(
                serde_json::json!({"section":0,"interface":0,"vlan_ids":[[33024,7]],"vlan_aux":null})
            ),
            Some(
                serde_json::json!({"section":0,"interface":0,"vlan_ids":[[33024,8]],"vlan_aux":null})
            ),
        ]
    );
    let connection = Connection::open(temporary.path().join("index.sqlite"))?;
    assert_eq!(
        connection.query_row("SELECT COUNT(*) FROM scopes", [], |row| row
            .get::<_, u64>(0))?,
        2
    );
    store.verify_sources()?;
    Ok(())
}

#[test]
fn verification_rebuilds_trusting_integer_references() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    store.ingest(
        "scope",
        Cursor::new(capture(&[frames::tcp(false, 1, 2, b"")?])?),
    )?;
    let connection = Connection::open(temporary.path().join("index.sqlite"))?;
    connection.execute("UPDATE scopes SET value=X'7b7d'", [])?;
    assert!(store.verify_sources().is_err());
    Ok(())
}

#[test]
fn verification_unused_normalized_scope_rows() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    store.ingest(
        "scope",
        Cursor::new(capture(&[frames::tcp(false, 1, 2, b"")?])?),
    )?;
    let connection = Connection::open(temporary.path().join("index.sqlite"))?;
    connection.execute("INSERT INTO scopes(value) VALUES(X'7b7d')", [])?;
    assert!(store.verify_sources().is_err());
    Ok(())
}
