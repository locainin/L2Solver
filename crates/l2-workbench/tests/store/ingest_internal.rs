#[path = "../reconstruction/ipv4.rs"]
mod ipv4;

use crate::{sha256, store::Options};
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    io::{self, Cursor},
    path::PathBuf,
};

use super::super::Store;

struct OrphanedSource {
    temporary: tempfile::TempDir,
    store: Store,
    bytes: Vec<u8>,
    path: PathBuf,
}

#[path = "../reconstruction/tcp.rs"]
mod frames;
#[path = "support.rs"]
mod support;

#[test]
fn source_directory_not_commit_row() -> Result<(), Box<dyn Error>> {
    let fixture = orphaned_source()?;
    assert_eq!(fixture.store.inventory()?.sources, 0);
    assert_eq!(std::fs::read(&fixture.path)?, fixture.bytes);
    fixture.store.verify_sources()?;
    Ok(())
}

#[test]
fn retry_reuses_orphan_postpublication_failure() -> Result<(), Box<dyn Error>> {
    let mut fixture = orphaned_source()?;

    let receipt = fixture
        .store
        .ingest("retry-source.pcap", Cursor::new(&fixture.bytes))?;

    assert_eq!(
        receipt.source_id,
        format!("sha256:{}", sha256(&fixture.bytes))
    );
    assert_eq!(fixture.store.inventory()?.sources, 1);
    assert!(fixture.store.packet(&receipt.source_id, 1)?.flow.is_some());
    assert_eq!(
        fixture.store.frame(&receipt.source_id, 1)?.bytes(),
        frames::tcp(false, 1, 0x18, b"payload")?.bytes()
    );
    assert_eq!(std::fs::read(&fixture.path)?, fixture.bytes);
    fixture.store.verify_sources()?;
    Ok(())
}

#[test]
fn retry_corrupt_occupied_source_path() -> Result<(), Box<dyn Error>> {
    let mut fixture = orphaned_source()?;
    let mut corrupt = fixture.bytes.clone();
    let first_byte = corrupt.get_mut(0).ok_or("empty source fixture")?;
    *first_byte ^= 0xff;
    std::fs::write(&fixture.path, &corrupt)?;

    assert!(
        fixture
            .store
            .ingest("retry-source.pcap", Cursor::new(&fixture.bytes))
            .is_err()
    );

    assert_eq!(std::fs::read(&fixture.path)?, corrupt);
    assert_eq!(fixture.store.inventory()?.sources, 0);
    Ok(())
}

#[cfg(unix)]
#[test]
fn retry_symlink_without_touching_target() -> Result<(), Box<dyn Error>> {
    let mut fixture = orphaned_source()?;
    let protected = fixture.temporary.path().join("protected-evidence.bin");
    std::fs::write(&protected, b"protected evidence")?;
    std::fs::remove_file(&fixture.path)?;
    std::os::unix::fs::symlink(&protected, &fixture.path)?;

    assert!(
        fixture
            .store
            .ingest("retry-source.pcap", Cursor::new(&fixture.bytes))
            .is_err()
    );

    assert!(
        std::fs::symlink_metadata(&fixture.path)?
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read(&protected)?, b"protected evidence");
    assert_eq!(fixture.store.inventory()?.sources, 0);
    Ok(())
}

fn orphaned_source() -> Result<OrphanedSource, Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let bytes = support::capture(&[frames::tcp(false, 1, 0x18, b"payload")?])?;
    let path = temporary
        .path()
        .join("sources")
        .join(format!("{}.pcap", sha256(&bytes)));
    let result = store.ingest_with_source_sync("sync-failure.pcap", Cursor::new(&bytes), |_| {
        Err(io::Error::other("controlled directory sync failure").into())
    });

    let error = result
        .err()
        .ok_or("expected controlled directory sync failure")?;
    assert!(
        error
            .to_string()
            .contains("controlled directory sync failure")
    );
    assert_eq!(store.inventory()?.sources, 0);
    assert_eq!(std::fs::read(&path)?, bytes);
    {
        let verifier = Store::open(temporary.path(), Options::default())?;
        assert_eq!(verifier.inventory()?.sources, 0);
        verifier.verify_sources()?;
    }
    Ok(OrphanedSource {
        temporary,
        store,
        bytes,
        path,
    })
}

#[test]
fn deep_verification_packet_index_mismatch() -> Result<(), Box<dyn Error>> {
    for statement in [
        "UPDATE packets SET offset=offset+1 WHERE number=1",
        "UPDATE packets SET length=length-1 WHERE number=1",
        "UPDATE packets SET original_length=original_length+1 WHERE number=1",
        "UPDATE packets SET ticks=X'0000000000000001' WHERE number=1",
        "UPDATE packets SET framing_offset=framing_offset+1 WHERE number=1",
        "UPDATE packets SET format=format+1 WHERE number=1",
        "UPDATE packets SET sha256=zeroblob(32) WHERE number=1",
        "UPDATE packets SET flow=NULL WHERE number=1",
        "UPDATE packets SET payload_length=payload_length+1 WHERE number=1",
        "UPDATE packets SET direction=1-direction WHERE number=1",
    ] {
        assert_packet_update_is_rejected(statement)?;
    }
    assert_context_update_is_rejected()?;
    assert_cross_flow_reference_is_rejected()?;
    Ok(())
}

fn assert_packet_update_is_rejected(statement: &str) -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let bytes = support::capture(&[
        frames::tcp(false, 1, 0x18, b"payload")?,
        frames::tcp_ports(false, (41_000, 8_000), 1, 0x18, b"other")?,
    ])?;
    store.ingest("packet-metadata.pcap", Cursor::new(bytes))?;
    let connection = Connection::open(temporary.path().join("index.sqlite"))?;
    assert_eq!(connection.execute(statement, [])?, 1);
    assert!(store.verify_sources().is_err(), "accepted: {statement}");
    Ok(())
}

fn assert_context_update_is_rejected() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let bytes = support::capture(&[frames::tcp(false, 1, 0x18, b"payload")?])?;
    store.ingest("context-metadata.pcap", Cursor::new(bytes))?;
    let connection = Connection::open(temporary.path().join("index.sqlite"))?;
    let (context_id, text): (i64, String) =
        connection.query_row("SELECT id,value FROM contexts LIMIT 1", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
    let mut context: serde_json::Value = serde_json::from_str(&text)?;
    *context
        .get_mut("direction")
        .ok_or("indexed context lacks direction")? = serde_json::Value::from(2);
    connection.execute(
        "UPDATE contexts SET value=?1 WHERE id=?2",
        params![context.to_string(), context_id],
    )?;
    assert!(store.verify_sources().is_err());
    Ok(())
}

fn assert_cross_flow_reference_is_rejected() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let bytes = support::capture(&[
        frames::tcp(false, 1, 0x18, b"payload")?,
        frames::tcp_ports(false, (41_000, 8_000), 1, 0x18, b"other")?,
    ])?;
    store.ingest("flow-metadata.pcap", Cursor::new(bytes))?;
    let connection = Connection::open(temporary.path().join("index.sqlite"))?;
    connection.execute(
        "UPDATE packets SET flow=(SELECT MAX(id) FROM flows) WHERE number=1",
        [],
    )?;
    assert!(store.verify_sources().is_err());
    Ok(())
}

#[test]
fn deep_verification_packet_indexes_rehashed() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let frame = frames::tcp(false, 1, 0x18, b"payload")?;
    let mut bytes = support::capture(std::slice::from_ref(&frame))?;
    let source_hash = sha256(&bytes);
    store.ingest("source-hash.pcap", Cursor::new(bytes.as_slice()))?;
    let mut capture_reader = l2_pcap::CaptureSource::new(Cursor::new(bytes.as_slice()))?;
    let indexed_frame = capture_reader
        .next_packet()?
        .ok_or("capture frame missing")?;
    let data_offset = match indexed_frame
        .metadata()
        .locator()
        .ok_or("capture locator missing")?
    {
        l2_capture::CaptureLocator::ClassicPcap { data_offset, .. }
        | l2_capture::CaptureLocator::PcapNg { data_offset, .. } => data_offset,
    };
    let data_start = usize::try_from(data_offset)?;
    let data_end = data_start
        .checked_add(frame.bytes().len())
        .ok_or("capture range overflow")?;
    let capture_frame = bytes
        .get_mut(data_start..data_end)
        .ok_or("capture frame range missing")?;
    let mut changed_frame = capture_frame.to_vec();
    let final_byte = changed_frame
        .len()
        .checked_sub(1)
        .ok_or("capture frame is empty")?;
    *changed_frame
        .get_mut(final_byte)
        .ok_or("capture frame byte missing")? ^= 1;
    capture_frame.copy_from_slice(&changed_frame);
    let digest: [u8; 32] = Sha256::digest(&changed_frame).into();
    let retained_path = temporary
        .path()
        .join("sources")
        .join(format!("{source_hash}.pcap"));
    std::fs::write(retained_path, &bytes)?;
    let connection = Connection::open(temporary.path().join("index.sqlite"))?;
    assert_eq!(
        connection.execute(
            "UPDATE packets SET sha256=?1 WHERE number=1",
            [digest.as_slice()],
        )?,
        1
    );
    assert_eq!(
        connection.execute(
            "UPDATE shared_facts SET fact_key=?1 WHERE kind='packet_bytes' AND packet=1",
            [digest.as_slice()],
        )?,
        1
    );

    assert!(store.verify_sources().is_err());
    Ok(())
}
