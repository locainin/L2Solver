#[path = "../reconstruction/ipv4.rs"]
mod ipv4;

#[path = "../store/support.rs"]
mod captures;
#[path = "../reconstruction/tcp.rs"]
mod frames;
use l2_workbench::{
    evidence::Case,
    journal::{Journal, JournalOptions},
    store::{Options, Store},
};
use std::{error::Error, io::Cursor};

#[test]
fn overlapping_case_not_opaque_frames() -> Result<(), Box<dyn Error>> {
    let frames = [
        frames::tcp(false, 100, 2, b"")?,
        frames::tcp(false, 101, 0x18, b"sample")?,
    ];
    let bytes = captures::capture(&frames)?;
    let index_dir = tempfile::tempdir()?;
    let mut index = Store::create(index_dir.path(), Options::default())?;
    index.ingest("ethernet.pcap", Cursor::new(&bytes))?;
    let case = index.investigate_flow(1)?.case;
    let journal_dir = tempfile::tempdir()?;
    let mut journal = Journal::create(journal_dir.path(), &case, JournalOptions::default())?;
    journal.import_base_events()?;
    let mut packets = Vec::new();
    journal.visit_events(0, None, |event| {
        if event.kind == "packet_tcp" {
            packets.push(event);
        }
        Ok(())
    })?;
    assert_eq!(packets.len(), 2);
    let first_packet = packets.first().ok_or("missing first packet event")?;
    assert_eq!(
        first_packet
            .fields
            .get("source_mac")
            .and_then(serde_json::Value::as_str),
        Some("02:00:00:00:00:01")
    );
    assert_eq!(
        first_packet
            .fields
            .get("destination_mac")
            .and_then(serde_json::Value::as_str),
        Some("02:00:00:00:00:02")
    );
    assert_eq!(
        first_packet.fields.get("arp_source_ip"),
        Some(&serde_json::Value::Null)
    );
    assert_eq!(
        first_packet.fields.get("arp_destination_ip"),
        Some(&serde_json::Value::Null)
    );
    assert_eq!(journal.import_index_events(&index)?, 0);
    let mut opaque = captures::capture(frames.get(..1).ok_or("missing frame")?)?;
    opaque
        .get_mut(20..24)
        .ok_or("missing link type")?
        .copy_from_slice(&12_u32.to_le_bytes());
    index.ingest("opaque.pcap", Cursor::new(opaque))?;
    assert_eq!(journal.import_index_events(&index)?, 1);
    journal.verify()?;
    Ok(())
}

#[test]
fn failed_event_import_rolls_back() -> Result<(), Box<dyn Error>> {
    let frames = [
        frames::tcp(false, 100, 2, b"")?,
        frames::tcp(false, 101, 0x18, b"sample")?,
    ];
    let bytes = captures::capture(&frames)?;
    let index_dir = tempfile::tempdir()?;
    let mut index = Store::create(index_dir.path(), Options::default())?;
    index.ingest("capture.pcap", Cursor::new(bytes))?;
    let journal_dir = tempfile::tempdir()?;
    let mut journal = Journal::create(
        journal_dir.path(),
        &Case::new(),
        JournalOptions {
            cache_mib: 1,
            max_entry_bytes: 32,
            ..JournalOptions::default()
        },
    )?;
    assert!(journal.import_index_events(&index).is_err());
    let connection = rusqlite::Connection::open(journal_dir.path().join("journal.sqlite"))?;
    let events: u64 = connection.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;
    assert_eq!(events, 0);
    Ok(())
}
