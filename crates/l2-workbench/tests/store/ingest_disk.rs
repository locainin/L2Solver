use super::Store;
use crate::store::Options;
use std::{
    cell::Cell,
    error::Error,
    fs,
    io::{self, Cursor, Read},
    path::{Path, PathBuf},
    rc::Rc,
};

const WORKSPACE_LIMIT: u64 = 4 * 1024 * 1024;

#[test]
fn index_growth_rollback() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let first = capture(1);
    let original = store.ingest("original.pcap", Cursor::new(&first))?;
    let bytes = capture(40_000);
    let peak = Rc::new(Cell::new(0));
    let read = Rc::new(Cell::new(0));
    let reader = ObservedReader::new(temporary.path(), &bytes, &peak, &read);
    let result = ingest_budget(
        &mut store,
        reader,
        u64::try_from(bytes.len())?,
        WORKSPACE_LIMIT,
    );
    let error = result
        .err()
        .ok_or("an index larger than the workspace budget succeeded")?;
    assert!(
        error.to_string().contains("full"),
        "unexpected error: {error}"
    );
    assert!(read.get() > 4096, "the test did not reach index growth");
    assert!(
        peak.get() <= WORKSPACE_LIMIT,
        "observed {} bytes",
        peak.get()
    );
    assert_eq!(store.inventory()?.sources, 1);
    assert_eq!(store.inventory()?.packets, 1);
    assert_eq!(fs::read_dir(temporary.path().join("sources"))?.count(), 1);
    assert_eq!(store.frame(&original.source_id, 1)?.bytes().len(), 14);
    store.verify_sources()?;
    assert!(!temporary.path().join("index.sqlite-journal").exists());

    let short = capture(2);
    let receipt = ingest_budget(
        &mut store,
        Cursor::new(&short),
        u64::try_from(short.len())?,
        WORKSPACE_LIMIT,
    )?;
    assert_eq!(receipt.packets, 2);
    assert_eq!(store.inventory()?.sources, 2);
    store.verify_sources()?;
    Ok(())
}

#[test]
fn source_growth_rollback() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let bytes = wide_capture();
    let peak = Rc::new(Cell::new(0));
    let read = Rc::new(Cell::new(0));
    let reader = ObservedReader::new(temporary.path(), &bytes, &peak, &read);
    let error = ingest_budget(
        &mut store,
        reader,
        u64::try_from(bytes.len())?,
        WORKSPACE_LIMIT,
    )
    .err()
    .ok_or("an oversized source succeeded")?;
    assert!(
        error.to_string().contains("workspace"),
        "unexpected error: {error}"
    );
    assert!(read.get() > 4096, "the test did not reach source growth");
    assert!(
        peak.get() <= WORKSPACE_LIMIT,
        "observed {} bytes",
        peak.get()
    );
    assert_eq!(store.inventory()?.sources, 0);
    assert_eq!(fs::read_dir(temporary.path().join("sources"))?.count(), 0);
    assert!(!temporary.path().join("index.sqlite-journal").exists());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn existing_index_headroom() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    store.ingest("original.pcap", Cursor::new(capture(3_000)))?;
    let short = capture(1);
    let receipt = ingest_budget(
        &mut store,
        Cursor::new(&short),
        u64::try_from(short.len())?,
        WORKSPACE_LIMIT,
    )?;
    assert_eq!(receipt.packets, 1);
    assert_eq!(store.inventory()?.sources, 2);
    store.verify_sources()?;
    Ok(())
}

#[test]
fn orphan_source_headroom() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let orphan = temporary.path().join("sources").join("orphan.pcap");
    fs::write(&orphan, vec![0x5a; 4_100_000])?;
    let short = capture(1);
    let error = ingest_budget(
        &mut store,
        Cursor::new(&short),
        u64::try_from(short.len())?,
        WORKSPACE_LIMIT,
    )
    .err()
    .ok_or("an existing source exceeded the workspace budget")?;
    assert!(
        error.to_string().contains("workspace"),
        "unexpected error: {error}"
    );
    assert_eq!(fs::metadata(orphan)?.len(), 4_100_000);
    assert_eq!(store.inventory()?.sources, 0);
    Ok(())
}

#[test]
fn rejects_wal_ingest() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let mode: String =
        store
            .connection
            .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
    assert_eq!(mode, "wal");
    let error = store
        .ingest("wal.pcap", Cursor::new(capture(1)))
        .err()
        .ok_or("WAL ingest succeeded")?;
    assert!(
        error.to_string().contains("journal"),
        "unexpected error: {error}"
    );
    assert_eq!(store.inventory()?.sources, 0);
    assert_eq!(fs::read_dir(temporary.path().join("sources"))?.count(), 0);
    Ok(())
}

fn ingest_budget(
    store: &mut Store,
    reader: impl Read,
    source_limit: u64,
    workspace_limit: u64,
) -> crate::store::Result<crate::store::IngestReceipt> {
    store.ingest_with_workspace_limit(
        "budget.pcap",
        reader,
        source_limit,
        super::super::Directory::sync,
        Some(workspace_limit),
    )
}

struct ObservedReader<'a> {
    bytes: Cursor<&'a [u8]>,
    directory: PathBuf,
    peak: Rc<Cell<u64>>,
    read: Rc<Cell<u64>>,
}

impl<'a> ObservedReader<'a> {
    fn new(directory: &Path, bytes: &'a [u8], peak: &Rc<Cell<u64>>, read: &Rc<Cell<u64>>) -> Self {
        Self {
            bytes: Cursor::new(bytes),
            directory: directory.to_path_buf(),
            peak: Rc::clone(peak),
            read: Rc::clone(read),
        }
    }
}

impl Read for ObservedReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut total = 0_u64;
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_file() {
                total += entry.metadata()?.len();
            } else if kind.is_dir() {
                for child in fs::read_dir(entry.path())? {
                    total += child?.metadata()?.len();
                }
            }
        }
        // Named file samples are a lower bound on the live workspace
        self.peak.set(self.peak.get().max(total));
        let length = buffer.len().min(4096);
        let amount = self.bytes.read(buffer.split_at_mut(length).0)?;
        self.read
            .set(self.read.get() + u64::try_from(amount).map_err(io::Error::other)?);
        Ok(amount)
    }
}

fn wide_capture() -> Vec<u8> {
    let mut bytes = capture(0);
    let payload = vec![0xff; 65_535];
    for number in 0_u32..64 {
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&number.to_le_bytes());
        bytes.extend_from_slice(&65_535_u32.to_le_bytes());
        bytes.extend_from_slice(&65_535_u32.to_le_bytes());
        bytes.extend_from_slice(&payload);
    }
    bytes
}

fn capture(count: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xa1b2_c3d4_u32.to_le_bytes());
    bytes.extend_from_slice(&[2, 0, 4, 0]);
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(&65_535_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    for number in 0..count {
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&number.to_le_bytes());
        bytes.extend_from_slice(&14_u32.to_le_bytes());
        bytes.extend_from_slice(&14_u32.to_le_bytes());
        bytes.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0xff, 0xff]);
    }
    bytes
}
