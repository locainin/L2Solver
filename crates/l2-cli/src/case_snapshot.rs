//! Shared descriptor-based storage for exact cached Case snapshots

use crate::input;
use l2_workbench::{
    evidence::{Case, CaseSnapshotLimits, CaseSnapshotUsage},
    job::{
        MemoryBudget, MemoryClass,
        cache::{CacheEntry, Lease},
    },
};
use std::{
    error::Error,
    fs::{File, OpenOptions},
    io::{self, BufWriter, Read, Seek, SeekFrom, Write},
};

pub const GRAPH_FILE: &str = "case.graph.gz";
pub const BLOB_PACK_FILE: &str = "case.blobs";
pub const STORAGE_FORMAT: u32 = 1;

// Reserve a bounded scratch allowance before either stream is opened
// The reader separately charges its own buffers; library allocations are not measured
const CODEC_SCRATCH_BYTES: u64 = 2 * 1024 * 1024;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// A checked file whose size can be read from the same open descriptor
pub trait SnapshotFile: Read + Seek {
    fn snapshot_len(&self) -> io::Result<u64>;
}

impl SnapshotFile for File {
    fn snapshot_len(&self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }
}

impl SnapshotFile for input::InputFile {
    fn snapshot_len(&self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }
}

pub fn read(
    entry: &CacheEntry,
    usage: CaseSnapshotUsage,
    limits: CaseSnapshotLimits,
    budget: Option<&MemoryBudget>,
) -> Result<Case> {
    // Open each descriptor once so a later path replacement cannot redirect the read
    let mut graph = input::regular_no_follow(&entry.directory().join(GRAPH_FILE))?;
    let mut blobs = input::regular_no_follow(&entry.directory().join(BLOB_PACK_FILE))?;
    read_files(&mut graph, &mut blobs, usage, limits, budget)
}

/// Validate and restore a snapshot from already-open seekable file descriptors
pub fn read_files<G: SnapshotFile, B: SnapshotFile>(
    graph: &mut G,
    blobs: &mut B,
    usage: CaseSnapshotUsage,
    limits: CaseSnapshotLimits,
    budget: Option<&MemoryBudget>,
) -> Result<Case> {
    let decoded = usage
        .graph_decoded_bytes
        .checked_add(usage.blob_pack_bytes)
        .ok_or("snapshot decoded size overflow")?;
    let stored = usage
        .graph_bytes
        .checked_add(usage.blob_pack_bytes)
        .ok_or("snapshot storage size overflow")?;
    if decoded > limits.maximum_decoded_bytes() || stored > limits.maximum_storage_bytes() {
        return Err(invalid("cached Case snapshot exceeds its size limit"));
    }

    let _scratch = budget
        .map(|budget| budget.try_reserve(MemoryClass::Cache, CODEC_SCRATCH_BYTES))
        .transpose()?;
    if graph.snapshot_len()? != usage.graph_bytes || blobs.snapshot_len()? != usage.blob_pack_bytes
    {
        return Err(invalid(
            "cached Case snapshot file lengths do not match its metadata",
        ));
    }
    // A previous restore can leave both descriptors at end of file
    graph.seek(SeekFrom::Start(0))?;
    blobs.seek(SeekFrom::Start(0))?;
    let (case, actual) = if let Some(budget) = budget {
        Case::from_snapshot_with_memory(&mut *graph, &mut *blobs, limits, budget)?
    } else {
        Case::from_snapshot(&mut *graph, &mut *blobs, limits)?
    };
    if actual != usage {
        return Err(invalid(
            "cached Case snapshot usage does not match its metadata",
        ));
    }
    Ok(case)
}

pub fn write(
    lease: &Lease,
    case: &Case,
    limits: CaseSnapshotLimits,
    budget: Option<&MemoryBudget>,
) -> Result<CaseSnapshotUsage> {
    let mut graph = create_file(lease, GRAPH_FILE)?;
    let mut blobs = create_file(lease, BLOB_PACK_FILE)?;
    write_files(&mut graph, &mut blobs, case, limits, budget)
}

/// Write an exact snapshot to fresh owned file descriptors
pub fn write_files(
    graph: &mut File,
    blobs: &mut File,
    case: &Case,
    limits: CaseSnapshotLimits,
    budget: Option<&MemoryBudget>,
) -> Result<CaseSnapshotUsage> {
    if graph.metadata()?.len() != 0 || blobs.metadata()?.len() != 0 {
        return Err(invalid("Case snapshot destination is not empty"));
    }
    let _scratch = budget
        .map(|budget| budget.try_reserve(MemoryClass::Cache, CODEC_SCRATCH_BYTES))
        .transpose()?;
    // Empty files can still have a nonzero seek position
    graph.seek(SeekFrom::Start(0))?;
    blobs.seek(SeekFrom::Start(0))?;
    let usage = {
        let mut graph_writer = BufWriter::new(&mut *graph);
        let mut blob_writer = BufWriter::new(&mut *blobs);
        let usage = case.write_snapshot(&mut graph_writer, &mut blob_writer, limits)?;
        graph_writer.flush()?;
        blob_writer.flush()?;
        usage
    };
    graph.sync_all()?;
    blobs.sync_all()?;
    Ok(usage)
}

fn create_file(lease: &Lease, name: &str) -> Result<File> {
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(lease.directory().join(name))?)
}

fn invalid(message: &'static str) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidData, message).into()
}
