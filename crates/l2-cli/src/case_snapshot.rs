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
    io::{self, BufWriter, Write},
};

pub const GRAPH_FILE: &str = "case.graph.gz";
pub const BLOB_PACK_FILE: &str = "case.blobs";
pub const STORAGE_FORMAT: u32 = 1;

// Reserve a bounded scratch allowance before either stream is opened
// The reader separately charges its own buffers; library allocations are not measured
const CODEC_SCRATCH_BYTES: u64 = 2 * 1024 * 1024;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub fn read(
    entry: &CacheEntry,
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
    // Keep the checked descriptors for the whole read so path replacement cannot redirect it
    let graph = input::regular_no_follow(&entry.directory().join(GRAPH_FILE))?;
    let blobs = input::regular_no_follow(&entry.directory().join(BLOB_PACK_FILE))?;
    if graph.metadata()?.len() != usage.graph_bytes
        || blobs.metadata()?.len() != usage.blob_pack_bytes
    {
        return Err(invalid(
            "cached Case snapshot file lengths do not match its metadata",
        ));
    }
    let (case, actual) = if let Some(budget) = budget {
        Case::from_snapshot_with_memory(graph, blobs, limits, budget)?
    } else {
        Case::from_snapshot(graph, blobs, limits)?
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
    let _scratch = budget
        .map(|budget| budget.try_reserve(MemoryClass::Cache, CODEC_SCRATCH_BYTES))
        .transpose()?;
    let mut graph = BufWriter::new(create_file(lease, GRAPH_FILE)?);
    let mut blobs = BufWriter::new(create_file(lease, BLOB_PACK_FILE)?);
    let usage = case.write_snapshot(&mut graph, &mut blobs, limits)?;
    sync_file(graph)?;
    sync_file(blobs)?;
    Ok(usage)
}

fn create_file(lease: &Lease, name: &str) -> Result<File> {
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(lease.directory().join(name))?)
}

fn sync_file(mut writer: BufWriter<File>) -> Result<()> {
    writer.flush()?;
    writer
        .into_inner()
        .map_err(io::IntoInnerError::into_error)?
        .sync_all()?;
    Ok(())
}

fn invalid(message: &'static str) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidData, message).into()
}
