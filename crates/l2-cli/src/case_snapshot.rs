//! Shared descriptor-based storage for exact cached Case snapshots

use crate::input;
#[cfg(target_os = "linux")]
use l2_workbench::job::MemorySnapshot;
use l2_workbench::{
    evidence::{Case, CaseSnapshotLimits, CaseSnapshotUsage},
    job::{
        Job, JobError, MemoryBudget, MemoryClass, MemoryLease,
        cache::{CacheEntry, Lease},
    },
};
use std::{
    cell::Cell,
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
const FILE_BUFFER_CAPACITY: usize = 16 * 1024;
const FILE_BUFFER_BYTES: u64 = 2 * FILE_BUFFER_CAPACITY as u64;
// Bound each transfer while a job can request cancellation
const CANCELLABLE_IO_CHUNK_BYTES: usize = 64 * 1024;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub struct Cancellation<'a> {
    job: Option<&'a Job>,
    observed: Cell<bool>,
    io_failed: Cell<bool>,
}

impl Cancellation<'_> {
    fn check(&self) -> io::Result<()> {
        if let Some(job) = self.job {
            job.check_cancelled().map_err(|error| {
                if !self.io_failed.get() {
                    self.observed.set(true);
                }
                io::Error::other(error)
            })?;
        }
        Ok(())
    }

    fn record_io<T>(&self, result: io::Result<T>) -> io::Result<T> {
        if let Err(error) = &result
            && error.kind() != io::ErrorKind::Interrupted
        {
            self.io_failed.set(true);
        }
        result
    }

    pub const fn wrap<T>(&self, inner: T) -> CancellableIo<'_, T> {
        CancellableIo {
            inner,
            cancellation: self,
        }
    }
}

pub struct CancellableIo<'a, T> {
    inner: T,
    cancellation: &'a Cancellation<'a>,
}

impl<T> CancellableIo<'_, T> {
    fn length(&self, available: usize) -> usize {
        if self.cancellation.job.is_some() {
            available.min(CANCELLABLE_IO_CHUNK_BYTES)
        } else {
            available
        }
    }
}

impl<T: Read> Read for CancellableIo<'_, T> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.cancellation.check()?;
        let length = self.length(bytes.len());
        let (chunk, _) = bytes.split_at_mut(length);
        self.cancellation.record_io(self.inner.read(chunk))
    }
}

impl<T: Write> Write for CancellableIo<'_, T> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.cancellation.check()?;
        let (chunk, _) = bytes.split_at(self.length(bytes.len()));
        self.cancellation.record_io(self.inner.write(chunk))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.cancellation.check()?;
        self.cancellation.record_io(self.inner.flush())
    }
}

pub fn with_cancellation<T>(
    job: Option<&Job>,
    operation: impl FnOnce(&Cancellation<'_>) -> Result<T>,
) -> Result<T> {
    let cancellation = Cancellation {
        job,
        observed: Cell::new(false),
        io_failed: Cell::new(false),
    };
    let result = (|| {
        cancellation.check()?;
        let value = operation(&cancellation)?;
        cancellation.check()?;
        Ok(value)
    })();
    // The codec maps stream failures to its own error types
    if cancellation.observed.get() {
        Err(JobError::Cancelled.into())
    } else {
        result
    }
}

/// A checked file whose size can be read from the same open descriptor
pub trait SnapshotFile: Read + Seek {
    fn snapshot_len(&self) -> io::Result<u64>;

    /// Best-effort advice when snapshot I/O has finished
    #[cfg(target_os = "linux")]
    fn advise_consumed(&mut self) {}
}

impl SnapshotFile for File {
    fn snapshot_len(&self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }

    #[cfg(target_os = "linux")]
    fn advise_consumed(&mut self) {
        advise_file(self);
    }
}

impl SnapshotFile for input::InputFile {
    fn snapshot_len(&self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }

    #[cfg(target_os = "linux")]
    fn advise_consumed(&mut self) {
        advise_file(self);
    }
}

#[cfg(target_os = "linux")]
fn advise_file(file: &impl std::os::fd::AsFd) {
    // The kernel may retain pages; admission still checks measured cgroup usage
    let _ = rustix::fs::fadvise(file, 0, None, rustix::fs::Advice::DontNeed);
}

#[cfg(target_os = "linux")]
fn constrained_cgroup(budget: Option<&MemoryBudget>) -> bool {
    budget
        .and_then(|budget| budget.snapshot().ok())
        .is_some_and(|snapshot| should_advise_snapshot_pages(&snapshot))
}

#[cfg(target_os = "linux")]
/// Return whether a fresh cgroup sample leaves little headroom for new work
pub fn should_advise_snapshot_pages(snapshot: &MemorySnapshot) -> bool {
    if snapshot.system_sample_age_ms.is_none_or(|age| {
        std::time::Duration::from_millis(age) > crate::recovery_job::MAX_MEMORY_SAMPLE_AGE
    }) {
        return false;
    }
    let Some(cgroup) = snapshot.system.and_then(|system| system.cgroup) else {
        return false;
    };
    [
        (cgroup.effective_max_bytes, cgroup.max_headroom_bytes),
        (cgroup.effective_high_bytes, cgroup.high_headroom_bytes),
    ]
    .into_iter()
    .any(|(limit, headroom)| {
        let (Some(limit), Some(headroom)) = (limit, headroom) else {
            return false;
        };
        // Leave twice the admission safety margin plus active workers' future growth
        let threshold = (snapshot.limit_bytes.min(limit)
            / crate::recovery_job::MEMORY_SAFETY_MARGIN_DIVISOR)
            .saturating_mul(2)
            .saturating_add(snapshot.working_sets.reserved_bytes);
        headroom <= threshold
    })
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
    read_files_cancellable(graph, blobs, usage, limits, budget, None)
}

/// Validate and restore open descriptors while checking a running job
pub fn read_files_cancellable<G: SnapshotFile, B: SnapshotFile>(
    graph: &mut G,
    blobs: &mut B,
    usage: CaseSnapshotUsage,
    limits: CaseSnapshotLimits,
    budget: Option<&MemoryBudget>,
    job: Option<&Job>,
) -> Result<Case> {
    with_cancellation(job, |cancellation| {
        if graph.snapshot_len()? != usage.graph_bytes
            || blobs.snapshot_len()? != usage.blob_pack_bytes
        {
            return Err(invalid(
                "cached Case snapshot file lengths do not match its metadata",
            ));
        }
        // A previous restore can leave both descriptors at end of file
        graph.seek(SeekFrom::Start(0))?;
        blobs.seek(SeekFrom::Start(0))?;
        let result = {
            let mut graph_reader = cancellation.wrap(&mut *graph);
            let mut blob_reader = cancellation.wrap(&mut *blobs);
            read_streams(&mut graph_reader, &mut blob_reader, usage, limits, budget)
        };
        #[cfg(target_os = "linux")]
        if constrained_cgroup(budget) {
            // Only advise the exact descriptors used by this operation
            graph.advise_consumed();
            blobs.advise_consumed();
        }
        result
    })
}

/// Restore an already-verified snapshot stream and check its measured usage
pub fn read_streams(
    graph: &mut dyn Read,
    blobs: &mut dyn Read,
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
    // Reject an understated receipt before decoding beyond its declared allocation bound
    let receipt_limits = CaseSnapshotLimits::new(stored, decoded);

    let _scratch = budget
        .map(|budget| budget.try_reserve(MemoryClass::Cache, CODEC_SCRATCH_BYTES))
        .transpose()?;
    let (case, actual) = if let Some(budget) = budget {
        Case::from_snapshot_with_memory(graph, blobs, receipt_limits, budget)?
    } else {
        Case::from_snapshot(graph, blobs, receipt_limits)?
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
    write_files_cancellable(graph, blobs, case, limits, budget, None)
}

/// Write fresh descriptors while checking a running job
pub fn write_files_cancellable(
    graph: &mut File,
    blobs: &mut File,
    case: &Case,
    limits: CaseSnapshotLimits,
    budget: Option<&MemoryBudget>,
    job: Option<&Job>,
) -> Result<CaseSnapshotUsage> {
    with_cancellation(job, |cancellation| {
        let mut buffers = prepare_snapshot_files(graph, blobs, budget)?;
        let usage = write_buffered_snapshot(
            graph,
            blobs,
            case,
            limits,
            budget,
            &mut buffers,
            cancellation,
        )?;
        sync_snapshot_files(graph, blobs, budget, cancellation)?;
        Ok(usage)
    })
}

fn prepare_snapshot_files(
    graph: &mut File,
    blobs: &mut File,
    budget: Option<&MemoryBudget>,
) -> Result<Option<MemoryLease>> {
    if graph.metadata()?.len() != 0 || blobs.metadata()?.len() != 0 {
        return Err(invalid("Case snapshot destination is not empty"));
    }
    let buffers = budget
        .map(|budget| budget.try_reserve(MemoryClass::Cache, FILE_BUFFER_BYTES))
        .transpose()?;
    // Empty files can still have a nonzero seek position
    graph.seek(SeekFrom::Start(0))?;
    blobs.seek(SeekFrom::Start(0))?;
    Ok(buffers)
}

fn write_buffered_snapshot(
    graph: &mut File,
    blobs: &mut File,
    case: &Case,
    limits: CaseSnapshotLimits,
    budget: Option<&MemoryBudget>,
    buffers: &mut Option<MemoryLease>,
    cancellation: &Cancellation<'_>,
) -> Result<CaseSnapshotUsage> {
    let mut graph_writer = BufWriter::with_capacity(FILE_BUFFER_CAPACITY, cancellation.wrap(graph));
    let mut blob_writer = BufWriter::with_capacity(FILE_BUFFER_CAPACITY, cancellation.wrap(blobs));
    let result = write_snapshot_buffers(
        &mut graph_writer,
        &mut blob_writer,
        case,
        limits,
        budget,
        buffers,
    );
    if result.is_err() {
        // Do not retry buffered writes during cleanup after a failed snapshot
        let _ = graph_writer.into_parts();
        let _ = blob_writer.into_parts();
    }
    result
}

fn write_snapshot_buffers(
    graph: &mut BufWriter<impl Write>,
    blobs: &mut BufWriter<impl Write>,
    case: &Case,
    limits: CaseSnapshotLimits,
    budget: Option<&MemoryBudget>,
    buffers: &mut Option<MemoryLease>,
) -> Result<CaseSnapshotUsage> {
    if let Some(buffers) = buffers {
        let actual = graph
            .capacity()
            .checked_add(blobs.capacity())
            .ok_or("snapshot writer buffer size overflow")?;
        buffers.try_resize(u64::try_from(actual)?)?;
    }
    let usage = write_streams(graph, blobs, case, limits, budget)?;
    graph.flush()?;
    blobs.flush()?;
    Ok(usage)
}

fn sync_snapshot_files(
    graph: &mut File,
    blobs: &mut File,
    budget: Option<&MemoryBudget>,
    cancellation: &Cancellation<'_>,
) -> Result<()> {
    cancellation.check()?;
    graph.sync_all()?;
    cancellation.check()?;
    blobs.sync_all()?;
    #[cfg(not(target_os = "linux"))]
    let _ = budget;
    #[cfg(target_os = "linux")]
    if constrained_cgroup(budget) {
        // Clean pages can be reclaimed without risking unsynced snapshot contents
        graph.advise_consumed();
        blobs.advise_consumed();
    }
    Ok(())
}

/// Write an exact snapshot to caller-owned bounded streams
pub fn write_streams(
    mut graph: &mut dyn Write,
    mut blobs: &mut dyn Write,
    case: &Case,
    limits: CaseSnapshotLimits,
    budget: Option<&MemoryBudget>,
) -> Result<CaseSnapshotUsage> {
    let _scratch = budget
        .map(|budget| budget.try_reserve(MemoryClass::Cache, CODEC_SCRATCH_BYTES))
        .transpose()?;
    Ok(case.write_snapshot(&mut graph, &mut blobs, limits)?)
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
