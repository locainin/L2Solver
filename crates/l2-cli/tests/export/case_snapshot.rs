#[cfg(target_os = "linux")]
use crate::case_snapshot::SnapshotFile;
use crate::case_snapshot::{read_files, read_streams, write_files, write_streams};
#[cfg(target_os = "linux")]
use l2_workbench::job::{CgroupMemoryEvents, CgroupMemorySnapshot, SystemMemorySnapshot};
use l2_workbench::{
    evidence::{Case, CaseSnapshotLimits},
    job::{MemoryBudget, MemoryClass},
};
use serde_json::json;
use std::{
    error::Error,
    io::{Read, Seek, SeekFrom, Write},
};
#[cfg(target_os = "linux")]
use std::{fs::File, io};

type TestResult = Result<(), Box<dyn Error>>;

fn source_case() -> Result<Case, Box<dyn Error>> {
    let bytes = b"synthetic retained source";
    let mut case = Case::new();
    let blob = case.add_blob(bytes)?;
    let digest = blob.strip_prefix("sha256:").ok_or("missing blob digest")?;
    case.add_source(
        "source",
        "capture",
        u64::try_from(bytes.len())?,
        digest,
        Some(&blob),
    )?;
    case.add_node("opaque", Some(&blob), Vec::new(), json!({"value": 7}))?;
    Ok(case)
}

#[cfg(target_os = "linux")]
struct ObservedFile {
    file: File,
    release_calls: usize,
}

#[cfg(target_os = "linux")]
impl Read for ObservedFile {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.file.read(bytes)
    }
}

#[cfg(target_os = "linux")]
impl Seek for ObservedFile {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}

#[cfg(target_os = "linux")]
impl SnapshotFile for ObservedFile {
    fn snapshot_len(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    fn advise_consumed(&mut self) {
        self.release_calls += 1;
    }
}

#[cfg(target_os = "linux")]
fn constrained_budget(
    maximum: Option<u64>,
    high: Option<u64>,
) -> Result<MemoryBudget, Box<dyn Error>> {
    let budget = MemoryBudget::new(16 * 1024 * 1024);
    budget.observe_system_memory(Some(SystemMemorySnapshot {
        process_rss_bytes: 0,
        process_peak_rss_bytes: 0,
        cgroup: Some(CgroupMemorySnapshot {
            current_bytes: 0,
            peak_bytes: None,
            anonymous_bytes: None,
            file_bytes: None,
            kernel_bytes: None,
            shared_bytes: None,
            dirty_file_bytes: None,
            writeback_file_bytes: None,
            inactive_file_bytes: None,
            effective_max_bytes: maximum,
            effective_high_bytes: high,
            max_headroom_bytes: maximum,
            high_headroom_bytes: high,
            events: CgroupMemoryEvents::default(),
        }),
    }))?;
    Ok(budget)
}

#[cfg(target_os = "linux")]
#[test]
fn constrained_snapshot_reads_advise_only_consumed_files_even_when_invalid() -> TestResult {
    let directory = tempfile::tempdir()?;
    let limits = CaseSnapshotLimits::new(16 * 1024 * 1024, 16 * 1024 * 1024);
    for (maximum, high, damaged) in [
        (Some(16 * 1024 * 1024), None, false),
        (None, Some(16 * 1024 * 1024), true),
    ] {
        let mut graph = ObservedFile {
            file: tempfile::tempfile_in(directory.path())?,
            release_calls: 0,
        };
        let mut blobs = ObservedFile {
            file: tempfile::tempfile_in(directory.path())?,
            release_calls: 0,
        };
        let expected = source_case()?;
        let usage = write_files(&mut graph.file, &mut blobs.file, &expected, limits, None)?;
        if damaged {
            graph.file.seek(SeekFrom::Start(0))?;
            graph.file.write_all(&[0])?;
        }
        let budget = constrained_budget(maximum, high)?;
        let restored = read_files(&mut graph, &mut blobs, usage, limits, Some(&budget));
        assert_eq!(restored.is_err(), damaged);
        if let Ok(restored) = restored {
            assert_eq!(restored, expected);
        }
        assert_eq!(graph.release_calls, 1, "graph pages should be advised");
        assert_eq!(blobs.release_calls, 1, "blob-pack pages should be advised");
        assert_eq!(budget.snapshot()?.used_bytes, 0);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn snapshot_reads_do_not_advise_pages_without_a_finite_observed_cgroup_limit() -> TestResult {
    let directory = tempfile::tempdir()?;
    let limits = CaseSnapshotLimits::new(16 * 1024 * 1024, 16 * 1024 * 1024);
    let mut graph = ObservedFile {
        file: tempfile::tempfile_in(directory.path())?,
        release_calls: 0,
    };
    let mut blobs = ObservedFile {
        file: tempfile::tempfile_in(directory.path())?,
        release_calls: 0,
    };
    let expected = source_case()?;
    let usage = write_files(&mut graph.file, &mut blobs.file, &expected, limits, None)?;
    for budget in [
        MemoryBudget::new(16 * 1024 * 1024),
        constrained_budget(None, None)?,
    ] {
        assert_eq!(
            read_files(&mut graph, &mut blobs, usage, limits, Some(&budget))?,
            expected
        );
    }
    assert_eq!(graph.release_calls, 0);
    assert_eq!(blobs.release_calls, 0);
    Ok(())
}

#[test]
fn open_snapshot_descriptors_restore_the_same_charged_case_more_than_once() -> TestResult {
    let directory = tempfile::tempdir()?;
    let mut graph = tempfile::tempfile_in(directory.path())?;
    let mut blobs = tempfile::tempfile_in(directory.path())?;
    let expected = source_case()?;
    let limits = CaseSnapshotLimits::new(16 * 1024 * 1024, 16 * 1024 * 1024);
    let usage = write_files(&mut graph, &mut blobs, &expected, limits, None)?;
    let budget = MemoryBudget::new(16 * 1024 * 1024);

    for _ in 0..2 {
        let restored = read_files(&mut graph, &mut blobs, usage, limits, Some(&budget))?;
        assert_eq!(restored, expected);
        assert!(budget.snapshot()?.used(MemoryClass::Case) > 0);
        assert_eq!(budget.snapshot()?.used(MemoryClass::Cache), 0);
        drop(restored);
        assert_eq!(budget.snapshot()?.used_bytes, 0);
    }
    Ok(())
}

#[test]
fn damaged_open_snapshot_is_rejected_and_releases_its_charge() -> TestResult {
    let directory = tempfile::tempdir()?;
    let mut graph = tempfile::tempfile_in(directory.path())?;
    let mut blobs = tempfile::tempfile_in(directory.path())?;
    let limits = CaseSnapshotLimits::new(16 * 1024 * 1024, 16 * 1024 * 1024);
    let usage = write_files(&mut graph, &mut blobs, &source_case()?, limits, None)?;
    graph.set_len(1)?;
    let budget = MemoryBudget::new(16 * 1024 * 1024);
    assert!(read_files(&mut graph, &mut blobs, usage, limits, Some(&budget)).is_err());
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn snapshot_writer_refuses_a_nonempty_descriptor_without_overwriting_it() -> TestResult {
    let directory = tempfile::tempdir()?;
    let mut graph = tempfile::tempfile_in(directory.path())?;
    let mut blobs = tempfile::tempfile_in(directory.path())?;
    graph.write_all(b"existing")?;
    let limits = CaseSnapshotLimits::new(16 * 1024 * 1024, 16 * 1024 * 1024);
    assert!(write_files(&mut graph, &mut blobs, &source_case()?, limits, None).is_err());
    assert_eq!(graph.metadata()?.len(), 8);
    assert_eq!(blobs.metadata()?.len(), 0);
    Ok(())
}

#[test]
fn snapshot_writer_rejects_insufficient_scratch_before_writing() -> TestResult {
    let directory = tempfile::tempdir()?;
    let mut graph = tempfile::tempfile_in(directory.path())?;
    let mut blobs = tempfile::tempfile_in(directory.path())?;
    let limits = CaseSnapshotLimits::new(16 * 1024 * 1024, 16 * 1024 * 1024);
    let budget = MemoryBudget::new(1024 * 1024);
    assert!(
        write_files(
            &mut graph,
            &mut blobs,
            &source_case()?,
            limits,
            Some(&budget)
        )
        .is_err()
    );
    assert!(budget.snapshot()?.rejected > 0);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    assert_eq!(graph.metadata()?.len(), 0);
    assert_eq!(blobs.metadata()?.len(), 0);
    Ok(())
}

#[test]
fn verified_generation_streams_restore_exact_charged_case() -> TestResult {
    let directory = tempfile::tempdir()?;
    let mut graph = tempfile::tempfile_in(directory.path())?;
    let mut blobs = tempfile::tempfile_in(directory.path())?;
    let expected = source_case()?;
    let limits = CaseSnapshotLimits::new(16 * 1024 * 1024, 16 * 1024 * 1024);
    let budget = MemoryBudget::new(16 * 1024 * 1024);
    let usage = {
        let graph_writer: &mut dyn Write = &mut graph;
        let blob_writer: &mut dyn Write = &mut blobs;
        write_streams(graph_writer, blob_writer, &expected, limits, Some(&budget))?
    };
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    graph.seek(SeekFrom::Start(0))?;
    blobs.seek(SeekFrom::Start(0))?;
    let restored = {
        let graph_reader: &mut dyn Read = &mut graph;
        let blob_reader: &mut dyn Read = &mut blobs;
        read_streams(graph_reader, blob_reader, usage, limits, Some(&budget))?
    };
    assert_eq!(restored, expected);
    assert!(budget.snapshot()?.used(MemoryClass::Case) > 0);
    drop(restored);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}
