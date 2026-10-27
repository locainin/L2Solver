use crate::case_snapshot::{read_files, write_files};
use l2_workbench::{
    evidence::{Case, CaseSnapshotLimits},
    job::{MemoryBudget, MemoryClass},
};
use serde_json::json;
use std::{error::Error, io::Write};

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
