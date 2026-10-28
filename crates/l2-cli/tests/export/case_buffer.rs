use super::BufferedResult;
use l2_workbench::{
    evidence::{Case, CaseSnapshotLimits},
    investigation::BuildResult,
    job::{MemoryBudget, MemoryClass},
};
use serde_json::json;
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

fn retained_result(memory: &MemoryBudget) -> Result<BuildResult, Box<dyn Error>> {
    let mut case = Case::with_memory_budget(memory)?;
    case.add_bytes_node(
        "original",
        b"retained original",
        Vec::new(),
        json!({"ordinal":7}),
    )?;
    Ok(BuildResult {
        case,
        complete: false,
    })
}

#[test]
fn spilling_releases_the_case_charge_and_restores_exact_evidence_and_coverage() -> TestResult {
    let pool = rayon::ThreadPoolBuilder::new().num_threads(1).build()?;
    let directory = tempfile::tempdir()?;
    let memory = MemoryBudget::new(16 * 1024 * 1024);
    let result = retained_result(&memory)?;
    let expected = result.case.to_json()?;
    assert!(memory.snapshot()?.used(MemoryClass::Case) > 0);
    let limits = CaseSnapshotLimits::new(4 * 1024 * 1024, 4 * 1024 * 1024);

    let buffered = BufferedResult::spill(result, directory.path(), limits, Some(&memory))?;
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    // Anonymous descriptors cannot be mistaken for a published or reusable completed result
    assert_eq!(directory.path().read_dir()?.count(), 0);
    let restored = buffered.restore(&pool, Some(&memory))?;
    assert!(!restored.complete);
    assert_eq!(restored.case.to_json()?, expected);
    drop(restored);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn snapshot_write_limit_failure_releases_the_original_case() -> TestResult {
    let directory = tempfile::tempdir()?;
    let memory = MemoryBudget::new(16 * 1024 * 1024);
    let result = retained_result(&memory)?;
    let limits = CaseSnapshotLimits::new(1, 1);
    assert!(BufferedResult::spill(result, directory.path(), limits, Some(&memory)).is_err());
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    assert_eq!(directory.path().read_dir()?.count(), 0);
    Ok(())
}

#[test]
fn snapshot_restore_admission_failure_is_typed_and_drops_private_files() -> TestResult {
    let pool = rayon::ThreadPoolBuilder::new().num_threads(1).build()?;
    let directory = tempfile::tempdir()?;
    let writer_memory = MemoryBudget::new(16 * 1024 * 1024);
    let result = retained_result(&writer_memory)?;
    let limits = CaseSnapshotLimits::new(4 * 1024 * 1024, 4 * 1024 * 1024);
    let buffered = BufferedResult::spill(result, directory.path(), limits, Some(&writer_memory))?;
    let reader_memory = MemoryBudget::new(1);
    let error = buffered
        .restore(&pool, Some(&reader_memory))
        .err()
        .ok_or("restore should exceed admission")?;
    assert!(crate::memory_error::find(error.as_ref()).is_some());
    assert_eq!(writer_memory.snapshot()?.used_bytes, 0);
    assert_eq!(reader_memory.snapshot()?.used_bytes, 0);
    assert_eq!(directory.path().read_dir()?.count(), 0);
    Ok(())
}

#[test]
fn damaged_handoff_snapshot_is_rejected_before_collection() -> TestResult {
    let pool = rayon::ThreadPoolBuilder::new().num_threads(1).build()?;
    let directory = tempfile::tempdir()?;
    let memory = MemoryBudget::new(16 * 1024 * 1024);
    let limits = CaseSnapshotLimits::new(4 * 1024 * 1024, 4 * 1024 * 1024);
    let mut buffered = BufferedResult::spill(
        retained_result(&memory)?,
        directory.path(),
        limits,
        Some(&memory),
    )?;
    let BufferedResult::Snapshot { graph, .. } = &mut buffered else {
        return Err("result was not spilled".into());
    };
    graph.set_len(0)?;
    assert!(buffered.restore(&pool, Some(&memory)).is_err());
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn ordered_restoration_uses_the_pool_without_blocking_a_later_worker_waiting_for_the_prefix()
-> TestResult {
    let directory = tempfile::tempdir()?;
    let pool = rayon::ThreadPoolBuilder::new().num_threads(2).build()?;
    let memory = MemoryBudget::new(16 * 1024 * 1024);
    let limits = CaseSnapshotLimits::new(4 * 1024 * 1024, 4 * 1024 * 1024);
    let mut items = Vec::new();
    for index in 0..2 {
        let buffered = BufferedResult::spill(
            retained_result(&memory)?,
            directory.path(),
            limits,
            Some(&memory),
        )?;
        items.push((index, buffered));
    }
    let (release, receiver) = std::sync::mpsc::channel();
    let receiver = std::sync::Mutex::new(receiver);
    let mut collected = Vec::new();
    super::super::process_ordered(
        &pool,
        items,
        |_, _| Ok(Some(())),
        |(index, buffered), ()| {
            if index == 1 {
                receiver
                    .lock()
                    .map_err(|error| error.to_string())?
                    .recv_timeout(std::time::Duration::from_secs(3))
                    .map_err(|error| error.to_string())?;
            }
            Ok::<_, String>((index, buffered))
        },
        |(index, buffered)| {
            let restored = buffered.restore(&pool, Some(&memory))?;
            assert_eq!(
                restored
                    .case
                    .blobs()
                    .first()
                    .ok_or("missing restored blob")?
                    .bytes,
                b"retained original"
            );
            drop(restored);
            collected.push(index);
            if index == 0 {
                release.send(())?;
            }
            Ok(())
        },
    )?;
    assert_eq!(collected, [0, 1]);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}
