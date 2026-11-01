//! Exercise real disk-backed Case handoff under deterministic ordering and failures

use super::{BufferedResult, TestResult};
use crate::{export::processing::process_ordered, publish};
use l2_workbench::{
    evidence::{Case, CaseSnapshotLimits},
    investigation::BuildResult,
    job::{BufferedCase, MemoryBudget, MemoryClass},
    sha256,
};
use serde_json::json;
use std::{
    error::Error,
    fs,
    path::Path,
    sync::{Mutex, mpsc},
    time::Duration,
};

const MIB: usize = 1024 * 1024;
const PREVIOUS: &[u8] = b"previous completed output";

fn case_for_index(
    memory: &MemoryBudget,
    index: usize,
    size: usize,
) -> Result<BuildResult, Box<dyn Error>> {
    let byte = u8::try_from(index + 1)?;
    let bytes = vec![byte; size];
    let mut case = Case::with_memory_budget(memory)?;
    case.add_bytes_node("original", &bytes, Vec::new(), json!({"ordinal": index}))?;
    Ok(BuildResult {
        case,
        complete: index.is_multiple_of(2),
    })
}

fn old_destination(
    root: &Path,
) -> Result<(std::path::PathBuf, publish::PreparedDirectoryReplacement), Box<dyn Error>> {
    let destination = root.join("bundle");
    publish::create_directory(&destination, |staging| {
        fs::write(staging.join("payload"), PREVIOUS)?;
        Ok(())
    })?;
    let prepared = publish::prepare_directory_replacement(&destination)?;
    Ok((destination, prepared))
}

fn assert_previous_and_clean(root: &Path, destination: &Path, memory: &MemoryBudget) -> TestResult {
    assert_eq!(fs::read(destination.join("payload"))?, PREVIOUS);
    assert_eq!(fs::read_dir(root)?.count(), 1);
    let snapshot = memory.snapshot()?;
    assert_eq!(snapshot.used_bytes, 0);
    assert_eq!(snapshot.buffered_cases.current_cases, 0);
    assert_eq!(snapshot.buffered_cases.current_snapshot_bytes, 0);
    Ok(())
}

struct QueuedCase {
    index: usize,
    buffered: BufferedResult,
    observation: BufferedCase,
    case_sha256: String,
    blob_sha256: String,
}

fn prepare_case(
    root: &Path,
    memory: &MemoryBudget,
    limits: CaseSnapshotLimits,
    index: usize,
) -> Result<QueuedCase, Box<dyn Error>> {
    let result = case_for_index(memory, index, 4 * MIB)?;
    let case_sha256 = sha256(&result.case.to_json()?);
    let blob_sha256 = sha256(&result.case.blobs().first().ok_or("blob missing")?.bytes);
    let buffered = if index == 0 {
        BufferedResult::Resident(Box::new(result))
    } else {
        BufferedResult::spill(result, root, limits, Some(memory), None)?
    };
    let observation = buffered.observe(memory)?;
    Ok(QueuedCase {
        index,
        buffered,
        observation,
        case_sha256,
        blob_sha256,
    })
}

fn check_restored_case(
    queued: QueuedCase,
    pool: &rayon::ThreadPool,
    memory: &MemoryBudget,
) -> Result<usize, Box<dyn Error>> {
    let QueuedCase {
        index,
        buffered,
        observation,
        case_sha256,
        blob_sha256,
    } = queued;
    drop(observation);
    let restored = buffered.restore(pool, Some(memory), None)?;
    assert_eq!(sha256(&restored.case.to_json()?), case_sha256);
    let blob = restored
        .case
        .blobs()
        .first()
        .ok_or("restored blob missing")?;
    let node = restored
        .case
        .nodes()
        .first()
        .ok_or("restored node missing")?;
    let expected_byte = u8::try_from(index + 1)?;
    assert_eq!(blob.id, format!("sha256:{blob_sha256}"));
    assert_eq!(blob.bytes.len(), 4 * MIB);
    assert!(blob.bytes.iter().all(|byte| *byte == expected_byte));
    assert_eq!(node.id, 1);
    assert_eq!(node.blob.as_deref(), Some(blob.id.as_str()));
    assert_eq!(
        node.details
            .get("ordinal")
            .and_then(serde_json::Value::as_u64),
        Some(u64::try_from(index)?)
    );
    assert_eq!(restored.complete, index.is_multiple_of(2));
    println!(
        "restored case={index} graph_sha256={case_sha256} blob_sha256={blob_sha256} bytes={}",
        blob.bytes.len()
    );
    Ok(index)
}

#[test]
fn delayed_first_case_restores_real_spills_in_order_with_exact_identities() -> TestResult {
    let root = tempfile::tempdir()?;
    let pool = rayon::ThreadPoolBuilder::new().num_threads(3).build()?;
    let memory = MemoryBudget::new(128 * u64::try_from(MIB)?);
    let limits = CaseSnapshotLimits::new(32 * u64::try_from(MIB)?, 32 * u64::try_from(MIB)?);
    let (later_finished, receiver) = mpsc::channel();
    let receiver = Mutex::new(receiver);
    let mut emitted = Vec::new();

    process_ordered(
        &pool,
        vec![0_usize, 1, 2],
        |_, _| Ok(Some(())),
        |index, ()| {
            if index == 0 {
                let receiver = receiver.lock().map_err(|error| error.to_string())?;
                for _ in 0..2 {
                    receiver
                        .recv_timeout(Duration::from_secs(20))
                        .map_err(|error| error.to_string())?;
                }
            }
            let queued = prepare_case(root.path(), &memory, limits, index)
                .map_err(|error| error.to_string())?;
            if index != 0 {
                later_finished
                    .send(index)
                    .map_err(|error| error.to_string())?;
            }
            Ok::<_, String>(queued)
        },
        |queued| {
            emitted.push(check_restored_case(queued, &pool, &memory)?);
            Ok(())
        },
    )?;
    assert_eq!(emitted, [0, 1, 2]);
    let snapshot = memory.snapshot()?;
    let buffered = snapshot.buffered_cases;
    assert_eq!(buffered.spilled_cases, 2);
    assert!(buffered.peak_cases >= 2);
    assert!(buffered.peak_snapshot_bytes >= 8 * u64::try_from(MIB)?);
    assert!(buffered.peak_snapshot_bytes <= 32 * u64::try_from(MIB)?);
    assert_eq!(buffered.current_cases, 0);
    assert_eq!(buffered.current_snapshot_bytes, 0);
    assert_eq!(snapshot.used_bytes, 0);
    assert_eq!(fs::read_dir(root.path())?.count(), 0);
    println!(
        "handoff peak_cases={} peak_snapshot_bytes={} spilled_cases={} spilled_snapshot_bytes={} peak_memory_bytes={}",
        buffered.peak_cases,
        buffered.peak_snapshot_bytes,
        buffered.spilled_cases,
        buffered.spilled_snapshot_bytes,
        snapshot.peak_bytes
    );
    Ok(())
}

#[test]
fn corrupted_ordered_spill_does_not_replace_previous_output_or_leak_files() -> TestResult {
    let root = tempfile::tempdir()?;
    let (destination, prepared) = old_destination(root.path())?;
    let pool = rayon::ThreadPoolBuilder::new().num_threads(2).build()?;
    let memory = MemoryBudget::new(32 * u64::try_from(MIB)?);
    let limits = CaseSnapshotLimits::new(8 * u64::try_from(MIB)?, 8 * u64::try_from(MIB)?);
    let outcome = publish::replace_directory_with_precommit(
        &prepared,
        |staging| {
            fs::write(staging.join("payload"), b"incomplete replacement")?;
            let mut damaged = BufferedResult::spill(
                case_for_index(&memory, 0, MIB)?,
                staging,
                limits,
                Some(&memory),
                None,
            )?;
            let BufferedResult::Snapshot { graph, .. } = &mut damaged else {
                return Err("snapshot was not spilled".into());
            };
            graph.set_len(0)?;
            let second = BufferedResult::spill(
                case_for_index(&memory, 1, MIB)?,
                staging,
                limits,
                Some(&memory),
                None,
            )?;
            let first_observation = damaged.observe(&memory)?;
            let second_observation = second.observe(&memory)?;
            process_ordered(
                &pool,
                vec![(damaged, first_observation), (second, second_observation)],
                |_, _| Ok(Some(())),
                |item, ()| Ok::<_, String>(item),
                |(buffered, observation)| {
                    drop(observation);
                    let restored = buffered.restore(&pool, Some(&memory), None)?;
                    drop(restored);
                    Ok(())
                },
            )?;
            Ok(())
        },
        || Ok(()),
    );
    assert!(matches!(
        outcome,
        Err(publish::DirectoryPublishError::BeforePublication(_))
    ));
    assert_previous_and_clean(root.path(), &destination, &memory)?;
    assert_eq!(memory.snapshot()?.used(MemoryClass::Case), 0);
    Ok(())
}

#[path = "batch.rs"]
mod batch;
#[path = "cancellation.rs"]
mod cancellation;
#[cfg(unix)]
#[path = "faults.rs"]
mod faults;
