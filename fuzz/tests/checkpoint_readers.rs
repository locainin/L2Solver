#[path = "../fuzz_targets/checkpoint_readers/mod.rs"]
mod checkpoint_readers;

use l2_workbench::{
    evidence::{Case, CaseSnapshotLimits},
    job::{
        Counter, Job,
        cache::{CheckpointStatus, JOB_SNAPSHOT_VERSION},
    },
};
use serde_json::json;
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn combined_reader_oracles_handle_empty_malformed_and_dense_inputs() {
    for input in [b"".as_slice(), b"{", b"\xff\xff\x00", &[b'\n'; 4096]] {
        checkpoint_readers::exercise(input);
    }
}

#[test]
fn snapshot_reader_restores_valid_data_and_rejects_corrupt_blob_pack() -> TestResult {
    let mut expected = Case::new();
    expected.add_bytes_node("fixture", b"snapshot data", Vec::new(), json!({}))?;
    let mut graph = Vec::new();
    let mut pack = Vec::new();
    expected.write_snapshot(
        &mut graph,
        &mut pack,
        CaseSnapshotLimits::new(65_536, 65_536),
    )?;

    let restored = checkpoint_readers::case::read(&graph, &pack)?;
    assert_eq!(restored, expected);
    let first = pack.first_mut().ok_or("expected a nonempty blob pack")?;
    *first ^= 1;
    assert!(checkpoint_readers::case::read(&graph, &pack).is_err());
    assert!(checkpoint_readers::case::read(b"not a gzip stream", &[]).is_err());
    Ok(())
}

#[test]
fn job_reader_restores_valid_json_and_reports_counter_overflow() -> TestResult {
    let snapshot = Job::new("checkpoint seed").snapshot()?;
    let encoded = serde_json::to_vec(&snapshot)?;
    let restored = checkpoint_readers::job::restore(&encoded)?;
    assert_eq!(restored.snapshot()?.label, "checkpoint seed");

    let mut overflowing = snapshot;
    overflowing.counters.insert(Counter::SourceReadBytes, 1);
    overflowing
        .counters
        .insert(Counter::PriorSourceReadBytes, u64::MAX);
    assert!(checkpoint_readers::job::restore(&serde_json::to_vec(&overflowing)?).is_err());
    assert!(checkpoint_readers::job::restore(b"{").is_err());
    Ok(())
}

#[test]
fn cache_reader_checks_database_payload_status_version_and_topology() -> TestResult {
    let cache = checkpoint_readers::cache::Fixture::new()?;
    let snapshot = Job::new("cache seed").snapshot()?;
    let valid = serde_json::to_vec(&snapshot)?;
    let version = i64::from(JOB_SNAPSHOT_VERSION);

    let loaded = cache
        .read(&valid, 1, version)?
        .ok_or("missing checkpoint")?;
    assert_eq!(loaded.status, CheckpointStatus::Active);
    assert_eq!(loaded.snapshot, snapshot);
    assert!(cache.read(&valid, 9, version).is_err());
    assert!(cache.read(&valid, 1, 999).is_err());
    assert!(cache.read(b"\xff", 1, version).is_err());
    assert!(cache.read(b"{", 1, version).is_err());

    let mut invalid_topology = snapshot.clone();
    invalid_topology.phases.pop();
    assert!(
        cache
            .read(&serde_json::to_vec(&invalid_topology)?, 1, version)
            .is_err()
    );

    // A corrupted row must not contaminate the next independent fuzz input
    let loaded = cache
        .read(&valid, 2, version)?
        .ok_or("missing checkpoint")?;
    assert_eq!(loaded.status, CheckpointStatus::Complete);
    assert_eq!(loaded.snapshot, snapshot);
    Ok(())
}
