use super::*;
use l2_workbench::carrier::discovery::results::{
    DiscoveryResultStore, ResultReadOptions, StoreOptions, discover_samples_to_store,
    replay_candidate,
};
use l2_workbench::carrier::discovery::{DiscoveryCandidate, Partition};
use sha2::{Digest, Sha256};
use std::{io, path::Path};

#[path = "../../../../../tests/fixtures/carrier_bit_planes.rs"]
mod carrier_bit_planes;

use carrier_bit_planes::printable_bit_planes as two_printable_planes;

fn result_plan(report_budget: usize) -> DiscoveryPlan {
    DiscoveryPlan {
        widths: vec![8],
        phases: vec![0, 7],
        start_offsets: vec![0],
        reset_modes: vec![ResetMode::PerSample],
        sample_orders: vec![SampleOrder::InputOrder],
        remainder: BitRemainder::Reject,
        max_input_bytes: 1024,
        max_work_bytes: 4096,
        max_candidates: 8,
        minimum_printable_run_bytes: 4,
        max_report_bytes: report_budget,
        constraints: Vec::new(),
    }
}

fn result_sample(bytes: &[u8]) -> DiscoverySample<'_> {
    sample(1, 7, 1, bytes, vec![mapping(0, 12, 40)])
}

fn stored_candidates(
    directory: &Path,
    samples: &[DiscoverySample<'_>],
    plan: &DiscoveryPlan,
) -> Result<(usize, bool, Vec<DiscoveryCandidate>), Box<dyn Error>> {
    let summary = discover_samples_to_store(
        samples,
        plan,
        directory,
        StoreOptions {
            max_output_bytes: 4096,
            max_disk_bytes: 4 * 1024 * 1024,
        },
    )?;
    let store = DiscoveryResultStore::open(directory, summary.disk_budget_bytes)?;
    let candidates = store.list_candidates(None, 32)?.rows;
    Ok((
        summary.candidate_count,
        summary.enumeration_complete,
        candidates,
    ))
}

#[test]
fn competitors_retain_discovery_hashes() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let bytes = vec![0x80; 40];
    let samples = [result_sample(&bytes)];
    let mut plan = result_plan(4096);
    plan.phases = vec![0, 1, 7];
    plan.max_candidates = 3;

    let (_, enumeration_complete, candidates) =
        stored_candidates(directory.path(), &samples, &plan)?;

    assert!(enumeration_complete);
    assert_eq!(candidates.len(), 3);
    let first = candidates.first().ok_or("first candidate is missing")?;
    let second = candidates.get(1).ok_or("second candidate is missing")?;
    let third = candidates.get(2).ok_or("third candidate is missing")?;
    let first_hash = first
        .discovery
        .as_ref()
        .and_then(|summary| summary.output_sha256.as_deref())
        .ok_or("first candidate has no complete discovery output")?;
    let second_hash = second
        .discovery
        .as_ref()
        .and_then(|summary| summary.output_sha256.as_deref())
        .ok_or("second candidate has no complete discovery output")?;
    let third_hash = third
        .discovery
        .as_ref()
        .and_then(|summary| summary.output_sha256.as_deref())
        .ok_or("third candidate has no complete discovery output")?;
    assert_ne!(first_hash, second_hash);
    assert_eq!(second_hash, third_hash);
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.competitor_count)
            .collect::<Vec<_>>(),
        [1, 2, 2]
    );
    Ok(())
}

#[test]
fn competitors_share_control_hashes() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let discovery_bytes = vec![0x80; 40];
    let control_bytes = vec![0x00; 40];
    let samples = [
        sample(1, 7, 1, &discovery_bytes, vec![mapping(0, 12, 40)]),
        sample(2, 7, 2, &control_bytes, vec![mapping(0, 52, 40)]),
    ];
    let mut plan = result_plan(4096);
    plan.max_candidates = 2;

    let (_, enumeration_complete, candidates) =
        stored_candidates(directory.path(), &samples, &plan)?;

    assert!(enumeration_complete);
    assert_eq!(candidates.len(), 2);
    let first = candidates.first().ok_or("first candidate is missing")?;
    let second = candidates.get(1).ok_or("second candidate is missing")?;
    assert_ne!(
        first
            .discovery
            .as_ref()
            .and_then(|summary| summary.output_sha256.as_ref()),
        second
            .discovery
            .as_ref()
            .and_then(|summary| summary.output_sha256.as_ref())
    );
    assert_eq!(
        first
            .control
            .as_ref()
            .and_then(|summary| summary.output_sha256.as_ref()),
        second
            .control
            .as_ref()
            .and_then(|summary| summary.output_sha256.as_ref())
    );
    assert_eq!(first.competitor_count, 1);
    assert_eq!(second.competitor_count, 1);
    Ok(())
}

#[test]
fn candidates_without_competitors() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let bytes = [0x80; 3];
    let samples = [sample(1, 7, 1, &bytes, vec![mapping(0, 12, 3)])];
    let mut plan = result_plan(4096);
    plan.max_candidates = 2;

    let (_, enumeration_complete, candidates) =
        stored_candidates(directory.path(), &samples, &plan)?;

    assert!(enumeration_complete);
    assert_eq!(candidates.len(), 2);
    assert!(candidates.iter().all(|candidate| {
        candidate
            .discovery
            .as_ref()
            .is_some_and(|summary| summary.output_sha256.is_none())
            && candidate.competitor_count == 0
    }));
    Ok(())
}

#[test]
fn partial_enumeration_retains_candidates() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let bytes = vec![0x00; 40];
    let samples = [result_sample(&bytes)];
    let mut plan = result_plan(4096);
    plan.phases = vec![0, 1, 7];
    plan.max_candidates = 2;

    let (candidate_count, enumeration_complete, candidates) =
        stored_candidates(directory.path(), &samples, &plan)?;

    assert_eq!(candidate_count, 2);
    assert!(!enumeration_complete);
    assert_eq!(candidates.len(), 2);
    assert!(
        candidates
            .iter()
            .all(|candidate| candidate.competitor_count == 2)
    );
    Ok(())
}

#[test]
fn schema_one_store_readable() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let bytes = two_printable_planes()?;
    discover_samples_to_store(
        &[result_sample(&bytes)],
        &result_plan(4096),
        directory.path(),
        StoreOptions {
            max_output_bytes: 4096,
            max_disk_bytes: 4 * 1024 * 1024,
        },
    )?;
    let database = rusqlite::Connection::open(directory.path().join("results.sqlite"))?;
    let index_count: usize = database.query_row(
        "SELECT COUNT(*) FROM sqlite_schema \
         WHERE type = 'index' AND name = 'candidates_discovery_sha256'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(index_count, 1);
    database.execute("DROP INDEX candidates_discovery_sha256", [])?;
    drop(database);

    let store = DiscoveryResultStore::open(directory.path(), 4 * 1024 * 1024)?;

    assert_eq!(store.summary().schema_version, 1);
    assert_eq!(store.candidate(0)?.id, 0);
    Ok(())
}

#[test]
fn late_printable_receipts_preview_budget() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let bytes = two_printable_planes()?;
    let samples = [result_sample(&bytes)];
    let plan = result_plan(900);

    let preview = discover(&samples, &plan)?;
    assert!(!preview.printable_runs_complete);

    let summary = discover_samples_to_store(
        &samples,
        &plan,
        directory.path(),
        StoreOptions {
            max_output_bytes: 4096,
            max_disk_bytes: 4 * 1024 * 1024,
        },
    )?;
    let store = DiscoveryResultStore::open(directory.path(), 4 * 1024 * 1024)?;
    let first_candidate_runs = store.printable_runs(0, Partition::Discovery, None, 8)?;
    let later_candidate_runs = store.printable_runs(1, Partition::Discovery, None, 8)?;
    let receipts = store.sample_receipts(None, 1)?;

    assert_eq!(summary.printable_run_count, 2);
    assert_eq!(first_candidate_runs.rows.len(), 1);
    assert_eq!(
        first_candidate_runs
            .rows
            .first()
            .ok_or("first candidate run page is empty")?
            .text,
        "EARLY"
    );
    assert_eq!(later_candidate_runs.rows.len(), 1);
    assert_eq!(
        later_candidate_runs
            .rows
            .first()
            .ok_or("later candidate run page is empty")?
            .text,
        "LATER"
    );
    assert_eq!(summary.sample_receipt_count, 1);
    let receipt = receipts
        .rows
        .first()
        .ok_or("source receipt page is empty")?;
    assert_eq!(receipt.partition, Partition::Discovery);
    let source_mapping = receipt
        .mappings
        .first()
        .ok_or("source receipt has no mapping")?;
    assert_eq!(source_mapping.range.offset, 12);
    assert_eq!(source_mapping.range.length, 40);
    assert_eq!(store.summary().plan_sha256, summary.plan_sha256);
    Ok(())
}

#[test]
fn disk_budget_prevents_result_publication() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let bytes = two_printable_planes()?;
    let result = discover_samples_to_store(
        &[result_sample(&bytes)],
        &result_plan(1),
        directory.path(),
        StoreOptions {
            max_output_bytes: 4096,
            max_disk_bytes: 4096,
        },
    );

    assert!(result.is_err());
    assert!(DiscoveryResultStore::open(directory.path(), 4096).is_err());
    Ok(())
}

#[test]
fn result_pages_replay_candidate_identity() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let bytes = two_printable_planes()?;
    let samples = [result_sample(&bytes)];
    let plan = result_plan(1);
    let summary = discover_samples_to_store(
        &samples,
        &plan,
        directory.path(),
        StoreOptions {
            max_output_bytes: 4096,
            max_disk_bytes: 4 * 1024 * 1024,
        },
    )?;
    let store = DiscoveryResultStore::open(directory.path(), 4 * 1024 * 1024)?;

    let first_page = store.list_candidates(None, 1)?;
    let first = first_page
        .rows
        .first()
        .ok_or("first candidate page is empty")?;
    assert_eq!(first.id, 0);
    let next = first_page
        .next_after
        .ok_or("first candidate page has no cursor")?;
    let second_page = store.list_candidates(Some(next), 1)?;
    let second = second_page
        .rows
        .first()
        .ok_or("second candidate page is empty")?;
    assert_eq!(second.id, 1);
    assert_eq!(summary.candidate_count, 2);

    let mut exported = Vec::new();
    store.export_output(second.id, Partition::Discovery, &mut exported)?;
    assert_eq!(exported, b"LATER");
    let replay = replay_candidate(&samples, &plan, &store, second.id)?;
    assert_eq!(replay.candidate_id, second.id);
    assert!(replay.matches_stored_output);

    let mut changed_plan = plan.clone();
    changed_plan.phases = vec![0];
    assert!(replay_candidate(&samples, &changed_plan, &store, second.id).is_err());
    let changed_bytes = [0_u8; 40];
    let changed_samples = [result_sample(&changed_bytes)];
    assert!(replay_candidate(&changed_samples, &plan, &store, second.id).is_err());
    Ok(())
}

#[test]
fn store_open_rejects_missing_rows() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let bytes = two_printable_planes()?;
    let samples = [result_sample(&bytes)];
    discover_samples_to_store(
        &samples,
        &result_plan(900),
        directory.path(),
        StoreOptions {
            max_output_bytes: 4096,
            max_disk_bytes: 4 * 1024 * 1024,
        },
    )?;

    let database = rusqlite::Connection::open(directory.path().join("results.sqlite"))?;
    database.execute("DELETE FROM printable_runs WHERE run_id = 1", [])?;
    drop(database);

    assert!(DiscoveryResultStore::open(directory.path(), 4 * 1024 * 1024).is_err());
    Ok(())
}

#[test]
fn oversized_result_row_rejected() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let bytes = two_printable_planes()?;
    discover_samples_to_store(
        &[result_sample(&bytes)],
        &result_plan(900),
        directory.path(),
        StoreOptions {
            max_output_bytes: 4096,
            max_disk_bytes: 4 * 1024 * 1024,
        },
    )?;
    let database = rusqlite::Connection::open(directory.path().join("results.sqlite"))?;
    database.execute(
        "UPDATE printable_runs SET payload = zeroblob(32768) WHERE run_id = 0",
        [],
    )?;
    drop(database);

    let result = DiscoveryResultStore::open_with_options(
        directory.path(),
        ResultReadOptions {
            max_disk_bytes: 4 * 1024 * 1024,
            max_record_bytes: 4096,
            max_page_bytes: 4 * 1024 * 1024,
        },
    );
    let Err(error) = result else {
        return Err("oversized row unexpectedly opened".into());
    };
    assert!(error.to_string().contains("record exceeds"));
    Ok(())
}

#[test]
fn candidate_pages_enforce_size_limit() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let bytes = two_printable_planes()?;
    discover_samples_to_store(
        &[result_sample(&bytes)],
        &result_plan(1),
        directory.path(),
        StoreOptions {
            max_output_bytes: 4096,
            max_disk_bytes: 4 * 1024 * 1024,
        },
    )?;
    let store = DiscoveryResultStore::open_with_options(
        directory.path(),
        ResultReadOptions {
            max_disk_bytes: 4 * 1024 * 1024,
            max_record_bytes: 4 * 1024 * 1024,
            max_page_bytes: 1,
        },
    )?;

    let error = store
        .list_candidates(None, 1)
        .err()
        .ok_or("page exceeding its encoded-size budget was accepted")?;
    assert!(error.to_string().contains("record exceeds reader limit"));
    Ok(())
}

#[test]
fn large_output_streams_candidate_digest() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let bytes = vec![b'A'; 128 * 1024];
    let mut large_plan = result_plan(1);
    large_plan.widths = vec![1];
    large_plan.phases = vec![0];
    large_plan.max_candidates = 1;
    large_plan.max_input_bytes = bytes.len();
    large_plan.max_work_bytes = bytes.len() * 10;
    let sample = sample(
        1,
        7,
        1,
        &bytes,
        vec![mapping(0, 12, u64::try_from(bytes.len())?)],
    );
    let summary = discover_samples_to_store(
        &[sample],
        &large_plan,
        directory.path(),
        StoreOptions {
            max_output_bytes: 256 * 1024,
            max_disk_bytes: 2 * 1024 * 1024,
        },
    )?;
    let store = DiscoveryResultStore::open(directory.path(), summary.disk_budget_bytes)?;
    let candidate = store.candidate(0)?;
    let output_digest = candidate
        .discovery
        .as_ref()
        .and_then(|partition| partition.output_sha256.as_deref())
        .ok_or("candidate has no complete output digest")?;
    let mut writer = DigestWriter::default();
    let exported = store.export_output(0, Partition::Discovery, &mut writer)?;

    assert_eq!(exported, u64::try_from(bytes.len())?);
    assert_eq!(writer.length, bytes.len());
    assert_eq!(writer.finish(), output_digest);
    Ok(())
}

#[test]
fn snapshot_consistent_result_pages() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let bytes = two_printable_planes()?;
    discover_samples_to_store(
        &[result_sample(&bytes)],
        &result_plan(900),
        directory.path(),
        StoreOptions {
            max_output_bytes: 4096,
            max_disk_bytes: 4 * 1024 * 1024,
        },
    )?;
    let store = DiscoveryResultStore::open(directory.path(), 4 * 1024 * 1024)?;
    let database = rusqlite::Connection::open(directory.path().join("results.sqlite"))?;

    let concurrent_write = database.execute(
        "UPDATE candidates SET payload = payload || ' ' WHERE candidate_id = 0",
        [],
    );

    assert!(concurrent_write.is_err());
    assert_eq!(store.candidate(0)?.id, 0);
    Ok(())
}

#[derive(Default)]
struct DigestWriter {
    hasher: Sha256,
    length: usize,
}

impl DigestWriter {
    fn finish(self) -> String {
        format!("{:x}", self.hasher.finalize())
    }
}

impl io::Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.hasher.update(bytes);
        self.length = self
            .length
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("test digest length overflowed"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
