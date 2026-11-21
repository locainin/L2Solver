use super::{
    AcquisitionOptions, LLDP_CAPTURE, STP_CAPTURE, acquire_indexed_source, open_test_cache,
    source_alias_key,
};
use l2_workbench::job::{
    Counter, Job, Phase, PhaseState,
    cache::{Cache, SourceFingerprint, StageStatus},
};
use l2_workbench::store::IngestReceipt;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{error::Error, fs, path::Path};

#[test]
fn matching_alias_verifies_source_bytes() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let capture_path = directory.path().join("capture.pcap");
    let other_path = directory.path().join("other.pcap");
    fs::write(&capture_path, LLDP_CAPTURE)?;
    fs::write(&other_path, STP_CAPTURE)?;
    let cache = open_test_cache(directory.path())?;
    let options = AcquisitionOptions {
        cache: Some(&cache),
        ..AcquisitionOptions::default()
    };

    let indexed = acquire_indexed_source(&capture_path, directory.path(), &options)?;
    let expected_source_id = indexed.receipt.source_id.clone();
    drop(indexed);
    let other = acquire_indexed_source(&other_path, directory.path(), &options)?;
    let other_receipt = other.receipt.clone();
    assert_ne!(other_receipt.source_id, expected_source_id);
    drop(other);

    point_alias_to(&cache, &capture_path, &other_receipt)?;

    let job = Job::new("verify cached capture identity");
    let verified = acquire_indexed_source(
        &capture_path,
        directory.path(),
        &AcquisitionOptions {
            cache: Some(&cache),
            job: Some(&job),
            ..AcquisitionOptions::default()
        },
    )?;
    assert_eq!(verified.receipt.source_id, expected_source_id);
    let snapshot = job.snapshot()?;
    assert_eq!(
        snapshot.phase(Phase::Ingestion).map(|phase| phase.state),
        Some(PhaseState::Skipped)
    );
    assert!(
        snapshot
            .counters
            .get(&Counter::SourceReadBytes)
            .copied()
            .unwrap_or(0)
            >= u64::try_from(LLDP_CAPTURE.len())?,
        "the full verification read must be recorded"
    );
    Ok(())
}

#[test]
fn missing_verified_index_is_built() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let capture_path = directory.path().join("capture.pcap");
    let other_path = directory.path().join("other.pcap");
    fs::write(&capture_path, LLDP_CAPTURE)?;
    fs::write(&other_path, STP_CAPTURE)?;
    let cache = open_test_cache(directory.path())?;
    let other = acquire_indexed_source(
        &other_path,
        directory.path(),
        &AcquisitionOptions {
            cache: Some(&cache),
            ..AcquisitionOptions::default()
        },
    )?;
    point_alias_to(&cache, &capture_path, &other.receipt)?;
    drop(other);

    let job = Job::new("build missing capture index");
    let indexed = acquire_indexed_source(
        &capture_path,
        directory.path(),
        &AcquisitionOptions {
            cache: Some(&cache),
            job: Some(&job),
            ..AcquisitionOptions::default()
        },
    )?;
    assert_eq!(
        indexed.receipt.source_id,
        format!("sha256:{:x}", Sha256::digest(LLDP_CAPTURE))
    );
    let snapshot = job.snapshot()?;
    assert_eq!(
        snapshot.phase(Phase::Ingestion).map(|phase| phase.state),
        Some(PhaseState::Completed)
    );
    assert_eq!(snapshot.counters.get(&Counter::Packets), Some(&1));
    assert!(
        snapshot
            .counters
            .get(&Counter::CacheMisses)
            .copied()
            .unwrap_or(0)
            > 0
    );
    Ok(())
}

#[test]
fn cancelled_warm_cache_verification_stops() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let capture_path = directory.path().join("capture.pcap");
    fs::write(&capture_path, LLDP_CAPTURE)?;
    let cache = open_test_cache(directory.path())?;
    drop(acquire_indexed_source(
        &capture_path,
        directory.path(),
        &AcquisitionOptions {
            cache: Some(&cache),
            ..AcquisitionOptions::default()
        },
    )?);

    let job = Job::new("cancel cached capture verification");
    job.request_cancel();
    let result = acquire_indexed_source(
        &capture_path,
        directory.path(),
        &AcquisitionOptions {
            cache: Some(&cache),
            job: Some(&job),
            ..AcquisitionOptions::default()
        },
    );
    assert!(result.is_err(), "cancelled verification must stop");
    let snapshot = job.snapshot()?;
    assert_eq!(
        snapshot
            .counters
            .get(&Counter::CacheHits)
            .copied()
            .unwrap_or(0),
        0
    );
    assert_eq!(
        snapshot.phase(Phase::Ingestion).map(|phase| phase.state),
        Some(PhaseState::Cancelled)
    );
    Ok(())
}

fn point_alias_to(
    cache: &Cache,
    path: &Path,
    receipt: &IngestReceipt,
) -> Result<(), Box<dyn Error>> {
    // Keep the source fingerprint while linking a different, valid index receipt
    let fingerprint = SourceFingerprint::fast(path)?;
    let alias_key = source_alias_key(&fingerprint)?;
    let lease = cache.lease(&alias_key)?;
    drop(lease.commit(
        StageStatus::Complete,
        json!({"fingerprint": fingerprint, "receipt": receipt}),
    )?);
    Ok(())
}
