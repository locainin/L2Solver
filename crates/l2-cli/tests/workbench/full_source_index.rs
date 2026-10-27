use super::{
    AcquisitionOptions, IndexedAnalysisContext, IndexedAnalysisOptions, acquire_indexed_source,
    analyze_indexed_source, analyze_indexed_source_with_context, source_coverage,
};
use l2_pcap::CaptureSource;
use l2_workbench::{
    job::{
        Counter, Job, Phase, PhaseState,
        cache::{Cache, CacheReadPolicy, SourceIdentity, StageKey, StageStatus},
    },
    reconstruction::Limits,
    store::{IngestReceipt, Options, SCHEMA_VERSION, Store},
};
use serde_json::json;
use std::{
    error::Error,
    fs,
    io::Cursor,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

const LLDP_CAPTURE: &[u8] = include_bytes!("../../../../tests/pcaps/lldp.pcap");
const STP_CAPTURE: &[u8] = include_bytes!("../../../../tests/pcaps/linux-stp.pcap");

#[test]
fn published_capture_index_can_be_reused_without_reingestion() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let capture = LLDP_CAPTURE;
    let mut store = Store::create(directory.path(), Options::default())?;
    let receipt = store.ingest("input", Cursor::new(capture))?;
    drop(store);

    let store = Store::open(directory.path(), Options::default())?;
    let coverage = analyze_indexed_source(
        &store,
        &receipt,
        IndexedAnalysisOptions {
            limits: Limits::default(),
            include_cohorts: true,
        },
        |_| Ok(()),
    )?;
    assert_eq!(coverage.source.source_id, receipt.source_id);
    assert_eq!(coverage.source.bytes, u64::try_from(capture.len())?);
    assert_eq!(coverage.source.packet_records, 1);
    assert_eq!(coverage.source.packets_without_supported_transport, 1);
    assert_eq!(coverage.analysis.flows, 0);
    assert_eq!(source_coverage(&receipt).bytes, coverage.source.bytes);
    Ok(())
}

#[test]
fn cached_receipt_cannot_be_applied_to_another_index() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let capture = LLDP_CAPTURE;
    let mut store = Store::create(directory.path(), Options::default())?;
    let mut receipt = store.ingest("input", Cursor::new(capture))?;
    receipt.source_id = format!("sha256:{}", "00".repeat(32));

    let result =
        analyze_indexed_source(&store, &receipt, IndexedAnalysisOptions::default(), |_| {
            Ok(())
        });
    assert!(result.is_err());
    Ok(())
}

#[test]
fn cached_receipt_must_match_indexed_source_metadata() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let capture = LLDP_CAPTURE;
    let mut store = Store::create(directory.path(), Options::default())?;
    let receipt = store.ingest("input", Cursor::new(capture))?;

    for (bytes, packets) in [(0, receipt.packets), (receipt.bytes, 0)] {
        let mut mismatched = receipt.clone();
        mismatched.bytes = bytes;
        mismatched.packets = packets;
        assert!(
            analyze_indexed_source(
                &store,
                &mismatched,
                IndexedAnalysisOptions::default(),
                |_| Ok(())
            )
            .is_err(),
            "receipt byte and packet totals must match the indexed source"
        );
    }
    Ok(())
}

#[test]
fn ingest_receipt_roundtrips_with_canonical_collection_summary() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let capture = LLDP_CAPTURE;
    let mut store = Store::create(directory.path(), Options::default())?;
    let receipt = store.ingest("input", Cursor::new(capture))?;
    let encoded = serde_json::to_vec(&receipt)?;
    let decoded: IngestReceipt = serde_json::from_slice(&encoded)?;

    assert_eq!(
        serde_json::to_value(decoded)?,
        serde_json::to_value(receipt)?
    );
    Ok(())
}

#[test]
fn warm_cached_capture_index_skips_ingestion() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let capture_path = directory.path().join("capture.pcap");
    fs::write(&capture_path, LLDP_CAPTURE)?;
    let cache = open_test_cache(directory.path())?;
    let options = AcquisitionOptions {
        cache: Some(&cache),
        ..AcquisitionOptions::default()
    };

    let first = acquire_indexed_source(&capture_path, directory.path(), &options)?;
    let source_id = first.receipt.source_id.clone();
    drop(first);

    let job = Job::new("cached capture acquisition");
    let options = AcquisitionOptions {
        cache: Some(&cache),
        job: Some(&job),
        ..AcquisitionOptions::default()
    };
    let reused = acquire_indexed_source(&capture_path, directory.path(), &options)?;
    assert_eq!(reused.receipt.source_id, source_id);

    let snapshot = job.snapshot()?;
    assert_eq!(
        snapshot.phase(Phase::Ingestion).map(|phase| phase.state),
        Some(PhaseState::Skipped)
    );
    assert_eq!(
        snapshot
            .phase(Phase::Ingestion)
            .map(|phase| phase.completed),
        Some(0)
    );
    assert_eq!(
        snapshot
            .counters
            .get(&Counter::Packets)
            .copied()
            .unwrap_or(0),
        0
    );
    assert!(
        snapshot
            .counters
            .get(&Counter::CacheHits)
            .copied()
            .unwrap_or(0)
            > 0
    );
    Ok(())
}

#[test]
fn fresh_lldp_tcp_capture_counts_packets_and_warm_cache_reuse_counts_none()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let capture_path = directory.path().join("mixed.pcap");
    fs::write(&capture_path, capture_with_lldp_and_tcp()?)?;
    let cache = open_test_cache(directory.path())?;
    let job = Job::new("mixed capture acquisition");
    let options = AcquisitionOptions {
        cache: Some(&cache),
        job: Some(&job),
        ..AcquisitionOptions::default()
    };

    let indexed = acquire_indexed_source(&capture_path, directory.path(), &options)?;
    assert_eq!(indexed.receipt.packets, 2);
    assert_eq!(indexed.receipt.transport_packets, 1);
    assert_eq!(indexed.receipt.unsupported_transport_packets, 1);
    assert_eq!(
        job.snapshot()?
            .counters
            .get(&Counter::Packets)
            .copied()
            .unwrap_or(0),
        2
    );
    drop(indexed);

    let warm_job = Job::new("warm mixed capture acquisition");
    let options = AcquisitionOptions {
        cache: Some(&cache),
        job: Some(&warm_job),
        ..AcquisitionOptions::default()
    };
    let reused = acquire_indexed_source(&capture_path, directory.path(), &options)?;
    assert_eq!(reused.receipt.packets, 2);
    assert_eq!(
        warm_job
            .snapshot()?
            .counters
            .get(&Counter::Packets)
            .copied()
            .unwrap_or(0),
        0
    );
    Ok(())
}

#[test]
fn renamed_capture_reuses_content_addressed_index() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let original = directory.path().join("original.pcap");
    let renamed = directory.path().join("renamed.pcap");
    fs::write(&original, LLDP_CAPTURE)?;
    fs::copy(&original, &renamed)?;
    let cache = open_test_cache(directory.path())?;
    let options = AcquisitionOptions {
        cache: Some(&cache),
        ..AcquisitionOptions::default()
    };

    let first = acquire_indexed_source(&original, directory.path(), &options)?;
    let source_id = first.receipt.source_id.clone();
    drop(first);

    let job = Job::new("renamed capture acquisition");
    let options = AcquisitionOptions {
        cache: Some(&cache),
        job: Some(&job),
        ..AcquisitionOptions::default()
    };
    let reused = acquire_indexed_source(&renamed, directory.path(), &options)?;
    assert_eq!(reused.receipt.source_id, source_id);
    assert_eq!(
        job.snapshot()?
            .phase(Phase::Ingestion)
            .map(|phase| phase.state),
        Some(PhaseState::Skipped)
    );
    Ok(())
}

#[test]
fn changed_capture_content_misses_cached_index() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let capture_path = directory.path().join("capture.pcap");
    fs::write(&capture_path, LLDP_CAPTURE)?;
    let cache = open_test_cache(directory.path())?;
    let options = AcquisitionOptions {
        cache: Some(&cache),
        ..AcquisitionOptions::default()
    };
    let first = acquire_indexed_source(&capture_path, directory.path(), &options)?;
    let source_id = first.receipt.source_id.clone();
    drop(first);

    fs::write(&capture_path, STP_CAPTURE)?;
    let job = Job::new("changed capture acquisition");
    let options = AcquisitionOptions {
        cache: Some(&cache),
        job: Some(&job),
        ..AcquisitionOptions::default()
    };
    let changed = acquire_indexed_source(&capture_path, directory.path(), &options)?;
    assert_ne!(changed.receipt.source_id, source_id);
    assert_eq!(
        job.snapshot()?
            .phase(Phase::Ingestion)
            .map(|phase| phase.state),
        Some(PhaseState::Completed)
    );
    assert!(
        job.snapshot()?
            .counters
            .get(&Counter::CacheMisses)
            .copied()
            .unwrap_or(0)
            > 0
    );
    Ok(())
}

#[test]
fn strict_cache_rejects_a_stale_caller_fingerprint() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let capture_path = directory.path().join("capture.pcap");
    fs::write(&capture_path, LLDP_CAPTURE)?;
    let fingerprint = Cache::fingerprint_source(&capture_path)?;
    fs::write(&capture_path, STP_CAPTURE)?;
    let cache = open_test_cache(directory.path())?;
    let options = AcquisitionOptions {
        cache: Some(&cache),
        fingerprint: Some(fingerprint),
        strict_cache: true,
        ..AcquisitionOptions::default()
    };

    assert!(acquire_indexed_source(&capture_path, directory.path(), &options).is_err());
    assert_eq!(cache.stats()?.entries, 0);
    Ok(())
}

#[test]
fn strict_cache_checks_content_before_trusting_a_matching_fast_alias() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    let capture_path = directory.path().join("capture.pcap");
    fs::write(&capture_path, LLDP_CAPTURE)?;
    let cache = open_test_cache(directory.path())?;
    let acquisition = AcquisitionOptions {
        cache: Some(&cache),
        ..AcquisitionOptions::default()
    };
    let indexed = acquire_indexed_source(&capture_path, directory.path(), &acquisition)?;
    let expected_source_id = indexed.receipt.source_id.clone();
    let mut incorrect_receipt = indexed.receipt.clone();
    incorrect_receipt.source_id = format!("sha256:{}", "00".repeat(32));
    drop(indexed);

    let fingerprint = Cache::fingerprint_source(&capture_path)?;
    let alias_key = StageKey::new(
        "capture_source",
        SCHEMA_VERSION,
        "pcap-source-alias-v1",
        &json!({}),
        &SourceIdentity::Fast(fingerprint.sample_hint()),
        &[],
    )?;
    let lease = cache.lease(&alias_key)?;
    drop(lease.commit(
        StageStatus::Complete,
        json!({
            "fingerprint": fingerprint,
            "receipt": incorrect_receipt,
        }),
    )?);

    let strict = AcquisitionOptions {
        cache: Some(&cache),
        strict_cache: true,
        ..AcquisitionOptions::default()
    };
    let checked = acquire_indexed_source(&capture_path, directory.path(), &strict)?;
    assert_eq!(checked.receipt.source_id, expected_source_id);
    assert!(
        cache
            .lookup(&alias_key, CacheReadPolicy::CompleteOnly)?
            .is_some()
    );
    Ok(())
}

#[test]
fn cancelled_capture_ingestion_drops_uncommitted_cache_work() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let capture_path = directory.path().join("capture.pcap");
    fs::write(&capture_path, LLDP_CAPTURE)?;
    let cache = open_test_cache(directory.path())?;
    let job = Job::new("cancelled capture acquisition");
    job.request_cancel();
    let options = AcquisitionOptions {
        cache: Some(&cache),
        job: Some(&job),
        ..AcquisitionOptions::default()
    };

    assert!(acquire_indexed_source(&capture_path, directory.path(), &options).is_err());
    assert_eq!(cache.stats()?.entries, 0);
    assert_eq!(
        job.snapshot()?
            .phase(Phase::Ingestion)
            .map(|phase| phase.state),
        Some(PhaseState::Cancelled)
    );
    Ok(())
}

#[test]
fn concurrent_capture_acquisition_waits_for_alias_writer_and_reuses_its_index()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let capture_path = directory.path().join("capture.pcap");
    fs::write(&capture_path, LLDP_CAPTURE)?;
    let cache = open_test_cache(directory.path())?;
    let initial = acquire_indexed_source(
        &capture_path,
        directory.path(),
        &AcquisitionOptions {
            cache: Some(&cache),
            ..AcquisitionOptions::default()
        },
    )?;
    let source_id = initial.receipt.source_id.clone();
    drop(initial);

    // Hold the source alias as though a competing process is updating the index
    let fingerprint = Cache::fingerprint_source(&capture_path)?;
    let alias_key = source_alias_key(&fingerprint)?;
    let writer_lease = cache.lease(&alias_key)?;
    let job = Job::new("concurrent capture acquisition");
    let (sender, receiver) = mpsc::channel();
    let worker_parent = directory.path().to_path_buf();
    let worker_job = job.clone();
    let worker = thread::spawn(move || {
        let options = AcquisitionOptions {
            cache: Some(&cache),
            job: Some(&worker_job),
            ..AcquisitionOptions::default()
        };
        let result = acquire_indexed_source(&capture_path, &worker_parent, &options)
            .map(|indexed| indexed.receipt.source_id)
            .map_err(|error| error.to_string());
        let _ = sender.send(result);
    });

    assert!(receiver.recv_timeout(Duration::from_millis(100)).is_err());
    drop(writer_lease);
    assert_eq!(
        receiver.recv_timeout(Duration::from_secs(3))?,
        Ok(source_id)
    );
    worker
        .join()
        .map_err(|_| "capture acquisition worker panicked")?;

    let snapshot = job.snapshot()?;
    assert_eq!(
        snapshot.phase(Phase::Ingestion).map(|phase| phase.state),
        Some(PhaseState::Skipped)
    );
    assert!(
        snapshot
            .counters
            .get(&Counter::CacheHits)
            .copied()
            .unwrap_or(0)
            > 0
    );
    Ok(())
}

#[test]
fn persistently_busy_alias_falls_back_to_temporary_index_with_progress_message()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let capture_path = directory.path().join("capture.pcap");
    fs::write(&capture_path, LLDP_CAPTURE)?;
    let cache = open_test_cache(directory.path())?;
    let fingerprint = Cache::fingerprint_source(&capture_path)?;
    let alias_key = source_alias_key(&fingerprint)?;
    let writer_lease = cache.lease(&alias_key)?;
    let job = Job::new("busy capture cache");
    let options = AcquisitionOptions {
        cache: Some(&cache),
        job: Some(&job),
        ..AcquisitionOptions::default()
    };

    let indexed = acquire_indexed_source(&capture_path, directory.path(), &options)?;
    assert!(indexed.receipt.source_id.starts_with("sha256:"));
    let snapshot = job.snapshot()?;
    let phase = snapshot
        .phase(Phase::Ingestion)
        .ok_or("capture acquisition records ingestion progress")?;
    assert_eq!(phase.state, PhaseState::Completed);
    assert!(phase.message.as_deref().is_some_and(|message| {
        let message = message.to_ascii_lowercase();
        message.contains("temporary") && message.contains("cache")
    }));
    assert!(
        job.snapshot()?
            .counters
            .get(&Counter::CacheMisses)
            .copied()
            .unwrap_or(0)
            > 0
    );
    drop(indexed);
    drop(writer_lease);
    Ok(())
}

#[test]
fn busy_content_index_lease_does_not_restart_completed_ingestion() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let capture_path = directory.path().join("capture.pcap");
    fs::write(&capture_path, LLDP_CAPTURE)?;
    let cache = open_test_cache(directory.path())?;
    let identity = SourceIdentity::sha256_file(&capture_path)?;
    let source_key = source_index_key(&identity)?;
    cache.clear()?;
    let writer_lease = cache.lease(&source_key)?;
    let job = Job::new("contended content index");
    let (sender, receiver) = mpsc::channel();
    let worker_parent = directory.path().to_path_buf();
    let worker_job = job.clone();
    let worker = thread::spawn(move || {
        let options = AcquisitionOptions {
            cache: Some(&cache),
            job: Some(&worker_job),
            ..AcquisitionOptions::default()
        };
        let result = acquire_indexed_source(&capture_path, &worker_parent, &options)
            .map(|indexed| indexed.receipt.source_id)
            .map_err(|error| error.to_string());
        let _ = sender.send(result);
    });

    let expected_bytes = u64::try_from(LLDP_CAPTURE.len())?;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let completed = job
            .snapshot()?
            .phase(Phase::Ingestion)
            .map(|phase| phase.completed)
            .unwrap_or_default();
        if completed == expected_bytes {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "capture ingestion must reach EOF"
        );
        thread::sleep(Duration::from_millis(10));
    }

    drop(writer_lease);
    let SourceIdentity::Sha256(digest) = identity else {
        return Err("source hashing must return a strong identity".into());
    };
    assert_eq!(
        receiver.recv_timeout(Duration::from_secs(3))?,
        Ok(format!("sha256:{digest}"))
    );
    worker
        .join()
        .map_err(|_| "capture acquisition worker panicked")?;
    assert_eq!(
        job.snapshot()?
            .phase(Phase::Ingestion)
            .map(|phase| phase.completed),
        Some(expected_bytes)
    );
    Ok(())
}

#[test]
fn indexed_flow_analysis_cache_requires_matching_reconstruction_limits()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let capture_path = directory.path().join("flow.pcap");
    fs::write(&capture_path, single_flow_capture())?;
    let cache = open_test_cache(directory.path())?;
    let acquisition = AcquisitionOptions {
        cache: Some(&cache),
        ..AcquisitionOptions::default()
    };
    let indexed = acquire_indexed_source(&capture_path, directory.path(), &acquisition)?;
    let options = IndexedAnalysisOptions {
        include_cohorts: false,
        ..IndexedAnalysisOptions::default()
    };
    let first = analyze_indexed_source_with_context(
        &indexed.store,
        &indexed.receipt,
        options,
        IndexedAnalysisContext {
            cache: Some(&cache),
            job: None,
        },
        |_| Ok(()),
    )?;
    assert_eq!(first.analysis.flows, 1);
    drop(indexed);

    let indexed = acquire_indexed_source(&capture_path, directory.path(), &acquisition)?;
    let job = Job::new("cached native flow analysis");
    let cached = analyze_indexed_source_with_context(
        &indexed.store,
        &indexed.receipt,
        options,
        IndexedAnalysisContext {
            cache: Some(&cache),
            job: Some(&job),
        },
        |_| Ok(()),
    )?;
    assert_eq!(cached.analysis.flows, 1);
    assert!(
        job.snapshot()?
            .counters
            .get(&Counter::CacheHits)
            .copied()
            .unwrap_or(0)
            > 0
    );

    let changed_limits = Limits {
        frames: 1,
        ..Limits::default()
    };
    let changed_job = Job::new("native flow analysis with changed limits");
    let changed = analyze_indexed_source_with_context(
        &indexed.store,
        &indexed.receipt,
        IndexedAnalysisOptions {
            limits: changed_limits,
            include_cohorts: false,
        },
        IndexedAnalysisContext {
            cache: Some(&cache),
            job: Some(&changed_job),
        },
        |_| Ok(()),
    )?;
    assert_eq!(changed.analysis.flows, 1);
    assert!(
        changed_job
            .snapshot()?
            .counters
            .get(&Counter::CacheMisses)
            .copied()
            .unwrap_or(0)
            > 0,
        "changing reconstruction limits must not reuse a native flow Case"
    );
    Ok(())
}

fn open_test_cache(directory: &std::path::Path) -> Result<Cache, Box<dyn Error>> {
    Ok(Cache::open_at(
        directory.join("cache"),
        directory.join("state"),
        256 * 1024 * 1024,
    )?)
}

fn source_alias_key(
    fingerprint: &l2_workbench::job::cache::SourceFingerprint,
) -> Result<StageKey, Box<dyn Error>> {
    Ok(StageKey::new(
        "capture_source",
        SCHEMA_VERSION,
        "pcap-source-alias-v1",
        &json!({}),
        &SourceIdentity::Fast(fingerprint.sample_hint()),
        &[],
    )?)
}

fn source_index_key(identity: &SourceIdentity) -> Result<StageKey, Box<dyn Error>> {
    Ok(StageKey::new(
        "capture_index",
        SCHEMA_VERSION,
        "pcap-index-v1",
        &json!({}),
        identity,
        &[],
    )?)
}

fn single_flow_capture() -> Vec<u8> {
    let mut capture = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
    capture.extend_from_slice(&[0; 8]);
    capture.extend_from_slice(&65_535_u32.to_le_bytes());
    capture.extend_from_slice(&1_u32.to_le_bytes());

    // Keep the fixture as explicit Ethernet, IPv4, and TCP header bytes
    let mut frame = vec![0_u8; 12];
    frame.extend_from_slice(&0x0800_u16.to_be_bytes());
    frame.extend_from_slice(&[
        0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 192, 0, 2, 10, 192, 0, 2, 20,
    ]);
    frame.extend_from_slice(&[
        0x9c, 0x40, 0, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 2, 0x04, 0, 0, 0, 0, 0,
    ]);
    capture.extend_from_slice(&1_u32.to_le_bytes());
    capture.extend_from_slice(&0_u32.to_le_bytes());
    capture.extend_from_slice(&54_u32.to_le_bytes());
    capture.extend_from_slice(&54_u32.to_le_bytes());
    capture.extend_from_slice(&frame);
    capture
}

fn capture_with_lldp_and_tcp() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut lldp_source = CaptureSource::new(Cursor::new(LLDP_CAPTURE))?;
    let lldp = lldp_source
        .next_packet()?
        .ok_or("LLDP packet fixture is empty")?;
    let frame = lldp.bytes();
    let length = u32::try_from(frame.len())?;
    let mut capture = single_flow_capture();
    capture.extend_from_slice(&2_u32.to_le_bytes());
    capture.extend_from_slice(&0_u32.to_le_bytes());
    capture.extend_from_slice(&length.to_le_bytes());
    capture.extend_from_slice(&length.to_le_bytes());
    capture.extend_from_slice(frame);
    Ok(capture)
}
