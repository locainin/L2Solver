use super::{
    AcquisitionOptions, IndexedAnalysisContext, IndexedAnalysisOptions, acquire_indexed_source,
    analyze_indexed_source, analyze_indexed_source_with_context, source_coverage,
};
use l2_workbench::{
    job::{
        Counter, Job, Phase, PhaseState,
        cache::{Cache, CacheReadPolicy, SourceIdentity, StageKey, StageStatus},
    },
    reconstruction::Limits,
    store::{IngestReceipt, Options, SCHEMA_VERSION, Store},
};
use serde_json::json;
use std::{error::Error, fs, io::Cursor};

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
fn indexed_flow_analysis_reuses_a_validated_native_case() -> Result<(), Box<dyn Error>> {
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
    Ok(())
}

fn open_test_cache(directory: &std::path::Path) -> Result<Cache, Box<dyn Error>> {
    Ok(Cache::open_at(
        directory.join("cache"),
        directory.join("state"),
        256 * 1024 * 1024,
    )?)
}

fn single_flow_capture() -> Vec<u8> {
    let mut capture = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
    capture.extend_from_slice(&[0; 8]);
    capture.extend_from_slice(&65_535_u32.to_le_bytes());
    capture.extend_from_slice(&1_u32.to_le_bytes());

    let mut frame = vec![0_u8; 54];
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&40_u16.to_be_bytes());
    frame[22] = 64;
    frame[23] = 6;
    frame[26..30].copy_from_slice(&[192, 0, 2, 10]);
    frame[30..34].copy_from_slice(&[192, 0, 2, 20]);
    frame[34..36].copy_from_slice(&40_000_u16.to_be_bytes());
    frame[36..38].copy_from_slice(&80_u16.to_be_bytes());
    frame[46..48].copy_from_slice(&0x5002_u16.to_be_bytes());
    frame[48..50].copy_from_slice(&1024_u16.to_be_bytes());

    capture.extend_from_slice(&1_u32.to_le_bytes());
    capture.extend_from_slice(&0_u32.to_le_bytes());
    capture.extend_from_slice(&54_u32.to_le_bytes());
    capture.extend_from_slice(&54_u32.to_le_bytes());
    capture.extend_from_slice(&frame);
    capture
}
