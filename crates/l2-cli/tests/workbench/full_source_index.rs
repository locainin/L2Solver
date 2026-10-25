use super::{IndexedAnalysisOptions, analyze_indexed_source, source_coverage};
use l2_workbench::{
    reconstruction::Limits,
    store::{IngestReceipt, Options, Store},
};
use std::{error::Error, io::Cursor};

#[test]
fn published_capture_index_can_be_reused_without_reingestion() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let capture = include_bytes!("../../../../tests/pcaps/lldp.pcap");
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
    let capture = include_bytes!("../../../../tests/pcaps/lldp.pcap");
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
    let capture = include_bytes!("../../../../tests/pcaps/lldp.pcap");
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
    let capture = include_bytes!("../../../../tests/pcaps/lldp.pcap");
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
