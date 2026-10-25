use super::{Manifest, write};
use crate::workbench::bundle_budget::MAX_BUNDLE_BYTES;
use crate::workbench::stream::Source;
use std::error::Error;

fn empty_manifest() -> Manifest {
    Manifest {
        schema_version: 1,
        source: Source {
            id: format!("sha256:{}", l2_workbench::sha256(b"capture")),
            label: "capture.pcap".to_owned(),
            length: 24,
            frames: 0,
            collection_summary: l2_pcap::CollectionSummary::default(),
        },
        raw_collection_complete: true,
        analysis_complete: true,
        context_records: 0,
        pages: Vec::new(),
        limitations: Vec::new(),
    }
}

#[test]
fn manifest_pages_equal_bundle_budget() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let manifest = empty_manifest();
    let document = serde_json::to_vec(&manifest)?;
    // A recorded page-byte count exercises the real boundary without a GiB fixture
    let pages_bytes = MAX_BUNDLE_BYTES - u64::try_from(document.len())?;

    let digest = write(directory.path(), &manifest, pages_bytes)?;

    assert_eq!(
        std::fs::read(directory.path().join("manifest.json"))?,
        document
    );
    assert_eq!(digest, l2_workbench::sha256(&document));
    Ok(())
}

#[test]
fn manifest_not_remaining_bundle_bytes() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let manifest = empty_manifest();
    let document = serde_json::to_vec(&manifest)?;
    let pages_bytes = MAX_BUNDLE_BYTES - u64::try_from(document.len())? + 1;

    let result = write(directory.path(), &manifest, pages_bytes);

    assert!(result.is_err());
    assert!(!directory.path().join("manifest.json").exists());
    Ok(())
}
