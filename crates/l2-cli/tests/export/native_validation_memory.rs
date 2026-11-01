use std::{
    error::Error,
    io::{Cursor, Write},
};

use l2_workbench::{
    artifact::DerNode,
    evidence::Case,
    job::{MemoryBudget, MemoryError},
};
use serde_json::json;

use super::{ArtifactCollection, ArtifactLimits, recovered_test_context};

const MEMBER_BYTES: usize = 128 * 1024;
const DER_CHILDREN: usize = 512;
type TestResult = Result<(), Box<dyn Error>>;

fn native_archive_case() -> Result<Case, Box<dyn Error>> {
    let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
    archive.start_file(
        "member.bin",
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
    )?;
    archive.write_all(&vec![7; MEMBER_BYTES])?;
    native_case(&archive.finish()?.into_inner())
}

fn native_der_case() -> Result<Case, Box<dyn Error>> {
    let mut bytes = vec![0x30, 0x82, 0x04, 0x00];
    for _ in 0..DER_CHILDREN {
        bytes.extend_from_slice(&[0x05, 0x00]);
    }
    native_case(&bytes)
}

fn native_case(bytes: &[u8]) -> Result<Case, Box<dyn Error>> {
    let mut case = Case::new();
    case.add_bytes_node(
        "http_body",
        bytes,
        Vec::new(),
        json!({"status": "complete", "framing_complete": true}),
    )?;
    Ok(case)
}

#[test]
fn native_zip_validation_rejects_insufficient_shared_memory_before_publication() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let mut artifacts = ArtifactCollection::new(temporary.path(), ArtifactLimits::default())?;
    let case = native_archive_case()?;
    let budget = MemoryBudget::new(32 * 1024);
    let error = super::super::collection::collect_case_artifacts_with_context(
        &mut artifacts,
        &case,
        Some(&budget),
        |_, _| Ok(recovered_test_context()),
    )
    .err()
    .ok_or("native ZIP validation ignored shared memory")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(artifacts.coverage().references_selected, 0);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn native_zip_validation_releases_expansion_charge_after_publication() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let mut artifacts = ArtifactCollection::new(temporary.path(), ArtifactLimits::default())?;
    let case = native_archive_case()?;
    let budget = MemoryBudget::new(2 * 1024 * 1024);
    super::super::collection::collect_case_artifacts_with_context(
        &mut artifacts,
        &case,
        Some(&budget),
        |_, _| Ok(recovered_test_context()),
    )?;
    assert_eq!(artifacts.coverage().references_selected, 1);
    assert!(
        artifacts
            .file_names()?
            .contains(std::ffi::OsStr::new("000001-http.zip"))
    );
    assert!(budget.snapshot()?.peak_bytes >= u64::try_from(MEMBER_BYTES)?);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn native_der_fallback_rejects_insufficient_shared_memory() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let mut artifacts = ArtifactCollection::new(temporary.path(), ArtifactLimits::default())?;
    let case = native_der_case()?;
    let budget = MemoryBudget::new(4 * 1024);
    let error = super::super::collection::collect_case_artifacts_with_context(
        &mut artifacts,
        &case,
        Some(&budget),
        |_, _| Ok(recovered_test_context()),
    )
    .err()
    .ok_or("native DER fallback ignored shared memory")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(artifacts.coverage().references_selected, 0);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn native_der_fallback_releases_inventory_after_publication() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let mut artifacts = ArtifactCollection::new(temporary.path(), ArtifactLimits::default())?;
    let case = native_der_case()?;
    let budget = MemoryBudget::new(1024 * 1024);
    super::super::collection::collect_case_artifacts_with_context(
        &mut artifacts,
        &case,
        Some(&budget),
        |_, _| Ok(recovered_test_context()),
    )?;
    assert_eq!(artifacts.coverage().references_selected, 1);
    assert!(
        artifacts
            .file_names()?
            .contains(std::ffi::OsStr::new("000001-http.der"))
    );
    let inventory = (DER_CHILDREN + 1) * std::mem::size_of::<DerNode>();
    assert!(budget.snapshot()?.peak_bytes >= u64::try_from(inventory)?);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn native_zip_and_der_names_remain_available_without_a_job_budget() -> TestResult {
    for (case, expected) in [
        (native_archive_case()?, "000001-http.zip"),
        (native_der_case()?, "000001-http.der"),
    ] {
        let temporary = tempfile::tempdir()?;
        let mut artifacts = ArtifactCollection::new(temporary.path(), ArtifactLimits::default())?;
        super::super::collection::collect_case_artifacts_with_context(
            &mut artifacts,
            &case,
            None,
            |_, _| Ok(recovered_test_context()),
        )?;
        assert_eq!(artifacts.coverage().references_selected, 1);
        assert!(
            artifacts
                .file_names()?
                .contains(std::ffi::OsStr::new(expected))
        );
    }
    Ok(())
}
