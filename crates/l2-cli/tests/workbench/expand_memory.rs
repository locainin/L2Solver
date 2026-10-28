use super::{ExpansionError, ExpansionLimits, ExpansionService};
use l2_workbench::{
    evidence::Case,
    job::{MemoryBudget, MemoryClass, MemoryError},
};
use serde_json::json;
use std::{
    error::Error,
    io::{Cursor, Write},
};

type TestResult = Result<(), Box<dyn Error>>;

fn limits() -> ExpansionLimits {
    ExpansionLimits {
        depth: 2,
        objects: 32,
        input_bytes: 4096,
        archive_entries: 32,
        member_bytes: 4096,
        zip_work_bytes: 4096,
        retained_bytes: 4096,
    }
}

#[test]
fn expansion_rejects_input_copy_pressure_before_case_mutation() -> TestResult {
    let mut case = Case::new();
    let root = case.add_bytes_node("input", b"content", Vec::new(), json!({}))?;
    let before = case.to_json()?;
    let budget = MemoryBudget::new(0);
    let mut service = ExpansionService::new(&mut case, limits(), Some(&budget));
    let result = service.probe_candidate(root);
    assert!(matches!(
        result,
        Err(ExpansionError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(service.case().to_json()?, before);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn expansion_releases_its_copied_input_after_the_candidate_finishes() -> TestResult {
    let mut case = Case::new();
    let root = case.add_bytes_node("input", b"content", Vec::new(), json!({}))?;
    let budget = MemoryBudget::new(100_000);
    let mut service = ExpansionService::new(&mut case, limits(), Some(&budget));
    service.probe_candidate(root)?;
    let snapshot = budget.snapshot()?;
    assert!(snapshot.peak_bytes >= u64::try_from(b"content".len())?);
    assert_eq!(snapshot.used(MemoryClass::Executor), 0);
    Ok(())
}

#[test]
fn zip_member_pressure_fails_before_adding_case_evidence() -> TestResult {
    let archive = stored_zip(b"member bytes")?;
    let mut case = Case::new();
    let root = case.add_bytes_node("input", &archive, Vec::new(), json!({}))?;
    let before = case.to_json()?;
    let budget = MemoryBudget::new(u64::try_from(archive.len())?);
    let mut service = ExpansionService::new(&mut case, limits(), Some(&budget));

    let result = service.probe_candidate(root);

    assert!(matches!(
        result,
        Err(ExpansionError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(service.case().to_json()?, before);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn zip_member_memory_is_held_while_expansion_retains_the_member() -> TestResult {
    let payload = b"member bytes";
    let archive = stored_zip(payload)?;
    let mut case = Case::new();
    let root = case.add_bytes_node("input", &archive, Vec::new(), json!({}))?;
    let budget = MemoryBudget::new(100_000);
    let mut service = ExpansionService::new(&mut case, limits(), Some(&budget));

    let result = service.probe_candidate(root)?;

    assert!(result.complete);
    assert!(
        service
            .case()
            .nodes()
            .iter()
            .any(|node| node.kind == "archive_member")
    );
    let snapshot = budget.snapshot()?;
    assert!(snapshot.peak_bytes >= u64::try_from(archive.len() + payload.len())?);
    assert_eq!(snapshot.used(MemoryClass::Executor), 0);
    Ok(())
}

fn stored_zip(payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    archive.start_file("payload", options)?;
    archive.write_all(payload)?;
    Ok(archive.finish()?.into_inner())
}
