use std::{
    error::Error,
    io::{Cursor, Write},
};

use l2_workbench::{
    artifact::{
        ArtifactStructure, ArtifactValidationFormat, ArtifactValidationOutcome, ArtifactValidator,
    },
    evidence::{Case, Edge, EvidenceStatus},
    job::{MemoryBudget, MemoryClass, MemoryError},
};
use serde_json::json;

const MEMBER_BYTES: usize = 128 * 1024;
type TestResult = Result<(), Box<dyn Error>>;

fn archive_case() -> Result<Case, Box<dyn Error>> {
    let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
    archive.start_file(
        "member.bin",
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
    )?;
    archive.write_all(&vec![7; MEMBER_BYTES])?;
    let bytes = archive.finish()?.into_inner();
    let ArtifactValidationOutcome::Validated {
        structure: ArtifactStructure::Zip(report),
        ..
    } = ArtifactValidator::default().validate_as(ArtifactValidationFormat::Zip, &bytes)
    else {
        return Err("test archive did not validate".into());
    };
    let mut case = Case::new();
    let input = case.add_bytes_node("candidate_object", &bytes, Vec::new(), json!({}))?;
    let blob = case
        .node(input)
        .and_then(|node| node.blob.clone())
        .ok_or("archive blob is missing")?;
    let structure = case.add_node(
        "archive_structure",
        Some(&blob),
        Vec::new(),
        json!({
            "input_node": input,
            "depth": 0,
            "format": "zip",
            "archive_sha256": report.archive_sha256,
            "archive_size": report.archive_size,
            "entry_count": report.entry_count,
            "extracted_entry_count": report.extracted_entry_count,
            "expanded_byte_count": report.expanded_byte_count,
            "expanded_work_byte_count": report.expanded_work_byte_count,
            "omitted_entry_count": report.omitted_entry_count
        }),
    )?;
    case.add_edge(Edge {
        from: input,
        to: structure,
        relation: "parsed_as".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "Archive structure was parsed".to_owned(),
    })?;
    Ok(case)
}

#[test]
fn zip_expansion_rejects_a_budget_too_small_for_its_member() -> TestResult {
    let case = archive_case()?;
    let budget = MemoryBudget::new(32 * 1024);
    let error = super::super::select_artifacts(&case, Some(&budget))
        .err()
        .ok_or("ZIP member expansion ignored shared memory")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn zip_expansion_charge_is_released_after_cached_report_drops() -> TestResult {
    let case = archive_case()?;
    let budget = MemoryBudget::new(2 * 1024 * 1024);
    let selected = super::super::select_artifacts(&case, Some(&budget))?;
    assert_eq!(selected.len(), 1);
    assert!(budget.snapshot()?.peak_bytes >= u64::try_from(MEMBER_BYTES)?);
    assert!(budget.snapshot()?.used(MemoryClass::Publication) < u64::try_from(MEMBER_BYTES)?);
    drop(selected);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}
