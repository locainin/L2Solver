use std::{error::Error, fs, path::Path};

use l2_workbench::{
    artifact::{AnalysisStatus, ArtifactOrigin, ArtifactValidationState, ValidationSummary},
    evidence::Case,
    job::{MemoryBudget, MemoryClass, MemoryError},
};
use serde_json::json;

use crate::refine::{
    file_artifact::FileArtifact,
    output::{ArtifactRecord, RefineManifest, SourceRecord, make_manifest, write_summary_file},
};
use crate::workbench::artifact_export::select_artifacts;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn manifest_admits_retained_origins_and_releases_them_after_drop() -> TestResult {
    let budget = MemoryBudget::new(256 * 1024);
    let mut case = Case::new();
    let node = case.add_bytes_node("record_object", b"source bytes", Vec::new(), json!({}))?;
    let selected = select_artifacts(&case)?;
    let validation = ValidationSummary {
        state: ArtifactValidationState::Unsupported,
        format: None,
        boundary: None,
        range: None,
        structure_count: 0,
    };
    let sources = [SourceRecord {
        label: "source.bin".to_owned(),
        sha256: Some(l2_workbench::sha256(b"source bytes")),
        byte_length: 12,
        status: AnalysisStatus::Complete,
        omissions: Vec::new(),
        work_bytes_charged: None,
        zip_expanded_work_bytes_charged: None,
        reason: None,
        omission_memory: budget.try_reserve(MemoryClass::Executor, 0)?,
    }];
    let records = [0, 1].map(|artifact_index| ArtifactRecord {
        node_id: node,
        source_index: 0,
        artifact_index,
        origin: ArtifactOrigin::Source,
        sha256: l2_workbench::sha256(b"source bytes"),
        byte_length: 12,
        validation,
        signature_match_count: 0,
    });
    let digest = l2_workbench::sha256(b"source bytes");
    let files = [FileArtifact::zip(2, 0, 2, 12, &digest, 0, &budget)?];
    let baseline = budget.snapshot()?.used_bytes;
    let many_records: Vec<_> = (0..64)
        .map(|artifact_index| ArtifactRecord {
            node_id: node,
            source_index: 0,
            artifact_index,
            origin: ArtifactOrigin::Source,
            sha256: digest.clone(),
            byte_length: 12,
            validation,
            signature_match_count: 0,
        })
        .collect();
    let partial_blocker = budget.try_reserve(
        MemoryClass::Cache,
        budget.snapshot()?.limit_bytes - baseline - 2048,
    )?;
    let before = budget.snapshot()?.used_bytes;
    let error = make_manifest(&selected, &files, &sources, &many_records, true, &budget)
        .err()
        .ok_or("manifest ignored pressure while building origins")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::Limit { .. })
    ));
    assert!(budget.snapshot()?.peak_bytes > before);
    drop(partial_blocker);
    assert_eq!(budget.snapshot()?.used_bytes, baseline);

    let blocker = budget.try_reserve(MemoryClass::Cache, budget.snapshot()?.limit_bytes - baseline)?;
    let error = make_manifest(&selected, &files, &sources, &records, true, &budget)
        .err()
        .ok_or("manifest ignored the shared memory limit")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::Limit { .. })
    ));
    drop(blocker);
    assert_eq!(budget.snapshot()?.used_bytes, baseline);

    let manifest = make_manifest(&selected, &files, &sources, &records, true, &budget)?;
    assert_manifest_contents_and_release(manifest, &digest, &budget, baseline)
}

fn assert_manifest_contents_and_release(
    manifest: RefineManifest<'_>,
    digest: &str,
    budget: &MemoryBudget,
    baseline: u64,
) -> TestResult {
    let value = serde_json::to_value(&manifest)?;
    let artifact = value
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .and_then(|artifacts| artifacts.first())
        .ok_or("manifest artifact missing")?;
    assert_eq!(
        artifact.get("sha256").and_then(serde_json::Value::as_str),
        Some(l2_workbench::sha256(b"source bytes").as_str())
    );
    assert_eq!(
        artifact
            .get("origins")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(2)
    );
    let file = value
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .and_then(|artifacts| artifacts.get(1))
        .ok_or("file-backed artifact missing")?;
    assert_eq!(
        file.get("sha256").and_then(serde_json::Value::as_str),
        Some(digest)
    );
    assert_eq!(
        file.get("origins")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(1)
    );
    assert!(budget.snapshot()?.used_bytes > baseline);
    drop(manifest);
    assert_eq!(budget.snapshot()?.used_bytes, baseline);
    Ok(())
}

#[test]
fn streamed_summary_preserves_escaped_source_details() -> TestResult {
    let directory = tempfile::tempdir()?;
    let budget = MemoryBudget::new(1024);
    let sources = [SourceRecord {
        label: "input\nname".to_owned(),
        sha256: None,
        byte_length: 17,
        status: AnalysisStatus::Partial,
        omissions: Vec::new(),
        work_bytes_charged: None,
        zip_expanded_work_bytes_charged: None,
        reason: Some("invalid\tdata".to_owned()),
        omission_memory: budget.try_reserve(MemoryClass::Executor, 0)?,
    }];

    write_summary_file(directory.path(), Path::new("result\nname"), &[], &[], &sources, false)?;
    assert_eq!(
        fs::read_to_string(directory.path().join("summary.txt"))?,
        "Refined artifacts\nDirectory: result\\nname\nSources: 1; files: 0; status: incomplete\nSource: input\\nname; SHA-256: not read; bytes: 17; analysis: partial; reason: invalid\\tdata\n"
    );
    Ok(())
}
