use std::error::Error;

#[cfg(unix)]
use std::fs;

use l2_workbench::{
    evidence::Case,
    job::{MemoryBudget, MemoryError},
};
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn Error>>;
const FLOW_BYTES: usize = 64 * 1024;

fn context() -> super::ArtifactSourceContext {
    super::ArtifactSourceContext {
        flow: Some(json!({"label": "x".repeat(FLOW_BYTES)})),
        supporting_flows: Vec::new(),
        cohort_scope: None,
        case_id: None,
        case_scope: json!({"kind": "flow"}),
    }
}

fn case() -> Result<Case, Box<dyn Error>> {
    let mut case = Case::new();
    case.add_bytes_node("ftp_data_candidate", b"payload", Vec::new(), json!({}))?;
    Ok(case)
}

#[test]
fn provenance_encoding_reports_budget_failure_before_retaining_the_artifact() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let mut artifacts = super::super::ArtifactCollection::new(
        temporary.path(),
        super::super::ArtifactLimits::default(),
    )?;
    let case = case()?;
    let source = context();
    let budget = MemoryBudget::new(32 * 1024);
    let error = super::super::collect_case_artifacts_with_context(
        &mut artifacts,
        &case,
        Some(&budget),
        |_, _| Ok(source.clone()),
    )
    .err()
    .ok_or("provenance encoding ignored shared publication memory")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(artifacts.coverage().unique_artifacts_retained, 0);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn admitted_provenance_encoding_keeps_the_exact_flow_and_releases_its_charge() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let mut artifacts = super::super::ArtifactCollection::new(
        temporary.path(),
        super::super::ArtifactLimits::default(),
    )?;
    let case = case()?;
    let source = context();
    let expected = source.flow.clone();
    let budget = MemoryBudget::new(2 * 1024 * 1024);
    super::super::collect_case_artifacts_with_context(
        &mut artifacts,
        &case,
        Some(&budget),
        |_, _| Ok(source.clone()),
    )?;
    let mut found = 0;
    artifacts.visit_artifact_origins(|_, _, origin| {
        found += 1;
        assert_eq!(origin.flow, expected);
        assert!(origin.node.is_none());
        assert_eq!(
            origin
                .flow
                .as_ref()
                .and_then(|flow| flow.get("label"))
                .and_then(Value::as_str)
                .map(str::len),
            Some(FLOW_BYTES)
        );
        Ok(())
    })?;
    assert_eq!(found, 1);
    assert!(budget.snapshot()?.peak_bytes >= u64::try_from(FLOW_BYTES)?);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[cfg(unix)]
#[test]
fn tshark_provenance_encoding_preserves_typed_memory_failure() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let staging = temporary.path().join("staging");
    let objects = temporary.path().join("objects");
    fs::create_dir(&staging)?;
    fs::create_dir(&objects)?;
    fs::write(objects.join("entry"), b"payload")?;
    let mut artifacts =
        super::super::ArtifactCollection::new(&staging, super::super::ArtifactLimits::default())?;
    let budget = MemoryBudget::new(32);
    let error = super::super::tshark_objects::collect(
        &[(String::from("http"), objects)],
        &mut artifacts,
        10,
        Some(&budget),
    )
    .err()
    .ok_or("TShark provenance ignored shared publication memory")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(artifacts.coverage().unique_artifacts_retained, 0);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[cfg(unix)]
#[test]
fn omission_detail_reports_memory_failure_separately_from_size_omission() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let staging = temporary.path().join("staging");
    fs::create_dir(&staging)?;
    let mut artifacts =
        super::super::ArtifactCollection::new(&staging, super::super::ArtifactLimits::default())?;
    let provenance =
        super::export_provenance(None, Some(json!({"archive_path": "x".repeat(FLOW_BYTES)})));
    let mut directory = fs::File::open(temporary.path())?;
    let budget = MemoryBudget::new(4 * 1024);
    let error = artifacts
        .add_open_file(&mut directory, "omitted.bin", &provenance, Some(&budget))
        .err()
        .ok_or("omission detail ignored shared publication memory")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(artifacts.coverage().omission_details_retained, 0);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn admitted_size_limit_keeps_the_existing_omission_reason() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let limits = super::super::ArtifactLimits {
        artifact_bytes: 1,
        ..super::super::ArtifactLimits::default()
    };
    let mut artifacts = super::super::ArtifactCollection::new(temporary.path(), limits)?;
    let provenance = super::export_provenance(None, None);
    let budget = MemoryBudget::new(1024 * 1024);
    assert_eq!(
        artifacts.add_bytes(b"payload", "payload.bin", &provenance, Some(&budget))?,
        super::super::artifact_collection::AddOutcome::Omitted(
            super::super::artifact_collection::OmissionReason::ArtifactBytes
        )
    );
    assert_eq!(artifacts.coverage().omission_details_retained, 1);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}
