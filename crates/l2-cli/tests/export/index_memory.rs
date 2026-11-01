use std::{error::Error, mem::size_of};

use l2_workbench::{
    evidence::{Case, Edge, EvidenceStatus},
    job::{MemoryBudget, MemoryError},
};
use serde_json::json;

use super::ArtifactSourceContext;

const SIGNATURES: usize = 1_024;
type TestResult = Result<(), Box<dyn Error>>;

fn case_with_signature_candidates() -> Result<Case, Box<dyn Error>> {
    let mut case = Case::new();
    let input = case.add_bytes_node("record_object", b"small record", Vec::new(), json!({}))?;
    for _ in 0..SIGNATURES {
        case.add_node(
            "file_signature_match",
            None,
            Vec::new(),
            json!({"input_node": input}),
        )?;
    }
    Ok(case)
}

fn case_with_mapping_receipts() -> Result<Case, Box<dyn Error>> {
    let mut case = Case::new();
    let input_blob = case.add_blob(b"input")?;
    let receipt_blob = case.add_blob(b"[]")?;
    for _ in 0..SIGNATURES {
        let input = case.add_node("candidate_object", Some(&input_blob), Vec::new(), json!({}))?;
        let receipt = case.add_node(
            "byte_mapping_receipt",
            Some(&receipt_blob),
            Vec::new(),
            json!({"output_node": input, "representation": "json_blob"}),
        )?;
        case.add_edge(Edge {
            from: input,
            to: receipt,
            relation: "mapped_by".to_owned(),
            status: EvidenceStatus::Observed,
            reason: "The output has a byte mapping receipt".to_owned(),
        })?;
    }
    Ok(case)
}

fn context() -> ArtifactSourceContext {
    ArtifactSourceContext {
        flow: None,
        supporting_flows: Vec::new(),
        cohort_scope: None,
        case_id: None,
        case_scope: json!({"kind": "flow"}),
    }
}

fn retained_context() -> ArtifactSourceContext {
    let mut context = context();
    context.case_id = Some("retained-case".to_owned());
    context
}

#[test]
fn signature_reference_index_rejects_insufficient_shared_memory() -> TestResult {
    let case = case_with_signature_candidates()?;
    let temporary = tempfile::tempdir()?;
    let mut artifacts = super::super::ArtifactCollection::new(
        temporary.path(),
        super::super::ArtifactLimits::default(),
    )?;
    let budget = MemoryBudget::new(4 * 1024);
    let error = super::super::collect_case_artifacts_with_context(
        &mut artifacts,
        &case,
        Some(&budget),
        |_, _| Ok(retained_context()),
    )
    .err()
    .ok_or("signature reference index ignored shared publication memory")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(artifacts.coverage().references_selected, 0);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn signature_reference_index_releases_its_charge_after_collection() -> TestResult {
    let case = case_with_signature_candidates()?;
    let temporary = tempfile::tempdir()?;
    let mut artifacts = super::super::ArtifactCollection::new(
        temporary.path(),
        super::super::ArtifactLimits::default(),
    )?;
    let budget = MemoryBudget::new(8 * 1024 * 1024);
    super::super::collect_case_artifacts_with_context(
        &mut artifacts,
        &case,
        Some(&budget),
        |_, _| Ok(retained_context()),
    )?;
    assert_eq!(artifacts.coverage().references_selected, 1);
    assert!(budget.snapshot()?.peak_bytes >= u64::try_from(SIGNATURES * size_of::<&()>())?);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn omitted_case_does_not_build_an_unused_signature_index() -> TestResult {
    let case = case_with_signature_candidates()?;
    let temporary = tempfile::tempdir()?;
    let mut artifacts = super::super::ArtifactCollection::new(
        temporary.path(),
        super::super::ArtifactLimits::default(),
    )?;
    let budget = MemoryBudget::new(4 * 1024);
    super::super::collect_case_artifacts_with_context(
        &mut artifacts,
        &case,
        Some(&budget),
        |_, _| Ok(context()),
    )?;
    assert_eq!(artifacts.coverage().references_selected, 1);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn mapping_receipt_index_rejects_insufficient_shared_memory() -> TestResult {
    let case = case_with_mapping_receipts()?;
    let temporary = tempfile::tempdir()?;
    let mut artifacts = super::super::ArtifactCollection::new(
        temporary.path(),
        super::super::ArtifactLimits::default(),
    )?;
    let budget = MemoryBudget::new(4 * 1024);
    let error = super::super::collect_case_artifacts_with_context(
        &mut artifacts,
        &case,
        Some(&budget),
        |_, _| Ok(context()),
    )
    .err()
    .ok_or("mapping receipt index ignored shared publication memory")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(artifacts.coverage().references_selected, 0);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn mapping_receipt_index_releases_its_charge_after_collection() -> TestResult {
    let case = case_with_mapping_receipts()?;
    let temporary = tempfile::tempdir()?;
    let mut artifacts = super::super::ArtifactCollection::new(
        temporary.path(),
        super::super::ArtifactLimits::default(),
    )?;
    let budget = MemoryBudget::new(2 * 1024 * 1024);
    super::super::collect_case_artifacts_with_context(
        &mut artifacts,
        &case,
        Some(&budget),
        |_, _| Ok(context()),
    )?;
    assert_eq!(artifacts.coverage().references_selected, 0);
    assert!(budget.snapshot()?.peak_bytes >= u64::try_from(SIGNATURES * size_of::<&()>())?);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn signature_candidates_preserve_case_order_for_each_selected_input() -> TestResult {
    let mut case = Case::new();
    let first = case.add_bytes_node("record_object", b"first", Vec::new(), json!({}))?;
    let second = case.add_bytes_node("record_object", b"second", Vec::new(), json!({}))?;
    let first_a = case.add_node(
        "file_signature_match",
        None,
        Vec::new(),
        json!({"input_node": first}),
    )?;
    let second_a = case.add_node(
        "file_signature_match",
        None,
        Vec::new(),
        json!({"input_node": second}),
    )?;
    let first_b = case.add_node(
        "file_signature_match",
        None,
        Vec::new(),
        json!({"input_node": first}),
    )?;
    let temporary = tempfile::tempdir()?;
    let mut artifacts = super::super::ArtifactCollection::new(
        temporary.path(),
        super::super::ArtifactLimits::default(),
    )?;
    super::super::collect_case_artifacts_with_context(&mut artifacts, &case, None, |_, _| {
        let mut source = context();
        source.case_id = Some("retained-case".to_owned());
        Ok(source)
    })?;
    let mut origins = 0;
    artifacts.visit_artifact_origins(|_, _, origin| {
        origins += 1;
        let ids: Vec<_> = origin
            .signature_candidates
            .iter()
            .map(|node| node.id)
            .collect();
        match origin.selected_node_id {
            Some(id) if id == first => assert_eq!(ids, [first_a, first_b]),
            Some(id) if id == second => assert_eq!(ids, [second_a]),
            _ => return Err("unexpected source node".into()),
        }
        Ok(())
    })?;
    assert_eq!(origins, 2);
    Ok(())
}
