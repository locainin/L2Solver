use std::error::Error;

use l2_workbench::{
    evidence::{Case, Node},
    job::{MemoryBudget, MemoryError},
};
use serde_json::json;

use super::super::provenance::ArtifactPublication;

type TestResult = Result<(), Box<dyn Error>>;
const RANGES: usize = 512;
const SIGNATURES: usize = 128;

fn context() -> super::ArtifactSourceContext {
    super::ArtifactSourceContext {
        flow: None,
        supporting_flows: Vec::new(),
        cohort_scope: None,
        case_id: Some("retained-case".to_owned()),
        case_scope: json!({"kind": "flow"}),
    }
}

fn case_with_many_ranges() -> Result<(Case, u64), Box<dyn Error>> {
    let mut case = Case::new();
    super::add_source(&mut case)?;
    let ranges = (0..RANGES)
        .map(|index| {
            Ok(super::source_range(
                u64::try_from(index + 1)?,
                u64::try_from(index)?,
                1,
            ))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let node = case.add_bytes_node("ftp_data_candidate", b"payload", ranges, json!({}))?;
    Ok((case, node))
}

fn case_with_signatures() -> Result<(Case, u64), Box<dyn Error>> {
    let mut case = Case::new();
    let input = case.add_bytes_node("ftp_data_candidate", b"payload", Vec::new(), json!({}))?;
    for _ in 0..SIGNATURES {
        case.add_node(
            "file_signature_match",
            None,
            Vec::new(),
            json!({"input_node": input, "label": "x".repeat(512)}),
        )?;
    }
    Ok((case, input))
}

fn signature_nodes(case: &Case) -> impl Iterator<Item = &Node> {
    case.nodes()
        .iter()
        .filter(|node| node.kind == "file_signature_match")
}

#[test]
fn retained_node_copy_rejects_insufficient_publication_memory() -> TestResult {
    let (case, node_id) = case_with_many_ranges()?;
    let node = case.node(node_id).ok_or("node is missing")?;
    let budget = MemoryBudget::new(4 * 1024);
    let error = super::artifact_provenance(
        "native_ftp_candidate",
        &context(),
        Some(node),
        None,
        None,
        std::iter::empty(),
        ArtifactPublication {
            case: &case,
            memory: Some(&budget),
        },
    )
    .err()
    .ok_or("retained Node copy ignored shared publication memory")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn retained_node_charge_lives_until_published_provenance_drops() -> TestResult {
    let (case, node_id) = case_with_many_ranges()?;
    let node = case.node(node_id).ok_or("node is missing")?;
    let budget = MemoryBudget::new(8 * 1024 * 1024);
    let origin = super::artifact_provenance(
        "native_ftp_candidate",
        &context(),
        Some(node),
        None,
        None,
        std::iter::empty(),
        ArtifactPublication {
            case: &case,
            memory: Some(&budget),
        },
    )?;
    assert!(budget.snapshot()?.used_bytes >= u64::try_from(RANGES * 64)?);
    let temporary = tempfile::tempdir()?;
    let mut artifacts = super::super::ArtifactCollection::new(
        temporary.path(),
        super::super::ArtifactLimits::default(),
    )?;
    artifacts.add_bytes(b"payload", "payload.bin", &origin, Some(&budget))?;
    let mut found = false;
    artifacts.visit_artifact_origins(|_, _, persisted| {
        found = true;
        assert_eq!(persisted.node.as_ref(), Some(node));
        Ok(())
    })?;
    assert!(found);
    assert!(budget.snapshot()?.used_bytes > 0);
    drop(origin);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn signature_node_copies_reject_insufficient_publication_memory() -> TestResult {
    let (case, node_id) = case_with_signatures()?;
    let node = case.node(node_id).ok_or("node is missing")?;
    let budget = MemoryBudget::new(8 * 1024);
    let error = super::artifact_provenance(
        "native_ftp_candidate",
        &context(),
        Some(node),
        None,
        None,
        signature_nodes(&case),
        ArtifactPublication {
            case: &case,
            memory: Some(&budget),
        },
    )
    .err()
    .ok_or("signature Node copies ignored shared publication memory")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn retained_signature_copies_keep_their_evidence_and_release_their_charge() -> TestResult {
    let (case, node_id) = case_with_signatures()?;
    let node = case.node(node_id).ok_or("node is missing")?;
    let budget = MemoryBudget::new(8 * 1024 * 1024);
    let origin = super::artifact_provenance(
        "native_ftp_candidate",
        &context(),
        Some(node),
        None,
        None,
        signature_nodes(&case),
        ArtifactPublication {
            case: &case,
            memory: Some(&budget),
        },
    )?;
    assert_eq!(origin.signature_candidates.len(), SIGNATURES);
    assert!(
        origin
            .signature_candidates
            .iter()
            .eq(signature_nodes(&case))
    );
    assert!(budget.snapshot()?.used_bytes >= u64::try_from(SIGNATURES * 512)?);
    drop(origin);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}
