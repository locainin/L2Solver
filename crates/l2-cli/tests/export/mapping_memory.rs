use std::error::Error;

use l2_workbench::{
    evidence::{ByteMapping, Case, Edge, EvidenceStatus, SourceRange},
    job::{MemoryBudget, MemoryClass, MemoryError},
};
use serde_json::json;

use super::ArtifactSourceContext;

const CHILDREN: usize = 512;
type TestResult = Result<(), Box<dyn Error>>;

fn mapped_der_case() -> Result<Case, Box<dyn Error>> {
    let mut bytes = vec![0x30, 0x82, 0x04, 0x00];
    for _ in 0..CHILDREN {
        bytes.extend_from_slice(&[0x05, 0x00]);
    }
    let mut case = Case::new();
    let source = case.add_source("mapped.pcap", "capture", 4_096, &"f".repeat(64), None)?;
    let mappings = (0..bytes.len())
        .step_by(2)
        .map(|offset| {
            Ok(ByteMapping {
                offset,
                range: SourceRange {
                    source: source.clone(),
                    packet: Some(7),
                    offset: u64::try_from(offset)?,
                    length: 2,
                },
            })
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let input = case.add_mapped_bytes_node("candidate_object", &bytes, &mappings, json!({}))?;
    let blob = case
        .node(input)
        .and_then(|node| node.blob.clone())
        .ok_or("mapped input blob is missing")?;
    let structure = case.add_node(
        "der_structure",
        Some(&blob),
        Vec::new(),
        json!({
            "input_node": input,
            "depth": 1,
            "value_count": CHILDREN + 1,
            "boundary_range": {"offset": 0, "length": bytes.len()},
            "object_range": {"offset": 0, "length": bytes.len()},
        }),
    )?;
    case.add_edge(Edge {
        from: input,
        to: structure,
        relation: "parsed_as".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "The DER structure was parsed".to_owned(),
    })?;
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

#[test]
fn mapping_receipt_rejects_a_budget_too_small_for_its_decoded_ranges() -> TestResult {
    let case = mapped_der_case()?;
    let temporary = tempfile::tempdir()?;
    let mut artifacts = super::super::ArtifactCollection::new(
        temporary.path(),
        super::super::ArtifactLimits::default(),
    )?;
    let budget = MemoryBudget::new(512 * 1024);
    let error = super::super::collect_case_artifacts_with_context(
        &mut artifacts,
        &case,
        Some(&budget),
        |_, _| Ok(context()),
    )
    .err()
    .ok_or("mapping receipt ignored shared publication memory")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(artifacts.coverage().references_selected, 0);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn mapping_receipt_keeps_exact_ranges_and_releases_its_charge() -> TestResult {
    let case = mapped_der_case()?;
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
        |_, _| Ok(context()),
    )?;
    let mut found = false;
    artifacts.visit_artifact_origins(|_, _, origin| {
        found = true;
        assert_eq!(origin.source_ranges.len(), (CHILDREN * 2 + 4) / 2);
        assert_eq!(
            origin.source_ranges.first().map(|range| range.offset),
            Some(0)
        );
        assert_eq!(
            origin.source_ranges.last().map(|range| range.offset),
            Some(1026)
        );
        Ok(())
    })?;
    assert!(found);
    assert!(budget.snapshot()?.peak_bytes > 512 * 1024);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn selected_source_ranges_remain_charged_until_the_ranges_drop() -> TestResult {
    let case = mapped_der_case()?;
    let selected = crate::workbench::artifact_export::select_artifacts(&case, None)?;
    let origin = selected
        .first()
        .and_then(|artifact| artifact.provenance().first())
        .ok_or("selected source provenance is missing")?;
    let index = super::CaseArtifactIndex::new(&case)?;
    let budget = MemoryBudget::new(8 * 1024 * 1024);
    let ranges = super::selected_artifact_source_ranges(origin, &index, Some(&budget))?;
    assert_eq!(ranges.ranges.len(), (CHILDREN * 2 + 4) / 2);
    assert!(budget.snapshot()?.used(MemoryClass::Publication) > 0);
    drop(ranges);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn direct_source_ranges_respect_pressure_and_release_their_charge() -> TestResult {
    let mut case = Case::new();
    let source = case.add_source("mapped.pcap", "capture", 128, &"f".repeat(64), None)?;
    let bytes = b"complete object";
    let input = case.add_mapped_bytes_node(
        "mapped_input",
        bytes,
        &[ByteMapping {
            offset: 0,
            range: SourceRange {
                source,
                packet: Some(7),
                offset: 3,
                length: u64::try_from(bytes.len())?,
            },
        }],
        json!({}),
    )?;
    let selected = super::selected_origin(&mut case, input, bytes, 0, bytes.len())?;
    let index = super::CaseArtifactIndex::new(&case)?;
    let budget = MemoryBudget::new(64 * 1024);
    let blocker = budget.try_reserve(MemoryClass::Cache, budget.snapshot()?.limit_bytes)?;
    let error = super::selected_artifact_source_ranges(&selected, &index, Some(&budget))
        .err()
        .ok_or("direct source ranges ignored shared publication memory")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::Limit { .. })
    ));
    drop(blocker);
    assert_eq!(budget.snapshot()?.used_bytes, 0);

    let ranges = super::selected_artifact_source_ranges(&selected, &index, Some(&budget))?;
    assert_eq!(ranges.ranges.len(), 1);
    assert_eq!(ranges.ranges.first().map(|range| range.offset), Some(3));
    assert!(budget.snapshot()?.used(MemoryClass::Publication) > 0);
    drop(ranges);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}
