use std::error::Error;

use l2_workbench::{
    artifact::DerNode,
    evidence::{Case, Edge, EvidenceStatus},
    job::{MemoryBudget, MemoryClass, MemoryError},
};
use serde_json::json;

const CHILDREN: usize = 512;
type TestResult = Result<(), Box<dyn Error>>;

fn der_case() -> Result<Case, Box<dyn Error>> {
    // The sequence contains 512 canonical NULL values
    let mut bytes = vec![0x30, 0x82, 0x04, 0x00];
    for _ in 0..CHILDREN {
        bytes.extend_from_slice(&[0x05, 0x00]);
    }
    let mut case = Case::new();
    let input = case.add_bytes_node("candidate_object", &bytes, Vec::new(), json!({}))?;
    let blob = case
        .node(input)
        .and_then(|node| node.blob.clone())
        .ok_or("DER blob is missing")?;
    let structure = case.add_node(
        "der_structure",
        Some(&blob),
        Vec::new(),
        json!({
            "input_node": input,
            "depth": 1,
            "value_count": CHILDREN + 1,
            "boundary_range": {"offset": 0, "length": bytes.len()}
        }),
    )?;
    case.add_edge(Edge {
        from: input,
        to: structure,
        relation: "parsed_as".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "DER structure was parsed".to_owned(),
    })?;
    Ok(case)
}

#[test]
fn der_inventory_rejects_a_budget_too_small_for_its_nodes() -> TestResult {
    let case = der_case()?;
    let budget = MemoryBudget::new(4 * 1024);
    let error = super::super::select_artifacts(&case, Some(&budget))
        .err()
        .ok_or("DER inventory ignored shared memory")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn der_inventory_charge_ends_with_the_cached_report() -> TestResult {
    let case = der_case()?;
    let budget = MemoryBudget::new(1024 * 1024);
    let selected = super::super::select_artifacts(&case, Some(&budget))?;
    assert_eq!(selected.len(), 1);
    let inventory_bytes = (CHILDREN + 1) * std::mem::size_of::<DerNode>();
    assert!(budget.snapshot()?.peak_bytes >= u64::try_from(inventory_bytes)?);
    assert!(budget.snapshot()?.used(MemoryClass::Publication) < u64::try_from(inventory_bytes)?);
    drop(selected);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}
