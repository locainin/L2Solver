use l2_workbench::{
    evidence::{Case, CaseSnapshotLimits},
    sha256,
};
use serde_json::{Value, json};
use std::error::Error;

#[test]
fn checkpoint_prefix_accepts_new_derivations_after_a_snapshot_restore() -> Result<(), Box<dyn Error>>
{
    let mut case = source_case()?;
    let prefix = case.checkpoint_prefix()?;
    case.add_source("alias.bin", "file", 8, &sha256(b"original"), None)?;
    case.add_bytes_node(
        "derived",
        b"result",
        Vec::new(),
        json!({"operation":"test"}),
    )?;
    case.mark_incomplete("one later search was limited")?;
    let limits = CaseSnapshotLimits::new(1024 * 1024, 1024 * 1024);
    let mut graph = Vec::new();
    let mut blobs = Vec::new();
    case.write_snapshot(&mut graph, &mut blobs, limits)?;
    let (restored, _) = Case::from_snapshot(graph.as_slice(), blobs.as_slice(), limits)?;
    assert!(prefix.matches(&restored)?);
    Ok(())
}

#[test]
fn checkpoint_prefix_rejects_changed_original_details_and_removed_records()
-> Result<(), Box<dyn Error>> {
    let case = source_case()?;
    let prefix = case.checkpoint_prefix()?;
    let mut changed: Value = serde_json::from_slice(&case.to_json()?)?;
    *changed
        .pointer_mut("/nodes/0/details")
        .ok_or("missing original node details")? = json!({"origin":"different"});
    let changed = Case::from_json(&serde_json::to_vec(&changed)?)?;
    assert!(!prefix.matches(&changed)?);
    assert!(!prefix.matches(&Case::new())?);
    Ok(())
}

#[test]
fn checkpoint_prefix_rejects_lost_source_aliases_and_upgraded_completeness()
-> Result<(), Box<dyn Error>> {
    let mut case = source_case()?;
    let original = case.try_clone()?;
    case.add_source("alias.bin", "file", 8, &sha256(b"original"), None)?;
    let prefix = case.checkpoint_prefix()?;
    assert!(!prefix.matches(&original)?);

    case.mark_incomplete("source coverage is incomplete")?;
    let prefix = case.checkpoint_prefix()?;
    let mut changed: Value = serde_json::from_slice(&case.to_json()?)?;
    *changed
        .get_mut("collection_complete")
        .ok_or("missing collection completeness")? = json!(true);
    let changed = Case::from_json(&serde_json::to_vec(&changed)?)?;
    assert!(!prefix.matches(&changed)?);
    Ok(())
}

#[test]
fn checkpoint_prefix_and_alias_matching_share_the_case_memory_budget() -> Result<(), Box<dyn Error>>
{
    use l2_workbench::{
        evidence::EvidenceError,
        job::{MemoryBudget, MemoryClass, MemoryError},
    };

    let budget = MemoryBudget::new(1024 * 1024);
    let mut case = source_case()?;
    case.add_source("alias.bin", "file", 8, &sha256(b"original"), None)?;
    case.admit_memory_budget(&budget)?;
    let base = budget.snapshot()?.used_bytes;
    let prefix = case.checkpoint_prefix()?;
    let retained = budget.snapshot()?.used_bytes;
    assert!(retained > base);
    assert!(prefix.matches(&case)?);
    let remaining = budget.snapshot()?.limit_bytes - budget.snapshot()?.used_bytes;
    let held = budget.try_reserve(MemoryClass::Executor, remaining)?;
    assert!(matches!(
        prefix.matches(&case),
        Err(EvidenceError::Memory(MemoryError::Limit { .. }))
    ));
    drop(held);
    drop(prefix);
    assert_eq!(budget.snapshot()?.used_bytes, base);
    Ok(())
}

fn source_case() -> Result<Case, Box<dyn Error>> {
    let mut case = Case::new();
    let blob = case.add_blob(b"original")?;
    case.add_source("input.bin", "file", 8, &sha256(b"original"), Some(&blob))?;
    case.add_node(
        "original",
        Some(&blob),
        Vec::new(),
        json!({"origin":"test"}),
    )?;
    Ok(case)
}
