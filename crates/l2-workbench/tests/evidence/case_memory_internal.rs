use super::{Case, CaseMemory, graph_bytes, value_bytes};
use crate::{
    evidence::{CaseSnapshotLimits, Edge, EvidenceError, EvidenceStatus, SourceRange},
    job::MemoryBudget,
    sha256,
};
use serde_json::json;

#[test]
fn json_object_charge_covers_a_btree_node_for_each_nested_object() -> Result<(), EvidenceError> {
    let empty = json!({});
    let nested = json!({"outer":{"inner":1}});
    let node_floor =
        11 * std::mem::size_of::<(String, serde_json::Value)>() + 2 * std::mem::size_of::<usize>();

    // An empty map can keep its root after the last field is removed
    assert!(value_bytes(&empty)? >= node_floor);
    assert!(value_bytes(&nested)? >= 2 * node_floor + "outer".len() + "inner".len());
    Ok(())
}

fn assert_charges_match_case(case: &Case) -> Result<(), EvidenceError> {
    let memory: &CaseMemory = case.memory.as_ref().ok_or(EvidenceError::InvalidJson)?;
    assert_eq!(
        memory.graph_bytes(),
        u64::try_from(graph_bytes(case)?).map_err(|_| EvidenceError::InvalidJson)?
    );
    let blobs = case.blobs().iter().try_fold(0_u64, |total, blob| {
        let capacity =
            u64::try_from(blob.bytes.capacity()).map_err(|_| EvidenceError::InvalidJson)?;
        total
            .checked_add(capacity)
            .ok_or(EvidenceError::InvalidJson)
    })?;
    assert_eq!(memory.blobs.bytes(), blobs);
    Ok(())
}

#[test]
fn retained_case_charges_match_graph_after_mutation_clone_and_rollback() -> Result<(), EvidenceError>
{
    let budget = MemoryBudget::new(1_000_000);
    let mut case = Case::with_memory_budget(&budget)?;
    assert_charges_match_case(&case)?;
    let source = case.add_source("source.bin", "file", 7, &sha256(b"payload"), None)?;
    assert_charges_match_case(&case)?;
    let first = case.add_bytes_node("first", b"body", Vec::new(), json!({"values":[1, 2]}))?;
    let second = case.add_node(
        "second",
        None,
        vec![SourceRange {
            source: source.clone(),
            packet: None,
            offset: 1,
            length: 3,
        }],
        json!({"label":"value"}),
    )?;
    case.add_edge(Edge {
        from: first,
        to: second,
        relation: "supports".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "Observed together".to_owned(),
    })?;
    case.add_limitation("An explicit limit")?;
    assert_charges_match_case(&case)?;
    let copied = case.try_clone()?;
    assert_charges_match_case(&copied)?;
    drop(copied);
    let aborted = case.transaction(|case| {
        case.add_source("other.bin", "file", 7, &sha256(b"payload"), None)?;
        case.add_bytes_node("temporary", b"temp", Vec::new(), json!({}))?;
        assert_charges_match_case(case)?;
        Err::<(), _>(EvidenceError::InvalidSourceRange)
    });
    assert_eq!(aborted, Err(EvidenceError::InvalidSourceRange));
    assert_charges_match_case(&case)?;
    let nested = case.transaction(|case| {
        case.add_source("outer.bin", "file", 7, &sha256(b"payload"), None)?;
        case.transaction(|case| {
            case.add_source("inner.bin", "file", 7, &sha256(b"payload"), None)?;
            assert_charges_match_case(case)?;
            Ok::<(), EvidenceError>(())
        })?;
        assert_charges_match_case(case)?;
        Err::<(), _>(EvidenceError::InvalidSourceRange)
    });
    assert_eq!(nested, Err(EvidenceError::InvalidSourceRange));
    assert_charges_match_case(&case)?;
    let rebind = case.transaction(|case| {
        case.rebind_source_label(&source, "temporary.bin")?;
        Err::<(), _>(EvidenceError::InvalidSourceRange)
    });
    assert_eq!(rebind, Err(EvidenceError::InvalidSourceRange));
    assert_eq!(
        case.sources().first().map(|entry| entry.label.as_str()),
        Some("source.bin")
    );
    assert_charges_match_case(&case)?;
    case.rebind_source_label(&source, "current.bin")?;
    assert_charges_match_case(&case)?;
    let limits = CaseSnapshotLimits::new(1_000_000, 1_000_000);
    let mut graph = Vec::new();
    let mut pack = Vec::new();
    case.write_snapshot(&mut graph, &mut pack, limits)?;
    let (restored, _) =
        Case::from_snapshot_with_memory(graph.as_slice(), pack.as_slice(), limits, &budget)?;
    assert_eq!(restored, case);
    assert_charges_match_case(&restored)?;
    Ok(())
}
