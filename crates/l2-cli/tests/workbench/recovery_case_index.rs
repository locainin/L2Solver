use super::*;
use serde_json::json;
use std::error::Error;

#[test]
fn duplicate_index_observations_do_not_increase_retained_admission() -> Result<(), Box<dyn Error>> {
    use l2_workbench::{
        evidence::Edge,
        job::{MemoryBudget, MemoryClass},
    };

    let mut case = Case::new();
    let input = case.add_bytes_node("input", b"input", Vec::new(), json!({}))?;
    let details = json!({"shared_transform_receipt": input, "source_input_node": input});
    let output = case.add_bytes_node("decoding_output", b"decoded", Vec::new(), details.clone())?;
    let add_edge = |case: &mut Case, from, to, relation: &str, reason: &str| {
        case.add_edge(Edge {
            from,
            to,
            relation: relation.to_owned(),
            status: EvidenceStatus::Observed,
            reason: reason.to_owned(),
        })
    };
    add_edge(&mut case, input, output, "produced", "first")?;
    add_edge(&mut case, input, output, "validated_range", "first")?;
    let memory = MemoryBudget::new(1024 * 1024);
    let mut index = CaseIndex::with_memory(CaseIndexScanLedger::new()?, Some(&memory))?;
    index.initialize(&case)?;
    let retained = memory.snapshot()?.used(MemoryClass::Executor);
    assert!(retained > 0);

    let duplicate = case.add_bytes_node("decoding_output", b"decoded", Vec::new(), details)?;
    add_edge(&mut case, input, duplicate, "produced", "second")?;
    add_edge(&mut case, input, output, "validated_range", "second")?;
    let available = memory.snapshot()?.limit_bytes - memory.snapshot()?.used_bytes;
    let held = memory.try_reserve(MemoryClass::Executor, available)?;
    index.refresh(&case)?;
    drop(held);
    assert_eq!(memory.snapshot()?.used(MemoryClass::Executor), retained);
    assert_eq!(index.contextual_decoding_views.len(), 1);
    assert_eq!(index.decoding_outputs.get(&input), Some(&output));
    assert_eq!(
        index.validated_range_inputs(output).map(BTreeSet::len),
        Some(1)
    );

    let another = case.add_bytes_node("input", b"new", Vec::new(), json!({}))?;
    add_edge(&mut case, another, output, "validated_range", "new input")?;
    index.refresh(&case)?;
    assert!(memory.snapshot()?.used(MemoryClass::Executor) > retained);
    assert_eq!(
        index.validated_range_inputs(output).map(BTreeSet::len),
        Some(2)
    );
    Ok(())
}

#[test]
fn source_only_blobs_do_not_consume_discovery_link_index_work() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let mut index = CaseIndex::new(&case)?;
    let before = index.scan_ledger.charged();
    let bytes = b"retained source without an eligible input node";
    let blob = case.add_blob(bytes)?;
    case.add_source(
        "source.bin",
        "external",
        u64::try_from(bytes.len())?,
        &l2_workbench::sha256(bytes),
        Some(&blob),
    )?;
    case.validate()?;
    index.refresh(&case)?;
    assert_eq!(
        index.scan_ledger.charged(),
        before,
        "the Case content index owns blob lookup; no discovery links changed"
    );
    Ok(())
}

#[test]
fn executor_lookups_follow_committed_case_bytes_after_rollback_and_id_reuse()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let input = case.add_bytes_node("input", b"original", Vec::new(), json!({}))?;
    let metadata = case.add_node("metadata", None, Vec::new(), json!({}))?;
    let plan = RecoveryPlan::default();
    let policy = normal_policy(&case)?;
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    assert_eq!(executor.node_kind(input)?, "input");
    assert_eq!(executor.node_bytes(input)?, b"original");
    let original_blob = executor.node_blob_id(input)?.to_owned();
    assert!(matches!(
        executor.node_bytes(metadata),
        Err(RecoveryExecutionError::Coordinator(RecoveryError::InputBlobMissing { node_id }))
            if node_id == metadata
    ));
    let mut aborted_node = None;
    let rollback: Result<(), Box<dyn Error>> = executor.case.transaction(|case| {
        aborted_node = Some(case.add_bytes_node("aborted", b"discarded", Vec::new(), json!({}))?);
        Err("injected evidence rollback".into())
    });
    assert!(rollback.is_err());
    let aborted_node = aborted_node.ok_or("aborted node was not created")?;
    for missing in [0, aborted_node, u64::MAX] {
        assert!(matches!(
            executor.node_kind(missing),
            Err(RecoveryExecutionError::Coordinator(RecoveryError::UnknownEvidenceNode { node_id }))
                if node_id == missing
        ));
    }
    let committed =
        executor
            .case
            .add_bytes_node("committed", b"retained", Vec::new(), json!({}))?;
    assert_eq!(
        committed, aborted_node,
        "rolled-back identifiers must be reusable"
    );
    assert_eq!(executor.node_kind(committed)?, "committed");
    assert_eq!(executor.node_bytes(committed)?, b"retained");
    let alias = executor
        .case
        .add_bytes_node("same_bytes", b"original", Vec::new(), json!({}))?;
    assert_eq!(executor.node_kind(alias)?, "same_bytes");
    assert_eq!(executor.node_blob_id(alias)?, original_blob);
    assert_eq!(executor.node_bytes(alias)?, b"original");
    assert_eq!(executor.node_bytes(input)?, b"original");
    Ok(())
}

#[test]
fn relational_lineage_index_updates_only_for_committed_decoded_frames() -> Result<(), Box<dyn Error>>
{
    let mut case = Case::new();
    case.add_bytes_node(
        "record_candidate",
        b"ordinary",
        Vec::new(),
        json!({"relational_decoded_frame":true}),
    )?;
    let mut index = CaseIndex::new(&case)?;
    assert!(!index.has_relational_frames);

    // A failed evidence transaction must not affect the incremental lineage index
    let rolled_back: Result<(), Box<dyn Error>> = case.transaction(|transaction| {
        transaction.add_bytes_node(
            "relational_decoded_frame",
            b"not committed",
            Vec::new(),
            json!({"relational_decoded_frame":true}),
        )?;
        Err(std::io::Error::other("injected evidence rollback").into())
    });
    assert!(rolled_back.is_err());
    index.refresh(&case)?;
    assert!(!index.has_relational_frames);

    case.add_bytes_node(
        "relational_decoded_frame",
        b"committed",
        Vec::new(),
        json!({"relational_decoded_frame":true}),
    )?;
    index.refresh(&case)?;
    assert!(index.has_relational_frames);
    assert!(CaseIndex::new(&case)?.has_relational_frames);
    Ok(())
}
