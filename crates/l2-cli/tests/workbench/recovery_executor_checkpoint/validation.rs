use super::*;
use serde_json::{Value, json};

#[test]
fn checkpoint_reader_rejects_invalid_cursors_context_ids_and_cumulative_charges()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    case.add_bytes_node("http_body", b"4142", Vec::new(), json!({}))?;
    let plan = RecoveryPlan {
        discover_transforms: true,
        ..RecoveryPlan::default()
    };
    let policy = normal_policy(&case)?;
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    executor.case_index = CaseIndex::with_ledger(CaseIndexScanLedger::new()?);
    let mut cursor = SchedulerCursor::default();
    assert!(step(&mut executor, &mut cursor)?);
    assert!(step(&mut executor, &mut cursor)?);
    assert!(executor.coordinator.peek_next_id().is_some());
    let mut bytes = Vec::new();
    checkpoint::write(&executor, &cursor, &mut bytes, 1024 * 1024)?;
    let valid: Value = serde_json::from_slice(&bytes)?;
    drop(executor);

    for (change, path, replacement) in [
        (
            "seed_position",
            "/cursor/phase/Seeding/next",
            json!(usize::MAX),
        ),
        ("false_finished", "/cursor/phase", json!("Finished")),
        (
            "candidate_snapshot",
            "/state/snapshot_candidates",
            json!(false),
        ),
        (
            "work_charge",
            "/state/record_phase_work_charged",
            json!(usize::MAX),
        ),
        (
            "association_charge",
            "/state/record_schema_associations_charged",
            json!(usize::MAX),
        ),
        (
            "orphan_context",
            "/state/transform_discoveries/0/0",
            json!(usize::MAX),
        ),
    ] {
        let mut invalid = valid.clone();
        *invalid
            .pointer_mut(path)
            .ok_or("checkpoint fixture field is missing")? = replacement;
        let mut restored = case.try_clone()?;
        let bytes = serde_json::to_vec(&invalid)?;
        assert!(
            checkpoint::read(&mut restored, &plan, &policy, &bytes, 1024 * 1024, None).is_err(),
            "invalid checkpoint accepted: {change}"
        );
    }
    Ok(())
}
