use super::execution_state::{SchedulerCursor, step};
use super::{
    CaseIndex, CaseIndexScanLedger, RecoveryPlan, checkpoint, execute, finish_executor,
    normal_policy, record_discovery_tests::build_session_relative_fixture, test_support,
};
use crate::arguments::RecoveryProfile;
use l2_workbench::evidence::{Case, CaseSnapshotLimits};
use std::error::Error;

#[path = "recovery_executor_checkpoint/durable.rs"]
mod durable;
#[path = "recovery_executor_checkpoint/limits.rs"]
mod limits;
#[path = "recovery_executor_checkpoint/memory.rs"]
mod memory;
#[path = "recovery_executor_checkpoint/profile_resume.rs"]
mod profile_resume;

fn without_cache_hits(mut work: serde_json::Value) -> Result<serde_json::Value, Box<dyn Error>> {
    work.pointer_mut("/counts/counters")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("missing work counters")?
        .remove("cache_hits");
    Ok(work)
}
#[cfg(target_os = "linux")]
#[path = "recovery_executor_checkpoint/relational_interrupt.rs"]
mod relational_interrupt;
#[path = "recovery_executor_checkpoint/validation.rs"]
mod validation;

#[test]
fn checkpoint_rejects_an_unused_secret_recipe_before_writing_any_bytes()
-> Result<(), Box<dyn Error>> {
    use l2_workbench::derivation::{Operation, Recipe};
    let mut case = Case::new();
    let plan = RecoveryPlan {
        recipes: vec![Recipe {
            steps: vec![Operation::XorRepeat {
                key: b"test-secret".to_vec(),
                offset: 0,
            }],
            constraints: Vec::new(),
        }],
        ..RecoveryPlan::default()
    };
    let policy = normal_policy(&case)?;
    let executor = test_support::build_executor(&mut case, &plan, &policy)?;
    let mut output = b"existing".to_vec();
    assert!(
        checkpoint::write(
            &executor,
            &SchedulerCursor::default(),
            &mut output,
            1024 * 1024
        )
        .is_err()
    );
    assert_eq!(output, b"existing");
    Ok(())
}

#[test]
fn default_executor_checkpoint_preserves_pending_record_assembly_and_exact_recovery()
-> Result<(), Box<dyn Error>> {
    let fixture = build_session_relative_fixture()?;
    let plan = RecoveryPlan {
        discover_transforms: true,
        discover_framing: true,
        discover_records: true,
        ..RecoveryPlan::default()
    };
    let mut uninterrupted = fixture.case.try_clone()?;
    let expected_policy = super::policy::policy_for_profile(
        &uninterrupted,
        RecoveryProfile::Normal,
        64 * 1024 * 1024,
    )?;
    let expected = execute(&mut uninterrupted, &plan, &expected_policy)?;
    assert!(
        uninterrupted
            .blobs()
            .iter()
            .any(|blob| blob.bytes == fixture.plaintext)
    );
    assert!(expected.validated_artifact_count > 0);

    let mut running = fixture.case;
    let policy =
        super::policy::policy_for_profile(&running, RecoveryProfile::Normal, 64 * 1024 * 1024)?;
    let mut executor = test_support::build_executor(&mut running, &plan, &policy)?;
    executor.case_index = CaseIndex::with_ledger(CaseIndexScanLedger::new()?);
    let mut cursor = SchedulerCursor::default();
    for _ in 0..20_000 {
        assert!(
            step(&mut executor, &mut cursor)?,
            "no pending assembly was reached"
        );
        if executor.pending_record_assembly_count > 0 {
            break;
        }
    }
    assert!(executor.pending_record_assembly_count > 0);
    let charged = executor.coordinator.work_bytes_charged();
    let pending = executor.pending_record_assembly_count;
    let limits = CaseSnapshotLimits::new(64 * 1024 * 1024, 64 * 1024 * 1024);
    let mut graph = Vec::new();
    let mut blobs = Vec::new();
    executor
        .case
        .write_snapshot(&mut graph, &mut blobs, limits)?;
    let mut state = Vec::new();
    checkpoint::write(&executor, &cursor, &mut state, 32 * 1024 * 1024)?;
    drop(executor);
    drop(running);

    let (mut restored_case, _) = Case::from_snapshot(graph.as_slice(), blobs.as_slice(), limits)?;
    let (mut restored, mut restored_cursor) = checkpoint::read(
        &mut restored_case,
        &plan,
        &policy,
        state.as_slice(),
        32 * 1024 * 1024,
        None,
    )?;
    assert_eq!(restored.coordinator.work_bytes_charged(), charged);
    assert_eq!(restored.pending_record_assembly_count, pending);
    while step(&mut restored, &mut restored_cursor)? {}
    let actual = finish_executor(restored)?;

    assert_eq!(restored_case.to_json()?, uninterrupted.to_json()?);
    assert_eq!(actual.candidates, expected.candidates);
    assert_eq!(actual.omissions, expected.omissions);
    assert_eq!(actual.resources, expected.resources);
    assert_eq!(
        actual.validated_artifact_count,
        expected.validated_artifact_count
    );
    Ok(())
}

#[path = "recovery_executor_checkpoint/lease_lifetime.rs"]
mod lease_lifetime;
