use l2_workbench::job::{
    Job, MemoryBudget, MemoryClass, RecoveryFunnelAdmission, RecoveryFunnelIdentity,
    RecoveryFunnelInput, RecoveryFunnelRegistration,
};
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

fn register_one_cohort(job: &Job) -> TestResult {
    let inputs = [RecoveryFunnelInput {
        node_id: 21,
        session_node_id: 31,
    }];
    job.register_recovery_cohort(RecoveryFunnelRegistration {
        identity: RecoveryFunnelIdentity {
            source_sha256: [3; 32],
            cohort_sha256: [4; 32],
        },
        inputs: &inputs,
        total_inputs: inputs.len(),
        admission: RecoveryFunnelAdmission::Unknown,
    })?;
    Ok(())
}

#[test]
fn retained_job_snapshots_keep_funnel_memory_charged_after_the_job_is_dropped() -> TestResult {
    let budget = MemoryBudget::new(64 * 1024 * 1024);
    let job = Job::with_memory_budget("snapshot lifetime", &budget);
    register_one_cohort(&job)?;
    let snapshot = job.snapshot()?;
    let copy = snapshot.clone();

    drop(job);
    assert!(
        budget.snapshot()?.used_bytes > 0,
        "a retained snapshot must keep its funnel allocations charged"
    );
    drop(snapshot);
    assert!(
        budget.snapshot()?.used_bytes > 0,
        "a retained snapshot copy must keep its funnel allocations charged"
    );
    assert!(
        serde_json::to_value(&copy.recovery_transitions)?
            .get("cohorts")
            .is_some(),
        "the retained copy must still contain the cohort"
    );
    drop(copy);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn retained_work_snapshots_keep_funnel_memory_charged_after_the_job_is_dropped() -> TestResult {
    let budget = MemoryBudget::new(64 * 1024 * 1024);
    let job = Job::with_memory_budget("work snapshot lifetime", &budget);
    let worker = job.work_scope(&"1".repeat(64))?;
    register_one_cohort(&worker)?;
    let snapshot = worker.work_snapshot()?;
    let copy = snapshot.clone();

    drop(worker);
    drop(job);
    assert!(
        budget.snapshot()?.used_bytes > 0,
        "a work snapshot must keep its funnel allocations charged"
    );
    drop(snapshot);
    assert!(
        budget.snapshot()?.used_bytes > 0,
        "a work snapshot copy must keep its funnel allocations charged"
    );
    assert!(
        serde_json::to_value(&copy)?
            .pointer("/counts/recovery_transitions/cohorts")
            .is_some(),
        "the work snapshot copy must still contain the cohort"
    );
    drop(copy);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn snapshot_under_memory_pressure_keeps_a_charged_cohort_or_reports_its_omission() -> TestResult {
    let budget = MemoryBudget::new(64 * 1024 * 1024);
    let job = Job::with_memory_budget("snapshot pressure", &budget);
    register_one_cohort(&job)?;
    let before = budget.snapshot()?;
    let blocker = budget.try_reserve(
        MemoryClass::Executor,
        before.limit_bytes - before.used_bytes,
    )?;
    let snapshot = job.snapshot()?;
    drop(job);
    drop(blocker);

    let wire = serde_json::to_value(&snapshot.recovery_transitions)?;
    if wire.get("cohorts").is_some() {
        assert!(
            budget.snapshot()?.used_bytes > 0,
            "retained cohort data must stay charged even after its Job is dropped"
        );
    } else {
        assert!(
            wire.pointer("/funnel_omission_reasons/memory_admission")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|count| count > 0),
            "a snapshot denied diagnostic memory must say what was omitted"
        );
    }
    drop(snapshot);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn cloning_an_existing_snapshot_under_pressure_keeps_the_same_diagnostics() -> TestResult {
    let budget = MemoryBudget::new(64 * 1024 * 1024);
    let job = Job::with_memory_budget("snapshot clone under pressure", &budget);
    register_one_cohort(&job)?;
    let original = job.snapshot()?;
    let before = budget.snapshot()?;
    let blocker = budget.try_reserve(
        MemoryClass::Executor,
        before.limit_bytes - before.used_bytes,
    )?;
    let copied = original.clone();
    assert_eq!(
        copied.recovery_transitions, original.recovery_transitions,
        "Clone must preserve already admitted diagnostic observations"
    );
    drop(original);
    drop(job);
    drop(blocker);
    assert!(
        budget.snapshot()?.used_bytes > 0,
        "the unchanged snapshot copy must retain its own charged or shared storage"
    );
    drop(copied);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn earlier_snapshot_is_unchanged_when_a_cohort_receives_another_session() -> TestResult {
    let budget = MemoryBudget::new(64 * 1024 * 1024);
    let job = Job::with_memory_budget("immutable snapshot", &budget);
    register_one_cohort(&job)?;
    let first = job.snapshot()?;
    let later_input = [RecoveryFunnelInput {
        node_id: 22,
        session_node_id: 32,
    }];
    job.register_recovery_cohort(RecoveryFunnelRegistration {
        identity: RecoveryFunnelIdentity {
            source_sha256: [3; 32],
            cohort_sha256: [4; 32],
        },
        inputs: &later_input,
        total_inputs: 1,
        admission: RecoveryFunnelAdmission::Unknown,
    })?;
    let later = job.snapshot()?;
    let earlier = serde_json::to_value(&first.recovery_transitions)?;
    let later = serde_json::to_value(&later.recovery_transitions)?;
    assert_eq!(
        earlier.pointer("/cohorts/0/sessions"),
        Some(&serde_json::json!([31]))
    );
    assert_eq!(
        later.pointer("/cohorts/0/sessions"),
        Some(&serde_json::json!([31, 32]))
    );
    Ok(())
}
