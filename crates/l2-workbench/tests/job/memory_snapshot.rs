use l2_workbench::job::{Job, JobSnapshot, MemoryBudget, MemoryClass};
use std::error::Error;

#[test]
fn job_snapshots_observe_shared_live_charges_and_releases() -> Result<(), Box<dyn Error>> {
    let budget = MemoryBudget::new(1000);
    let job = Job::with_memory_budget("memory observation", &budget);
    let worker = job.clone();
    let mut lease = worker
        .memory_budget()
        .ok_or("job memory budget was lost")?
        .try_reserve(MemoryClass::Case, 400)?;
    let snapshot = job.snapshot()?;
    let memory = snapshot
        .memory_admission
        .ok_or("live memory was not observed")?;
    assert_eq!(memory.limit_bytes, 1000);
    assert_eq!(memory.used_bytes, 400);
    assert_eq!(memory.used(MemoryClass::Case), 400);
    assert_eq!(memory.peak_bytes, 400);
    assert_eq!(memory.used(MemoryClass::Executor), 0);
    assert!(lease.try_resize(1001).is_err());
    drop(lease);
    let value = serde_json::to_value(worker.snapshot()?)?;
    let observed = value.get("memory_admission").ok_or("memory JSON missing")?;
    for (field, expected) in [("used_bytes", 0), ("peak_bytes", 400), ("rejected", 1)] {
        assert_eq!(
            observed.get(field).and_then(serde_json::Value::as_u64),
            Some(expected)
        );
    }
    Ok(())
}

#[test]
fn restoring_progress_never_replays_old_memory_as_current_allocations() -> Result<(), Box<dyn Error>>
{
    let old_budget = MemoryBudget::new(1000);
    let old_job = Job::with_memory_budget("old invocation", &old_budget);
    let _old_lease = old_budget.try_reserve(MemoryClass::Case, 700)?;
    let saved = old_job.checkpoint_snapshot()?;
    assert_eq!(
        saved
            .memory_admission
            .ok_or("old memory missing")?
            .used_bytes,
        700
    );

    // A serialized allocation observation is diagnostic history, not restorable admission state
    let decoded: JobSnapshot = serde_json::from_slice(&serde_json::to_vec(&saved)?)?;
    assert!(decoded.memory_admission.is_none());
    let budget = MemoryBudget::new(2000);
    let resumed = Job::with_memory_budget("new invocation", &budget);
    let _lease = budget.try_reserve(MemoryClass::Cache, 40)?;
    let preview = resumed.preview_checkpoint(Some(&saved))?;
    assert_eq!(
        preview
            .memory_admission
            .ok_or("preview memory missing")?
            .used_bytes,
        40
    );
    resumed.restore(saved)?;
    let snapshot = resumed.checkpoint_snapshot()?;
    let memory = snapshot.memory_admission.ok_or("restored memory missing")?;
    assert_eq!(memory.used_bytes, 40);
    assert_eq!(memory.peak_bytes, 40);
    assert_eq!(memory.used(MemoryClass::Cache), 40);
    assert_eq!(memory.used(MemoryClass::Case), 0);

    let detached = Job::new("no memory monitor");
    detached.restore(old_job.snapshot()?)?;
    assert!(detached.snapshot()?.memory_admission.is_none());
    assert!(
        detached
            .preview_checkpoint(None)?
            .memory_admission
            .is_none()
    );
    Ok(())
}
