use l2_workbench::job::{
    CgroupMemoryEvents, CgroupMemorySnapshot, Job, JobSnapshot, MemoryBudget, MemoryClass,
    MemoryError, SystemMemorySnapshot,
};
use std::{
    error::Error,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

const fn observation(cgroup: Option<CgroupMemorySnapshot>) -> SystemMemorySnapshot {
    SystemMemorySnapshot {
        process_rss_bytes: 700,
        process_peak_rss_bytes: 800,
        cgroup,
    }
}

fn cgroup_observation() -> CgroupMemorySnapshot {
    CgroupMemorySnapshot {
        current_bytes: 700,
        peak_bytes: None,
        anonymous_bytes: None,
        file_bytes: None,
        kernel_bytes: None,
        shared_bytes: None,
        dirty_file_bytes: None,
        writeback_file_bytes: None,
        inactive_file_bytes: None,
        effective_max_bytes: Some(1000),
        effective_high_bytes: None,
        max_headroom_bytes: Some(300),
        high_headroom_bytes: None,
        events: CgroupMemoryEvents::default(),
    }
}

#[test]
fn overlapping_root_and_worker_observers_do_not_reorder_success_and_failure()
-> Result<(), Box<dyn Error>> {
    let budget = MemoryBudget::new(1000);
    let worker = budget.try_working_set(100)?;
    let worker_budget = worker.budget().clone();
    let (entered, entered_rx) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let earlier = budget.clone();
    let first = thread::spawn(move || {
        earlier.try_observe_system_memory_with(|| {
            if entered.send(()).is_err() || release_rx.recv_timeout(Duration::from_secs(3)).is_err()
            {
                return Err(io::Error::other("test observer did not receive release"));
            }
            Ok(observation(None))
        })
    });
    entered_rx.recv_timeout(Duration::from_secs(2))?;

    // A competing provider must not run or block the collector while the first read is active
    let invoked = Arc::new(AtomicBool::new(false));
    let called = Arc::clone(&invoked);
    let later = worker_budget.try_observe_system_memory_with(|| {
        called.store(true, Ordering::SeqCst);
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    });
    release.send(())?;
    first.join().map_err(|_| "observation thread panicked")??;
    assert_eq!(later, Err(MemoryError::SystemObservationBusy));
    assert!(!invoked.load(Ordering::SeqCst));

    // Retrying the newer failure clears the old success after the lock is released
    worker_budget
        .try_observe_system_memory_with(|| Err(io::Error::from(io::ErrorKind::PermissionDenied)))?;
    let snapshot = budget.snapshot()?;
    assert!(snapshot.system.is_none());
    assert_eq!(snapshot.system_observation_failures, 1);
    assert_eq!(
        snapshot.system_observation_error,
        Some(MemoryError::SystemObservationUnavailable {
            kind: io::ErrorKind::PermissionDenied,
            raw_os_error: None,
        })
    );
    Ok(())
}

#[test]
fn sample_age_includes_time_spent_reading_the_provider() -> Result<(), Box<dyn Error>> {
    let budget = MemoryBudget::new(1000);
    budget.try_observe_system_memory_with(|| {
        thread::sleep(Duration::from_millis(40));
        Ok(observation(None))
    })?;
    assert!(
        budget
            .snapshot()?
            .system_sample_age_ms
            .is_some_and(|age| age >= 40)
    );
    Ok(())
}

#[test]
fn a_previously_observed_cgroup_cannot_silently_disappear() -> Result<(), Box<dyn Error>> {
    let budget = MemoryBudget::new(1000);
    budget.observe_system_memory(Some(observation(Some(cgroup_observation()))))?;
    budget
        .try_observe_system_memory_with(|| Err(io::Error::from(io::ErrorKind::PermissionDenied)))?;
    assert!(budget.snapshot()?.system.is_none());
    budget.observe_system_memory(Some(observation(None)))?;
    let first = budget.snapshot()?;
    assert!(first.system.is_none());
    assert_eq!(first.system_observation_failures, 2);
    assert_eq!(
        first.system_observation_error,
        Some(MemoryError::SystemCgroupUnavailable)
    );
    budget.observe_system_memory(Some(observation(None)))?;
    let second = budget.snapshot()?;
    assert!(second.system.is_none());
    assert_eq!(second.system_observation_failures, 3);
    assert_eq!(
        second.system_observation_error,
        Some(MemoryError::SystemCgroupUnavailable)
    );
    budget.observe_system_memory(Some(observation(Some(cgroup_observation()))))?;
    assert!(
        budget
            .snapshot()?
            .system
            .and_then(|sample| sample.cgroup)
            .is_some()
    );
    Ok(())
}

#[test]
fn kernel_observations_do_not_replace_charges_and_failed_samples_clear_stale_data()
-> Result<(), Box<dyn Error>> {
    let budget = MemoryBudget::new(1000);
    let _lease = budget.try_reserve(MemoryClass::Case, 200)?;
    let observed = SystemMemorySnapshot {
        process_rss_bytes: 700,
        process_peak_rss_bytes: 800,
        cgroup: None,
    };
    budget.observe_system_memory(Some(observed))?;
    let snapshot = budget.snapshot()?;
    assert_eq!(snapshot.system, Some(observed));
    assert_eq!(snapshot.used_bytes, 200);
    assert!(snapshot.system_sample_age_ms.is_some());
    budget.observe_system_memory(None)?;
    let snapshot = budget.snapshot()?;
    assert_eq!(snapshot.system, None);
    assert_eq!(snapshot.system_sample_age_ms, None);
    assert_eq!(snapshot.system_observation_failures, 1);
    assert_eq!(snapshot.used_bytes, 200);
    Ok(())
}

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
