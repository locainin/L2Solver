use super::*;
use l2_workbench::job::{
    CgroupMemoryEvents, CgroupMemorySnapshot, Job, JobError, MemoryBudget, SystemMemorySnapshot,
};

type TestResult = Result<(), Box<dyn Error>>;
const MIB: u64 = 1024 * 1024;

fn observed_budget(
    rss: u64,
    cgroup: Option<CgroupMemorySnapshot>,
) -> Result<MemoryBudget, MemoryError> {
    let memory = MemoryBudget::new(512 * MIB);
    memory.observe_system_memory(Some(SystemMemorySnapshot {
        process_rss_bytes: rss,
        process_peak_rss_bytes: rss,
        cgroup,
    }))?;
    Ok(memory)
}

fn cgroup_with_headroom(maximum: u64, high: Option<u64>) -> CgroupMemorySnapshot {
    CgroupMemorySnapshot {
        current_bytes: 400 * MIB,
        peak_bytes: None,
        anonymous_bytes: Some(100 * MIB),
        file_bytes: Some(290 * MIB),
        kernel_bytes: Some(10 * MIB),
        shared_bytes: Some(0),
        dirty_file_bytes: Some(0),
        writeback_file_bytes: Some(0),
        inactive_file_bytes: Some(280 * MIB),
        effective_max_bytes: Some(512 * MIB),
        effective_high_bytes: high.map(|_| 480 * MIB),
        max_headroom_bytes: Some(maximum),
        high_headroom_bytes: high,
        events: CgroupMemoryEvents::default(),
    }
}

#[test]
fn resident_memory_can_block_admission_even_when_logical_charges_are_small() -> TestResult {
    let memory = observed_budget(460 * MIB, None)?;
    let snapshot = memory.snapshot()?;
    assert_eq!(snapshot.used_bytes, 0);
    assert!(matches!(
        check_pressure(&snapshot, 32 * MIB),
        Err(MemoryError::Pressure { .. })
    ));
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn inherited_cgroup_headroom_is_used_without_treating_inactive_file_pages_as_free() -> TestResult {
    let memory = observed_budget(100 * MIB, Some(cgroup_with_headroom(24 * MIB, None)))?;
    assert!(matches!(
        check_pressure(&memory.snapshot()?, 32 * MIB),
        Err(MemoryError::Pressure { .. })
    ));
    Ok(())
}

#[test]
fn cgroup_high_pressure_prevents_starting_an_additional_case() -> TestResult {
    let memory = observed_budget(
        100 * MIB,
        Some(cgroup_with_headroom(200 * MIB, Some(16 * MIB))),
    )?;
    assert!(matches!(
        check_pressure(&memory.snapshot()?, 32 * MIB),
        Err(MemoryError::Pressure { .. })
    ));
    Ok(())
}

#[test]
fn future_growth_of_active_cases_is_included_in_pressure_admission() -> TestResult {
    let memory = observed_budget(200 * MIB, None)?;
    check_pressure(&memory.snapshot()?, 100 * MIB)?;
    let active = memory.try_working_set(200 * MIB)?;
    assert!(matches!(
        check_pressure(&memory.snapshot()?, 100 * MIB),
        Err(MemoryError::Pressure { .. })
    ));
    drop(active);
    check_pressure(&memory.snapshot()?, 100 * MIB)?;
    Ok(())
}

#[test]
fn unavailable_or_stale_os_observations_do_not_become_current_memory_claims() -> TestResult {
    let memory = MemoryBudget::new(512 * MIB);
    check_pressure(&memory.snapshot()?, 32 * MIB)?;
    memory.observe_system_memory(None)?;
    check_pressure(&memory.snapshot()?, 32 * MIB)?;
    assert_eq!(memory.snapshot()?.system_observation_failures, 1);
    let memory = observed_budget(500 * MIB, None)?;
    let mut old = memory.snapshot()?;
    old.system_sample_age_ms = Some(10_000);
    check_pressure(&old, 32 * MIB)?;
    Ok(())
}

#[test]
fn historical_cgroup_events_do_not_deny_a_case_when_current_capacity_is_available() -> TestResult {
    let mut cgroup = cgroup_with_headroom(300 * MIB, None);
    cgroup.events.oom = 2;
    cgroup.events.oom_kill = 1;
    let memory = observed_budget(100 * MIB, Some(cgroup))?;
    check_pressure(&memory.snapshot()?, 32 * MIB)?;
    Ok(())
}

#[test]
fn quiescent_admission_rechecks_pressure_before_rejecting_released_worker_storage() -> TestResult {
    let pressured = observed_budget(460 * MIB, None)?.snapshot()?;
    let available = observed_budget(100 * MIB, None)?.snapshot()?;
    let mut observations = 0;
    check_admission_pressure(0, 32 * MIB, None, || {
        observations += 1;
        Ok(if observations == 1 {
            pressured
        } else {
            available
        })
    })?;
    assert_eq!(observations, 2);
    Ok(())
}

#[test]
fn persistent_quiescent_pressure_returns_a_typed_failure_after_bounded_rechecks() -> TestResult {
    let pressured = observed_budget(460 * MIB, None)?.snapshot()?;
    let mut observations = 0;
    let result = check_admission_pressure(0, 32 * MIB, None, || {
        observations += 1;
        Ok(pressured)
    });
    let error = result.err().ok_or("persistent pressure was ignored")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::Pressure { .. })
    ));
    assert_eq!(observations, 3);
    Ok(())
}

#[test]
fn active_workers_return_pressure_immediately_so_the_collector_can_release_results() -> TestResult {
    let pressured = observed_budget(460 * MIB, None)?.snapshot()?;
    let mut observations = 0;
    let result = check_admission_pressure(2, 32 * MIB, None, || {
        observations += 1;
        Ok(pressured)
    });
    let error = result.err().ok_or("pressure must defer another worker")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::Pressure { .. })
    ));
    assert_eq!(observations, 1);
    Ok(())
}

#[test]
fn cancelled_admission_does_not_start_an_observation_or_wait_for_pressure() -> TestResult {
    let pressured = observed_budget(460 * MIB, None)?.snapshot()?;
    let job = Job::new("cancelled admission");
    job.request_cancel();
    let mut observations = 0;
    let result = check_admission_pressure(0, 32 * MIB, Some(&job), || {
        observations += 1;
        Ok(pressured)
    });
    let error = result.err().ok_or("cancelled admission was allowed")?;
    assert!(matches!(
        error.downcast_ref::<JobError>(),
        Some(JobError::Cancelled)
    ));
    assert_eq!(observations, 0);
    Ok(())
}

#[test]
fn cancellation_during_an_observation_stops_further_pressure_rechecks() -> TestResult {
    let pressured = observed_budget(460 * MIB, None)?.snapshot()?;
    let job = Job::new("admission cancelled during observation");
    job.start(Phase::FramingRecordDiscovery, None)?;
    let mut observations = 0;
    let result = check_admission_pressure(0, 32 * MIB, Some(&job), || {
        observations += 1;
        job.request_cancel();
        Ok(pressured)
    });
    let error = result
        .err()
        .ok_or("cancelled pressure recheck was allowed")?;
    assert!(matches!(
        error.downcast_ref::<JobError>(),
        Some(JobError::Cancelled)
    ));
    assert_eq!(observations, 1);
    Ok(())
}
