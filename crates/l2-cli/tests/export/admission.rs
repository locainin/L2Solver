use super::*;
use l2_workbench::job::{
    CgroupMemoryEvents, CgroupMemorySnapshot, Job, JobError, MemoryBudget, SystemMemorySnapshot,
};

type TestResult = Result<(), Box<dyn Error>>;
const MIB: u64 = 1024 * 1024;
#[cfg(target_os = "linux")]
const PRESSURE_TEST: &str = "export::processing::admission::tests::kernel_pressure_followed_by_simulated_eacces_blocks_admission";

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
fn a_logical_only_budget_does_not_require_an_os_observation() -> TestResult {
    let memory = MemoryBudget::new(512 * MIB);
    check_pressure(&memory.snapshot()?, 32 * MIB)?;
    assert_eq!(memory.snapshot()?.system_observation_failures, 0);
    Ok(())
}

#[test]
fn failed_observation_after_pressure_does_not_admit_new_work() -> TestResult {
    let memory = observed_budget(460 * MIB, None)?;
    assert!(matches!(
        check_pressure(&memory.snapshot()?, 32 * MIB),
        Err(MemoryError::Pressure { .. })
    ));
    memory.observe_system_memory(None)?;
    let snapshot = memory.snapshot()?;
    assert_eq!(snapshot.system_observation_failures, 1);
    assert!(snapshot.system.is_none());
    assert!(matches!(
        check_pressure(&snapshot, 32 * MIB),
        Err(MemoryError::SystemObservationUnavailable { .. })
    ));
    Ok(())
}

#[test]
fn an_enabled_monitor_that_never_succeeded_does_not_admit_work() -> TestResult {
    let memory = MemoryBudget::new(512 * MIB);
    memory.observe_system_memory(None)?;
    assert!(matches!(
        check_pressure(&memory.snapshot()?, 32 * MIB),
        Err(MemoryError::SystemObservationUnavailable { .. })
    ));
    Ok(())
}

#[test]
fn stale_pressure_does_not_become_an_admission_success() -> TestResult {
    let memory = observed_budget(460 * MIB, None)?;
    let mut old = memory.snapshot()?;
    old.system_sample_age_ms = Some(10_000);
    assert!(matches!(
        check_pressure(&old, 32 * MIB),
        Err(MemoryError::SystemObservationStale { age_ms: 10_000 })
    ));
    Ok(())
}

#[test]
fn a_fresh_healthy_observation_restores_admission_after_failure() -> TestResult {
    let memory = observed_budget(460 * MIB, None)?;
    memory.observe_system_memory(None)?;
    assert!(matches!(
        check_pressure(&memory.snapshot()?, 32 * MIB),
        Err(MemoryError::SystemObservationUnavailable { .. })
    ));
    memory.observe_system_memory(Some(SystemMemorySnapshot {
        process_rss_bytes: 100 * MIB,
        process_peak_rss_bytes: 460 * MIB,
        cgroup: None,
    }))?;
    let snapshot = memory.snapshot()?;
    assert_eq!(snapshot.system_observation_failures, 1);
    check_pressure(&snapshot, 32 * MIB)?;
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
fn quiescent_missing_observation_retries_until_a_fresh_healthy_sample() -> TestResult {
    let memory = MemoryBudget::new(512 * MIB);
    memory.observe_system_memory(None)?;
    let missing = memory.snapshot()?;
    let healthy = observed_budget(100 * MIB, None)?.snapshot()?;
    let mut observations = 0;
    check_admission_pressure(0, 32 * MIB, None, || {
        observations += 1;
        Ok(if observations == 1 { missing } else { healthy })
    })?;
    assert_eq!(observations, 2);
    Ok(())
}

#[test]
fn quiescent_busy_observer_is_retried_without_assuming_healthy_memory() -> TestResult {
    let healthy = observed_budget(100 * MIB, None)?.snapshot()?;
    let mut observations = 0;
    check_admission_pressure(0, 32 * MIB, None, || {
        observations += 1;
        if observations == 1 {
            Err(MemoryError::SystemObservationBusy)
        } else {
            Ok(healthy)
        }
    })?;
    assert_eq!(observations, 2);
    Ok(())
}

#[test]
fn persistent_missing_observation_has_a_bounded_quiescent_failure() -> TestResult {
    let memory = MemoryBudget::new(512 * MIB);
    memory.observe_system_memory(None)?;
    let missing = memory.snapshot()?;
    let mut observations = 0;
    let result = check_admission_pressure(0, 32 * MIB, None, || {
        observations += 1;
        Ok(missing)
    });
    let error = result
        .err()
        .ok_or("missing observation allowed admission")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::SystemObservationUnavailable { .. })
    ));
    assert_eq!(observations, 3);
    Ok(())
}

#[test]
fn active_workers_are_not_joined_inside_an_unavailable_observation_check() -> TestResult {
    let memory = MemoryBudget::new(512 * MIB);
    memory.observe_system_memory(None)?;
    let missing = memory.snapshot()?;
    let mut observations = 0;
    let result = check_admission_pressure(2, 32 * MIB, None, || {
        observations += 1;
        Ok(missing)
    });
    let error = result
        .err()
        .ok_or("missing observation allowed admission")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::SystemObservationUnavailable { .. })
    ));
    assert_eq!(observations, 1);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn busy_observer_defers_actual_admission_while_a_worker_is_active() -> TestResult {
    use crate::workbench::full_source::{
        FlowAnalysis, FullSourceItem, PerFlowCoverage, ReconstructionCaseOmissions,
    };
    use l2_workbench::{evidence::Case, investigation::BuildResult};
    use std::{io, sync::mpsc};

    let item = FullSourceItem::Flow(Box::new(FlowAnalysis {
        flow: crate::export::provenance_tests::flow(1),
        result: BuildResult {
            case: Case::new(),
            complete: true,
        },
        coverage: PerFlowCoverage {
            selected_records: 0,
            retained_records: 0,
            omitted_records: 0,
            retention_limits: Vec::new(),
            reconstruction_omissions: ReconstructionCaseOmissions::default(),
            complete: true,
        },
    }));
    let mut pending = PendingCase::new(item)?;
    let memory = observed_budget(100 * MIB, None)?;
    let options = crate::arguments::RecoveryOptions::default();
    let context = RecoveryContext {
        cache: None,
        job: None,
        memory: Some(&memory),
        options: &options,
    };
    let (entered, entered_rx) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let observer_budget = memory.clone();
    let observer = thread::spawn(move || {
        observer_budget.try_observe_system_memory_with(|| {
            entered.send(()).map_err(io::Error::other)?;
            release_rx
                .recv_timeout(Duration::from_secs(3))
                .map_err(io::Error::other)?;
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        })
    });
    entered_rx.recv_timeout(Duration::from_secs(2))?;

    // Admission must return control so the collector can release the active worker
    let admission = admit(&mut pending, 1, &context);
    release.send(())?;
    observer.join().map_err(|_| "observer thread panicked")??;
    assert!(admission?.is_none(), "busy observer allowed admission");
    assert!(matches!(
        memory.snapshot()?.system_observation_error,
        Some(MemoryError::SystemObservationUnavailable {
            kind: io::ErrorKind::PermissionDenied,
            ..
        })
    ));
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

#[test]
fn cancellation_during_a_failed_observation_wins_over_retry() -> TestResult {
    let memory = MemoryBudget::new(512 * MIB);
    memory.observe_system_memory(None)?;
    let missing = memory.snapshot()?;
    let job = Job::new("admission cancelled while observation failed");
    job.start(Phase::FramingRecordDiscovery, None)?;
    let mut observations = 0;
    let result = check_admission_pressure(0, 32 * MIB, Some(&job), || {
        observations += 1;
        job.request_cancel();
        Ok(missing)
    });
    let error = result.err().ok_or("cancellation did not stop admission")?;
    assert!(matches!(
        error.downcast_ref::<JobError>(),
        Some(JobError::Cancelled)
    ));
    assert_eq!(observations, 1);
    Ok(())
}

#[test]
fn cancellation_during_a_busy_observation_wins_over_retry() -> TestResult {
    let job = Job::new("admission cancelled while observer is busy");
    job.start(Phase::FramingRecordDiscovery, None)?;
    let mut observations = 0;
    let result = check_admission_pressure(0, 32 * MIB, Some(&job), || {
        observations += 1;
        job.request_cancel();
        Err(MemoryError::SystemObservationBusy)
    });
    let error = result.err().ok_or("cancellation did not stop admission")?;
    assert!(matches!(
        error.downcast_ref::<JobError>(),
        Some(JobError::Cancelled)
    ));
    assert_eq!(observations, 1);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn pressure_child_rejects_the_parent_cgroup() -> TestResult {
    let parent_cgroup = unified_cgroup_path()?;
    let output = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", PRESSURE_TEST, "--nocapture"])
        .env("L2_TEST_CGROUP_INNER", "1")
        .env("L2_TEST_PARENT_CGROUP", parent_cgroup)
        .output()?;
    assert!(!output.status.success());
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(diagnostic.contains("requires a dedicated 512 MiB cgroup"));
    Ok(())
}

#[cfg(target_os = "linux")]
fn unified_cgroup_path() -> Result<String, Box<dyn Error>> {
    let entries = std::fs::read_to_string("/proc/self/cgroup")?;
    let paths: Vec<_> = entries
        .lines()
        .filter_map(|line| line.strip_prefix("0::"))
        .collect();
    let [path] = paths.as_slice() else {
        return Err("unified cgroup path is unavailable".into());
    };
    Ok((*path).to_owned())
}

#[cfg(target_os = "linux")]
fn verify_pressure_cgroup() -> TestResult {
    use std::{os::unix::fs::MetadataExt, path::Path};

    let current = unified_cgroup_path()?;
    let parent = std::env::var("L2_TEST_PARENT_CGROUP")?;
    if current == parent {
        return Err("pressure test requires a dedicated 512 MiB cgroup".into());
    }
    let expected_unit = std::env::var("L2_TEST_CGROUP_UNIT")?;
    let root = Path::new("/sys/fs/cgroup").canonicalize()?;
    let group = root.join(current.trim_start_matches('/')).canonicalize()?;
    if !group.starts_with(&root)
        || group.file_name().and_then(|name| name.to_str()) != Some(expected_unit.as_str())
        || std::fs::metadata(&group)?.uid() != std::fs::metadata("/proc/self")?.uid()
        || std::fs::read_to_string(group.join("memory.max"))?.trim() != (512 * MIB).to_string()
        || std::fs::read_to_string(group.join("memory.swap.max"))?.trim() != "0"
        || std::fs::read_to_string(group.join("cgroup.procs"))?.trim()
            != std::process::id().to_string()
    {
        return Err("pressure test requires a dedicated 512 MiB cgroup with swap disabled".into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_pressure_in_owned_cgroup() -> TestResult {
    let parent = unified_cgroup_path()?;
    let unit = format!("l2solver-pressure-test-{}.service", std::process::id());
    // A transient user service limits only the spawned test process
    let output = std::process::Command::new("timeout")
        .args([
            "--kill-after=2s",
            "30s",
            "systemd-run",
            "--user",
            "--quiet",
            "--wait",
            "--pipe",
            "--collect",
            "--service-type=exec",
            "--expand-environment=no",
            "--property=MemoryMax=512M",
            "--property=MemorySwapMax=0",
            "--property=RuntimeMaxSec=25s",
            "--property=Delegate=yes",
        ])
        .arg(format!("--unit={unit}"))
        .arg("--setenv=L2_TEST_CGROUP_INNER=1")
        .arg(format!("--setenv=L2_TEST_PARENT_CGROUP={parent}"))
        .arg(format!("--setenv=L2_TEST_CGROUP_UNIT={unit}"))
        .arg(std::env::current_exe()?)
        .args(["--exact", PRESSURE_TEST, "--nocapture"])
        .output()?;
    if !output.status.success()
        || !String::from_utf8_lossy(&output.stdout).contains("kernel_pressure_verified=1")
    {
        return Err(format!(
            "dedicated cgroup pressure test failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    print!("{}", String::from_utf8_lossy(&output.stdout));
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn kernel_pressure_followed_by_simulated_eacces_blocks_admission() -> TestResult {
    if std::env::var_os("L2_TEST_CGROUP_INNER").as_deref() != Some(std::ffi::OsStr::new("1")) {
        return run_pressure_in_owned_cgroup();
    }
    verify_pressure_cgroup()?;
    let memory = MemoryBudget::new(512 * MIB);
    crate::recovery_job::refresh_memory_observation(&memory)?;
    let initial = memory
        .snapshot()?
        .system
        .and_then(|sample| sample.cgroup)
        .ok_or("a real cgroup observation is required")?;
    assert_eq!(initial.effective_max_bytes, Some(512 * MIB));
    assert!(
        initial.current_bytes < 384 * MIB,
        "cgroup starts too close to its limit"
    );

    // Keep ballast well below the hard cap and request future work separately
    let mut ballast = Vec::new();
    let mut pressured = None;
    for _ in 0..32 {
        ballast.push(vec![0xa5; 8 * 1024 * 1024]);
        crate::recovery_job::refresh_memory_observation(&memory)?;
        let snapshot = memory.snapshot()?;
        let current = snapshot
            .system
            .and_then(|sample| sample.cgroup)
            .ok_or("cgroup observation disappeared")?;
        if matches!(
            check_pressure(&snapshot, 192 * MIB),
            Err(MemoryError::Pressure { .. })
        ) {
            pressured = Some(current);
            break;
        }
        if current.current_bytes >= 384 * MIB {
            break;
        }
    }
    let actual = pressured.ok_or("bounded ballast did not reach measured admission pressure")?;
    assert!(actual.current_bytes > initial.current_bytes);
    assert_eq!(actual.events.max, initial.events.max);
    assert_eq!(actual.events.oom, initial.events.oom);
    assert_eq!(actual.events.oom_kill, initial.events.oom_kill);

    // This EACCES is injected after the real pressure sample; kernel permissions are unchanged
    memory
        .try_observe_system_memory_with(|| Err(std::io::Error::from_raw_os_error(libc::EACCES)))?;
    let failed = memory.snapshot()?;
    assert!(failed.system.is_none());
    assert_eq!(
        check_pressure(&failed, 192 * MIB),
        Err(MemoryError::SystemObservationUnavailable {
            kind: std::io::ErrorKind::PermissionDenied,
            raw_os_error: Some(libc::EACCES),
        })
    );
    drop(ballast);
    println!("kernel_pressure_verified=1");
    Ok(())
}
