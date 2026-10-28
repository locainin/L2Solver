use l2_workbench::job::{Job, MemoryBudget, MemoryClass, MemoryError};
use std::error::Error;
use std::sync::{Arc, Barrier, mpsc};
use std::thread;
use std::time::Duration;
use std::time::Instant;

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

#[path = "memory/working_set.rs"]
mod working_set;

#[test]
fn buffered_case_observations_measure_retention_without_charging_memory_twice() -> TestResult {
    let budget = MemoryBudget::new(100);
    let retained = budget.try_reserve(MemoryClass::Case, 80)?;
    let first = budget.observe_buffered_case(30)?;
    let second = budget.observe_buffered_case(50)?;
    let snapshot = budget.snapshot()?;
    assert_eq!(snapshot.used_bytes, 80);
    assert_eq!(snapshot.buffered_cases.current_cases, 2);
    assert_eq!(snapshot.buffered_cases.current_charged_bytes, 80);
    assert_eq!(snapshot.buffered_cases.peak_cases, 2);
    assert_eq!(snapshot.buffered_cases.peak_charged_bytes, 80);

    drop(first);
    let snapshot = budget.snapshot()?;
    assert_eq!(snapshot.buffered_cases.current_cases, 1);
    assert_eq!(snapshot.buffered_cases.current_charged_bytes, 50);
    drop(second);
    let snapshot = budget.snapshot()?;
    assert_eq!(snapshot.buffered_cases.current_cases, 0);
    assert_eq!(snapshot.buffered_cases.current_charged_bytes, 0);
    assert_eq!(snapshot.buffered_cases.completed_waits, 2);
    assert_eq!(snapshot.used_bytes, 80);
    drop(retained);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn buffered_case_wait_is_measured_when_the_collector_releases_its_observation() -> TestResult {
    let budget = MemoryBudget::new(100);
    let queued = budget.observe_buffered_case(20)?;
    // A short real wait checks the monotonic clock rather than an invented duration
    thread::sleep(Duration::from_millis(5));
    drop(queued);
    let snapshot = budget.snapshot()?;
    assert!(snapshot.buffered_cases.longest_wait_ms >= 5);
    assert!(snapshot.buffered_cases.total_wait_ms >= snapshot.buffered_cases.longest_wait_ms);
    Ok(())
}

#[test]
fn overflowing_buffer_observation_preserves_the_previous_metrics() -> TestResult {
    let budget = MemoryBudget::new(u64::MAX);
    let first = budget.observe_buffered_case(u64::MAX)?;
    let before = budget.snapshot()?;
    assert_eq!(
        budget.observe_buffered_case(1).err(),
        Some(MemoryError::ObservationOverflow)
    );
    assert_eq!(budget.snapshot()?, before);
    drop(first);
    assert_eq!(budget.snapshot()?.buffered_cases.current_charged_bytes, 0);
    Ok(())
}

#[test]
fn completed_snapshot_storage_is_observed_separately_from_resident_charges() -> TestResult {
    let memory = MemoryBudget::new(100);
    let first = memory.observe_spilled_case(700)?;
    let second = memory.observe_spilled_case(900)?;
    let live = memory.snapshot()?;
    assert_eq!(live.used_bytes, 0);
    assert_eq!(live.buffered_cases.current_charged_bytes, 0);
    assert_eq!(live.buffered_cases.current_snapshot_bytes, 1600);
    assert_eq!(live.buffered_cases.spilled_cases, 2);
    drop(first);
    assert_eq!(
        memory.snapshot()?.buffered_cases.current_snapshot_bytes,
        900
    );
    drop(second);
    let completed = memory.snapshot()?.buffered_cases;
    assert_eq!(completed.current_snapshot_bytes, 0);
    assert_eq!(completed.peak_snapshot_bytes, 1600);
    assert_eq!(completed.spilled_snapshot_bytes, 1600);
    Ok(())
}

#[test]
fn leases_share_an_exact_limit_and_release_on_drop() -> TestResult {
    let budget = MemoryBudget::new(100);
    let mut case = budget.try_reserve(MemoryClass::Case, 40)?;
    let cache = budget.try_reserve(MemoryClass::Cache, 30)?;
    case.try_resize(70)?;

    let snapshot = budget.snapshot()?;
    assert_eq!(snapshot.used_bytes, 100);
    assert_eq!(snapshot.peak_bytes, 100);
    assert_eq!(snapshot.used(MemoryClass::Case), 70);
    assert_eq!(snapshot.used(MemoryClass::Cache), 30);
    assert_eq!(
        budget.try_reserve(MemoryClass::Publication, 1).err(),
        Some(MemoryError::Limit {
            limit: 100,
            used: 100,
            requested: 1
        })
    );

    case.try_resize(15)?;
    assert_eq!(budget.snapshot()?.used_bytes, 45);
    drop(cache);
    assert_eq!(budget.snapshot()?.used_bytes, 15);
    drop(case);
    let snapshot = budget.snapshot()?;
    assert_eq!(snapshot.used_bytes, 0);
    assert_eq!(snapshot.peak_bytes, 100);
    assert_eq!(snapshot.rejected, 1);
    Ok(())
}

#[test]
fn failed_growth_preserves_the_original_lease_and_charge() -> TestResult {
    let budget = MemoryBudget::new(10);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 7)?;
    assert_eq!(
        lease.try_resize(11),
        Err(MemoryError::Limit {
            limit: 10,
            used: 7,
            requested: 4
        })
    );
    assert_eq!(lease.bytes(), 7);
    assert_eq!(budget.snapshot()?.used_bytes, 7);
    Ok(())
}

#[test]
fn one_two_and_four_workers_never_exceed_the_shared_bound() -> TestResult {
    for workers in [1_usize, 2, 4] {
        let budget = MemoryBudget::new(12);
        let barrier = Arc::new(Barrier::new(workers));
        let handles = (0..workers)
            .map(|_| {
                let budget = budget.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || -> TestResult {
                    barrier.wait();
                    let lease = budget.wait_reserve(
                        MemoryClass::Executor,
                        7,
                        None,
                        Instant::now() + Duration::from_secs(2),
                    )?;
                    assert_eq!(lease.bytes(), 7);
                    assert!(budget.snapshot()?.used_bytes <= 12);
                    Ok(())
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.join().map_err(|_| "worker panicked")??;
        }
        let snapshot = budget.snapshot()?;
        assert_eq!(snapshot.used_bytes, 0);
        assert_eq!(snapshot.peak_bytes, 7);
    }
    Ok(())
}

#[test]
fn over_limit_request_returns_without_waiting_for_other_workers() {
    let budget = MemoryBudget::new(10);
    assert_eq!(
        budget
            .wait_reserve(
                MemoryClass::Case,
                11,
                None,
                Instant::now() + Duration::from_secs(2)
            )
            .err(),
        Some(MemoryError::Limit {
            limit: 10,
            used: 0,
            requested: 11
        })
    );
}

#[test]
fn waiting_admission_rechecks_cancellation_while_other_memory_is_held() -> TestResult {
    let budget = MemoryBudget::new(10);
    let lease = budget.try_reserve(MemoryClass::Case, 10)?;
    let job = Job::new("cancel admission");
    let thread_budget = budget.clone();
    let thread_job = job.clone();
    let (started, receiver) = mpsc::channel();
    let worker = thread::spawn(move || {
        started.send(())?;
        Ok::<_, Box<dyn Error + Send + Sync>>(thread_budget.wait_reserve(
            MemoryClass::Cache,
            1,
            Some(&thread_job),
            Instant::now() + Duration::from_secs(2),
        ))
    });
    receiver.recv_timeout(Duration::from_secs(2))?;
    wait_for_waiter(&budget)?;
    job.request_cancel();
    let outcome = worker
        .join()
        .map_err(|_| "worker panicked")?
        .map_err(|error| error.to_string())?;
    assert_eq!(outcome.err(), Some(MemoryError::Cancelled));
    assert_eq!(budget.snapshot()?.used_bytes, 10);
    drop(lease);
    Ok(())
}

#[test]
fn releasing_publication_pressure_wakes_waiting_cache_admission() -> TestResult {
    let budget = MemoryBudget::new(10);
    let lease = budget.try_reserve(MemoryClass::Publication, 10)?;
    let other_budget = budget.clone();
    let (sent, received) = mpsc::channel();
    let worker = thread::spawn(move || {
        let result = other_budget.wait_reserve(
            MemoryClass::Cache,
            10,
            None,
            Instant::now() + Duration::from_secs(2),
        );
        sent.send(result).map_err(|_| "receiver dropped")
    });
    wait_for_waiter(&budget)?;
    drop(lease);
    let cache = received.recv_timeout(Duration::from_secs(2))??;
    assert_eq!(budget.snapshot()?.used(MemoryClass::Cache), 10);
    drop(cache);
    worker.join().map_err(|_| "worker panicked")??;
    Ok(())
}

#[test]
fn exact_u64_limit_rejects_overflow_without_changing_live_charges() -> TestResult {
    let budget = MemoryBudget::new(u64::MAX);
    let lease = budget.try_reserve(MemoryClass::Base, u64::MAX)?;
    assert_eq!(
        budget.try_reserve(MemoryClass::Executor, 1).err(),
        Some(MemoryError::Limit {
            limit: u64::MAX,
            used: u64::MAX,
            requested: 1
        })
    );
    assert_eq!(budget.snapshot()?.used_bytes, u64::MAX);
    drop(lease);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn held_capacity_times_out_without_changing_live_charges() -> TestResult {
    let budget = MemoryBudget::new(10);
    let lease = budget.try_reserve(MemoryClass::Case, 10)?;
    assert_eq!(
        budget
            .wait_reserve(
                MemoryClass::Executor,
                1,
                None,
                Instant::now() + Duration::from_millis(20),
            )
            .err(),
        Some(MemoryError::TimedOut {
            limit: 10,
            used: 10,
            requested: 1
        })
    );
    assert_eq!(budget.snapshot()?.used_bytes, 10);
    assert_eq!(budget.snapshot()?.timed_out, 1);
    drop(lease);
    Ok(())
}

fn wait_for_waiter(budget: &MemoryBudget) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(2);
    while budget.snapshot()?.waiting == 0 {
        if Instant::now() >= deadline {
            return Err("worker did not start waiting for admission".into());
        }
        thread::yield_now();
    }
    Ok(())
}
