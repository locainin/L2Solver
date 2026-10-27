use l2_workbench::job::{Job, MemoryBudget, MemoryClass, MemoryError};
use std::error::Error;
use std::sync::{Arc, Barrier, mpsc};
use std::thread;
use std::time::Duration;
use std::time::Instant;

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

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
        budget.try_reserve(MemoryClass::Publication, 1).unwrap_err(),
        MemoryError::Limit {
            limit: 100,
            used: 100,
            requested: 1
        }
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
                    let lease = budget.wait_reserve(MemoryClass::Executor, 7, None)?;
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
            .wait_reserve(MemoryClass::Case, 11, None)
            .unwrap_err(),
        MemoryError::Limit {
            limit: 10,
            used: 0,
            requested: 11
        }
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
        ))
    });
    receiver.recv_timeout(Duration::from_secs(2))?;
    wait_for_waiter(&budget)?;
    job.request_cancel();
    let outcome = worker
        .join()
        .map_err(|_| "worker panicked")?
        .map_err(|error| error.to_string())?;
    assert_eq!(outcome.unwrap_err(), MemoryError::Cancelled);
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
        let result = other_budget.wait_reserve(MemoryClass::Cache, 10, None);
        sent.send(result).expect("receiver remains alive");
    });
    wait_for_waiter(&budget)?;
    drop(lease);
    let cache = received.recv_timeout(Duration::from_secs(2))??;
    assert_eq!(budget.snapshot()?.used(MemoryClass::Cache), 10);
    drop(cache);
    worker.join().map_err(|_| "worker panicked")?;
    Ok(())
}

#[test]
fn exact_u64_limit_rejects_overflow_without_changing_live_charges() -> TestResult {
    let budget = MemoryBudget::new(u64::MAX);
    let lease = budget.try_reserve(MemoryClass::Base, u64::MAX)?;
    assert_eq!(
        budget.try_reserve(MemoryClass::Executor, 1).unwrap_err(),
        MemoryError::Limit {
            limit: u64::MAX,
            used: u64::MAX,
            requested: 1
        }
    );
    assert_eq!(budget.snapshot()?.used_bytes, u64::MAX);
    drop(lease);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
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
