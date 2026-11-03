use super::super::processing::{classify_worker_error, process_ordered};
use l2_workbench::{evidence::EvidenceError, job::MemoryError};
use std::{
    error::Error,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};

type TestResult = Result<(), Box<dyn Error>>;

struct RetainedCase {
    index: usize,
    drops: Arc<AtomicUsize>,
}

impl Drop for RetainedCase {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn completed_prefix_is_emitted_and_released_before_later_work_finishes() -> TestResult {
    let pool = rayon::ThreadPoolBuilder::new().num_threads(2).build()?;
    let drops = Arc::new(AtomicUsize::new(0));
    let (release_later, receiver) = mpsc::channel();
    let receiver = Mutex::new(receiver);
    let mut emitted = Vec::new();

    process_ordered(
        &pool,
        vec![0, 1],
        |_, _| Ok(Some(())),
        |index, ()| {
            if index == 1 {
                receiver
                    .lock()
                    .map_err(|error| error.to_string())?
                    .recv_timeout(Duration::from_secs(3))
                    .map_err(|error| error.to_string())?;
                if drops.load(Ordering::SeqCst) != 1 {
                    return Err("the emitted Case was still retained".to_owned());
                }
            }
            Ok(RetainedCase {
                index,
                drops: Arc::clone(&drops),
            })
        },
        |case| {
            let index = case.index;
            emitted.push(index);
            drop(case);
            if index == 0 {
                release_later.send(())?;
            }
            Ok(())
        },
    )?;
    assert_eq!(emitted, [0, 1]);
    assert_eq!(drops.load(Ordering::SeqCst), 2);
    Ok(())
}

#[test]
fn earliest_input_failure_wins_even_when_a_later_failure_finishes_first() -> TestResult {
    let pool = rayon::ThreadPoolBuilder::new().num_threads(3).build()?;
    let (later_done, receiver) = mpsc::channel();
    let receiver = Mutex::new(receiver);
    let mut emitted = Vec::new();
    let result = process_ordered(
        &pool,
        vec![0, 1, 2],
        |_, _| Ok(Some(())),
        |index, ()| match index {
            1 => {
                receiver
                    .lock()
                    .map_err(|error| error.to_string())?
                    .recv_timeout(Duration::from_secs(3))
                    .map_err(|error| error.to_string())?;
                Err("first input failure".to_owned())
            }
            2 => {
                later_done.send(()).map_err(|error| error.to_string())?;
                Err("later input failure".to_owned())
            }
            _ => Ok(index),
        },
        |index| {
            emitted.push(index);
            Ok(())
        },
    );
    assert_eq!(
        result.err().map(|error| error.to_string()),
        Some("first input failure".to_owned())
    );
    assert_eq!(emitted, [0]);
    Ok(())
}

#[test]
fn ordered_collection_rejects_a_nested_pool_worker_before_starting_tasks() -> TestResult {
    let pool = rayon::ThreadPoolBuilder::new().num_threads(2).build()?;
    let started = AtomicUsize::new(0);
    let result = pool.install(|| {
        process_ordered(
            &pool,
            vec![0],
            |_, _| Ok(Some(())),
            |index, ()| {
                started.fetch_add(1, Ordering::SeqCst);
                Ok::<_, String>(index)
            },
            |_| Ok(()),
        )
        .err()
        .map(|error| error.to_string())
    });
    assert_eq!(
        result.as_deref(),
        Some("ordered collection cannot run inside its recovery pool")
    );
    assert_eq!(started.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn worker_error_keeps_the_typed_memory_limit_inside_nested_causes() -> TestResult {
    let pool = rayon::ThreadPoolBuilder::new().num_threads(2).build()?;
    let expected = MemoryError::Limit {
        limit: 12,
        used: 9,
        requested: 4,
    };
    let nested = std::io::Error::other(EvidenceError::Memory(expected));
    let classified = classify_worker_error(&nested);
    let result = process_ordered(
        &pool,
        vec![classified],
        |_, _| Ok(Some(())),
        |error, ()| Err::<(), _>(error),
        |()| Ok(()),
    );
    let error = result.err().ok_or("memory pressure should fail")?;
    assert_eq!(crate::memory_error::find(error.as_ref()), Some(expected));
    Ok(())
}

#[test]
fn memory_cancellation_remains_distinct_from_a_limit_failure() -> TestResult {
    let nested = std::io::Error::other(EvidenceError::Memory(MemoryError::Cancelled));
    let classified = classify_worker_error(&nested);
    let error = classified.source().ok_or("missing cancellation cause")?;
    assert_eq!(
        error.downcast_ref::<MemoryError>(),
        Some(&MemoryError::Cancelled)
    );
    assert!(crate::memory_error::find(&std::io::Error::other("limit")).is_none());
    Ok(())
}

#[test]
fn worker_error_keeps_wrapped_job_failures_typed() {
    for expected in [
        l2_workbench::job::JobError::Cancelled,
        l2_workbench::job::JobError::LockPoisoned,
    ] {
        let nested = std::io::Error::other(expected);
        let classified = classify_worker_error(&nested);
        assert_eq!(
            classified
                .source()
                .and_then(|error| error.downcast_ref::<l2_workbench::job::JobError>()),
            Some(&expected)
        );
    }
}

#[test]
fn ordered_collection_preserves_typed_worker_failures() -> TestResult {
    let pool = rayon::ThreadPoolBuilder::new().num_threads(2).build()?;
    let expected = MemoryError::Limit {
        limit: 20,
        used: 14,
        requested: 7,
    };
    let result = process_ordered(
        &pool,
        vec![0],
        |_, _| Ok(Some(())),
        |_, ()| Err::<(), _>(expected),
        |()| Ok(()),
    );
    let error = result.err().ok_or("memory pressure should fail")?;
    assert_eq!(error.downcast_ref::<MemoryError>(), Some(&expected));
    Ok(())
}

#[test]
fn admission_waits_for_released_prefix_bytes_instead_of_failing_the_next_case() -> TestResult {
    use l2_workbench::job::{MemoryBudget, MemoryClass};
    let pool = rayon::ThreadPoolBuilder::new().num_threads(4).build()?;
    let memory = MemoryBudget::new(32 * 1024);
    let mut emitted = Vec::new();
    process_ordered(
        &pool,
        vec![0, 1, 2],
        |_, active| match memory.try_working_set(20 * 1024) {
            Ok(work) => Ok(Some(work)),
            Err(MemoryError::Limit { .. }) if active > 0 => Ok(None),
            Err(error) => Err(error.into()),
        },
        |index, work| {
            let retained = work.budget().try_reserve(MemoryClass::Case, 20 * 1024)?;
            Ok::<_, MemoryError>((index, retained))
        },
        |(index, retained)| {
            emitted.push(index);
            drop(retained);
            Ok(())
        },
    )?;
    assert_eq!(emitted, [0, 1, 2]);
    let snapshot = memory.snapshot()?;
    assert_eq!(snapshot.used_bytes, 0);
    assert_eq!(snapshot.working_sets.peak_active_cases, 1);
    assert_eq!(snapshot.working_sets.admitted_cases, 3);
    assert!(snapshot.working_sets.admission_denials > 0);
    Ok(())
}

#[test]
fn later_admission_failure_does_not_hide_an_earlier_worker_failure() -> TestResult {
    let pool = rayon::ThreadPoolBuilder::new().num_threads(2).build()?;
    let outcome = process_ordered(
        &pool,
        vec![0, 1],
        |index, _| {
            if *index == 1 {
                return Err("later admission failure".into());
            }
            Ok(Some(()))
        },
        |_, ()| Err::<(), _>("earlier worker failure".to_owned()),
        |()| Ok(()),
    );
    assert_eq!(
        outcome.err().ok_or("failure was lost")?.to_string(),
        "earlier worker failure"
    );
    Ok(())
}

#[test]
fn no_admissible_worker_reports_a_resource_failure_without_starting_work() -> TestResult {
    let pool = rayon::ThreadPoolBuilder::new().num_threads(2).build()?;
    let started = AtomicUsize::new(0);
    let outcome = process_ordered(
        &pool,
        vec![0],
        |_, _| Ok(None::<()>),
        |_, ()| {
            started.fetch_add(1, Ordering::SeqCst);
            Ok::<_, String>(())
        },
        |()| Ok(()),
    );
    assert!(
        outcome
            .err()
            .ok_or("blocked admission was ignored")?
            .to_string()
            .contains("no recovery worker can be admitted")
    );
    assert_eq!(started.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
#[expect(
    clippy::panic,
    reason = "An injected worker panic verifies collector wakeup"
)]
fn worker_panic_wakes_the_collector_while_later_admission_is_blocked() -> TestResult {
    let pool = rayon::ThreadPoolBuilder::new().num_threads(2).build()?;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        process_ordered(
            &pool,
            vec![0, 1],
            |index, _| Ok((*index == 0).then_some(())),
            |_, ()| -> Result<(), String> {
                panic!("worker failure while admission remains open");
            },
            |()| Ok(()),
        )
        .err()
        .map(|error| error.to_string())
    }));
    let failure = outcome
        .err()
        .ok_or("worker panic did not reach the collector")?;
    assert_eq!(
        failure.downcast_ref::<&str>().copied(),
        Some("worker failure while admission remains open")
    );
    Ok(())
}

#[test]
fn queued_native_case_bytes_flush_a_batch_before_the_requested_worker_count() -> TestResult {
    use l2_workbench::job::{MemoryBudget, MemoryClass};
    let memory = MemoryBudget::new(512 * 1024 * 1024);
    let retained = memory.try_reserve(MemoryClass::Case, 128 * 1024 * 1024)?;
    assert!(super::super::processing::batch_ready(1, 20, Some(&memory))?);
    assert!(!super::super::processing::batch_ready(
        0,
        20,
        Some(&memory)
    )?);
    drop(retained);
    assert!(!super::super::processing::batch_ready(
        1,
        20,
        Some(&memory)
    )?);
    Ok(())
}

#[test]
fn shared_capture_index_bytes_do_not_count_as_queued_case_bytes() -> TestResult {
    use l2_workbench::job::{MemoryBudget, MemoryClass};
    let memory = MemoryBudget::new(512 * 1024 * 1024);
    let index = memory.try_reserve(MemoryClass::Base, 160 * 1024 * 1024)?;
    assert!(!super::super::processing::batch_ready(1, 4, Some(&memory))?);
    assert!(super::super::processing::batch_ready(4, 4, Some(&memory))?);
    drop(index);
    Ok(())
}
