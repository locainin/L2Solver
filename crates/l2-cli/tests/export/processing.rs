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
        |index| {
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
        |index| match index {
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
            |index| {
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
    let result = process_ordered(&pool, vec![classified], Err::<(), _>, |()| Ok(()));
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
fn ordered_collection_preserves_typed_worker_failures() -> TestResult {
    let pool = rayon::ThreadPoolBuilder::new().num_threads(2).build()?;
    let expected = MemoryError::Limit {
        limit: 20,
        used: 14,
        requested: 7,
    };
    let result = process_ordered(&pool, vec![0], |_| Err::<(), _>(expected), |()| Ok(()));
    let error = result.err().ok_or("memory pressure should fail")?;
    assert_eq!(error.downcast_ref::<MemoryError>(), Some(&expected));
    Ok(())
}
