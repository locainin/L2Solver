//! Admit work from the collector and release completed results in source order

use std::{collections::VecDeque, error::Error, io, sync::mpsc};

type WorkerResult<T> = Result<T, Box<dyn Error + Send + Sync>>;
type CollectedResult<T> = Result<T, Box<dyn Error>>;

// A panic must wake the collector even while it holds the sender for later admissions
struct Completion<T> {
    sender: mpsc::SyncSender<(usize, WorkerResult<T>)>,
    index: usize,
    result: Option<WorkerResult<T>>,
}

impl<T> Drop for Completion<T> {
    fn drop(&mut self) {
        let result = self.result.take().unwrap_or_else(|| {
            Err(io::Error::other("recovery worker panicked before producing a result").into())
        });
        // An earlier failure can end collection before the remaining workers finish
        let _ = self.sender.send((self.index, result));
    }
}

/// Retry blocked admission only after collecting and releasing available prefix results
pub(in crate::export) fn process_ordered<T, U, E, P>(
    pool: &rayon::ThreadPool,
    items: Vec<T>,
    mut admit: impl FnMut(&mut T, usize) -> Result<Option<P>, Box<dyn Error>>,
    work: impl Fn(T, P) -> Result<U, E> + Sync,
    mut emit: impl FnMut(U) -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>>
where
    T: Send,
    U: Send,
    E: Send + Into<Box<dyn Error + Send + Sync>>,
    P: Send,
{
    // The collector cannot occupy a worker whose result it needs to receive
    if pool.current_thread_index().is_some() {
        return Err(
            io::Error::other("ordered collection cannot run inside its recovery pool").into(),
        );
    }
    let count = items.len();
    let mut waiting = Vec::new();
    waiting.try_reserve_exact(count)?;
    waiting.resize_with(count, || None);
    // A deferred item returns to the front without cloning it or growing the queue
    let mut pending = VecDeque::from(items);
    let (sender, receiver) = mpsc::sync_channel(count);
    pool.in_place_scope_fifo(|scope| {
        let outcome = (|| {
            let mut next = 0;
            let mut active = 0;
            let mut admission_failed = false;
            while next < count {
                // Publication drops live Case charges before the next admission attempt
                while let Some(result) = waiting.get_mut(next).and_then(Option::take) {
                    emit(result?)?;
                    next += 1;
                }
                if next == count {
                    break;
                }
                while !admission_failed && active < pool.current_num_threads() {
                    let Some(mut item) = pending.pop_front() else {
                        break;
                    };
                    let index = count - pending.len() - 1;
                    let permit = match admit(&mut item, active) {
                        Ok(Some(permit)) => permit,
                        Ok(None) => {
                            pending.push_front(item);
                            break;
                        }
                        Err(error) => {
                            // Earlier work keeps its error and emission priority
                            store_result(&mut waiting, index, Err(error))?;
                            admission_failed = true;
                            break;
                        }
                    };
                    active += 1;
                    let sender = sender.clone();
                    let work = &work;
                    scope.spawn_fifo(move |_| {
                        let mut completion = Completion {
                            sender,
                            index,
                            result: None,
                        };
                        completion.result = Some(work(item, permit).map_err(Into::into));
                    });
                }
                if waiting.get(next).is_some_and(Option::is_some) {
                    continue;
                }
                if active == 0 {
                    return Err(io::Error::other(
                        "no recovery worker can be admitted within the available memory",
                    )
                    .into());
                }
                let (index, result) = receiver.recv().map_err(|_| {
                    io::Error::other("recovery worker stopped before producing all results")
                })?;
                active -= 1;
                store_result(
                    &mut waiting,
                    index,
                    result.map_err(|error| error as Box<dyn Error>),
                )?;
            }
            Ok(())
        })();
        // Workers can finish without blocking when publication or admission fails
        drop(receiver);
        outcome
    })
}

fn store_result<T>(
    waiting: &mut [Option<CollectedResult<T>>],
    index: usize,
    result: CollectedResult<T>,
) -> Result<(), Box<dyn Error>> {
    let slot = waiting
        .get_mut(index)
        .ok_or_else(|| io::Error::other("recovery worker returned an invalid result index"))?;
    *slot = Some(result);
    Ok(())
}
