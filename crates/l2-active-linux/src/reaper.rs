#[cfg(test)]
#[path = "../tests/reaper/slots.rs"]
pub mod tests;

use std::{
    io,
    process::Child,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError},
    },
    thread,
    time::{Duration, Instant},
};

const MAX_ACTIVE_HELPERS: usize = 16;
const FAILED_HANDOFF_ATTEMPTS: usize = 20;
const FAILED_HANDOFF_DELAY: Duration = Duration::from_millis(1);
const FAILED_HANDOFF_TIMEOUT: Duration = Duration::from_millis(20);
static ACTIVE_HELPERS: AtomicUsize = AtomicUsize::new(0);
static REAPER: OnceLock<Option<SyncSender<Task>>> = OnceLock::new();
static RETAINED: OnceLock<Retention> = OnceLock::new();

pub struct Lease {
    slots: &'static AtomicUsize,
    retention: &'static Retention,
}

impl Lease {
    fn acquire(slots: &'static AtomicUsize, retention: &'static Retention) -> io::Result<Self> {
        slots
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_ACTIVE_HELPERS).then_some(count + 1)
            })
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "active helper process limit reached",
                )
            })?;
        Ok(Self { slots, retention })
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.slots.fetch_sub(1, Ordering::AcqRel);
    }
}

struct Task {
    child: Child,
    lease: Lease,
}

struct Retention {
    sender: SyncSender<Task>,
    // Holding the receiver keeps the queued children owned and retrievable
    _receiver: Mutex<Receiver<Task>>,
}

impl Retention {
    fn new() -> Self {
        let (sender, receiver) = mpsc::sync_channel(MAX_ACTIVE_HELPERS);
        Self {
            sender,
            _receiver: Mutex::new(receiver),
        }
    }
}

pub fn reserve() -> io::Result<Lease> {
    sender()?;
    // Allocate fallback storage before a lease can be used to launch a child
    let retention = RETAINED.get_or_init(Retention::new);
    Lease::acquire(&ACTIVE_HELPERS, retention)
}

pub fn submit(child: Child, lease: Lease) {
    #[cfg(test)]
    tests::record_handoff();
    submit_with_sender(child, lease, REAPER.get().and_then(Option::as_ref));
}

pub fn retain_unwaitable(child: Child, lease: Lease) {
    retain_task(Task { child, lease });
}

fn submit_with_sender(child: Child, lease: Lease, sender: Option<&SyncSender<Task>>) {
    let task = Task { child, lease };
    let task = if let Some(sender) = sender {
        match sender.try_send(task) {
            Ok(()) => return,
            Err(TrySendError::Full(task) | TrySendError::Disconnected(task)) => task,
        }
    } else {
        task
    };
    reap_after_failed_handoff(task);
}

fn reap_after_failed_handoff(mut task: Task) {
    let deadline = Instant::now() + FAILED_HANDOFF_TIMEOUT;
    for attempt in 0..FAILED_HANDOFF_ATTEMPTS {
        match reap_attempt(&mut task) {
            Ok(true) => return,
            // A missing wait status does not prove that the process has exited
            Err(_) => break,
            Ok(false) => {}
        }
        let now = Instant::now();
        if attempt + 1 == FAILED_HANDOFF_ATTEMPTS || now >= deadline {
            break;
        }
        thread::sleep(FAILED_HANDOFF_DELAY.min(deadline.saturating_duration_since(now)));
    }
    retain_task(task);
}

#[expect(
    clippy::mem_forget,
    reason = "The unreachable retention queue failure must still preserve both resources"
)]
fn retain_task(task: Task) {
    // Every queued or incoming task owns one of the same 16 leases, so this
    // live queue has room for every task that can reach it
    let retention = task.lease.retention;
    if let Err(TrySendError::Full(task) | TrySendError::Disconnected(task)) =
        retention.sender.try_send(task)
    {
        // Preserve both resources if the queue invariant is ever violated
        std::mem::forget(task);
    }
}

fn reap_attempt(task: &mut Task) -> io::Result<bool> {
    #[cfg(test)]
    tests::record_wait();
    match task.child.try_wait() {
        Ok(Some(_)) => Ok(true),
        Err(error) if error.raw_os_error() == Some(nix::libc::ECHILD) => Err(error),
        _ => {
            #[cfg(test)]
            tests::record_kill();
            let _ignored = task.child.kill();
            Ok(false)
        }
    }
}

fn sender() -> io::Result<&'static SyncSender<Task>> {
    // A failed reaper start makes all later helper launches fail closed
    REAPER
        .get_or_init(|| start().ok())
        .as_ref()
        .ok_or_else(|| io::Error::other("active helper reaper is unavailable"))
}

fn start() -> io::Result<SyncSender<Task>> {
    let (sender, receiver) = mpsc::sync_channel(MAX_ACTIVE_HELPERS);
    let mut pending: Vec<Task> = Vec::new();
    pending
        .try_reserve_exact(MAX_ACTIVE_HELPERS)
        .map_err(io::Error::other)?;
    thread::Builder::new()
        .name("l2-active-reaper".into())
        .spawn(move || {
            loop {
                match receiver.recv_timeout(Duration::from_millis(100)) {
                    Ok(task) => pending.push(task),
                    Err(RecvTimeoutError::Disconnected) if pending.is_empty() => break,
                    Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {}
                }
                pending.retain_mut(|task| matches!(reap_attempt(task), Ok(false)));
            }
        })?;
    Ok(sender)
}
