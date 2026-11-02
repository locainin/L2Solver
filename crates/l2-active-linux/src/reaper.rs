#[cfg(test)]
#[path = "../tests/reaper/slots.rs"]
mod tests;

use std::{
    io,
    process::Child,
    sync::{
        OnceLock,
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, RecvTimeoutError, SyncSender, TrySendError},
    },
    thread,
    time::Duration,
};

const MAX_ACTIVE_HELPERS: usize = 16;
static ACTIVE_HELPERS: AtomicUsize = AtomicUsize::new(0);
static REAPER: OnceLock<Option<SyncSender<Task>>> = OnceLock::new();

pub struct Lease(&'static AtomicUsize);

impl Lease {
    fn acquire(slots: &'static AtomicUsize) -> io::Result<Self> {
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
        Ok(Self(slots))
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct Task {
    child: Child,
    lease: Lease,
}

pub fn reserve() -> io::Result<Lease> {
    sender()?;
    Lease::acquire(&ACTIVE_HELPERS)
}

#[expect(
    clippy::mem_forget,
    reason = "A failed handoff must retain the helper slot until process exit"
)]
pub fn submit(child: Child, lease: Lease) {
    let task = Task { child, lease };
    if let Some(sender) = REAPER.get().and_then(Option::as_ref) {
        match sender.try_send(task) {
            Ok(()) => (),
            Err(TrySendError::Full(task) | TrySendError::Disconnected(task)) => {
                // Never free a slot when the child could not be handed to the reaper
                std::mem::forget(task.lease);
            }
        }
    } else {
        std::mem::forget(task.lease);
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
                pending.retain_mut(|task| match task.child.try_wait() {
                    Ok(Some(_)) => false,
                    Err(error) if error.raw_os_error() == Some(nix::libc::ECHILD) => false,
                    _ => {
                        let _ignored = task.child.kill();
                        true
                    }
                });
            }
        })?;
    Ok(sender)
}
