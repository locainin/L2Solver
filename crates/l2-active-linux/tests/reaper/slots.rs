use super::{Lease, MAX_ACTIVE_HELPERS, Retention, sender, start, submit, submit_with_sender};
use nix::{
    errno::Errno,
    sys::wait::{WaitPidFlag, WaitStatus, waitpid},
    unistd::Pid,
};
use std::{
    cell::Cell,
    io,
    os::fd::AsRawFd,
    process::{Child, Command, Stdio},
    sync::{
        OnceLock,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

static TEST_SLOTS: AtomicUsize = AtomicUsize::new(0);
static CHILD_SLOTS: AtomicUsize = AtomicUsize::new(0);
static KILLED_SLOTS: AtomicUsize = AtomicUsize::new(0);
static LIVE_SLOTS: AtomicUsize = AtomicUsize::new(0);
static UNKNOWN_SLOTS: AtomicUsize = AtomicUsize::new(0);
static BACKGROUND_UNKNOWN_SLOTS: AtomicUsize = AtomicUsize::new(0);
static DROP_UNKNOWN_SLOTS: AtomicUsize = AtomicUsize::new(0);
static TEST_RETENTION: OnceLock<Retention> = OnceLock::new();
static KILLED_RETENTION: OnceLock<Retention> = OnceLock::new();
static LIVE_RETENTION: OnceLock<Retention> = OnceLock::new();
static UNKNOWN_RETENTION: OnceLock<Retention> = OnceLock::new();
static BACKGROUND_UNKNOWN_RETENTION: OnceLock<Retention> = OnceLock::new();
static DROP_UNKNOWN_RETENTION: OnceLock<Retention> = OnceLock::new();

thread_local! {
    static REAP_OPERATIONS: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
    static OBSERVED_HANDOFFS: Cell<Option<usize>> = const { Cell::new(None) };
}

pub(super) fn record_handoff() {
    OBSERVED_HANDOFFS.update(|count| count.map(|value| value + 1));
}

pub fn start_handoff_observation() {
    OBSERVED_HANDOFFS.set(Some(0));
}

pub fn finish_handoff_observation() -> Option<usize> {
    OBSERVED_HANDOFFS.replace(None)
}

pub fn drop_unknown_lease() -> io::Result<Lease> {
    Lease::acquire(
        &DROP_UNKNOWN_SLOTS,
        DROP_UNKNOWN_RETENTION.get_or_init(Retention::new),
    )
}

pub fn drop_unknown_slots() -> usize {
    DROP_UNKNOWN_SLOTS.load(Ordering::Acquire)
}

pub fn take_drop_unknown() -> io::Result<(Child, Lease)> {
    let retention = DROP_UNKNOWN_RETENTION.get_or_init(Retention::new);
    let Retention {
        _receiver: receiver,
        ..
    } = retention;
    let task = receiver
        .lock()
        .map_err(|_| io::Error::other("retention lock poisoned"))?
        .try_recv()
        .map_err(io::Error::other)?;
    Ok((task.child, task.lease))
}

pub(super) fn record_wait() {
    REAP_OPERATIONS.update(|(waits, kills)| (waits + 1, kills));
}

pub(super) fn record_kill() {
    REAP_OPERATIONS.update(|(waits, kills)| (waits, kills + 1));
}

#[test]
fn outstanding_workers_cannot_exceed_the_fixed_slot_limit() -> io::Result<()> {
    let retention = TEST_RETENTION.get_or_init(Retention::new);
    let mut leases = Vec::new();
    for _ in 0..MAX_ACTIVE_HELPERS {
        leases.push(Lease::acquire(&TEST_SLOTS, retention)?);
    }
    assert_eq!(
        Lease::acquire(&TEST_SLOTS, retention)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::WouldBlock)
    );
    drop(leases.pop());
    assert!(Lease::acquire(&TEST_SLOTS, retention).is_ok());
    Ok(())
}

#[test]
fn reaper_releases_the_slot_only_after_the_child_is_gone() -> io::Result<()> {
    sender()?;
    let retention = TEST_RETENTION.get_or_init(Retention::new);
    let lease = Lease::acquire(&CHILD_SLOTS, retention)?;
    let child = Command::new("sleep").arg("60").spawn()?;
    let pid = child.id();
    submit(child, lease);
    let deadline = Instant::now() + Duration::from_secs(3);
    while CHILD_SLOTS.load(Ordering::Acquire) != 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        CHILD_SLOTS.load(Ordering::Acquire),
        0,
        "child was not reaped before the test deadline"
    );
    assert!(
        !std::path::Path::new("/proc").join(pid.to_string()).exists(),
        "reaped child still appears in procfs"
    );
    Ok(())
}

fn check_disconnected_handoff(
    child: Child,
    slots: &'static AtomicUsize,
    retention: &'static Retention,
) -> io::Result<()> {
    let (sender, receiver) = mpsc::sync_channel(1);
    drop(receiver);
    let lease = Lease::acquire(slots, retention)?;
    let pid = Pid::from_raw(i32::try_from(child.id()).map_err(io::Error::other)?);
    let start = Instant::now();
    submit_with_sender(child, lease, Some(&sender));
    let elapsed = start.elapsed();

    // A heavily delayed child can remain safely owned after the bounded attempt
    let Retention {
        _receiver: receiver,
        ..
    } = retention;
    let retained = receiver
        .lock()
        .map_err(|_| io::Error::other("retention lock poisoned"))?
        .try_recv()
        .ok();
    if let Some(mut task) = retained {
        assert_eq!(
            slots.load(Ordering::Acquire),
            1,
            "retained child lost its slot"
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if task.child.try_wait()?.is_some() {
                break;
            }
            if Instant::now() >= deadline {
                retention.sender.try_send(task).map_err(io::Error::other)?;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "killed child did not exit",
                ));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        drop(task);
    } else {
        let deadline = Instant::now() + Duration::from_secs(3);
        let outcome = loop {
            match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                outcome => break outcome,
            }
        };
        assert_eq!(
            outcome,
            Err(Errno::ECHILD),
            "failed handoff left the child unreaped"
        );
    }
    assert!(
        elapsed < Duration::from_millis(500),
        "failed handoff blocked teardown: {elapsed:?}"
    );
    assert_eq!(
        slots.load(Ordering::Acquire),
        0,
        "reaped child retained its slot"
    );
    Ok(())
}

#[test]
fn disconnected_handoff_reaps_an_already_killed_child_within_a_bound() -> io::Result<()> {
    let mut child = Command::new("sleep").arg("60").spawn()?;
    child.kill()?;
    check_disconnected_handoff(
        child,
        &KILLED_SLOTS,
        KILLED_RETENTION.get_or_init(Retention::new),
    )
}

#[test]
fn disconnected_handoff_kills_a_live_child_within_a_bound() -> io::Result<()> {
    // Closing the owned input also releases the child if handoff regresses
    let child = Command::new("sh")
        .args(["-c", "read -r line"])
        .stdin(Stdio::piped())
        .spawn()?;
    REAP_OPERATIONS.set((0, 0));
    check_disconnected_handoff(
        child,
        &LIVE_SLOTS,
        LIVE_RETENTION.get_or_init(Retention::new),
    )?;
    assert!(
        REAP_OPERATIONS.get().1 > 0,
        "a live child was never sent a kill signal"
    );
    Ok(())
}

#[test]
fn disconnected_handoff_retains_child_and_slot_when_wait_status_is_unavailable() -> io::Result<()> {
    let (sender, receiver) = mpsc::sync_channel(1);
    drop(receiver);
    let retention = UNKNOWN_RETENTION.get_or_init(Retention::new);
    let lease = Lease::acquire(&UNKNOWN_SLOTS, retention)?;
    let mut child = Command::new("sleep")
        .arg("60")
        .stdout(Stdio::piped())
        .spawn()?;
    let descriptor = child
        .stdout
        .as_ref()
        .ok_or_else(|| io::Error::other("missing child stdout"))?
        .as_raw_fd();
    let descriptor_path = std::path::Path::new("/proc/self/fd").join(descriptor.to_string());
    let identity = std::fs::read_link(&descriptor_path)?;
    let pid = Pid::from_raw(i32::try_from(child.id()).map_err(io::Error::other)?);
    child.kill()?;
    waitpid(pid, None).map_err(io::Error::other)?;

    // An outside waiter consumed the status, so the Child cannot confirm exit
    REAP_OPERATIONS.set((0, 0));
    submit_with_sender(child, lease, Some(&sender));
    let Retention {
        _receiver: receiver,
        ..
    } = retention;
    let task = receiver
        .lock()
        .map_err(|_| io::Error::other("retention lock poisoned"))?
        .try_recv()
        .map_err(io::Error::other)?;
    assert_eq!(
        REAP_OPERATIONS.get(),
        (1, 0),
        "PID was used again after an unavailable wait status"
    );
    assert_eq!(
        UNKNOWN_SLOTS.load(Ordering::Acquire),
        1,
        "unconfirmed termination released the slot"
    );
    assert_eq!(
        std::fs::read_link(descriptor_path).ok().as_ref(),
        Some(&identity),
        "unconfirmed termination dropped the child handle"
    );
    drop(task);
    assert_eq!(
        UNKNOWN_SLOTS.load(Ordering::Acquire),
        0,
        "retrieved task did not release its slot"
    );
    Ok(())
}

#[test]
fn background_reaper_retains_child_and_slot_when_wait_status_is_unavailable() -> io::Result<()> {
    let reaper = start()?;
    let retention = BACKGROUND_UNKNOWN_RETENTION.get_or_init(Retention::new);
    let lease = Lease::acquire(&BACKGROUND_UNKNOWN_SLOTS, retention)?;
    let mut child = Command::new("sleep")
        .arg("60")
        .stdout(Stdio::piped())
        .spawn()?;
    let descriptor = child
        .stdout
        .as_ref()
        .ok_or_else(|| io::Error::other("missing child stdout"))?
        .as_raw_fd();
    let descriptor_path = std::path::Path::new("/proc/self/fd").join(descriptor.to_string());
    let identity = std::fs::read_link(&descriptor_path)?;
    let pid = Pid::from_raw(i32::try_from(child.id()).map_err(io::Error::other)?);
    child.kill()?;
    waitpid(pid, None).map_err(io::Error::other)?;

    // The real worker must transfer an unavailable status to retained ownership
    submit_with_sender(child, lease, Some(&reaper));
    let Retention {
        _receiver: receiver,
        ..
    } = retention;
    let deadline = Instant::now() + Duration::from_secs(3);
    let task = loop {
        let queued = receiver
            .lock()
            .map_err(|_| io::Error::other("retention lock poisoned"))?
            .try_recv();
        match queued {
            Ok(task) => break Some(task),
            Err(mpsc::TryRecvError::Empty)
                if BACKGROUND_UNKNOWN_SLOTS.load(Ordering::Acquire) != 0
                    && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected) => break None,
        }
    };
    assert_eq!(
        BACKGROUND_UNKNOWN_SLOTS.load(Ordering::Acquire),
        1,
        "unconfirmed termination released the slot"
    );
    assert_eq!(
        std::fs::read_link(descriptor_path).ok().as_ref(),
        Some(&identity),
        "unconfirmed termination dropped the child handle"
    );
    let task = task.ok_or_else(|| io::Error::other("background reaper did not retain the task"))?;
    drop(task);
    assert_eq!(
        BACKGROUND_UNKNOWN_SLOTS.load(Ordering::Acquire),
        0,
        "retrieved task did not release its slot"
    );
    Ok(())
}
