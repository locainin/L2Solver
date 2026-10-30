use super::{Lease, MAX_ACTIVE_HELPERS, sender, submit};
use std::{
    io,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

static TEST_SLOTS: AtomicUsize = AtomicUsize::new(0);
static CHILD_SLOTS: AtomicUsize = AtomicUsize::new(0);

#[test]
fn outstanding_workers_cannot_exceed_the_fixed_slot_limit() -> io::Result<()> {
    let mut leases = Vec::new();
    for _ in 0..MAX_ACTIVE_HELPERS {
        leases.push(Lease::acquire(&TEST_SLOTS)?);
    }
    assert_eq!(
        Lease::acquire(&TEST_SLOTS).err().map(|error| error.kind()),
        Some(io::ErrorKind::WouldBlock)
    );
    drop(leases.pop());
    assert!(Lease::acquire(&TEST_SLOTS).is_ok());
    Ok(())
}

#[test]
fn reaper_releases_the_slot_only_after_the_child_is_gone() -> io::Result<()> {
    sender()?;
    let lease = Lease::acquire(&CHILD_SLOTS)?;
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
