use std::{io, sync::atomic::AtomicBool};

use super::cancelled_discovery;
use crate::Error;

#[test]
fn interrupted_discovery_is_cancelled_only_when_cancellation_was_requested() {
    let interrupted = || Error::Discovery(io::Error::new(io::ErrorKind::Interrupted, "stopped"));
    assert!(matches!(
        cancelled_discovery::<()>(Err(interrupted()), &AtomicBool::new(true)),
        Ok(None)
    ));
    assert!(matches!(
        cancelled_discovery::<()>(Err(interrupted()), &AtomicBool::new(false)),
        Err(Error::Discovery(_))
    ));
    let missing = Error::Discovery(io::Error::new(io::ErrorKind::NotFound, "missing"));
    assert!(matches!(
        cancelled_discovery::<()>(Err(missing), &AtomicBool::new(true)),
        Err(Error::Discovery(_))
    ));
    assert!(matches!(
        cancelled_discovery(Ok(4), &AtomicBool::new(false)),
        Ok(Some(4))
    ));
}
