use super::{Gate, ResourceScope};
use std::{
    num::NonZeroU64,
    time::{Duration, Instant},
};

#[test]
fn unsupported_scope_never_releases() -> Result<(), Box<dyn std::error::Error>> {
    let limit = NonZeroU64::new(4096).ok_or("invalid test limit")?;
    assert!(ResourceScope::new(limit, 0, limit, Duration::from_secs(1)).is_err());
    let mut gate = Gate;
    assert!(gate.claim().is_err());
    assert!(gate.verify(1).is_err());
    let file = tempfile::tempfile()?;
    assert!(gate.verify_member(&file).is_err());
    assert!(gate.request_freeze().is_err());
    assert!(gate.poll_frozen().is_err());
    assert!(gate.verify_only_members(1).is_err());
    assert!(gate.stop_verified_scope(Instant::now()).is_err());
    assert!(gate.receipt().is_none());
    Ok(())
}
