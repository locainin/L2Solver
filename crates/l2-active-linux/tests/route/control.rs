use std::{
    error::Error,
    io,
    net::Ipv6Addr,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

use super::verify_on_link;
use crate::InterfaceSelector;
use l2_capture::LinuxInterfaceIdentity;

#[test]
fn cancellation_and_expired_deadline_fail_before_interface_discovery() -> Result<(), Box<dyn Error>>
{
    let selector = InterfaceSelector::new("not-a-link")?;
    let identity = LinuxInterfaceIdentity::new(1, 1, 1, 1, 1)?;
    let source: Ipv6Addr = "2001:db8::1".parse()?;
    let target = "2001:db8::2".parse()?;
    let cancelled = AtomicBool::new(true);
    let result = verify_on_link(
        &selector,
        identity,
        source,
        target,
        Instant::now() + Duration::from_secs(1),
        &cancelled,
    );
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::Interrupted)
    );
    let result = verify_on_link(
        &selector,
        identity,
        source,
        target,
        Instant::now(),
        &AtomicBool::new(false),
    );
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    Ok(())
}

#[test]
fn rejects_invalid_targets_before_interface_discovery() -> Result<(), Box<dyn Error>> {
    let selector = InterfaceSelector::new("not-a-link")?;
    let identity = LinuxInterfaceIdentity::new(1, 1, 1, 1, 1)?;
    let source = "2001:db8::1".parse()?;
    for target in [
        Ipv6Addr::UNSPECIFIED,
        Ipv6Addr::LOCALHOST,
        "ff02::1".parse()?,
        source,
    ] {
        let result = verify_on_link(
            &selector,
            identity,
            source,
            target,
            Instant::now() + Duration::from_secs(1),
            &AtomicBool::new(false),
        );
        assert_eq!(
            result.err().map(|error| error.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
    }
    Ok(())
}
