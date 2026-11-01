#![cfg(target_os = "linux")]

use l2_active_linux::{InterfaceSelector, discover};
use std::{
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

#[test]
fn bounded_discovery_honors_cancellation_and_expired_deadline() -> io::Result<()> {
    let selector = InterfaceSelector::new("lo")?;
    let cancelled = AtomicBool::new(true);
    assert_eq!(
        l2_active_linux::discover_until(
            &selector,
            Instant::now() + Duration::from_secs(1),
            &cancelled
        )
        .err()
        .map(|error| error.kind()),
        Some(io::ErrorKind::Interrupted)
    );
    cancelled.store(false, std::sync::atomic::Ordering::Release);
    assert_eq!(
        l2_active_linux::discover_until(&selector, Instant::now(), &cancelled)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert_eq!(
        l2_active_linux::discover_until(
            &selector,
            Instant::now() + Duration::from_secs(1),
            &cancelled
        )?
        .vlan(),
        None
    );
    Ok(())
}
use std::{io, net::Ipv4Addr};

#[test]
fn loopback_discovery_returns_pinned_kernel_identity() -> io::Result<()> {
    let selector = InterfaceSelector::new("lo")?;
    let first = discover(&selector)?;
    let second = discover(&selector)?;
    assert_eq!(first.vlan(), None, "loopback is not a VLAN netdevice");

    assert_eq!(first.name(), "lo");
    assert_eq!(first.identity(), second.identity());
    assert_ne!(first.identity().ifindex(), 0);
    assert!(first.mtu() > 0);
    assert!(
        first
            .ipv4_assignments()
            .iter()
            .any(|item| item.address() == Ipv4Addr::LOCALHOST)
    );
    assert_eq!(first.mac().len(), 6);
    Ok(())
}

#[test]
fn missing_selected_interface_is_reported_without_fallback() -> io::Result<()> {
    let selector = InterfaceSelector::new("l2miss999999999")?;
    let result = discover(&selector);
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::NotFound)
    );
    Ok(())
}
