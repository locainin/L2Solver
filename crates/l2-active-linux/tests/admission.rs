#![cfg(target_os = "linux")]

use l2_active::{ArpProbe, Limits, dhcp::DhcpProbe, dot1x::Dot1xProbe};
use l2_active_linux::{HelperLink, InterfaceSelector, discover, select_arp_source};
use l2_onpath::MacAddress;
use std::{
    io,
    net::Ipv4Addr,
    path::Path,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

#[test]
fn loopback_cannot_be_admitted_for_an_ethernet_arp_probe() -> io::Result<()> {
    let info = discover(&InterfaceSelector::new("lo")?)?;
    let result = select_arp_source(
        &info,
        Some(Ipv4Addr::LOCALHOST),
        Ipv4Addr::new(192, 0, 2, 1),
    );
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::Unsupported)
    );
    Ok(())
}

#[test]
fn helper_launch_failure_is_returned_without_a_raw_socket_fallback()
-> Result<(), Box<dyn std::error::Error>> {
    let selector = InterfaceSelector::new("lo")?;
    let limits = Limits::new(Duration::from_secs(1), 1, 60)?;
    let source_mac = MacAddress::new([2, 0, 0, 0, 0, 1])?;
    let probe = ArpProbe::new(
        source_mac,
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(192, 0, 2, 2),
        None,
        limits,
    )?;
    let info = discover(&selector)?;
    let result = HelperLink::open(
        Path::new("/proc/self/fd/no-such-active-helper"),
        &selector,
        &info,
        &probe,
        Instant::now() + Duration::from_secs(1),
        &AtomicBool::new(false),
    );
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::NotFound)
    );
    Ok(())
}

#[test]
fn launched_helper_rejects_loopback_before_opening_a_raw_socket()
-> Result<(), Box<dyn std::error::Error>> {
    let selector = InterfaceSelector::new("lo")?;
    let limits = Limits::new(Duration::from_secs(1), 1, 60)?;
    let source_mac = MacAddress::new([2, 0, 0, 0, 0, 1])?;
    let probe = ArpProbe::new(
        source_mac,
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(192, 0, 2, 2),
        None,
        limits,
    )?;
    let info = discover(&selector)?;
    let result = HelperLink::open(
        Path::new(env!("CARGO_BIN_EXE_l2solver-active-helper")),
        &selector,
        &info,
        &probe,
        Instant::now() + Duration::from_secs(1),
        &AtomicBool::new(false),
    );
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::Unsupported)
    );
    Ok(())
}

#[test]
fn cancelled_or_expired_open_never_launches_the_helper() -> Result<(), Box<dyn std::error::Error>> {
    let selector = InterfaceSelector::new("lo")?;
    let info = discover(&selector)?;
    let limits = Limits::new(Duration::from_secs(1), 1, 60)?;
    let source = MacAddress::new([2, 0, 0, 0, 0, 1])?;
    let probe = ArpProbe::new(
        source,
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(192, 0, 2, 2),
        None,
        limits,
    )?;
    let missing = Path::new("/proc/self/fd/no-such-active-helper");
    let cancelled = HelperLink::open(
        missing,
        &selector,
        &info,
        &probe,
        Instant::now() + Duration::from_secs(1),
        &AtomicBool::new(true),
    );
    assert_eq!(
        cancelled.err().map(|error| error.kind()),
        Some(io::ErrorKind::Interrupted)
    );
    let expired = HelperLink::open(
        missing,
        &selector,
        &info,
        &probe,
        Instant::now(),
        &AtomicBool::new(false),
    );
    assert_eq!(
        expired.err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    Ok(())
}

#[test]
fn dhcp_helper_rejects_a_non_ethernet_link_without_sending()
-> Result<(), Box<dyn std::error::Error>> {
    let selector = InterfaceSelector::new("lo")?;
    let info = discover(&selector)?;
    let limits = Limits::new(Duration::from_secs(1), 4, 1024)?;
    let mac = MacAddress::new([2, 0, 0, 0, 0, 1])?;
    let xid = std::num::NonZeroU32::new(1).ok_or("zero xid")?;
    let probe = DhcpProbe::new(mac, xid, None, limits)?;
    let result = HelperLink::open_dhcp(
        Path::new(env!("CARGO_BIN_EXE_l2solver-active-helper")),
        &selector,
        &info,
        &probe,
        Instant::now() + Duration::from_secs(1),
        &AtomicBool::new(false),
    );
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::Unsupported)
    );
    Ok(())
}

#[test]
fn ndp_helper_rejects_a_non_ethernet_link_without_sending() -> Result<(), Box<dyn std::error::Error>>
{
    let selector = InterfaceSelector::new("lo")?;
    let info = l2_active_linux::ndp::discover(&selector)?;
    let limits = Limits::new(Duration::from_secs(1), 4, 1024)?;
    let mac = MacAddress::new([2, 0, 0, 0, 0, 1])?;
    let probe = l2_active::NdpProbe::new(
        mac,
        "fe80::1".parse()?,
        64,
        "fe80::2".parse()?,
        None,
        limits,
    )?;
    let result = HelperLink::open_ndp(
        Path::new(env!("CARGO_BIN_EXE_l2solver-active-helper")),
        &selector,
        &info,
        &probe,
        Instant::now() + Duration::from_secs(1),
        &AtomicBool::new(false),
    );
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::Unsupported)
    );
    Ok(())
}

#[test]
fn dot1x_requires_explicit_dedicated_interface_acknowledgement_before_launch()
-> Result<(), Box<dyn std::error::Error>> {
    let selector = InterfaceSelector::new("lo")?;
    let info = discover(&selector)?;
    let limits = Limits::new(Duration::from_secs(1), 4, 1024)?;
    let probe = Dot1xProbe::new(MacAddress::new([2, 0, 0, 0, 0, 1])?, limits)?;
    let missing = Path::new("/proc/self/fd/no-such-active-helper");
    let cancelled = AtomicBool::new(false);
    for (acknowledged, expected) in [
        (false, io::ErrorKind::PermissionDenied),
        (true, io::ErrorKind::NotFound),
    ] {
        let result = HelperLink::open_dot1x(
            missing,
            &selector,
            &info,
            &probe,
            acknowledged,
            Instant::now() + Duration::from_secs(1),
            &cancelled,
        );
        assert_eq!(result.err().map(|error| error.kind()), Some(expected));
    }
    Ok(())
}
