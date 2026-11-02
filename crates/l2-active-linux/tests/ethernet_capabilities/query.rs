use std::{
    io,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

use crate::{
    InterfaceSelector,
    ethernet_capabilities::{self, Capability, UnknownReason},
};

#[test]
fn cancellation_and_elapsed_deadline_stop_before_the_query()
-> Result<(), Box<dyn std::error::Error>> {
    let selector = InterfaceSelector::new("lo")?;
    let identity = crate::discover(&selector)?.identity();
    let cancelled = AtomicBool::new(true);
    let error = ethernet_capabilities::discover(
        &selector,
        identity,
        Instant::now() + Duration::from_secs(1),
        &cancelled,
    )
    .err()
    .ok_or("cancelled query must fail")?;
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    let error = ethernet_capabilities::discover(
        &selector,
        identity,
        Instant::now(),
        &AtomicBool::new(false),
    )
    .err()
    .ok_or("expired query must fail")?;
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    Ok(())
}

#[test]
fn different_selected_identity_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let selector = InterfaceSelector::new("lo")?;
    let identity = crate::discover(&selector)?.identity();
    let mismatched = l2_capture::LinuxInterfaceIdentity::new(
        identity.namespace_device(),
        identity.namespace_inode(),
        identity.interface_device(),
        identity.interface_inode(),
        identity
            .ifindex()
            .checked_add(1)
            .ok_or("interface index overflow")?,
    )?;
    let result = ethernet_capabilities::discover(
        &selector,
        mismatched,
        Instant::now() + Duration::from_secs(2),
        &AtomicBool::new(false),
    );
    assert!(
        result.is_err(),
        "a snapshot of another interface must not be admitted"
    );
    Ok(())
}

#[test]
fn loopback_produces_kernel_evidence_or_an_explicit_unavailable_state()
-> Result<(), Box<dyn std::error::Error>> {
    let selector = InterfaceSelector::new("lo")?;
    let identity = crate::discover(&selector)?.identity();
    let report = ethernet_capabilities::discover(
        &selector,
        identity,
        Instant::now() + Duration::from_secs(3),
        &AtomicBool::new(false),
    )?;
    assert_eq!(report.identity, identity);
    // A malformed reply must not be mislabeled as kernel support or denial
    assert_ne!(
        report.vlan.ctag_rx,
        Capability::Unknown(UnknownReason::InvalidResponse)
    );
    assert_ne!(
        report.timestamps.tx_software,
        Capability::Unknown(UnknownReason::InvalidResponse)
    );
    Ok(())
}

#[test]
fn query_failures_preserve_denied_unsupported_and_unknown_distinctions()
-> Result<(), Box<dyn std::error::Error>> {
    use super::classify;

    for code in [nix::libc::EPERM, nix::libc::EACCES] {
        assert_eq!(
            classify(io::Error::from_raw_os_error(code), false)?.capability::<()>(),
            Capability::Denied
        );
    }
    assert_eq!(
        classify(io::Error::from_raw_os_error(nix::libc::EOPNOTSUPP), false)?.capability::<()>(),
        Capability::Unsupported
    );
    assert_eq!(
        classify(io::Error::from_raw_os_error(nix::libc::ENOENT), true)?.capability::<()>(),
        Capability::Unknown(UnknownReason::KernelApiUnavailable)
    );
    assert_eq!(
        classify(io::Error::from_raw_os_error(nix::libc::ENOENT), false)?.capability::<()>(),
        Capability::Unknown(UnknownReason::QueryFailed(Some(nix::libc::ENOENT)))
    );
    assert_eq!(
        classify(
            io::Error::new(io::ErrorKind::InvalidData, "bad reply"),
            false
        )?
        .capability::<()>(),
        Capability::Unknown(UnknownReason::InvalidResponse)
    );
    for kind in [io::ErrorKind::Interrupted, io::ErrorKind::TimedOut] {
        assert_eq!(
            classify(io::Error::from(kind), false)
                .err()
                .map(|error| error.kind()),
            Some(kind)
        );
    }
    Ok(())
}

#[test]
fn loopback_advertisements_match_independent_ethtool_queries()
-> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    let selector = InterfaceSelector::new("lo")?;
    let identity = crate::discover(&selector)?.identity();
    let report = ethernet_capabilities::discover(
        &selector,
        identity,
        Instant::now() + Duration::from_secs(3),
        &AtomicBool::new(false),
    )?;
    let features = Command::new("ethtool")
        .args(["--show-features", "lo"])
        .output()?;
    assert!(
        features.status.success(),
        "{}",
        String::from_utf8_lossy(&features.stderr)
    );
    let text = std::str::from_utf8(&features.stdout)?;
    for (name, result) in [
        ("rx-vlan-offload", report.vlan.ctag_rx),
        ("tx-vlan-offload", report.vlan.ctag_tx),
        ("rx-vlan-filter", report.vlan.ctag_filter),
        ("rx-vlan-stag-hw-parse", report.vlan.stag_rx),
        ("tx-vlan-stag-hw-insert", report.vlan.stag_tx),
        ("rx-vlan-stag-filter", report.vlan.stag_filter),
    ] {
        let line = text
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with(&format!("{name}:")))
            .ok_or("ethtool feature missing")?;
        let state = line
            .split_once(':')
            .ok_or("ethtool feature lacks separator")?
            .1
            .trim_start();
        let expected = state
            .split_whitespace()
            .next()
            .ok_or("ethtool feature lacks state")?;
        let Capability::Reported(result) = result else {
            return Err(format!("feature {name} unavailable: {result:?}").into());
        };
        assert_eq!(result.active, expected == "on", "feature {name}");
    }
    let timestamp = Command::new("ethtool")
        .args(["--show-time-stamping", "lo"])
        .output()?;
    assert!(
        timestamp.status.success(),
        "{}",
        String::from_utf8_lossy(&timestamp.stderr)
    );
    let text = std::str::from_utf8(&timestamp.stdout)?;
    for (name, result) in [
        ("software-transmit", report.timestamps.tx_software),
        ("software-receive", report.timestamps.rx_software),
        ("hardware-transmit", report.timestamps.tx_hardware),
        ("hardware-receive", report.timestamps.rx_hardware),
    ] {
        assert_eq!(
            result,
            Capability::Reported(text.lines().any(|line| line.trim() == name)),
            "timestamp {name}"
        );
    }
    let clock = text
        .lines()
        .find_map(|line| line.strip_prefix("PTP Hardware Clock: "))
        .ok_or("ethtool clock line missing")?;
    let expected = if clock == "none" {
        None
    } else {
        Some(clock.parse::<u32>()?)
    };
    assert_eq!(report.timestamps.phc_index, Capability::Reported(expected));
    Ok(())
}
