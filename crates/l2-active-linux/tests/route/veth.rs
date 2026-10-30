use std::{
    error::Error,
    fs, io,
    net::Ipv6Addr,
    os::unix::fs::MetadataExt,
    path::Path,
    process::Command,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

use super::verify_on_link;
use crate::{InterfaceSelector, discover};

#[test]
#[ignore = "uses a proved private user, mount, and network namespace with an owned veth pair"]
fn owned_veth_distinguishes_direct_gateway_and_reject_routes() -> Result<(), Box<dyn Error>> {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/listen/namespace.py");
    let result = Command::new("python3")
        .arg(fixture)
        .arg("--")
        .arg(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "route::veth_tests::owned_namespace_child_checks_kernel_routes",
            "--nocapture",
        ])
        .output()?;
    assert!(
        result.status.success(),
        "route fixture failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("lldp_sent=3 cdp_sent=1 cleanup=true")
    );
    Ok(())
}

#[test]
#[ignore = "invoked only after the namespace fixture proves the owned veth pair"]
fn owned_namespace_child_checks_kernel_routes() -> Result<(), Box<dyn Error>> {
    let parent = (
        std::env::var("L2_TEST_PARENT_NET_DEVICE")?.parse::<u64>()?,
        std::env::var("L2_TEST_PARENT_NET_INODE")?.parse::<u64>()?,
    );
    let current = fs::metadata("/proc/thread-self/ns/net")?;
    assert_ne!((current.dev(), current.ino()), parent);
    assert_eq!(std::env::var("L2_TEST_DISCOVERY_INTERFACE")?, "l2src0");
    let selector = InterfaceSelector::new("l2src0")?;
    let info = discover(&selector)?;
    assert_eq!(
        info.identity().ifindex(),
        std::env::var("L2_MEMBERSHIP_INDEX")?.parse::<u32>()?
    );
    configure_routes()?;
    fs::write(
        std::env::var_os("L2_TEST_DISCOVERY_READY").ok_or("missing ready path")?,
        b"ready",
    )?;
    check_routes(&selector, info.identity())?;
    let sent = std::env::var_os("L2_TEST_DISCOVERY_SENT").ok_or("missing sent path")?;
    let sent = Path::new(&sent);
    let wait_until = Instant::now() + Duration::from_secs(2);
    while !sent.exists() && Instant::now() < wait_until {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        sent.exists(),
        "independent peer did not complete fixture traffic"
    );
    fs::write(
        std::env::var_os("L2_TEST_DISCOVERY_OBSERVED").ok_or("missing observation path")?,
        b"observed",
    )?;
    Ok(())
}

fn configure_routes() -> Result<(), Box<dyn Error>> {
    ip(&[
        "-6",
        "address",
        "add",
        "2001:db8:1::1/64",
        "dev",
        "l2src0",
        "nodad",
        "noprefixroute",
    ])?;
    ip(&[
        "-6",
        "address",
        "add",
        "2001:db8:1::3/64",
        "dev",
        "l2src0",
        "nodad",
        "noprefixroute",
    ])?;
    ip(&["-6", "route", "add", "2001:db8:2::/64", "dev", "l2src0"])?;
    ip(&[
        "-6",
        "route",
        "add",
        "2001:db8:3::/64",
        "via",
        "fe80::2",
        "dev",
        "l2src0",
    ])?;
    ip(&["-6", "route", "add", "prohibit", "2001:db8:4::/64"])?;
    ip(&["-6", "route", "add", "2001:db8:5::/64", "dev", "l2dst0"])?;
    ip(&[
        "-6",
        "route",
        "add",
        "2001:db8:6::/64",
        "dev",
        "l2src0",
        "table",
        "100",
    ])?;
    ip(&[
        "-6",
        "rule",
        "add",
        "from",
        "2001:db8:1::1/128",
        "table",
        "100",
    ])?;
    ip(&[
        "-6",
        "route",
        "add",
        "2001:db8:7::/64",
        "dev",
        "l2src0",
        "table",
        "101",
    ])?;
    ip(&["-6", "rule", "add", "uidrange", "0-0", "table", "101"])?;
    Ok(())
}

fn check_routes(
    selector: &InterfaceSelector,
    identity: l2_capture::LinuxInterfaceIdentity,
) -> Result<(), Box<dyn Error>> {
    let source: Ipv6Addr = "2001:db8:1::1".parse()?;
    let deadline = || Instant::now() + Duration::from_secs(1);
    let cancelled = AtomicBool::new(false);
    let check =
        |source, target| verify_on_link(selector, identity, source, target, deadline(), &cancelled);
    assert!(
        check(source, "2001:db8:2::2".parse()?).is_ok(),
        "direct route must be accepted"
    );
    let gateway = check(source, "2001:db8:3::2".parse()?)
        .err()
        .ok_or("gateway route accepted")?;
    assert_eq!(
        gateway.kind(),
        io::ErrorKind::Unsupported,
        "gateway: {gateway:?}"
    );
    let prohibited = check(source, "2001:db8:4::2".parse()?)
        .err()
        .ok_or("prohibit route accepted")?;
    assert_eq!(
        prohibited.raw_os_error(),
        Some(nix::libc::EACCES),
        "prohibit: {prohibited:?}"
    );
    assert!(
        check(source, "2001:db8:5::2".parse()?).is_err(),
        "different output interface must be rejected"
    );
    let no_route = check(source, "2001:db8:1::2".parse()?)
        .err()
        .ok_or("unrouted assigned prefix accepted")?;
    assert_eq!(
        no_route.raw_os_error(),
        Some(nix::libc::ENETUNREACH),
        "no route: {no_route:?}"
    );
    assert!(
        check(source, "2001:db8:6::2".parse()?).is_ok(),
        "matching source policy route must be accepted"
    );
    assert!(
        check("2001:db8:1::3".parse()?, "2001:db8:6::2".parse()?).is_err(),
        "other source must not inherit the policy route"
    );
    assert!(
        check(source, "2001:db8:7::2".parse()?).is_ok(),
        "matching kernel UID policy route must be accepted"
    );
    Ok(())
}

fn ip(arguments: &[&str]) -> Result<(), Box<dyn Error>> {
    let output = Command::new("ip").args(arguments).output()?;
    if !output.status.success() {
        return Err(io::Error::other(String::from_utf8_lossy(&output.stderr).into_owned()).into());
    }
    Ok(())
}
