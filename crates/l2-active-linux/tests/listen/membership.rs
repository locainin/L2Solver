use std::{error::Error, io};

use super::{DISCOVERY_GROUPS, MembershipError, checked_ifindex, join_groups};

#[path = "../support/child_mode.rs"]
mod child_mode;

#[test]
fn joins_exactly_the_four_required_multicast_groups_in_order() -> Result<(), Box<dyn Error>> {
    let mut joined = Vec::new();
    join_groups(DISCOVERY_GROUPS, |address| {
        joined.push(address);
        Ok(())
    })?;
    assert_eq!(
        joined,
        [
            [1, 0x80, 0xc2, 0, 0, 14],
            [1, 0x80, 0xc2, 0, 0, 3],
            [1, 0x80, 0xc2, 0, 0, 0],
            [1, 0, 0x0c, 0xcc, 0xcc, 0xcc],
        ]
    );
    assert_eq!(joined.as_slice(), DISCOVERY_GROUPS.as_slice());
    Ok(())
}

#[test]
fn partial_membership_failure_names_the_group_and_stops_further_joins() -> Result<(), Box<dyn Error>>
{
    let mut attempts = 0_usize;
    let result = join_groups(DISCOVERY_GROUPS, |_| {
        attempts += 1;
        if attempts == 3 {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        } else {
            Ok(())
        }
    });
    assert_eq!(attempts, 3);
    let Err(MembershipError::Join {
        joined,
        address,
        source,
    }) = result
    else {
        return Err("the third membership should have failed".into());
    };
    assert_eq!(joined, 2);
    assert_eq!(address, [1, 0x80, 0xc2, 0, 0, 0]);
    assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
    Ok(())
}

#[test]
fn rejects_zero_or_unrepresentable_interface_indices() {
    assert_eq!(
        checked_ifindex(0).err().map(|error| error.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    assert_eq!(
        checked_ifindex(u32::MAX).err().map(|error| error.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    assert_eq!(checked_ifindex(1).ok(), Some(1));
}

#[test]
fn owned_veth_memberships_are_released_on_socket_close() -> Result<(), Box<dyn Error>> {
    if child_mode::selected(
        "listen::membership::tests::owned_veth_memberships_are_released_on_socket_close",
    )? {
        return owned_namespace_child_joins_and_releases_only_fixed_groups();
    }
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/listen/namespace.py");
    let output = std::process::Command::new("python3")
        .arg(script)
        .arg(std::env::current_exe()?)
        .output()?;
    assert!(
        output.status.success(),
        "fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("memberships=true cleanup=true"));
    Ok(())
}

fn owned_namespace_child_joins_and_releases_only_fixed_groups() -> Result<(), Box<dyn Error>> {
    use super::{join_discovery, join_pae, join_stp};
    use rscap::{
        Interface,
        linux::{addr::L2Protocol, l2::L2Socket},
    };
    use std::{
        os::{fd::AsRawFd, unix::fs::MetadataExt},
        path::Path,
    };

    let parent_device: u64 = std::env::var("L2_MEMBERSHIP_PARENT_DEVICE")?.parse()?;
    let parent_inode: u64 = std::env::var("L2_MEMBERSHIP_PARENT_INODE")?.parse()?;
    let child = std::fs::metadata("/proc/thread-self/ns/net")?;
    assert_ne!((child.dev(), child.ino()), (parent_device, parent_inode));
    let ifindex: u32 = std::env::var("L2_MEMBERSHIP_INDEX")?.parse()?;
    assert_eq!(nix::net::if_::if_nametoindex("l2src0")?, ifindex);
    let peer: u32 = std::env::var("L2_MEMBERSHIP_PEER_INDEX")?.parse()?;
    let before = membership_entries(ifindex)?;
    let before_flags = interface_flags()?;
    for address in DISCOVERY_GROUPS {
        assert!(!before.contains(&address));
    }

    let rejected = L2Socket::new()?;
    rejected.bind(
        Interface::new("l2src0")?,
        L2Protocol::Other(u16::try_from(nix::libc::ETH_P_ALL)?.to_be()),
    )?;
    let rejected_fd = rejected.as_raw_fd();
    assert!(matches!(
        join_discovery(rejected, peer),
        Err(MembershipError::Binding(_))
    ));
    assert!(!Path::new(&format!("/proc/self/fd/{rejected_fd}")).exists());
    assert_eq!(membership_entries(ifindex)?, before);

    let socket = L2Socket::new()?;
    socket.bind(
        Interface::new("l2src0")?,
        L2Protocol::Other(u16::try_from(nix::libc::ETH_P_ALL)?.to_be()),
    )?;
    let joined = join_discovery(socket, ifindex)?;
    let during = membership_entries(ifindex)?;
    for address in DISCOVERY_GROUPS {
        assert!(during.contains(&address), "missing group {address:02x?}");
    }
    assert_eq!(
        interface_flags()? & 0x300,
        before_flags & 0x300,
        "membership must not enable promiscuous or all-multicast mode"
    );
    drop(joined);
    assert_eq!(
        membership_entries(ifindex)?,
        before,
        "socket close must release the memberships"
    );
    assert_eq!(interface_flags()? & 0x300, before_flags & 0x300);

    check_single_group(
        ifindex,
        &before,
        before_flags,
        [1, 0x80, 0xc2, 0, 0, 0],
        join_stp,
    )?;
    check_single_group(
        ifindex,
        &before,
        before_flags,
        [1, 0x80, 0xc2, 0, 0, 3],
        join_pae,
    )?;
    Ok(())
}

fn check_single_group(
    ifindex: u32,
    before: &[[u8; 6]],
    before_flags: u32,
    group: [u8; 6],
    join: fn(
        rscap::linux::l2::L2Socket,
        u32,
    ) -> Result<rscap::linux::l2::L2Socket, MembershipError>,
) -> Result<(), Box<dyn Error>> {
    use rscap::{
        Interface,
        linux::{addr::L2Protocol, l2::L2Socket},
    };

    let socket = L2Socket::new()?;
    socket.bind(
        Interface::new("l2src0")?,
        L2Protocol::Other(u16::try_from(nix::libc::ETH_P_ALL)?.to_be()),
    )?;
    let joined = join(socket, ifindex)?;
    let mut expected = before.to_vec();
    expected.push(group);
    expected.sort_unstable();
    assert_eq!(membership_entries(ifindex)?, expected);
    assert_eq!(interface_flags()? & 0x300, before_flags & 0x300);
    drop(joined);
    assert_eq!(membership_entries(ifindex)?, before);
    Ok(())
}

fn membership_entries(index: u32) -> Result<Vec<[u8; 6]>, Box<dyn Error>> {
    let mut addresses = Vec::new();
    for line in std::fs::read_to_string("/proc/net/dev_mcast")?.lines() {
        let mut fields = line.split_whitespace();
        let Some(found) = fields.next().and_then(|field| field.parse::<u32>().ok()) else {
            continue;
        };
        if found != index {
            continue;
        }
        let Some(value) = fields.nth(3) else {
            return Err("incomplete multicast entry".into());
        };
        if value.len() != 12 {
            continue;
        }
        let bytes = value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
            .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
        addresses.push(<[u8; 6]>::try_from(bytes).map_err(|_| "invalid multicast address")?);
    }
    addresses.sort_unstable();
    Ok(addresses)
}

fn interface_flags() -> Result<u32, Box<dyn Error>> {
    let raw = std::fs::read_to_string("/sys/class/net/l2src0/flags")?;
    Ok(u32::from_str_radix(
        raw.trim().trim_start_matches("0x"),
        16,
    )?)
}

#[test]
fn discovery_fixture_rejects_a_receiver_that_never_arms() -> Result<(), Box<dyn Error>> {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/listen/namespace.py");
    let result = std::process::Command::new("python3")
        .arg(script)
        .args(["--", "python3", "-c", "pass"])
        .output()?;
    assert!(
        !result.status.success(),
        "a silent receiver must fail the fixture"
    );
    assert!(String::from_utf8_lossy(&result.stderr).contains("exited before readiness"));
    Ok(())
}

#[test]
fn discovery_fixture_delivers_four_independent_link_local_frames() -> Result<(), Box<dyn Error>> {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/listen");
    let result = std::process::Command::new("python3")
        .arg(base.join("namespace.py"))
        .arg("--")
        .arg("python3")
        .arg(base.join("independent_receiver.py"))
        .output()?;
    assert!(
        result.status.success(),
        "fixture failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("lldp_sent=3 cdp_sent=1 cleanup=true")
    );
    Ok(())
}

#[test]
fn discovery_fixture_rejects_readiness_without_confirmed_observation() -> Result<(), Box<dyn Error>>
{
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/listen/namespace.py");
    let receiver = "import os; from pathlib import Path; Path(os.environ['L2_TEST_DISCOVERY_READY']).write_text('ready')";
    let result = std::process::Command::new("python3")
        .arg(script)
        .args(["--", "python3", "-c", receiver])
        .output()?;
    assert!(
        !result.status.success(),
        "readiness without frame observations must fail"
    );
    assert!(String::from_utf8_lossy(&result.stderr).contains("observation acknowledgement"));
    Ok(())
}
