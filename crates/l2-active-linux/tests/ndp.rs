#![cfg(target_os = "linux")]

use std::{fs, io, net::Ipv6Addr, time::Duration};

use l2_active::Limits;
use l2_active_linux::{InterfaceSelector, ndp};

#[test]
fn loopback_ipv6_snapshot_is_bound_to_the_selected_interface() -> io::Result<()> {
    let selector = InterfaceSelector::new("lo")?;
    let records = match fs::read_to_string("/proc/thread-self/net/if_inet6") {
        Ok(records) => records,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            assert_eq!(
                ndp::discover(&selector).err().map(|error| error.kind()),
                Some(io::ErrorKind::Unsupported)
            );
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let snapshot = ndp::discover(&selector)?;
    assert_eq!(snapshot.interface().name(), "lo");
    assert_ne!(snapshot.interface().identity().ifindex(), 0);
    let kernel_reports_loopback = records.lines().any(|line| {
        let mut fields = line.split_ascii_whitespace();
        fields.next() == Some("00000000000000000000000000000001") && fields.last() == Some("lo")
    });
    assert_eq!(
        snapshot
            .assignments()
            .iter()
            .any(|assignment| assignment.address() == Ipv6Addr::LOCALHOST),
        kernel_reports_loopback
    );
    let limits = Limits::new(Duration::from_millis(20), 4, 512).map_err(io::Error::other)?;
    let result = ndp::prepare(
        &snapshot,
        None,
        "fe80::2".parse().map_err(io::Error::other)?,
        None,
        limits,
    );
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::Unsupported)
    );
    Ok(())
}
