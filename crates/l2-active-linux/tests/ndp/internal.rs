use std::{error::Error, io, net::Ipv6Addr, time::Duration};

use l2_active::Limits;
use l2_capture::LinuxInterfaceIdentity;

use super::{Ipv6Assignment, NdpInterfaceInfo, discovery::parse_snapshot, prepare};
use crate::InterfaceInfo;

const SOURCE: &str = "fe80::1";
const TARGET: &str = "fe80::2";

fn assignment(
    address: &str,
    prefix_len: u8,
    scope: u8,
    flags: u8,
) -> Result<Ipv6Assignment, Box<dyn Error>> {
    Ok(Ipv6Assignment {
        address: address.parse()?,
        prefix_len,
        scope,
        flags,
    })
}

fn fixture(assignments: Vec<Ipv6Assignment>) -> Result<NdpInterfaceInfo, Box<dyn Error>> {
    Ok(NdpInterfaceInfo {
        interface: InterfaceInfo {
            name: "veth0".into(),
            identity: LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?,
            mac: [2, 0, 0, 0, 0, 1],
            mtu: 1500,
            flags: 0x1001,
            hardware_type: 1,
            assignments: Vec::new(),
        },
        assignments,
    })
}

fn limits() -> Result<Limits, Box<dyn Error>> {
    Ok(Limits::new(Duration::from_millis(20), 8, 1024)?)
}

#[test]
fn one_usable_assigned_source_supplies_the_prefix_for_the_probe() -> Result<(), Box<dyn Error>> {
    let info = fixture(vec![assignment(SOURCE, 64, 0x20, 0x80)?])?;
    let probe = prepare(&info, None, TARGET.parse()?, None, limits()?)?;
    assert_eq!(probe.source_ip(), SOURCE.parse::<Ipv6Addr>()?);
    assert_eq!(probe.prefix_len(), 64);
    assert_eq!(probe.target(), TARGET.parse::<Ipv6Addr>()?);
    Ok(())
}

#[test]
fn interface_at_the_minimum_ipv6_mtu_can_prepare_a_probe() -> Result<(), Box<dyn Error>> {
    let mut info = fixture(vec![assignment(SOURCE, 64, 0x20, 0x80)?])?;
    info.interface.mtu = 1280;
    let probe = prepare(&info, None, TARGET.parse()?, None, limits()?)?;
    assert_eq!(probe.source_ip(), SOURCE.parse::<Ipv6Addr>()?);
    Ok(())
}

#[test]
fn unusable_flags_unassigned_sources_and_off_link_targets_fail_closed() -> Result<(), Box<dyn Error>>
{
    for flag in [0x04, 0x08, 0x20, 0x40] {
        let info = fixture(vec![assignment(SOURCE, 64, 0x20, flag)?])?;
        assert_eq!(
            prepare(&info, None, TARGET.parse()?, None, limits()?)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
        assert_eq!(
            prepare(
                &info,
                Some(SOURCE.parse()?),
                TARGET.parse()?,
                None,
                limits()?
            )
            .err()
            .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
    }
    let info = fixture(vec![assignment(SOURCE, 64, 0x20, 0x80)?])?;
    for (source, target) in [
        (Some("fe80::9".parse()?), TARGET.parse()?),
        (None, "fe80:0:0:1::2".parse()?),
        (None, SOURCE.parse()?),
    ] {
        assert_eq!(
            prepare(&info, source, target, None, limits()?)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
    }
    Ok(())
}

#[test]
fn multiple_eligible_sources_require_an_explicit_assigned_choice() -> Result<(), Box<dyn Error>> {
    let info = fixture(vec![
        assignment(SOURCE, 64, 0x20, 0x80)?,
        assignment("fe80::3", 64, 0x20, 0x01)?,
    ])?;
    let target = TARGET.parse()?;
    assert_eq!(
        prepare(&info, None, target, None, limits()?)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    let source = "fe80::3".parse()?;
    assert_eq!(
        prepare(&info, Some(source), target, None, limits()?)?.source_ip(),
        source
    );
    Ok(())
}

#[test]
fn matching_global_prefix_does_not_establish_an_on_link_target() -> Result<(), Box<dyn Error>> {
    let info = fixture(vec![assignment("2001:db8::1", 64, 0, 0x80)?])?;
    let source = "2001:db8::1".parse()?;
    let target = "2001:db8::2".parse()?;
    for requested in [None, Some(source)] {
        assert_eq!(
            prepare(&info, requested, target, None, limits()?)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::Unsupported)
        );
    }
    assert_eq!(
        prepare(&info, Some(source), TARGET.parse()?, None, limits()?)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::Unsupported)
    );
    Ok(())
}

#[test]
fn unsuitable_link_or_inconsistent_address_scope_is_rejected() -> Result<(), Box<dyn Error>> {
    for (hardware_type, flags, mtu) in [
        (0, 0x1001, 1500),
        (1, 0x1000, 1500),
        (1, 1, 1500),
        (1, 0x1001, 1279),
    ] {
        let mut info = fixture(vec![assignment(SOURCE, 64, 0x20, 0x80)?])?;
        info.interface.hardware_type = hardware_type;
        info.interface.flags = flags;
        info.interface.mtu = mtu;
        assert_eq!(
            prepare(&info, None, TARGET.parse()?, None, limits()?)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::Unsupported)
        );
    }
    let info = fixture(vec![assignment(SOURCE, 64, 0, 0x80)?])?;
    assert_eq!(
        prepare(&info, None, TARGET.parse()?, None, limits()?)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    Ok(())
}

#[test]
fn proc_records_are_scoped_to_the_exact_interface_name_and_index() -> Result<(), Box<dyn Error>> {
    let input = "fe800000000000000000000000000001 05 40 20 80 veth0\nfe800000000000000000000000000003 06 40 20 80 veth1\n";
    let assignments = parse_snapshot(input, "veth0", 5)?;
    assert_eq!(assignments.len(), 1);
    let first = assignments.first().ok_or("missing assignment")?;
    assert_eq!(first.address(), SOURCE.parse::<Ipv6Addr>()?);
    assert_eq!(first.prefix_len(), 64);
    assert_eq!(first.scope(), 0x20);
    assert_eq!(first.flags(), 0x80);
    for bad in [
        "fe800000000000000000000000000001 06 40 20 80 veth0\n",
        "fe800000000000000000000000000001 05 40 20 80 veth1\n",
        "fe800000000000000000000000000001 05 81 20 80 veth0\n",
        "fe800000000000000000000000000001 05 40 20 80\n",
        "fe80000000000000000000000000000x 05 40 20 80 veth0\n",
    ] {
        assert_eq!(
            parse_snapshot(bad, "veth0", 5)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidData)
        );
    }
    Ok(())
}

#[test]
fn excessive_or_truncated_proc_data_is_rejected() {
    let line = "fe800000000000000000000000000001 05 40 20 80 veth0\n";
    let excessive = line.repeat(257);
    assert_eq!(
        parse_snapshot(&excessive, "veth0", 5)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    assert_eq!(
        parse_snapshot(line.trim_end(), "veth0", 5)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
}
