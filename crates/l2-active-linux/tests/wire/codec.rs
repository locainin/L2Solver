use super::{ERROR, Reader, Writer, error_record, read_error, read_vlan, write_vlan};
use crate::{VlanInfo, VlanProtocol};
use l2_capture::LinuxInterfaceIdentity;
use std::io;

fn identities() -> io::Result<(LinuxInterfaceIdentity, LinuxInterfaceIdentity)> {
    Ok((
        LinuxInterfaceIdentity::new(1, 2, 3, 4, 5).map_err(io::Error::other)?,
        LinuxInterfaceIdentity::new(1, 2, 3, 6, 7).map_err(io::Error::other)?,
    ))
}

#[test]
fn vlan_snapshots_round_trip_with_the_parent_identity() -> io::Result<()> {
    let (selected, parent) = identities()?;
    for vlan in [
        None,
        Some(VlanInfo {
            id: 0,
            protocol: VlanProtocol::Ieee8021Q,
            parent,
            reorders_headers: true,
        }),
        Some(VlanInfo {
            id: 4094,
            protocol: VlanProtocol::Ieee8021Ad,
            parent,
            reorders_headers: false,
        }),
    ] {
        let mut writer = Writer::new(0);
        write_vlan(&mut writer, vlan);
        let bytes = writer.finish();
        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.u8()?, 0);
        assert_eq!(read_vlan(&mut reader, selected)?, vlan);
        reader.finish()?;
    }
    Ok(())
}

#[test]
fn vlan_snapshot_rejects_invalid_scope_fields_and_cross_namespace_parent() -> io::Result<()> {
    let (selected, parent) = identities()?;
    for (id, protocol, actual_parent, reorder) in [
        (4095, 1, parent, 1),
        (37, 0, parent, 1),
        (37, 3, parent, 1),
        (37, 1, parent, 2),
        (37, 1, selected, 1),
        (
            37,
            1,
            LinuxInterfaceIdentity::new(1, 8, 3, 6, 7).map_err(io::Error::other)?,
            1,
        ),
    ] {
        let mut writer = Writer::new(1);
        writer.u16(id);
        writer.u8(protocol);
        super::write_identity(&mut writer, actual_parent);
        writer.u8(reorder);
        assert_eq!(
            read_vlan(&mut Reader::new(&writer.finish()), selected)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::InvalidData)
        );
    }
    assert_eq!(
        read_vlan(&mut Reader::new(&[2]), selected)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    assert_eq!(
        read_vlan(&mut Reader::new(&[1, 0]), selected)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    Ok(())
}

#[test]
fn vlan_scope_change_keeps_its_typed_source_across_the_helper_channel() -> io::Result<()> {
    let original = io::Error::new(io::ErrorKind::InvalidData, crate::VlanScopeChanged);
    let encoded = error_record(&original);
    let mut reader = Reader::new(&encoded);
    assert_eq!(reader.u8()?, ERROR);
    let decoded = read_error(&mut reader)?;
    assert_eq!(decoded.kind(), io::ErrorKind::InvalidData);
    assert!(
        decoded
            .get_ref()
            .and_then(|source| source.downcast_ref::<crate::VlanScopeChanged>())
            .is_some()
    );
    Ok(())
}

#[test]
fn route_unreachable_errors_keep_their_kind_across_the_helper_channel() -> io::Result<()> {
    for kind in [
        io::ErrorKind::NetworkUnreachable,
        io::ErrorKind::HostUnreachable,
    ] {
        let encoded = error_record(&io::Error::new(kind, "route unavailable"));
        let mut reader = Reader::new(&encoded);
        assert_eq!(reader.u8()?, ERROR);
        assert_eq!(read_error(&mut reader)?.kind(), kind);
    }
    Ok(())
}

#[test]
fn finite_wire_values_round_trip_and_require_full_consumption() -> io::Result<()> {
    let mut writer = Writer::new(7);
    writer.u8(42);
    writer.u16(1025);
    writer.u32(123_456);
    writer.u64(789_123_456);
    writer.bytes(b"ok");
    let bytes = writer.finish();
    let mut reader = Reader::new(&bytes);
    assert_eq!(reader.u8()?, 7);
    assert_eq!(reader.u8()?, 42);
    assert_eq!(reader.u16()?, 1025);
    assert_eq!(reader.u32()?, 123_456);
    assert_eq!(reader.u64()?, 789_123_456);
    assert_eq!(reader.take(2)?, b"ok");
    reader.finish()?;
    Ok(())
}

#[test]
fn incomplete_or_trailing_wire_values_are_rejected() -> io::Result<()> {
    let mut short = Reader::new(&[0]);
    assert_eq!(
        short.u32().err().map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    let mut extra = Reader::new(&[0, 1]);
    assert_eq!(extra.u8()?, 0);
    assert_eq!(
        extra.finish().err().map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    Ok(())
}
