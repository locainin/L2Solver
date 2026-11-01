use super::open_request;
use crate::{
    InterfaceSelector, discover,
    wire::{self, Writer},
};
use std::io;

fn prefix(kind: u8) -> io::Result<Writer> {
    let selector = InterfaceSelector::new("lo")?;
    let info = discover(&selector)?;
    let mut writer = Writer::new(wire::OPEN);
    writer.u8(wire::VERSION);
    writer.u8(kind);
    writer.u8(2);
    writer.bytes(b"lo");
    wire::write_identity(&mut writer, info.identity());
    wire::write_vlan(&mut writer, None);
    writer.bytes(&[2, 0, 0, 0, 0, 1]);
    Ok(writer)
}

#[test]
fn open_rejects_a_vlan_snapshot_that_differs_from_the_selected_interface() -> io::Result<()> {
    let selector = InterfaceSelector::new("lo")?;
    let info = discover(&selector)?;
    let identity = info.identity();
    let parent = l2_capture::LinuxInterfaceIdentity::new(
        identity.namespace_device(),
        identity.namespace_inode(),
        identity.interface_device(),
        identity.interface_inode(),
        identity
            .ifindex()
            .checked_add(1)
            .ok_or_else(|| io::Error::other("ifindex overflow"))?,
    )
    .map_err(io::Error::other)?;
    let mut writer = Writer::new(wire::OPEN);
    writer.u8(wire::VERSION);
    writer.u8(4);
    writer.u8(2);
    writer.bytes(b"lo");
    wire::write_identity(&mut writer, identity);
    wire::write_vlan(
        &mut writer,
        Some(crate::VlanInfo {
            id: 37,
            protocol: crate::VlanProtocol::Ieee8021Q,
            parent,
            reorders_headers: true,
        }),
    );
    writer.bytes(&[2, 0, 0, 0, 0, 1]);
    writer.u32(1000);
    writer.u32(10);
    writer.u64(4096);
    writer.u64(crate::deadline::encode_deadline(
        std::time::Instant::now() + std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(1),
    )?);
    let error = open_request(&writer.finish())
        .err()
        .ok_or_else(|| io::Error::other("different VLAN scope was admitted"))?;
    assert!(
        matches!(error.get_ref(), Some(source) if source.is::<crate::VlanScopeChanged>()),
        "{error:?}"
    );
    Ok(())
}

#[test]
fn zero_dhcp_transaction_is_rejected_before_opening_a_socket() -> io::Result<()> {
    let mut writer = prefix(2)?;
    writer.u32(0);
    assert_eq!(
        open_request(&writer.finish())
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    Ok(())
}

#[test]
fn unknown_open_intent_is_rejected_before_opening_a_socket() -> io::Result<()> {
    let writer = prefix(255)?;
    assert_eq!(
        open_request(&writer.finish())
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    Ok(())
}

#[test]
fn worker_rejects_version_eight_before_socket_admission() {
    let mut writer = Writer::new(wire::OPEN);
    writer.u8(8);
    assert_eq!(
        open_request(&writer.finish())
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
}

#[test]
fn dot1x_worker_rejects_missing_dedicated_interface_acknowledgement() -> io::Result<()> {
    let mut writer = prefix(6)?;
    writer.u8(0);
    assert_eq!(
        open_request(&writer.finish())
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    Ok(())
}
