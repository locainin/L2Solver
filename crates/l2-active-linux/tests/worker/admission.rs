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
    writer.bytes(&[2, 0, 0, 0, 0, 1]);
    Ok(writer)
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
fn worker_rejects_an_older_protocol_version_before_socket_admission() {
    let mut writer = Writer::new(wire::OPEN);
    writer.u8(wire::VERSION - 1);
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
