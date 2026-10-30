use super::{ERROR, Reader, Writer, error_record, read_error};
use std::io;

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
