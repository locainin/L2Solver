pub mod common;

use common::pcapng::{self, ByteOrder};
use l2_capture::LinuxInterfaceIdentity;
use l2_pcap::{Error, PcapNgReader};
use std::io::Cursor;

#[test]
fn linux_identity_declared_byte() -> Result<(), Box<dyn std::error::Error>> {
    for order in [ByteOrder::Little, ByteOrder::Big] {
        let mut bytes = pcapng::section_header(order, -1);
        bytes.extend(pcapng::interface(
            order,
            65_535,
            &[(3, b"l2solver:linux-interface:v1:1:2:3:4:5")],
        ));
        bytes.extend(pcapng::enhanced_packet(order, 0, 12, &[1, 2], 2, &[]));
        let mut reader = PcapNgReader::new(Cursor::new(bytes))?;
        let frame = pcapng::first_frame(&mut reader)?;
        assert_eq!(
            frame.metadata().linux_interface(),
            Some(LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?)
        );
        assert_eq!(frame.bytes(), [1, 2]);
        assert!(reader.next_packet()?.is_none());
    }
    Ok(())
}

#[test]
fn malformed_linux_without_raw_source() -> Result<(), Box<dyn std::error::Error>> {
    let malformed = [
        "l2solver:linux-interface:v1:1:2:3:4:0",
        "l2solver:linux-interface:v1:1:2:3:4:4294967296",
        "l2solver:linux-interface:v1:1:2:3:4",
        "l2solver:linux-interface:v1:1:2:3:4:5:6",
        "l2solver:linux-interface:v1:1:2:3:4:+5",
        "l2solver:linux-interface:v1:01:2:3:4:5",
        "l2solver:linux-interface:v1:1:2:3:4:5 ",
    ];
    for description in malformed {
        let mut bytes = pcapng::section_header(ByteOrder::Little, -1);
        bytes.extend(pcapng::interface(
            ByteOrder::Little,
            65_535,
            &[(3, description.as_bytes())],
        ));
        let mut reader = PcapNgReader::new(Cursor::new(bytes))?;
        assert!(
            matches!(
                reader.next_packet(),
                Err(Error::InvalidLinuxInterfaceIdentity)
            ),
            "{description}"
        );
    }
    Ok(())
}

#[test]
fn ordinary_interface_not_linux_identity() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = pcapng::section_header(ByteOrder::Little, -1);
    bytes.extend(pcapng::interface(
        ByteOrder::Little,
        65_535,
        &[(3, b"Ethernet adapter")],
    ));
    bytes.extend(pcapng::simple_packet(ByteOrder::Little, &[1], 1));
    let mut reader = PcapNgReader::new(Cursor::new(bytes))?;
    assert_eq!(
        pcapng::first_frame(&mut reader)?
            .metadata()
            .linux_interface(),
        None
    );
    Ok(())
}
