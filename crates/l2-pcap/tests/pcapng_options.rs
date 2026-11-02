pub mod common;

use common::pcapng::{
    ByteOrder, block, enhanced_packet, interface, section_header, section_header_with_options,
};
use l2_pcap::{Error, PcapNgReader};
use std::io::Cursor;

fn interface_option_error(
    code: u16,
    value: &[u8],
    duplicate: bool,
) -> Result<Error, Box<dyn std::error::Error>> {
    let mut capture = section_header(ByteOrder::Little, -1);
    let values = if duplicate {
        vec![(code, value), (code, value)]
    } else {
        vec![(code, value)]
    };
    capture.extend_from_slice(&interface(ByteOrder::Little, 64, &values));
    let mut reader = PcapNgReader::new(Cursor::new(capture))?;
    match reader.next_packet() {
        Err(error) => Ok(error),
        Ok(Some(_)) => Err("capture produced a packet instead of an option error".into()),
        Ok(None) => Err("capture ended without an option error".into()),
    }
}

fn packet_option_error(
    code: u16,
    value: &[u8],
    duplicate: bool,
) -> Result<Error, Box<dyn std::error::Error>> {
    let values = if duplicate {
        vec![(code, value), (code, value)]
    } else {
        vec![(code, value)]
    };
    let mut capture = section_header(ByteOrder::Little, -1);
    capture.extend_from_slice(&interface(ByteOrder::Little, 128, &[]));
    capture.extend_from_slice(&enhanced_packet(
        ByteOrder::Little,
        0,
        0,
        &[0xaa],
        1,
        &values,
    ));
    let mut reader = PcapNgReader::new(Cursor::new(capture))?;
    match reader.next_packet() {
        Err(error) => Ok(error),
        Ok(Some(_)) => Err("capture produced a packet instead of an option error".into()),
        Ok(None) => Err("capture ended without an option error".into()),
    }
}

#[test]
fn enforces_option_count_limit() -> Result<(), Box<dyn std::error::Error>> {
    let value = [0x01];
    for count in [127_usize, 128] {
        let values: Vec<(u16, &[u8])> = (0..count).map(|_| (99, value.as_slice())).collect();
        let mut capture = section_header(ByteOrder::Little, -1);
        capture.extend_from_slice(&interface(ByteOrder::Little, 64, &values));
        let mut reader = PcapNgReader::new(Cursor::new(capture))?;
        if count == 127 {
            assert!(reader.next_packet()?.is_none());
        } else {
            assert!(matches!(
                reader.next_packet(),
                Err(Error::OptionLimitExceeded { limit: 128 })
            ));
        }
    }
    Ok(())
}

#[test]
fn known_option_duplicates_rejected_scope() -> Result<(), Box<dyn std::error::Error>> {
    let any = [1];
    let eight = [0; 8];
    let six = [0; 6];
    let four = [0; 4];

    let section = section_header_with_options(ByteOrder::Little, -1, &[(2, &any), (2, &any)]);
    assert!(matches!(
        PcapNgReader::new(Cursor::new(section)),
        Err(Error::DuplicateOption {
            block_type: 0x0a0d_0d0a,
            code: 2
        })
    ));

    for (code, value) in [
        (2, any.as_slice()),
        (6, six.as_slice()),
        (7, eight.as_slice()),
        (9, [6].as_slice()),
        (10, four.as_slice()),
        (11, any.as_slice()),
    ] {
        assert!(matches!(
            interface_option_error(code, value, true)?,
            Error::DuplicateOption { block_type: 1, code: actual } if actual == code
        ));
    }

    for (code, value) in [(2, four.as_slice()), (4, eight.as_slice())] {
        assert!(matches!(
            packet_option_error(code, value, true)?,
            Error::DuplicateOption { block_type: 6, code: actual } if actual == code
        ));
    }
    Ok(())
}

#[test]
fn checks_known_option_lengths() -> Result<(), Box<dyn std::error::Error>> {
    let short = [0; 7];
    let empty = [];
    let short_three = short.get(..3).ok_or("short option fixture range")?;
    let section = section_header_with_options(ByteOrder::Little, -1, &[(2988, short_three)]);
    assert!(matches!(
        PcapNgReader::new(Cursor::new(section)),
        Err(Error::InvalidOptionLength { code: 2988, .. })
    ));

    for (code, value) in [
        (4, short.as_slice()),
        (5, short.as_slice()),
        (6, short.as_slice()),
        (7, short.as_slice()),
        (9, empty.as_slice()),
        (10, short_three),
        (11, empty.as_slice()),
    ] {
        assert!(matches!(
            interface_option_error(code, value, false)?,
            Error::InvalidOptionLength { code: actual, .. } if actual == code
        ));
    }

    let short_seven = short.as_slice();
    for (code, value) in [(2, short_three), (3, empty.as_slice()), (4, short_seven)] {
        assert!(matches!(
            packet_option_error(code, value, false)?,
            Error::InvalidOptionLength { code: actual, .. } if actual == code
        ));
    }
    Ok(())
}

#[test]
fn rejects_truncated_options() -> Result<(), Box<dyn std::error::Error>> {
    let value = [1];
    let mut after_terminator = section_header(ByteOrder::Little, -1);
    after_terminator.extend_from_slice(&interface(
        ByteOrder::Little,
        64,
        &[(0, &[]), (99, &value)],
    ));
    let mut reader = PcapNgReader::new(Cursor::new(after_terminator))?;
    assert!(matches!(
        reader.next_packet(),
        Err(Error::OptionAfterTerminator { block_type: 1 })
    ));

    let mut body = Vec::new();
    body.extend_from_slice(&1_u16.to_le_bytes());
    body.extend_from_slice(&0_u16.to_le_bytes());
    body.extend_from_slice(&64_u32.to_le_bytes());
    body.extend_from_slice(&99_u16.to_le_bytes());
    body.extend_from_slice(&1_u16.to_le_bytes());
    let mut capture = section_header(ByteOrder::Little, -1);
    capture.extend_from_slice(&block(ByteOrder::Little, 1, &body));
    let mut reader = PcapNgReader::new(Cursor::new(capture))?;
    assert!(matches!(
        reader.next_packet(),
        Err(Error::UnexpectedEof {
            section: "PCAPNG option value",
            ..
        })
    ));
    Ok(())
}

#[test]
fn comment_options_known_repeatable() -> Result<(), Box<dyn std::error::Error>> {
    let comment_a = *b"a";
    let comment_b = *b"bc";
    let mut capture = section_header(ByteOrder::Little, -1);
    capture.extend_from_slice(&interface(
        ByteOrder::Little,
        64,
        &[(1, &comment_a), (1, &comment_b)],
    ));

    let mut reader = PcapNgReader::new(Cursor::new(capture))?;
    assert!(reader.next_packet()?.is_none());
    assert_eq!(
        reader
            .interface_descriptions()
            .first()
            .ok_or("missing interface")?
            .unknown_options(),
        []
    );
    Ok(())
}
