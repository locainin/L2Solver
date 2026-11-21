pub mod common;

use common::pcapng::{ByteOrder, block, enhanced_packet, interface, options, section_header};
use l2_pcap::{CollectionSummary, PcapNgReader};
use std::{error::Error, io::Cursor};

const fn u32_bytes(order: ByteOrder, value: u32) -> [u8; 4] {
    match order {
        ByteOrder::Little => value.to_le_bytes(),
        ByteOrder::Big => value.to_be_bytes(),
    }
}

const fn u64_bytes(order: ByteOrder, value: u64) -> [u8; 8] {
    match order {
        ByteOrder::Little => value.to_le_bytes(),
        ByteOrder::Big => value.to_be_bytes(),
    }
}

fn statistics(order: ByteOrder, interface_id: u32, values: &[(u16, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&u32_bytes(order, interface_id));
    body.extend_from_slice(&u32_bytes(order, 0));
    body.extend_from_slice(&u32_bytes(order, 1));
    body.extend_from_slice(&options(order, values));
    block(order, 5, &body)
}

fn summary(bytes: Vec<u8>) -> Result<CollectionSummary, Box<dyn Error>> {
    let mut reader = PcapNgReader::new(Cursor::new(bytes))?;
    while reader.next_packet()?.is_some() {}
    Ok(reader.collection_summary())
}

#[test]
fn packet_drop_presence_and_intervals() -> Result<(), Box<dyn Error>> {
    for order in [ByteOrder::Little, ByteOrder::Big] {
        let mut capture = section_header(order, -1);
        capture.extend_from_slice(&interface(order, 64, &[]));
        capture.extend_from_slice(&enhanced_packet(order, 0, 1, &[1], 1, &[]));
        let mut reader = PcapNgReader::new(Cursor::new(capture.clone()))?;
        assert!(reader.next_packet()?.is_some());
        assert_eq!(
            reader.collection_summary().enhanced_packet_packets_dropped,
            None
        );
        let zero = u64_bytes(order, 0);
        let first = u64_bytes(order, 9);
        let second = u64_bytes(order, 4);
        capture.extend_from_slice(&enhanced_packet(order, 0, 2, &[2], 1, &[(4, &zero)]));
        let mut reader = PcapNgReader::new(Cursor::new(capture.clone()))?;
        assert!(reader.next_packet()?.is_some());
        assert!(reader.next_packet()?.is_some());
        assert_eq!(
            reader.collection_summary().enhanced_packet_packets_dropped,
            Some(0)
        );
        assert_eq!(
            reader.collection_summary().authority().as_str(),
            "source_declared"
        );
        capture.extend_from_slice(&enhanced_packet(order, 0, 3, &[3], 1, &[(4, &first)]));
        capture.extend_from_slice(&enhanced_packet(order, 0, 4, &[4], 1, &[(4, &second)]));
        assert_eq!(summary(capture)?.enhanced_packet_packets_dropped, Some(13));
    }
    Ok(())
}

#[test]
fn interface_statistics_section_maxima() -> Result<(), Box<dyn Error>> {
    for order in [ByteOrder::Little, ByteOrder::Big] {
        let mut capture = section_header(order, -1);
        capture.extend_from_slice(&interface(order, 64, &[]));
        capture.extend_from_slice(&interface(order, 64, &[]));
        let five = u64_bytes(order, 5);
        let seven = u64_bytes(order, 7);
        let three = u64_bytes(order, 3);
        let four = u64_bytes(order, 4);
        let one = u64_bytes(order, 1);
        capture.extend_from_slice(&statistics(order, 0, &[(5, &five), (7, &three)]));
        capture.extend_from_slice(&statistics(order, 0, &[(5, &seven), (7, &one)]));
        capture.extend_from_slice(&statistics(order, 1, &[(5, &four)]));
        capture.extend_from_slice(&section_header(order, -1));
        capture.extend_from_slice(&interface(order, 64, &[]));
        capture.extend_from_slice(&statistics(order, 0, &[(5, &one), (7, &five)]));

        let result = summary(capture)?;
        assert_eq!(result.interface_statistics_interface_dropped, Some(12));
        assert_eq!(result.interface_statistics_os_dropped, Some(8));
    }
    Ok(())
}

#[test]
fn interface_statistics_minimum_block() -> Result<(), Box<dyn Error>> {
    for order in [ByteOrder::Little, ByteOrder::Big] {
        let mut capture = section_header(order, -1);
        capture.extend_from_slice(&interface(order, 64, &[]));
        // The required fields fit in a 24-byte block when options are absent
        let statistics = block(order, 5, &[0; 12]);
        assert_eq!(statistics.len(), 24);
        capture.extend_from_slice(&statistics);
        capture.extend_from_slice(&enhanced_packet(order, 0, 1, &[0x42], 1, &[]));

        let mut reader = PcapNgReader::new(Cursor::new(capture))?;
        let packet = reader.next_packet();
        assert!(
            matches!(&packet, Ok(Some(_))),
            "a minimum-length statistics block must not stop the following packet"
        );
        assert_eq!(packet?.ok_or("missing packet")?.bytes(), [0x42]);
        assert!(reader.next_packet()?.is_none());
        assert_eq!(
            reader
                .collection_summary()
                .interface_statistics_interface_dropped,
            None
        );
        assert_eq!(
            reader.collection_summary().interface_statistics_os_dropped,
            None
        );
    }
    Ok(())
}

#[test]
fn interface_statistics_invalid_fields() {
    for order in [ByteOrder::Little, ByteOrder::Big] {
        let mut header = section_header(order, -1);
        header.extend_from_slice(&interface(order, 64, &[]));
        let count = u64_bytes(order, 1);
        let cases = [
            statistics(order, 0, &[(5, &[0; 4])]),
            statistics(order, 0, &[(7, &count), (7, &count)]),
            statistics(order, 1, &[(5, &count)]),
            block(order, 5, &[]),
        ];
        for record in cases {
            let mut capture = header.clone();
            capture.extend_from_slice(&record);
            assert!(summary(capture).is_err());
        }
    }
}

#[test]
fn packet_drop_total_overflow() -> Result<(), Box<dyn Error>> {
    let order = ByteOrder::Little;
    let mut capture = section_header(order, -1);
    capture.extend_from_slice(&interface(order, 64, &[]));
    let maximum = u64_bytes(order, u64::MAX);
    let one = u64_bytes(order, 1);
    capture.extend_from_slice(&enhanced_packet(order, 0, 1, &[1], 1, &[(4, &maximum)]));
    capture.extend_from_slice(&enhanced_packet(order, 0, 2, &[2], 1, &[(4, &one)]));
    let mut reader = PcapNgReader::new(Cursor::new(capture))?;
    assert!(reader.next_packet()?.is_some());
    assert!(reader.next_packet().is_err());
    assert!(matches!(
        reader.next_packet(),
        Err(l2_pcap::Error::ReaderTerminated)
    ));
    Ok(())
}

#[test]
fn interface_statistics_total_overflow() -> Result<(), Box<dyn Error>> {
    let order = ByteOrder::Big;
    let mut capture = section_header(order, -1);
    capture.extend_from_slice(&interface(order, 64, &[]));
    capture.extend_from_slice(&interface(order, 64, &[]));
    let maximum = u64_bytes(order, u64::MAX);
    let one = u64_bytes(order, 1);
    capture.extend_from_slice(&statistics(order, 0, &[(5, &maximum)]));
    capture.extend_from_slice(&statistics(order, 1, &[(5, &one)]));
    let mut reader = PcapNgReader::new(Cursor::new(capture))?;
    assert!(matches!(
        reader.next_packet(),
        Err(l2_pcap::Error::LossCounterOverflow)
    ));
    assert_eq!(
        reader
            .collection_summary()
            .interface_statistics_interface_dropped,
        Some(u64::MAX)
    );
    assert!(matches!(
        reader.next_packet(),
        Err(l2_pcap::Error::ReaderTerminated)
    ));
    Ok(())
}
