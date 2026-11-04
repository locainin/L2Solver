#[path = "../../tests/fixtures/cooked.rs"]
mod cooked_fixture;
#[path = "../fuzz_targets/pcap/reader.rs"]
mod reader;

use l2_capture::{
    CaptureMetadata, CaptureTimestamp, CapturedFrame, Direction, FcsStatus, InterfaceId, LinkType,
    TimestampResolution, TimestampSource,
};
use l2_discovery::NetworkAddress;
use l2_pcap::{InterfaceConfig, PcapNgWriter};
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

fn classic(link: u16, packets: &[&[u8]]) -> TestResultBytes {
    let mut capture = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
    capture.extend_from_slice(&[0; 8]);
    capture.extend_from_slice(&65_535_u32.to_le_bytes());
    capture.extend_from_slice(&u32::from(link).to_le_bytes());
    for packet in packets {
        capture.extend_from_slice(&[0; 8]);
        let length = u32::try_from(packet.len())?;
        capture.extend_from_slice(&length.to_le_bytes());
        capture.extend_from_slice(&length.to_le_bytes());
        capture.extend_from_slice(packet);
    }
    Ok(capture)
}

type TestResultBytes = Result<Vec<u8>, Box<dyn Error>>;

fn ipv4() -> Vec<u8> {
    let mut frame = vec![0; 12];
    frame.extend_from_slice(&[0x08, 0x00]);
    frame.extend_from_slice(&[
        0x45, 0, 0, 28, 0, 42, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2,
    ]);
    frame.extend_from_slice(&[0x30, 0x39, 0, 53, 0, 8, 0, 0]);
    frame
}

fn ipv6() -> Vec<u8> {
    let mut frame = vec![0; 12];
    frame.extend_from_slice(&[0x86, 0xdd]);
    frame.extend_from_slice(&[0x60, 0, 0, 0, 0, 8, 17, 64]);
    frame.extend_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    frame.extend_from_slice(&[0x30, 0x39, 0, 53, 0, 8, 0, 0]);
    frame
}

#[test]
fn classic_ethernet_and_cooked_records_reach_shared_ip_decoding() -> TestResult {
    let cases = [
        (
            ipv4(),
            NetworkAddress::Ipv4([192, 0, 2, 1]),
            NetworkAddress::Ipv4([198, 51, 100, 2]),
        ),
        (
            ipv6(),
            NetworkAddress::Ipv6([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            NetworkAddress::Ipv6([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
        ),
    ];
    for (ethernet, source, destination) in cases {
        for version in [1_u16, 113, 276] {
            let frame = if version == 1 {
                ethernet.clone()
            } else {
                cooked_fixture::cooked(
                    &ethernet,
                    version,
                    InterfaceId {
                        section: 0,
                        index: 0,
                    },
                    7,
                )?
                .bytes()
                .to_vec()
            };
            let capture = classic(version, &[&frame])?;
            let mut observed = Vec::new();
            reader::exercise(&capture, |link, packet| {
                observed.push((
                    link,
                    packet.map(|ip| (ip.source, ip.destination, ip.ports(), ip.fragmented)),
                ));
            });
            assert_eq!(
                observed,
                vec![(
                    LinkType::from_raw(version),
                    Some((source, destination, Some((12_345, 53)), false)),
                )],
                "link type {version}"
            );
        }
    }
    Ok(())
}

#[test]
fn pcapng_sll2_record_reaches_shared_ipv6_decoding() -> TestResult {
    let interface = InterfaceId {
        section: 0,
        index: 0,
    };
    let frame = cooked_fixture::cooked(&ipv6(), 276, interface, 7)?;
    let metadata = CaptureMetadata::new(
        interface,
        u32::try_from(frame.bytes().len())?,
        None,
        Some(CaptureTimestamp::new(
            0,
            TimestampResolution::MICROSECOND,
            0,
            TimestampSource::CaptureFile,
        )),
        Direction::Unknown,
        None,
        FcsStatus::Unknown,
    )
    .with_link_type(LinkType::LinuxSll2);
    let frame = CapturedFrame::new(frame.bytes().to_vec(), metadata)?;
    let config = InterfaceConfig::new_with_link_type(
        LinkType::LinuxSll2,
        65_535,
        TimestampResolution::MICROSECOND,
        0,
        FcsStatus::Unknown,
    )?;
    let mut writer = PcapNgWriter::new(Vec::new(), 1_048_576)?;
    writer.add_interface_and_write_frame(interface, config, &frame)?;
    writer.finish()?;

    let mut observed = Vec::new();
    reader::exercise(&writer.into_inner(), |link, packet| {
        observed.push((link, packet.map(|ip| (ip.source, ip.ports()))));
    });
    assert_eq!(
        observed,
        vec![(
            LinkType::LinuxSll2,
            Some((
                NetworkAddress::Ipv6([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,]),
                Some((12_345, 53)),
            )),
        )]
    );
    Ok(())
}

#[test]
fn fragmented_cooked_ipv4_does_not_expose_transport_ports() -> TestResult {
    let mut ethernet = ipv4();
    ethernet
        .get_mut(20..22)
        .ok_or("missing IPv4 flags")?
        .copy_from_slice(&[0x20, 0]);
    let frame = cooked_fixture::cooked(
        &ethernet,
        113,
        InterfaceId {
            section: 0,
            index: 0,
        },
        7,
    )?;
    let capture = classic(113, &[frame.bytes()])?;
    let mut observed = Vec::new();
    reader::exercise(&capture, |_, packet| {
        observed.push(packet.map(|ip| (ip.fragmented, ip.ports())));
    });
    assert_eq!(observed, vec![Some((true, None))]);
    Ok(())
}

#[test]
fn truncated_and_unsupported_link_records_remain_unparsed() -> TestResult {
    for (link, frame) in [(113, vec![0; 15]), (999, ipv4())] {
        let capture = classic(link, &[&frame])?;
        let mut observed = Vec::new();
        reader::exercise(&capture, |kind, packet| {
            observed.push((kind, packet.is_some()));
        });
        assert_eq!(observed, vec![(LinkType::from_raw(link), false)]);
    }
    Ok(())
}

#[test]
fn cooked_protocols_without_ethertype_semantics_remain_opaque() -> TestResult {
    let frame = cooked_fixture::cooked(
        &ipv4(),
        113,
        InterfaceId {
            section: 0,
            index: 0,
        },
        7,
    )?;
    for (offset, replacement) in [(2, [0x03, 0x02]), (14, [0x81, 0x00])] {
        let mut bytes = frame.bytes().to_vec();
        bytes
            .get_mut(offset..offset + 2)
            .ok_or("missing cooked header field")?
            .copy_from_slice(&replacement);
        let capture = classic(113, &[&bytes])?;
        let mut observed = Vec::new();
        reader::exercise(&capture, |_, packet| observed.push(packet.is_some()));
        assert_eq!(observed, vec![false], "header offset {offset}");
    }
    Ok(())
}

#[test]
fn partial_following_record_stops_after_the_complete_record() -> TestResult {
    let frame = ipv4();
    let mut capture = classic(1, &[&frame])?;
    capture.extend_from_slice(&[0, 1, 2]);
    let mut count = 0;
    reader::exercise(&capture, |_, _| count += 1);
    assert_eq!(count, 1);
    Ok(())
}
