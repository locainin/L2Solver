use l2_capture::{
    CaptureMetadata, CaptureTimestamp, CapturedFrame, Direction, FcsStatus, InterfaceId,
    LinuxInterfaceIdentity, TimestampResolution, TimestampSource, VlanAuxData,
};
use l2_pcap::{
    InterfaceConfig, MAX_EVIDENCE_OUTPUT_BYTES, PcapNgReader, PcapNgWriter, WriterError,
};
use std::io::{self, Cursor, Write};

const SOURCE: InterfaceId = InterfaceId {
    section: 7,
    index: 3,
};

fn config(fcs: FcsStatus) -> Result<InterfaceConfig, Box<dyn std::error::Error>> {
    Ok(InterfaceConfig::new(
        65_535,
        TimestampResolution::decimal(6)?,
        -2,
        fcs,
    )?)
}

fn frame(
    bytes: &[u8],
    direction: Direction,
    fcs: FcsStatus,
    vlan: Option<VlanAuxData>,
) -> Result<CapturedFrame, Box<dyn std::error::Error>> {
    let timestamp = CaptureTimestamp::new(
        0x0102_0304_0506_0708,
        TimestampResolution::decimal(6)?,
        -2,
        TimestampSource::Unknown,
    );
    let metadata = CaptureMetadata::new(
        SOURCE,
        u32::try_from(bytes.len())?,
        None,
        Some(timestamp),
        direction,
        vlan,
        fcs,
    );
    Ok(CapturedFrame::new(bytes.to_vec(), metadata)?)
}

#[test]
fn emits_little_endian_section_header() -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = PcapNgWriter::new(Vec::new(), MAX_EVIDENCE_OUTPUT_BYTES)?;
    writer.finish()?;
    assert!(matches!(
        writer.add_interface(SOURCE, config(FcsStatus::Unknown)?),
        Err(WriterError::Finished)
    ));

    assert_eq!(
        writer.into_inner(),
        [
            0x0a, 0x0d, 0x0d, 0x0a, 0x1c, 0x00, 0x00, 0x00, 0x4d, 0x3c, 0x2b, 0x1a, 0x01, 0x00,
            0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1c, 0x00, 0x00, 0x00,
        ]
    );
    Ok(())
}

#[test]
fn round_trip_preserves_packet_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let declared_fcs = FcsStatus::present(4)?;
    let mut writer = PcapNgWriter::new(Vec::new(), MAX_EVIDENCE_OUTPUT_BYTES)?;
    assert_eq!(writer.add_interface(SOURCE, config(declared_fcs)?)?, 0);
    assert_eq!(writer.interface_count(), 1);
    writer.write_frame(&frame(
        &[1, 2, 3, 4, 5],
        Direction::Inbound,
        declared_fcs,
        None,
    )?)?;
    writer.finish()?;
    writer.finish()?;

    assert_eq!(writer.packet_count(), 1);
    let bytes = writer.into_inner();
    let mut reader = PcapNgReader::new(Cursor::new(bytes))?;
    let decoded = reader.next_packet()?.ok_or("missing packet")?;
    let metadata = decoded.metadata();

    assert_eq!(decoded.bytes(), [1, 2, 3, 4, 5]);
    assert_eq!(metadata.original_len(), 5);
    assert_eq!(
        metadata.interface(),
        InterfaceId {
            section: 0,
            index: 0
        }
    );
    assert_eq!(metadata.direction(), Direction::Inbound);
    assert_eq!(metadata.fcs(), declared_fcs);
    let timestamp = metadata.timestamp().ok_or("missing timestamp")?;
    assert_eq!(timestamp.ticks(), 0x0102_0304_0506_0708);
    assert_eq!(timestamp.resolution(), TimestampResolution::MICROSECOND);
    assert_eq!(timestamp.offset_seconds(), -2);
    assert_eq!(reader.next_packet()?, None);
    Ok(())
}

#[test]
fn preflights_interface_without_output() -> Result<(), Box<dyn std::error::Error>> {
    let packet = frame(&[1], Direction::Inbound, FcsStatus::Unknown, None)?;
    let configuration = config(FcsStatus::Unknown)?;
    let mut writer = PcapNgWriter::new(Vec::new(), MAX_EVIDENCE_OUTPUT_BYTES)?;
    let before = writer.bytes_written();

    let prospective = writer.preflight_interface_and_frame(SOURCE, configuration, &packet)?;
    assert!(prospective > before);
    assert_eq!(writer.bytes_written(), before);
    assert_eq!(writer.interface_count(), 0);
    assert_eq!(writer.packet_count(), 0);

    assert_eq!(
        writer.add_interface_and_write_frame(SOURCE, configuration, &packet)?,
        0
    );
    assert_eq!(writer.bytes_written(), prospective);
    assert_eq!(writer.interface_count(), 1);
    assert_eq!(writer.packet_count(), 1);
    Ok(())
}

#[test]
fn preflight_rejects_invalid_packet() -> Result<(), Box<dyn std::error::Error>> {
    let packet = frame(&[1], Direction::Outbound, FcsStatus::Absent, None)?;
    let configuration = config(FcsStatus::Absent)?;
    let writer = PcapNgWriter::new(Vec::new(), MAX_EVIDENCE_OUTPUT_BYTES)?;
    let before = writer.bytes_written();

    assert!(matches!(
        writer.preflight_interface_and_frame(SOURCE, configuration, &packet),
        Err(WriterError::UnrepresentablePacketFlags)
    ));
    assert_eq!(writer.bytes_written(), before);
    assert_eq!(writer.interface_count(), 0);
    assert_eq!(writer.packet_count(), 0);
    Ok(())
}

#[test]
fn preserves_interface_and_packet_fcs() -> Result<(), Box<dyn std::error::Error>> {
    let present_four = FcsStatus::present(4)?;
    let present_two = FcsStatus::present(2)?;
    let cases = [
        (FcsStatus::Absent, FcsStatus::Absent),
        (present_four, FcsStatus::Unknown),
        (FcsStatus::Unknown, present_four),
        (present_four, present_two),
    ];

    for (interface_fcs, packet_fcs) in cases {
        let mut writer = PcapNgWriter::new(Vec::new(), MAX_EVIDENCE_OUTPUT_BYTES)?;
        writer.add_interface(SOURCE, config(interface_fcs)?)?;
        writer.write_frame(&frame(&[0xaa], Direction::Unknown, packet_fcs, None)?)?;
        writer.finish()?;

        let mut reader = PcapNgReader::new(Cursor::new(writer.into_inner()))?;
        let decoded = reader.next_packet()?.ok_or("missing packet")?;
        assert_eq!(decoded.metadata().fcs(), packet_fcs);
        assert_eq!(reader.next_packet()?, None);
    }
    Ok(())
}

#[test]
fn every_writer_alignment_octet_zero() -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = PcapNgWriter::new(Vec::new(), MAX_EVIDENCE_OUTPUT_BYTES)?;
    writer.add_interface(SOURCE, config(FcsStatus::Unknown)?)?;
    writer.write_frame(&frame(
        &[0xaa, 0xbb, 0xcc],
        Direction::Inbound,
        FcsStatus::Unknown,
        None,
    )?)?;
    writer.finish()?;
    let bytes = writer.into_inner();

    // SHB is 28 bytes and this IDB is 44 bytes, so EPB packet data starts at byte 100
    assert_eq!(bytes.get(100..103), Some([0xaa, 0xbb, 0xcc].as_slice()));
    assert_eq!(bytes.get(103), Some(&0));
    Ok(())
}

#[test]
fn enforces_output_quota_before_write() -> Result<(), Box<dyn std::error::Error>> {
    let packet = frame(&[1, 2, 3], Direction::Unknown, FcsStatus::Unknown, None)?;
    let configuration = config(FcsStatus::Unknown)?;
    let mut sizing = PcapNgWriter::new(Vec::new(), MAX_EVIDENCE_OUTPUT_BYTES)?;
    sizing.add_interface(SOURCE, configuration)?;
    sizing.write_frame(&packet)?;
    sizing.finish()?;
    let exact = sizing.bytes_written();

    let mut accepted = PcapNgWriter::new(Vec::new(), exact)?;
    accepted.add_interface(SOURCE, configuration)?;
    accepted.write_frame(&packet)?;
    accepted.finish()?;
    assert_eq!(accepted.bytes_written(), exact);

    let mut rejected = PcapNgWriter::new(Vec::new(), exact - 1)?;
    rejected.add_interface(SOURCE, configuration)?;
    let before = rejected.bytes_written();
    assert!(matches!(
        rejected.write_frame(&packet),
        Err(WriterError::OutputLimitExceeded { .. })
    ));
    assert_eq!(rejected.bytes_written(), before);
    assert_eq!(rejected.packet_count(), 0);
    Ok(())
}

#[test]
fn rejects_interface_metadata_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = PcapNgWriter::new(Vec::new(), MAX_EVIDENCE_OUTPUT_BYTES)?;
    writer.add_interface(SOURCE, config(FcsStatus::Unknown)?)?;
    assert!(matches!(
        writer.add_interface(SOURCE, config(FcsStatus::Unknown)?),
        Err(WriterError::DuplicateInterface { .. })
    ));

    let unknown = InterfaceId {
        section: 8,
        index: 4,
    };
    let timestamp = CaptureTimestamp::new(
        1,
        TimestampResolution::decimal(6)?,
        -2,
        TimestampSource::Unknown,
    );
    let metadata = CaptureMetadata::new(
        unknown,
        1,
        None,
        Some(timestamp),
        Direction::Unknown,
        None,
        FcsStatus::Unknown,
    );
    let unknown_frame = CapturedFrame::new(vec![0], metadata)?;
    assert!(matches!(
        writer.write_frame(&unknown_frame),
        Err(WriterError::UnknownInterface { .. })
    ));
    assert_eq!(writer.packet_count(), 0);
    Ok(())
}

#[test]
fn rejects_lossy_metadata_encoding() -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = PcapNgWriter::new(Vec::new(), MAX_EVIDENCE_OUTPUT_BYTES)?;
    writer.add_interface(SOURCE, config(FcsStatus::Absent)?)?;

    let vlan = frame(
        &[1],
        Direction::Unknown,
        FcsStatus::Absent,
        Some(VlanAuxData {
            tpid: 0x8100,
            tci: 10,
        }),
    )?;
    assert!(matches!(
        writer.write_frame(&vlan),
        Err(WriterError::UnsupportedVlanMetadata)
    ));

    let direction_and_absent_fcs = frame(&[1], Direction::Outbound, FcsStatus::Absent, None)?;
    assert!(matches!(
        writer.write_frame(&direction_and_absent_fcs),
        Err(WriterError::UnrepresentablePacketFlags)
    ));
    let too_long_fcs = frame(&[1], Direction::Unknown, FcsStatus::present(16)?, None)?;
    assert!(matches!(
        writer.write_frame(&too_long_fcs),
        Err(WriterError::UnrepresentablePacketFlags)
    ));

    let timestamp = CaptureTimestamp::new(
        1,
        TimestampResolution::MICROSECOND,
        -2,
        TimestampSource::Unknown,
    );
    let metadata = CaptureMetadata::new(
        SOURCE,
        1,
        None,
        Some(timestamp),
        Direction::Unknown,
        None,
        FcsStatus::Absent,
    )
    .with_linux_interface(LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?);
    let linux_source = CapturedFrame::new(vec![1], metadata)?;
    assert!(matches!(
        writer.write_frame(&linux_source),
        Err(WriterError::LinuxInterfaceIdentityMismatch)
    ));
    assert_eq!(writer.packet_count(), 0);
    Ok(())
}

#[test]
fn config_values() -> Result<(), Box<dyn std::error::Error>> {
    let fcs = FcsStatus::present(4)?;
    let resolution = TimestampResolution::binary(10)?;
    let config = InterfaceConfig::new(64, resolution, -7, fcs)?;

    assert_eq!(config.link_type(), l2_capture::LinkType::Ethernet);
    assert_eq!(config.snaplen(), 64);
    assert_eq!(config.timestamp_resolution(), resolution);
    assert_eq!(config.timestamp_offset_seconds(), -7);
    assert_eq!(config.fcs(), fcs);
    Ok(())
}

#[test]
fn writer_snaplen() -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = PcapNgWriter::new(Vec::new(), MAX_EVIDENCE_OUTPUT_BYTES)?;
    let config = InterfaceConfig::new(1, TimestampResolution::MICROSECOND, -2, FcsStatus::Unknown)?;
    writer.add_interface(SOURCE, config)?;

    writer.write_frame(&frame(&[1], Direction::Unknown, FcsStatus::Unknown, None)?)?;
    assert!(matches!(
        writer.write_frame(&frame(
            &[1, 2],
            Direction::Unknown,
            FcsStatus::Unknown,
            None,
        )?),
        Err(WriterError::CapturedLengthExceedsSnaplen {
            captured: 2,
            snaplen: 1,
        })
    ));
    Ok(())
}

#[test]
fn writer_timestamp() -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = PcapNgWriter::new(Vec::new(), MAX_EVIDENCE_OUTPUT_BYTES)?;
    let config =
        InterfaceConfig::new(64, TimestampResolution::MICROSECOND, -1, FcsStatus::Unknown)?;
    writer.add_interface(SOURCE, config)?;
    assert!(matches!(
        writer.write_frame(&frame(&[1], Direction::Unknown, FcsStatus::Unknown, None)?),
        Err(WriterError::TimestampConfigurationMismatch)
    ));
    Ok(())
}

#[test]
fn writer_binary() -> Result<(), Box<dyn std::error::Error>> {
    let resolution = TimestampResolution::binary(10)?;
    let timestamp = CaptureTimestamp::new(1, resolution, 0, TimestampSource::Unknown);
    let metadata = CaptureMetadata::new(
        SOURCE,
        1,
        None,
        Some(timestamp),
        Direction::Unknown,
        None,
        FcsStatus::Unknown,
    );
    let packet = CapturedFrame::new(vec![1], metadata)?;
    let config = InterfaceConfig::new(64, resolution, 0, FcsStatus::Unknown)?;
    let mut writer = PcapNgWriter::new(Vec::new(), MAX_EVIDENCE_OUTPUT_BYTES)?;
    writer.add_interface(SOURCE, config)?;
    writer.write_frame(&packet)?;
    writer.finish()?;

    let mut reader = PcapNgReader::new(Cursor::new(writer.into_inner()))?;
    let decoded = reader.next_packet()?.ok_or("missing packet")?;
    let decoded_timestamp = decoded.metadata().timestamp().ok_or("missing timestamp")?;
    assert_eq!(decoded_timestamp.resolution(), resolution);
    Ok(())
}

struct FailingWriter {
    bytes: Vec<u8>,
    remaining: usize,
}

impl Write for FailingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::other("injected write failure"));
        }
        let count = bytes.len().min(self.remaining);
        let part = bytes
            .get(..count)
            .ok_or_else(|| io::Error::other("invalid test slice"))?;
        self.bytes.extend_from_slice(part);
        self.remaining -= count;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn terminal_on_partial_sink_failure() -> Result<(), Box<dyn std::error::Error>> {
    let sink = FailingWriter {
        bytes: Vec::new(),
        remaining: 30,
    };
    let mut writer = PcapNgWriter::new(sink, MAX_EVIDENCE_OUTPUT_BYTES)?;
    assert!(matches!(
        writer.add_interface(SOURCE, config(FcsStatus::Unknown)?),
        Err(WriterError::Io(_))
    ));
    assert_eq!(writer.interface_count(), 0);
    assert!(matches!(
        writer.add_interface(SOURCE, config(FcsStatus::Unknown)?),
        Err(WriterError::Terminated)
    ));
    Ok(())
}

#[test]
fn partial_first_interface_stays_terminal() -> Result<(), Box<dyn std::error::Error>> {
    let packet = frame(&[1], Direction::Inbound, FcsStatus::Unknown, None)?;
    let configuration = config(FcsStatus::Unknown)?;
    let sink = FailingWriter {
        bytes: Vec::new(),
        // The section header consumes 28 bytes, leaving a partial IDB/EPB transaction
        remaining: 70,
    };
    let mut writer = PcapNgWriter::new(sink, MAX_EVIDENCE_OUTPUT_BYTES)?;
    let header_length = writer.bytes_written();

    assert!(matches!(
        writer.add_interface_and_write_frame(SOURCE, configuration, &packet),
        Err(WriterError::Io(_))
    ));
    assert_eq!(writer.bytes_written(), header_length);
    assert_eq!(writer.interface_count(), 0);
    assert_eq!(writer.packet_count(), 0);
    assert!(matches!(
        writer.add_interface(SOURCE, configuration),
        Err(WriterError::Terminated)
    ));
    Ok(())
}

#[test]
fn fails_closed_each_output_boundary() -> Result<(), Box<dyn std::error::Error>> {
    let packet = frame(&[1], Direction::Inbound, FcsStatus::Unknown, None)?;
    let configuration = config(FcsStatus::Unknown)?;
    let mut complete = PcapNgWriter::new(Vec::new(), MAX_EVIDENCE_OUTPUT_BYTES)?;
    complete.add_interface_and_write_frame(SOURCE, configuration, &packet)?;
    let complete_length = complete.into_inner().len();

    for boundary in 0..complete_length {
        let sink = FailingWriter {
            bytes: Vec::new(),
            remaining: boundary,
        };
        let Ok(mut writer) = PcapNgWriter::new(sink, MAX_EVIDENCE_OUTPUT_BYTES) else {
            // A failure inside the section header cannot expose a writer state
            assert!(boundary < 28, "constructor failed after byte {boundary}");
            continue;
        };
        assert!(boundary >= 28);
        assert!(matches!(
            writer.add_interface_and_write_frame(SOURCE, configuration, &packet),
            Err(WriterError::Io(_))
        ));
        assert_eq!(writer.interface_count(), 0, "boundary {boundary}");
        assert_eq!(writer.packet_count(), 0, "boundary {boundary}");
        assert_eq!(writer.bytes_written(), 28, "boundary {boundary}");
        assert!(matches!(writer.finish(), Err(WriterError::Terminated)));
    }
    Ok(())
}

#[test]
fn rejects_invalid_writer_limits() {
    assert_eq!(MAX_EVIDENCE_OUTPUT_BYTES, l2_pcap::ABSOLUTE_MAX_INPUT_BYTES);
    assert!(matches!(
        PcapNgWriter::new(Vec::new(), 27),
        Err(WriterError::OutputLimitTooSmall { .. })
    ));
    assert!(matches!(
        PcapNgWriter::new(Vec::new(), MAX_EVIDENCE_OUTPUT_BYTES + 1),
        Err(WriterError::OutputLimitTooLarge { .. })
    ));
    assert_eq!(
        WriterError::Finished.to_string(),
        "PCAPNG writer is already finished"
    );
    let error = WriterError::Io(io::Error::other("sink detail"));
    assert_eq!(
        std::error::Error::source(&error).map(std::string::ToString::to_string),
        Some("sink detail".to_owned())
    );
    assert!(std::error::Error::source(&WriterError::Finished).is_none());
}

#[test]
fn streaming_writer_old_spool_ceiling() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = vec![0xaa; 65_535];
    let packet = frame(&bytes, Direction::Unknown, FcsStatus::Unknown, None)?;
    let mut writer = PcapNgWriter::new(io::sink(), 128 * 1024 * 1024)?;
    writer.add_interface(SOURCE, config(FcsStatus::Unknown)?)?;
    for _ in 0..1_025 {
        writer.write_frame(&packet)?;
    }
    writer.finish()?;
    assert!(writer.bytes_written() > 64 * 1024 * 1024);
    assert_eq!(writer.packet_count(), 1_025);
    Ok(())
}
