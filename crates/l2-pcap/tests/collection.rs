pub mod common;

use common::pcapng::{self, ByteOrder};
use l2_pcap::{
    CollectionGoal, CollectionReport, CollectionStopReason, Error, PcapNgReader, PcapNgWriter,
    WriterError,
};
use std::{
    fs::{self, File, OpenOptions},
    io::Cursor,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct RemoveFile(PathBuf);

impl Drop for RemoveFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn append_output() -> Result<(RemoveFile, File), Box<dyn std::error::Error>> {
    loop {
        let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "l2-pcap-append-report-{}-{sequence}.pcapng",
            std::process::id()
        ));
        match OpenOptions::new().append(true).create_new(true).open(&path) {
            Ok(file) => return Ok((RemoveFile(path), file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
}

#[test]
fn finalizing_collection_existing_sink_prefix() -> Result<(), Box<dyn std::error::Error>> {
    let pending = CollectionReport::new(
        CollectionStopReason::Unavailable,
        CollectionGoal::Packets,
        0,
        0,
        0,
        false,
    );
    let complete = CollectionReport::new(
        CollectionStopReason::PacketLimit,
        CollectionGoal::Packets,
        2,
        0,
        0,
        true,
    );
    let mut sink = Cursor::new(vec![0xaa; 37]);
    sink.set_position(37);
    let mut writer = PcapNgWriter::new_with_collection_report(sink, 1_048_576, pending)?;
    let source = l2_capture::InterfaceId {
        section: 0,
        index: 0,
    };
    let config = l2_pcap::InterfaceConfig::new(
        65_535,
        l2_capture::TimestampResolution::MICROSECOND,
        0,
        l2_capture::FcsStatus::Unknown,
    )?;
    writer.add_interface(source, config)?;
    let time = l2_capture::CaptureTimestamp::new(
        12,
        l2_capture::TimestampResolution::MICROSECOND,
        0,
        l2_capture::TimestampSource::Unknown,
    );
    let packet = l2_capture::CapturedFrame::new(
        vec![1, 2],
        l2_capture::CaptureMetadata::new(
            source,
            2,
            None,
            Some(time),
            l2_capture::Direction::Unknown,
            None,
            l2_capture::FcsStatus::Unknown,
        ),
    )?;
    writer.write_frame(&packet)?;
    let before = writer.bytes_written();
    writer.update_collection_report(complete)?;
    assert_eq!(writer.bytes_written(), before);
    writer.write_frame(&packet)?;
    writer.finish()?;
    let bytes = writer.into_inner().into_inner();
    assert_eq!(bytes.get(..37), Some(vec![0xaa; 37].as_slice()));
    let capture = bytes.get(37..).ok_or("missing section")?;
    let mut reader = PcapNgReader::new(Cursor::new(capture))?;
    assert_eq!(pcapng::first_frame(&mut reader)?.bytes(), [1, 2]);
    assert_eq!(pcapng::first_frame(&mut reader)?.bytes(), [1, 2]);
    assert!(reader.next_packet()?.is_none());
    assert_eq!(reader.collection_summary().incomplete_sections, 0);
    Ok(())
}

#[test]
fn collection_update_sink_terminates_writer() -> Result<(), Box<dyn std::error::Error>> {
    let pending = CollectionReport::new(
        CollectionStopReason::Unavailable,
        CollectionGoal::Packets,
        0,
        0,
        0,
        false,
    );
    let complete = CollectionReport::new(
        CollectionStopReason::PacketLimit,
        CollectionGoal::Packets,
        10,
        0,
        0,
        true,
    );
    let sizing = PcapNgWriter::new_with_collection_report(Vec::new(), 1_048_576, pending)?;
    let output_limit = sizing.bytes_written();
    let (cleanup, output) = append_output()?;
    let mut writer = PcapNgWriter::new_with_collection_report(output, output_limit, pending)?;

    assert!(matches!(
        writer.update_collection_report(complete),
        Err(WriterError::Io(_))
    ));
    assert_eq!(writer.bytes_written(), output_limit);
    assert!(matches!(writer.finish(), Err(WriterError::Terminated)));

    let output = writer.into_inner();
    assert!(output.metadata()?.len() > output_limit);
    let mut reader = PcapNgReader::new(File::open(&cleanup.0)?)?;
    assert!(reader.next_packet()?.is_none());
    assert_eq!(reader.collection_summary().sections, 2);
    assert_eq!(reader.collection_summary().incomplete_sections, 1);
    Ok(())
}

#[test]
fn collection_round_fixed_header_length() -> Result<(), Box<dyn std::error::Error>> {
    let reports = [
        CollectionReport::new(
            CollectionStopReason::Unavailable,
            CollectionGoal::Packets,
            0,
            0,
            0,
            false,
        ),
        CollectionReport::new(
            CollectionStopReason::PacketLimit,
            CollectionGoal::Packets,
            10,
            0,
            0,
            true,
        ),
        CollectionReport::new(
            CollectionStopReason::Deadline,
            CollectionGoal::Packets,
            u32::MAX,
            4,
            7,
            false,
        ),
    ];
    let mut lengths = Vec::new();
    for report in reports {
        let mut writer = PcapNgWriter::new_with_collection_report(Vec::new(), 1_048_576, report)?;
        writer.finish()?;
        let bytes = writer.into_inner();
        lengths.push(bytes.len());
        let mut reader = PcapNgReader::new(Cursor::new(bytes))?;
        assert!(reader.next_packet()?.is_none());
        let quality = reader.collection_summary();
        assert_eq!(quality.reported_sections, 1);
        assert_eq!(
            quality.incomplete_sections,
            u64::from(!report.supports_complete_collection())
        );
        assert_eq!(quality.capture_dropped, u64::from(report.capture_dropped()));
        assert_eq!(
            quality.interface_dropped,
            u64::from(report.interface_dropped())
        );
    }
    assert!(lengths.windows(2).all(|pair| pair.first() == pair.get(1)));
    Ok(())
}

#[test]
fn later_complete_not_incomplete_collection() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = pcapng::section_header_with_options(
        ByteOrder::Big,
        -1,
        &[(
            1,
            b"l2solver:collection:v1:1:1:0000000010:0000000000:0000000000:0",
        )],
    );
    bytes.extend(pcapng::section_header_with_options(
        ByteOrder::Little,
        -1,
        &[(
            1,
            b"l2solver:collection:v1:2:2:0000000020:0000000000:0000000000:1",
        )],
    ));
    let mut reader = PcapNgReader::new(Cursor::new(bytes))?;
    assert!(reader.next_packet()?.is_none());
    let quality = reader.collection_summary();
    assert_eq!(quality.reported_sections, 2);
    assert_eq!(quality.incomplete_sections, 1);
    Ok(())
}

#[test]
fn malformed_duplicate_never_complete_evidence() {
    for (report, repeated) in [
        (
            "l2solver:collection:v1:1:1:10:0000000000:0000000000:1",
            false,
        ),
        (
            "l2solver:collection:v1:1:1:0000000010:0000000000:0000000000:2",
            false,
        ),
        (
            "l2solver:collection:v1:1:1:0000000010:0000000000:0000000000:1",
            true,
        ),
    ] {
        let mut comments = vec![(1, report.as_bytes())];
        if repeated {
            comments.push((1, report.as_bytes()));
        }
        let bytes = pcapng::section_header_with_options(ByteOrder::Little, -1, &comments);
        assert!(matches!(
            PcapNgReader::new(Cursor::new(bytes)),
            Err(Error::InvalidCollectionReport)
        ));
    }
}
