use l2_capture::{
    CaptureMetadata, CaptureTimestamp, CapturedFrame, Direction, FcsStatus, InterfaceId,
    TimestampResolution, TimestampSource,
};
use l2_io::{
    FakeLink, FrameRecorder, LinkEvent, LinkIo, PcapNgRecorder, RecordingError, RecordingLink,
};
use l2_pcap::{PcapNgReader, WriterError};
use std::{
    error::Error,
    io::{self, Cursor, Write},
};

struct FlushFailure;

impl Write for FlushFailure {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("flush failed"))
    }
}

struct FailAfter {
    remaining: usize,
}

impl Write for FailAfter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::other("injected write failure"));
        }
        let accepted = self.remaining.min(bytes.len());
        self.remaining -= accepted;
        Ok(accepted)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn frame(source: InterfaceId, ticks: u64, bytes: &[u8]) -> Result<CapturedFrame, Box<dyn Error>> {
    let timestamp = CaptureTimestamp::new(
        ticks,
        TimestampResolution::decimal(6)?,
        0,
        TimestampSource::Unknown,
    );
    let metadata = CaptureMetadata::new(
        source,
        u32::try_from(bytes.len())?,
        None,
        Some(timestamp),
        Direction::Inbound,
        None,
        FcsStatus::Unknown,
    );
    Ok(CapturedFrame::new(bytes.to_vec(), metadata)?)
}

#[test]
fn records_each_frame_once() -> Result<(), Box<dyn Error>> {
    let first_source = InterfaceId {
        section: 3,
        index: 9,
    };
    let second_source = InterfaceId {
        section: 4,
        index: 2,
    };
    let mut source = FakeLink::with_capacity(3)?;
    source.push_rx(frame(first_source, 11, &[1, 2, 3])?)?;
    source.push_rx(frame(second_source, 12, &[4, 5])?)?;
    source.push_rx(frame(first_source, 13, &[6])?)?;
    let recorder = PcapNgRecorder::new(Vec::new(), 1_048_576)?;
    let mut link = RecordingLink::new(source, recorder);

    for expected in [&[1, 2, 3][..], &[4, 5][..], &[6][..]] {
        let Some(LinkEvent::Frame(observed)) = link.next_event()? else {
            return Err("missing recorded frame".into());
        };
        assert_eq!(observed.bytes(), expected);
    }
    assert!(link.next_event()?.is_none());
    assert_eq!(link.recorder().interface_count(), 2);
    assert_eq!(link.recorder().packet_count(), 3);

    let (_, mut writer) = link.into_parts();
    writer.finish()?;
    let mut reader = PcapNgReader::new(Cursor::new(writer.into_inner()))?;
    let mut decoded = Vec::new();
    while let Some(packet) = reader.next_packet()? {
        decoded.push(packet.bytes().to_vec());
    }
    assert_eq!(decoded, vec![vec![1, 2, 3], vec![4, 5], vec![6]]);
    Ok(())
}

#[test]
fn recording_linux_without_packet_bytes() -> Result<(), Box<dyn Error>> {
    let source = InterfaceId {
        section: 0,
        index: 7,
    };
    let identity = l2_capture::LinuxInterfaceIdentity::new(1, 2, 3, 4, 7)?;
    let packet = frame(source, 12, &[0xaa, 0xbb])?;
    let packet = CapturedFrame::new(
        packet.bytes().to_vec(),
        packet.metadata().clone().with_linux_interface(identity),
    )?;
    let mut recorder = PcapNgRecorder::new(Vec::new(), 1_048_576)?;
    recorder.record(&packet)?;
    recorder.finish()?;

    let mut reader = PcapNgReader::new(Cursor::new(recorder.into_inner()))?;
    let recovered = reader.next_packet()?.ok_or("missing recorded packet")?;
    assert_eq!(recovered.bytes(), packet.bytes());
    assert_eq!(recovered.metadata().linux_interface(), Some(identity));
    assert!(reader.next_packet()?.is_none());
    Ok(())
}

#[test]
fn stops_on_spool_quota() -> Result<(), Box<dyn Error>> {
    let source_id = InterfaceId {
        section: 0,
        index: 1,
    };
    let mut source = FakeLink::with_capacity(1)?;
    source.push_rx(frame(source_id, 1, &[0xaa])?)?;
    let recorder = PcapNgRecorder::new(Vec::new(), 28)?;
    let mut link = RecordingLink::new(source, recorder);

    assert!(matches!(
        link.next_event(),
        Err(RecordingError::Recorder(
            WriterError::OutputLimitExceeded { .. }
        ))
    ));
    assert!(matches!(link.next_event(), Err(RecordingError::Terminated)));
    assert_eq!(link.recorder().packet_count(), 0);
    Ok(())
}

#[test]
fn rejects_missing_timestamp_before_commit() -> Result<(), Box<dyn Error>> {
    let source_id = InterfaceId {
        section: 0,
        index: 1,
    };
    let packet = CapturedFrame::new(vec![0xaa], CaptureMetadata::unknown(source_id, 1))?;
    let mut source = FakeLink::with_capacity(1)?;
    source.push_rx(packet)?;
    let recorder = PcapNgRecorder::new(Vec::new(), 1_048_576)?;
    let mut link = RecordingLink::new(source, recorder);

    assert!(matches!(
        link.next_event(),
        Err(RecordingError::Recorder(WriterError::MissingTimestamp))
    ));
    assert_eq!(link.recorder().interface_count(), 0);
    assert_eq!(link.recorder().packet_count(), 0);
    Ok(())
}

#[test]
fn rejects_invalid_frame_before_commit() -> Result<(), Box<dyn Error>> {
    let packet = frame(
        InterfaceId {
            section: 0,
            index: 1,
        },
        1,
        &[0xaa],
    )?;
    let metadata = packet.metadata();
    let invalid_metadata = l2_capture::CaptureMetadata::new(
        metadata.interface(),
        metadata.original_len(),
        metadata.locator(),
        metadata.timestamp(),
        l2_capture::Direction::Outbound,
        metadata.vlan(),
        l2_capture::FcsStatus::Absent,
    );
    let invalid_packet = CapturedFrame::new(packet.bytes().to_vec(), invalid_metadata)?;
    let mut recorder = PcapNgRecorder::new(Vec::new(), 1_048_576)?;
    let before = recorder.bytes_written();

    assert!(matches!(
        recorder.record(&invalid_packet),
        Err(WriterError::UnrepresentablePacketFlags)
    ));
    assert_eq!(recorder.interface_count(), 0);
    assert_eq!(recorder.packet_count(), 0);
    assert_eq!(recorder.bytes_written(), before);
    Ok(())
}

#[test]
fn checks_interface_budget_before_commit() -> Result<(), Box<dyn Error>> {
    let packet = frame(
        InterfaceId {
            section: 0,
            index: 1,
        },
        1,
        &[0xaa],
    )?;
    let mut sizing = PcapNgRecorder::new(Vec::new(), 1_048_576)?;
    sizing.record(&packet)?;
    let limit = sizing
        .bytes_written()
        .checked_sub(1)
        .ok_or("missing bytes")?;

    let mut recorder = PcapNgRecorder::new(Vec::new(), limit)?;
    let before = recorder.bytes_written();
    assert!(matches!(
        recorder.record(&packet),
        Err(WriterError::OutputLimitExceeded { .. })
    ));
    assert_eq!(recorder.interface_count(), 0);
    assert_eq!(recorder.packet_count(), 0);
    assert_eq!(recorder.bytes_written(), before);
    Ok(())
}

#[test]
fn first_frame_closed_output_boundary() -> Result<(), Box<dyn Error>> {
    let packet = frame(
        InterfaceId {
            section: 0,
            index: 1,
        },
        1,
        &[0xaa],
    )?;
    let mut complete = PcapNgRecorder::new(Vec::new(), 1_048_576)?;
    complete.record(&packet)?;
    let complete_length = complete.into_inner().len();

    for boundary in 0..complete_length {
        let sink = FailAfter {
            remaining: boundary,
        };
        let Ok(mut recorder) = PcapNgRecorder::new(sink, 1_048_576) else {
            assert!(boundary < 28, "constructor failed after byte {boundary}");
            continue;
        };
        assert!(matches!(recorder.record(&packet), Err(WriterError::Io(_))));
        assert_eq!(recorder.interface_count(), 0, "boundary {boundary}");
        assert_eq!(recorder.packet_count(), 0, "boundary {boundary}");
        assert_eq!(recorder.bytes_written(), 28, "boundary {boundary}");
        assert!(matches!(recorder.finish(), Err(WriterError::Terminated)));
    }
    Ok(())
}

#[test]
fn finishes_complete_recording() -> Result<(), Box<dyn Error>> {
    let mut recorder = PcapNgRecorder::new(Vec::new(), 1_048_576)?;
    assert!(recorder.bytes_written() > 0);
    assert_eq!(recorder.packet_count(), 0);
    recorder.finish()?;
    let bytes_written = recorder.bytes_written();
    let output = recorder.into_inner();
    assert_eq!(bytes_written, u64::try_from(output.len())?);
    Ok(())
}

#[test]
fn recorder_finish_propagates_flush_failures() -> Result<(), Box<dyn Error>> {
    let mut recorder = PcapNgRecorder::new(FlushFailure, 1_048_576)?;

    assert!(matches!(
        recorder.finish(),
        Err(WriterError::Io(error)) if error.to_string() == "flush failed"
    ));
    Ok(())
}
