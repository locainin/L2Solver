use l2_capture::{CaptureMetadata, CapturedFrame, InterfaceId, LinkType};
use l2_io::{FakeLink, LinkEvent, LinkIo, PcapNgRecorder, RecordingLink};
use std::io::Cursor;

#[test]
fn recording_source_type() -> Result<(), Box<dyn std::error::Error>> {
    let source_id = InterfaceId {
        section: 0,
        index: 0,
    };
    let metadata = CaptureMetadata::new(
        source_id,
        2,
        None,
        Some(l2_capture::CaptureTimestamp::new(
            1,
            l2_capture::TimestampResolution::MICROSECOND,
            0,
            l2_capture::TimestampSource::Unknown,
        )),
        l2_capture::Direction::Unknown,
        None,
        l2_capture::FcsStatus::Unknown,
    )
    .with_link_type(LinkType::Ieee80211Radiotap);
    let frame = CapturedFrame::new(vec![0xaa, 0xbb], metadata)?;
    let mut source = FakeLink::with_capacity(1)?;
    source.push_rx(frame)?;
    let recorder = PcapNgRecorder::new(Vec::new(), 1_048_576)?;
    let mut link = RecordingLink::new(source, recorder);

    let Some(LinkEvent::Frame(received)) = link.next_event()? else {
        return Err("missing recorded frame".into());
    };
    assert_eq!(received.metadata().link_type(), LinkType::Ieee80211Radiotap);
    let (_, mut recorder) = link.into_parts();
    recorder.finish()?;
    let mut reader = l2_pcap::PcapNgReader::new(Cursor::new(recorder.into_inner()))?;
    let decoded = reader.next_packet()?.ok_or("missing replayed frame")?;
    assert_eq!(decoded.metadata().link_type(), LinkType::Ieee80211Radiotap);
    Ok(())
}
