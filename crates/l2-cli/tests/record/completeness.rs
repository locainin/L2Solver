use std::{error::Error, io::Cursor};

use crate::completion::{LiveCaptureQuality, LiveGoal, LiveStopReason};

fn recorded_quality(
    quality: LiveCaptureQuality,
) -> Result<l2_pcap::CollectionSummary, Box<dyn Error>> {
    let pending = l2_pcap::CollectionReport::new(
        l2_pcap::CollectionStopReason::Unavailable,
        l2_pcap::CollectionGoal::Packets,
        0,
        0,
        0,
        false,
    );
    let mut recorder = l2_io::PcapNgRecorder::new_with_collection_report(
        Cursor::new(Vec::new()),
        1_048_576,
        pending,
    )?;
    super::finish_recording(&mut recorder, quality)?;
    let mut reader = l2_pcap::PcapNgReader::new(Cursor::new(recorder.into_inner().into_inner()))?;
    assert!(reader.next_packet()?.is_none());
    Ok(reader.collection_summary())
}

#[test]
fn reported_loss_saved_incomplete_collection() -> Result<(), Box<dyn Error>> {
    let quality = LiveCaptureQuality::reported_for_test(
        LiveStopReason::PacketLimit,
        LiveGoal::Packets,
        10,
        0,
        0,
    );
    let recorded = recorded_quality(quality)?;
    assert_eq!(recorded.reported_sections, 1);
    assert_eq!(recorded.incomplete_sections, 1);
    assert!(!quality.supports_complete_collection());
    Ok(())
}

#[test]
fn authoritative_loss_saved_complete_collection() -> Result<(), Box<dyn Error>> {
    let quality = LiveCaptureQuality::authoritative_for_test(
        Some(l2_live::StopReason::PacketLimit),
        false,
        10,
        0,
        0,
    );
    assert_eq!(recorded_quality(quality)?.incomplete_sections, 0);
    assert!(quality.supports_complete_collection());
    Ok(())
}

#[test]
fn wrong_ceiling_losses_visible_recording() -> Result<(), Box<dyn Error>> {
    let wrong_stop = LiveCaptureQuality::authoritative_for_test(
        Some(l2_live::StopReason::Deadline),
        false,
        10,
        0,
        0,
    );
    assert_eq!(recorded_quality(wrong_stop)?.incomplete_sections, 1);
    let loss = LiveCaptureQuality::authoritative_for_test(
        Some(l2_live::StopReason::PacketLimit),
        false,
        10,
        3,
        4,
    );
    let recorded = recorded_quality(loss)?;
    assert_eq!(recorded.incomplete_sections, 1);
    assert_eq!(
        (recorded.capture_dropped, recorded.interface_dropped),
        (3, 4)
    );
    Ok(())
}
