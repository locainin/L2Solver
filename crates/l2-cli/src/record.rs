//! Atomic receive-only PCAPNG recording with retained collection conditions

use crate::arguments::LiveLimit;
use std::{error::Error, io::Write, path::Path};

#[cfg(all(test, feature = "live"))]
#[path = "../tests/record/completeness.rs"]
mod tests;

#[cfg(feature = "live")]
fn finish_recording<W: Write + std::io::Seek>(
    recorder: &mut l2_io::PcapNgRecorder<W>,
    quality: crate::completion::LiveCaptureQuality,
) -> std::io::Result<()> {
    // A partial collection remains useful evidence when its limits stay attached
    recorder
        .update_collection_report(quality.collection_report())
        .map_err(std::io::Error::other)?;
    recorder.finish().map_err(std::io::Error::other)
}

#[cfg(feature = "live")]
pub fn run(
    interface: &str,
    limit: LiveLimit,
    destination: &Path,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    use l2_io::{LinkIo, PcapNgRecorder, RecordingLink};
    use l2_pcap::MAX_EVIDENCE_OUTPUT_BYTES;
    use std::io;

    let packets = limit.packet_ceiling();
    let duration = limit.duration_ceiling();
    let live = l2_live::LiveLink::open_with_limits(interface, packets, duration)?;
    writeln!(
        io::stderr().lock(),
        "Recording {} (receive-only, inbound filter requested, non-promiscuous; at most {packets} frames / {} seconds)",
        interface.escape_debug(),
        duration.as_secs()
    )?;

    // Publish only after the complete PCAPNG stream has been flushed and synced
    let (recorded, bytes, quality) = crate::publish::create(destination, |file| {
        let pending = l2_pcap::CollectionReport::new(
            l2_pcap::CollectionStopReason::Unavailable,
            if limit.duration_is_goal() {
                l2_pcap::CollectionGoal::Duration
            } else {
                l2_pcap::CollectionGoal::Packets
            },
            0,
            0,
            0,
            false,
        );
        let recorder =
            PcapNgRecorder::new_with_collection_report(file, MAX_EVIDENCE_OUTPUT_BYTES, pending)
                .map_err(io::Error::other)?;
        let mut recording = RecordingLink::new(live, recorder);
        while recording.next_event().map_err(io::Error::other)?.is_some() {}
        let (mut live, mut recorder) = recording.into_parts();
        let packet_count = recorder.packet_count();
        let bytes_written = recorder.bytes_written();
        let statistics = live.statistics().map_err(io::Error::other)?;
        let quality = crate::completion::LiveCaptureQuality::from_libpcap(
            live.stop_reason(),
            limit.duration_is_goal(),
            statistics,
        );
        finish_recording(&mut recorder, quality)?;
        Ok((packet_count, bytes_written, quality))
    })?;
    let stop = match quality.stop_reason() {
        crate::completion::LiveStopReason::PacketLimit => "packet-limit",
        crate::completion::LiveStopReason::Deadline => "duration-limit",
        crate::completion::LiveStopReason::Unavailable => "unavailable",
    };
    writeln!(
        output,
        "recorded={recorded} bytes={bytes} stop={stop} capture_received={} capture_dropped={} interface_dropped={} loss_counters_authoritative={} output={}",
        quality.received(),
        quality.capture_dropped(),
        quality.interface_dropped(),
        quality.loss_counters_authoritative(),
        destination.display().to_string().escape_debug()
    )?;
    Ok(quality.supports_complete_collection())
}

#[cfg(not(feature = "live"))]
pub fn run(
    _interface: &str,
    _limit: LiveLimit,
    _destination: &Path,
    _output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    Err("live recording is optional; build with cargo build -p l2-cli --features live".into())
}
