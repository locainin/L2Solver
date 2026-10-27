#![no_main]

use libfuzzer_sys::fuzz_target;
use wifi_discovery::{ObservationContext, Survey, SurveyLimits, WirelessInput};

const MAX_INPUT_BYTES: usize = 4_096;
const MAX_CHUNK_BYTES: usize = 256;
const MAX_CHUNKS: usize = 8;
const SCHEDULE_NS: u64 = 1_000_000;

// Small runtime limits make inventory and diagnostic exhaustion reachable
fuzz_target!(|data: &[u8]| {
    let length = data.len().min(MAX_INPUT_BYTES);
    let Some(input) = data.get(..length) else {
        return;
    };
    let Ok(limits) = SurveyLimits::new(8, 32, 64, 8) else {
        return;
    };
    let Ok(mut survey) = Survey::new(limits) else {
        return;
    };
    let _ = survey.record_radio_schedule(0, SCHEDULE_NS);

    for (ordinal, chunk) in input.chunks(MAX_CHUNK_BYTES).take(MAX_CHUNKS).enumerate() {
        let Ok(index) = u64::try_from(ordinal) else {
            return;
        };
        let sequence = index.saturating_mul(3).saturating_add(1);
        let truncated = chunk.first().copied().is_some_and(|value| value & 1 != 0);
        let context = if truncated {
            ObservationContext::without_time(sequence)
        } else {
            ObservationContext::new(sequence, sequence.saturating_mul(1_000))
        }
        .with_capture_truncated(truncated);
        let _ = context.monotonic_ns();
        let _ = survey.observe(WirelessInput::Ieee80211(chunk), context);

        let beacon = seeded_beacon(chunk);
        let beacon_context = ObservationContext::new(
            sequence.saturating_add(1),
            sequence.saturating_add(1).saturating_mul(1_000),
        );
        let _ = survey.observe(WirelessInput::Ieee80211(&beacon), beacon_context);

        let frequency = 2_412_u16.saturating_add(
            u16::from(chunk.first().copied().map_or(0, |value| value % 15)).saturating_mul(5),
        );
        let dwell = u64::from(chunk.get(1).copied().unwrap_or(1));
        let _ = survey.record_channel_dwell(0, frequency, dwell);

        let radiotap = seeded_radiotap(&beacon, chunk.first().copied().unwrap_or(0));
        let radiotap_context = ObservationContext::new(
            sequence.saturating_add(2),
            sequence.saturating_add(2).saturating_mul(1_000),
        );
        let _ = survey.observe(WirelessInput::Radiotap(&radiotap), radiotap_context);
    }

    if let Ok(coverage) = survey.channel_coverage(0) {
        let _ = (
            coverage.radio(),
            coverage.total_scheduled_ns(),
            coverage.observed_ns(),
            coverage.coverage_basis_points(),
        );
        for channel in coverage.channels() {
            let _ = (channel.frequency_mhz(), channel.dwell_ns());
        }
    }
    for access_point in survey.access_points().take(8) {
        let _ = (
            access_point.bssid(),
            access_point.ssid(),
            access_point.channel(),
            access_point.frequency_mhz(),
            access_point.signal_dbm(),
            access_point.security(),
            access_point.security_complete(),
        );
    }
    for station in survey.stations().take(32) {
        let _ = (
            station.address(),
            station.associated_bssid(),
            station.first_sequence(),
            station.last_sequence(),
            station.frames(),
        );
    }
    for diagnostic in survey.diagnostics().iter().take(64) {
        let _ = (
            diagnostic.sequence(),
            diagnostic.kind(),
            diagnostic.message(),
        );
    }
    let _ = survey.inventory_incomplete();
});

fn seeded_beacon(input: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(320);

    // Three-address management header with a stable BSSID
    frame.extend_from_slice(&(8_u16 << 4).to_le_bytes());
    frame.extend_from_slice(&[0_u8; 2]);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 3]);
    frame.extend_from_slice(&[0_u8; 2]);
    frame.extend_from_slice(&[0_u8; 8]);
    frame.extend_from_slice(&100_u16.to_le_bytes());
    frame.extend_from_slice(&0x0010_u16.to_le_bytes());

    // Bound the SSID at the protocol maximum and retain arbitrary bytes
    let ssid_length = input.len().min(32);
    let Ok(ssid_length) = u8::try_from(ssid_length) else {
        return frame;
    };
    frame.extend_from_slice(&[0, ssid_length]);
    if let Some(ssid) = input.get(..usize::from(ssid_length)) {
        frame.extend_from_slice(ssid);
    }
    frame.extend_from_slice(&[3, 1, 6]);

    // A malformed fuzzed RSN element is followed by a valid one for both paths
    let security_length = input.len().min(255);
    let Ok(security_length) = u8::try_from(security_length) else {
        return frame;
    };
    frame.extend_from_slice(&[48, security_length]);
    if let Some(security) = input.get(..usize::from(security_length)) {
        frame.extend_from_slice(security);
    }
    frame.extend_from_slice(&[
        48, 20, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 128, 0,
    ]);
    frame
}

fn seeded_radiotap(wifi: &[u8], marker: u8) -> Vec<u8> {
    let has_fcs = marker & 1 != 0;
    let flags = if has_fcs { 0x10 } else { 0 };
    let mut frame = Vec::with_capacity(32 + wifi.len());

    // Present flags, channel, and signal fields with bounded alignment
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&15_u16.to_le_bytes());
    frame.extend_from_slice(&((1_u32 << 1) | (1_u32 << 3) | (1_u32 << 5)).to_le_bytes());
    frame.push(flags);
    frame.push(0);
    frame.extend_from_slice(&2_412_u16.to_le_bytes());
    frame.extend_from_slice(&[0_u8; 2]);
    frame.extend_from_slice(&i8::from_ne_bytes([marker]).to_ne_bytes());
    frame.extend_from_slice(wifi);
    if has_fcs {
        frame.extend_from_slice(&[0_u8; 4]);
    }
    frame
}
