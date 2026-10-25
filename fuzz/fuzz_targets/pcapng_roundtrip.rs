#![no_main]

use l2_pcap::{
    CaptureMetadata, CaptureTimestamp, CapturedFrame, CollectionGoal, CollectionReport,
    CollectionStopReason, Direction, FcsStatus, InterfaceConfig, InterfaceId,
    MAX_EVIDENCE_OUTPUT_BYTES, MAX_FCS_LENGTH, PcapNgReader, PcapNgWriter, TimestampResolution,
    TimestampSource,
};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

const MAX_INTERFACES: u8 = 4;
const MAX_FRAMES: u8 = 8;
const MAX_FRAME_BYTES: usize = 512;
const MAX_EPB_FCS_BYTES: u8 = 15;

// Keep generated captures small while covering several independent interfaces
fuzz_target!(|data: &[u8]| {
    let mut seed = Seed::new(data);
    let interface_count = usize::from(seed.byte() % MAX_INTERFACES).saturating_add(1);
    let mut interfaces = Vec::with_capacity(interface_count);

    for ordinal in 0..interface_count {
        let section = u32::from(seed.byte());
        let Ok(index) = u32::try_from(ordinal) else {
            return;
        };
        let source = InterfaceId { section, index };
        let Some(config) = interface_config(&mut seed) else {
            return;
        };
        interfaces.push((source, config));
    }

    let pending = CollectionReport::new(
        CollectionStopReason::Unavailable,
        CollectionGoal::Packets,
        0,
        0,
        0,
        false,
    );
    let mut writer = PcapNgWriter::new_with_collection_report(
        Cursor::new(Vec::new()),
        MAX_EVIDENCE_OUTPUT_BYTES,
        pending,
    )
    .unwrap_or_else(|error| panic!("valid memory writer failed: {error}"));
    for (source, config) in &interfaces {
        writer
            .add_interface(*source, *config)
            .unwrap_or_else(|error| panic!("valid interface was rejected: {error}"));
    }

    let frame_count = usize::from(seed.byte() % MAX_FRAMES).saturating_add(1);
    let mut expected = Vec::with_capacity(frame_count);
    for _ in 0..frame_count {
        let Some((source, config)) = choose_interface(&mut seed, &interfaces) else {
            return;
        };
        let Some(frame) = frame(&mut seed, source, config) else {
            return;
        };
        writer
            .write_frame(&frame)
            .unwrap_or_else(|error| panic!("valid frame was rejected: {error}"));
        expected.push(frame);
    }
    let report = collection_report(&mut seed);
    writer
        .update_collection_report(report)
        .unwrap_or_else(|error| panic!("valid cursor update failed: {error}"));
    writer
        .finish()
        .unwrap_or_else(|error| panic!("valid cursor finish failed: {error}"));

    let bytes = writer.into_inner().into_inner();
    let mut reader = PcapNgReader::new(Cursor::new(bytes))
        .unwrap_or_else(|error| panic!("writer emitted an invalid section: {error}"));
    for original in &expected {
        let decoded = reader
            .next_packet()
            .unwrap_or_else(|error| panic!("writer emitted an invalid packet: {error}"))
            .unwrap_or_else(|| panic!("writer lost a packet"));
        assert!(same_frame_metadata(original, &decoded));
        assert_eq!(decoded.bytes(), original.bytes());
    }
    assert!(matches!(reader.next_packet(), Ok(None)));
    // IDBs are consumed while reading packet blocks, not by the reader constructor
    assert!(same_interfaces(
        &interfaces,
        reader.interface_descriptions()
    ));
    let summary = reader.collection_summary();
    assert_eq!(summary.reported_sections, 1);
    assert_eq!(
        summary.incomplete_sections,
        u64::from(!report.supports_complete_collection())
    );
    assert_eq!(summary.capture_dropped, u64::from(report.capture_dropped()));
    assert_eq!(
        summary.interface_dropped,
        u64::from(report.interface_dropped())
    );
});

fn collection_report(seed: &mut Seed<'_>) -> CollectionReport {
    let stop = match seed.byte() % 3 {
        0 => CollectionStopReason::Unavailable,
        1 => CollectionStopReason::PacketLimit,
        _ => CollectionStopReason::Deadline,
    };
    let goal = if seed.byte() & 1 == 0 {
        CollectionGoal::Packets
    } else {
        CollectionGoal::Duration
    };
    CollectionReport::new(
        stop,
        goal,
        u32::from(seed.next_u16()),
        u32::from(seed.next_u16()),
        u32::from(seed.next_u16()),
        seed.byte() & 1 != 0,
    )
}

fn interface_config(seed: &mut Seed<'_>) -> Option<InterfaceConfig> {
    let snaplen = u32::from(seed.next_u16() % 513);
    let resolution_byte = seed.byte();
    let exponent = resolution_byte & 0x7f;
    let timestamp_resolution = if resolution_byte & 0x80 == 0 {
        TimestampResolution::decimal(exponent).ok()?
    } else {
        TimestampResolution::binary(exponent).ok()?
    };
    let offset = i64::from(i8::from_ne_bytes([seed.byte()]));
    let fcs = fcs_status(seed);
    if let FcsStatus::Present { length } = fcs {
        // The IDB stores FCS length in one octet of bits
        length.get().checked_mul(8)?;
    }
    let config = InterfaceConfig::new(snaplen, timestamp_resolution, offset, fcs).ok()?;
    if seed.byte() & 1 == 0 {
        return Some(config);
    }
    let identity = l2_capture::LinuxInterfaceIdentity::new(
        seed.next_u64().max(1),
        seed.next_u64().max(1),
        seed.next_u64().max(1),
        seed.next_u64().max(1),
        u32::from(seed.next_u16()).max(1),
    )
    .ok()?;
    Some(config.with_linux_interface(identity))
}

fn fcs_status(seed: &mut Seed<'_>) -> FcsStatus {
    match seed.byte() % 3 {
        0 => FcsStatus::Unknown,
        1 => FcsStatus::Absent,
        _ => {
            let length = (seed.byte() % MAX_FCS_LENGTH).saturating_add(1);
            FcsStatus::present(length).unwrap_or(FcsStatus::Unknown)
        }
    }
}

fn choose_interface(
    seed: &mut Seed<'_>,
    interfaces: &[(InterfaceId, InterfaceConfig)],
) -> Option<(InterfaceId, InterfaceConfig)> {
    let count = interfaces.len();
    if count == 0 {
        return None;
    }
    let choice = usize::from(seed.byte()) % count;
    interfaces.get(choice).copied()
}

fn frame(
    seed: &mut Seed<'_>,
    source: InterfaceId,
    config: InterfaceConfig,
) -> Option<CapturedFrame> {
    let requested_length = usize::from(seed.next_u16() % 513);
    let snaplen = usize::try_from(config.snaplen()).ok()?;
    let captured_length = if snaplen == 0 {
        requested_length
    } else {
        requested_length.min(snaplen)
    };
    let bytes = seed.bytes(captured_length);
    let extra_length = usize::from(seed.byte() % 32);
    let original_length = u32::try_from(bytes.len().saturating_add(extra_length)).ok()?;
    let timestamp = CaptureTimestamp::new(
        seed.next_u64(),
        config.timestamp_resolution(),
        config.timestamp_offset_seconds(),
        TimestampSource::Unknown,
    );
    let direction = packet_direction(seed, config.fcs());
    let packet_fcs = packet_fcs(seed, config.fcs());
    let metadata = CaptureMetadata::new(
        source,
        original_length,
        None,
        Some(timestamp),
        direction,
        None,
        packet_fcs,
    );
    let metadata = match config.linux_interface() {
        Some(identity) => metadata.with_linux_interface(identity),
        None => metadata,
    };
    CapturedFrame::new(bytes, metadata).ok()
}

fn packet_direction(seed: &mut Seed<'_>, interface_fcs: FcsStatus) -> Direction {
    // Packet flags cannot carry an absent or long FCS declaration
    if matches!(interface_fcs, FcsStatus::Absent)
        || matches!(interface_fcs, FcsStatus::Present { length } if length.get() > MAX_EPB_FCS_BYTES)
    {
        return Direction::Unknown;
    }
    match seed.byte() % 3 {
        0 => Direction::Unknown,
        1 => Direction::Inbound,
        _ => Direction::Outbound,
    }
}

fn packet_fcs(seed: &mut Seed<'_>, interface_fcs: FcsStatus) -> FcsStatus {
    if !matches!(interface_fcs, FcsStatus::Unknown) {
        return interface_fcs;
    }
    if seed.byte() & 1 == 0 {
        return FcsStatus::Unknown;
    }
    let length = (seed.byte() % MAX_EPB_FCS_BYTES).saturating_add(1);
    FcsStatus::present(length).unwrap_or(FcsStatus::Unknown)
}

fn same_frame_metadata(original: &CapturedFrame, decoded: &CapturedFrame) -> bool {
    let original_timestamp = original.metadata().timestamp().map(timestamp_fields);
    let decoded_timestamp = decoded.metadata().timestamp().map(timestamp_fields);
    let expected_interface = InterfaceId {
        section: 0,
        index: original.metadata().interface().index,
    };
    original.metadata().original_len() == decoded.metadata().original_len()
        && expected_interface == decoded.metadata().interface()
        && original.metadata().direction() == decoded.metadata().direction()
        && original.metadata().fcs() == decoded.metadata().fcs()
        && original.metadata().linux_interface() == decoded.metadata().linux_interface()
        && original_timestamp == decoded_timestamp
        && original.is_truncated() == decoded.is_truncated()
}

fn same_interfaces(
    original: &[(InterfaceId, InterfaceConfig)],
    decoded: &[l2_pcap::InterfaceDescription],
) -> bool {
    if original.len() != decoded.len() {
        return false;
    }
    for (ordinal, ((_, config), description)) in original.iter().zip(decoded).enumerate() {
        let Ok(index) = u32::try_from(ordinal) else {
            return false;
        };
        let expected_fcs = match config.fcs() {
            FcsStatus::Unknown => None,
            FcsStatus::Absent => Some(0),
            FcsStatus::Present { length } => Some(length.get()),
        };
        if description.id != (InterfaceId { section: 0, index })
            || description.snaplen != config.snaplen()
            || description.timestamp_resolution != config.timestamp_resolution()
            || description.timestamp_offset_seconds != config.timestamp_offset_seconds()
            || description.fcs_length != expected_fcs
            || description.linux_interface() != config.linux_interface()
        {
            return false;
        }
    }
    true
}

const fn timestamp_fields(timestamp: CaptureTimestamp) -> (u64, TimestampResolution, i64) {
    (
        timestamp.ticks(),
        timestamp.resolution(),
        timestamp.offset_seconds(),
    )
}

struct Seed<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Seed<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn byte(&mut self) -> u8 {
        let value = self.data.get(self.offset).copied().unwrap_or(0);
        self.offset = self.offset.saturating_add(1);
        value
    }

    fn next_u16(&mut self) -> u16 {
        u16::from_le_bytes([self.byte(), self.byte()])
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];
        for byte in &mut bytes {
            *byte = self.byte();
        }
        u64::from_le_bytes(bytes)
    }

    fn bytes(&mut self, length: usize) -> Vec<u8> {
        let remaining = self.data.len().saturating_sub(self.offset);
        let count = length.min(remaining).min(MAX_FRAME_BYTES);
        let output = self
            .data
            .get(self.offset..self.offset.saturating_add(count))
            .map_or_else(Vec::new, ToOwned::to_owned);
        self.offset = self.offset.saturating_add(count);
        output
    }
}
