//! NDJSON records retain raw bytes and exact capture timestamp units

#[path = "json/ip.rs"]
mod ip;

use crate::report;
use l2_capture::{CaptureMetadata, CaptureTimestamp, CapturedFrame};
use l2_io::LinkIo;
use serde::Serialize;
use std::{error::Error, io::Write};

#[derive(Serialize)]
struct Timestamp {
    ticks: u64,
    radix: u8,
    exponent: u8,
    offset_seconds: i64,
    source: String,
}

impl From<CaptureTimestamp> for Timestamp {
    fn from(time: CaptureTimestamp) -> Self {
        let resolution = time.resolution();
        Self {
            ticks: time.ticks(),
            radix: resolution.radix(),
            exponent: resolution.exponent(),
            offset_seconds: time.offset_seconds(),
            source: format!("{:?}", time.source()),
        }
    }
}

#[derive(Serialize)]
struct Record<'input> {
    sequence: u64,
    section: u32,
    interface: u32,
    captured_len: usize,
    original_len: u32,
    truncated: bool,
    link_type: String,
    link_type_raw: u16,
    timestamp: Option<Timestamp>,
    direction: String,
    fcs: String,
    vlan_aux: Option<(u16, u16)>,
    status: report::Status,
    diagnostic: Option<String>,
    ip: Option<ip::IpRecord>,
    // A failed protocol assessment still exports the original captured bytes
    raw_bytes: &'input [u8],
}

fn record(sequence: u64, packet: &CapturedFrame) -> Record<'_> {
    let metadata: &CaptureMetadata = packet.metadata();
    let interface = metadata.interface();
    let original_len = metadata.original_len();
    let timestamp = metadata.timestamp();
    let direction = metadata.direction();
    let vlan = metadata.vlan();
    let fcs = metadata.fcs();
    let link_type = metadata.link_type();
    let assessment = report::assess_with_link_type(link_type, packet.bytes());
    // A capture cut short cannot supply a complete payload observation
    let ip = if packet.is_truncated() {
        None
    } else {
        assessment.ethernet.as_ref().and_then(|frame| {
            assessment.ip.map(|packet_ip| {
                // VLAN depth and IP extensions change offsets, so use the decoded boundary
                ip::record(packet_ip, packet.captured_len() - frame.payload.len())
            })
        })
    };
    Record {
        sequence,
        section: interface.section,
        interface: interface.index,
        captured_len: packet.captured_len(),
        original_len,
        truncated: packet.is_truncated(),
        link_type: format!("{link_type:?}"),
        link_type_raw: link_type.raw(),
        timestamp: timestamp.map(Timestamp::from),
        direction: format!("{direction:?}"),
        fcs: format!("{fcs:?}"),
        vlan_aux: vlan.map(|tag| (tag.tpid, tag.tci)),
        status: assessment.status,
        diagnostic: assessment.diagnostic,
        ip,
        raw_bytes: packet.bytes(),
    }
}

pub fn write<L: LinkIo>(link: &mut L, output: &mut impl Write) -> Result<bool, Box<dyn Error>> {
    let mut sequence = 0_u64;
    let mut clean = true;
    while let Some(packet) = link.recv()? {
        sequence = sequence.checked_add(1).ok_or("packet sequence overflow")?;
        let value = record(sequence, &packet);
        clean &= !(value.truncated
            || matches!(
                value.status,
                report::Status::Malformed | report::Status::Invalid
            )
            || value.status == report::Status::Unsupported && value.diagnostic.is_some());
        serde_json::to_writer(&mut *output, &value)?;
        output.write_all(b"\n")?;
    }
    let quality = link.collection_summary();
    crate::source_collection::json(quality, output)?;
    Ok(clean && !l2_workbench::capture_collection::reports_incomplete_collection(quality))
}
