use l2_capture::{CaptureMetadata, CapturedFrame, InterfaceId};

// Shared names keep fixture access consistent across the survey suite
pub use super::captures::{LINUX_STP as LINUX_STP_PCAP, LLDP as LLDP_PCAP};

// The synthetic STP source and root share this locally administered address
pub const STP_FIXTURE_MAC: &str = "02:00:00:00:00:02";

pub fn frame(bytes: Vec<u8>, original: u32) -> Result<CapturedFrame, l2_capture::FrameError> {
    CapturedFrame::new(
        bytes,
        CaptureMetadata::unknown(
            InterfaceId {
                section: 0,
                index: 0,
            },
            original,
        ),
    )
}

pub fn captured(bytes: Vec<u8>) -> Result<CapturedFrame, Box<dyn std::error::Error>> {
    let original = u32::try_from(bytes.len())?;
    Ok(frame(bytes, original)?)
}

pub fn ethernet_frame(
    destination: [u8; 6],
    source: [u8; 6],
    field: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(14 + payload.len());
    bytes.extend_from_slice(&destination);
    bytes.extend_from_slice(&source);
    bytes.extend_from_slice(&field.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

pub fn tagged_ethernet_frame(
    destination: [u8; 6],
    source: [u8; 6],
    tpid: u16,
    tci: u16,
    field: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(18 + payload.len());
    bytes.extend_from_slice(&destination);
    bytes.extend_from_slice(&source);
    bytes.extend_from_slice(&tpid.to_be_bytes());
    bytes.extend_from_slice(&tci.to_be_bytes());
    bytes.extend_from_slice(&field.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

pub const fn source_with_suffix(suffix: u16) -> [u8; 6] {
    let [high, low] = suffix.to_be_bytes();
    [0, 0, 0, 0, high, low]
}
