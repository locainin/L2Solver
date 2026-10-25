use l2_audit::{Policy, Report, Survey};
use l2_capture::{CaptureMetadata, CapturedFrame, Direction, FcsStatus, InterfaceId};

pub type TestResult = Result<(), Box<dyn std::error::Error>>;
pub const FIRST_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
pub const SECOND_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
pub const CLIENT_MAC: [u8; 6] = [2, 0, 0, 0, 0, 3];
pub const ADDRESS: [u8; 4] = [192, 0, 2, 1];

pub fn ethernet(source: [u8; 6], destination: [u8; 6], field: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = destination.to_vec();
    bytes.extend_from_slice(&source);
    bytes.extend_from_slice(&field.to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

pub fn arp(source: [u8; 6], claimed: [u8; 6], address: [u8; 4]) -> Vec<u8> {
    let mut body = vec![0, 1, 8, 0, 6, 4, 0, 1];
    body.extend_from_slice(&claimed);
    body.extend_from_slice(&address);
    body.extend_from_slice(&[0; 6]);
    body.extend_from_slice(&[192, 0, 2, 9]);
    ethernet(source, [0xff; 6], 0x0806, &body)
}

pub fn traffic(destination: [u8; 6], address: [u8; 4]) -> Vec<u8> {
    // A complete UDP envelope keeps endpoint tests independent of service fingerprints
    let mut body = vec![0x45, 0, 0, 28, 0, 1, 0, 0, 64, 17, 0, 0];
    body.extend_from_slice(&[192, 0, 2, 3]);
    body.extend_from_slice(&address);
    body.extend_from_slice(&[0x30, 0x39, 0x01, 0xbb, 0, 8, 0, 0]);
    ethernet(CLIENT_MAC, destination, 0x0800, &body)
}

pub fn tagged(bytes: &[u8], tci: u16) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut tagged = bytes.get(..12).ok_or("short Ethernet fixture")?.to_vec();
    tagged.extend_from_slice(&[0x81, 0]);
    tagged.extend_from_slice(&tci.to_be_bytes());
    tagged.extend_from_slice(bytes.get(12..).ok_or("short Ethernet fixture")?);
    Ok(tagged)
}

pub fn captured(bytes: Vec<u8>, index: u32) -> Result<CapturedFrame, Box<dyn std::error::Error>> {
    captured_with_fcs(bytes, index, FcsStatus::Unknown)
}

pub fn captured_with_fcs(
    bytes: Vec<u8>,
    index: u32,
    fcs: FcsStatus,
) -> Result<CapturedFrame, Box<dyn std::error::Error>> {
    let length = u32::try_from(bytes.len())?;
    Ok(CapturedFrame::new(
        bytes,
        CaptureMetadata::new(
            InterfaceId { section: 0, index },
            length,
            None,
            None,
            Direction::Unknown,
            None,
            fcs,
        ),
    )?)
}

pub fn assess(
    packets: impl IntoIterator<Item = CapturedFrame>,
) -> Result<Report, Box<dyn std::error::Error>> {
    let mut survey = Survey::new();
    for packet in packets {
        survey.observe(&packet)?;
    }
    Ok(survey.finish(&Policy::default())?)
}

#[track_caller]
pub fn assert_evidence(report: &Report, sequences: &[u64]) {
    for sequence in sequences {
        assert!(
            report
                .evidence_refs
                .iter()
                .any(|reference| reference.sequence == *sequence),
            "missing evidence for packet {sequence}"
        );
    }
}
