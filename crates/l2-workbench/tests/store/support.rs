use l2_capture::CapturedFrame;
use std::error::Error;

pub fn capture(frames: &[CapturedFrame]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xa1b2_c3d4_u32.to_le_bytes());
    bytes.extend_from_slice(&[2, 0, 4, 0]);
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(&65_535_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    for (index, frame) in frames.iter().enumerate() {
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&u32::try_from(index)?.to_le_bytes());
        bytes.extend_from_slice(&u32::try_from(frame.bytes().len())?.to_le_bytes());
        bytes.extend_from_slice(&frame.metadata().original_len().to_le_bytes());
        bytes.extend_from_slice(frame.bytes());
    }
    Ok(bytes)
}
